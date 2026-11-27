import { Injectable } from '@nestjs/common';
import { remediationDecisionRecordSchema } from '@email-gateway/mailbox-api';
import type { Prisma } from '@email-gateway/database';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import { rangeWindow, resolveRange } from '../../../http/listing/range';
import type { ClientContext } from '../../auth/services/session.service';
import {
  decodeListCursor,
  encodeListCursor,
  listBinding,
  timeIdKeyOf,
  timeIdKeys,
} from '../../messages/domain/v1-list';
import type { ReleaseOutcome } from '../../quarantine/dto/quarantine.schemas';
import {
  AuditedRefusal,
  InconsistentQuarantineReadError,
  inconsistentRead,
} from '../../quarantine/quarantine.errors';
import { QuarantineReleaseService } from '../../quarantine/services/quarantine-release.service';
import { QuarantineWriter } from '../../quarantine/services/quarantine-writer';
import {
  API_MODE_AUDIT,
  API_MODE_CURSOR_RESOURCES,
  API_MODE_OPERATIONS,
  API_MODE_RESOURCES,
  API_MODE_TX_TIMEOUT_MS,
  QUARANTINE_RELEASE_PERMISSION,
  REMEDIATIONS_DEFAULT_DAYS,
  REMEDIATIONS_MAX_DAYS,
} from '../api-mode.constants';
import {
  detectionNotFound,
  detectionNotRemediable,
  hardDeleteNotManual,
  mailboxAccessRequired,
  nothingToRestore,
  quarantinePermissionRequired,
  remediationAlreadyApplied,
  remediationInProgress,
  remediationNotFound,
  remediationNotRetryable,
  restoreNotPossible,
} from '../api-mode.errors';
import {
  decideManualRemediation,
  decideRestore,
  decideRetry,
  latencyMs,
  type RemediateRefusal,
  type RestoreRefusal,
} from '../domain/remediation-rules';
import {
  RemediateBodySchema,
  type RemediationDetailView,
  type RemediationListQuery,
  type RemediationPage,
  type RemediationRequestView,
  type RemediationView,
  RestoreBodySchema,
  type RestoreResponseView,
} from '../dto/api-mode-remediation.schemas';
import {
  ApiRemediationRepository,
  type CopyFacts,
  type RemediationDetailRow,
  type RemediationRow,
} from '../repositories/api-remediation.repository';
import { RemediationActionWriter } from '../repositories/remediation-action-writer';
import { parseBody, parsePublicId } from './protection-mode.service';

type Tx = Prisma.TransactionClient;

const DAY_MS = 86_400_000;
const iso = (d: Date | null): string | null => (d === null ? null : d.toISOString());

function remediateError(refusal: RemediateRefusal) {
  switch (refusal.code) {
    case 'hard_delete_not_manual':
      return hardDeleteNotManual();
    case 'detection_not_remediable':
      return detectionNotRemediable(refusal.status);
    case 'mailbox_access_required':
      return mailboxAccessRequired();
    case 'remediation_in_progress':
      return remediationInProgress();
    case 'remediation_already_applied':
      return remediationAlreadyApplied(refusal.action);
  }
}

function restoreError(refusal: RestoreRefusal) {
  switch (refusal.code) {
    case 'remediation_in_progress':
      return remediationInProgress();
    case 'nothing_to_restore':
      return nothingToRestore(refusal.state);
    case 'restore_not_possible':
      return restoreNotPossible(refusal.cause);
  }
}

/** A stored `decision` as the view shows it (the R2.4 record or the manual request; else null). */
function decisionView(value: unknown): RemediationDetailView['decision'] {
  const record = remediationDecisionRecordSchema.safeParse(value);
  if (record.success) return record.data;
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const v = value as { requestedAction?: unknown; reason?: unknown };
    if (typeof v.requestedAction === 'string') {
      return {
        requestedAction: v.requestedAction as RemediationView['action'],
        reason: typeof v.reason === 'string' ? v.reason : null,
      };
    }
  }
  return null;
}

/**
 * The remediation history and the manual requests (step API-2 R12, R13 #5-#9; ADR-0101):
 * history list and detail (signed tenant-bound v1 cursors; provider ids never returned), retry of
 * a failed action, manual remediation of a detection and its restore. Each request is one writer
 * transaction with its Idempotency-Key: the copy row locked (`FOR UPDATE`), the R12 rules
 * (`domain/remediation-rules.ts`), the action row queued for the mailbox-worker (`pending`, due
 * now, `action_key` of the copy's public id, action and current generation), the copy marked
 * `pending`, and the audit row. A restore of an entry-creating remediation delegates to the
 * quarantine release of its mailbox-located entry inside the same transaction (the caller also
 * needs `quarantine:release`; the quarantine's approval rules apply and its outcome is returned).
 */
@Injectable()
export class RemediationActionsService {
  constructor(
    private readonly repository: ApiRemediationRepository,
    private readonly actions: RemediationActionWriter,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
    private readonly release: QuarantineReleaseService,
    private readonly quarantineWriter: QuarantineWriter,
  ) {}

  now(): Date {
    return new Date();
  }

  // ---- views ------------------------------------------------------------------------------------

  remediationView(row: RemediationRow): RemediationView {
    return {
      id: row.publicId,
      action: row.action,
      trigger: row.trigger,
      status: row.status,
      reasonCode: row.reasonCode,
      attempts: row.attempts,
      lastErrorCode: row.lastErrorCode,
      generation: row.generation,
      mailbox: { id: row.mailboxPublicId, address: row.mailboxAddress },
      connectionId: row.connectionPublicId,
      detectionId: row.detectionPublicId,
      quarantineEntryId: row.quarantineEntryPublicId,
      createdAt: row.createdAt.toISOString(),
      nextAttemptAt: row.status === 'pending' ? iso(row.nextAttemptAt) : null,
      completedAt: iso(row.completedAt),
      latencyMs: latencyMs(row),
    };
  }

  detailView(row: RemediationDetailRow): RemediationDetailView {
    const container = row.providerRefs?.container ?? null;
    return {
      ...this.remediationView(row),
      decision: decisionView(row.decision),
      requestedBy: { type: row.requestedByType, userId: row.requestedByUserPublicId },
      requestReason: row.requestReason,
      locateAttempts: row.locateAttempts,
      lastHttpStatus: row.lastHttpStatus,
      providerRefs:
        row.providerRefs === null
          ? null
          : {
              container:
                container === 'quarantine_folder' ||
                container === 'junk' ||
                container === 'deleted_items' ||
                container === 'inbox'
                  ? container
                  : null,
              before: row.providerRefs.before,
              after: row.providerRefs.after,
            },
      reverses: row.reversesPublicId,
      reversedBy: row.reversedByPublicId,
      releaseId: row.releasePublicId,
      verdictAt: iso(row.verdictAt),
      startedAt: iso(row.startedAt),
      updatedAt: row.updatedAt.toISOString(),
    };
  }

  /** `GET /api-mode/remediations` (v1 cursor list; `[from, to)` ≤ 31 days; newest first). */
  async list(
    principal: Principal,
    scope: TenantScope,
    query: RemediationListQuery,
  ): Promise<RemediationPage> {
    const binding = listBinding({
      resource: API_MODE_CURSOR_RESOURCES.remediations,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    const range = resolveRange(query, {
      defaultMs: REMEDIATIONS_DEFAULT_DAYS * DAY_MS,
      maxDays: REMEDIATIONS_MAX_DAYS,
      now: this.now(),
      cursorWindow: decoded?.window,
    });
    const before = timeIdKeyOf(decoded);
    const f = query.filters;
    const one = <T>(v: { values?: T[] } | undefined): T | undefined => v?.values?.[0];
    const id = (v: string | number | boolean | undefined): string | undefined =>
      v === undefined ? undefined : String(v).toLowerCase();
    const fetched = await this.repository.remediations(
      scope,
      {
        ...(f.status?.values && { status: [...f.status.values] }),
        ...(f.action?.values && { action: [...f.action.values] }),
        ...(f.trigger?.values && { trigger: [...f.trigger.values] }),
        ...(id(one(f.mailboxId)) !== undefined && { mailboxPublicId: id(one(f.mailboxId)) }),
        ...(id(one(f.connectionId)) !== undefined && {
          connectionPublicId: id(one(f.connectionId)),
        }),
        ...(id(one(f.detectionId)) !== undefined && {
          detectionPublicId: id(one(f.detectionId)),
        }),
      },
      range,
      { take: query.limit + 1, ...(before && { before }) },
    );
    const decision = decideKeysetPage({
      fetched,
      limit: query.limit,
      keyOf: (r) => ({ at: r.createdAt, id: r.id }),
    });
    return {
      data: fetched.slice(0, decision.rows).map((r) => this.remediationView(r)),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, timeIdKeys(decision.next), rangeWindow(range)),
    };
  }

  /** `GET /api-mode/remediations/{remediationId}`. */
  async detail(scope: TenantScope, rawId: unknown): Promise<RemediationDetailView> {
    const row = await this.repository.remediation(scope, parsePublicId(rawId, 'remediationId'));
    if (row === null) throw remediationNotFound();
    return this.detailView(row);
  }

  // ---- writes -----------------------------------------------------------------------------------

  private async queued(tx: Tx, scope: TenantScope, publicId: string): Promise<RemediationView> {
    const row = await this.repository.remediation(scope, publicId, tx);
    if (row === null) throw remediationNotFound();
    return this.remediationView(row);
  }

  private async lockCopy(
    tx: Tx,
    scope: TenantScope,
    publicId: string,
    lock = true,
  ): Promise<CopyFacts> {
    const copy = await this.repository.lockCopy(tx, scope, publicId, lock);
    if (copy === null) throw detectionNotFound();
    return copy;
  }

  /** `POST /api-mode/remediations/{remediationId}/retry` (R12; keyed). */
  async retry(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<RemediationView>> {
    const publicId = parsePublicId(input.id, 'remediationId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const operation = API_MODE_OPERATIONS.remediationRetry;
    return this.idempotency.execute<RemediationView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body: {} }),
      },
      async (tx) => {
        const locked = await this.repository.lockRemediation(tx, scope, publicId);
        if (locked === null) throw remediationNotFound();
        const { row, copyGeneration } = locked;
        const copy = { id: row.copyId, receivedAt: row.copyReceivedAt };
        const other = await this.repository.hasActiveAction(tx, scope, copy, row.id);
        const decision = decideRetry(row, other, copyGeneration);
        if (!decision.ok) {
          throw decision.code === 'in_progress'
            ? remediationInProgress()
            : remediationNotRetryable(decision.cause);
        }
        const now = this.now();
        if (!(await this.repository.retry(tx, scope, row, now))) {
          throw remediationNotRetryable('changed');
        }
        await this.actions.markCopyPending(
          tx,
          {
            organizationId: scope.organizationId,
            copyId: row.copyId,
            copyReceivedAt: row.copyReceivedAt,
          },
          {
            remediationAction:
              row.action === 'restore_inbox' || row.action === 'remove_tag' ? null : row.action,
            lastActionId: row.id,
            now,
          },
        );
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: API_MODE_AUDIT.remediationRetryRequested,
            resourceType: API_MODE_RESOURCES.remediation,
            resourceId: row.publicId,
            sourceIp,
            metadata: { remediationId: row.publicId, action: row.action },
          },
          tx,
        );
        return { statusCode: 202, body: await this.queued(tx, scope, row.publicId) };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  /** `POST /api-mode/detections/{detectionId}/remediate` (R12; keyed; 202). */
  async remediate(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<RemediationRequestView>> {
    const publicId = parsePublicId(input.id, 'detectionId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(RemediateBodySchema, input.body);
    // R-I2: never manual, refused before any read.
    if (body.action === 'hard_delete') throw hardDeleteNotManual();
    const operation = API_MODE_OPERATIONS.remediate;
    return this.idempotency.execute<RemediationRequestView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body }),
      },
      async (tx) => {
        const copy = await this.lockCopy(tx, scope, publicId);
        const decision = decideManualRemediation(
          { ...copy, hasActiveAction: await this.repository.hasActiveAction(tx, scope, copy) },
          body.action,
        );
        if (!decision.ok) throw remediateError(decision.refusal);
        const now = this.now();
        const queued = await this.actions.queue(tx, {
          organizationId: scope.organizationId,
          apiConnectionId: copy.apiConnectionId,
          mailboxId: copy.mailboxId,
          copyId: copy.id,
          copyReceivedAt: copy.receivedAt,
          copyPublicId: copy.publicId,
          messageId: copy.messageId,
          action: decision.action,
          generation: copy.remediationGeneration,
          trigger: 'admin',
          decision: { requestedAction: decision.action, reason: body.reason },
          reversesActionId: null,
          quarantineEntryId: null,
          releaseLogId: null,
          requestedByType: principal.kind,
          requestedByUserId: principal.kind === 'user' ? principal.userId : null,
          requestReason: body.reason,
          now,
        });
        if (queued.outcome === 'busy') throw remediationInProgress();
        if (queued.outcome === 'succeeded') throw remediationAlreadyApplied(decision.action);
        await this.actions.markCopyPending(
          tx,
          {
            organizationId: scope.organizationId,
            copyId: copy.id,
            copyReceivedAt: copy.receivedAt,
          },
          { remediationAction: decision.action, lastActionId: queued.id, now },
        );
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: API_MODE_AUDIT.remediationRequested,
            resourceType: API_MODE_RESOURCES.detection,
            resourceId: copy.publicId,
            sourceIp,
            metadata: {
              detectionId: copy.publicId,
              remediationId: queued.publicId,
              action: decision.action,
              generation: copy.remediationGeneration,
              verdictAuthority: copy.verdictAuthority,
              rearmed: queued.outcome === 'rearmed',
              reason: body.reason,
            },
          },
          tx,
        );
        return {
          statusCode: 202,
          body: {
            detectionId: copy.publicId,
            remediation: await this.queued(tx, scope, queued.publicId),
          },
        };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  /**
   * `POST /api-mode/detections/{detectionId}/restore` (R12; keyed; 202). A tag → `remove_tag`;
   * an entry-creating remediation → the quarantine release of its entry (same transaction and
   * Idempotency-Key; `quarantine:release` required, else `403 quarantine_permission_required`;
   * a refusal of the release is audited like the quarantine route's and its error returned).
   */
  async restore(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    client: ClientContext,
  ): Promise<IdempotentResult<RestoreResponseView>> {
    const publicId = parsePublicId(input.id, 'detectionId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(RestoreBodySchema, input.body);
    const operation = API_MODE_OPERATIONS.restore;
    try {
      return await this.idempotency.execute<RestoreResponseView>(
        {
          organizationId: scope.organizationId,
          principal: principalKey(principal),
          operation,
          key,
          resourceId: publicId,
          fingerprint: requestFingerprint({ operation, resourceId: publicId, body }),
        },
        (tx) =>
          this.applyRestore(tx, principal, scope, { publicId, key, reason: body.reason }, client),
        { timeoutMs: API_MODE_TX_TIMEOUT_MS },
      );
    } catch (error) {
      if (error instanceof AuditedRefusal) {
        await this.quarantineWriter.recordRefusal(principal, scope, client, error, key);
        throw error.error;
      }
      if (error instanceof InconsistentQuarantineReadError) throw inconsistentRead();
      throw error;
    }
  }

  private async applyRestore(
    tx: Tx,
    principal: Principal,
    scope: TenantScope,
    input: { publicId: string; key: string; reason: string },
    client: ClientContext,
  ): Promise<{ statusCode: number; body: RestoreResponseView }> {
    const copy = await this.lockCopy(tx, scope, input.publicId, false);
    const hasActiveAction = await this.repository.hasActiveAction(tx, scope, copy);
    const entry = await this.repository.entryOfCopy(tx, scope, copy);
    const decision = decideRestore({ ...copy, hasActiveAction }, entry);
    if (!decision.ok) throw restoreError(decision.refusal);
    const audit = (metadata: Record<string, unknown>) =>
      this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: API_MODE_AUDIT.restoreRequested,
          resourceType: API_MODE_RESOURCES.detection,
          resourceId: copy.publicId,
          sourceIp: client.ip,
          metadata: { detectionId: copy.publicId, reason: input.reason, ...metadata },
        },
        tx,
      );
    if (decision.plan.kind === 'release') {
      if (!principal.permissions.has(QUARANTINE_RELEASE_PERMISSION)) {
        throw quarantinePermissionRequired();
      }
      const released = await this.release.releaseInTx(tx, {
        principal,
        scope,
        entryId: decision.plan.entryPublicId,
        key: input.key,
        body: { reason: input.reason },
        client,
      });
      const outcome: ReleaseOutcome = released.body;
      await audit({
        via: 'quarantine_release',
        entryId: decision.plan.entryPublicId,
        outcome: outcome.outcome,
        ...(outcome.outcome === 'queued'
          ? { releaseId: outcome.releaseId }
          : { approvalRequestId: outcome.approvalRequestId }),
      });
      return {
        statusCode: 202,
        body: {
          detectionId: copy.publicId,
          via: 'quarantine_release',
          remediation: null,
          release: outcome,
        },
      };
    }
    const reversed = await this.repository.lastSucceeded(tx, scope, copy, 'tag');
    const now = this.now();
    const queued = await this.actions.queue(tx, {
      organizationId: scope.organizationId,
      apiConnectionId: copy.apiConnectionId,
      mailboxId: copy.mailboxId,
      copyId: copy.id,
      copyReceivedAt: copy.receivedAt,
      copyPublicId: copy.publicId,
      messageId: copy.messageId,
      action: 'remove_tag',
      generation: copy.remediationGeneration,
      trigger: 'admin',
      decision: { requestedAction: 'remove_tag', reason: input.reason },
      reversesActionId: reversed?.id ?? copy.lastActionId,
      quarantineEntryId: null,
      releaseLogId: null,
      requestedByType: principal.kind,
      requestedByUserId: principal.kind === 'user' ? principal.userId : null,
      requestReason: input.reason,
      now,
    });
    if (queued.outcome === 'busy' || queued.outcome === 'succeeded') throw remediationInProgress();
    await this.actions.markCopyPending(
      tx,
      { organizationId: scope.organizationId, copyId: copy.id, copyReceivedAt: copy.receivedAt },
      { remediationAction: null, lastActionId: queued.id, now },
    );
    await audit({ via: 'mailbox_action', remediationId: queued.publicId, action: 'remove_tag' });
    return {
      statusCode: 202,
      body: {
        detectionId: copy.publicId,
        via: 'mailbox_action',
        remediation: await this.queued(tx, scope, queued.publicId),
        release: null,
      },
    };
  }
}
