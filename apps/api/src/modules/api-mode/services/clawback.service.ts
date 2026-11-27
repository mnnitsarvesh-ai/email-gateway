import { createHash } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { EventTypes, notificationAlertRequestedV1 } from '@email-gateway/event-contracts';
import {
  canonicalCriteriaSha256,
  type ClawbackAction,
  type ClawbackCriteria,
  clawbackCriteriaSchema,
  type ClawbackSignalFacts,
  clawbackSignalFactsSchema,
  clawbackSignalSchema,
  type MessageVerdict,
  REMEDIATION_PURGE_PERMISSION,
} from '@email-gateway/mailbox-api';
import { API_CONFIG } from '../../../api-config.token';
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
import { rangeWindow, resolveRange } from '../../../http/listing/range';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import { maskAddress } from '../../messages/domain/sensitive-masking';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  listBinding,
  timeIdKeyOf,
  timeIdKeys,
} from '../../messages/domain/v1-list';
import {
  API_MODE_AUDIT,
  API_MODE_CURSOR_RESOURCES,
  API_MODE_OPERATIONS,
  API_MODE_RESOURCES,
  API_MODE_TX_TIMEOUT_MS,
  type ApiModeConfig,
  CLAWBACKS_DEFAULT_DAYS,
  CLAWBACKS_MAX_DAYS,
  QUARANTINE_RELEASE_PERMISSION,
} from '../api-mode.constants';
import {
  clawbackCriteriaInvalid,
  clawbackNotCancellable,
  clawbackNotFound,
  clawbackNotRestorable,
  clawbackStateConflict,
  detectionNotFound,
  purgeApprovalForbidden,
  purgeApprovalNotPending,
  purgeHardDeleteDisabled,
} from '../api-mode.errors';
import {
  approvalReasonsOf,
  buildAdminCriteria,
  decideApproval,
  decideCancel,
  decideClawbackRestore,
  decideSubmit,
  SUBMITTABLE_CLAWBACK_STATUSES,
  submitFacts,
  truncatedHash,
} from '../domain/clawback-rules';
import {
  type ClawbackCreatedView,
  type ClawbackDetailView,
  type ClawbackListQuery,
  type ClawbackPage,
  type ClawbackTargetListQuery,
  type ClawbackTargetPage,
  type ClawbackTargetView,
  type ClawbackView,
  CreateClawbackBodySchema,
  DecisionBodySchema,
  ReasonBodySchema,
  SubmitClawbackBodySchema,
  type SubmitClawbackResponseView,
} from '../dto/api-mode-clawback.schemas';
import {
  ApiClawbackRepository,
  type ClawbackRow,
  type OutboxRow,
  type TargetRow,
} from '../repositories/api-clawback.repository';
import { OrgSettingsService } from './org-settings.service';
import { parseBody, parsePublicId } from './protection-mode.service';

type Tx = Prisma.TransactionClient;

const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;
const iso = (d: Date | null): string | null => (d === null ? null : d.toISOString());

/** The alert kind of a purge waiting for its second approver (C6). */
export const PURGE_APPROVAL_ALERT_KIND = 'api_mode_purge_approval';

/** SHA-256 of the decider's sorted permission keys (Q14 practice, C6 `approver_permissions_hash`). */
export function permissionsHash(principal: Principal): string {
  return createHash('sha256')
    .update([...principal.permissions].sort().join('\n'))
    .digest('hex');
}

const userIdOf = (p: Principal): bigint | null => (p.kind === 'user' ? p.userId : null);

/** The stored signal's kind and facts (lenient: unknown documents read as empty). */
function signalOf(row: ClawbackRow): {
  kind: ClawbackView['signalKind'];
  facts: ClawbackSignalFacts | null;
} {
  const parsed = clawbackSignalSchema.safeParse(row.signal);
  const kind = parsed.success ? parsed.data.kind : null;
  if (row.signalVerdict !== null && row.signalLevel !== null) {
    const facts = clawbackSignalFactsSchema.safeParse({
      verdict: row.signalVerdict,
      level: row.signalLevel,
      hardBlocks: Array.isArray(row.signalHardBlocks) ? row.signalHardBlocks : [],
    });
    if (facts.success) return { kind, facts: facts.data };
  }
  return { kind, facts: parsed.success ? parsed.data.facts : null };
}

/** The criteria view: hashes truncated (C14 #3); a stored document that no longer parses is empty. */
function criteriaView(value: unknown): ClawbackDetailView['criteria'] {
  const parsed = clawbackCriteriaSchema.safeParse(value);
  const c: ClawbackCriteria | null = parsed.success ? parsed.data : null;
  const k = c?.keys ?? {};
  return {
    window: c?.window ?? { from: new Date(0).toISOString(), to: new Date(0).toISOString() },
    directions: c?.directions ?? [],
    keys: {
      messageIdHashes: (k.messageIdHashes ?? []).map(truncatedHash),
      attachmentSha256: (k.attachmentSha256 ?? []).map(truncatedHash),
      urlSha256: (k.urlSha256 ?? []).map(truncatedHash),
      urlDomains: [...(k.urlDomains ?? [])],
      senders: [...(k.senders ?? [])],
      senderDomains: [...(k.senderDomains ?? [])],
      senderSubject: k.senderSubject ? { ...k.senderSubject } : null,
    },
  };
}

/** Key counts of a criteria document (the audit metadata: no hash, address or subject). */
function keyCounts(c: ClawbackCriteria): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [key, value] of Object.entries(c.keys)) {
    if (value === undefined) continue;
    out[key] = Array.isArray(value) ? value.length : 1;
  }
  return out;
}

/**
 * API-mode clawbacks (step API-3 C2.3, C2.4, C4, C5.1, C5.6, C6, C7, C14 #1-#10; ADR-0103): the
 * admin search (criteria normalized with the explorer's keys, or a seed detection with its
 * campaign expansion; the mailbox-worker `clawback` role materializes the frozen targets), the
 * list, detail and target pages, and the submit / hard-delete submit / approve / deny / cancel /
 * restore requests. Each write is one writer transaction with its Idempotency-Key: the clawback
 * row locked (`FOR UPDATE`), the version and state rules (`domain/clawback-rules.ts`), the row
 * updated with CAS on `row_version`, the audit row, and for an approval request the
 * `api_mode_purge_approval` alert through its `notification_alert_windows` throttle. The api
 * never queues mailbox actions itself: the worker does (C-I1).
 */
@Injectable()
export class ClawbackService {
  constructor(
    @Inject(API_CONFIG)
    private readonly config: Pick<
      ApiModeConfig,
      | 'API_MODE_HARD_DELETE_ENABLED'
      | 'API_MODE_CLAWBACK_MAX_WINDOW_DAYS'
      | 'API_MODE_PURGE_APPROVAL_TTL_HOURS'
    >,
    private readonly repository: ApiClawbackRepository,
    private readonly settings: OrgSettingsService,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
  ) {}

  now(): Date {
    return new Date();
  }

  // ---- views ------------------------------------------------------------------------------------

  clawbackView(row: ClawbackRow): ClawbackView {
    return {
      id: row.publicId,
      trigger: row.trigger,
      status: row.status,
      decisionMode: row.decisionMode,
      action: row.action,
      signalKind: signalOf(row).kind,
      counts: {
        targetsTotal: row.targetsTotal,
        mailboxesTotal: row.mailboxesTotal,
        targetsEligible: row.targetsEligible,
        mailboxesEligible: row.mailboxesEligible,
        skipped: row.targetsSkipped,
        simulated: row.targetsSimulated,
        queued: row.targetsQueued,
        succeeded: row.targetsSucceeded,
        failed: row.targetsFailed,
        cancelled: row.targetsCancelled,
      },
      approval: {
        required: row.requiresApproval,
        status: row.approvalStatus,
        reasons: approvalReasonsOf(row.approvalReasons),
        requestedAt: iso(row.approvalRequestedAt),
        expiresAt: iso(row.approvalExpiresAt),
        decidedAt: iso(row.approvalDecidedAt),
      },
      restore: {
        status: row.restoreStatus,
        queued: row.restoresQueued,
        succeeded: row.restoresSucceeded,
        failed: row.restoresFailed,
        skipped: row.restoresSkipped,
      },
      cancelRequested: row.cancelRequestedAt !== null,
      reportId: row.reportPublicId,
      lastErrorCode: row.lastErrorCode,
      signalAt: row.signalAt.toISOString(),
      createdAt: row.createdAt.toISOString(),
      submittedAt: iso(row.submittedAt),
      startedAt: iso(row.startedAt),
      completedAt: iso(row.completedAt),
      updatedAt: row.updatedAt.toISOString(),
      rowVersion: row.rowVersion,
    };
  }

  detailView(row: ClawbackRow, principal: Principal, now: Date): ClawbackDetailView {
    const signal = signalOf(row);
    const has = (p: string) => principal.permissions.has(p);
    const purge = has(REMEDIATION_PURGE_PERMISSION);
    const approval = decideApproval({
      status: row.status,
      rowVersion: row.rowVersion,
      expectedRowVersion: row.rowVersion,
      approval: {
        status: row.approvalStatus,
        expiresAt: row.approvalExpiresAt,
        requestedByUserId: row.requestedByUserId,
        submittedByUserId: row.submittedByUserId,
      },
      approver: {
        kind: principal.kind,
        userId: userIdOf(principal),
        permissions: [...principal.permissions],
      },
      now,
    });
    const cancel = decideCancel(row.status, row.cancelRequestedAt);
    return {
      ...this.clawbackView(row),
      criteria: criteriaView(row.criteria),
      signal: {
        kind: signal.kind,
        verdict: signal.facts?.verdict ?? null,
        level: signal.facts?.level ?? null,
        hardBlocks: signal.facts?.hardBlocks ?? [],
        seedDetectionId: row.seedCopyPublicId,
      },
      requestedBy: { type: row.requestedByType, userId: row.requestedByUserPublicId },
      submittedBy: row.submittedByUserPublicId,
      requestReason: row.requestReason,
      approvalDecision: {
        decidedBy: row.approvedByUserPublicId,
        reason: row.approvalDecisionReason,
      },
      hints: {
        canSubmit:
          purge && (SUBMITTABLE_CLAWBACK_STATUSES as readonly string[]).includes(row.status),
        canApprove: approval.allowed,
        canCancel: purge && cancel.ok && !cancel.alreadyRequested,
        canRestore:
          purge &&
          has(QUARANTINE_RELEASE_PERMISSION) &&
          decideClawbackRestore({
            status: row.status,
            restoreStatus: row.restoreStatus,
            targetsSucceeded: row.targetsSucceeded,
          }).ok,
      },
    };
  }

  /** A target row; without `remediation:purge` the mailbox is masked and sender/subject withheld. */
  targetView(row: TargetRow, purge: boolean): ClawbackTargetView {
    const keys = Array.isArray(row.matchKeys)
      ? (row.matchKeys.filter((k) => typeof k === 'string') as ClawbackTargetView['matchKeys'])
      : [];
    return {
      mailbox: {
        id: row.mailboxPublicId,
        address: purge ? row.mailboxAddress : maskAddress(row.mailboxAddress),
      },
      connectionId: row.connectionPublicId,
      detectionId: row.detectionPublicId,
      receivedAt: row.receivedAt.toISOString(),
      headerFrom: purge && row.headerFrom !== '' ? row.headerFrom : null,
      subject: purge && row.subject !== '' ? row.subject : null,
      matchKeys: keys,
      copyRemediationState: row.copyRemediationState,
      status: row.status,
      plannedAction: row.plannedAction,
      reasonCode: row.reasonCode,
      remediationId: row.remediationPublicId,
      restoreStatus: row.restoreStatus,
      restoreReasonCode: row.restoreReasonCode,
    };
  }

  // ---- reads ------------------------------------------------------------------------------------

  /** `GET /api-mode/clawbacks` (v1 cursor list; `[from, to)` ≤ 93 days; newest first). */
  async list(
    principal: Principal,
    scope: TenantScope,
    query: ClawbackListQuery,
  ): Promise<ClawbackPage> {
    const binding = listBinding({
      resource: API_MODE_CURSOR_RESOURCES.clawbacks,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    const range = resolveRange(query, {
      defaultMs: CLAWBACKS_DEFAULT_DAYS * DAY_MS,
      maxDays: CLAWBACKS_MAX_DAYS,
      now: this.now(),
      cursorWindow: decoded?.window,
    });
    const before = timeIdKeyOf(decoded);
    const f = query.filters;
    const fetched = await this.repository.clawbacks(
      scope,
      {
        ...(f.status?.values && { status: [...f.status.values] }),
        ...(f.trigger?.values && { trigger: [...f.trigger.values] }),
        ...(f.approvalStatus?.values && { approvalStatus: [...f.approvalStatus.values] }),
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
      data: fetched.slice(0, decision.rows).map((r) => this.clawbackView(r)),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, timeIdKeys(decision.next), rangeWindow(range)),
    };
  }

  /** `GET /api-mode/clawbacks/{clawbackId}`. */
  async detail(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
  ): Promise<ClawbackDetailView> {
    const row = await this.repository.clawback(scope, parsePublicId(rawId, 'clawbackId'));
    if (row === null) throw clawbackNotFound();
    return this.detailView(row, principal, this.now());
  }

  /** `GET /api-mode/clawbacks/{clawbackId}/targets` (v1 cursor bound to the clawback). */
  async targets(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    query: ClawbackTargetListQuery,
  ): Promise<ClawbackTargetPage> {
    const publicId = parsePublicId(rawId, 'clawbackId');
    const clawback = await this.repository.clawback(scope, publicId);
    if (clawback === null) throw clawbackNotFound();
    const binding = listBinding({
      resource: API_MODE_CURSOR_RESOURCES.clawbackTargets,
      principal,
      // The clawback is part of the filter hash: a cursor of one clawback is refused on another.
      filters: { ...query.filters, clawbackId: { values: [publicId] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const f = query.filters;
    const mailboxId = f.mailboxId?.values?.[0];
    const fetched = await this.repository.targets(
      scope,
      clawback.id,
      {
        ...(f.status?.values && { status: [...f.status.values] }),
        ...(f.restoreStatus?.values && { restoreStatus: [...f.restoreStatus.values] }),
        ...(mailboxId !== undefined && { mailboxPublicId: String(mailboxId).toLowerCase() }),
      },
      { take: query.limit + 1, ...(decoded && { afterId: decimalKey(decoded.keys[0]) }) },
    );
    const decision = decideKeysetPage({ fetched, limit: query.limit, keyOf: (r) => r.id });
    const purge = principal.permissions.has(REMEDIATION_PURGE_PERMISSION);
    return {
      data: fetched.slice(0, decision.rows).map((r) => this.targetView(r, purge)),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [decision.next.toString()]),
    };
  }

  // ---- create (C14 #1) --------------------------------------------------------------------------

  /** `POST /api-mode/clawbacks` (keyed; 202). */
  async create(
    principal: Principal,
    scope: TenantScope,
    input: { idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<ClawbackCreatedView>> {
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(CreateClawbackBodySchema, input.body);
    const operation = API_MODE_OPERATIONS.clawbackCreate;
    return this.idempotency.execute<ClawbackCreatedView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: 'clawbacks',
        fingerprint: requestFingerprint({ operation, resourceId: 'clawbacks', body }),
      },
      async (tx) => {
        const now = this.now();
        const seed =
          body.seedDetectionId === undefined
            ? null
            : await this.repository.seedCopy(tx, scope, body.seedDetectionId.toLowerCase());
        if (body.seedDetectionId !== undefined && seed === null) throw detectionNotFound();
        const built = buildAdminCriteria({
          organizationId: scope.organizationId,
          criteria: body.criteria ?? null,
          seed,
          expand: body.expand ?? null,
          directions: body.directions ?? null,
          now,
          maxWindowDays: this.config.API_MODE_CLAWBACK_MAX_WINDOW_DAYS,
        });
        if (!built.ok) throw clawbackCriteriaInvalid(built.codes);
        const signal = clawbackSignalSchema.parse({
          v: 1,
          kind: built.trigger === 'campaign' ? 'campaign' : 'admin',
          refs: seed === null ? {} : { seedCopyId: seed.id.toString() },
          facts: null,
          signalAt: now.toISOString(),
        });
        const criteriaSha256 = canonicalCriteriaSha256(built.criteria);
        const created = await this.repository.createClawback(tx, scope, {
          publicId: uuidv7(now.getTime()),
          trigger: built.trigger,
          signal: signal,
          criteria: built.criteria,
          criteriaSha256,
          requestedByType: principal.kind,
          requestedByUserId: userIdOf(principal),
          requestReason: body.reason,
          reportId: null,
          seedCopyId: seed?.id ?? null,
          seedCopyReceivedAt: seed?.receivedAt ?? null,
          now,
        });
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: API_MODE_AUDIT.clawbackCreated,
            resourceType: API_MODE_RESOURCES.clawback,
            resourceId: created.publicId,
            sourceIp,
            metadata: {
              clawbackId: created.publicId,
              trigger: built.trigger,
              criteriaSha256,
              keys: keyCounts(built.criteria),
              directions: built.criteria.directions,
              window: built.criteria.window,
              seedDetectionId: seed?.publicId ?? null,
              reason: body.reason,
            },
          },
          tx,
        );
        return {
          statusCode: 202,
          body: {
            id: created.publicId,
            status: 'searching',
            trigger: built.trigger,
            rowVersion: created.rowVersion,
          },
        };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  // ---- submit (C14 #5, #6) ----------------------------------------------------------------------

  private async lock(tx: Tx, scope: TenantScope, publicId: string): Promise<ClawbackRow> {
    const row = await this.repository.lockClawback(tx, scope, publicId);
    if (row === null) throw clawbackNotFound();
    return row;
  }

  private async reload(tx: Tx, scope: TenantScope, publicId: string): Promise<ClawbackRow> {
    const row = await this.repository.clawback(scope, publicId, tx);
    if (row === null) throw clawbackNotFound();
    return row;
  }

  /** `POST /api-mode/clawbacks/{clawbackId}/submit` (keyed; 202). */
  async submit(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<SubmitClawbackResponseView>> {
    const body = parseBody(SubmitClawbackBodySchema, input.body);
    const action: ClawbackAction | null = body.mode === 'explicit' ? body.action : null;
    return this.submitWith(principal, scope, input, sourceIp, {
      operation: API_MODE_OPERATIONS.clawbackSubmit,
      body,
      action,
      chosen:
        body.mode === 'policy'
          ? {
              ...(body.verdict !== undefined && { verdict: body.verdict }),
              ...(body.level !== undefined && { level: body.level }),
            }
          : null,
      reason: body.reason,
      expectedRowVersion: body.expectedRowVersion,
    });
  }

  /** `POST /api-mode/clawbacks/{clawbackId}/submit-hard-delete` (keyed; 202; portal only). */
  async submitHardDelete(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<SubmitClawbackResponseView>> {
    const body = parseBody(DecisionBodySchema, input.body);
    if (!this.config.API_MODE_HARD_DELETE_ENABLED) throw purgeHardDeleteDisabled();
    return this.submitWith(principal, scope, input, sourceIp, {
      operation: API_MODE_OPERATIONS.clawbackSubmitHardDelete,
      body,
      action: 'hard_delete',
      chosen: null,
      reason: body.reason,
      expectedRowVersion: body.expectedRowVersion,
    });
  }

  private submitWith(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown },
    sourceIp: string | null,
    s: {
      operation: string;
      body: unknown;
      action: ClawbackAction | null;
      chosen: Parameters<typeof submitFacts>[0]['chosen'] | null;
      reason: string;
      expectedRowVersion: number;
    },
  ): Promise<IdempotentResult<SubmitClawbackResponseView>> {
    const publicId = parsePublicId(input.id, 'clawbackId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    return this.idempotency.execute<SubmitClawbackResponseView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: s.operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({
          operation: s.operation,
          resourceId: publicId,
          body: s.body,
        }),
      },
      async (tx) => {
        const row = await this.lock(tx, scope, publicId);
        const { settings, purgeThreshold } = await this.settings.resolveForSubmit(
          scope,
          principal,
          tx,
        );
        const decision = decideSubmit({
          status: row.status,
          rowVersion: row.rowVersion,
          expectedRowVersion: s.expectedRowVersion,
          trigger: row.trigger,
          mailboxesEligible: row.mailboxesEligible,
          storedApprovalReasons: approvalReasonsOf(row.approvalReasons),
          settings: {
            purgeApprovalMailboxes: purgeThreshold.threshold,
            autoMaxMailboxes: settings.autoMaxMailboxes,
          },
          action: s.action,
          hardDeleteEnabled: this.config.API_MODE_HARD_DELETE_ENABLED,
        });
        if (!decision.ok) {
          if (decision.code === 'hard_delete_disabled') throw purgeHardDeleteDisabled();
          throw clawbackStateConflict(decision.status, decision.currentRowVersion);
        }
        const now = this.now();
        const facts =
          s.chosen === null
            ? null
            : submitFacts({
                trigger: row.trigger,
                chosen: s.chosen,
                stored: signalOf(row).facts,
                reportScanVerdict: await this.reportScanVerdict(tx, scope, row),
              });
        const expiresAt = decision.requiresApproval
          ? new Date(now.getTime() + this.config.API_MODE_PURGE_APPROVAL_TTL_HOURS * HOUR_MS)
          : null;
        const ok = await this.repository.updateClawback(tx, scope, row.id, row.rowVersion, {
          status: decision.status,
          decisionMode: s.action === null ? 'policy' : 'explicit',
          action: s.action,
          ...(facts !== null && {
            signalVerdict: facts.verdict,
            signalLevel: facts.level,
            signalHardBlocks: facts.hardBlocks,
          }),
          requiresApproval: decision.requiresApproval,
          approvalReasons: decision.reasons.length > 0 ? decision.reasons : [],
          approvalStatus: decision.requiresApproval ? 'pending' : null,
          approvalRequestedAt: decision.requiresApproval ? now : null,
          approvalExpiresAt: expiresAt,
          approvalDecidedAt: null,
          approvedByUserId: null,
          approvalDecisionReason: null,
          approverPermissionsHash: null,
          submittedByUserId: userIdOf(principal),
          submittedAt: now,
          ...(row.requestReason === null && { requestReason: s.reason }),
          nextStepAt: decision.status === 'queued' ? now : null,
        });
        if (!ok) throw clawbackStateConflict(row.status, row.rowVersion);
        const record = (action: string, metadata: Record<string, unknown>) =>
          this.audit.record(
            {
              organizationId: scope.organizationId,
              actor: this.audit.actorFrom(principal),
              action,
              resourceType: API_MODE_RESOURCES.clawback,
              resourceId: row.publicId,
              sourceIp,
              metadata: { clawbackId: row.publicId, ...metadata },
            },
            tx,
          );
        await record(API_MODE_AUDIT.clawbackSubmitted, {
          trigger: row.trigger,
          mode: s.action === null ? 'policy' : 'explicit',
          action: s.action,
          verdict: facts?.verdict ?? null,
          level: facts?.level ?? null,
          status: decision.status,
          requiresApproval: decision.requiresApproval,
          approvalReasons: decision.reasons,
          targetsEligible: row.targetsEligible,
          mailboxesEligible: row.mailboxesEligible,
          reason: s.reason,
        });
        if (decision.requiresApproval) {
          await record(API_MODE_AUDIT.clawbackApprovalRequested, {
            approvalReasons: decision.reasons,
            expiresAt: expiresAt!.toISOString(),
            threshold: purgeThreshold.threshold,
            ...(purgeThreshold.selfRaised && {
              storedThreshold: settings.purgeApprovalMailboxes,
              selfRaisedThreshold: true,
            }),
          });
          await this.requestApprovalAlert(tx, scope, row.publicId, s.action === 'hard_delete', now);
        }
        const after = await this.reload(tx, scope, row.publicId);
        return {
          statusCode: 202,
          body: {
            id: after.publicId,
            status: decision.status,
            requiresApproval: decision.requiresApproval,
            approvalReasons: decision.reasons,
            approvalExpiresAt: iso(after.approvalExpiresAt),
            rowVersion: after.rowVersion,
          },
        };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  /** The scan verdict of a report clawback's report (the C3.1 report row), else null. */
  private async reportScanVerdict(
    tx: Tx,
    scope: TenantScope,
    row: ClawbackRow,
  ): Promise<MessageVerdict | null> {
    if (row.trigger !== 'report' || row.reportPublicId === null) return null;
    const report = await this.repository.report(scope, row.reportPublicId, tx);
    return report?.scanVerdict ?? null;
  }

  /**
   * C6: `notification.alert_requested.v1` kind `api_mode_purge_approval` (refs the clawback;
   * severity `high` for hard delete, else `medium`), throttled per clawback through
   * `notification_alert_windows` (one window = the approval TTL).
   */
  private async requestApprovalAlert(
    tx: Tx,
    scope: TenantScope,
    clawbackPublicId: string,
    hardDelete: boolean,
    now: Date,
  ): Promise<void> {
    const minutes = this.config.API_MODE_PURGE_APPROVAL_TTL_HOURS * 60;
    const size = minutes * 60_000;
    const from = new Date(Math.floor(now.getTime() / size) * size);
    const window = { from, to: new Date(from.getTime() + size) };
    const sourceEventId = uuidv7(now.getTime());
    await this.repository.requestAlert(tx, {
      organizationId: scope.organizationId,
      kind: PURGE_APPROVAL_ALERT_KIND,
      scopeKey: clawbackPublicId,
      window,
      windowMinutes: minutes,
      sourceEventId,
      outbox: (suppressedBefore): OutboxRow => ({
        eventId: uuidv7(now.getTime()),
        organizationId: scope.organizationId,
        eventType: EventTypes.NotificationAlertRequested,
        aggregateType: 'organization',
        aggregateId: scope.organizationId.toString(),
        correlationId: `api-mode-clawback:${clawbackPublicId}`,
        payload: notificationAlertRequestedV1.parse({
          kind: PURGE_APPROVAL_ALERT_KIND,
          severity: hardDelete ? 'high' : 'medium',
          refs: { clawbackId: clawbackPublicId },
          window: { from: window.from.toISOString(), to: window.to.toISOString() },
          counts: { suppressedBefore },
          requestedAt: now.toISOString(),
        }),
      }),
    });
  }

  // ---- approve / deny (C14 #7, #8) --------------------------------------------------------------

  async approve(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<ClawbackView>> {
    return this.decide(principal, scope, input, sourceIp, 'approve');
  }

  async deny(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<ClawbackView>> {
    return this.decide(principal, scope, input, sourceIp, 'deny');
  }

  private decide(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
    verb: 'approve' | 'deny',
  ): Promise<IdempotentResult<ClawbackView>> {
    const publicId = parsePublicId(input.id, 'clawbackId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(DecisionBodySchema, input.body);
    const operation =
      verb === 'approve' ? API_MODE_OPERATIONS.clawbackApprove : API_MODE_OPERATIONS.clawbackDeny;
    return this.idempotency.execute<ClawbackView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body }),
      },
      async (tx) => {
        const row = await this.lock(tx, scope, publicId);
        const now = this.now();
        const decision = decideApproval({
          status: row.status,
          rowVersion: row.rowVersion,
          expectedRowVersion: body.expectedRowVersion,
          approval: {
            status: row.approvalStatus,
            expiresAt: row.approvalExpiresAt,
            requestedByUserId: row.requestedByUserId,
            submittedByUserId: row.submittedByUserId,
          },
          approver: {
            kind: principal.kind,
            userId: userIdOf(principal),
            permissions: [...principal.permissions],
          },
          now,
        });
        if (!decision.allowed) {
          if (decision.code === 'state_conflict') {
            throw clawbackStateConflict(decision.status, decision.currentRowVersion);
          }
          if (decision.code === 'api_mode_purge_approval_forbidden') {
            throw purgeApprovalForbidden(decision.reason);
          }
          throw purgeApprovalNotPending(decision.reason);
        }
        const ok = await this.repository.updateClawback(tx, scope, row.id, row.rowVersion, {
          status: verb === 'approve' ? 'queued' : 'denied',
          approvalStatus: verb === 'approve' ? 'approved' : 'denied',
          approvalDecidedAt: now,
          approvedByUserId: userIdOf(principal),
          approvalDecisionReason: body.reason,
          approverPermissionsHash: permissionsHash(principal),
          nextStepAt: verb === 'approve' ? now : null,
          ...(verb === 'deny' && { completedAt: now }),
        });
        if (!ok) throw clawbackStateConflict(row.status, row.rowVersion);
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action:
              verb === 'approve' ? API_MODE_AUDIT.clawbackApproved : API_MODE_AUDIT.clawbackDenied,
            resourceType: API_MODE_RESOURCES.clawback,
            resourceId: row.publicId,
            sourceIp,
            metadata: {
              clawbackId: row.publicId,
              action: row.action,
              decisionMode: row.decisionMode,
              approvalReasons: approvalReasonsOf(row.approvalReasons),
              targetsEligible: row.targetsEligible,
              mailboxesEligible: row.mailboxesEligible,
              approverPermissionsHash: permissionsHash(principal),
              reason: body.reason,
            },
          },
          tx,
        );
        return { statusCode: 200, body: this.clawbackView(await this.reload(tx, scope, publicId)) };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  // ---- cancel (C14 #9) --------------------------------------------------------------------------

  async cancel(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<ClawbackView>> {
    const publicId = parsePublicId(input.id, 'clawbackId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(ReasonBodySchema, input.body);
    const operation = API_MODE_OPERATIONS.clawbackCancel;
    return this.idempotency.execute<ClawbackView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body }),
      },
      async (tx) => {
        const row = await this.lock(tx, scope, publicId);
        const decision = decideCancel(row.status, row.cancelRequestedAt);
        if (!decision.ok) throw clawbackNotCancellable(decision.status);
        const now = this.now();
        if (!decision.alreadyRequested) {
          const ok = await this.repository.updateClawback(
            tx,
            scope,
            row.id,
            row.rowVersion,
            decision.immediate
              ? {
                  status: 'cancelled',
                  cancelRequestedAt: now,
                  completedAt: now,
                  nextStepAt: null,
                  ...(row.approvalStatus === 'pending' && {
                    approvalStatus: 'cancelled' as const,
                    approvalDecidedAt: now,
                  }),
                }
              : { cancelRequestedAt: now, nextStepAt: now },
          );
          if (!ok) throw clawbackStateConflict(row.status, row.rowVersion);
          await this.audit.record(
            {
              organizationId: scope.organizationId,
              actor: this.audit.actorFrom(principal),
              action: API_MODE_AUDIT.clawbackCancelled,
              resourceType: API_MODE_RESOURCES.clawback,
              resourceId: row.publicId,
              sourceIp,
              metadata: {
                clawbackId: row.publicId,
                from: row.status,
                immediate: decision.immediate,
                targetsQueued: row.targetsQueued,
                reason: body.reason,
              },
            },
            tx,
          );
        }
        return { statusCode: 202, body: this.clawbackView(await this.reload(tx, scope, publicId)) };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  // ---- restore (C14 #10) ------------------------------------------------------------------------

  async restore(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<ClawbackView>> {
    const publicId = parsePublicId(input.id, 'clawbackId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(ReasonBodySchema, input.body);
    const operation = API_MODE_OPERATIONS.clawbackRestore;
    return this.idempotency.execute<ClawbackView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body }),
      },
      async (tx) => {
        const row = await this.lock(tx, scope, publicId);
        const decision = decideClawbackRestore({
          status: row.status,
          restoreStatus: row.restoreStatus,
          targetsSucceeded: row.targetsSucceeded,
        });
        if (!decision.ok) throw clawbackNotRestorable(decision.status, decision.restoreStatus);
        const now = this.now();
        const ok = await this.repository.updateClawback(tx, scope, row.id, row.rowVersion, {
          restoreStatus: 'requested',
          nextStepAt: now,
        });
        if (!ok) throw clawbackStateConflict(row.status, row.rowVersion);
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: API_MODE_AUDIT.clawbackRestoreRequested,
            resourceType: API_MODE_RESOURCES.clawback,
            resourceId: row.publicId,
            sourceIp,
            metadata: {
              clawbackId: row.publicId,
              from: row.restoreStatus,
              targetsSucceeded: row.targetsSucceeded,
              reason: body.reason,
            },
          },
          tx,
        );
        return { statusCode: 202, body: this.clawbackView(await this.reload(tx, scope, publicId)) };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }
}
