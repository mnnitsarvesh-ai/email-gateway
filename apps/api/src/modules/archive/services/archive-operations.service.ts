import { Injectable } from '@nestjs/common';
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
import { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import {
  decodeListCursor,
  encodeListCursor,
  listBinding,
  timeIdKeyOf,
  timeIdKeys,
} from '../../messages/domain/v1-list';
import {
  ARCHIVE_AUDIT,
  ARCHIVE_CURSOR_RESOURCES,
  ARCHIVE_OPERATIONS,
  ARCHIVE_RESOURCE,
  ARCHIVE_TX_TIMEOUT_MS,
} from '../archive.constants';
import { captureIssueNotFound, captureRetryNotAllowed } from '../archive.errors';
import {
  CAPTURE_ISSUE_STATUSES,
  type CaptureIssueListQuery,
  type CaptureIssuePage,
  type CaptureIssueView,
  type CaptureRetryView,
  type DisposalListQuery,
  type DisposalPage,
} from '../dto/archive.schemas';
import {
  ArchiveRecordsRepository,
  type CaptureIssueRow,
} from '../repositories/archive-records.repository';
import { parsePublicId, requireArchiving } from './archive-common';

/** A pending intent older than this is a capture issue (the `ArchiveCaptureBacklog` warning). */
export const CAPTURE_ISSUE_AGE_MS = 6 * 3_600_000;
/** Default and longest range of the disposal log. */
const DISPOSALS_DEFAULT_MS = 30 * 86_400_000;
const DISPOSALS_MAX_DAYS = 366;

/** The list item view of a capture intent (the list and the single read share it). */
function captureIssueView(r: CaptureIssueRow, messageId: string): CaptureIssueView {
  return {
    messageId,
    receivedAt: r.receivedAt.toISOString(),
    status: r.status,
    code: r.lastErrorCode ?? r.skipReason,
    attempts: r.attempts,
    sources: { journal: r.sourceJournal, policy: r.sourcePolicy },
    nextCheckAt: r.nextCheckAt.toISOString(),
    createdAt: r.createdAt.toISOString(),
  };
}

/**
 * Capture issues and the disposal log (step 8.1 §4.4 #11–#13; A2, A14, A15): `failed`, `lost`
 * and aged `pending` capture intents of the organization with their codes; the retry that moves
 * a `failed` intent back to `pending` (never a `lost` one: its original is gone); and the
 * append-only `archive_disposals` log (message public id, received time, reason, state,
 * SHA-256, times — no content).
 */
@Injectable()
export class ArchiveOperationsService {
  constructor(
    private readonly records: ArchiveRecordsRepository,
    private readonly features: OrganizationFeaturesService,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
  ) {}

  now(): Date {
    return new Date();
  }

  async captureIssues(
    principal: Principal,
    scope: TenantScope,
    query: CaptureIssueListQuery,
  ): Promise<CaptureIssuePage> {
    const binding = listBinding({
      resource: ARCHIVE_CURSOR_RESOURCES.captureIssues,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    const before = timeIdKeyOf(decoded);
    const statuses = query.filters.status?.values ?? [...CAPTURE_ISSUE_STATUSES];
    const rows = await this.records.captureIssues(scope, {
      take: query.limit + 1,
      statuses,
      agedBefore: new Date(this.now().getTime() - CAPTURE_ISSUE_AGE_MS),
      before,
    });
    const decision = decideKeysetPage({
      fetched: rows,
      limit: query.limit,
      keyOf: (r) => ({ at: r.receivedAt, id: r.id }),
    });
    return {
      data: rows
        .slice(0, decision.rows)
        .filter((r) => r.messagePublicId !== null)
        .map((r) => captureIssueView(r, r.messagePublicId!)),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, timeIdKeys(decision.next)),
    };
  }

  /**
   * `GET /archive/capture-issues/{messageId}` (step AI-5 D8): the capture intent of one message
   * in the list item's view, for any intent status (pending, captured_open, closed, skipped,
   * lost, failed). Unknown message, another organization's or one without an intent →
   * `404 archive_capture_issue_not_found` (the retry's code). No plan gating (as the list).
   */
  async captureIssue(scope: TenantScope, rawId: unknown): Promise<CaptureIssueView> {
    const id = parsePublicId(rawId, 'messageId');
    const row = await this.records.captureIssue(scope, id);
    if (row === null || row.messagePublicId === null) throw captureIssueNotFound();
    return captureIssueView(row, row.messagePublicId);
  }

  /** `POST /archive/capture-issues/{messageId}/retry` (#12): `failed` → `pending`. */
  async retry(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    sourceIp: string | null,
  ): Promise<IdempotentResult<CaptureRetryView>> {
    const id = parsePublicId(rawId, 'messageId');
    const key = parseIdempotencyKey(idempotencyKey);
    const operation = ARCHIVE_OPERATIONS.captureRetry;
    return this.idempotency.execute<CaptureRetryView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: id,
        fingerprint: requestFingerprint({ operation, resourceId: id, body: {} }),
      },
      async (tx) => {
        const message = await this.records.messageKey(scope, id, tx);
        if (message === null) throw captureIssueNotFound();
        const intent = await this.records.lockIntent(tx, scope, message);
        if (intent === null) throw captureIssueNotFound();
        await requireArchiving(this.features, scope, tx);
        if (intent.status !== 'failed') throw captureRetryNotAllowed(intent.status);
        const now = this.now();
        if (!(await this.records.retryIntent(tx, scope, message, intent.id, now))) {
          throw captureRetryNotAllowed('changed');
        }
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: ARCHIVE_AUDIT.captureRetried,
            resourceType: ARCHIVE_RESOURCE.message,
            resourceId: message.publicId,
            sourceIp,
            metadata: { messageId: message.publicId, fromStatus: intent.status },
          },
          tx,
        );
        return {
          statusCode: 200,
          body: { messageId: message.publicId, status: 'pending', nextCheckAt: now.toISOString() },
        };
      },
      { timeoutMs: ARCHIVE_TX_TIMEOUT_MS },
    );
  }

  async disposals(
    principal: Principal,
    scope: TenantScope,
    query: DisposalListQuery,
  ): Promise<DisposalPage> {
    const binding = listBinding({
      resource: ARCHIVE_CURSOR_RESOURCES.disposals,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    const range = resolveRange(query, {
      defaultMs: DISPOSALS_DEFAULT_MS,
      maxDays: DISPOSALS_MAX_DAYS,
      now: this.now(),
      cursorWindow: decoded?.window,
    });
    const rows = await this.records.disposals(scope, {
      take: query.limit + 1,
      from: range.from,
      to: range.to,
      reasons: query.filters.reason?.values,
      states: query.filters.state?.values,
      before: timeIdKeyOf(decoded),
    });
    const decision = decideKeysetPage({
      fetched: rows,
      limit: query.limit,
      keyOf: (r) => ({ at: r.requestedAt, id: r.id }),
    });
    return {
      data: rows.slice(0, decision.rows).map((r) => ({
        messageId: r.messagePublicId,
        receivedAt: r.messageReceivedAt.toISOString(),
        reason: r.reason,
        state: r.state,
        sha256: r.sha256,
        sizeBytes: r.sizeBytes,
        attempts: r.attempts,
        requestedAt: r.requestedAt.toISOString(),
        completedAt: r.completedAt?.toISOString() ?? null,
      })),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, timeIdKeys(decision.next), rangeWindow(range)),
    };
  }
}
