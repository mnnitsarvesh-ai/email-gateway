import { BadRequestException, Inject, Injectable, Logger } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { decodeCursor, encodeCursor, pageWindow, toPage } from '../../../http/pagination';
import type { ClientContext } from '../../auth/services/session.service';
import { messageNotFound } from '../../messages/messages.errors';
import {
  becLimitReached,
  becNotFound,
  becResultNotFound,
  becScanNotFound,
  feedbackExists,
} from '../bec.errors';
import { exportRecordOf } from '../domain/bec-export';
import { planFeedback } from '../domain/bec-feedback';
import { fromIdentityOf, ruleCodesOf } from '../domain/bec-result';
import type {
  BecFeedbackCreate,
  BecFeedbackCreated,
  BecFeedbackExportQuery,
  BecFeedbackListQuery,
  BecFeedbackPage,
  BecFeedbackView,
  BecHistoryPurged,
  BecSuppressionListQuery,
  BecSuppressionPage,
  BecSuppressionView,
} from '../dto/bec.schemas';
import {
  BecFeedbackRepository,
  type FeedbackRow,
  HISTORY_PURGE_BATCH,
  isFeedbackKeyViolation,
  type SuppressionRow,
} from '../repositories/bec-feedback.repository';
import { BEC_AUDIT, BEC_RESOURCE, BecMetrics, BecWriter, stringList, userIdOf } from './bec-writer';

/** Feedback rows the export reads per replica query. */
const EXPORT_BATCH = 500;

export function suppressionView(
  row: SuppressionRow,
  feedbackIds: ReadonlyMap<bigint, string>,
  now: Date,
): BecSuppressionView {
  return {
    id: row.publicId,
    reasonCode: row.reasonCode,
    senderScope: row.senderScope,
    senderValue: row.senderValue,
    expiresAt: row.expiresAt.toISOString(),
    expired: row.expiresAt.getTime() <= now.getTime(),
    feedbackId: row.feedbackId === null ? null : (feedbackIds.get(row.feedbackId) ?? null),
    createdByUserId: row.createdBy?.publicId ?? null,
    createdAt: row.createdAt.toISOString(),
  };
}

export function feedbackView(
  row: FeedbackRow,
  messageIds: ReadonlyMap<bigint, string>,
): BecFeedbackView {
  return {
    id: row.publicId,
    kind: row.kind,
    messageId: messageIds.get(row.messageId) ?? null,
    scanId: row.scanId.toString(),
    reasonCodes: stringList(row.reasonCodes),
    note: row.note,
    createdByUserId: row.createdBy?.publicId ?? null,
    createdAt: row.createdAt.toISOString(),
  };
}

/**
 * What the audit rows keep of a suppression rule. Keys never contain `code` (AuditService
 * scrubs keys matching /code/i as credentials), so the reason code is `rule`.
 */
const suppressionImage = (row: SuppressionRow) => ({
  id: row.publicId,
  rule: row.reasonCode,
  senderScope: row.senderScope,
  senderValue: row.senderValue,
  expiresAt: row.expiresAt.toISOString(),
});

const dateOf = (value: string | undefined): Date | undefined =>
  value === undefined ? undefined : new Date(value);

function checkWindow(from: Date | undefined, to: Date | undefined): void {
  if (from !== undefined && to !== undefined && from.getTime() >= to.getTime()) {
    throw new BadRequestException(['to: must be after from']);
  }
}

/** One page of the retraining export: the NDJSON lines (lazy) and the next cursor. */
export interface BecExportStream {
  nextCursor: string | null;
  lines: AsyncIterable<string>;
}

/**
 * Analyst feedback on BEC verdicts, its bounded suppressions, the retraining export and the
 * communication-history purge (step 4.4 B11, B12, B18):
 *
 * - `record`: the message, the scan and its `bec_scan_results` row must belong to the caller's
 *   organization (writer reads, echo-checked; `404 message_not_found` / `scan_not_found` /
 *   `bec_result_not_found`); disputed codes of a false positive ⊂ the result's codes; the
 *   optional suppression within the B11 bounds (planFeedback) and the per-tenant cap of active
 *   rules (`BEC_SUPPRESSIONS_MAX_PER_TENANT`, `409 bec_limit_reached`); an existing rule of the
 *   same (code, scope, sender) is renewed. One feedback per (scan, user, kind) (`409
 *   feedback_exists`). Audited `bec_feedback.recorded` (with the suppressions) in the same
 *   transaction; `bec_feedback_total{kind}`.
 * - `export`: NDJSON of the B11 fields only, oldest first, ≤ 10 000 records per response with
 *   `X-Next-Cursor`; audited `bec_feedback.exported` before the first byte.
 * - suppressions list (replica) and delete (audited with the before-image).
 * - `purgeHistory`: deletes the organization's `bec_contact_history` rows in batches of 5 000;
 *   audited `bec_history.purged` with the count in the last batch's transaction.
 */
@Injectable()
export class BecFeedbackService {
  private readonly logger = new Logger(BecFeedbackService.name);

  constructor(
    @Inject(API_CONFIG) private readonly limits: { BEC_SUPPRESSIONS_MAX_PER_TENANT: number },
    private readonly repository: BecFeedbackRepository,
    private readonly writer: BecWriter,
    private readonly audit: AuditService,
    private readonly metrics: BecMetrics,
  ) {}

  /** `POST /messages/{messageId}/scans/{scanId}/bec-feedback`: `201`. */
  async record(
    principal: UserPrincipal,
    scope: TenantScope,
    messageId: string,
    scanId: bigint,
    body: BecFeedbackCreate,
    client: ClientContext,
  ): Promise<BecFeedbackCreated> {
    const now = new Date();
    try {
      const created = await this.writer.run(async (tx) => {
        // First statement: every later lock of this transaction (the bec_feedback insert's
        // foreign-key share locks, the suppression key's gap lock) is taken under it.
        await this.repository.lockOrganization(tx, scope);
        const message = await this.repository.findMessage(tx, scope, messageId);
        if (!message) throw messageNotFound();
        if (!(await this.repository.scanExists(tx, scope, message, scanId))) {
          throw becScanNotFound();
        }
        const result = await this.repository.findResult(tx, scope, message, scanId);
        if (!result) throw becResultNotFound();
        const finalCodes = await this.repository.finalReasonCodes(tx, scope, message, scanId);
        const codes = new Set([...ruleCodesOf(result.rules), ...stringList(finalCodes)]);
        const planned = planFeedback(body, codes, fromIdentityOf(result.identity), now);
        if (await this.repository.findOwnFeedback(tx, scope, scanId, principal.userId, body.kind)) {
          throw feedbackExists();
        }
        const feedback = await this.repository.createFeedback(tx, scope, {
          publicId: uuidv7(now.getTime()),
          message,
          scanId,
          becResultId: result.id,
          kind: body.kind,
          reasonCodes: body.reasonCodes ?? null,
          note: body.note ?? null,
          userId: userIdOf(principal),
        });
        const suppressions: SuppressionRow[] = [];
        if (planned.length > 0) {
          let active = await this.repository.countActiveSuppressions(tx, scope, now);
          for (const plan of planned) {
            const existing = await this.repository.findSuppressionByKey(tx, scope, plan);
            if (existing) {
              const wasActive = existing.expiresAt.getTime() > now.getTime();
              if (!wasActive) active += 1;
              if (active > this.limits.BEC_SUPPRESSIONS_MAX_PER_TENANT) {
                throw becLimitReached('suppressions', this.limits.BEC_SUPPRESSIONS_MAX_PER_TENANT);
              }
              const expiresAt =
                existing.expiresAt.getTime() > plan.expiresAt.getTime()
                  ? existing.expiresAt
                  : plan.expiresAt;
              suppressions.push(
                await this.repository.renewSuppression(
                  tx,
                  scope,
                  existing.id,
                  expiresAt,
                  feedback.id,
                ),
              );
              continue;
            }
            active += 1;
            if (active > this.limits.BEC_SUPPRESSIONS_MAX_PER_TENANT) {
              throw becLimitReached('suppressions', this.limits.BEC_SUPPRESSIONS_MAX_PER_TENANT);
            }
            suppressions.push(
              await this.repository.createSuppression(tx, scope, {
                ...plan,
                publicId: uuidv7(now.getTime()),
                feedbackId: feedback.id,
                userId: userIdOf(principal),
              }),
            );
          }
        }
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: BEC_AUDIT.feedbackRecorded,
            resourceType: BEC_RESOURCE.feedback,
            resourceId: feedback.publicId,
            sourceIp: client.ip,
            metadata: {
              kind: feedback.kind,
              messageId: message.publicId,
              scanId: scanId.toString(),
              // `disputed`, not `reasonCodes`: AuditService scrubs keys matching /code/i.
              disputed: body.reasonCodes ?? [],
              suppressions: suppressions.map(suppressionImage),
            },
          },
          tx,
        );
        const feedbackIds = new Map([[feedback.id, feedback.publicId]]);
        return {
          ...feedbackView(feedback, new Map([[message.id, message.publicId]])),
          suppressions: suppressions.map((row) => suppressionView(row, feedbackIds, now)),
        };
      });
      this.metrics.feedback.inc({ kind: created.kind });
      this.logger.log({
        message: 'bec feedback recorded',
        organizationId: scope.organizationId.toString(),
        id: created.id,
        kind: created.kind,
        scanId: created.scanId,
        suppressions: created.suppressions.length,
      });
      return created;
    } catch (error) {
      // Two identical feedbacks raced on the (scan, user, kind) key (the organization lock makes
      // this unreachable in practice; any other unique key is not `feedback_exists`).
      if (isFeedbackKeyViolation(error)) throw feedbackExists();
      throw error;
    }
  }

  /** `GET /bec/feedback` (replica, newest first). */
  async list(scope: TenantScope, query: BecFeedbackListQuery): Promise<BecFeedbackPage> {
    const from = dateOf(query.from);
    const to = dateOf(query.to);
    checkWindow(from, to);
    const rows = await this.repository.listFeedback(scope, {
      ...pageWindow(query),
      ...(query.kind !== undefined && { kind: query.kind }),
      ...(from !== undefined && { from }),
      ...(to !== undefined && { to }),
    });
    const messageIds = await this.repository.messagePublicIds(
      scope,
      rows.slice(0, query.limit).map((row) => row.messageId),
    );
    return toPage(rows, query.limit, (row) => feedbackView(row, messageIds));
  }

  /**
   * `GET /bec/feedback/export` (NDJSON): the ids of this response are fixed first (≤ limit,
   * oldest first, after the cursor), the export is audited, then the records are read in batches
   * of 500 from the replica as the response is written.
   */
  async export(
    principal: Principal,
    scope: TenantScope,
    query: BecFeedbackExportQuery,
    client: ClientContext,
  ): Promise<BecExportStream> {
    const from = dateOf(query.from);
    const to = dateOf(query.to);
    checkWindow(from, to);
    const afterId = query.cursor === undefined ? undefined : decodeCursor(query.cursor);
    const ids = await this.repository.exportIds(scope, {
      take: query.limit + 1,
      ...(afterId !== undefined && { afterId }),
      ...(from !== undefined && { from }),
      ...(to !== undefined && { to }),
    });
    const pageIds = ids.slice(0, query.limit);
    const last = pageIds.at(-1);
    const nextCursor = ids.length > query.limit && last !== undefined ? encodeCursor(last) : null;
    await this.audit.record({
      organizationId: scope.organizationId,
      actor: this.audit.actorFrom(principal),
      action: BEC_AUDIT.feedbackExported,
      resourceType: BEC_RESOURCE.feedback,
      resourceId: null,
      sourceIp: client.ip,
      metadata: {
        from: query.from ?? null,
        to: query.to ?? null,
        cursor: query.cursor ?? null,
        records: pageIds.length,
        more: nextCursor !== null,
      },
    });
    this.logger.log({
      message: 'bec feedback exported',
      organizationId: scope.organizationId.toString(),
      records: pageIds.length,
    });
    return { nextCursor, lines: this.exportLines(scope, pageIds) };
  }

  private async *exportLines(scope: TenantScope, ids: readonly bigint[]): AsyncIterable<string> {
    for (let i = 0; i < ids.length; i += EXPORT_BATCH) {
      const feedback = await this.repository.exportFeedback(scope, ids.slice(i, i + EXPORT_BATCH));
      const results = await this.repository.exportResults(
        scope,
        feedback.map((row) => ({ id: row.becResultId, receivedAt: row.messageReceivedAt })),
      );
      const byKey = new Map(
        results.map((row) => [`${row.id}:${row.receivedAt.getTime()}`, row] as const),
      );
      for (const row of feedback) {
        const result = byKey.get(`${row.becResultId}:${row.messageReceivedAt.getTime()}`);
        if (!result) continue;
        const record = exportRecordOf(row, result);
        if (record) yield `${JSON.stringify(record)}\n`;
      }
    }
  }

  /** `GET /bec/suppressions` (replica, newest first). */
  async listSuppressions(
    scope: TenantScope,
    query: BecSuppressionListQuery,
  ): Promise<BecSuppressionPage> {
    const now = new Date();
    const rows = await this.repository.listSuppressions(scope, {
      ...pageWindow(query),
      ...(query.active !== undefined && { active: query.active }),
      now,
    });
    const feedbackIds = await this.repository.feedbackPublicIds(
      scope,
      rows.flatMap((row) => (row.feedbackId === null ? [] : [row.feedbackId])),
    );
    return toPage(rows, query.limit, (row) => suppressionView(row, feedbackIds, now));
  }

  /** `DELETE /bec/suppressions/{id}`: `204`, or `404`. */
  async deleteSuppression(
    principal: Principal,
    scope: TenantScope,
    id: string,
    client: ClientContext,
  ): Promise<void> {
    await this.writer.run(async (tx) => {
      const row = await this.repository.findSuppressionForUpdate(tx, scope, id);
      if (!row) throw becNotFound('suppression');
      await this.repository.deleteSuppression(tx, scope, row.id);
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: BEC_AUDIT.suppressionDeleted,
          resourceType: BEC_RESOURCE.suppression,
          resourceId: row.publicId,
          sourceIp: client.ip,
          metadata: { before: suppressionImage(row) },
        },
        tx,
      );
    });
    this.logger.log({
      message: 'bec suppression deleted',
      organizationId: scope.organizationId.toString(),
      id,
    });
  }

  /** `DELETE /bec/history`: `202 { deleted }`. */
  async purgeHistory(
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
  ): Promise<BecHistoryPurged> {
    let deleted = 0;
    let batches = 0;
    for (;;) {
      const removed = await this.writer.run(async (tx) => {
        const n = await this.repository.purgeHistoryBatch(tx, scope, HISTORY_PURGE_BATCH);
        if (n < HISTORY_PURGE_BATCH) {
          await this.audit.record(
            {
              organizationId: scope.organizationId,
              actor: this.audit.actorFrom(principal),
              action: BEC_AUDIT.historyPurged,
              resourceType: BEC_RESOURCE.history,
              resourceId: null,
              sourceIp: client.ip,
              metadata: { deleted: deleted + n, batches: batches + 1 },
            },
            tx,
          );
        }
        return n;
      });
      deleted += removed;
      batches += 1;
      if (removed < HISTORY_PURGE_BATCH) break;
    }
    this.logger.log({
      message: 'bec history purged',
      organizationId: scope.organizationId.toString(),
      deleted,
      batches,
    });
    return { deleted };
  }
}
