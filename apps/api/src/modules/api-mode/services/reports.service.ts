import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { EventTypes, reportFeedbackRequestedV1 } from '@email-gateway/event-contracts';
import {
  canonicalCriteriaSha256,
  clawbackSignalSchema,
  type ReportOriginal,
  reportOriginalSchema,
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
import {
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
  REPORT_GROUP_MEMBERS_MAX,
  REPORT_HISTORY_MAX,
  REPORTS_DEFAULT_DAYS,
  REPORTS_MAX_DAYS,
} from '../api-mode.constants';
import {
  clawbackCriteriaInvalid,
  mailboxNotFound,
  organizationNotFound,
  reportAddressOutOfScope,
  reportMailboxLimit,
  reportMailboxNotEligible,
  reportNotFound,
  reportNotReopenable,
  reportOriginalUnknown,
  reportStateConflict,
} from '../api-mode.errors';
import {
  buildReportCriteria,
  decideReportMailbox,
  decideTriage,
  groupResolutionApplies,
  normalizeAddress,
  shouldNotifyReporter,
  truncatedHash,
} from '../domain/clawback-rules';
import {
  AddReportMailboxBodySchema,
  ReportClawbackBodySchema,
  type ReportClawbackResponseView,
  type ReportDetailView,
  type ReportListQuery,
  type ReportMailboxChangeView,
  type ReportMailboxListView,
  type ReportMailboxView,
  type ReportPage,
  type ReportView,
  SetReportMailboxBodySchema,
  TriageBodySchema,
  type TriageResponseView,
} from '../dto/api-mode-clawback.schemas';
import {
  ApiClawbackRepository,
  type HistoryRow,
  type ReportMailboxRow,
  type ReportRow,
} from '../repositories/api-clawback.repository';
import { OrgSettingsService } from './org-settings.service';
import { parseBody, parsePublicId } from './protection-mode.service';

type Tx = Prisma.TransactionClient;

const DAY_MS = 86_400_000;
const iso = (d: Date | null): string | null => (d === null ? null : d.toISOString());

/** The stored `api-report-original/1` (lenient: an unparseable document reads as unknown). */
export function originalOf(value: unknown): ReportOriginal | null {
  const parsed = reportOriginalSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

/** `metadata` of an `api_mode.report_triaged` row, as the history shows it. */
function historyEntry(row: HistoryRow): ReportDetailView['history'][number] {
  const m =
    row.metadata !== null && typeof row.metadata === 'object' && !Array.isArray(row.metadata)
      ? (row.metadata as Record<string, unknown>)
      : {};
  const text = (v: unknown): string | null => (typeof v === 'string' ? v.slice(0, 64) : null);
  return {
    at: row.at.toISOString(),
    actor: {
      type: row.actorType === 'user' || row.actorType === 'api_key' ? row.actorType : 'system',
      userId: row.actorType === 'user' ? row.actorId : null,
    },
    from: text(m.from),
    to: text(m.to),
    verdict: text(m.verdict),
    reopened: m.reopened === true,
  };
}

/** How many times the history shows a reopen (`resolved` → `in_review`). */
export const reopenCountOf = (history: readonly HistoryRow[]): number =>
  history.filter((h) => historyEntry(h).reopened).length;

/**
 * User-reported phishing in API mode (step API-3 C9.1, C10, C11, C12, C14 #11-#17; ADR-0104):
 * the report list and detail (group members ≤ 50, the triage history from the audit rows), the
 * triage with its group resolution and the reporter result e-mail
 * (`mail.report.feedback_requested.v1` kind `resolved`, written to the outbox in the same
 * transaction), the clawback from a report (criteria from the identified original; never
 * automatic, C-I5) and the report-mailbox designation (≤ `API_MODE_REPORT_MAILBOXES_MAX`, by
 * mailbox or by address). Writes lock the organization row (designation) or the report rows and
 * write their audit rows in the same transaction.
 */
@Injectable()
export class ReportsService {
  constructor(
    @Inject(API_CONFIG)
    private readonly config: Pick<
      ApiModeConfig,
      'API_MODE_CLAWBACK_MAX_WINDOW_DAYS' | 'API_MODE_REPORT_MAILBOXES_MAX'
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

  reportView(row: ReportRow, groupSize: number): ReportView {
    return {
      id: row.publicId,
      status: row.status,
      reporterAddress: row.reporterAddress,
      reportedAt: row.reportedAt.toISOString(),
      identification: row.identification,
      assessment: row.assessment,
      analystVerdict: row.analystVerdict,
      scan: { verdict: row.scanVerdict, riskScore: row.scanRiskScore, level: row.scanLevel },
      groupSize: row.groupKey === null ? 1 : Math.max(1, groupSize),
      clawbackId: row.clawbackPublicId,
      rejectReason: row.rejectReason,
      rowVersion: row.rowVersion,
    };
  }

  mailboxView(row: ReportMailboxRow): ReportMailboxView {
    return {
      id: row.publicId,
      address: row.primaryAddress,
      connectionId: row.connectionPublicId,
      provider: row.provider,
      status: row.status,
      coverage: row.coverageState,
      domain: row.domain === null ? null : { id: row.domain.publicId, name: row.domain.name },
      reportMailbox: row.reportMailbox,
      reportMailboxAt: iso(row.reportMailboxAt),
      lastReportAt: iso(row.lastReportAt),
    };
  }

  // ---- reads ------------------------------------------------------------------------------------

  /** `GET /api-mode/reports` (v1 cursor list; `[from, to)` ≤ 93 days; newest first). */
  async list(
    principal: Principal,
    scope: TenantScope,
    query: ReportListQuery,
  ): Promise<ReportPage> {
    const binding = listBinding({
      resource: API_MODE_CURSOR_RESOURCES.reports,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    const range = resolveRange(query, {
      defaultMs: REPORTS_DEFAULT_DAYS * DAY_MS,
      maxDays: REPORTS_MAX_DAYS,
      now: this.now(),
      cursorWindow: decoded?.window,
    });
    const before = timeIdKeyOf(decoded);
    const f = query.filters;
    const reporter = f.reporter?.values?.[0];
    const fetched = await this.repository.reports(
      scope,
      {
        ...(f.status?.values && { status: [...f.status.values] }),
        ...(f.assessment?.values && { assessment: [...f.assessment.values] }),
        ...(f.analystVerdict?.values && { analystVerdict: [...f.analystVerdict.values] }),
        ...(reporter !== undefined && { reporter: String(reporter).toLowerCase() }),
      },
      range,
      { take: query.limit + 1, ...(before && { before }) },
    );
    const decision = decideKeysetPage({
      fetched,
      limit: query.limit,
      keyOf: (r) => ({ at: r.reportedAt, id: r.id }),
    });
    const page = fetched.slice(0, decision.rows);
    const sizes = await this.repository.groupSizes(
      scope,
      page.flatMap((r) => (r.groupKey === null ? [] : [r.groupKey])),
    );
    return {
      data: page.map((r) =>
        this.reportView(r, r.groupKey === null ? 1 : (sizes.get(r.groupKey) ?? 1)),
      ),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, timeIdKeys(decision.next), rangeWindow(range)),
    };
  }

  /** `GET /api-mode/reports/{reportId}`. */
  async detail(scope: TenantScope, rawId: unknown): Promise<ReportDetailView> {
    const row = await this.repository.report(scope, parsePublicId(rawId, 'reportId'));
    if (row === null) throw reportNotFound();
    return this.detailOf(scope, row);
  }

  private async detailOf(scope: TenantScope, row: ReportRow, tx?: Tx): Promise<ReportDetailView> {
    const [sizes, members, history] = await Promise.all([
      row.groupKey === null
        ? Promise.resolve(new Map<string, number>())
        : this.repository.groupSizes(scope, [row.groupKey], tx),
      row.groupKey === null
        ? Promise.resolve([])
        : this.repository.groupMembers(scope, row.groupKey, row.id, REPORT_GROUP_MEMBERS_MAX),
      this.repository.reportHistory(scope, row.publicId, REPORT_HISTORY_MAX, tx),
    ]);
    const original = originalOf(row.original);
    const groupSize = row.groupKey === null ? 1 : (sizes.get(row.groupKey) ?? 1);
    return {
      ...this.reportView(row, groupSize),
      reporter: {
        address: row.reporterAddress,
        mailboxId: row.reporterMailboxPublicId,
        userId: row.reporterUserPublicId,
      },
      reportMailbox: { id: row.reportMailboxPublicId, address: row.reportMailboxAddress },
      original:
        original === null
          ? null
          : {
              messageIdHash:
                original.messageIdHash === null ? null : truncatedHash(original.messageIdHash),
              sender: original.sender,
              subjectKey: original.subjectKey,
              date: original.date,
              attachmentCount: original.attachmentSha256.length,
              urlCount: original.urlSha256.length,
              extraOriginals: original.extraOriginals,
            },
      originalDetectionId: row.originalCopyPublicId,
      originalIngested: row.originalIngested,
      analyst: {
        verdict: row.analystVerdict,
        note: row.analystNote,
        triagedBy: row.triagedByUserPublicId,
        triagedAt: iso(row.triagedAt),
      },
      group: {
        size: Math.max(1, groupSize),
        members: members.map((m) => ({
          id: m.publicId,
          status: m.status,
          reporterAddress: m.reporterAddress,
          reportedAt: m.reportedAt.toISOString(),
        })),
      },
      history: history.map(historyEntry),
      feedback: { acknowledgement: row.ackFeedback, result: row.resultFeedback },
      updatedAt: row.updatedAt.toISOString(),
    };
  }

  // ---- triage (C14 #13) -------------------------------------------------------------------------

  /** `POST /api-mode/reports/{reportId}/triage` (keyed; CAS; group resolution; feedback). */
  async triage(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<TriageResponseView>> {
    const publicId = parsePublicId(input.id, 'reportId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(TriageBodySchema, input.body);
    if (body.status === 'resolved' && body.verdict === undefined) {
      throw new BadRequestException(['verdict: required when status is resolved']);
    }
    if (body.status !== 'resolved' && body.verdict !== undefined) {
      throw new BadRequestException(['verdict: only allowed when status is resolved']);
    }
    const operation = API_MODE_OPERATIONS.reportTriage;
    return this.idempotency.execute<TriageResponseView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body }),
      },
      async (tx) => {
        const row = await this.repository.lockReport(tx, scope, publicId);
        if (row === null) throw reportNotFound();
        const history = await this.repository.reportHistory(
          scope,
          publicId,
          REPORT_HISTORY_MAX,
          tx,
        );
        const decision = decideTriage({
          status: row.status,
          rowVersion: row.rowVersion,
          expectedRowVersion: body.expectedRowVersion,
          reopenCount: reopenCountOf(history),
          to: body.status,
          verdict: body.verdict ?? null,
        });
        if (!decision.ok) {
          if (decision.code === 'not_reopenable') throw reportNotReopenable();
          if (decision.code === 'state_conflict') {
            throw reportStateConflict(decision.status, decision.currentRowVersion);
          }
          throw reportStateConflict(row.status, null);
        }
        const now = this.now();
        const settings = await this.settings.resolve(scope, tx);
        const notify = shouldNotifyReporter(
          decision.to,
          body.notifyReporter,
          settings.reportFeedbackEnabled,
        );
        const userId = principal.kind === 'user' ? principal.userId : null;
        const update = {
          status: decision.to,
          analystVerdict: decision.to === 'resolved' ? (body.verdict ?? null) : null,
          ...(body.note !== undefined && { analystNote: body.note.length > 0 ? body.note : null }),
          triagedByUserId: userId,
          triagedAt: now,
          rejectReason: decision.rejectReason,
          ...(decision.to === 'resolved' && {
            resultFeedback: notify ? ('queued' as const) : ('skipped' as const),
          }),
        };
        if (!(await this.repository.updateReport(tx, scope, row.id, row.rowVersion, update))) {
          throw reportStateConflict(row.status, row.rowVersion);
        }
        const resolved: Array<{ publicId: string; apiConnectionId: bigint; from: string }> = [];
        if (decision.to === 'resolved') {
          resolved.push({
            publicId: row.publicId,
            apiConnectionId: row.apiConnectionId,
            from: row.status,
          });
        }
        const applyToGroup = body.applyToGroup ?? true;
        if (
          groupResolutionApplies({ to: decision.to, applyToGroup, groupKey: row.groupKey }) &&
          row.groupKey !== null
        ) {
          for (const member of await this.repository.lockOpenGroupReports(
            tx,
            scope,
            row.groupKey,
            row.id,
          )) {
            const ok = await this.repository.updateReport(tx, scope, member.id, member.rowVersion, {
              status: 'resolved',
              analystVerdict: body.verdict ?? null,
              triagedByUserId: userId,
              triagedAt: now,
              rejectReason: null,
              resultFeedback: notify ? 'queued' : 'skipped',
            });
            if (ok) {
              resolved.push({
                publicId: member.publicId,
                apiConnectionId: member.apiConnectionId,
                from: member.status,
              });
            }
          }
        }
        let feedbackQueued = 0;
        for (const r of resolved) {
          if (notify) {
            await this.repository.insertOutbox(tx, {
              eventId: uuidv7(now.getTime()),
              organizationId: scope.organizationId,
              eventType: EventTypes.ReportFeedbackRequested,
              aggregateType: 'organization',
              aggregateId: scope.organizationId.toString(),
              correlationId: `api-mode-report:${r.publicId}`,
              payload: reportFeedbackRequestedV1.parse({
                reportId: r.publicId,
                kind: 'resolved',
                requestedAt: now.toISOString(),
              }),
            });
            feedbackQueued += 1;
          }
          await this.audit.record(
            {
              organizationId: scope.organizationId,
              actor: this.audit.actorFrom(principal),
              action: API_MODE_AUDIT.reportTriaged,
              resourceType: API_MODE_RESOURCES.report,
              resourceId: r.publicId,
              sourceIp,
              metadata: {
                reportId: r.publicId,
                from: r.from,
                to: 'resolved',
                verdict: body.verdict ?? null,
                notifyReporter: notify,
                reopened: false,
                viaGroupOf: r.publicId === row.publicId ? null : row.publicId,
                noteSet: r.publicId === row.publicId && body.note !== undefined,
              },
            },
            tx,
          );
        }
        if (decision.to !== 'resolved') {
          await this.audit.record(
            {
              organizationId: scope.organizationId,
              actor: this.audit.actorFrom(principal),
              action: API_MODE_AUDIT.reportTriaged,
              resourceType: API_MODE_RESOURCES.report,
              resourceId: row.publicId,
              sourceIp,
              metadata: {
                reportId: row.publicId,
                from: row.status,
                to: decision.to,
                verdict: null,
                notifyReporter: false,
                reopened: decision.reopened,
                viaGroupOf: null,
                noteSet: body.note !== undefined,
              },
            },
            tx,
          );
        }
        const perConnection = new Map<bigint, number>();
        for (const r of resolved) {
          perConnection.set(r.apiConnectionId, (perConnection.get(r.apiConnectionId) ?? 0) + 1);
        }
        for (const [apiConnectionId, n] of perConnection) {
          await this.repository.addReportsResolved(tx, scope, apiConnectionId, n, now);
        }
        const after = await this.repository.report(scope, publicId, tx);
        if (after === null) throw reportNotFound();
        const sizes =
          after.groupKey === null
            ? new Map<string, number>()
            : await this.repository.groupSizes(scope, [after.groupKey], tx);
        return {
          statusCode: 200,
          body: {
            report: this.reportView(
              after,
              after.groupKey === null ? 1 : (sizes.get(after.groupKey) ?? 1),
            ),
            groupResolved: Math.max(0, resolved.length - (decision.to === 'resolved' ? 1 : 0)),
            feedbackQueued,
          },
        };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  // ---- clawback from a report (C14 #14) ---------------------------------------------------------

  /** `POST /api-mode/reports/{reportId}/clawback` (keyed; 202). */
  async clawback(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<ReportClawbackResponseView>> {
    const publicId = parsePublicId(input.id, 'reportId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(ReportClawbackBodySchema, input.body);
    const operation = API_MODE_OPERATIONS.reportClawback;
    return this.idempotency.execute<ReportClawbackResponseView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body }),
      },
      async (tx) => {
        const row = await this.repository.lockReport(tx, scope, publicId);
        if (row === null) throw reportNotFound();
        if (row.status === 'rejected') throw reportStateConflict(row.status, null);
        const now = this.now();
        const built = buildReportCriteria({
          original: originalOf(row.original),
          reportedAt: row.reportedAt,
          expand: body.expand ?? null,
          now,
          maxWindowDays: this.config.API_MODE_CLAWBACK_MAX_WINDOW_DAYS,
        });
        if (!built.ok) {
          if (built.code === 'original_unknown') throw reportOriginalUnknown();
          throw clawbackCriteriaInvalid(built.codes);
        }
        const signal = clawbackSignalSchema.parse({
          v: 1,
          kind: built.trigger,
          refs: { reportId: row.publicId },
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
          requestedByUserId: principal.kind === 'user' ? principal.userId : null,
          requestReason: body.reason,
          reportId: row.id,
          seedCopyId: null,
          seedCopyReceivedAt: null,
          now,
        });
        if (
          !(await this.repository.updateReport(tx, scope, row.id, row.rowVersion, {
            clawbackId: created.id,
          }))
        ) {
          throw reportStateConflict(row.status, row.rowVersion);
        }
        const record = (action: string, resourceType: string, resourceId: string) =>
          this.audit.record(
            {
              organizationId: scope.organizationId,
              actor: this.audit.actorFrom(principal),
              action,
              resourceType,
              resourceId,
              sourceIp,
              metadata: {
                reportId: row.publicId,
                clawbackId: created.publicId,
                trigger: built.trigger,
                criteriaSha256,
                keys: Object.fromEntries(
                  Object.entries(built.criteria.keys)
                    .filter(([, v]) => v !== undefined)
                    .map(([k, v]) => [k, Array.isArray(v) ? v.length : 1]),
                ),
                window: built.criteria.window,
                reason: body.reason,
              },
            },
            tx,
          );
        await record(
          API_MODE_AUDIT.reportClawbackRequested,
          API_MODE_RESOURCES.report,
          row.publicId,
        );
        await record(API_MODE_AUDIT.clawbackCreated, API_MODE_RESOURCES.clawback, created.publicId);
        return {
          statusCode: 202,
          body: {
            reportId: row.publicId,
            clawbackId: created.publicId,
            status: 'searching',
            trigger: built.trigger,
          },
        };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  // ---- report mailboxes (C14 #15-#17) -----------------------------------------------------------

  /** `GET /api-mode/report-mailboxes`. */
  async mailboxes(scope: TenantScope): Promise<ReportMailboxListView> {
    const rows = await this.repository.reportMailboxes(scope);
    return {
      data: rows.map((r) => this.mailboxView(r)),
      max: this.config.API_MODE_REPORT_MAILBOXES_MAX,
    };
  }

  /** `POST /api-mode/report-mailboxes` (C9.1 by address; keyed). */
  async addMailbox(
    principal: Principal,
    scope: TenantScope,
    input: { idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<ReportMailboxChangeView>> {
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(AddReportMailboxBodySchema, input.body);
    const address = normalizeAddress(body.address);
    const operation = API_MODE_OPERATIONS.reportMailboxAdd;
    return this.idempotency.execute<ReportMailboxChangeView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: 'report-mailboxes',
        fingerprint: requestFingerprint({ operation, resourceId: 'report-mailboxes', body }),
      },
      async (tx) => {
        if (address === null) throw reportAddressOutOfScope();
        if (!(await this.repository.lockOrganization(tx, scope))) throw organizationNotFound();
        let mailbox = await this.repository.lockMailboxByAddress(tx, scope, address);
        let created = false;
        if (mailbox === null) {
          const domain = await this.repository.domainForReportAddress(
            tx,
            scope,
            address.slice(address.lastIndexOf('@') + 1),
          );
          if (domain === null || !domain.apiSide || domain.apiConnectionId === null) {
            throw reportAddressOutOfScope();
          }
          const designated = await this.repository.countReportMailboxes(tx, scope);
          if (designated >= this.config.API_MODE_REPORT_MAILBOXES_MAX) {
            throw reportMailboxLimit(this.config.API_MODE_REPORT_MAILBOXES_MAX);
          }
          const publicId = await this.repository.createDiscoveredMailbox(tx, scope, {
            apiConnectionId: domain.apiConnectionId,
            address,
            domainId: domain.id,
            now: this.now(),
          });
          mailbox = await this.repository.lockMailbox(tx, scope, publicId);
          created = true;
        }
        if (mailbox === null) throw reportAddressOutOfScope();
        return {
          statusCode: 200,
          body: await this.designate(tx, principal, scope, mailbox, true, body.reason, sourceIp, {
            created,
          }),
        };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  /** `PUT /api-mode/mailboxes/{mailboxId}/report-mailbox` (C9.1; keyed). */
  async setMailbox(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<ReportMailboxChangeView>> {
    const publicId = parsePublicId(input.id, 'mailboxId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(SetReportMailboxBodySchema, input.body);
    const operation = API_MODE_OPERATIONS.reportMailboxSet;
    return this.idempotency.execute<ReportMailboxChangeView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body }),
      },
      async (tx) => {
        if (!(await this.repository.lockOrganization(tx, scope))) throw organizationNotFound();
        const mailbox = await this.repository.lockMailbox(tx, scope, publicId);
        if (mailbox === null) throw mailboxNotFound();
        return {
          statusCode: 200,
          body: await this.designate(
            tx,
            principal,
            scope,
            mailbox,
            body.enabled,
            body.reason,
            sourceIp,
            { created: false },
          ),
        };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  private async designate(
    tx: Tx,
    principal: Principal,
    scope: TenantScope,
    mailbox: ReportMailboxRow,
    enabled: boolean,
    reason: string,
    sourceIp: string | null,
    o: { created: boolean },
  ): Promise<ReportMailboxChangeView> {
    const decision = decideReportMailbox({
      enabled,
      current: mailbox.reportMailbox,
      mailboxStatus: mailbox.status,
      domainApiSide: mailbox.domain?.apiSide ?? false,
      designatedCount: enabled ? await this.repository.countReportMailboxes(tx, scope) : 0,
      max: this.config.API_MODE_REPORT_MAILBOXES_MAX,
    });
    if (!decision.ok) {
      if (decision.code === 'limit') throw reportMailboxLimit(decision.max);
      throw reportMailboxNotEligible(decision.cause);
    }
    if (decision.change) {
      await this.repository.setReportMailbox(tx, scope, mailbox.id, enabled, this.now());
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: API_MODE_AUDIT.reportMailboxUpdated,
          resourceType: API_MODE_RESOURCES.mailbox,
          resourceId: mailbox.publicId,
          sourceIp,
          metadata: {
            mailboxId: mailbox.publicId,
            enabled,
            created: o.created,
            connectionId: mailbox.connectionPublicId,
            reason,
          },
        },
        tx,
      );
    }
    const after = await this.repository.lockMailbox(tx, scope, mailbox.publicId);
    if (after === null) throw mailboxNotFound();
    return { mailbox: this.mailboxView(after), created: o.created, changed: decision.change };
  }
}
