import { createHash } from 'node:crypto';
import { uuidv7, withTransactionDefaults } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import { EventTypes, reportFeedbackRequestedV1 } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import {
  assessReport,
  buildReportOriginal,
  classifyRecipientDirection,
  extractReportedMessage,
  reportEnvelopeHeaders,
  reporterCheck,
  reportGroupKey,
  reportIdentificationOf,
  type ReportOriginal,
} from '@email-gateway/mailbox-api';
import type { HeaderReader } from '../copies/header-reader';
import { domainForAddress, loadOrgApiModeState } from '../domain/api-mode-state';
import { findMailboxByAddress } from '../domain/mailboxes';
import { loadOrgSettings } from '../domain/org-settings';
import type { EmlSink } from '../feeds/eml-sink';
import type { MailboxMetrics, ReportResult } from '../metrics/mailbox-metrics';
import type { MailboxRedis } from '../runtime/redis-stores';
import { big, TX_MAX_WAIT_MS, TX_OPTIONS, TX_TIMEOUT_MS } from '../shared/db';
import { errorCode, errorFields, InconsistentReadError } from '../shared/errors';
import {
  latestRiskFacts,
  REPORT_SCAN_TIMEOUT_CODE,
  requestReportAlert,
  type MessageScanFacts,
} from './report-intake';
import { ReportOriginalRepository, reportOriginalObjectKey } from './report-original.repository';

/** Claim lease and batch of the `reports` role (C10.1). */
export const REPORT_LEASE_SECONDS = 120;
export const REPORT_BATCH = 20;
/** Inline forwards are matched by sender + subject key within ± this window (C10.3). */
export const INLINE_MATCH_WINDOW_MS = 72 * 3_600_000;
/** Back-off of a transient failure (S3, database): 30 s × 2^attempts, capped at one hour. */
const RETRY_BASE_MS = 30_000;
const RETRY_MAX_MS = 3_600_000;

const RATE_SCRIPT = `
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], 7200) end
return n`;

export interface ReportsConfig {
  /** `API_MODE_REPORT_MAX_BYTES`. */
  maxBytes: number;
  /** `API_MODE_MAX_MESSAGE_BYTES` (the decoded original). */
  maxOriginalBytes: number;
  headerMaxBytes: number;
  /** `API_MODE_REPORTS_PER_REPORTER_PER_HOUR`. */
  perReporterPerHour: number;
  /** `API_MODE_REPORT_ALERT_MIN_INTERVAL_MINUTES`. */
  alertMinIntervalMinutes: number;
  /** `API_MODE_REPORT_SCAN_TIMEOUT_MINUTES`: an ingested original's scan is overdue after this. */
  scanTimeoutMinutes: number;
}

export interface ReportsDeps {
  prisma: PrismaClient;
  redis: MailboxRedis;
  /** Bounded reads of the report copy's EML (mail bucket). */
  reader: HeaderReader;
  sink: EmlSink;
  metrics: MailboxMetrics | null;
  logger: Logger;
  now: () => Date;
  config: ReportsConfig;
  organizationIds?: readonly bigint[];
}

interface ClaimedReport {
  id: bigint;
  organizationId: bigint;
  rowVersion: number;
}

interface ReportRow {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  apiConnectionId: bigint;
  reportMailboxId: bigint;
  reportCopyId: bigint;
  reportCopyReceivedAt: Date;
  reportMessageId: bigint;
  reporterAddress: string;
  attempts: number;
  reportedAt: Date;
  rowVersion: number;
}

/** What the processing of one report decided (written in one transaction). */
interface ReportOutcome {
  status: 'pending_triage' | 'rejected';
  rejectReason?: string;
  identification?: string | null;
  original?: ReportOriginal | null;
  groupKey?: string | null;
  originalCopy?: { id: bigint; receivedAt: Date } | null;
  originalMessage?: { id: bigint; receivedAt: Date } | null;
  scan?: MessageScanFacts | null;
  reporterMailboxId?: bigint | null;
  reporterUserId?: bigint | null;
  result: ReportResult;
}

/**
 * The `reports` role (step API-3, note 37 C10; ADR-0104). Every `API_MODE_REPORTS_TICK_MS` it
 * claims `received` reports (lease 120 s, batch 20, `FOR UPDATE SKIP LOCKED`, CAS on
 * `row_version`; an expired `parsing` lease is re-claimed) and per report:
 *
 * 1. reporter checks (`reporterCheck`: organization-side reporter, no report-mailbox loop, no
 *    auto-reply) and the per-reporter rate limit (Redis `mbx:rpt:<org>:<sha256(address)>:<hour>`,
 *    `API_MODE_REPORTS_PER_REPORTER_PER_HOUR`) → `rejected` with the reason, no feedback;
 * 2. the report copy's EML read from the mail bucket (bounded by `API_MODE_REPORT_MAX_BYTES`) and
 *    `extractReportedMessage` (attachment, inline, unsupported, none); the original document
 *    (`api-report-original/1`) with URL hashes from the report message's `message_urls` and —
 *    without an attached original — attachment hashes from its `email_attachments`;
 * 3. the original's recorded copy: by Message-ID hash in the reporter's mailbox first, then the
 *    whole tenant; an inline forward without Message-ID by sender + subject key within ± 72 h;
 *    found → its message's latest risk facts, `pending_triage`;
 * 4. an attached original not found → written to the mail bucket and committed as a
 *    `mailbox_api` registry message without a copy row (`ReportOriginalRepository`, ingest key
 *    `v2:rpt:…`), report `scanning`; the copies role stores the scan later;
 * 5. none/unsupported or not found → the report copy's own scan, `pending_triage`.
 *
 * A `scanning` report whose original's scan has not arrived by its deadline (`next_attempt_at`,
 * `API_MODE_REPORT_SCAN_TIMEOUT_MINUTES` after the ingest; the scan event lost, dead-lettered or
 * never emitted) moves to `pending_triage` with the original's latest risk row if one exists,
 * else the report copy's own scan (C10.5 fallback), `last_error_code = original_scan_timeout`,
 * so it can always be triaged; a scan arriving later still updates its facts (copies role).
 *
 * Leaving `received` (not rejected) with `report_ack_enabled` writes the acknowledgement
 * `mail.report.feedback_requested.v1` (kind `received`); reaching `pending_triage` requests the
 * throttled `api_mode_report_received` alert. Reports never remediate (C-I5) and the role never
 * calls a provider (C-I1). Tenant from the report row; every read echo-checked; content-free.
 */
export class ReportsRunner {
  private readonly txPrisma: PrismaClient;
  private readonly originals: ReportOriginalRepository;

  constructor(private readonly deps: ReportsDeps) {
    this.txPrisma = withTransactionDefaults(deps.prisma, {
      timeoutMs: TX_TIMEOUT_MS,
      maxWaitMs: TX_MAX_WAIT_MS,
    });
    this.originals = new ReportOriginalRepository(deps.prisma);
  }

  async tick(): Promise<boolean> {
    const claimed = await this.claim();
    for (const claim of claimed) {
      try {
        await this.process(claim);
      } catch (error) {
        await this.retryLater(claim, error);
      }
    }
    const overdue = await this.sweepOverdueScans();
    return claimed.length >= REPORT_BATCH || overdue >= REPORT_BATCH;
  }

  /**
   * `scanning` reports past their scan deadline (`next_attempt_at`; a row without one counts
   * from `updated_at`) → `pending_triage` with the best scan facts available, the reason
   * `original_scan_timeout` and the throttled alert, one transaction each (CAS on
   * `row_version`). Returns the reports examined.
   */
  async sweepOverdueScans(): Promise<number> {
    const now = this.deps.now();
    const legacy = new Date(now.getTime() - this.deps.config.scanTimeoutMinutes * 60_000);
    const orgs = this.deps.organizationIds
      ? Prisma.sql`AND organization_id IN (${Prisma.join(this.deps.organizationIds)})`
      : Prisma.empty;
    const rows = await this.deps.prisma.$queryRaw<Array<{ id: bigint | number }>>`
      SELECT id FROM api_user_reports
      WHERE status = 'scanning'
        AND (next_attempt_at <= ${now} OR (next_attempt_at IS NULL AND updated_at <= ${legacy}))
        ${orgs}
      ORDER BY id
      LIMIT ${REPORT_BATCH}`;
    for (const r of rows) {
      try {
        await this.timeoutScan(big(r.id));
      } catch (error) {
        this.deps.logger.warn(
          { reportId: big(r.id).toString(), ...errorFields(error) },
          'overdue report scan not resolved; retried next tick',
        );
      }
    }
    return rows.length;
  }

  private async timeoutScan(id: bigint): Promise<void> {
    const prisma = this.deps.prisma;
    const report = await prisma.apiUserReport.findUnique({
      where: { id },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        status: true,
        rowVersion: true,
        reportedAt: true,
        reportMessageId: true,
        reportCopyId: true,
        reportCopyReceivedAt: true,
        originalMessageId: true,
        originalReceivedAt: true,
      },
    });
    if (!report || report.status !== 'scanning') return;
    const org = report.organizationId;
    const originalScan =
      report.originalMessageId !== null && report.originalReceivedAt !== null
        ? await latestRiskFacts(prisma, {
            id: report.originalMessageId,
            receivedAt: report.originalReceivedAt,
            organizationId: org,
          })
        : null;
    const scan =
      originalScan ??
      (await this.copyScan(
        {
          id: report.reportMessageId,
          receivedAt: report.reportCopyReceivedAt,
          organizationId: org,
        },
        report.reportCopyId,
      ));
    const assessment = assessReport(
      scan === null || scan.verdict === null
        ? null
        : { verdict: scan.verdict, level: scan.level, hardBlocks: scan.hardBlocks },
    );
    const score = scan?.score ?? null;
    const now = this.deps.now();
    const moved = await this.txPrisma.$transaction(async (tx) => {
      const n = await tx.$executeRaw`
        UPDATE api_user_reports
        SET status = 'pending_triage', scan_verdict = ${scan?.verdict ?? null},
            scan_risk_score = ${score === null ? null : Math.min(65_535, Math.max(0, score))},
            scan_level = ${scan?.level ?? null}, assessment = ${assessment},
            next_attempt_at = NULL, last_error_code = ${REPORT_SCAN_TIMEOUT_CODE},
            row_version = row_version + 1, updated_at = ${now}
        WHERE id = ${report.id} AND organization_id = ${org}
          AND status = 'scanning' AND row_version = ${report.rowVersion}`;
      if (n !== 1) return false;
      await requestReportAlert(tx, {
        organizationId: org,
        windowMinutes: this.deps.config.alertMinIntervalMinutes,
        now,
      });
      return true;
    });
    if (!moved) return;
    const m = this.deps.metrics;
    m?.report('scan_timeout');
    m?.report('pending_triage');
    m?.reportTriage.observe(Math.max(0, (now.getTime() - report.reportedAt.getTime()) / 1000));
    this.deps.logger.warn(
      {
        reportId: report.publicId,
        fallback: originalScan !== null ? 'original_risk' : 'report_copy',
      },
      'reported original not scanned in time; report moved to triage',
    );
  }

  /** C10.1: due `received` reports (and `parsing` ones whose lease expired) → `parsing`. */
  private async claim(): Promise<ClaimedReport[]> {
    const now = this.deps.now();
    const leaseUntil = new Date(now.getTime() + REPORT_LEASE_SECONDS * 1000);
    const orgs = this.deps.organizationIds
      ? Prisma.sql`AND organization_id IN (${Prisma.join(this.deps.organizationIds)})`
      : Prisma.empty;
    return this.deps.prisma.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<
        Array<{ id: bigint | number; organization_id: bigint | number; row_version: number }>
      >`
        SELECT id, organization_id, row_version FROM api_user_reports
        WHERE ((status = 'received' AND (next_attempt_at IS NULL OR next_attempt_at <= ${now})
                AND (lease_until IS NULL OR lease_until < ${now}))
            OR (status = 'parsing' AND lease_until < ${now})) ${orgs}
        ORDER BY id
        LIMIT ${REPORT_BATCH}
        FOR UPDATE SKIP LOCKED`;
      if (rows.length === 0) return [];
      await tx.$executeRaw`
        UPDATE api_user_reports
        SET status = 'parsing', lease_until = ${leaseUntil}, row_version = row_version + 1,
            updated_at = ${now}
        WHERE id IN (${Prisma.join(rows.map((r) => big(r.id)))})`;
      return rows.map((r) => ({
        id: big(r.id),
        organizationId: big(r.organization_id),
        rowVersion: Number(r.row_version) + 1,
      }));
    }, TX_OPTIONS);
  }

  /** A transient failure: back to `received` with back-off (attempts + 1, the error code). */
  private async retryLater(claim: ClaimedReport, error: unknown): Promise<void> {
    const now = this.deps.now();
    const row = await this.deps.prisma.apiUserReport.findUnique({
      where: { id: claim.id },
      select: { attempts: true },
    });
    const attempts = (row?.attempts ?? 0) + 1;
    const delay = Math.min(RETRY_MAX_MS, RETRY_BASE_MS * 2 ** Math.min(attempts, 16));
    this.deps.logger.warn(
      { reportId: claim.id.toString(), attempts, ...errorFields(error) },
      'user report not processed; retried later',
    );
    this.deps.metrics?.report('failed');
    await this.deps.prisma.$executeRaw`
      UPDATE api_user_reports
      SET status = 'received', lease_until = NULL, attempts = LEAST(attempts + 1, 65535),
          next_attempt_at = ${new Date(now.getTime() + delay)},
          last_error_code = ${errorCode(error, 'internal_error').slice(0, 64)},
          row_version = row_version + 1, updated_at = ${now}
      WHERE id = ${claim.id} AND row_version = ${claim.rowVersion} AND status = 'parsing'`;
  }

  async process(claim: ClaimedReport): Promise<void> {
    const prisma = this.deps.prisma;
    const report = await prisma.apiUserReport.findUnique({
      where: { id: claim.id },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        apiConnectionId: true,
        reportMailboxId: true,
        reportCopyId: true,
        reportCopyReceivedAt: true,
        reportMessageId: true,
        reporterAddress: true,
        attempts: true,
        reportedAt: true,
        rowVersion: true,
        status: true,
      },
    });
    if (!report || report.rowVersion !== claim.rowVersion || report.status !== 'parsing') return;
    if (report.organizationId !== claim.organizationId) {
      throw new InconsistentReadError('api_user_reports');
    }
    const org = report.organizationId;
    const state = await loadOrgApiModeState(prisma, org);
    const settings = await loadOrgSettings(prisma, org);
    const message = await prisma.emailMessage.findUnique({
      where: {
        id_receivedAt: { id: report.reportMessageId, receivedAt: report.reportCopyReceivedAt },
      },
      select: { organizationId: true, emlObjectKey: true },
    });
    if (message && message.organizationId !== org) {
      throw new InconsistentReadError('email_messages');
    }
    if (!message || !state) {
      await this.finish(report, settings.reportAckEnabled, {
        status: 'rejected',
        rejectReason: 'parse_failed',
        result: 'rejected',
      });
      return;
    }
    const cfg = this.deps.config;
    const bytes = await this.deps.reader.read(
      message.emlObjectKey,
      cfg.maxBytes + 1,
      AbortSignal.timeout(120_000),
    );
    if (bytes === null) throw new ReportObjectMissing();
    if (bytes.length > cfg.maxBytes) {
      await this.finish(report, settings.reportAckEnabled, {
        status: 'rejected',
        rejectReason: 'too_large',
        result: 'rejected',
      });
      return;
    }
    // C10.1 reporter checks, then the rate limit.
    const reportMailboxAddresses = await this.reportMailboxAddresses(org);
    const check = reporterCheck({
      reporterAddress: report.reporterAddress,
      orgDomains: state.domains.map((d) => d.name),
      reportMailboxAddresses,
      headers: reportEnvelopeHeaders(bytes),
    });
    if (!check.ok) {
      await this.finish(report, settings.reportAckEnabled, {
        status: 'rejected',
        rejectReason: check.reason,
        result: 'rejected',
      });
      return;
    }
    if (!(await this.withinRateLimit(org, report.reporterAddress))) {
      await this.finish(report, settings.reportAckEnabled, {
        status: 'rejected',
        rejectReason: 'rate_limited',
        result: 'rejected',
      });
      return;
    }
    const reporterMailbox = await findMailboxByAddress(prisma, org, report.reporterAddress);
    const reporterUser = await prisma.user.findFirst({
      where: { organizationId: org, email: report.reporterAddress, deletedAt: null },
      select: { id: true, organizationId: true },
      orderBy: { id: 'asc' },
    });
    if (reporterUser && reporterUser.organizationId !== org) {
      throw new InconsistentReadError('users');
    }
    const reporter = {
      reporterMailboxId: reporterMailbox?.id ?? null,
      reporterUserId: reporterUser?.id ?? null,
    };

    // C10.2 identification.
    const extraction = extractReportedMessage(bytes, {
      maxBytes: cfg.maxBytes,
      maxOriginalBytes: cfg.maxOriginalBytes,
    });
    if (!extraction.ok) {
      await this.finish(report, settings.reportAckEnabled, {
        status: 'rejected',
        rejectReason: extraction.code,
        result: 'rejected',
        ...reporter,
      });
      return;
    }
    const reportMessage = {
      id: report.reportMessageId,
      receivedAt: report.reportCopyReceivedAt,
      organizationId: org,
    };
    const urls = await this.reportUrls(reportMessage);
    const original = buildReportOriginal({
      organizationId: org,
      extraction,
      urlSha256: urls,
      ...(extraction.identification === 'inline'
        ? { fallbackAttachmentSha256: await this.reportAttachments(reportMessage) }
        : {}),
    });
    const identification = reportIdentificationOf(extraction);
    const groupKey = reportGroupKey(original);
    const identified = { identification, original, groupKey, ...reporter };

    // C10.3 lookup of the original's recorded copy.
    const found = original
      ? await this.findOriginalCopy(org, original, reporterMailbox?.id ?? null, report.reportedAt)
      : null;
    if (found) {
      const scan =
        (await latestRiskFacts(prisma, {
          id: found.messageId,
          receivedAt: found.receivedAt,
          organizationId: org,
        })) ?? found.copyScan;
      await this.finish(report, settings.reportAckEnabled, {
        status: 'pending_triage',
        ...identified,
        originalCopy: { id: found.copyId, receivedAt: found.receivedAt },
        originalMessage: { id: found.messageId, receivedAt: found.receivedAt },
        scan,
        result: 'matched',
      });
      return;
    }
    // C10.4 ingest of an attached original that is not in the tenant.
    if (extraction.identification === 'attachment') {
      await this.ingest(report, settings.reportAckEnabled, extraction, identified, state.domains);
      return;
    }
    // C10.5 no original: the report copy's own scan.
    await this.finish(report, settings.reportAckEnabled, {
      status: 'pending_triage',
      ...identified,
      scan: await this.copyScan(reportMessage, report.reportCopyId),
      result: 'no_original',
    });
  }

  /** Addresses (primary and aliases) of the organization's report mailboxes (C10.1 loop). */
  private async reportMailboxAddresses(organizationId: bigint): Promise<string[]> {
    const mailboxes = await this.deps.prisma.apiMailbox.findMany({
      where: { organizationId, reportMailbox: true },
      select: {
        organizationId: true,
        primaryAddress: true,
        addresses: { select: { address: true } },
      },
      take: 50,
    });
    const out: string[] = [];
    for (const m of mailboxes) {
      if (m.organizationId !== organizationId) throw new InconsistentReadError('api_mailboxes');
      out.push(m.primaryAddress, ...m.addresses.map((a) => a.address));
    }
    return out;
  }

  /** C10.1: at most `API_MODE_REPORTS_PER_REPORTER_PER_HOUR` reports per reporter per hour. */
  private async withinRateLimit(organizationId: bigint, address: string): Promise<boolean> {
    const hour = Math.floor(this.deps.now().getTime() / 3_600_000);
    const digest = createHash('sha256').update(address.toLowerCase(), 'utf8').digest('hex');
    const key = `mbx:rpt:${organizationId.toString()}:${digest}:${hour}`;
    const n = Number(await this.deps.redis.eval(RATE_SCRIPT, 1, key));
    if (!Number.isFinite(n)) throw new Error('report_rate_limit_unavailable');
    return n <= this.deps.config.perReporterPerHour;
  }

  /** URL identity hashes of the report message (`message_urls`, ≤ 50, C10.2). */
  private async reportUrls(m: { id: bigint; receivedAt: Date; organizationId: bigint }) {
    const rows = await this.deps.prisma.$queryRaw<
      Array<{ url_sha256: string; organization_id: bigint | number }>
    >`
      SELECT url_sha256, organization_id FROM message_urls
      WHERE message_id = ${m.id} AND received_at = ${m.receivedAt}
      ORDER BY url_seq LIMIT 50`;
    return rows.map((r) => {
      if (big(r.organization_id) !== m.organizationId) {
        throw new InconsistentReadError('message_urls');
      }
      return r.url_sha256;
    });
  }

  /** Attachment hashes of the report message (`email_attachments`, ≤ 20, inline forwards). */
  private async reportAttachments(m: { id: bigint; receivedAt: Date; organizationId: bigint }) {
    const rows = await this.deps.prisma.$queryRaw<
      Array<{ sha256: string; organization_id: bigint | number }>
    >`
      SELECT sha256, organization_id FROM email_attachments
      WHERE message_id = ${m.id} AND received_at = ${m.receivedAt}
      ORDER BY part_index LIMIT 20`;
    return rows.map((r) => {
      if (big(r.organization_id) !== m.organizationId) {
        throw new InconsistentReadError('email_attachments');
      }
      return r.sha256;
    });
  }

  /**
   * C10.3: the original's recorded copy — by Message-ID hash in the reporter's mailbox, then the
   * whole tenant (most recent; report mailboxes excluded); an inline forward without Message-ID
   * by sender + subject key within ± 72 h of its date in the reporter's mailbox.
   */
  private async findOriginalCopy(
    organizationId: bigint,
    original: ReportOriginal,
    reporterMailboxId: bigint | null,
    reportedAt: Date,
  ): Promise<{
    copyId: bigint;
    receivedAt: Date;
    messageId: bigint;
    copyScan: MessageScanFacts;
  } | null> {
    type Row = {
      id: bigint | number;
      received_at: Date;
      message_id: bigint | number;
      organization_id: bigint | number;
      verdict: MessageScanFacts['verdict'];
      risk_score: number | null;
    };
    const pick = (rows: Row[]) => {
      const r = rows[0];
      if (!r) return null;
      if (big(r.organization_id) !== organizationId) {
        throw new InconsistentReadError('api_message_copies');
      }
      return {
        copyId: big(r.id),
        receivedAt: r.received_at,
        messageId: big(r.message_id),
        copyScan: {
          verdict: r.verdict,
          score: r.risk_score === null ? null : Number(r.risk_score),
          level: null,
          hardBlocks: [],
        },
      };
    };
    const notReport = Prisma.sql`AND EXISTS (
      SELECT 1 FROM api_mailboxes m WHERE m.id = c.mailbox_id
        AND m.organization_id = c.organization_id AND m.report_mailbox = 0)`;
    if (original.messageIdHash !== null) {
      if (reporterMailboxId !== null) {
        const own = pick(
          await this.deps.prisma.$queryRaw<Row[]>`
            SELECT c.id, c.received_at, c.message_id, c.organization_id, c.verdict, c.risk_score
            FROM api_message_copies c
            WHERE c.organization_id = ${organizationId}
              AND c.message_id_hash = ${original.messageIdHash}
              AND c.mailbox_id = ${reporterMailboxId}
            ORDER BY c.received_at DESC, c.id DESC LIMIT 1`,
        );
        if (own) return own;
      }
      const tenant = pick(
        await this.deps.prisma.$queryRaw<Row[]>`
          SELECT c.id, c.received_at, c.message_id, c.organization_id, c.verdict, c.risk_score
          FROM api_message_copies c
          WHERE c.organization_id = ${organizationId}
            AND c.message_id_hash = ${original.messageIdHash} ${notReport}
          ORDER BY c.received_at DESC, c.id DESC LIMIT 1`,
      );
      if (tenant) return tenant;
    }
    if (
      original.messageIdHash === null &&
      original.sender !== null &&
      original.subjectKey !== null &&
      reporterMailboxId !== null
    ) {
      const around = original.date === null ? reportedAt : new Date(original.date);
      const from = new Date(around.getTime() - INLINE_MATCH_WINDOW_MS);
      const to = new Date(around.getTime() + INLINE_MATCH_WINDOW_MS);
      return pick(
        await this.deps.prisma.$queryRaw<Row[]>`
          SELECT c.id, c.received_at, c.message_id, c.organization_id, c.verdict, c.risk_score
          FROM email_messages e
          JOIN api_message_copies c
            ON c.message_id = e.id AND c.received_at = e.received_at
          WHERE e.organization_id = ${organizationId}
            AND e.header_from = ${original.sender}
            AND e.received_at >= ${from} AND e.received_at <= ${to}
            AND e.subject_key = ${original.subjectKey}
            AND c.organization_id = ${organizationId} AND c.mailbox_id = ${reporterMailboxId}
            AND c.received_at >= ${from} AND c.received_at <= ${to}
          ORDER BY c.received_at DESC, c.id DESC LIMIT 1`,
      );
    }
    return null;
  }

  /** C10.5: the report copy's own scan (its latest risk row, else the copy's verdict). */
  private async copyScan(
    m: { id: bigint; receivedAt: Date; organizationId: bigint },
    copyId: bigint,
  ): Promise<MessageScanFacts | null> {
    const risk = await latestRiskFacts(this.deps.prisma, m);
    if (risk) return risk;
    const copy = await this.deps.prisma.apiMessageCopy.findUnique({
      where: { id_receivedAt: { id: copyId, receivedAt: m.receivedAt } },
      select: { organizationId: true, verdict: true, riskScore: true },
    });
    if (!copy) return null;
    if (copy.organizationId !== m.organizationId) {
      throw new InconsistentReadError('api_message_copies');
    }
    return copy.verdict === null
      ? null
      : { verdict: copy.verdict, score: copy.riskScore, level: null, hardBlocks: [] };
  }

  /** C10.4: the attached original into the mail bucket and the registry; report `scanning`. */
  private async ingest(
    report: ReportRow,
    ackEnabled: boolean,
    extraction: Extract<
      ReturnType<typeof extractReportedMessage>,
      { identification: 'attachment' }
    >,
    identified: Pick<
      ReportOutcome,
      'identification' | 'original' | 'groupKey' | 'reporterMailboxId' | 'reporterUserId'
    >,
    domains: Parameters<typeof domainForAddress>[0],
  ): Promise<void> {
    const org = report.organizationId;
    const now = this.deps.now();
    const key = reportOriginalObjectKey(org, report.publicId, now);
    const stored = await this.deps.sink.put(key, single(extraction.original), {
      maxBytes: this.deps.config.maxOriginalBytes,
      headerMaxBytes: this.deps.config.headerMaxBytes,
      signal: AbortSignal.timeout(120_000),
    });
    const sender = extraction.headers.from;
    const direction = classifyRecipientDirection(
      sender,
      report.reporterAddress,
      domains.map((d) => d.name),
    );
    const result = await this.originals.commit(
      {
        organizationId: org,
        report: { id: report.id, publicId: report.publicId, rowVersion: report.rowVersion },
        reporterAddress: report.reporterAddress,
        domainId: domainForAddress(domains, report.reporterAddress)?.id ?? null,
        receivedAt: now,
        direction,
        internetMessageId: extraction.headers.messageId,
        headerFrom: sender,
        subject: extraction.headers.subject,
        sizeBytes: stored.sizeBytes,
        emlObjectKey: key,
        emlSha256: stored.sha256,
        scanDeadline: new Date(now.getTime() + this.deps.config.scanTimeoutMinutes * 60_000),
      },
      async (tx) => {
        await this.writeIdentification(tx, report, identified, now);
        await this.ack(tx, report, ackEnabled, now);
      },
    );
    if (result.status !== 'lost') {
      this.deps.metrics?.report('ingested');
      this.deps.logger.info(
        { reportId: report.publicId, status: result.status },
        'reported original ingested for a detect-mode scan',
      );
    }
  }

  /** The identification columns (C10.2) of a report, in the caller's transaction. */
  private async writeIdentification(
    tx: Prisma.TransactionClient,
    report: ReportRow,
    o: Pick<
      ReportOutcome,
      'identification' | 'original' | 'groupKey' | 'reporterMailboxId' | 'reporterUserId'
    >,
    now: Date,
  ): Promise<void> {
    await tx.$executeRaw`
      UPDATE api_user_reports
      SET identification = ${o.identification ?? null},
          original = ${o.original ? JSON.stringify(o.original) : null},
          original_message_id_hash = ${o.original?.messageIdHash ?? null},
          group_key = ${o.groupKey ?? null},
          reporter_mailbox_id = ${o.reporterMailboxId ?? null},
          reporter_user_id = ${o.reporterUserId ?? null}, updated_at = ${now}
      WHERE id = ${report.id} AND organization_id = ${report.organizationId}`;
  }

  /** C10.6: the acknowledgement outbox row (`kind = received`) when enabled; else skipped. */
  private async ack(
    tx: Prisma.TransactionClient,
    report: ReportRow,
    enabled: boolean,
    now: Date,
  ): Promise<void> {
    if (!enabled) {
      await tx.$executeRaw`
        UPDATE api_user_reports SET ack_feedback = 'skipped'
        WHERE id = ${report.id} AND organization_id = ${report.organizationId}`;
      return;
    }
    const payload = reportFeedbackRequestedV1.parse({
      reportId: report.publicId,
      kind: 'received',
      requestedAt: now.toISOString(),
    });
    await tx.messageOutbox.create({
      data: {
        eventId: uuidv7(now.getTime()),
        organizationId: report.organizationId,
        eventType: EventTypes.ReportFeedbackRequested,
        aggregateType: 'organization',
        aggregateId: report.organizationId.toString(),
        correlationId: `rpt:${report.publicId}`,
        payload,
      },
      select: { id: true },
    });
    await tx.$executeRaw`
      UPDATE api_user_reports SET ack_feedback = 'queued'
      WHERE id = ${report.id} AND organization_id = ${report.organizationId}`;
  }

  /**
   * The end of automatic processing in one transaction (CAS on the claimed `row_version`):
   * `rejected` (no feedback, `ack_feedback = skipped`) or `pending_triage` with the original,
   * group key, scan facts and assessment (C11.2), the acknowledgement and the throttled alert.
   */
  private async finish(report: ReportRow, ackEnabled: boolean, o: ReportOutcome): Promise<void> {
    const now = this.deps.now();
    const scan = o.scan ?? null;
    const assessment =
      o.status === 'pending_triage'
        ? assessReport(
            scan === null || scan.verdict === null
              ? null
              : { verdict: scan.verdict, level: scan.level, hardBlocks: scan.hardBlocks },
          )
        : null;
    const score = scan?.score ?? null;
    const done = await this.txPrisma.$transaction(async (tx) => {
      const n = await tx.$executeRaw`
        UPDATE api_user_reports
        SET status = ${o.status}, reject_reason = ${o.rejectReason ?? null},
            original_copy_id = ${o.originalCopy?.id ?? null},
            original_copy_received_at = ${o.originalCopy?.receivedAt ?? null},
            original_message_id = ${o.originalMessage?.id ?? null},
            original_received_at = ${o.originalMessage?.receivedAt ?? null},
            scan_verdict = ${scan?.verdict ?? null},
            scan_risk_score = ${score === null ? null : Math.min(65_535, Math.max(0, score))},
            scan_level = ${scan?.level ?? null}, assessment = ${assessment},
            lease_until = NULL, next_attempt_at = NULL, last_error_code = NULL,
            row_version = row_version + 1, updated_at = ${now}
        WHERE id = ${report.id} AND organization_id = ${report.organizationId}
          AND row_version = ${report.rowVersion} AND status = 'parsing'`;
      if (n !== 1) return false;
      await this.writeIdentification(tx, report, o, now);
      if (o.status === 'rejected') {
        await tx.$executeRaw`
          UPDATE api_user_reports SET ack_feedback = 'skipped'
          WHERE id = ${report.id} AND organization_id = ${report.organizationId}`;
        return true;
      }
      await this.ack(tx, report, ackEnabled, now);
      await requestReportAlert(tx, {
        organizationId: report.organizationId,
        windowMinutes: this.deps.config.alertMinIntervalMinutes,
        now,
      });
      return true;
    });
    if (!done) return;
    const m = this.deps.metrics;
    m?.report(o.result);
    if (o.status === 'pending_triage') {
      m?.report('pending_triage');
      m?.reportTriage.observe(Math.max(0, (now.getTime() - report.reportedAt.getTime()) / 1000));
    }
    this.deps.logger.info(
      {
        reportId: report.publicId,
        status: o.status,
        rejectReason: o.rejectReason ?? null,
        identification: o.identification ?? null,
        result: o.result,
      },
      'user report processed',
    );
  }
}

/** The report copy's EML is gone (retention or a failed store): retried, then visible. */
class ReportObjectMissing extends Error {
  readonly code = 'report_object_missing';
  constructor() {
    super('report object missing');
    this.name = 'ReportObjectMissing';
  }
}

async function* single(bytes: Uint8Array): AsyncGenerator<Uint8Array> {
  yield await Promise.resolve(bytes);
}
