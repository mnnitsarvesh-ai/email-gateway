import { uuidv7 } from '@email-gateway/common';
import { Prisma, type MessageVerdict, type RiskLevel } from '@email-gateway/database';
import { big, type Db } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';
import { requestThrottledAlert } from '../shared/alerts';
import { hardBlockIds } from '../remediation/decide';

/** `notification_alert_windows.scope_key` of the `api_mode_report_received` alert (C13). */
export const REPORT_ALERT_SCOPE = 'api-mode-reports';
export const REPORT_ALERT_KIND = 'api_mode_report_received';
/**
 * `api_user_reports.last_error_code` of a report the reports role moved to triage because its
 * ingested original's scan was overdue (`API_MODE_REPORT_SCAN_TIMEOUT_MINUTES`).
 */
export const REPORT_SCAN_TIMEOUT_CODE = 'original_scan_timeout';

/**
 * The lower-case addr-spec of a header value (`Name <local@domain>` or a bare address), else null.
 * Display names and comments are dropped (no content is stored, C-I6).
 */
export function addrSpecOf(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const text = raw.trim();
  const angle = /<([^<>\s]+@[^<>\s]+)>/.exec(text);
  const candidate = (angle ? angle[1]! : text).trim().toLowerCase();
  const at = candidate.lastIndexOf('@');
  if (at <= 0 || at === candidate.length - 1 || /\s/.test(candidate)) return null;
  return candidate.slice(0, 320);
}

/** C9.2: the reporter address — header From addr-spec, else the envelope sender (lower case). */
export function reporterAddressOf(headerFrom: string | null, envelopeFrom: string): string {
  return addrSpecOf(headerFrom) ?? addrSpecOf(envelopeFrom) ?? '';
}

/**
 * C9.2 intake (copies role, inside the ledger transaction): an `api_user_reports` row for a copy
 * recorded in a report mailbox — `INSERT IGNORE` on UNIQUE (report_copy_id,
 * report_copy_received_at), status `received`, due now. True when a row was created (a duplicate
 * copy creates nothing).
 */
export async function recordUserReport(
  tx: Prisma.TransactionClient,
  input: {
    organizationId: bigint;
    apiConnectionId: bigint;
    mailboxId: bigint;
    copy: { id: bigint; receivedAt: Date };
    messageId: bigint;
    reporterAddress: string;
    now: Date;
  },
): Promise<boolean> {
  const inserted = await tx.$executeRaw`
    INSERT IGNORE INTO api_user_reports
      (public_id, organization_id, api_connection_id, report_mailbox_id, report_copy_id,
       report_copy_received_at, report_message_id, reporter_address, status, reported_at,
       attempts, next_attempt_at, row_version, created_at, updated_at)
    VALUES (${uuidv7(input.now.getTime())}, ${input.organizationId}, ${input.apiConnectionId},
            ${input.mailboxId}, ${input.copy.id}, ${input.copy.receivedAt}, ${input.messageId},
            ${input.reporterAddress.slice(0, 320)}, 'received', ${input.copy.receivedAt}, 0,
            ${input.now}, 1, ${input.now}, ${input.now})`;
  return inserted === 1;
}

/** Scan facts of a message (C10.3, C10.5): the latest risk row (optionally of one scan). */
export interface MessageScanFacts {
  verdict: MessageVerdict | null;
  score: number | null;
  level: RiskLevel | null;
  hardBlocks: string[];
}

/**
 * The latest `message_risk_scores` row of a message (highest scan, then revision; or the highest
 * revision of `scanId`), organization echo-checked; null when the message has none.
 */
export async function latestRiskFacts(
  db: Db,
  message: { id: bigint; receivedAt: Date; organizationId: bigint },
  scanId: bigint | null = null,
): Promise<MessageScanFacts | null> {
  const rows = await db.$queryRaw<
    Array<{
      organization_id: bigint | number;
      verdict: MessageVerdict | null;
      score: number | null;
      level: RiskLevel | null;
      hard_blocks: unknown;
    }>
  >`
    SELECT organization_id, verdict, score, level, hard_blocks FROM message_risk_scores
    WHERE message_id = ${message.id} AND received_at = ${message.receivedAt}
      ${scanId === null ? Prisma.empty : Prisma.sql`AND scan_id = ${scanId}`}
    ORDER BY scan_id DESC, revision DESC
    LIMIT 1`;
  const row = rows[0];
  if (!row) return null;
  if (big(row.organization_id) !== message.organizationId) {
    throw new InconsistentReadError('message_risk_scores');
  }
  const blocks = typeof row.hard_blocks === 'string' ? safeJson(row.hard_blocks) : row.hard_blocks;
  return {
    verdict: row.verdict ?? null,
    score: row.score === null ? null : Number(row.score),
    level: row.level ?? null,
    hardBlocks: hardBlockIds(blocks),
  };
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

/**
 * C13: the `api_mode_report_received` alert when new reports reached `pending_triage` — at most
 * once per organization per `API_MODE_REPORT_ALERT_MIN_INTERVAL_MINUTES` (throttle window, scope
 * `api-mode-reports`), in the caller's transaction. No refs (the kind needs none).
 */
export function requestReportAlert(
  tx: Prisma.TransactionClient,
  input: { organizationId: bigint; windowMinutes: number; now: Date },
): Promise<boolean> {
  return requestThrottledAlert(tx, {
    organizationId: input.organizationId,
    kind: REPORT_ALERT_KIND,
    scopeKey: REPORT_ALERT_SCOPE,
    windowMinutes: input.windowMinutes,
    severity: 'medium',
    refs: {},
    correlationId: `api-mode-reports:${input.organizationId.toString()}`,
    now: input.now,
  });
}
