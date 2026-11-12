import { randomUUID } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';
import type { ApiResponse, ApiSession } from './api-client';
import { waitFor } from './compose';
import type { MessageKey } from './lifecycle';
import { metricValue } from './metrics';

/**
 * Readers and checks of the step 5.3 quarantine store (docs/plan/steps/17-quarantine.md §3, Q3,
 * Q6, Q13, Q19, Q20; ADR-0046–0049) for the stack suites. Entries are written by the
 * policy-engine (evaluation transaction, adoption, executor, sweeper) and by the api (manual
 * quarantine and every user action); everything here reads the MySQL WRITER.
 */

/** Ledger consumer of the release executor on `email.quarantine` (Q13.2). */
export const QUARANTINE_LEDGER = 'policy-engine.quarantine';

/** Entries of a message (every round), by round and recipient sequence. */
export function entriesOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.quarantineMessage.findMany({
    where: { messageId: message.id, messageReceivedAt: message.receivedAt },
    orderBy: [{ lifecycleRound: 'asc' }, { rcptSeq: 'asc' }],
  });
}

export type EntryRow = Awaited<ReturnType<typeof entriesOf>>[number];

/** Waits until round `round` of a message has `count` entries (Q6: one per held recipient). */
export function waitForEntries(
  prisma: PrismaClient,
  message: MessageKey,
  count: number,
  options: { round?: number; timeoutMs?: number } = {},
): Promise<EntryRow[]> {
  const round = options.round ?? 0;
  return waitFor(
    `${count} quarantine entr${count === 1 ? 'y' : 'ies'} of round ${round} of message ${message.id}`,
    async () => {
      const rows = (await entriesOf(prisma, message)).filter((e) => e.lifecycleRound === round);
      return rows.length >= count ? rows : undefined;
    },
    { timeoutMs: options.timeoutMs ?? 180_000, intervalMs: 500 },
  );
}

/** One entry by public id (writer). */
export const entryByPublicId = (prisma: PrismaClient, publicId: string) =>
  prisma.quarantineMessage.findUniqueOrThrow({ where: { publicId } });

/** Waits until an entry is in `state` (`quarantine_messages.status`). */
export function waitForEntryState(
  prisma: PrismaClient,
  publicId: string,
  state: string,
  timeoutMs = 180_000,
): Promise<EntryRow> {
  return waitFor(
    `quarantine entry ${publicId} in ${state}`,
    async () => {
      const row = await entryByPublicId(prisma, publicId);
      return row.status === state ? row : undefined;
    },
    { timeoutMs, intervalMs: 500 },
  );
}

/** Release log rows of one release (one per entry), writer. */
export function releaseLogsOf(prisma: PrismaClient, releasePublicId: string) {
  return prisma.quarantineReleaseLog.findMany({
    where: { releasePublicId },
    orderBy: { id: 'asc' },
  });
}

/** Waits until the release executor finished a release (every log row left `pending`). */
export function waitForReleaseOutcome(
  prisma: PrismaClient,
  releasePublicId: string,
  timeoutMs = 180_000,
) {
  return waitFor(
    `release ${releasePublicId} executed`,
    async () => {
      const rows = await releaseLogsOf(prisma, releasePublicId);
      return rows.length > 0 && rows.every((r) => r.status !== 'pending') ? rows : undefined;
    },
    { timeoutMs, intervalMs: 500 },
  );
}

/** `quarantine_actions` rows of an entry, oldest first. */
export function actionsOfEntry(prisma: PrismaClient, entryId: bigint) {
  return prisma.quarantineAction.findMany({
    where: { quarantineMessageId: entryId },
    orderBy: { id: 'asc' },
  });
}

/**
 * §2.0-1: a quarantine row carries no message content. The retired `subject` column is NULL; the
 * JSON and text columns written by the step (explanation, explanation text, hard blocks, reason
 * codes, floor reasons) hold no `@`, no `://` and none of the given names (fixture domains,
 * local parts, subjects, body markers). Addresses already stored by earlier steps (recipient,
 * envelope sender, header From) are allowed in their own columns.
 */
export function entryContentProblems(row: EntryRow, forbidden: readonly string[]): string[] {
  const problems: string[] = [];
  if (row.subject !== null) problems.push(`entry ${row.publicId}: subject is not NULL`);
  const json = JSON.stringify({
    explanation: row.explanation,
    text: row.explanationText,
    hardBlocks: row.hardBlocks,
    reasonCodes: row.reasonCodes,
    floorReasons: row.floorReasons,
    terminalReason: row.terminalReason,
  });
  problems.push(...jsonProblems(`entry ${row.publicId}`, json, forbidden));
  return problems;
}

/** `@`, `://` and forbidden names in a JSON text of content-free columns. */
export function jsonProblems(label: string, json: string, forbidden: readonly string[]): string[] {
  const problems: string[] = [];
  if (json.includes('@')) problems.push(`${label}: contains "@"`);
  if (json.includes('://')) problems.push(`${label}: contains "://"`);
  for (const name of forbidden) {
    if (name && json.toLowerCase().includes(name.toLowerCase())) {
      problems.push(`${label}: contains "${name}"`);
    }
  }
  return problems;
}

/**
 * Every quarantine row of the given organizations, checked for content (§2.0-1): entries (as
 * above), actions (`details`, `result`; the operator `reason` must not contain the names),
 * release logs (`precheck`, `revalidation`, `blockedReason`), approval requests (reasons and
 * their codes), purges, digest rows. Returns the problems and the row counts read.
 */
export async function quarantineContentProblems(
  prisma: PrismaClient,
  organizationIds: readonly bigint[],
  forbidden: readonly string[],
): Promise<{ problems: string[]; counts: Record<string, number> }> {
  const where = { organizationId: { in: [...organizationIds] } };
  const [entries, actions, logs, approvals, purges, digests, runs] = await Promise.all([
    prisma.quarantineMessage.findMany({ where }),
    prisma.quarantineAction.findMany({ where }),
    prisma.quarantineReleaseLog.findMany({ where }),
    prisma.quarantineApprovalRequest.findMany({ where }),
    prisma.quarantineObjectPurge.findMany({ where }),
    prisma.quarantineDigest.findMany({ where }),
    prisma.quarantineDigestRun.findMany({ where }),
  ]);
  const problems: string[] = [];
  for (const e of entries) problems.push(...entryContentProblems(e, forbidden));
  for (const a of actions) {
    problems.push(
      ...jsonProblems(`action ${a.id}`, JSON.stringify({ d: a.details, r: a.result }), forbidden),
    );
    if (a.reason && /:\/\//.test(a.reason)) problems.push(`action ${a.id}: reason with a URL`);
  }
  for (const l of logs) {
    problems.push(
      ...jsonProblems(
        `release log ${l.id}`,
        JSON.stringify({ p: l.precheck, r: l.revalidation, b: l.blockedReason }),
        forbidden,
      ),
    );
  }
  for (const r of approvals) {
    problems.push(
      ...jsonProblems(
        `approval ${r.publicId}`,
        JSON.stringify({ a: r.approvalReasons, b: r.approvedReasons }),
        forbidden,
      ),
    );
  }
  for (const p of purges) {
    problems.push(
      ...jsonProblems(`purge ${p.id}`, JSON.stringify([p.reason, p.lastErrorCode]), forbidden),
    );
  }
  return {
    problems,
    counts: {
      entries: entries.length,
      actions: actions.length,
      releaseLogs: logs.length,
      approvals: approvals.length,
      purges: purges.length,
      digests: digests.length,
      digestRuns: runs.length,
    },
  };
}

/** A fresh Idempotency-Key header. */
export const idem = (label: string) => ({ 'Idempotency-Key': `it-q5-${label}-${randomUUID()}` });

/** POST with an Idempotency-Key. */
export const postIdem = (
  session: ApiSession,
  path: string,
  body: unknown,
  label = 'op',
): Promise<ApiResponse> => session.post(path, body, idem(label));

/** The `from`/`to` query of a search window around now (Q9 requires a bounded range). */
export function windowQuery(hours = 6): string {
  const now = Date.now();
  const from = new Date(now - hours * 3_600_000).toISOString();
  const to = new Date(now + 3_600_000).toISOString();
  return `from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;
}

/** A policy-engine metric of the quarantine role. */
export const quarantineMetric = (name: string, labels: Record<string, string> = {}) =>
  metricValue('policy-engine', name, labels);

/** The notification-worker's quarantine notices sent (`notification_quarantine_messages_total`). */
export const quarantineNoticesSent = (kind: string) =>
  metricValue('notification-worker', 'notification_quarantine_messages_total', {
    kind,
    result: 'sent',
  });

/** Sleeps until a new minute has started plus `marginMs` (fixed-window and cron instants). */
export async function untilNextMinute(marginMs = 2_000): Promise<void> {
  const now = Date.now();
  const wait = 60_000 - (now % 60_000) + marginMs;
  await new Promise((r) => setTimeout(r, wait));
}

/**
 * The text of a single-part notice as a reader sees it: the header block plus the body with a
 * quoted-printable transfer encoding undone (long lines such as portal links are soft-wrapped).
 */
export function noticeText(raw: Buffer | string): string {
  const text = (typeof raw === 'string' ? raw : raw.toString('utf8')).replace(/\r\n/g, '\n');
  const split = text.indexOf('\n\n');
  if (split === -1) return text;
  const head = text.slice(0, split);
  const body = text.slice(split + 2);
  if (!/^content-transfer-encoding:\s*quoted-printable/im.test(head)) return text;
  const bytes = Buffer.from(
    body
      .replace(/=\n/g, '')
      .replace(/=([0-9A-Fa-f]{2})/g, (_m, hex: string) => String.fromCharCode(parseInt(hex, 16))),
    'latin1',
  );
  return `${head}\n\n${bytes.toString('utf8')}`;
}
