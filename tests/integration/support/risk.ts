import { createHash } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';
import { waitFor } from './compose';
import type { MessageKey } from './lifecycle';
import { metricValue } from './metrics';
import { PASSTHROUGH_CONSUMER } from './scan-stage';

/**
 * Readers and checks of the step 5.1 risk scoring results (docs/plan/steps/15-risk-scoring.md
 * §3, R11, R13, R17) for the stack suites. Everything reads the MySQL WRITER.
 */

/** `message_risk_scores` rows of a message, by round then revision. */
export function riskRowsOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.messageRiskScore.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: [{ lifecycleRound: 'asc' }, { revision: 'asc' }],
  });
}

export type RiskRow = Awaited<ReturnType<typeof riskRowsOf>>[number];

/**
 * Waits for the risk row of `(scanId, revision)`. The revision-0 row commits with the round's
 * completion (R13), so once a round is no longer `running` it exists; the wait only covers the
 * reader seeing the commit.
 */
export function waitForRiskRow(
  prisma: PrismaClient,
  message: MessageKey,
  scanId: bigint,
  revision: 0 | 1 = 0,
  timeoutMs = 30_000,
): Promise<RiskRow> {
  return waitFor(
    `risk row (scan ${scanId}, revision ${revision}) of message ${message.id}`,
    async () =>
      (await riskRowsOf(prisma, message)).find(
        (r) => r.scanId === scanId && r.revision === revision,
      ),
    { timeoutMs, intervalMs: 250 },
  );
}

/** The step 5.1 snapshot columns of a round (`email_scans`). */
export function scanRiskColumns(prisma: PrismaClient, message: MessageKey, round: number) {
  return prisma.emailScan.findFirstOrThrow({
    where: { messageId: message.id, receivedAt: message.receivedAt, lifecycleRound: round },
    select: {
      id: true,
      verdict: true,
      riskScore: true,
      scoringVersion: true,
      riskProfileVersionId: true,
    },
  });
}

/** Signal ids of a row's `contributions` JSON. */
export function signalsOf(row: RiskRow): string[] {
  return (row.contributions as { signal: string }[]).map((c) => c.signal);
}

/** Groups with a non-zero total of a row's `groups` JSON. */
export function activeGroupsOf(row: RiskRow): string[] {
  return (row.groups as { group: string; total: number }[])
    .filter((g) => g.total > 0)
    .map((g) => g.group);
}

/** Hard-block ids of a row's `hard_blocks` JSON. */
export function hardBlocksOf(row: RiskRow): string[] {
  return (row.hardBlocks as { id: string }[]).map((h) => h.id);
}

/** The level order of R4. */
export const LEVEL_ORDER = ['none', 'low', 'medium', 'high', 'critical'] as const;
export const levelAtLeast = (level: string, min: (typeof LEVEL_ORDER)[number]): boolean =>
  LEVEL_ORDER.indexOf(level as (typeof LEVEL_ORDER)[number]) >= LEVEL_ORDER.indexOf(min);

/**
 * §2.0-6: a row carries no message content. The explanation (text and lines) and the JSON
 * columns hold no address, no URL and none of the given names (fixture domains, local parts).
 */
export function contentProblems(row: RiskRow, forbidden: readonly string[]): string[] {
  const problems: string[] = [];
  const text = row.explanationText;
  if (text.includes('@')) problems.push('explanation text contains "@"');
  if (text.includes('://')) problems.push('explanation text contains "://"');
  const json = JSON.stringify({
    hardBlocks: row.hardBlocks,
    reasonCodes: row.reasonCodes,
    contributions: row.contributions,
    groups: row.groups,
    engines: row.engines,
    failures: row.failures,
    floors: row.floors,
    trust: row.trust,
    evidence: row.evidence,
    explanation: row.explanation,
    text,
  });
  if (json.includes('@')) problems.push('a JSON column contains "@"');
  if (json.includes('://')) problems.push('a JSON column contains "://"');
  for (const name of forbidden) {
    if (name && json.toLowerCase().includes(name.toLowerCase())) {
      problems.push(`a JSON column contains "${name}"`);
    }
  }
  return problems;
}

const canonical = (value: unknown): string =>
  JSON.stringify(value, (_key, v: unknown) => {
    if (typeof v === 'bigint') return v.toString();
    if (v instanceof Date) return v.toISOString();
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      return Object.fromEntries(
        Object.entries(v as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)),
      );
    }
    return v;
  });

const digest = (rows: readonly unknown[]) =>
  createHash('sha256')
    .update(rows.map((r) => canonical(r)).join('\n'))
    .digest('hex');

/**
 * Checksums of every row the dry-run could write for one organization (§9.5 case 8): the
 * risk rows, the scan rounds (with their snapshot columns), the profile and its versions, the
 * audit log, and the outbox count. Each is the SHA-256 of the rows (all columns) in id order.
 */
export async function riskStateChecksums(prisma: PrismaClient, organizationId: bigint) {
  const where = { organizationId };
  const [scores, scans, profiles, versions, audits, outbox] = await Promise.all([
    prisma.messageRiskScore.findMany({ where, orderBy: { id: 'asc' } }),
    prisma.emailScan.findMany({ where, orderBy: { id: 'asc' } }),
    prisma.riskScoringProfile.findMany({ where, orderBy: { id: 'asc' } }),
    prisma.riskScoringProfileVersion.findMany({ where, orderBy: { id: 'asc' } }),
    prisma.auditLog.findMany({ where, orderBy: { id: 'asc' } }),
    prisma.messageOutbox.count({ where }),
  ]);
  return {
    messageRiskScores: { rows: scores.length, sha256: digest(scores) },
    emailScans: { rows: scans.length, sha256: digest(scans) },
    riskScoringProfiles: { rows: profiles.length, sha256: digest(profiles) },
    riskScoringProfileVersions: { rows: versions.length, sha256: digest(versions) },
    auditLogs: { rows: audits.length, sha256: digest(audits) },
    messageOutbox: { rows: outbox },
  };
}

/** delivery-worker counters of the pass-through risk hold (R17, R19). */
export const riskHoldCounters = async () => ({
  riskRecommendation: await metricValue('delivery-worker', 'delivery_approvals_skipped_total', {
    reason: 'risk_recommendation',
  }),
  riskMissing: await metricValue('delivery-worker', 'delivery_approvals_skipped_total', {
    reason: 'risk_missing',
  }),
});

/** `delivery_risk_holds_total{action}` of the delivery-worker. */
export const riskHolds = (action: string) =>
  metricValue('delivery-worker', 'delivery_risk_holds_total', { action });

/** R17: a revision-0 row the dev pass-through holds (it approves `deliver` and `tag` only). */
export const riskRowHolds = (row: RiskRow): boolean =>
  ['require_approval', 'quarantine', 'block'].includes(row.recommendedAction) ||
  (row.hardBlocks as unknown[]).length > 0 ||
  row.status === 'error';

/**
 * Step 5.1 R17 through the stack: the pass-through's decision for round `round` follows the
 * round's revision-0 risk row. A row that recommends `require_approval`/`quarantine`/`block`
 * (or carries a hard block or is an error row) → held: the pass-through handled the round's
 * `scanned.v1` (ledger row), `delivery_approvals_skipped_total{reason="risk_recommendation"}`
 * rose (when `before` is given), no approval of this message exists after a 10 s window and the
 * message stays `scanned`. `deliver`/`tag` → approved and delivered. Only for rounds the 4.x
 * checks approve (no `scan_failed`, `malicious`, bec or dlp hold), which the caller knows.
 */
export async function expectPassThroughFollowsRisk(
  prisma: PrismaClient,
  message: MessageKey,
  round: number,
  before?: { riskRecommendation: number },
): Promise<{ row: RiskRow; held: boolean }> {
  const scan = await prisma.emailScan.findFirstOrThrow({
    where: { messageId: message.id, receivedAt: message.receivedAt, lifecycleRound: round },
    select: { id: true, organizationId: true },
  });
  const row = await waitForRiskRow(prisma, message, scan.id, 0);
  const held = riskRowHolds(row);
  if (!held) {
    await waitForLifecycleState(prisma, message, 'delivered', 180_000);
    return { row, held };
  }
  const event = await waitFor(
    `scanned.v1 of round ${round} of message ${message.id}`,
    async () =>
      (
        await prisma.messageOutbox.findMany({
          where: {
            organizationId: scan.organizationId,
            aggregateId: message.id.toString(),
            eventType: 'mail.message.scanned.v1',
          },
        })
      ).find((e) => (e.payload as { lifecycleRound?: number }).lifecycleRound === round),
    { timeoutMs: 30_000, intervalMs: 500 },
  );
  await waitFor(
    `the dev pass-through to hold round ${round} of message ${message.id} (risk_recommendation)`,
    async () => {
      const ledger = await prisma.messageIdempotency.count({
        where: { consumer: PASSTHROUGH_CONSUMER, eventId: event.eventId },
      });
      if (ledger !== 1) return false;
      if (!before) return true;
      return (await riskHoldCounters()).riskRecommendation >= before.riskRecommendation + 1;
    },
    { timeoutMs: 60_000, intervalMs: 1_000 },
  );
  await new Promise((r) => setTimeout(r, 10_000));
  const approvals = await prisma.messageOutbox.findMany({
    where: { organizationId: scan.organizationId, eventType: 'mail.delivery.approved.v1' },
    select: { payload: true },
  });
  const mine = approvals.filter(
    (a) => (a.payload as { messageId?: string }).messageId === message.id.toString(),
  );
  const state = await prisma.emailMessage.findFirstOrThrow({
    where: { id: message.id, receivedAt: message.receivedAt },
    select: { status: true, statusReason: true },
  });
  if (mine.length !== 0 || state.status !== 'scanned') {
    throw new Error(
      `round ${round} of message ${message.id} recommends ${row.recommendedAction} (level ${row.level}) but was not held: ${mine.length} approval(s), state ${state.status}`,
    );
  }
  return { row, held };
}

async function waitForLifecycleState(
  prisma: PrismaClient,
  message: MessageKey,
  status: string,
  timeoutMs: number,
): Promise<void> {
  await waitFor(
    `message ${message.id} in ${status}`,
    async () =>
      (
        await prisma.emailMessage.findFirstOrThrow({
          where: { id: message.id, receivedAt: message.receivedAt },
          select: { status: true },
        })
      ).status === status,
    { timeoutMs, intervalMs: 500 },
  );
}
