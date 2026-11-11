import { createHash } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';
import { EventTypes } from '@email-gateway/event-contracts';
import type { ApiSession } from './api-client';
import { compose, composeOk, run, waitFor } from './compose';
import { stack } from './env';
import type { MessageKey } from './lifecycle';
import { metricValue } from './metrics';

/**
 * Readers and checks of the step 5.2 policy evaluations (docs/plan/steps/16-policy-engine.md
 * §3, P9, P10, P13, P18, P19; ADR-0044) for the stack suites. Since step 5.2 the policy-engine is
 * the only automatic producer of delivery approvals (the delivery-worker's development
 * pass-through was removed, P14): every scanned, scan-failed and parse-failed round gets exactly
 * one `policy_execution_logs` row, and only an `allow` disposition approves delivery. Everything
 * reads the MySQL WRITER.
 */

/** Ledger consumer of the policy-engine on `email.policy.evaluate` (P13). */
export const POLICY_LEDGER = 'policy-engine.evaluate';

/** Strictness order of dispositions (P9). */
export const DISPOSITION_ORDER = ['allow', 'require_approval', 'quarantine', 'reject'] as const;
export type Disposition = (typeof DISPOSITION_ORDER)[number];
export const dispositionAtLeast = (value: string, min: Disposition): boolean =>
  DISPOSITION_ORDER.indexOf(value as Disposition) >= DISPOSITION_ORDER.indexOf(min);

/** P9.4: the platform default's mapping of a risk `recommended_action` to a disposition. */
export const RISK_ACTION_DISPOSITION: Record<string, Disposition> = {
  deliver: 'allow',
  tag: 'allow',
  require_approval: 'require_approval',
  quarantine: 'quarantine',
  block: 'reject',
};

/** P18: the lifecycle state a disposition leads to. */
export const DISPOSITION_STATE: Record<Disposition, string> = {
  allow: 'approved',
  require_approval: 'held_for_review',
  quarantine: 'quarantined',
  reject: 'rejected',
};

/** P18: the disposition edge's target state and reason, from the row's final action. */
export const OUTCOME_OF_ACTION: Record<string, [string, string]> = {
  deliver: ['approved', 'policy_deliver'],
  tag: ['approved', 'policy_tag'],
  quarantine: ['quarantined', 'policy_quarantine'],
  require_approval: ['held_for_review', 'policy_hold'],
  discard: ['rejected', 'policy_discard'],
  reject: ['rejected', 'policy_reject'],
};

/** The lifecycle path rows of a round's policy decision: E8/E9/E5 then the disposition edge. */
export function policyPathOf(
  row: { action: string; trigger: string },
  from: 'scanned' | 'scan_failed' | 'persisted' = 'scanned',
): [string, string, string][] {
  const first =
    row.trigger === 'scan_failed'
      ? 'scan_failed_fail_safe'
      : row.trigger === 'parse_failed'
        ? 'parse_failed_fail_safe'
        : 'policy_decided';
  const [to, reason] = OUTCOME_OF_ACTION[row.action]!;
  return [
    [from, 'policy_evaluated', first],
    ['policy_evaluated', to, reason],
  ];
}

/** `policy_execution_logs` rows of a message, by round. */
export function evaluationsOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.policyExecutionLog.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: { evaluationSeq: 'asc' },
  });
}

export type EvaluationRow = Awaited<ReturnType<typeof evaluationsOf>>[number];

/** Waits for the evaluation of round `round` (P13: one per message and lifecycle round). */
export function waitForEvaluation(
  prisma: PrismaClient,
  message: MessageKey,
  round = 0,
  timeoutMs = 120_000,
): Promise<EvaluationRow> {
  return waitFor(
    `policy evaluation of round ${round} of message ${message.id}`,
    async () => (await evaluationsOf(prisma, message)).find((r) => r.evaluationSeq === round),
    { timeoutMs, intervalMs: 500 },
  );
}

/** Action types and statuses of a row's `actions` JSON (P10, P19). */
export interface StoredAction {
  type: string;
  params: Record<string, unknown>;
  origin: string;
  ruleRefs: string[];
  applicability: string;
  status: string;
}
export const actionsOf = (row: EvaluationRow): StoredAction[] =>
  row.actions as unknown as StoredAction[];
export const actionOf = (row: EvaluationRow, type: string): StoredAction | undefined =>
  actionsOf(row).find((a) => a.type === type);
export const floorOf = (row: EvaluationRow) =>
  row.floor as { disposition: string | null; tag: boolean; reasons: string[] };
export const recommendationOf = (row: EvaluationRow) =>
  row.recommendation as {
    disposition: string;
    tag: boolean;
    levelOnly: boolean;
    riskAction: string | null;
    revisions: number[];
  };

/**
 * §2.0-8: an evaluation row carries no message content. The explanation (text and lines), the
 * trace, the actions, the delivery block and every other JSON column hold no `@`, no `://` and
 * none of the given names (fixture domains, local parts, file names).
 */
export function evaluationContentProblems(
  row: EvaluationRow,
  forbidden: readonly string[],
): string[] {
  const problems: string[] = [];
  const json = JSON.stringify({
    explanation: row.explanation,
    text: row.explanationText,
    trace: row.trace,
    actions: row.actions,
    delivery: row.delivery,
    matchedRules: row.matchedRules,
    floor: row.floor,
    recommendation: row.recommendation,
    overrideDetail: row.overrideDetail,
    clamps: row.clamps,
    reasonCodes: row.reasonCodes,
    policyVersions: row.policyVersions,
  });
  if (json.includes('@')) problems.push('a column contains "@"');
  if (json.includes('://')) problems.push('a column contains "://"');
  for (const name of forbidden) {
    if (name && json.toLowerCase().includes(name.toLowerCase())) {
      problems.push(`a column contains "${name}"`);
    }
  }
  return problems;
}

/** Outbox rows of `eventType` about one message (payload `messageId`), oldest first. */
export async function messageOutboxOf(
  prisma: PrismaClient,
  organizationId: bigint,
  message: MessageKey,
  eventType: string,
) {
  const rows = await prisma.messageOutbox.findMany({
    where: { organizationId, aggregateId: message.id.toString(), eventType },
    orderBy: { id: 'asc' },
  });
  return rows;
}

/** `mail.delivery.approved.v1` outbox rows of a message (any round). */
export async function approvalsOf(prisma: PrismaClient, message: MessageKey) {
  const org = await organizationOf(prisma, message);
  const rows = await prisma.messageOutbox.findMany({
    where: { organizationId: org, eventType: EventTypes.DeliveryApproved },
    orderBy: { id: 'asc' },
  });
  return rows.filter(
    (r) => (r.payload as { messageId?: string }).messageId === message.id.toString(),
  );
}

export async function organizationOf(prisma: PrismaClient, message: MessageKey): Promise<bigint> {
  const row = await prisma.emailMessage.findFirstOrThrow({
    where: { id: message.id, receivedAt: message.receivedAt },
    select: { organizationId: true },
  });
  return row.organizationId;
}

async function stateOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.emailMessage.findFirstOrThrow({
    where: { id: message.id, receivedAt: message.receivedAt },
    select: { status: true, statusReason: true, finalAction: true, lifecycleRound: true },
  });
}

/**
 * The message was HELD by policy in round `round` (P13, P18): its evaluation exists with a
 * disposition other than `allow` (at least `min` when given), the message is in the state of
 * that disposition (`quarantined`, `held_for_review`, `rejected`), no approval of the round
 * exists, and nothing was delivered.
 */
export async function expectPolicyHeld(
  prisma: PrismaClient,
  message: MessageKey,
  options: { round?: number; min?: Disposition; timeoutMs?: number } = {},
): Promise<EvaluationRow> {
  const round = options.round ?? 0;
  const row = await waitForEvaluation(prisma, message, round, options.timeoutMs);
  if (row.disposition === 'allow' || !dispositionAtLeast(row.disposition, options.min ?? 'allow')) {
    throw new Error(
      `round ${round} of message ${message.id}: disposition ${row.disposition} (source ${row.decisionSource}), expected a hold${options.min ? ` ≥ ${options.min}` : ''}`,
    );
  }
  const expected = DISPOSITION_STATE[row.disposition as Disposition];
  const state = await waitFor(
    `message ${message.id} in ${expected}`,
    async () => {
      const s = await stateOf(prisma, message);
      return s.status === expected ? s : undefined;
    },
    { timeoutMs: 30_000, intervalMs: 250 },
  );
  const approvals = (await approvalsOf(prisma, message)).filter(
    (a) => (a.payload as { lifecycleRound?: number }).lifecycleRound === round,
  );
  if (approvals.length !== 0) {
    throw new Error(`round ${round} of message ${message.id} is held but has an approval`);
  }
  const deliveries = await prisma.emailDelivery.count({
    where: { messageId: message.id, receivedAt: message.receivedAt },
  });
  if (deliveries !== 0 && round === 0) {
    throw new Error(`held message ${message.id} has ${deliveries} delivery row(s)`);
  }
  void state;
  return row;
}

/** Risk rows (all revisions) of round `round`. */
async function riskRowsOfRound(prisma: PrismaClient, message: MessageKey, round: number) {
  return prisma.messageRiskScore.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt, lifecycleRound: round },
    orderBy: { revision: 'asc' },
  });
}

/**
 * Step 5.2 through the stack for suites whose round outcome depends on a score that moves with
 * Rspamd's learning (the 5.1 `expectPassThroughFollowsRisk`, replaced): the policy decision of
 * round `round` follows the round's revision-0 risk row (P9.4–P9.7). The disposition is at
 * least the platform mapping of the row's `recommended_action` (never weaker: the floor and the
 * recommendation); `allow` → approved (`source = policy`) and delivered; anything else → held in
 * the disposition's state with no approval. Both directions are asserted against the stored rows.
 */
export async function expectPolicyFollowsRisk(
  prisma: PrismaClient,
  message: MessageKey,
  round: number,
): Promise<{
  evaluation: EvaluationRow;
  risk: Awaited<ReturnType<typeof riskRowsOfRound>>[number];
  held: boolean;
}> {
  const evaluation = await waitForEvaluation(prisma, message, round, 180_000);
  const risks = await riskRowsOfRound(prisma, message, round);
  const risk = risks.find((r) => r.revision === 0);
  if (!risk) {
    // P9.5: a scanned round without a revision-0 row is quarantined by the floor.
    if (!dispositionAtLeast(evaluation.disposition, 'quarantine')) {
      throw new Error(`round ${round} of message ${message.id} has no risk row but was allowed`);
    }
    throw new Error(`round ${round} of message ${message.id} has no revision-0 risk row`);
  }
  const minimum = RISK_ACTION_DISPOSITION[risk.recommendedAction] ?? 'quarantine';
  const holdsByRisk =
    (risk.hardBlocks as unknown[]).length > 0 || risk.status === 'error' ? 'quarantine' : minimum;
  if (!dispositionAtLeast(evaluation.disposition, holdsByRisk)) {
    throw new Error(
      `round ${round} of message ${message.id}: risk recommends ${risk.recommendedAction} (level ${risk.level}) but policy decided ${evaluation.disposition}`,
    );
  }
  if (evaluation.disposition === 'allow') {
    await waitFor(
      `message ${message.id} delivered`,
      async () => (await stateOf(prisma, message)).status === 'delivered',
      { timeoutMs: 180_000, intervalMs: 500 },
    );
    const approvals = (await approvalsOf(prisma, message)).filter(
      (a) => (a.payload as { lifecycleRound?: number }).lifecycleRound === round,
    );
    if (
      approvals.length < 1 ||
      approvals.some((a) => (a.payload as { source?: string }).source !== 'policy')
    ) {
      throw new Error(
        `round ${round} of message ${message.id} delivered without a policy approval`,
      );
    }
    return { evaluation, risk, held: false };
  }
  await expectPolicyHeld(prisma, message, { round });
  return { evaluation, risk, held: true };
}

/** `policy_evaluations_total` of the policy-engine (labels: trigger, disposition, source, direction). */
export const policyEvaluations = (labels: Record<string, string> = {}) =>
  metricValue('policy-engine', 'policy_evaluations_total', labels);

/** `policy_floor_raises_total{reason}` (the floor code without `policy.floor.`). */
export const policyFloorRaises = (reason: string) =>
  metricValue('policy-engine', 'policy_floor_raises_total', { reason });

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

/** JSON of a Prisma row (BigInt ids as strings, keys sorted). */
export const rowJson = (value: unknown) => canonical(value);

/**
 * Checksums of every row a policy test or dry-run could write for one organization (§9.3 case
 * 12): evaluations, policies, versions, settings, departments, members, the message rows, the
 * audit log, and the outbox count. Each is the SHA-256 of the rows (all columns) in id order.
 */
export async function policyStateChecksums(prisma: PrismaClient, organizationId: bigint) {
  const where = { organizationId };
  const orderBy = { id: 'asc' as const };
  const [evaluations, policies, versions, settings, departments, members, messages, audits] =
    await Promise.all([
      prisma.policyExecutionLog.findMany({ where, orderBy }),
      prisma.emailPolicy.findMany({ where, orderBy }),
      prisma.policyVersion.findMany({ where, orderBy }),
      prisma.policySettings.findMany({ where, orderBy }),
      prisma.tenantDepartment.findMany({ where, orderBy }),
      prisma.tenantDepartmentMember.findMany({ where, orderBy }),
      prisma.emailMessage.findMany({ where, orderBy }),
      prisma.auditLog.findMany({ where, orderBy }),
    ]);
  const outbox = await prisma.messageOutbox.count({ where });
  return {
    policyExecutionLogs: { rows: evaluations.length, sha256: digest(evaluations) },
    emailPolicies: { rows: policies.length, sha256: digest(policies) },
    policyVersions: { rows: versions.length, sha256: digest(versions) },
    policySettings: { rows: settings.length, sha256: digest(settings) },
    tenantDepartments: { rows: departments.length, sha256: digest(departments) },
    tenantDepartmentMembers: { rows: members.length, sha256: digest(members) },
    emailMessages: { rows: messages.length, sha256: digest(messages) },
    auditLogs: { rows: audits.length, sha256: digest(audits) },
    messageOutbox: { rows: outbox },
  };
}

/**
 * Creates a policy with `definition` as its first draft (`policy:manage`) and publishes and
 * activates version 1 (`policy:publish`) through the live api (P17, P22). Returns the policy's
 * public id and the generation after the publish.
 */
export async function createAndPublishPolicy(
  manager: ApiSession,
  publisher: ApiSession,
  name: string,
  definition: unknown,
): Promise<{ policyId: string; generation: string }> {
  const created = await manager.post('/policies', { name, definition, changeNote: 'stack test' });
  if (created.status !== 201) {
    throw new Error(`POST /policies answered ${created.status}: ${JSON.stringify(created.body)}`);
  }
  const policyId = (created.body as { policy: { id: string } }).policy.id;
  return { policyId, generation: await publishVersion(publisher, policyId, 1) };
}

/** Publishes and activates draft `versionNo` (expected row version 1). */
export async function publishVersion(
  publisher: ApiSession,
  policyId: string,
  versionNo: number,
): Promise<string> {
  const published = await publisher.post(`/policies/${policyId}/versions/${versionNo}/publish`, {
    expectedRowVersion: 1,
  });
  if (published.status !== 200) {
    throw new Error(
      `publish of ${policyId} v${versionNo} answered ${published.status}: ${JSON.stringify(published.body)}`,
    );
  }
  return (published.body as { generation: string }).generation;
}

/**
 * The notification-worker pointed at the TEST mail-sink (§9.3 case 7, WP3 deviation 14): the
 * container is recreated with `NOTIFICATION_SMTP_HOST=mail-sink` (Compose interpolation: the
 * shell environment wins over `.env`) and joined to the `mailtest` network, where the sink
 * lives. `restoreNotificationWorker` recreates it from `.env` again (default relay
 * `postfix-notify`, `default` network only).
 */
export async function pointNotificationWorkerAtSink(): Promise<void> {
  await composeOk(['up', '-d', '--no-deps', '--force-recreate', '--wait', 'notification-worker'], {
    timeoutMs: 240_000,
    env: { NOTIFICATION_SMTP_HOST: 'mail-sink', NOTIFICATION_SMTP_PORT: '25' },
  });
  const id = (
    await composeOk(['ps', '--quiet', 'notification-worker'], { timeoutMs: 20_000 })
  ).stdout.trim();
  const network = `${stack.composeProject()}_mailtest`;
  const connected = await run('docker', ['network', 'connect', network, id], {
    timeoutMs: 30_000,
  });
  if (connected.exitCode !== 0 && !/already exists/.test(connected.stderr)) {
    throw new Error(`docker network connect ${network}: ${connected.stderr.trim()}`);
  }
}

export async function restoreNotificationWorker(): Promise<void> {
  await compose(['up', '-d', '--no-deps', '--force-recreate', '--wait', 'notification-worker'], {
    timeoutMs: 240_000,
  });
}

/** The live policy-engine container: stop (outage, §9.3 case 10) and start again. */
export async function stopPolicyEngine(): Promise<void> {
  await composeOk(['stop', 'policy-engine'], { timeoutMs: 120_000 });
}

export async function startPolicyEngine(): Promise<void> {
  await composeOk(['up', '-d', '--no-deps', '--wait', 'policy-engine'], { timeoutMs: 240_000 });
}
