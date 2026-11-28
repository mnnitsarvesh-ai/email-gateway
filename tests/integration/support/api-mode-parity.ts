import type { PrismaClient } from '@email-gateway/database';
// The published payload guard and strict `data` schemas of @email-gateway/webhooks, imported by
// path like `webhooks.ts` imports the signing module (`tests/package.json` does not declare the
// package; step API-4 WP7 changes no dependency).
import { dataSchemas } from '../../../packages/webhooks/src/catalogue';
import { assertWebhookPayloadSafe } from '../../../packages/webhooks/src/payload-guard';
import { waitFor } from './compose';
import { MAILBOX_WORKER_SUITE_ENV, sim, type SimCall } from './api-mode';
import { payloadProblems, type ReceivedRequest } from './webhooks';

/**
 * Pieces of the step API-4 stack suite `api-mode-parity.test.ts`
 * (docs/plan/steps/38-api-mode-parity-onboarding.md §10.6, ADR-0105–0107): the mailbox-worker
 * overrides of the run, readers of the detect-mode evaluation rows, the `copy_detected` /
 * alert / policy-notice outbox rows and the simulator call log, the payload assertion every
 * received `mailbox.*` webhook must pass, the alert-window seam and the removal of the step API-4
 * rows of the suite's organizations. Synthetic `it-apiparity-*` data only; nothing reaches
 * Microsoft, Google or the Internet; no credential or secret is printed.
 */

/**
 * mailbox-worker overrides of the run (shell environment over `.env`, LOCAL ONLY): the API-1
 * values (health leader every 3 s — it evaluates scopes (B6) and expires detect-only periods (B7)
 * on each tick — counters flushed every 2 s, feed ticks of 1 s) and the policy evaluation switch
 * explicitly on.
 */
export const PARITY_WORKER_SUITE_ENV: Record<string, string> = {
  ...MAILBOX_WORKER_SUITE_ENV,
  API_MODE_POLICY_EVALUATION_ENABLED: 'true',
};

export const COPY_DETECTED = 'mail.message.copy_detected.v1';
export const POLICY_NOTIFICATION_REQUESTED = 'mail.policy.notification_requested.v1';
export const ALERT_REQUESTED = 'notification.alert_requested.v1';
export const POLICY_DECIDED = 'mail.policy.decided.v1';

/** `policy_execution_logs` rows of a registry message evaluated in detect mode (writer). */
export function detectRowsOf(prisma: PrismaClient, organizationId: bigint, messageId: bigint) {
  return prisma.policyExecutionLog.findMany({
    where: { organizationId, messageId, evaluationMode: 'detect' },
    orderBy: { id: 'asc' },
  });
}

/** Waits for the detect row of a registry message. */
export function waitForDetectRow(
  prisma: PrismaClient,
  organizationId: bigint,
  messageId: bigint,
  timeoutMs = 180_000,
) {
  return waitFor(
    `detect-mode evaluation of message ${messageId.toString()}`,
    async () => (await detectRowsOf(prisma, organizationId, messageId))[0],
    { timeoutMs, intervalMs: 1_500 },
  );
}

/** Outbox rows of `eventType` of an organization whose aggregate is `aggregateId`. */
export function outboxRowsOf(
  prisma: PrismaClient,
  organizationId: bigint,
  eventType: string,
  aggregateId?: string,
) {
  return prisma.messageOutbox.findMany({
    where: { organizationId, eventType, ...(aggregateId ? { aggregateId } : {}) },
    orderBy: { id: 'asc' },
  });
}

/** `notification.alert_requested.v1` rows of `kind` that name the message in their refs. */
export async function alertRequestsFor(
  prisma: PrismaClient,
  organizationId: bigint,
  kind: string,
  messagePublicId?: string,
) {
  const rows = await outboxRowsOf(prisma, organizationId, ALERT_REQUESTED);
  return rows.filter((r) => {
    const p = r.payload as { kind?: string; refs?: Record<string, unknown> };
    if (p.kind !== kind) return false;
    if (messagePublicId === undefined) return true;
    return JSON.stringify(p.refs ?? {}).includes(messagePublicId);
  });
}

/**
 * Test seam (as the step API-1 suite's case 7): removes the organization's alert windows of
 * `kind`, so the next alert of that kind opens a new window and is e-mailed at once instead of
 * being counted in a window an earlier detection of the run opened (default throttle 60 min).
 */
export async function resetAlertWindows(
  prisma: PrismaClient,
  organizationId: bigint,
  kind: string,
): Promise<number> {
  const { count } = await prisma.notificationAlertWindow.deleteMany({
    where: { organizationId, kind },
  });
  return count;
}

/** Lengths of the simulator call logs (Graph, Gmail): a mark for `simCallsNaming`. */
export interface SimCallMark {
  graph: number;
  gmail: number;
}

export async function simCallMark(): Promise<SimCallMark> {
  return {
    graph: (await sim.calls({ simulator: 'graph' })).length,
    gmail: (await sim.calls({ simulator: 'gmail' })).length,
  };
}

/** Simulator calls (Graph and Gmail) after `from` whose path names one of `needles`. */
export async function simCallsNaming(
  needles: readonly string[],
  from: SimCallMark = { graph: 0, gmail: 0 },
): Promise<SimCall[]> {
  const lowered = needles.flatMap((n) => [n.toLowerCase(), encodeURIComponent(n).toLowerCase()]);
  const calls = [
    ...(await sim.calls({ simulator: 'graph' })).slice(from.graph),
    ...(await sim.calls({ simulator: 'gmail' })).slice(from.gmail),
  ];
  return calls.filter((c) => lowered.some((n) => c.path.toLowerCase().includes(n)));
}

/**
 * Every problem of one received `mailbox.*` (or any catalogue) webhook: the step 6.2 no-content
 * assertion on the raw body (`payloadProblems`), the published payload guard
 * (`assertWebhookPayloadSafe`, W2) and the strict catalogue v1 `data` schema of its type.
 */
export function parityPayloadProblems(
  request: ReceivedRequest,
  organizationPublicId: string,
  forbidden: readonly string[],
): string[] {
  const problems = payloadProblems(request, organizationPublicId, forbidden);
  try {
    assertWebhookPayloadSafe(request.envelope);
  } catch (error) {
    problems.push(`payload guard: ${(error as Error).message}`);
  }
  const schema = (
    dataSchemas as Record<string, { safeParse: (v: unknown) => { success: boolean } }>
  )[request.envelope.type];
  if (!schema) problems.push(`unknown type ${request.envelope.type}`);
  else if (!schema.safeParse(request.envelope.data).success) problems.push('data schema');
  return problems;
}

/**
 * Removes the step API-4 rows of the organizations that the API-1..API-3 purges do not cover:
 * `api_mode_domain_settings` (also cascades with its domain), the provider-check
 * `domain_verifications` rows (cascade with the domain) and the provider-check rate-limit window
 * (`rl:domain-provider-check:<org>`). Run before `purgeApiModeRows` and the fixture cleanup.
 */
export async function purgeParityRows(
  prisma: PrismaClient,
  redis: {
    keys: (pattern: string) => Promise<string[]>;
    del: (...keys: string[]) => Promise<number>;
  },
  organizationIds: readonly bigint[],
): Promise<void> {
  if (organizationIds.length === 0) return;
  const where = { organizationId: { in: [...organizationIds] } };
  await prisma.apiModeDomainSetting.deleteMany({ where });
  await prisma.domainVerification.deleteMany({ where: { ...where, method: 'provider_tenant' } });
  for (const id of organizationIds) {
    const keys = await redis.keys(`*domain-provider-check:${id.toString()}*`);
    if (keys.length > 0) await redis.del(...keys);
  }
}

/** Rows of the step API-4 tables and detect evaluations still referencing the organizations. */
export async function parityRowCounts(prisma: PrismaClient, organizationIds: readonly bigint[]) {
  const where = { organizationId: { in: [...organizationIds] } };
  return {
    domainSettings: await prisma.apiModeDomainSetting.count({ where }),
    detectRows: await prisma.policyExecutionLog.count({
      where: { ...where, evaluationMode: 'detect' },
    }),
    providerVerifications: await prisma.domainVerification.count({
      where: { ...where, method: 'provider_tenant' },
    }),
  };
}
