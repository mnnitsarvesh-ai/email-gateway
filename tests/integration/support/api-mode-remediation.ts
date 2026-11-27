import type { PrismaClient } from '@email-gateway/database';
import { waitFor } from './compose';
import { stack } from './env';

/**
 * Pieces of the step API-2 stack suite `api-mode-remediation.test.ts`
 * (docs/plan/steps/36-api-mode-remediation.md §9.6, ADR-0101/0102): the idp-simulator's message
 * location (`GET /admin/mailboxes/{user}/messages/{id}`, R7), readers of the remediation actions
 * and the mailbox-located quarantine entries (MySQL writer), the remediation counters and the
 * removal of the two step API-2 tables of the suite's organizations (purge order §3.4: actions
 * before mailboxes/connections, policies before domains/organizations). Synthetic data only;
 * nothing reaches Microsoft, Google or the Internet.
 */

const simAdminBase = () =>
  `http://${stack.host}:${process.env.IDP_SIMULATOR_ADMIN_HOST_PORT ?? 18097}`;

/** Where a simulated message is now (Graph folder and categories, Gmail labels; R7). */
export interface SimLocation {
  provider: 'microsoft' | 'google';
  userId: string;
  messageId: string;
  currentId: string | null;
  state: 'present' | 'deleted';
  folder: {
    id: string;
    displayName: string;
    wellKnownName: string | null;
    isHidden: boolean;
  } | null;
  labelIds: string[];
  labelNames: string[];
  categories: string[];
}

/** The location of a message delivered with `sim.deliver` (follows Graph moves). */
export async function simLocation(user: string, messageId: string): Promise<SimLocation> {
  const res = await fetch(
    `${simAdminBase()}/admin/mailboxes/${encodeURIComponent(user)}/messages/${encodeURIComponent(messageId)}`,
  );
  if (res.status !== 200) throw new Error(`idp-simulator location answered ${res.status}`);
  return (await res.json()) as SimLocation;
}

/** Waits until the simulated message satisfies `predicate` (the mailbox-worker acted). */
export function waitForLocation(
  user: string,
  messageId: string,
  what: string,
  predicate: (l: SimLocation) => boolean,
  timeoutMs = 180_000,
): Promise<SimLocation> {
  return waitFor(
    `simulated message ${what}`,
    async () => {
      const l = await simLocation(user, messageId);
      return predicate(l) ? l : undefined;
    },
    { timeoutMs, intervalMs: 1_500 },
  );
}

/** Remediation actions of a copy (writer), oldest first. */
export function actionsOfCopy(prisma: PrismaClient, organizationId: bigint, copyId: bigint) {
  return prisma.apiRemediationAction.findMany({
    where: { organizationId, copyId },
    orderBy: { id: 'asc' },
  });
}

export type ActionRow = Awaited<ReturnType<typeof actionsOfCopy>>[number];

/** Waits for an action of a copy that satisfies `predicate`. */
export function waitForAction(
  prisma: PrismaClient,
  organizationId: bigint,
  copyId: bigint,
  what: string,
  predicate: (a: ActionRow) => boolean,
  timeoutMs = 180_000,
): Promise<ActionRow> {
  return waitFor(
    `remediation action ${what}`,
    async () => (await actionsOfCopy(prisma, organizationId, copyId)).find(predicate),
    { timeoutMs, intervalMs: 1_000 },
  );
}

/** The mailbox-located quarantine entries of a copy (writer), oldest first (R9). */
export function mailboxEntriesOfCopy(prisma: PrismaClient, organizationId: bigint, copyId: bigint) {
  return prisma.quarantineMessage.findMany({
    where: { organizationId, location: 'mailbox', apiCopyId: copyId },
    orderBy: { id: 'asc' },
  });
}

/** Waits until a quarantine entry (by internal id) satisfies `predicate`. */
export function waitForEntryRow(
  prisma: PrismaClient,
  entryId: bigint,
  what: string,
  predicate: (e: { status: string }) => boolean,
  timeoutMs = 180_000,
) {
  return waitFor(
    `quarantine entry ${what}`,
    async () => {
      const row = await prisma.quarantineMessage.findUnique({ where: { id: entryId } });
      return row && predicate(row) ? row : undefined;
    },
    { timeoutMs, intervalMs: 1_000 },
  );
}

/** The step API-2 counters of an API-mode connection, summed over the hours (writer). */
export async function remediationCounterSums(prisma: PrismaClient, apiConnectionId: bigint) {
  const rows = await prisma.apiModeCounter.findMany({ where: { apiConnectionId } });
  const sum = (
    k:
      | 'remediationSucceeded'
      | 'remediationFailed'
      | 'remediationSkipped'
      | 'remediationSimulated'
      | 'restoresSucceeded'
      | 'restoresFailed'
      | 'remediationThrottled'
      | 'remediationLatencyCount',
  ) => rows.reduce((n, r) => n + r[k], 0);
  return {
    succeeded: sum('remediationSucceeded'),
    failed: sum('remediationFailed'),
    skipped: sum('remediationSkipped'),
    simulated: sum('remediationSimulated'),
    restoresSucceeded: sum('restoresSucceeded'),
    restoresFailed: sum('restoresFailed'),
    throttled: sum('remediationThrottled'),
    latencyCount: sum('remediationLatencyCount'),
  };
}

/**
 * Removes the step API-2 rows of the organizations in the api purge's order (§3.4,
 * `API_MODE_PURGE_ORDER`), preceded since step API-3 by the clawback targets, clawbacks and user
 * reports (note 37 §3.4): remediation actions (RESTRICT keys to mailboxes and connections) and
 * remediation policies (RESTRICT keys to domains and organizations). Run it before
 * `purgeApiModeRows` (mailboxes, connections) and the fixture cleanup (domains, organizations).
 * Mailbox-located quarantine entries carry no key to these tables; the quarantine purge of the
 * fixture cleanup removes them.
 */
export async function purgeRemediationRows(
  prisma: PrismaClient,
  organizationIds: readonly bigint[],
): Promise<void> {
  if (organizationIds.length === 0) return;
  const where = { organizationId: { in: [...organizationIds] } };
  // Step API-3 (note 37 §3.4): clawback targets, clawbacks and user reports first (a clawback of
  // the live mailbox-worker may target the suite's copies; reports reference mailboxes).
  await prisma.apiClawbackTarget.deleteMany({ where });
  await prisma.apiClawback.deleteMany({ where });
  await prisma.apiUserReport.deleteMany({ where });
  await prisma.apiRemediationAction.deleteMany({ where });
  await prisma.apiRemediationPolicy.deleteMany({ where });
}

/** Rows of the step API-2 tables and mailbox entries still referencing the organizations. */
export async function remediationRowCounts(
  prisma: PrismaClient,
  organizationIds: readonly bigint[],
) {
  const where = { organizationId: { in: [...organizationIds] } };
  return {
    actions: await prisma.apiRemediationAction.count({ where }),
    policies: await prisma.apiRemediationPolicy.count({ where }),
    mailboxEntries: await prisma.quarantineMessage.count({
      where: { ...where, location: 'mailbox' },
    }),
  };
}
