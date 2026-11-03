import type { DeliveryStatus, EmailDelivery, PrismaClient } from '@email-gateway/database';
import { waitFor } from './compose';

/**
 * Readers of the step 2.3 delivery records (docs/plan/steps/05-routing.md R7–R9) on the MySQL
 * WRITER, for the routing stack suites: per-recipient deliveries (`email_deliveries` joined with
 * the recipient address), reinjection groups and the append-only audit trail.
 */
export interface DeliveryRow extends EmailDelivery {
  address: string;
  recipientDirection: string | null;
  recipientStatus: string;
}

export const TERMINAL: readonly DeliveryStatus[] = [
  'delivered',
  'bounced',
  'expired',
  'failed',
  'suppressed',
];

/** Every delivery of one organization's message (by message id), with recipient addresses. */
export async function deliveriesOf(
  prisma: PrismaClient,
  organizationId: bigint,
  messageId: bigint,
): Promise<DeliveryRow[]> {
  const deliveries = await prisma.emailDelivery.findMany({
    where: { organizationId, messageId },
    orderBy: { id: 'asc' },
  });
  const recipients = await prisma.emailRecipient.findMany({
    where: { organizationId, messageId },
    select: { id: true, address: true, direction: true, status: true },
  });
  const byId = new Map(recipients.map((r) => [r.id, r]));
  return deliveries.map((d) => {
    const recipient = byId.get(d.recipientId);
    return {
      ...d,
      address: recipient?.address.toLowerCase() ?? '',
      recipientDirection: recipient?.direction ?? null,
      recipientStatus: recipient?.status ?? '',
    };
  });
}

/** The newest message of `organizationId` ingested from MTA queue `queueId` (Postfix queue id). */
export function waitForMessage(
  prisma: PrismaClient,
  organizationId: bigint,
  where: { mtaQueueId?: string; internetMessageId?: string },
  timeoutMs = 90_000,
) {
  return waitFor(
    `email_messages row of organization ${organizationId} (${JSON.stringify(where)})`,
    () =>
      prisma.emailMessage
        .findFirst({ where: { organizationId, ...where }, orderBy: { id: 'desc' } })
        .then((row) => row ?? undefined),
    { timeoutMs, intervalMs: 500 },
  );
}

/**
 * Waits until the message has `expected` deliveries and `check` accepts them (polling the
 * writer); returns the last rows. The failure message lists every delivery's state.
 */
export async function waitForDeliveries(
  prisma: PrismaClient,
  organizationId: bigint,
  messageId: bigint,
  description: string,
  check: (rows: DeliveryRow[]) => boolean,
  timeoutMs = 120_000,
): Promise<DeliveryRow[]> {
  let last: DeliveryRow[] = [];
  try {
    return await waitFor(
      description,
      async () => {
        last = await deliveriesOf(prisma, organizationId, messageId);
        return last.length > 0 && check(last) ? last : undefined;
      },
      { timeoutMs, intervalMs: 1_000 },
    );
  } catch (err) {
    const state = last.map(
      (d) =>
        `${d.address}: ${d.status} (attempts ${d.attemptCount}, class ${d.lastErrorClass ?? '-'}, reason ${d.failureReason ?? '-'}, ${d.finalSmtpResponse ?? ''})`,
    );
    throw new Error(`${(err as Error).message}\n  deliveries: ${state.join('\n  ') || 'none'}`);
  }
}

/** Waits until every delivery of the message has one of `statuses`. */
export function waitForAllDeliveries(
  prisma: PrismaClient,
  organizationId: bigint,
  messageId: bigint,
  statuses: readonly DeliveryStatus[],
  count: number,
  timeoutMs = 120_000,
): Promise<DeliveryRow[]> {
  return waitForDeliveries(
    prisma,
    organizationId,
    messageId,
    `${count} deliveries of message ${messageId} in ${statuses.join('/')}`,
    (rows) => rows.length === count && rows.every((d) => statuses.includes(d.status)),
    timeoutMs,
  );
}

/** Audit rows (`delivery_status_events`) of one message, oldest first. */
export function statusEventsOf(prisma: PrismaClient, organizationId: bigint, messageId: bigint) {
  return prisma.deliveryStatusEvent.findMany({
    where: { organizationId, messageId },
    orderBy: { id: 'asc' },
  });
}

/** Reinjection groups (`delivery_reinjections`) of one message. */
export function reinjectionsOf(prisma: PrismaClient, organizationId: bigint, messageId: bigint) {
  return prisma.deliveryReinjection.findMany({
    where: { organizationId, messageId },
    orderBy: { id: 'asc' },
  });
}

/** Row counts that a duplicate signal must never change (R9.1). */
export async function signalSideEffects(prisma: PrismaClient, organizationIds: readonly bigint[]) {
  const where = { organizationId: { in: [...organizationIds] } };
  const [statusEvents, emailEvents, outbox, attempts, bounces, history] = await Promise.all([
    prisma.deliveryStatusEvent.count({ where }),
    prisma.emailEvent.count({ where }),
    prisma.messageOutbox.count({ where }),
    prisma.deliveryAttempt.count({ where }),
    prisma.bounceEvent.count({ where }),
    prisma.emailMessageStatusHistory.count({ where }),
  ]);
  return { statusEvents, emailEvents, outbox, attempts, bounces, history };
}
