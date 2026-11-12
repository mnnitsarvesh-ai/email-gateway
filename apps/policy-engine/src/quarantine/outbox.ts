import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import {
  EventTypes,
  type QuarantineNotificationRequestedV1,
  quarantineNotificationRequestedV1,
} from '@email-gateway/event-contracts';

/** `actor.service`, `email_events.source_service` of the quarantine paths. */
export const QUARANTINE_SOURCE_SERVICE = 'policy-engine';

/**
 * One `mail.quarantine.notification_requested.v1` outbox row (Q20, Q27): aggregate
 * `quarantine`, `aggregate_id` = the decimal organization id (a digest or alert has no message;
 * per-organization relay ordering, WP1 deviation 7). The payload is parsed with its strict
 * schema (ids, enums and times only). Returns the event id.
 */
export async function writeQuarantineNotification(
  tx: Prisma.TransactionClient,
  input: {
    organizationId: bigint;
    correlationId: string;
    payload: QuarantineNotificationRequestedV1;
    at: Date;
    /** A pre-allocated event id (a digest row stores it before the outbox row exists). */
    eventId?: string;
  },
): Promise<string> {
  const payload = quarantineNotificationRequestedV1.parse(input.payload);
  const eventId = input.eventId ?? uuidv7(input.at.getTime());
  await tx.messageOutbox.create({
    data: {
      eventId,
      organizationId: input.organizationId,
      eventType: EventTypes.QuarantineNotificationRequested,
      aggregateType: 'quarantine',
      aggregateId: input.organizationId.toString(),
      correlationId: input.correlationId,
      payload: payload,
    },
    select: { id: true },
  });
  return eventId;
}

/** An `email_events` row of a message (ids, enums, counts only). */
export async function writeMessageEvent(
  tx: Prisma.TransactionClient,
  input: {
    messageId: bigint;
    receivedAt: Date;
    organizationId: bigint;
    eventType: string;
    at: Date;
    eventId?: string;
    details: Record<string, string | number | boolean | null>;
  },
): Promise<void> {
  await tx.emailEvent.create({
    data: {
      receivedAt: input.receivedAt,
      messageId: input.messageId,
      organizationId: input.organizationId,
      eventType: input.eventType,
      occurredAt: input.at,
      sourceService: QUARANTINE_SOURCE_SERVICE,
      eventId: input.eventId ?? uuidv7(input.at.getTime()),
      details: input.details,
    },
    select: { id: true },
  });
}

/** Splits `items` into chunks of at most `size`. */
export function chunks<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}
