/**
 * Registry-validated outbox insert (D2): the payload is parsed with the schema the event registry
 * holds for `eventType`, and the aggregate type must be the registered one, so a producer can never
 * write a row the event-relay would refuse. UUIDv7 event ids; correlation id from the request
 * context when present.
 */
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { eventDefinition } from '@email-gateway/event-contracts';
import { getCorrelationId } from '@email-gateway/logger';

export interface OutboxInsert {
  organizationId: bigint;
  eventType: string;
  aggregateId: string;
  payload: unknown;
  at: Date;
  /** Default: the request's correlation id, else `<aggregateType>:<aggregateId>`. */
  correlationId?: string;
}

/** Inserts one `message_outbox` row; returns the event id. Throws on an unknown type or payload. */
export async function insertRegisteredOutboxRow(
  tx: Prisma.TransactionClient,
  input: OutboxInsert,
): Promise<string> {
  const definition = eventDefinition(input.eventType);
  if (!definition) throw new Error(`Event type ${input.eventType} is not registered`);
  const payload = definition.schema.parse(input.payload) as Prisma.InputJsonValue;
  const eventId = uuidv7(input.at.getTime());
  const correlationId = (
    input.correlationId ??
    getCorrelationId() ??
    `${definition.aggregateType}:${input.aggregateId}`
  ).slice(0, 128);
  await tx.messageOutbox.create({
    data: {
      eventId,
      organizationId: input.organizationId,
      eventType: definition.type,
      aggregateType: definition.aggregateType,
      aggregateId: input.aggregateId,
      correlationId,
      payload,
    },
    select: { id: true },
  });
  return eventId;
}
