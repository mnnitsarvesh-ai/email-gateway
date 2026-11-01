import { z } from 'zod';

/**
 * Every message on RabbitMQ is wrapped in this envelope.
 *
 * - `eventId` is unique per publish attempt chain and doubles as the idempotency key:
 *   consumers record it in `processed_events` inside the same transaction as their side
 *   effects, so redelivery (at-least-once) never applies an effect twice.
 * - Payloads carry ids and S3 keys, never message bodies.
 */
export const eventEnvelopeSchema = z.object({
  eventId: z.uuid(),
  eventType: z.string().regex(/^[a-z]+(\.[a-z_]+)+\.v\d+$/),
  occurredAt: z.iso.datetime(),
  correlationId: z.string().min(8).max(128),
  tenantId: z.uuid(),
  payload: z.unknown(),
});

export type EventEnvelope<T = unknown> = Omit<z.infer<typeof eventEnvelopeSchema>, 'payload'> & {
  payload: T;
};

/** Parses an envelope and its payload; throws a ZodError on any mismatch. */
export function parseEvent<T>(raw: unknown, payloadSchema: z.ZodType<T>): EventEnvelope<T> {
  const envelope = eventEnvelopeSchema.parse(raw);
  return { ...envelope, payload: payloadSchema.parse(envelope.payload) };
}
