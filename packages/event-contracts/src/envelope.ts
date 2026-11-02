import { z } from 'zod';

/** A BIGINT UNSIGNED id serialized as a canonical decimal string (no sign, no leading zeros). */
export const decimalIdSchema = z.string().regex(/^[1-9][0-9]{0,19}$/, 'Expected a decimal id');

/**
 * Every message on RabbitMQ is wrapped in this envelope.
 *
 * - `eventId` (UUIDv7) is unique per publish attempt chain and doubles as the idempotency key:
 *   consumers record it in `message_idempotency` (via `processOnce`) inside the same
 *   transaction as their side effects, so redelivery (at-least-once) never applies an effect
 *   twice.
 * - `organizationId` is the tenant's numeric `organizations.id` as a decimal string (ADR-0014).
 *   It is set by the producer from authenticated context, never from client input.
 * - Payloads carry ids and S3 keys, never message bodies.
 */
export const eventEnvelopeSchema = z.object({
  eventId: z.uuid(),
  eventType: z.string().regex(/^[a-z]+(\.[a-z_]+)+\.v\d+$/),
  occurredAt: z.iso.datetime(),
  correlationId: z.string().min(8).max(128),
  organizationId: decimalIdSchema,
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
