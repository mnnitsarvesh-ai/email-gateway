import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  dataSchemas,
  WEBHOOK_ENVELOPE_TYPES,
  type WebhookEnvelopeType,
  type WebhookEventData,
} from './catalogue';
import { assertWebhookPayloadSafe } from './payload-guard';

/** Envelope payload version of every type in 6.2 (a breaking change ships as version 2). */
export const WEBHOOK_ENVELOPE_VERSION = 1;

const ID_NAMESPACE = 'eg-webhook-event/v1';

/**
 * The deterministic public event id (W2): SHA-256 of
 * `eg-webhook-event/v1\0<sourceEventId>\0<type>\0<subKey>`, first 16 bytes, version nibble 8
 * (RFC 9562 "custom" UUID) and the RFC 9562 variant bits (`10xx`). Redelivery of the same source
 * event yields the same id, so projection is idempotent on the unique key. Also used for the
 * alert outbox event id (`webhookEventId(sourceEventId, 'alert:<kind>')`, N2).
 */
export function webhookEventId(sourceEventId: string, type: string, subKey = ''): string {
  const digest = createHash('sha256')
    .update(`${ID_NAMESPACE}\0${sourceEventId}\0${type}\0${subKey}`, 'utf8')
    .digest();
  const bytes = Buffer.from(digest.subarray(0, 16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x80;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * The public envelope (W4): `id` (deterministic, also `EG-Event-Id` and `Idempotency-Key`),
 * `type`, `version`, `occurredAt` (the source envelope's), `organizationId` (the organization's
 * **public** id) and the type's strict `data`.
 */
export const webhookEnvelopeSchema = z
  .strictObject({
    id: z.uuid(),
    type: z.enum(WEBHOOK_ENVELOPE_TYPES as [WebhookEnvelopeType, ...WebhookEnvelopeType[]]),
    version: z.literal(WEBHOOK_ENVELOPE_VERSION),
    occurredAt: z.iso.datetime(),
    organizationId: z.uuid(),
    data: z.record(z.string(), z.unknown()),
  })
  .superRefine((envelope, ctx) => {
    const result = dataSchemas[envelope.type].safeParse(envelope.data);
    if (!result.success) {
      for (const issue of result.error.issues) {
        ctx.addIssue({ code: 'custom', path: ['data', ...issue.path], message: issue.message });
      }
    }
  });

export interface WebhookEnvelope<T extends WebhookEnvelopeType = WebhookEnvelopeType> {
  id: string;
  type: T;
  version: typeof WEBHOOK_ENVELOPE_VERSION;
  occurredAt: string;
  organizationId: string;
  data: WebhookEventData<T>;
}

export interface BuildEnvelopeInput<T extends WebhookEnvelopeType> {
  type: T;
  /** The source envelope's `occurredAt` (redeliveries produce identical ids and bytes). */
  occurredAt: Date | string;
  organizationPublicId: string;
  /** The internal source event's envelope id. */
  sourceEventId: string;
  /** Distinguishes several public events of one type from one source event (W3). */
  subKey?: string;
  data: WebhookEventData<T>;
}

export interface BuiltEnvelope<T extends WebhookEnvelopeType> {
  envelope: WebhookEnvelope<T>;
  /** `JSON.stringify(envelope)`: stored once and sent byte-identically on every attempt. */
  json: string;
  /** Lower-case hex SHA-256 of `json` (UTF-8). */
  sha256: string;
}

/** Invalid input of `buildEnvelope` (names fields, never values). */
export class WebhookEnvelopeError extends Error {
  override readonly name = 'WebhookEnvelopeError';
  constructor(readonly paths: string[]) {
    super(`invalid webhook envelope: ${paths.join(', ') || '(root)'}`);
  }
}

/**
 * Builds the envelope of one public event: validates `data` with the type's strict schema (the
 * parsed object is used, so key order and therefore the serialized bytes are deterministic),
 * computes the deterministic id, runs `assertWebhookPayloadSafe` (throws `WebhookPayloadError`)
 * and serializes once.
 */
export function buildEnvelope<T extends WebhookEnvelopeType>(
  input: BuildEnvelopeInput<T>,
): BuiltEnvelope<T> {
  const occurredAt =
    input.occurredAt instanceof Date ? input.occurredAt.toISOString() : input.occurredAt;
  const candidate = {
    id: webhookEventId(input.sourceEventId, input.type, input.subKey ?? ''),
    type: input.type,
    version: WEBHOOK_ENVELOPE_VERSION,
    occurredAt,
    organizationId: input.organizationPublicId,
    data: input.data,
  };
  const head = webhookEnvelopeSchema.safeParse(candidate);
  if (!head.success) {
    throw new WebhookEnvelopeError(head.error.issues.map((issue) => issue.path.join('.')));
  }
  const data = dataSchemas[input.type].parse(input.data) as WebhookEventData<T>;
  const envelope: WebhookEnvelope<T> = { ...candidate, data } as WebhookEnvelope<T>;
  assertWebhookPayloadSafe(envelope);
  const json = JSON.stringify(envelope);
  return { envelope, json, sha256: createHash('sha256').update(json, 'utf8').digest('hex') };
}

/** Parses a stored envelope (`webhook_events.payload_json`); throws on anything else. */
export function parseStoredEnvelope(json: string): WebhookEnvelope {
  return webhookEnvelopeSchema.parse(JSON.parse(json)) as unknown as WebhookEnvelope;
}
