import {
  eventDefinition,
  type EventEnvelope,
  eventEnvelopeSchema,
  eventRoutingKey,
  parseRoutingKey,
  schemaVersionOf,
} from '@email-gateway/event-contracts';
import type { ConsumeMessage, Message, Options } from 'amqplib';
import type { PayloadSchema } from '../outbox/outbox-poller';
import { ENVELOPE_VERSION, HEADERS, integerHeader, stringHeader } from './headers';

/** Q2 base headers of an envelope. */
export function baseHeaders(envelope: EventEnvelope): Record<string, string | number> {
  return {
    [HEADERS.envelopeVersion]: ENVELOPE_VERSION,
    [HEADERS.eventType]: envelope.eventType,
    [HEADERS.schemaVersion]: schemaVersionOf(envelope.eventType),
    [HEADERS.organizationId]: envelope.organizationId,
    [HEADERS.correlationId]: envelope.correlationId,
  };
}

/** Error of `encodeEvent` for a type that is not registered (or reserved, without a schema). */
export class UnknownEventTypeError extends Error {
  override readonly name = 'UnknownEventTypeError';
  readonly code = 'unknown_event_type';
  constructor() {
    super('event type is not registered');
  }
}

export interface EncodedEvent {
  exchange: string;
  routingKey: string;
  content: Buffer;
  options: Options.Publish;
}

/**
 * The AMQP message of an envelope (Q2): the registry exchange, `org.<id>.<eventType>`, the JSON
 * envelope as UTF-8 body, persistent, `messageId = eventId`, `correlationId`, `type`,
 * `timestamp = occurredAt` (seconds), `appId`, the base headers, `mandatory`. Throws
 * `UnknownEventTypeError` for an unknown or reserved type. Validation of the payload is the
 * producer's (the relay validates with the registry schema before publishing).
 */
export function encodeEvent(envelope: EventEnvelope, appId: string): EncodedEvent {
  const definition = eventDefinition(envelope.eventType);
  if (!definition) throw new UnknownEventTypeError();
  return {
    exchange: definition.exchange,
    routingKey: eventRoutingKey(envelope.organizationId, envelope.eventType),
    content: Buffer.from(JSON.stringify(envelope), 'utf8'),
    options: {
      persistent: true,
      deliveryMode: 2,
      contentType: 'application/json',
      contentEncoding: 'utf-8',
      messageId: envelope.eventId,
      correlationId: envelope.correlationId,
      type: envelope.eventType,
      timestamp: Math.floor(Date.parse(envelope.occurredAt) / 1000),
      appId,
      headers: baseHeaders(envelope),
      mandatory: true,
    },
  };
}

export type DecodeFailureReason =
  'contract_invalid' | 'unknown_event_type' | 'unsupported_schema_version' | 'tenant_mismatch';

export type DecodeResult<T> =
  | {
      ok: true;
      event: EventEnvelope<T>;
      attempt: number;
      transientRetries: number;
      firstFailedAt?: Date;
    }
  | { ok: false; reason: DecodeFailureReason };

/** Retry state of a delivery's headers (also for deliveries that fail to decode). */
export function retryState(msg: Message): {
  attempt: number;
  transientRetries: number;
  firstFailedAt?: Date;
} {
  const headers = msg.properties.headers;
  const firstFailedRaw = stringHeader(headers, HEADERS.firstFailedAt);
  const firstFailedMs = firstFailedRaw === undefined ? Number.NaN : Date.parse(firstFailedRaw);
  return {
    attempt: integerHeader(headers, HEADERS.attempt),
    transientRetries: integerHeader(headers, HEADERS.transientRetries),
    ...(Number.isFinite(firstFailedMs) ? { firstFailedAt: new Date(firstFailedMs) } : {}),
  };
}

const fail = (reason: DecodeFailureReason): { ok: false; reason: DecodeFailureReason } => ({
  ok: false,
  reason,
});

/**
 * Decodes and checks a delivery (Q3, §2.0.5). In order:
 *
 * 1. event type = `type` property (or `x-eg-event-type`; both present → they must agree, else
 *    `contract_invalid`); not in `accepted` → `unknown_event_type`;
 * 2. `x-eg-schema-version` must equal `N` of the type's `.vN` → else `unsupported_schema_version`;
 * 3. the body must be a JSON envelope of that type whose payload passes the accepted schema,
 *    and `messageId` (when set) must equal `eventId` → else `contract_invalid`;
 * 4. tenant: `x-eg-organization-id` must be present and equal `envelope.organizationId`, and the
 *    routing key's `org.<id>` segment (when the key has one) must equal it as well → else
 *    `tenant_mismatch`.
 *
 * Never throws; failures carry a reason code only (no values).
 */
export function decodeDelivery<T>(
  msg: ConsumeMessage | Message,
  accepted: ReadonlyMap<string, PayloadSchema<T>>,
): DecodeResult<T> {
  const headers = msg.properties.headers;
  const propertyType: unknown = msg.properties.type;
  const headerType = stringHeader(headers, HEADERS.eventType);
  if (propertyType !== undefined && typeof propertyType !== 'string') {
    return fail('contract_invalid');
  }
  if (propertyType !== undefined && headerType !== undefined && propertyType !== headerType) {
    return fail('contract_invalid');
  }
  const eventType = propertyType ?? headerType;
  if (eventType === undefined) return fail('contract_invalid');
  const schema = accepted.get(eventType);
  if (!schema) return fail('unknown_event_type');

  const declaredVersion = integerHeader(headers, HEADERS.schemaVersion, -1);
  if (declaredVersion !== schemaVersionOf(eventType)) return fail('unsupported_schema_version');

  let raw: unknown;
  try {
    raw = JSON.parse(msg.content.toString('utf8'));
  } catch {
    return fail('contract_invalid');
  }
  const envelope = eventEnvelopeSchema.safeParse(raw);
  if (!envelope.success || envelope.data.eventType !== eventType) return fail('contract_invalid');
  let payload: T;
  try {
    payload = schema.parse(envelope.data.payload);
  } catch {
    return fail('contract_invalid');
  }
  const messageId: unknown = msg.properties.messageId;
  if (messageId !== undefined && messageId !== envelope.data.eventId) {
    return fail('contract_invalid');
  }

  const organizationId = envelope.data.organizationId;
  const headerValue: unknown = headers?.[HEADERS.organizationId];
  const headerOrganization =
    typeof headerValue === 'number' || typeof headerValue === 'bigint'
      ? String(headerValue)
      : stringHeader(headers, HEADERS.organizationId);
  if (headerOrganization !== organizationId) {
    return fail('tenant_mismatch');
  }
  const key = parseRoutingKey(msg.fields.routingKey);
  if (key?.organizationId !== undefined && key.organizationId !== organizationId) {
    return fail('tenant_mismatch');
  }
  if (key === null && msg.fields.routingKey.startsWith('org.')) return fail('tenant_mismatch');
  if (key?.eventType !== undefined && key.eventType !== eventType) return fail('contract_invalid');

  return { ok: true, event: { ...envelope.data, payload }, ...retryState(msg) };
}
