import {
  EVENT_REGISTRY,
  type EventEnvelope,
  EXAMPLE_EVENT_PAYLOADS,
} from '@email-gateway/event-contracts';
import type { ConsumeMessage } from 'amqplib';
import { describe, expect, it } from 'vitest';
import type { PayloadSchema } from '../outbox/outbox-poller';
import { decodeDelivery, encodeEvent, UnknownEventTypeError } from './codec';
import { HEADERS } from './headers';

const TYPE = 'mail.message.received.v1';
const event: EventEnvelope = {
  eventId: '01936b2e-7c4f-7a3b-9c1d-2e3f4a5b6c7d',
  eventType: TYPE,
  occurredAt: '2026-11-01T10:15:30.123Z',
  correlationId: 'corr-0123456789',
  organizationId: '42',
  payload: EXAMPLE_EVENT_PAYLOADS[TYPE],
};
const accepted = new Map<string, PayloadSchema<unknown>>([[TYPE, EVENT_REGISTRY[TYPE].schema]]);

function delivery(
  overrides: {
    envelope?: unknown;
    content?: Buffer;
    routingKey?: string;
    headers?: Record<string, unknown>;
    properties?: Record<string, unknown>;
  } = {},
): ConsumeMessage {
  const encoded = encodeEvent(event, 'test-app');
  return {
    content:
      overrides.content ??
      (overrides.envelope === undefined
        ? encoded.content
        : Buffer.from(JSON.stringify(overrides.envelope))),
    fields: {
      deliveryTag: 1,
      redelivered: false,
      exchange: encoded.exchange,
      routingKey: overrides.routingKey ?? encoded.routingKey,
      consumerTag: 'c',
    },
    properties: {
      ...encoded.options,
      headers: { ...(encoded.options.headers as Record<string, unknown>), ...overrides.headers },
      ...overrides.properties,
    } as unknown as ConsumeMessage['properties'],
  };
}

describe('encodeEvent', () => {
  it('sets the Q2 exchange, routing key, properties and headers', () => {
    const encoded = encodeEvent(event, 'event-relay');
    expect(encoded.exchange).toBe('email.ingestion');
    expect(encoded.routingKey).toBe('org.42.mail.message.received.v1');
    expect(JSON.parse(encoded.content.toString('utf8'))).toEqual(event);
    expect(encoded.options).toEqual({
      persistent: true,
      deliveryMode: 2,
      contentType: 'application/json',
      contentEncoding: 'utf-8',
      messageId: event.eventId,
      correlationId: event.correlationId,
      type: TYPE,
      timestamp: Math.floor(Date.parse(event.occurredAt) / 1000),
      appId: 'event-relay',
      mandatory: true,
      headers: {
        'x-eg-envelope-version': 1,
        'x-eg-event-type': TYPE,
        'x-eg-schema-version': 1,
        'x-eg-organization-id': '42',
        'x-eg-correlation-id': event.correlationId,
      },
    });
    expect(encoded.options.expiration).toBeUndefined();
  });

  it('uses the registry exchange of every type', () => {
    for (const [type, definition] of Object.entries(EVENT_REGISTRY)) {
      expect(encodeEvent({ ...event, eventType: type }, 'a').exchange).toBe(definition.exchange);
    }
  });

  it('refuses unknown and reserved types', () => {
    expect(() => encodeEvent({ ...event, eventType: 'mail.unknown.thing.v1' }, 'a')).toThrow(
      UnknownEventTypeError,
    );
    // No type is reserved since step 4.2 registered sandbox_requested.v1; a type a later step
    // defines (4.6) is unknown until it is registered.
    expect(() =>
      encodeEvent({ ...event, eventType: 'mail.attachment.sandbox_completed.v1' }, 'a'),
    ).toThrow(UnknownEventTypeError);
  });
});

describe('decodeDelivery', () => {
  it('decodes a valid delivery with its retry state', () => {
    const result = decodeDelivery(
      delivery({
        headers: {
          [HEADERS.attempt]: 3,
          [HEADERS.transientRetries]: '2',
          [HEADERS.firstFailedAt]: '2026-11-01T10:00:00.000Z',
        },
      }),
      accepted,
    );
    expect(result).toEqual({
      ok: true,
      event,
      attempt: 3,
      transientRetries: 2,
      firstFailedAt: new Date('2026-11-01T10:00:00.000Z'),
    });
  });

  it('defaults retry state and ignores malformed counters', () => {
    const result = decodeDelivery(
      delivery({ headers: { [HEADERS.attempt]: -1, [HEADERS.firstFailedAt]: 'yesterday' } }),
      accepted,
    );
    expect(result).toMatchObject({ ok: true, attempt: 0, transientRetries: 0 });
    expect(result.ok && result.firstFailedAt).toBe(undefined);
  });

  it('accepts retry, delay-expiry and other internal keys without an org segment check failure', () => {
    expect(
      decodeDelivery(delivery({ routingKey: `retry.email.received.org.42.${TYPE}` }), accepted).ok,
    ).toBe(true);
    expect(
      decodeDelivery(delivery({ routingKey: 'retry.email.delivery.pending.expired' }), accepted).ok,
    ).toBe(true);
  });

  it('unknown_event_type: a type not accepted (or missing)', () => {
    const parsed = 'mail.message.parsed.v1';
    expect(
      decodeDelivery(
        delivery({ properties: { type: parsed }, headers: { [HEADERS.eventType]: parsed } }),
        accepted,
      ),
    ).toEqual({ ok: false, reason: 'unknown_event_type' });
    expect(
      decodeDelivery(
        delivery({ properties: { type: undefined }, headers: { [HEADERS.eventType]: undefined } }),
        accepted,
      ),
    ).toEqual({ ok: false, reason: 'contract_invalid' });
  });

  it('unsupported_schema_version: header differs from the type version or is missing', () => {
    expect(decodeDelivery(delivery({ headers: { [HEADERS.schemaVersion]: 2 } }), accepted)).toEqual(
      {
        ok: false,
        reason: 'unsupported_schema_version',
      },
    );
    expect(
      decodeDelivery(delivery({ headers: { [HEADERS.schemaVersion]: undefined } }), accepted),
    ).toEqual({ ok: false, reason: 'unsupported_schema_version' });
  });

  it('contract_invalid: bad JSON, envelope, payload, type disagreement, messageId mismatch', () => {
    const invalid = { ok: false, reason: 'contract_invalid' };
    expect(decodeDelivery(delivery({ content: Buffer.from('{not json') }), accepted)).toEqual(
      invalid,
    );
    expect(decodeDelivery(delivery({ envelope: { ...event, eventId: 'nope' } }), accepted)).toEqual(
      invalid,
    );
    expect(
      decodeDelivery(delivery({ envelope: { ...event, payload: { messageId: 'x' } } }), accepted),
    ).toEqual(invalid);
    expect(
      decodeDelivery(
        delivery({ envelope: { ...event, eventType: 'mail.message.parsed.v1' } }),
        accepted,
      ),
    ).toEqual(invalid);
    expect(
      decodeDelivery(
        delivery({ headers: { [HEADERS.eventType]: 'mail.message.parsed.v1' } }),
        accepted,
      ),
    ).toEqual(invalid);
    expect(
      decodeDelivery(
        delivery({ properties: { messageId: '01936b2e-7c4f-7a3b-9c1d-000000000000' } }),
        accepted,
      ),
    ).toEqual(invalid);
    expect(
      decodeDelivery(delivery({ routingKey: 'org.42.mail.message.parsed.v1' }), accepted),
    ).toEqual(invalid);
  });

  it('tenant_mismatch: header, envelope and routing key must agree', () => {
    const mismatch = { ok: false, reason: 'tenant_mismatch' };
    expect(
      decodeDelivery(delivery({ headers: { [HEADERS.organizationId]: '43' } }), accepted),
    ).toEqual(mismatch);
    expect(
      decodeDelivery(delivery({ headers: { [HEADERS.organizationId]: undefined } }), accepted),
    ).toEqual(mismatch);
    expect(decodeDelivery(delivery({ routingKey: `org.7.${TYPE}` }), accepted)).toEqual(mismatch);
    expect(
      decodeDelivery(delivery({ routingKey: `retry.email.received.org.7.${TYPE}` }), accepted),
    ).toEqual(mismatch);
    expect(decodeDelivery(delivery({ routingKey: 'org.x.y' }), accepted)).toEqual(mismatch);
    // A numeric header is the same tenant.
    expect(
      decodeDelivery(delivery({ headers: { [HEADERS.organizationId]: 42 } }), accepted).ok,
    ).toBe(true);
  });
});
