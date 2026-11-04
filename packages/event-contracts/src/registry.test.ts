import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import { EventTypes } from './events';
import { EXAMPLE_EVENT_PAYLOADS } from './examples';
import {
  EVENT_REGISTRY,
  type EventDefinition,
  eventDefinition,
  isRegisteredEventType,
  isReservedEventType,
  type RegisteredEventType,
  RESERVED_EVENT_TYPES,
  schemaVersionOf,
} from './registry';
import { EXCHANGE_NAMES } from './topology';

describe('EVENT_REGISTRY', () => {
  it('registers exactly the EventTypes values, keyed by their own type', () => {
    expect(Object.keys(EVENT_REGISTRY).sort()).toEqual(Object.values(EventTypes).sort());
    for (const [type, definition] of Object.entries(EVENT_REGISTRY)) {
      expect(definition.type).toBe(type);
      expect(definition.version).toBe(schemaVersionOf(type));
    }
  });

  it('maps each type to the exchange and aggregate of design Q1', () => {
    const table = Object.fromEntries(
      Object.values(EVENT_REGISTRY).map((d) => [d.type, [d.exchange, d.aggregateType]]),
    );
    expect(table).toEqual({
      'mail.message.received.v1': ['email.ingestion', 'message'],
      'mail.message.parsed.v1': ['email.ingestion', 'message'],
      'mail.message.parse_failed.v1': ['email.ingestion', 'message'],
      'mail.message.scanned.v1': ['email.security', 'message'],
      'mail.policy.decided.v1': ['email.policy', 'message'],
      'mail.delivery.approved.v1': ['email.delivery', 'message'],
      'mail.delivery.status_changed.v1': ['email.delivery', 'message'],
      'domain.status.changed.v1': ['email.events', 'domain'],
      'domain.routing.changed.v1': ['email.events', 'domain'],
    });
    for (const definition of Object.values(EVENT_REGISTRY)) {
      expect(EXCHANGE_NAMES).toContain(definition.exchange);
    }
  });

  it('parses a valid example payload of every type through its schema in an envelope', () => {
    const definitions: EventDefinition[] = Object.values(EVENT_REGISTRY);
    for (const definition of definitions) {
      const payload = EXAMPLE_EVENT_PAYLOADS[definition.type as RegisteredEventType];
      const event = parseEvent(
        {
          eventId: randomUUID(),
          eventType: definition.type,
          occurredAt: '2026-11-01T10:15:30.123Z',
          correlationId: 'corr-12345678',
          organizationId: '42',
          payload,
        },
        definition.schema,
      );
      expect(event.payload, definition.type).toEqual(payload);
    }
  });

  it('rejects an invalid payload with the registered schema', () => {
    const schema = EVENT_REGISTRY['mail.message.received.v1'].schema;
    expect(schema.safeParse({ messageId: '1' }).success).toBe(false);
  });
});

describe('reserved event types', () => {
  it('reserves mail.attachment.sandbox_requested.v1 on email.security without a schema', () => {
    expect(RESERVED_EVENT_TYPES).toEqual({
      'mail.attachment.sandbox_requested.v1': {
        type: 'mail.attachment.sandbox_requested.v1',
        version: 1,
        exchange: 'email.security',
        aggregateType: 'message',
        definedBy: 'step 4.6',
      },
    });
    for (const definition of Object.values(RESERVED_EVENT_TYPES)) {
      expect('schema' in definition).toBe(false);
      expect(isReservedEventType(definition.type)).toBe(true);
      expect(isRegisteredEventType(definition.type)).toBe(false);
      expect(eventDefinition(definition.type)).toBeUndefined();
    }
  });
});

describe('eventDefinition', () => {
  it('returns the registered definition and undefined for unknown types', () => {
    expect(eventDefinition('mail.delivery.approved.v1')?.exchange).toBe('email.delivery');
    expect(eventDefinition('mail.delivery.approved.v2')).toBeUndefined();
    expect(eventDefinition('toString')).toBeUndefined();
    expect(eventDefinition('__proto__')).toBeUndefined();
  });
});

describe('schemaVersionOf', () => {
  it('returns N of .vN', () => {
    expect(schemaVersionOf('mail.message.received.v1')).toBe(1);
    expect(schemaVersionOf('mail.delivery.status_changed.v12')).toBe(12);
  });

  it('throws on malformed types', () => {
    for (const type of [
      '',
      'mail.received',
      'mail.message.received',
      'mail.message.received.v',
      'mail.message.received.v0',
      'mail.message.received.v01',
      'mail.message.received.V1',
      'v1',
      'Mail.message.received.v1',
      'mail.message.received.v1.extra',
    ]) {
      expect(() => schemaVersionOf(type), type).toThrow('Malformed event type');
    }
  });
});
