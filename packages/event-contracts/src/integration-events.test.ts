import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import {
  EventTypes,
  INTEGRATION_CHECK_CODE_PATTERN,
  INTEGRATION_HEALTH_MAX_FAILING_CHECKS,
  INTEGRATION_HEALTH_STATUS_VALUES,
  INTEGRATION_PROVIDER_VALUES,
  integrationHealthChangedV1,
} from './events';
import { EXAMPLE_EVENT_PAYLOADS } from './examples';
import { EVENT_REGISTRY } from './registry';
import { eventRoutingKey, queueDefinition, retryRoutingKey, routeMessage } from './topology';

/**
 * Step 8.2 §4.2 (docs/plan/steps/25-m365-google-connectors.md D12, ADR-0079):
 * `integration.connection.health_changed.v1` — strict; the connection's public id, provider,
 * statuses, time and failing check codes only. The content guard over the examples runs in
 * @email-gateway/common (content-guard.test.ts covers every registered type).
 */
const type = EventTypes.IntegrationHealthChanged;
const example = EXAMPLE_EVENT_PAYLOADS[type] as Record<string, unknown>;
const ok = (fields: Record<string, unknown>) =>
  integrationHealthChangedV1.safeParse({ ...example, ...fields }).success;
const envelope = (eventType: string, payload: unknown) => ({
  eventId: randomUUID(),
  eventType,
  occurredAt: '2026-11-17T09:00:00.000Z',
  correlationId: 'corr-12345678',
  organizationId: '42',
  payload,
});

describe('step 8.2 vocabularies', () => {
  it('mirrors the Prisma IntegrationProvider and ProviderHealthStatus enums', () => {
    expect(INTEGRATION_PROVIDER_VALUES).toEqual(['microsoft_365', 'google_workspace']);
    expect(INTEGRATION_HEALTH_STATUS_VALUES).toEqual(['unknown', 'healthy', 'warning', 'critical']);
    expect(INTEGRATION_HEALTH_MAX_FAILING_CHECKS).toBe(10);
    expect(INTEGRATION_CHECK_CODE_PATTERN.test('token.acquire')).toBe(true);
  });
});

describe('integration.connection.health_changed.v1 (§4.2)', () => {
  it('is registered on email.events (aggregate provider_connection), version 1', () => {
    expect(type).toBe('integration.connection.health_changed.v1');
    expect(EVENT_REGISTRY[type]).toMatchObject({
      type,
      exchange: 'email.events',
      aggregateType: 'provider_connection',
      version: 1,
    });
  });

  it('routes to the webhook fanout and the firehose only (topology v14)', () => {
    expect(routeMessage('email.events', eventRoutingKey('42', type))).toEqual([
      'email.analytics',
      'email.webhooks',
    ]);
    // Its retry hop reaches exactly the fanout queue.
    expect(routeMessage('email.events', retryRoutingKey('email.webhooks', '42', type))).toEqual([
      'email.webhooks',
    ]);
    expect(queueDefinition('email.webhooks').bindings).toContainEqual({
      exchange: 'email.events',
      routingKey: `org.*.${type}`,
    });
  });

  it('parses the example in an envelope and rejects an unversioned type', () => {
    expect(parseEvent(envelope(type, example), integrationHealthChangedV1).payload).toEqual(
      example,
    );
    expect(() =>
      parseEvent(
        envelope('integration.connection.health_changed', example),
        integrationHealthChangedV1,
      ),
    ).toThrow();
  });

  it('accepts every provider and every real transition, including recovery with no failing check', () => {
    for (const provider of INTEGRATION_PROVIDER_VALUES) expect(ok({ provider })).toBe(true);
    for (const previousStatus of INTEGRATION_HEALTH_STATUS_VALUES) {
      for (const status of INTEGRATION_HEALTH_STATUS_VALUES) {
        expect(ok({ previousStatus, status }), `${previousStatus} → ${status}`).toBe(
          previousStatus !== status,
        );
      }
    }
    expect(ok({ previousStatus: 'critical', status: 'healthy', failingChecks: [] })).toBe(true);
  });

  it('bounds and validates the failing check codes', () => {
    const codes = Array.from({ length: 10 }, (_, i) => `check.code_${i}`);
    expect(ok({ failingChecks: codes })).toBe(true);
    expect(ok({ failingChecks: [...codes, 'check.code_10'] })).toBe(false);
    expect(ok({ failingChecks: ['a'.repeat(64)] })).toBe(true);
    expect(ok({ failingChecks: ['a'.repeat(65)] })).toBe(false);
    for (const bad of ['', 'Token.Acquire', 'token acquire', 'token-acquire', 'token/acquire']) {
      expect(ok({ failingChecks: [bad] }), bad).toBe(false);
    }
    expect(ok({ failingChecks: ['token.acquire', 'token.acquire'] })).toBe(false);
  });

  it('is strict: no extra field (tenant, domain, evidence, error text, credential)', () => {
    for (const extra of [
      { tenantId: '00000000-0000-0000-0000-000000000000' },
      { tenantName: 'Example' },
      { domain: 'acme.example' },
      { evidence: {} },
      { error: 'invalid_client' },
      { accessToken: 'x' },
      { organizationId: '42' },
    ]) {
      expect(ok(extra), Object.keys(extra)[0]).toBe(false);
    }
  });

  it('rejects malformed ids, providers, statuses and times', () => {
    expect(ok({ connectionId: '42' })).toBe(false);
    expect(ok({ connectionId: 'not-a-uuid' })).toBe(false);
    expect(ok({ provider: 'exchange' })).toBe(false);
    expect(ok({ status: 'down' })).toBe(false);
    expect(ok({ previousStatus: 'ok' })).toBe(false);
    expect(ok({ changedAt: 'yesterday' })).toBe(false);
    for (const field of [
      'connectionId',
      'provider',
      'previousStatus',
      'status',
      'changedAt',
      'failingChecks',
    ]) {
      const payload: Record<string, unknown> = { ...example };
      delete payload[field];
      expect(integrationHealthChangedV1.safeParse(payload).success, field).toBe(false);
    }
  });
});
