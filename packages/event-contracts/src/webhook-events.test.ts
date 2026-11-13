import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import {
  DNS_RECORD_PURPOSE_VALUES,
  DNS_RECORD_STATUS_VALUES,
  DOMAIN_DNS_RECORDS_CHANGED_MAX_CHANGES,
  domainDnsRecordsChangedV1,
  EventTypes,
  NOTIFICATION_ALERT_KIND_VALUES,
  NOTIFICATION_ALERT_SEVERITY_VALUES,
  notificationAlertRequestedV1,
} from './events';
import { EXAMPLE_EVENT_PAYLOADS } from './examples';
import { EVENT_REGISTRY } from './registry';
import { eventRoutingKey, queueDefinition, routeMessage } from './topology';

/**
 * Step 6.2 §4.1 (docs/plan/steps/19-webhooks-notifications.md): `domain.dns.records_changed.v1`
 * and `notification.alert_requested.v1` — strict, ids and codes only. The content guard over the
 * examples runs in @email-gateway/common (content-guard.test.ts covers every registered type).
 */
const dns = EXAMPLE_EVENT_PAYLOADS['domain.dns.records_changed.v1'] as Record<string, unknown>;
const alert = EXAMPLE_EVENT_PAYLOADS['notification.alert_requested.v1'] as Record<string, unknown>;
const okDns = (fields: Record<string, unknown>) =>
  domainDnsRecordsChangedV1.safeParse({ ...dns, ...fields }).success;
const okAlert = (fields: Record<string, unknown>) =>
  notificationAlertRequestedV1.safeParse({ ...alert, ...fields }).success;
const envelope = (eventType: string, payload: unknown) => ({
  eventId: randomUUID(),
  eventType,
  occurredAt: '2026-11-13T09:00:00.000Z',
  correlationId: 'corr-12345678',
  organizationId: '42',
  payload,
});
const change = (
  recordKey: string,
  previousStatus: string = 'valid',
  status: string = 'invalid',
  purpose: string = 'spf',
) => ({ recordKey, purpose, previousStatus, status });

describe('step 6.2 vocabularies', () => {
  it('mirrors the Prisma DNS record enums and the alert kinds of N1', () => {
    expect(DNS_RECORD_PURPOSE_VALUES).toEqual([
      'verification',
      'mx',
      'spf',
      'dkim',
      'dmarc',
      'mta_sts',
      'tls_rpt',
    ]);
    expect(DNS_RECORD_STATUS_VALUES).toEqual(['pending', 'valid', 'invalid', 'missing']);
    expect(DOMAIN_DNS_RECORDS_CHANGED_MAX_CHANGES).toBe(32);
    expect(NOTIFICATION_ALERT_KIND_VALUES).toEqual([
      'threat_detected',
      'domain_dns_failed',
      'webhook_disabled',
    ]);
    expect(NOTIFICATION_ALERT_SEVERITY_VALUES).toEqual(['info', 'low', 'medium', 'high']);
  });
});

describe('domain.dns.records_changed.v1 (§4.1)', () => {
  const type = EventTypes.DomainDnsRecordsChanged;

  it('is registered on email.events (aggregate domain) and routes to the webhook fanout', () => {
    expect(type).toBe('domain.dns.records_changed.v1');
    expect(EVENT_REGISTRY[type]).toMatchObject({
      exchange: 'email.events',
      aggregateType: 'domain',
      version: 1,
    });
    expect(routeMessage('email.events', eventRoutingKey('42', type))).toEqual([
      'email.analytics',
      'email.webhooks',
    ]);
    expect(queueDefinition('email.webhooks').consumer).toMatchObject({
      ledgerName: 'webhook-worker.fanout',
    });
  });

  it('parses the example in an envelope', () => {
    const event = parseEvent(envelope(type, dns), domainDnsRecordsChangedV1);
    expect(event.payload).toEqual(dns);
  });

  it('rejects an unversioned event type', () => {
    expect(() =>
      parseEvent(envelope('domain.dns.records_changed', dns), domainDnsRecordsChangedV1),
    ).toThrow();
  });

  it('is strict at every level and carries no observed or expected value', () => {
    expect(okDns({ observed: 'v=spf1 -all' })).toBe(false);
    expect(okDns({ changes: [{ ...change('spf'), expected: 'v=spf1' }] })).toBe(false);
    expect(okDns({ changes: [{ ...change('spf'), evidence: 'x' }] })).toBe(false);
    expect(Object.keys(domainDnsRecordsChangedV1.parse(dns)).sort()).toEqual(
      ['checkedAt', 'changes', 'domainId', 'domainPublicId', 'domainStatus', 'name'].sort(),
    );
  });

  it('requires 1..32 real, unique transitions', () => {
    expect(okDns({ changes: [] })).toBe(false);
    expect(okDns({ changes: [change('spf', 'valid', 'valid')] })).toBe(false);
    expect(okDns({ changes: [change('spf'), change('spf', 'pending', 'valid')] })).toBe(false);
    expect(
      okDns({
        changes: Array.from({ length: 32 }, (_, i) => change(`dkim:s${i}`, 'pending', 'valid')),
      }),
    ).toBe(true);
    expect(
      okDns({
        changes: Array.from({ length: 33 }, (_, i) => change(`dkim:s${i}`, 'pending', 'valid')),
      }),
    ).toBe(false);
    for (const purpose of DNS_RECORD_PURPOSE_VALUES) {
      expect(okDns({ changes: [change('k', 'valid', 'missing', purpose)] }), purpose).toBe(true);
    }
    expect(okDns({ changes: [change('k', 'valid', 'missing', 'txt')] })).toBe(false);
    expect(okDns({ changes: [change('k', 'valid', 'broken')] })).toBe(false);
    expect(okDns({ changes: [change('k'.repeat(192))] })).toBe(false);
  });

  it('validates the domain identity fields', () => {
    expect(okDns({ domainId: '0' })).toBe(false);
    expect(okDns({ domainId: 77 })).toBe(false);
    expect(okDns({ domainPublicId: 'not-a-uuid' })).toBe(false);
    expect(okDns({ name: '' })).toBe(false);
    expect(okDns({ name: 'a'.repeat(254) })).toBe(false);
    expect(okDns({ name: 'bücher.example' })).toBe(false);
    expect(okDns({ name: 'xn--bcher-kva.example' })).toBe(true);
    expect(okDns({ domainStatus: '' })).toBe(false);
    expect(okDns({ checkedAt: 'yesterday' })).toBe(false);
  });
});

describe('notification.alert_requested.v1 (N2, §4.1)', () => {
  const type = EventTypes.NotificationAlertRequested;
  const uuid = '0193a1b2-7c3d-8e4f-9a0b-1c2d3e4f5a6b';

  it('is registered on email.policy (aggregate organization) and routes to the notification-worker', () => {
    expect(type).toBe('notification.alert_requested.v1');
    expect(EVENT_REGISTRY[type]).toMatchObject({
      exchange: 'email.policy',
      aggregateType: 'organization',
      version: 1,
    });
    expect(routeMessage('email.policy', eventRoutingKey('42', type))).toEqual([
      'email.analytics',
      'email.notifications',
    ]);
  });

  it('parses the example in an envelope and rejects an unversioned type', () => {
    expect(parseEvent(envelope(type, alert), notificationAlertRequestedV1).payload).toEqual(alert);
    expect(() =>
      parseEvent(envelope('notification.alert_requested', alert), notificationAlertRequestedV1),
    ).toThrow();
  });

  it('requires the refs of each kind', () => {
    const base = { window: alert.window, counts: alert.counts, requestedAt: alert.requestedAt };
    const threatRefs = { webhookEventId: uuid, messageId: '9', receivedAt: alert.requestedAt };
    expect(okAlert({ ...base, kind: 'threat_detected', refs: threatRefs })).toBe(true);
    for (const missing of ['webhookEventId', 'messageId', 'receivedAt']) {
      const refs: Record<string, unknown> = { ...threatRefs };
      delete refs[missing];
      expect(okAlert({ ...base, kind: 'threat_detected', refs }), missing).toBe(false);
    }
    expect(
      okAlert({
        ...base,
        kind: 'domain_dns_failed',
        refs: { webhookEventId: uuid, domainId: '7' },
      }),
    ).toBe(true);
    expect(okAlert({ ...base, kind: 'domain_dns_failed', refs: { domainId: '7' } })).toBe(false);
    expect(okAlert({ ...base, kind: 'domain_dns_failed', refs: { webhookEventId: uuid } })).toBe(
      false,
    );
    expect(okAlert({ ...base, kind: 'webhook_disabled', refs: { subscriptionId: uuid } })).toBe(
      true,
    );
    expect(okAlert({ ...base, kind: 'webhook_disabled', refs: {} })).toBe(false);
    // messageId and receivedAt go together, whatever the kind.
    expect(
      okAlert({
        ...base,
        kind: 'webhook_disabled',
        refs: { subscriptionId: uuid, messageId: '9' },
      }),
    ).toBe(false);
  });

  it('is strict, bounded and ids-only', () => {
    expect(okAlert({ subject: 'Invoice' })).toBe(false);
    expect(okAlert({ refs: { ...(alert.refs as object), address: 'a@b.example' } })).toBe(false);
    expect(okAlert({ counts: { suppressedBefore: 1, extra: 2 } })).toBe(false);
    expect(okAlert({ counts: { suppressedBefore: -1 } })).toBe(false);
    expect(okAlert({ counts: { suppressedBefore: 1.5 } })).toBe(false);
    expect(
      okAlert({ window: { from: '2026-11-01T11:00:00.000Z', to: '2026-11-01T11:00:00.000Z' } }),
    ).toBe(false);
    expect(
      okAlert({ window: { from: '2026-11-01T12:00:00.000Z', to: '2026-11-01T11:00:00.000Z' } }),
    ).toBe(false);
    expect(okAlert({ kind: 'policy_alert' })).toBe(false);
    expect(okAlert({ severity: 'critical' })).toBe(false);
    for (const severity of NOTIFICATION_ALERT_SEVERITY_VALUES) {
      expect(okAlert({ severity }), severity).toBe(true);
    }
    expect(okAlert({ refs: { ...(alert.refs as object), messageId: 'abc' } })).toBe(false);
  });
});
