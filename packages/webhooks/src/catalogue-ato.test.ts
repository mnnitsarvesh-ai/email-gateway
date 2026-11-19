/**
 * Step 8.4 D16: the four public security incident and account takeover types — strict
 * metadata-only schemas, the severity mapping, the filters they honour, the "ignore unknown
 * categories" note, and the payload guard over their envelopes (no address, IP or name).
 */
import { describe, expect, it } from 'vitest';
import {
  dataSchemas,
  eventSeverity,
  incidentWebhookSeverity,
  WEBHOOK_EVENT_CATALOGUE,
  WEBHOOK_EXAMPLE_DATA,
  type WebhookEnvelopeType,
} from './catalogue';
import { buildEnvelope } from './envelope';
import { assertWebhookPayloadSafe, WebhookPayloadError } from './payload-guard';

const TYPES = [
  'security.incident.created',
  'security.incident.updated',
  'ato.account.risk_changed',
  'ato.response.completed',
] as const;

const clone = <T>(value: T): T => structuredClone(value);
const ok = (type: WebhookEnvelopeType, data: unknown): boolean =>
  dataSchemas[type].safeParse(data).success;

describe('step 8.4 webhook types (D16)', () => {
  it('are version 1, filter by minSeverity only and document ignoring unknown categories', () => {
    for (const type of TYPES) {
      const entry = WEBHOOK_EVENT_CATALOGUE[type];
      expect(entry.version).toBe(1);
      expect(entry.subscribable).toBe(true);
      expect(entry.appliesFilters).toEqual(['minSeverity']);
      expect(ok(type, entry.example), type).toBe(true);
    }
    for (const type of ['security.incident.created', 'security.incident.updated'] as const) {
      expect(WEBHOOK_EVENT_CATALOGUE[type].description.toLowerCase()).toContain(
        'unknown categories',
      );
    }
  });

  it('maps incident severities and risk levels: critical/high → high, medium, low', () => {
    expect(incidentWebhookSeverity('critical')).toBe('high');
    expect(incidentWebhookSeverity('high')).toBe('high');
    expect(incidentWebhookSeverity('medium')).toBe('medium');
    expect(incidentWebhookSeverity('low')).toBe('low');
    const created = WEBHOOK_EXAMPLE_DATA['security.incident.created'];
    for (const [severity, expected] of [
      ['critical', 'high'],
      ['high', 'high'],
      ['medium', 'medium'],
      ['low', 'low'],
    ] as const) {
      expect(
        eventSeverity('security.incident.created', {
          ...created,
          incident: { ...created.incident, severity },
        }),
      ).toBe(expected);
    }
    const updated = WEBHOOK_EXAMPLE_DATA['security.incident.updated'];
    expect(eventSeverity('security.incident.updated', updated)).toBe('high');
    const risk = WEBHOOK_EXAMPLE_DATA['ato.account.risk_changed'];
    expect(
      eventSeverity('ato.account.risk_changed', {
        ...risk,
        risk: { score: 35, level: 'medium', previousLevel: 'low' },
      }),
    ).toBe('medium');
    expect(
      eventSeverity('ato.account.risk_changed', {
        ...risk,
        risk: { score: 5, level: 'low', previousLevel: 'medium' },
      }),
    ).toBe('low');
  });

  it('ato.response.completed is medium for failures and info otherwise', () => {
    const base = WEBHOOK_EXAMPLE_DATA['ato.response.completed'];
    const of = (status: string) =>
      eventSeverity('ato.response.completed', {
        ...base,
        response: { ...base.response, status },
      } as never);
    expect(of('failed')).toBe('medium');
    expect(of('rollback_failed')).toBe('medium');
    for (const status of ['succeeded', 'unsupported', 'rolled_back', 'attested', 'rejected']) {
      expect(of(status), status).toBe('info');
    }
  });

  it('refuses extra keys, addresses-as-ids, unknown categories, kinds and statuses', () => {
    for (const type of TYPES) {
      expect(ok(type, { ...clone(WEBHOOK_EXAMPLE_DATA[type]), extra: 1 }), type).toBe(false);
    }
    const created = clone(WEBHOOK_EXAMPLE_DATA['security.incident.created']);
    expect(
      ok('security.incident.created', {
        ...created,
        subject: { type: 'ato_account', id: 'j@x.example' },
      }),
    ).toBe(false);
    expect(
      ok('security.incident.created', {
        ...created,
        incident: { ...created.incident, category: 'message_threat' },
      }),
    ).toBe(false);
    expect(
      ok('security.incident.created', {
        ...created,
        incident: { ...created.incident, status: 'confirmed' },
      }),
    ).toBe(false);
    expect(
      ok('security.incident.created', {
        ...created,
        incident: {
          ...created.incident,
          reasonCodes: Array.from({ length: 17 }, (_, i) => `ato.r.c${i}`),
        },
      }),
    ).toBe(false);
    expect(
      ok('security.incident.created', {
        ...created,
        incident: { ...created.incident, address: 'j@x.example' },
      }),
    ).toBe(false);
    const risk = clone(WEBHOOK_EXAMPLE_DATA['ato.account.risk_changed']);
    expect(
      ok('ato.account.risk_changed', { ...risk, account: { ...risk.account, kind: 'robot' } }),
    ).toBe(false);
    expect(ok('ato.account.risk_changed', { ...risk, risk: { ...risk.risk, score: 101 } })).toBe(
      false,
    );
    expect(
      ok('ato.account.risk_changed', { ...risk, account: { ...risk.account, name: 'Jane' } }),
    ).toBe(false);
    const response = clone(WEBHOOK_EXAMPLE_DATA['ato.response.completed']);
    expect(ok('ato.response.completed', { ...response, incident: null })).toBe(true);
    expect(
      ok('ato.response.completed', {
        ...response,
        response: { ...response.response, status: 'pending_approval' },
      }),
    ).toBe(false);
    expect(
      ok('ato.response.completed', {
        ...response,
        response: { ...response.response, ip: '203.0.113.7' },
      }),
    ).toBe(false);
  });

  it('security.incident.updated lists status and severity exactly when they changed', () => {
    const base = clone(WEBHOOK_EXAMPLE_DATA['security.incident.updated']);
    expect(ok('security.incident.updated', { ...base, changedFields: ['status'] })).toBe(false);
    expect(
      ok('security.incident.updated', {
        ...base,
        previous: { status: 'confirmed', severity: 'critical' },
        changedFields: ['assignee'],
      }),
    ).toBe(true);
    expect(
      ok('security.incident.updated', {
        ...base,
        previous: { status: 'confirmed', severity: 'critical' },
        changedFields: ['assignee', 'assignee'],
      }),
    ).toBe(false);
  });

  it('ato.account.risk_changed is sent only for a level change', () => {
    const base = clone(WEBHOOK_EXAMPLE_DATA['ato.account.risk_changed']);
    expect(
      ok('ato.account.risk_changed', {
        ...base,
        risk: { score: 80, level: 'high', previousLevel: 'high' },
      }),
    ).toBe(false);
  });

  it('every example envelope passes the payload guard; an address or IP-like name is refused', () => {
    for (const type of TYPES) {
      const built = buildEnvelope({
        type,
        occurredAt: '2026-11-18T10:42:00.000Z',
        organizationPublicId: '0193a1b2-3e4f-7051-8c6d-7e8f90123456',
        sourceEventId: '0193a1b2-4f50-7162-9d7e-8f9012345678',
        data: WEBHOOK_EXAMPLE_DATA[type],
      });
      expect(() => assertWebhookPayloadSafe(built.envelope), type).not.toThrow();
    }
    const envelope = {
      id: '0193a1b2-4f50-7162-9d7e-8f9012345678',
      data: { account: { id: 'x', kind: 'mailbox', address: 'jane@corp.example' } },
    };
    expect(() => assertWebhookPayloadSafe(envelope)).toThrow(WebhookPayloadError);
  });
});
