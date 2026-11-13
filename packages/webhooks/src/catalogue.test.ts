import { describe, expect, it } from 'vitest';
import {
  dataSchemas,
  eventSeverity,
  isWebhookEnvelopeType,
  isWebhookEventType,
  SEVERITIES,
  severityRank,
  WEBHOOK_ENVELOPE_TYPES,
  WEBHOOK_EVENT_CATALOGUE,
  WEBHOOK_EVENT_TYPES,
  WEBHOOK_EXAMPLE_DATA,
  WEBHOOK_PING_TYPE,
  type WebhookEnvelopeType,
  webhookEventTypeSchema,
} from './catalogue';

const clone = <T>(value: T): T => structuredClone(value);
const ok = (type: WebhookEnvelopeType, data: unknown): boolean =>
  dataSchemas[type].safeParse(data).success;

describe('catalogue (§5)', () => {
  it('lists exactly the ten subscribable types plus the ping', () => {
    expect([...WEBHOOK_EVENT_TYPES]).toEqual([
      'email.received',
      'email.scanned',
      'email.threat.detected',
      'email.policy.triggered',
      'email.quarantined',
      'email.released',
      'email.delivered',
      'email.rejected',
      'domain.verified',
      'domain.dns.failed',
    ]);
    expect(WEBHOOK_PING_TYPE).toBe('webhook.ping');
    expect(WEBHOOK_ENVELOPE_TYPES).toEqual([...WEBHOOK_EVENT_TYPES, 'webhook.ping']);
    expect(webhookEventTypeSchema.safeParse('webhook.ping').success).toBe(false);
    expect(webhookEventTypeSchema.safeParse('email.*').success).toBe(false);
    expect(isWebhookEventType('email.received')).toBe(true);
    expect(isWebhookEventType('webhook.ping')).toBe(false);
    expect(isWebhookEnvelopeType('webhook.ping')).toBe(true);
    expect(isWebhookEnvelopeType('toString')).toBe(false);
  });

  it('has a version-1 catalogue entry with filters and a valid example for every type', () => {
    expect(Object.keys(WEBHOOK_EVENT_CATALOGUE)).toEqual([...WEBHOOK_ENVELOPE_TYPES]);
    for (const type of WEBHOOK_ENVELOPE_TYPES) {
      const entry = WEBHOOK_EVENT_CATALOGUE[type];
      expect(entry.type).toBe(type);
      expect(entry.version).toBe(1);
      expect(entry.description.length, type).toBeGreaterThan(10);
      expect(entry.severity.length, type).toBeGreaterThan(0);
      expect(entry.subscribable, type).toBe(type !== WEBHOOK_PING_TYPE);
      const parsed = dataSchemas[type].safeParse(entry.example);
      expect(parsed.success, `${type}: ${JSON.stringify(parsed.error?.issues)}`).toBe(true);
      expect(entry.example).toBe(WEBHOOK_EXAMPLE_DATA[type]);
    }
    expect(WEBHOOK_EVENT_CATALOGUE['email.scanned'].appliesFilters).toEqual([
      'directions',
      'domainIds',
      'minSeverity',
      'verdicts',
    ]);
    expect(WEBHOOK_EVENT_CATALOGUE['email.threat.detected'].appliesFilters).toContain('verdicts');
    for (const type of [
      'email.received',
      'email.policy.triggered',
      'email.quarantined',
      'email.released',
      'email.delivered',
      'email.rejected',
    ] as const) {
      expect(WEBHOOK_EVENT_CATALOGUE[type].appliesFilters, type).toEqual([
        'directions',
        'domainIds',
        'minSeverity',
      ]);
    }
    for (const type of ['domain.verified', 'domain.dns.failed'] as const) {
      expect(WEBHOOK_EVENT_CATALOGUE[type].appliesFilters, type).toEqual([
        'domainIds',
        'minSeverity',
      ]);
    }
    expect(WEBHOOK_EVENT_CATALOGUE['webhook.ping'].appliesFilters).toEqual([]);
  });

  it('rejects an extra key at the top, in the shared message and in every type object', () => {
    for (const type of WEBHOOK_ENVELOPE_TYPES) {
      const data = clone(WEBHOOK_EXAMPLE_DATA[type]) as Record<string, unknown>;
      expect(ok(type, { ...data, extra: 1 }), type).toBe(false);
      for (const [key, value] of Object.entries(data)) {
        if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
          expect(ok(type, { ...data, [key]: { ...value, extra: 1 } }), `${type}.${key}`).toBe(
            false,
          );
        }
      }
    }
  });

  it('bounds the shared message object (§5.1): domains only, no local part, ≤ 20 recipient domains', () => {
    const base = clone(WEBHOOK_EXAMPLE_DATA['email.received']);
    const withMessage = (fields: Record<string, unknown>) =>
      ok('email.received', { message: { ...base.message, ...fields } });
    expect(withMessage({ senderDomain: 'Partner.Example' })).toBe(false);
    expect(withMessage({ senderDomain: 'user@partner.example' })).toBe(false);
    expect(withMessage({ senderDomain: null, headerFromDomain: null })).toBe(true);
    expect(withMessage({ domainId: null })).toBe(true);
    expect(withMessage({ domainId: 'acme.example' })).toBe(false);
    expect(withMessage({ recipientDomains: ['a.example', 'a.example'] })).toBe(false);
    expect(
      withMessage({ recipientDomains: Array.from({ length: 20 }, (_, i) => `d${i}.example`) }),
    ).toBe(true);
    expect(
      withMessage({ recipientDomains: Array.from({ length: 21 }, (_, i) => `d${i}.example`) }),
    ).toBe(false);
    expect(withMessage({ internetMessageId: 'x'.repeat(255) })).toBe(true);
    expect(withMessage({ internetMessageId: 'x'.repeat(256) })).toBe(false);
    expect(withMessage({ internetMessageId: 'a\r\nb' })).toBe(false);
    expect(withMessage({ internetMessageId: null })).toBe(true);
    expect(withMessage({ direction: 'sideways' })).toBe(false);
    expect(withMessage({ sizeBytes: -1 })).toBe(false);
    expect(withMessage({ id: 'not-a-uuid' })).toBe(false);
    expect(withMessage({ subject: 'Invoice' })).toBe(false);
  });

  it('enforces the per-type consistency rules and bounds', () => {
    const threat = clone(WEBHOOK_EXAMPLE_DATA['email.threat.detected']);
    expect(
      ok('email.threat.detected', {
        ...threat,
        detection: { ...threat.detection, verdict: 'clean' },
      }),
    ).toBe(false);
    expect(
      ok('email.threat.detected', {
        ...threat,
        detection: {
          ...threat.detection,
          stage: 'sandbox',
          finalAction: null,
          attachment: { partIndex: 2, sha256: 'a'.repeat(64), detectedType: 'pe_executable' },
        },
      }),
    ).toBe(true);
    expect(
      ok('email.threat.detected', {
        ...threat,
        detection: { ...threat.detection, stage: 'sandbox' },
      }),
    ).toBe(false);
    expect(
      ok('email.threat.detected', {
        ...threat,
        detection: {
          ...threat.detection,
          attachment: { partIndex: 2, sha256: 'a'.repeat(64), detectedType: 'pdf' },
        },
      }),
    ).toBe(false);
    expect(
      ok('email.threat.detected', {
        ...threat,
        detection: { ...threat.detection, riskScore: 1001 },
      }),
    ).toBe(false);

    const quarantined = clone(WEBHOOK_EXAMPLE_DATA['email.quarantined']);
    expect(
      ok('email.quarantined', {
        ...quarantined,
        quarantine: { ...quarantined.quarantine, kinds: { quarantine: 1, review: 0 } },
      }),
    ).toBe(false);
    expect(
      ok('email.quarantined', {
        ...quarantined,
        quarantine: {
          ...quarantined.quarantine,
          entryCount: 60,
          kinds: { quarantine: 60, review: 0 },
          entryIds: Array.from(
            { length: 51 },
            (_, i) => `0192f0c4-a133-7e40-9f51-${String(i).padStart(12, '0')}`,
          ),
        },
      }),
    ).toBe(false);

    const rejected = clone(WEBHOOK_EXAMPLE_DATA['email.rejected']);
    expect(
      ok('email.rejected', {
        ...rejected,
        rejection: { ...rejected.rejection, stage: 'delivery' },
      }),
    ).toBe(false);
    expect(
      ok('email.rejected', {
        ...rejected,
        rejection: { ...rejected.rejection, reason: 'delivery_failed', stage: 'delivery' },
      }),
    ).toBe(true);

    const policy = clone(WEBHOOK_EXAMPLE_DATA['email.policy.triggered']);
    expect(
      ok('email.policy.triggered', { ...policy, policy: { ...policy.policy, matchedRules: [] } }),
    ).toBe(false);
    expect(
      ok('email.policy.triggered', {
        ...policy,
        policy: { ...policy.policy, decisive: { ...policy.policy.decisive, ruleId: 'Bad Rule' } },
      }),
    ).toBe(false);

    const scanned = clone(WEBHOOK_EXAMPLE_DATA['email.scanned']);
    expect(
      ok('email.scanned', {
        ...scanned,
        scan: { ...scanned.scan, engines: [scanned.scan.engines[0], scanned.scan.engines[0]] },
      }),
    ).toBe(false);
    expect(
      ok('email.scanned', { ...scanned, scan: { ...scanned.scan, reasonCodes: ['NotACode'] } }),
    ).toBe(false);

    const dns = clone(WEBHOOK_EXAMPLE_DATA['domain.dns.failed']);
    expect(ok('domain.dns.failed', { ...dns, failure: { ...dns.failure, records: [] } })).toBe(
      false,
    );
    expect(
      ok('domain.dns.failed', {
        ...dns,
        failure: {
          kind: 'verification_failed',
          reason: 'verification_expired',
          records: [],
          checkedAt: dns.failure.checkedAt,
        },
      }),
    ).toBe(true);

    const released = clone(WEBHOOK_EXAMPLE_DATA['email.released']);
    expect(
      ok('email.released', { ...released, release: { ...released.release, deliverySeq: -1 } }),
    ).toBe(false);
    // A fully quarantined message has no earlier delivery: its first release is sequence 0.
    expect(
      ok('email.released', { ...released, release: { ...released.release, deliverySeq: 0 } }),
    ).toBe(true);
    expect(
      ok('webhook.ping', { subscriptionId: 'x', requestedAt: '2026-11-13T00:00:00.000Z' }),
    ).toBe(false);
  });
});

describe('severities (§5.2)', () => {
  it('ranks info < low < medium < high', () => {
    expect([...SEVERITIES]).toEqual(['info', 'low', 'medium', 'high']);
    expect(SEVERITIES.map(severityRank)).toEqual([0, 1, 2, 3]);
    expect(() => severityRank('critical' as never)).toThrow();
  });

  it('applies the fixed severity rule of every type', () => {
    const d = WEBHOOK_EXAMPLE_DATA;
    const scanned = (verdict: string) =>
      eventSeverity('email.scanned', {
        ...d['email.scanned'],
        scan: { ...d['email.scanned'].scan, verdict },
      } as never);
    expect(
      ['clean', 'unknown', 'timeout', 'error', 'spam', 'suspicious', 'malicious'].map(scanned),
    ).toEqual(['info', 'info', 'info', 'info', 'low', 'medium', 'high']);
    const threat = (verdict: string) =>
      eventSeverity('email.threat.detected', {
        ...d['email.threat.detected'],
        detection: { ...d['email.threat.detected'].detection, verdict },
      } as never);
    expect(['spam', 'suspicious', 'malicious'].map(threat)).toEqual(['low', 'medium', 'high']);
    const policy = (disposition: string) =>
      eventSeverity('email.policy.triggered', {
        ...d['email.policy.triggered'],
        policy: { ...d['email.policy.triggered'].policy, disposition },
      } as never);
    expect(['allow', 'require_approval', 'quarantine', 'reject'].map(policy)).toEqual([
      'low',
      'medium',
      'medium',
      'medium',
    ]);
    expect(eventSeverity('email.quarantined', d['email.quarantined'])).toBe('medium');
    expect(eventSeverity('email.rejected', d['email.rejected'])).toBe('low');
    for (const type of [
      'email.received',
      'email.released',
      'email.delivered',
      'domain.verified',
      'webhook.ping',
    ] as const) {
      expect(eventSeverity(type, d[type] as never), type).toBe('info');
    }
    const dns = d['domain.dns.failed'];
    const records = (purpose: string) =>
      eventSeverity('domain.dns.failed', {
        ...dns,
        failure: { ...dns.failure, records: [{ ...dns.failure.records[0]!, purpose }] },
      } as never);
    expect(['mx', 'spf', 'dkim', 'dmarc'].map(records)).toEqual(['high', 'high', 'high', 'high']);
    expect(['mta_sts', 'tls_rpt', 'verification'].map(records)).toEqual([
      'medium',
      'medium',
      'medium',
    ]);
    expect(
      eventSeverity('domain.dns.failed', {
        ...dns,
        failure: { ...dns.failure, kind: 'verification_failed' },
      }),
    ).toBe('medium');
    expect(() => eventSeverity('email.unknown' as never, {} as never)).toThrow();
  });
});
