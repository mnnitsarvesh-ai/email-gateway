import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import {
  DLP_INCIDENT_ACTION_SOURCE_VALUES,
  DLP_INCIDENT_ACTION_VALUES,
  DLP_SEVERITY_VALUES,
  EventTypes,
  messageDlpIncidentV1,
} from './events';
import { EXAMPLE_EVENT_PAYLOADS } from './examples';
import { EVENT_REGISTRY } from './registry';
import { eventRoutingKey, routeMessage, TOPOLOGY } from './topology';

/** Step 4.5 D14: the DLP incident event `mail.message.dlp_incident.v1`. */
const type = 'mail.message.dlp_incident.v1';
const example = EXAMPLE_EVENT_PAYLOADS[type] as Record<string, unknown>;
const ok = (payload: unknown) => messageDlpIncidentV1.safeParse(payload).success;
const patch = (fields: Record<string, unknown>) => ({ ...example, ...fields });
const defaultPolicy = { actionSource: 'default_policy', policyId: null, ruleId: null };

describe('mail.message.dlp_incident.v1 (step 4.5 D14)', () => {
  it('is registered on email.security with aggregate message, version 1', () => {
    expect(EventTypes.MessageDlpIncident).toBe(type);
    expect(EVENT_REGISTRY[type]).toMatchObject({
      type,
      version: 1,
      exchange: 'email.security',
      aggregateType: 'message',
    });
    expect(EVENT_REGISTRY[type].schema).toBe(messageDlpIncidentV1);
  });

  it('parses its example inside an envelope', () => {
    const event = parseEvent(
      {
        eventId: randomUUID(),
        eventType: type,
        occurredAt: '2026-11-01T10:15:31.900Z',
        correlationId: 'corr-12345678',
        organizationId: '42',
        payload: example,
      },
      messageDlpIncidentV1,
    );
    expect(event.payload).toEqual(example);
    expect(example).toMatchObject({ action: 'quarantine', actionSource: 'tenant_policy' });
  });

  it('routes only to the analytics firehose (no queue binds it in topology v7)', () => {
    expect(routeMessage('email.security', eventRoutingKey('42', type))).toEqual([
      'email.analytics',
    ]);
    const bound = TOPOLOGY.queues.filter((q) =>
      q.bindings.some((b) => b.routingKey === `org.*.${type}`),
    );
    expect(bound).toEqual([]);
  });

  it('carries every action but allow, and both action sources', () => {
    expect([...DLP_INCIDENT_ACTION_VALUES]).toEqual([
      'alert',
      'require_approval',
      'quarantine',
      'block',
    ]);
    for (const action of DLP_INCIDENT_ACTION_VALUES) {
      expect(ok(patch({ action })), action).toBe(true);
      expect(ok(patch({ action, ...defaultPolicy })), `${action} default`).toBe(true);
    }
    expect(ok(patch({ action: 'allow' }))).toBe(false);
    expect(ok(patch({ action: 'ALERT' }))).toBe(false);
    expect([...DLP_INCIDENT_ACTION_SOURCE_VALUES]).toEqual(['tenant_policy', 'default_policy']);
    expect(ok(patch({ actionSource: 'none', policyId: null, ruleId: null }))).toBe(false);
  });

  it('accepts a coverage-only incident (no category) only with partial coverage', () => {
    const coverageOnly = {
      categories: [],
      detectorCodes: ['dlp.not_extracted.encrypted'],
      coverage: 'partial',
      evidenceAvailable: false,
    };
    expect(ok(patch(coverageOnly))).toBe(true);
    expect(ok(patch({ ...coverageOnly, coverage: 'complete' }))).toBe(false);
    expect(ok(patch({ ...coverageOnly, detectorCodes: [] }))).toBe(false);
  });

  it('accepts every severity, a zero count (coverage-reason match) and the bounds', () => {
    for (const maxSeverity of DLP_SEVERITY_VALUES) {
      expect(
        ok(patch({ categories: [{ category: 'credential', count: 1, maxSeverity }] })),
        maxSeverity,
      ).toBe(true);
    }
    expect(
      ok(
        patch({
          categories: [{ category: 'custom', count: 0, maxSeverity: 'info' }],
          detectorCodes: ['dlp.not_extracted.encrypted'],
          coverage: 'partial',
        }),
      ),
    ).toBe(true);
    const ten = [
      'payment_card',
      'bank_account',
      'national_id',
      'passport',
      'personal_info',
      'confidential',
      'source_code',
      'credential',
      'financial',
      'custom',
    ].map((category) => ({ category, count: 1_000_000, maxSeverity: 'critical' }));
    expect(ok(patch({ categories: ten }))).toBe(true);
    const codes = Array.from({ length: 24 }, (_, i) => `dlp.code_${i}.x`);
    expect(ok(patch({ detectorCodes: codes }))).toBe(true);
    expect(ok(patch({ lifecycleRound: 65_535, exceptionApplied: true }))).toBe(true);
    expect(ok(patch({ evidenceAvailable: false, coverage: 'complete' }))).toBe(true);
  });

  it('refuses malformed ids, rounds, categories, codes and policy references', () => {
    for (const fields of [
      { messageId: '0' },
      { messageId: 42 },
      { scanId: '011' },
      { receivedAt: '2026-11-01' },
      { detectedAt: 'now' },
      { direction: 'sideways' },
      { lifecycleRound: -1 },
      { lifecycleRound: 65_536 },
      { lifecycleRound: 1.5 },
      { coverage: 'none' },
      { exceptionApplied: 'yes' },
      { evidenceAvailable: 1 },
      { policyId: 'policy-1' },
      { ruleId: '42' },
      { policyId: null },
      { ruleId: null },
      { ...defaultPolicy, policyId: '01890a5d-ac96-774b-bcce-b302099a8061' },
      { ...defaultPolicy, ruleId: '01890a5d-ac96-774b-bcce-b302099a8062' },
      { categories: [], coverage: 'complete' },
      {
        categories: Array.from({ length: 11 }, (_, i) => ({
          category: `cat_${String.fromCharCode(97 + i)}`,
          count: 1,
          maxSeverity: 'low',
        })),
      },
      { categories: [{ category: 'payment.card', count: 1, maxSeverity: 'high' }] },
      { categories: [{ category: 'PaymentCard', count: 1, maxSeverity: 'high' }] },
      { categories: [{ category: 'p', count: 1, maxSeverity: 'high' }] },
      { categories: [{ category: 'a'.repeat(33), count: 1, maxSeverity: 'high' }] },
      { categories: [{ category: 'payment_card', count: -1, maxSeverity: 'high' }] },
      { categories: [{ category: 'payment_card', count: 1_000_001, maxSeverity: 'high' }] },
      { categories: [{ category: 'payment_card', count: 1.5, maxSeverity: 'high' }] },
      { categories: [{ category: 'payment_card', count: 1, maxSeverity: 'severe' }] },
      {
        categories: [
          { category: 'payment_card', count: 1, maxSeverity: 'high' },
          { category: 'payment_card', count: 2, maxSeverity: 'low' },
        ],
      },
      { detectorCodes: [] },
      { detectorCodes: Array.from({ length: 25 }, (_, i) => `dlp.code_${i}.x`) },
      { detectorCodes: ['dlp.payment_card.number', 'dlp.payment_card.number'] },
      { detectorCodes: ['dlp'] },
      { detectorCodes: ['DLP.payment_card.number'] },
      { detectorCodes: ['spam.score'] },
      { detectorCodes: [`dlp.${'x'.repeat(61)}`] },
    ]) {
      expect(ok(patch(fields)), JSON.stringify(fields)).toBe(false);
    }
  });

  it('is strict: no value, masked sample, address, name or text can be added', () => {
    for (const extra of [
      { maskedSamples: ['************0366'] },
      { values: ['4532015112830366'] },
      { sender: 'cfo@example.com' },
      { recipients: ['partner@example.net'] },
      { policyName: 'Cards outbound' },
      { subject: 'Q3 payroll' },
      { text: 'card 4532 0151 1283 0366' },
    ]) {
      expect(ok(patch(extra)), Object.keys(extra)[0]).toBe(false);
    }
    expect(
      ok(
        patch({
          categories: [{ category: 'payment_card', count: 1, maxSeverity: 'high', masked: 'x' }],
        }),
      ),
    ).toBe(false);
    for (const field of Object.keys(example)) {
      const { [field]: _dropped, ...missing } = example;
      expect(ok(missing), field).toBe(false);
    }
  });
});
