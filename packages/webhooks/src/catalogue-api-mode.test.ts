/**
 * Step API-4 A9 (ADR-0106): the API-mode detection types `mailbox.threat.detected` and
 * `mailbox.dlp.detected` — strict metadata-only schemas, the severity rules, the filters they
 * honour, valid examples, the payload guard over their envelopes, and the `dlp_detected` alert
 * kind with its tenant settings.
 */
import { describe, expect, it } from 'vitest';
import {
  dataSchemas,
  dlpDetectionSeverity,
  eventSeverity,
  MAILBOX_DLP_ACTIONS,
  WEBHOOK_EVENT_CATALOGUE,
  WEBHOOK_EXAMPLE_DATA,
  type WebhookEnvelopeType,
  type WebhookEventData,
} from './catalogue';
import { buildEnvelope } from './envelope';
import { matchesSubscription, subscriptionEventTypesSchema } from './filters';
import {
  ALERT_RECIPIENT_PERMISSION,
  alertKindSettings,
  NOTIFICATION_SETTINGS_BOUNDS,
  notificationPreferencesSchema,
  notificationSettingsSchema,
  resolveNotificationSettings,
} from './notifications';
import { assertWebhookPayloadSafe, WebhookPayloadError } from './payload-guard';

const THREAT = 'mailbox.threat.detected';
const DLP = 'mailbox.dlp.detected';
const ORG = '0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10';
const SOURCE = '01936b2e-7c4f-7a3b-9c1d-2e3f4a5b6c7d';
const ID = (n: number) => `0193b2c3-1a2b-7c3d-8e4f-${n.toString().padStart(12, '0')}`;

const clone = <T>(value: T): T => structuredClone(value);
const ok = (type: WebhookEnvelopeType, data: unknown): boolean =>
  dataSchemas[type].safeParse(data).success;
const threat = (): WebhookEventData<typeof THREAT> => clone(WEBHOOK_EXAMPLE_DATA[THREAT]);
const dlp = (): WebhookEventData<typeof DLP> => clone(WEBHOOK_EXAMPLE_DATA[DLP]);

describe('API-4 webhook types (A9.1)', () => {
  it('are version 1, subscribable, with valid examples and the documented filters', () => {
    expect(WEBHOOK_EVENT_CATALOGUE[THREAT]).toMatchObject({
      type: THREAT,
      version: 1,
      subscribable: true,
      appliesFilters: ['directions', 'domainIds', 'minSeverity', 'verdicts'],
    });
    expect(WEBHOOK_EVENT_CATALOGUE[DLP]).toMatchObject({
      type: DLP,
      version: 1,
      subscribable: true,
      appliesFilters: ['directions', 'domainIds', 'minSeverity'],
    });
    expect(ok(THREAT, WEBHOOK_EVENT_CATALOGUE[THREAT].example)).toBe(true);
    expect(ok(DLP, WEBHOOK_EVENT_CATALOGUE[DLP].example)).toBe(true);
    expect(WEBHOOK_EVENT_CATALOGUE[THREAT].description).toContain('email.threat.detected');
    expect(subscriptionEventTypesSchema.safeParse([THREAT, DLP]).success).toBe(true);
  });

  it('mailbox.threat.detected: scan vs sandbox consistency and bounds', () => {
    const sandbox = threat();
    sandbox.detection.stage = 'sandbox';
    sandbox.detection.remediation = null;
    sandbox.detection.attachment = { partIndex: 2, sha256: 'a'.repeat(64), detectedType: 'pe32' };
    expect(ok(THREAT, sandbox)).toBe(true);
    // A sandbox detection names its attachment and carries no remediation.
    expect(ok(THREAT, { ...sandbox, detection: { ...sandbox.detection, attachment: null } })).toBe(
      false,
    );
    expect(
      ok(THREAT, {
        ...sandbox,
        detection: { ...sandbox.detection, remediation: { pending: 0, simulated: 0, skipped: 0 } },
      }),
    ).toBe(false);
    // A scan detection names no attachment.
    const scan = threat();
    scan.detection.attachment = { partIndex: 0, sha256: 'b'.repeat(64), detectedType: 'zip' };
    expect(ok(THREAT, scan)).toBe(false);
    // Outbound threat detections carry no remediation.
    const outbound = threat();
    outbound.detection.direction = 'outbound';
    outbound.detection.remediation = null;
    expect(ok(THREAT, outbound)).toBe(true);
    for (const bad of [
      { verdict: 'clean' },
      { verdict: 'phishing' },
      { protectionMode: 'inline' },
      { copySource: 'smtp' },
      { policyDisposition: 'deliver' },
      { detectionIds: [] },
      { detectionIds: Array.from({ length: 21 }, (_, i) => ID(i)) },
      { detectionIds: [ID(1), ID(1)] },
      { riskScore: 1001 },
      { mailboxCount: -1 },
      { reasonCodes: ['NotACode'] },
      { mailbox: 'someone' },
    ]) {
      expect(
        ok(THREAT, { ...threat(), detection: { ...threat().detection, ...bad } }),
        JSON.stringify(bad),
      ).toBe(false);
    }
    expect(ok(THREAT, { ...threat(), extra: true })).toBe(false);
  });

  it('mailbox.dlp.detected: actions, codes only, outbound never remediated', () => {
    for (const action of MAILBOX_DLP_ACTIONS) {
      expect(ok(DLP, { ...dlp(), dlp: { ...dlp().dlp, action } })).toBe(true);
    }
    for (const bad of [
      { action: 'allow' },
      { categories: ['Payment Card'] },
      { categories: Array.from({ length: 9 }, (_, i) => `c${i}`) },
      { categories: ['payment_card', 'payment_card'] },
      { verdict: 'x'.repeat(33) },
      { remediation: { pending: 1, simulated: 0, skipped: 0 } }, // outbound example
      { matchedValue: 'redacted' },
    ]) {
      expect(ok(DLP, { ...dlp(), dlp: { ...dlp().dlp, ...bad } }), JSON.stringify(bad)).toBe(false);
    }
    const internal = dlp();
    internal.dlp.direction = 'internal';
    internal.dlp.remediation = { pending: 1, simulated: 2, skipped: 0 };
    expect(ok(DLP, internal)).toBe(true);
  });

  it('severity: threat as email.threat.detected; DLP block/quarantine high, approval medium, alert low', () => {
    for (const [verdict, severity] of [
      ['spam', 'low'],
      ['suspicious', 'medium'],
      ['malicious', 'high'],
    ] as const) {
      const data = threat();
      data.detection.verdict = verdict;
      expect(eventSeverity(THREAT, data)).toBe(severity);
      expect(
        eventSeverity('email.threat.detected', {
          ...WEBHOOK_EXAMPLE_DATA['email.threat.detected'],
          detection: { ...WEBHOOK_EXAMPLE_DATA['email.threat.detected'].detection, verdict },
        }),
      ).toBe(severity);
    }
    for (const [action, severity] of [
      ['block', 'high'],
      ['quarantine', 'high'],
      ['require_approval', 'medium'],
      ['alert', 'low'],
    ] as const) {
      expect(dlpDetectionSeverity(action)).toBe(severity);
      expect(eventSeverity(DLP, { ...dlp(), dlp: { ...dlp().dlp, action } })).toBe(severity);
    }
  });

  it('filters: verdicts narrow threat events only; directions, domains and severity both', () => {
    const sub = (filters: object) => ({ eventTypes: [THREAT, DLP], filters });
    expect(
      matchesSubscription(sub({ verdicts: ['malicious'] }), {
        type: THREAT,
        severity: 'high',
        direction: 'inbound',
        domainPublicId: ID(9),
        verdict: 'malicious',
      }),
    ).toBe(true);
    expect(
      matchesSubscription(sub({ verdicts: ['spam'] }), {
        type: THREAT,
        severity: 'high',
        verdict: 'malicious',
      }),
    ).toBe(false);
    // A DLP event carries no verdict: the verdicts filter does not narrow it.
    expect(
      matchesSubscription(sub({ verdicts: ['spam'], directions: ['outbound'] }), {
        type: DLP,
        severity: 'high',
        direction: 'outbound',
        domainPublicId: ID(9),
      }),
    ).toBe(true);
    expect(
      matchesSubscription(sub({ minSeverity: 'medium' }), {
        type: DLP,
        severity: dlpDetectionSeverity('alert'),
        direction: 'internal',
      }),
    ).toBe(false);
  });

  it('pass the payload guard as built envelopes; content keys are refused', () => {
    for (const type of [THREAT, DLP] as const) {
      const built = buildEnvelope({
        type,
        occurredAt: '2026-11-27T09:14:05.120Z',
        organizationPublicId: ORG,
        sourceEventId: SOURCE,
        data: WEBHOOK_EXAMPLE_DATA[type],
      });
      expect(() => assertWebhookPayloadSafe(built.envelope), type).not.toThrow();
      const leaked = clone(built.envelope) as { data: { message: Record<string, unknown> } };
      leaked.data.message.address = 'someone@acme.example';
      expect(() => assertWebhookPayloadSafe(leaked)).toThrow(WebhookPayloadError);
    }
  });
});

describe('dlp_detected alert kind (A9.2)', () => {
  it('goes to dlp:read holders and defaults to enabled, medium, hourly', () => {
    expect(ALERT_RECIPIENT_PERMISSION.dlp_detected).toBe('dlp:read');
    const { settings } = resolveNotificationSettings(null);
    expect(settings.alerts.dlpDetected).toEqual({
      enabled: true,
      minSeverity: 'medium',
      throttleMinutes: 60,
    });
    expect(alertKindSettings(settings, 'dlp_detected')).toEqual(settings.alerts.dlpDetected);
    expect(notificationPreferencesSchema.safeParse({ optOut: ['dlp_detected'] }).success).toBe(
      true,
    );
  });

  it('merges stored values and enforces the bounds', () => {
    expect(NOTIFICATION_SETTINGS_BOUNDS.dlpDetected).toEqual({
      minThrottleMinutes: 15,
      maxThrottleMinutes: 1440,
    });
    const { settings, invalidStored } = resolveNotificationSettings({
      alerts: { dlpDetected: { minSeverity: 'low', throttleMinutes: 15 } },
    });
    expect(invalidStored).toBe(false);
    expect(settings.alerts.dlpDetected).toEqual({
      enabled: true,
      minSeverity: 'low',
      throttleMinutes: 15,
    });
    for (const bad of [
      { throttleMinutes: 14 },
      { throttleMinutes: 1441 },
      { minSeverity: 'info' },
      { enabled: 'yes' },
      { extra: 1 },
    ]) {
      expect(
        notificationSettingsSchema.safeParse({ alerts: { dlpDetected: bad } }).success,
        JSON.stringify(bad),
      ).toBe(false);
    }
    expect(
      notificationSettingsSchema.safeParse({
        alerts: { dlpDetected: { enabled: false, minSeverity: 'high', throttleMinutes: 1440 } },
      }).success,
    ).toBe(true);
  });
});
