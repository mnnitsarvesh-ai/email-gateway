import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import {
  COPY_DETECTED_CODE_PATTERN,
  COPY_DETECTED_DIRECTION_VALUES,
  COPY_DETECTED_MAX_DETECTION_IDS,
  COPY_DETECTED_MAX_DLP_CATEGORIES,
  COPY_DETECTED_POLICY_STATE_VALUES,
  COPY_DETECTED_PROTECTION_MODE_VALUES,
  COPY_DETECTED_SOURCE_VALUES,
  EventTypes,
  messageCopyDetectedV1,
  NOTIFICATION_ALERT_KIND_VALUES,
  notificationAlertRequestedV1,
  POLICY_ACTION_TYPE_VALUES,
  POLICY_EVALUATION_MODE_VALUES,
  policyNotificationRequestedV1,
} from './events';
import {
  EXAMPLE_API_MODE_DETECT_ONLY_ENDED_ALERT_PAYLOAD,
  EXAMPLE_COPY_DETECTED_OUTBOUND_DLP_PAYLOAD,
  EXAMPLE_DLP_DETECTED_ALERT_PAYLOAD,
  EXAMPLE_EVENT_PAYLOADS,
  EXAMPLE_POLICY_ALERT_DETECT_PAYLOAD,
} from './examples';
import { EVENT_REGISTRY } from './registry';
import {
  eventRoutingKey,
  eventTypesBoundTo,
  queueDefinition,
  routeMessage,
  TOPOLOGY_VERSION,
} from './topology';

/**
 * Step API-4 (docs/plan/steps/38-api-mode-parity-onboarding.md A7, A8, A9.2, B7, §6; contracts
 * §39): `mail.message.copy_detected.v1` (strict; ids, codes, enums, counts and times only), the
 * optional `evaluationMode` of `mail.policy.notification_requested.v1` and the alert kinds
 * `dlp_detected` and `api_mode_detect_only_ended`. The content guard over the examples runs in
 * @email-gateway/common (content-guard.test.ts covers every registered type).
 */
const envelope = (eventType: string, payload: unknown) => ({
  eventId: randomUUID(),
  eventType,
  occurredAt: '2026-11-27T09:00:00.000Z',
  correlationId: 'corr-12345678',
  organizationId: '42',
  payload,
});
const uuid = (n: number) => `01890a5d-ac96-774b-bcce-${(0xb302099a8100 + n).toString(16)}`;

describe('step API-4 vocabularies', () => {
  it('mirrors the Prisma enums and the limits of A8.2', () => {
    expect(COPY_DETECTED_SOURCE_VALUES).toEqual(['journal', 'graph', 'gmail']);
    expect(COPY_DETECTED_DIRECTION_VALUES).toEqual(['inbound', 'internal', 'outbound']);
    expect(COPY_DETECTED_PROTECTION_MODE_VALUES).toEqual(['api', 'hybrid']);
    expect(COPY_DETECTED_POLICY_STATE_VALUES).toEqual(['evaluated', 'disabled', 'failed']);
    expect(POLICY_EVALUATION_MODE_VALUES).toEqual(['inline', 'detect']);
    expect(POLICY_ACTION_TYPE_VALUES).toEqual([
      'ALLOW',
      'REJECT',
      'QUARANTINE',
      'TAG',
      'WARN',
      'REQUIRE_APPROVAL',
      'URL_REWRITE',
      'ARCHIVE',
      'ALERT',
    ]);
    expect(COPY_DETECTED_MAX_DETECTION_IDS).toBe(20);
    expect(COPY_DETECTED_MAX_DLP_CATEGORIES).toBe(8);
    for (const code of ['payment_card', 'suspicious', 'national_id', 'a']) {
      expect(code).toMatch(COPY_DETECTED_CODE_PATTERN);
    }
    for (const code of ['', 'Payment', 'card number', 'x'.repeat(33), '1abc', 'a-b']) {
      expect(code, code).not.toMatch(COPY_DETECTED_CODE_PATTERN);
    }
  });
});

describe('mail.message.copy_detected.v1 (A8, §6)', () => {
  const type = EventTypes.MessageCopyDetected;
  const example = EXAMPLE_EVENT_PAYLOADS[type] as Record<string, unknown>;
  const outbound = EXAMPLE_COPY_DETECTED_OUTBOUND_DLP_PAYLOAD as Record<string, unknown>;
  const ok = (fields: Record<string, unknown>, base: Record<string, unknown> = example) =>
    messageCopyDetectedV1.safeParse({ ...base, ...fields }).success;
  const policy = example.policy as Record<string, unknown>;
  const copies = example.copies as { counted: number; remediation: Record<string, number> };

  it('is registered on the exchange of copy_scanned.v1 (aggregate message), version 1', () => {
    expect(type).toBe('mail.message.copy_detected.v1');
    expect(EVENT_REGISTRY[type]).toMatchObject({
      type,
      exchange: EVENT_REGISTRY[EventTypes.MessageCopyScanned].exchange,
      aggregateType: 'message',
      version: 1,
    });
    expect(EVENT_REGISTRY[type].exchange).toBe('email.security');
  });

  it('routes only to email.webhooks and the firehose (topology v19)', () => {
    expect(TOPOLOGY_VERSION).toBe(19);
    expect(routeMessage('email.security', eventRoutingKey('42', type))).toEqual([
      'email.analytics',
      'email.webhooks',
    ]);
    expect(eventTypesBoundTo('email.webhooks')).toContain(type);
    // Never the policy engine, the mailbox-worker, notifications, the archive or the ATO feed.
    for (const queue of [
      'email.policy.evaluate',
      'email.mailbox',
      'email.notifications',
      'email.archive',
      'ato.mail',
    ] as const) {
      expect(eventTypesBoundTo(queue), queue).not.toContain(type);
    }
    expect(queueDefinition('email.webhooks').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'webhook-worker.fanout',
      service: 'webhook-worker',
    });
  });

  it('parses both examples in an envelope and rejects an unversioned type', () => {
    expect(parseEvent(envelope(type, example), messageCopyDetectedV1).payload).toEqual(example);
    expect(parseEvent(envelope(type, outbound), messageCopyDetectedV1).payload).toEqual(outbound);
    expect(() =>
      parseEvent(envelope('mail.message.copy_detected', example), messageCopyDetectedV1),
    ).toThrow();
  });

  it('is strict at every level (no address, subject, URL or matched value)', () => {
    expect(ok({ subject: 'Invoice' })).toBe(false);
    expect(ok({ senderAddress: 'someone@example.test' })).toBe(false);
    expect(ok({ policy: { ...policy, ruleText: 'x' } })).toBe(false);
    expect(
      ok({ dlp: { action: 'block', verdict: 'suspicious', categories: [], sample: '4111' } }),
    ).toBe(false);
    expect(ok({ copies: { ...copies, mailboxes: ['a@example.test'] } })).toBe(false);
    expect(ok({ copies: { ...copies, remediation: { ...copies.remediation, failed: 0 } } })).toBe(
      false,
    );
  });

  it('accepts the enums of existing vocabularies only', () => {
    expect(ok({ ingestSource: 'gateway' })).toBe(false);
    expect(ok({ copySource: 'imap' })).toBe(false);
    expect(ok({ direction: 'outbound' })).toBe(true);
    expect(ok({ direction: 'relay' })).toBe(false);
    expect(ok({ protectionMode: 'hybrid' })).toBe(true);
    expect(ok({ protectionMode: 'inline' })).toBe(false);
    expect(ok({ verdict: null, riskScore: null })).toBe(true);
    expect(ok({ verdict: 'dlp_violation' })).toBe(true);
    expect(ok({ verdict: 'evil' })).toBe(false);
    expect(ok({ riskScore: 1001 })).toBe(false);
    expect(ok({ riskScore: -1 })).toBe(false);
    expect(ok({ messageId: '0' })).toBe(false);
    expect(ok({ messageId: 42 })).toBe(false);
    expect(ok({ messagePublicId: 'not-a-uuid' })).toBe(false);
    expect(ok({ policy: { ...policy, actionTypes: ['DELETE'] } })).toBe(false);
    expect(ok({ policy: { ...policy, disposition: 'discard' } })).toBe(false);
    expect(ok({ policy: { ...policy, state: 'none' } })).toBe(false);
    expect(ok({ policy: { ...policy, state: 'inline' } })).toBe(false);
  });

  it('carries a DLP block only with an action other than allow and unique category codes', () => {
    const dlp = outbound.dlp as Record<string, unknown>;
    for (const action of ['alert', 'require_approval', 'quarantine', 'block']) {
      expect(ok({ dlp: { ...dlp, action } }, outbound), action).toBe(true);
    }
    expect(ok({ dlp: { ...dlp, action: 'allow' } }, outbound)).toBe(false);
    expect(ok({ dlp: { ...dlp, categories: ['payment_card', 'payment_card'] } }, outbound)).toBe(
      false,
    );
    expect(ok({ dlp: { ...dlp, categories: ['Payment Card'] } }, outbound)).toBe(false);
    const nine = Array.from({ length: 9 }, (_, i) => `category_${i}`);
    expect(ok({ dlp: { ...dlp, categories: nine.slice(0, 8) } }, outbound)).toBe(true);
    expect(ok({ dlp: { ...dlp, categories: nine } }, outbound)).toBe(false);
    expect(ok({ dlp: { ...dlp, verdict: 'x'.repeat(33) } }, outbound)).toBe(false);
  });

  it('keeps the policy block consistent with its state', () => {
    expect(ok({ policy: { ...policy, disposition: null } })).toBe(false);
    expect(ok({ policy: { ...policy, decisionSource: null } })).toBe(false);
    expect(ok({ policy: { ...policy, decisionSource: 'floor', overrideApplied: true } })).toBe(
      true,
    );
    for (const state of ['disabled', 'failed']) {
      const none = {
        state,
        disposition: null,
        decisionSource: null,
        overrideApplied: false,
        actionTypes: [],
      };
      expect(ok({ policy: none }), state).toBe(true);
      expect(ok({ policy: { ...none, disposition: 'allow' } }), state).toBe(false);
      expect(ok({ policy: { ...none, decisionSource: 'platform_default' } }), state).toBe(false);
      expect(ok({ policy: { ...none, overrideApplied: true } }), state).toBe(false);
      expect(ok({ policy: { ...none, actionTypes: ['TAG'] } }), state).toBe(false);
    }
    expect(ok({ policy: { ...policy, actionTypes: ['ALERT', 'ALERT'] } })).toBe(false);
    expect(ok({ policy: { ...policy, actionTypes: [...POLICY_ACTION_TYPE_VALUES] } })).toBe(true);
  });

  it('bounds the detection ids (1..20, unique, no more than counted copies)', () => {
    const many = (n: number) => Array.from({ length: n }, (_, i) => uuid(i));
    const counted = (n: number) => ({
      counted: n,
      remediation: { pending: n, simulated: 0, skipped: 0, none: 0 },
    });
    expect(ok({ detectionIds: [] })).toBe(false);
    expect(ok({ detectionIds: many(20), copies: counted(20) })).toBe(true);
    expect(ok({ detectionIds: many(20), copies: counted(500) })).toBe(true);
    expect(ok({ detectionIds: many(21), copies: counted(21) })).toBe(false);
    expect(ok({ detectionIds: many(3), copies: counted(2) })).toBe(false);
    expect(ok({ detectionIds: [uuid(1), uuid(1)] })).toBe(false);
    expect(ok({ detectionIds: ['17'] })).toBe(false);
  });

  it('adds the remediation counts up to copies.counted (at least one copy)', () => {
    expect(
      ok({
        copies: { counted: 4, remediation: { pending: 1, simulated: 1, skipped: 1, none: 1 } },
      }),
    ).toBe(true);
    expect(
      ok({
        copies: { counted: 3, remediation: { pending: 1, simulated: 1, skipped: 1, none: 1 } },
      }),
    ).toBe(false);
    expect(
      ok({
        detectionIds: [],
        copies: { counted: 0, remediation: { pending: 0, simulated: 0, skipped: 0, none: 0 } },
      }),
    ).toBe(false);
    expect(
      ok({
        copies: { counted: 2, remediation: { pending: 2.5, simulated: 0, skipped: 0, none: 0 } },
      }),
    ).toBe(false);
  });
});

describe('mail.policy.notification_requested.v1 evaluationMode (A7)', () => {
  const inline = EXAMPLE_EVENT_PAYLOADS[EventTypes.PolicyNotificationRequested] as Record<
    string,
    unknown
  >;
  const detect = EXAMPLE_POLICY_ALERT_DETECT_PAYLOAD as Record<string, unknown>;
  const ok = (payload: unknown) => policyNotificationRequestedV1.safeParse(payload).success;

  it('is optional and additive: absent = inline (policy-engine payloads stay valid)', () => {
    expect('evaluationMode' in inline).toBe(false);
    expect(ok(inline)).toBe(true);
    expect(ok({ ...inline, evaluationMode: 'inline' })).toBe(true);
    expect(ok(detect)).toBe(true);
    expect(ok({ ...detect, evaluationMode: 'post_delivery' })).toBe(false);
    expect(ok({ ...detect, evaluationMode: null })).toBe(false);
  });

  it('never requests a sender non-delivery notice for a detect evaluation', () => {
    expect(ok({ ...inline, evaluationMode: 'detect' })).toBe(false);
    expect(ok({ ...detect, kind: 'sender_non_delivery', direction: 'outbound' })).toBe(false);
  });
});

describe('notification.alert_requested.v1 API-4 kinds (A9.2, B7)', () => {
  const okAlert = (payload: unknown) => notificationAlertRequestedV1.safeParse(payload).success;

  it('appends dlp_detected and api_mode_detect_only_ended', () => {
    expect(NOTIFICATION_ALERT_KIND_VALUES.slice(-2)).toEqual([
      'dlp_detected',
      'api_mode_detect_only_ended',
    ]);
  });

  it('requires the webhook event id, message id and received time for dlp_detected', () => {
    const base = EXAMPLE_DLP_DETECTED_ALERT_PAYLOAD;
    expect(okAlert(base)).toBe(true);
    for (const severity of ['low', 'medium', 'high']) {
      expect(okAlert({ ...base, severity }), severity).toBe(true);
    }
    for (const field of ['webhookEventId', 'messageId', 'receivedAt'] as const) {
      const refs: Record<string, unknown> = { ...base.refs };
      delete refs[field];
      expect(okAlert({ ...base, refs }), field).toBe(false);
    }
  });

  it('requires the remediation policy public id for api_mode_detect_only_ended', () => {
    const base = EXAMPLE_API_MODE_DETECT_ONLY_ENDED_ALERT_PAYLOAD;
    expect(okAlert(base)).toBe(true);
    expect(okAlert({ ...base, severity: 'medium' })).toBe(true);
    expect(okAlert({ ...base, refs: {} })).toBe(false);
    expect(okAlert({ ...base, refs: { remediationPolicyId: '17' } })).toBe(false);
    expect(okAlert({ ...base, refs: { ...base.refs, policyName: 'x' } })).toBe(false);
  });

  it('accepts remediationPolicyId as an optional ref of other kinds (refs stay strict)', () => {
    const base = EXAMPLE_DLP_DETECTED_ALERT_PAYLOAD;
    expect(okAlert({ ...base, refs: { ...base.refs, remediationPolicyId: uuid(9) } })).toBe(true);
  });
});
