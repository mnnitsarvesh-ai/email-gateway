import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import {
  EventTypes,
  HARD_BLOCK_ID_PATTERN,
  LATE_SIGNAL_KIND_VALUES,
  LATE_SIGNAL_LEVEL_VALUES,
  LATE_SIGNAL_MAX_HARD_BLOCKS,
  LATE_SIGNAL_MAX_HASHES,
  MESSAGE_VERDICT_VALUES,
  NOTIFICATION_ALERT_KIND_VALUES,
  notificationAlertRequestedV1,
  REPORT_FEEDBACK_KIND_VALUES,
  reportFeedbackRequestedV1,
  threatLateSignalV1,
} from './events';
import {
  EXAMPLE_API_MODE_PURGE_APPROVAL_ALERT_PAYLOAD,
  EXAMPLE_API_MODE_REPORT_RECEIVED_ALERT_PAYLOAD,
  EXAMPLE_EVENT_PAYLOADS,
} from './examples';
import { EVENT_REGISTRY } from './registry';
import { eventRoutingKey, eventTypesBoundTo, queueDefinition, routeMessage } from './topology';

/**
 * Step API-3 (docs/plan/steps/37-api-mode-clawback-reporting.md C2.1, C6, C12, C13, §5;
 * contracts §38): `mail.threat.late_signal.v1` (strict; ids, verdict, level, hard-block ids,
 * hashes and times only), `mail.report.feedback_requested.v1` (strict; report id, kind, time)
 * and the alert kinds `api_mode_purge_approval` and `api_mode_report_received`. The content guard
 * over the examples runs in @email-gateway/common (content-guard.test.ts covers every registered
 * type).
 */
const envelope = (eventType: string, payload: unknown) => ({
  eventId: randomUUID(),
  eventType,
  occurredAt: '2026-11-27T09:00:00.000Z',
  correlationId: 'corr-12345678',
  organizationId: '42',
  payload,
});
const hex = (char: string) => char.repeat(64);

describe('step API-3 vocabularies', () => {
  it('names the late-signal kinds, the Prisma RiskLevel values and the limits of §5', () => {
    expect(LATE_SIGNAL_KIND_VALUES).toEqual(['sandbox_revision', 'url_dynamic']);
    expect(LATE_SIGNAL_LEVEL_VALUES).toEqual(['none', 'low', 'medium', 'high', 'critical']);
    expect(LATE_SIGNAL_MAX_HASHES).toBe(20);
    expect(LATE_SIGNAL_MAX_HARD_BLOCKS).toBe(9);
    expect(REPORT_FEEDBACK_KIND_VALUES).toEqual(['received', 'resolved']);
    for (const id of ['hb.clawback.url', 'hb.clawback.threat_intel', 'hb.clawback.analyst']) {
      expect(id).toMatch(HARD_BLOCK_ID_PATTERN);
    }
    for (const id of ['', 'HB.Upper', 'hb clawback', 'hb/clawback', 'x'.repeat(65)]) {
      expect(id, id).not.toMatch(HARD_BLOCK_ID_PATTERN);
    }
  });
});

describe('mail.threat.late_signal.v1 (C2.1, §5)', () => {
  const type = EventTypes.ThreatLateSignal;
  const example = EXAMPLE_EVENT_PAYLOADS[type] as Record<string, unknown>;
  const urlSignal = {
    ...example,
    kind: 'url_dynamic',
    revision: null,
    verdict: 'phishing',
    level: 'critical',
    hardBlocks: ['hb.clawback.url'],
    attachmentSha256: [],
    urlSha256: [hex('b')],
  };
  const ok = (fields: Record<string, unknown>, base: Record<string, unknown> = example) =>
    threatLateSignalV1.safeParse({ ...base, ...fields }).success;

  it('is registered on the exchange of copy_scanned.v1 (aggregate message), version 1', () => {
    expect(type).toBe('mail.threat.late_signal.v1');
    expect(EVENT_REGISTRY[type]).toMatchObject({
      type,
      exchange: EVENT_REGISTRY[EventTypes.MessageCopyScanned].exchange,
      aggregateType: 'message',
      version: 1,
    });
    expect(EVENT_REGISTRY[type].exchange).toBe('email.security');
  });

  it('routes only to email.mailbox and the firehose (topology v18)', () => {
    expect(routeMessage('email.security', eventRoutingKey('42', type))).toEqual([
      'email.analytics',
      'email.mailbox',
    ]);
    expect(eventTypesBoundTo('email.mailbox')).toContain(type);
    // Never the policy engine, the webhook fanout, notifications or the ATO mail feed.
    for (const queue of [
      'email.policy.evaluate',
      'email.webhooks',
      'email.notifications',
      'ato.mail',
    ] as const) {
      expect(eventTypesBoundTo(queue), queue).not.toContain(type);
    }
    // Same consumer and ledger as copy_scanned.v1.
    expect(queueDefinition('email.mailbox').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'mailbox-worker.copies',
      service: 'mailbox-worker',
    });
  });

  it('parses both examples in an envelope and rejects an unversioned type', () => {
    expect(parseEvent(envelope(type, example), threatLateSignalV1).payload).toEqual(example);
    expect(parseEvent(envelope(type, urlSignal), threatLateSignalV1).payload).toEqual(urlSignal);
    expect(() =>
      parseEvent(envelope('mail.threat.late_signal', example), threatLateSignalV1),
    ).toThrow();
  });

  it('accepts every verdict and level, and refuses unknown values', () => {
    for (const verdict of MESSAGE_VERDICT_VALUES) expect(ok({ verdict }), verdict).toBe(true);
    for (const level of LATE_SIGNAL_LEVEL_VALUES) expect(ok({ level }), level).toBe(true);
    expect(ok({ verdict: 'evil' })).toBe(false);
    expect(ok({ level: 'severe' })).toBe(false);
    expect(ok({ kind: 'threat_indicator' })).toBe(false);
  });

  it('is strict and carries ids and times in their formats', () => {
    expect(ok({ subject: 'Invoice' })).toBe(false);
    expect(ok({ url: 'https://example.com/' })).toBe(false);
    expect(ok({ messageId: '0' })).toBe(false);
    expect(ok({ messageId: 42 })).toBe(false);
    expect(ok({ scanId: 'abc' })).toBe(false);
    expect(ok({ receivedAt: 'yesterday' })).toBe(false);
    expect(ok({ signalAt: '2026-11-27' })).toBe(false);
    for (const field of ['kind', 'messageId', 'receivedAt', 'scanId', 'revision', 'signalAt']) {
      const payload: Record<string, unknown> = { ...example };
      delete payload[field];
      expect(threatLateSignalV1.safeParse(payload).success, field).toBe(false);
    }
  });

  it('keeps sandbox revisions and URL verdicts consistent', () => {
    // sandbox_revision: a revision ≥ 1, no URL hash.
    expect(ok({ revision: null })).toBe(false);
    expect(ok({ revision: 0 })).toBe(false);
    expect(ok({ revision: 2 })).toBe(true);
    expect(ok({ urlSha256: [hex('c')] })).toBe(false);
    expect(ok({ attachmentSha256: [] })).toBe(true);
    // url_dynamic: no revision, at least one URL hash, no attachment hash.
    expect(ok({}, urlSignal)).toBe(true);
    expect(ok({ revision: 1 }, urlSignal)).toBe(false);
    expect(ok({ urlSha256: [] }, urlSignal)).toBe(false);
    expect(ok({ attachmentSha256: [hex('a')] }, urlSignal)).toBe(false);
    expect(ok({ hardBlocks: [], verdict: 'suspicious', level: 'high' }, urlSignal)).toBe(true);
  });

  it('caps the hash arrays at 20 lower-case hex SHA-256 values, unique', () => {
    const hashes = (n: number) =>
      Array.from({ length: n }, (_, i) => i.toString(16).padStart(2, '0').repeat(32));
    expect(ok({ attachmentSha256: hashes(20) })).toBe(true);
    expect(ok({ attachmentSha256: hashes(21) })).toBe(false);
    expect(ok({ urlSha256: hashes(20) }, urlSignal)).toBe(true);
    expect(ok({ urlSha256: hashes(21) }, urlSignal)).toBe(false);
    expect(ok({ attachmentSha256: [hex('A')] })).toBe(false);
    expect(ok({ attachmentSha256: ['a'.repeat(63)] })).toBe(false);
    expect(ok({ attachmentSha256: [hex('g')] })).toBe(false);
    expect(ok({ attachmentSha256: [hex('a'), hex('a')] })).toBe(false);
    expect(ok({ urlSha256: [hex('b'), hex('b')] }, urlSignal)).toBe(false);
  });

  it('accepts at most 9 hard-block ids of the documented pattern, unique', () => {
    const ids = (n: number) => Array.from({ length: n }, (_, i) => `hb.rule_${i}`);
    expect(ok({ hardBlocks: [] })).toBe(true);
    expect(ok({ hardBlocks: ids(9) })).toBe(true);
    expect(ok({ hardBlocks: ids(10) })).toBe(false);
    expect(ok({ hardBlocks: ['hb.sandbox:malicious-1'] })).toBe(true);
    expect(ok({ hardBlocks: ['HB.SANDBOX'] })).toBe(false);
    expect(ok({ hardBlocks: ['hb sandbox'] })).toBe(false);
    expect(ok({ hardBlocks: ['x'.repeat(65)] })).toBe(false);
    expect(ok({ hardBlocks: ['hb.a', 'hb.a'] })).toBe(false);
  });
});

describe('mail.report.feedback_requested.v1 (C12, §5)', () => {
  const type = EventTypes.ReportFeedbackRequested;
  const example = EXAMPLE_EVENT_PAYLOADS[type] as Record<string, unknown>;
  const ok = (fields: Record<string, unknown>) =>
    reportFeedbackRequestedV1.safeParse({ ...example, ...fields }).success;

  it('is registered on email.policy (aggregate organization), version 1', () => {
    expect(type).toBe('mail.report.feedback_requested.v1');
    expect(EVENT_REGISTRY[type]).toMatchObject({
      type,
      exchange: 'email.policy',
      aggregateType: 'organization',
      version: 1,
    });
  });

  it('routes only to email.notifications and the firehose (topology v18), like quarantine notifications', () => {
    expect(routeMessage('email.policy', eventRoutingKey('42', type))).toEqual(
      routeMessage(
        'email.policy',
        eventRoutingKey('42', EventTypes.QuarantineNotificationRequested),
      ),
    );
    expect(eventTypesBoundTo('email.notifications')).toContain(type);
    expect(eventTypesBoundTo('email.mailbox')).not.toContain(type);
    expect(queueDefinition('email.notifications').consumer).toMatchObject({
      kind: 'ledger',
      service: 'notification-worker',
    });
  });

  it('parses both kinds in an envelope', () => {
    expect(parseEvent(envelope(type, example), reportFeedbackRequestedV1).payload).toEqual(example);
    for (const kind of REPORT_FEEDBACK_KIND_VALUES) expect(ok({ kind }), kind).toBe(true);
  });

  it('is strict: a report public id, a kind and a time only', () => {
    expect(ok({ kind: 'reminder' })).toBe(false);
    expect(ok({ reportId: '17' })).toBe(false);
    expect(ok({ requestedAt: 'now' })).toBe(false);
    expect(ok({ reporterAddress: 'user@example.com' })).toBe(false);
    expect(ok({ verdict: 'malicious' })).toBe(false);
    expect(ok({ subject: 'Invoice' })).toBe(false);
    for (const field of ['reportId', 'kind', 'requestedAt']) {
      const payload: Record<string, unknown> = { ...example };
      delete payload[field];
      expect(reportFeedbackRequestedV1.safeParse(payload).success, field).toBe(false);
    }
  });
});

describe('notification.alert_requested.v1 API-3 kinds (C6, C13)', () => {
  const uuid = '01890a5d-ac96-774b-bcce-b302099a80e1';
  const okAlert = (payload: unknown) => notificationAlertRequestedV1.safeParse(payload).success;

  it('appends api_mode_purge_approval and api_mode_report_received', () => {
    expect(NOTIFICATION_ALERT_KIND_VALUES.slice(-2)).toEqual([
      'api_mode_purge_approval',
      'api_mode_report_received',
    ]);
  });

  it('requires the clawback public id for api_mode_purge_approval', () => {
    const base = EXAMPLE_API_MODE_PURGE_APPROVAL_ALERT_PAYLOAD;
    expect(okAlert(base)).toBe(true);
    expect(okAlert({ ...base, severity: 'high' })).toBe(true);
    expect(okAlert({ ...base, refs: {} })).toBe(false);
    expect(okAlert({ ...base, refs: { clawbackId: '17' } })).toBe(false);
    expect(okAlert({ ...base, refs: { apiModeConnectionId: uuid } })).toBe(false);
    expect(okAlert({ ...base, refs: { clawbackId: uuid, apiModeConnectionId: uuid } })).toBe(true);
    expect(okAlert({ ...base, refs: { clawbackId: uuid, reason: 'text' } })).toBe(false);
  });

  it('needs no refs for api_mode_report_received, and refs stay consistent', () => {
    const base = EXAMPLE_API_MODE_REPORT_RECEIVED_ALERT_PAYLOAD;
    expect(okAlert(base)).toBe(true);
    expect(okAlert({ ...base, refs: { clawbackId: uuid } })).toBe(true);
    // messageId and receivedAt still go together; the window is ordered.
    expect(okAlert({ ...base, refs: { messageId: '9' } })).toBe(false);
    expect(okAlert({ ...base, window: { from: base.window.to, to: base.window.from } })).toBe(
      false,
    );
    expect(okAlert({ ...base, refs: { reporterAddress: 'user@example.com' } })).toBe(false);
  });

  it('keeps the clawbackId ref optional for every other kind', () => {
    const example = EXAMPLE_EVENT_PAYLOADS[EventTypes.NotificationAlertRequested] as {
      refs: Record<string, unknown>;
    };
    expect(okAlert(example)).toBe(true);
    expect(okAlert({ ...example, refs: { ...example.refs, clawbackId: uuid } })).toBe(true);
  });
});
