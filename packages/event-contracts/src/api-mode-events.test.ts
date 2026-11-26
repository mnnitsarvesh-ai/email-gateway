import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import {
  COPY_SCAN_OUTCOME_VALUES,
  EventTypes,
  MESSAGE_COPY_INGEST_SOURCE_VALUES,
  MESSAGE_INGEST_SOURCE_VALUES,
  MESSAGE_VERDICT_VALUES,
  messageCopyScannedV1,
  notificationAlertRequestedV1,
} from './events';
import { EXAMPLE_API_MODE_UNHEALTHY_ALERT_PAYLOAD, EXAMPLE_EVENT_PAYLOADS } from './examples';
import { EVENT_REGISTRY } from './registry';
import { eventRoutingKey, eventTypesBoundTo, queueDefinition, routeMessage } from './topology';

/**
 * Step API-1 (docs/plan/steps/35-api-mode-protection.md D8, D11.3, §5; contracts §36):
 * `mail.message.copy_scanned.v1` (strict; ids, outcome, verdict, risk score and times only) and
 * the `api_mode_unhealthy` alert kind. The content guard over the examples runs in
 * @email-gateway/common (content-guard.test.ts covers every registered type).
 */
const type = EventTypes.MessageCopyScanned;
const example = EXAMPLE_EVENT_PAYLOADS[type] as Record<string, unknown>;
const ok = (fields: Record<string, unknown>) =>
  messageCopyScannedV1.safeParse({ ...example, ...fields }).success;
const envelope = (eventType: string, payload: unknown) => ({
  eventId: randomUUID(),
  eventType,
  occurredAt: '2026-11-26T09:00:00.000Z',
  correlationId: 'corr-12345678',
  organizationId: '42',
  payload,
});

describe('step API-1 vocabularies', () => {
  it('mirrors the Prisma MessageIngestSource enum (mailbox_api appended)', () => {
    expect(MESSAGE_INGEST_SOURCE_VALUES).toEqual(['gateway', 'journal_intake', 'mailbox_api']);
    expect(MESSAGE_COPY_INGEST_SOURCE_VALUES).toEqual(['journal_intake', 'mailbox_api']);
    expect(COPY_SCAN_OUTCOME_VALUES).toEqual(['scanned', 'scan_failed', 'parse_failed']);
  });
});

describe('mail.message.copy_scanned.v1 (D8, §5)', () => {
  it('is registered on the exchange of mail.message.scanned.v1 (aggregate message), version 1', () => {
    expect(type).toBe('mail.message.copy_scanned.v1');
    expect(EVENT_REGISTRY[type]).toMatchObject({
      type,
      exchange: EVENT_REGISTRY[EventTypes.MessageScanned].exchange,
      aggregateType: 'message',
      version: 1,
    });
    expect(EVENT_REGISTRY[type].exchange).toBe('email.security');
  });

  it('routes only to email.mailbox and the firehose (topology v17)', () => {
    expect(routeMessage('email.security', eventRoutingKey('42', type))).toEqual([
      'email.analytics',
      'email.mailbox',
    ]);
    expect(eventTypesBoundTo('email.mailbox')).toEqual([type]);
    // Never the policy engine, the webhook fanout or the ATO mail feed (N1).
    for (const queue of ['email.policy.evaluate', 'email.webhooks', 'ato.mail'] as const) {
      expect(eventTypesBoundTo(queue), queue).not.toContain(type);
    }
    expect(queueDefinition('email.mailbox').consumer).toEqual({
      kind: 'ledger',
      ledgerName: 'mailbox-worker.copies',
      service: 'mailbox-worker',
    });
  });

  it('parses the example in an envelope and rejects an unversioned type', () => {
    expect(parseEvent(envelope(type, example), messageCopyScannedV1).payload).toEqual(example);
    expect(() =>
      parseEvent(envelope('mail.message.copy_scanned', example), messageCopyScannedV1),
    ).toThrow();
  });

  it('accepts both copy sources and every outcome with a consistent shape', () => {
    for (const ingestSource of MESSAGE_COPY_INGEST_SOURCE_VALUES) {
      expect(ok({ ingestSource }), ingestSource).toBe(true);
    }
    for (const verdict of MESSAGE_VERDICT_VALUES) expect(ok({ verdict }), verdict).toBe(true);
    expect(ok({ outcome: 'scan_failed', verdict: null, riskScore: null })).toBe(true);
    expect(ok({ outcome: 'scan_failed', verdict: 'unknown' })).toBe(true);
    expect(ok({ outcome: 'parse_failed', scanId: null, verdict: null, riskScore: null })).toBe(
      true,
    );
    expect(ok({ riskScore: null })).toBe(true);
    expect(ok({ riskScore: 0 })).toBe(true);
    expect(ok({ riskScore: 1000 })).toBe(true);
  });

  it('refuses gateway messages, inconsistent outcomes and out-of-range values', () => {
    expect(ok({ ingestSource: 'gateway' })).toBe(false);
    expect(ok({ ingestSource: undefined })).toBe(false);
    // parse_failed carries no scan, verdict or score.
    expect(ok({ outcome: 'parse_failed', verdict: null, riskScore: null })).toBe(false);
    expect(ok({ outcome: 'parse_failed', scanId: null, riskScore: null })).toBe(false);
    expect(ok({ outcome: 'parse_failed', scanId: null, verdict: null })).toBe(false);
    // scanned and scan_failed name the round; scanned carries a verdict.
    expect(ok({ scanId: null })).toBe(false);
    expect(ok({ outcome: 'scan_failed', scanId: null })).toBe(false);
    expect(ok({ verdict: null })).toBe(false);
    expect(ok({ verdict: 'malicious' })).toBe(false);
    expect(ok({ riskScore: 1001 })).toBe(false);
    expect(ok({ riskScore: -1 })).toBe(false);
    expect(ok({ riskScore: 1.5 })).toBe(false);
    expect(ok({ lifecycleRound: 65_536 })).toBe(false);
    expect(ok({ messageId: '0' })).toBe(false);
    expect(ok({ messagePublicId: 'not-a-uuid' })).toBe(false);
    expect(ok({ receivedAt: '2026-11-01' })).toBe(false);
    expect(ok({ outcome: 'delivered' })).toBe(false);
  });

  it('is strict: no address, subject or other key can be added', () => {
    expect(ok({ subject: 'x' })).toBe(false);
    expect(ok({ recipient: 'user@example.com' })).toBe(false);
    expect(ok({ emlS3Key: 'org/42/eml/x.eml' })).toBe(false);
    const missing = { ...example };
    delete missing.completedAt;
    expect(messageCopyScannedV1.safeParse(missing).success).toBe(false);
  });
});

describe('notification.alert_requested.v1 kind api_mode_unhealthy (D11.3)', () => {
  it('parses the example variant (refs: the API-mode connection public id)', () => {
    expect(
      notificationAlertRequestedV1.safeParse(EXAMPLE_API_MODE_UNHEALTHY_ALERT_PAYLOAD).success,
    ).toBe(true);
    expect(
      notificationAlertRequestedV1.safeParse({
        ...EXAMPLE_API_MODE_UNHEALTHY_ALERT_PAYLOAD,
        refs: {},
      }).success,
    ).toBe(false);
  });
});
