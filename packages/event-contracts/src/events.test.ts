import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import {
  domainStatusChangedV1,
  EventTypes,
  messageReceivedV1,
  messageScannedV1,
  policyDecidedV1,
} from './events';
import { QUEUES, queueArguments } from './topology';

const organizationId = '42';
const receivedAt = '2026-11-01T10:15:30.123Z';

function envelope(payload: unknown, overrides: Record<string, unknown> = {}) {
  return {
    eventId: randomUUID(),
    eventType: EventTypes.MessageReceived,
    occurredAt: new Date().toISOString(),
    correlationId: 'corr-12345678',
    organizationId,
    payload,
    ...overrides,
  };
}

function receivedPayload(overrides: Record<string, unknown> = {}) {
  return {
    messageId: '9007199254740993',
    receivedAt,
    direction: 'inbound',
    emlS3Key: `org/${organizationId}/eml/2026/11/01/9007199254740993.eml`,
    sizeBytes: 1024,
    envelopeFrom: 'a@example.com',
    recipientCount: 1,
    ...overrides,
  };
}

describe('parseEvent', () => {
  it('accepts a valid message.received event', () => {
    const event = parseEvent(envelope(receivedPayload()), messageReceivedV1);
    expect(event.organizationId).toBe('42');
    expect(event.payload.messageId).toBe('9007199254740993');
    expect(event.payload.direction).toBe('inbound');
  });

  it('accepts a valid message.scanned event', () => {
    const event = parseEvent(
      envelope(
        { messageId: '7', receivedAt, scanIds: ['11', '12'], timedOutStages: [] },
        { eventType: EventTypes.MessageScanned },
      ),
      messageScannedV1,
    );
    expect(event.payload.scanIds).toEqual(['11', '12']);
  });

  it('accepts a valid policy.decided event', () => {
    const event = parseEvent(
      envelope(
        {
          messageId: '7',
          receivedAt,
          action: 'quarantine',
          matchedPolicyVersionIds: ['3'],
          archive: true,
        },
        { eventType: EventTypes.PolicyDecided },
      ),
      policyDecidedV1,
    );
    expect(event.payload.matchedPolicyVersionIds).toEqual(['3']);
  });

  it('rejects a UUID organization id', () => {
    expect(() =>
      parseEvent(envelope(receivedPayload(), { organizationId: randomUUID() }), messageReceivedV1),
    ).toThrow();
  });

  it('rejects ids with leading zeros', () => {
    expect(() =>
      parseEvent(envelope(receivedPayload(), { organizationId: '042' }), messageReceivedV1),
    ).toThrow();
    expect(() =>
      parseEvent(envelope(receivedPayload({ messageId: '0123' })), messageReceivedV1),
    ).toThrow();
    expect(() =>
      parseEvent(
        envelope(
          { messageId: '7', receivedAt, scanIds: ['011'], timedOutStages: [] },
          { eventType: EventTypes.MessageScanned },
        ),
        messageScannedV1,
      ),
    ).toThrow();
  });

  it('rejects a UUID message id', () => {
    expect(() =>
      parseEvent(envelope(receivedPayload({ messageId: randomUUID() })), messageReceivedV1),
    ).toThrow();
  });

  it('rejects S3 keys that are not organization-prefixed', () => {
    for (const emlS3Key of ['eml/x.eml', `org/${randomUUID()}/eml/x.eml`, 'org/042/eml/x.eml']) {
      expect(() =>
        parseEvent(envelope(receivedPayload({ emlS3Key })), messageReceivedV1),
      ).toThrow();
    }
  });

  it('rejects unversioned event types', () => {
    expect(() =>
      parseEvent(envelope(receivedPayload(), { eventType: 'mail.received' }), messageReceivedV1),
    ).toThrow();
  });
});

describe('domain.status.changed.v1', () => {
  const domainPayload = (overrides: Record<string, unknown> = {}) => ({
    domainId: '9007199254740993',
    domainPublicId: '01890a5d-ac96-774b-bcce-b302099a8057',
    name: 'xn--bcher-kva.example',
    previousStatus: 'verified',
    status: 'active',
    reason: null,
    changedAt: '2026-11-02T09:00:00.000Z',
    ...overrides,
  });
  const parse = (payload: unknown) =>
    parseEvent(
      envelope(payload, { eventType: EventTypes.DomainStatusChanged }),
      domainStatusChangedV1,
    );

  it('has a versioned event type', () => {
    expect(EventTypes.DomainStatusChanged).toBe('domain.status.changed.v1');
  });

  it('accepts a status change, a first status (previousStatus null) and a reason', () => {
    expect(parse(domainPayload()).payload.status).toBe('active');
    expect(
      parse(domainPayload({ previousStatus: null, status: 'pending_verification' })).payload
        .previousStatus,
    ).toBeNull();
    expect(
      parse(
        domainPayload({
          previousStatus: 'pending_verification',
          status: 'failed',
          reason: 'claimed_by_another_organization',
        }),
      ).payload.reason,
    ).toBe('claimed_by_another_organization');
  });

  it('rejects numeric or malformed ids, long names and reasons, and non-ISO timestamps', () => {
    for (const overrides of [
      { domainId: 9 },
      { domainId: '09' },
      { domainId: randomUUID().replaceAll('-', '') },
      { domainPublicId: '12' },
      { name: '' },
      { name: 'a'.repeat(254) },
      { status: '' },
      { reason: 'x'.repeat(513) },
      { changedAt: '2026-11-02' },
      { changedAt: 'yesterday' },
    ]) {
      expect(() => parse(domainPayload(overrides)), JSON.stringify(overrides)).toThrow();
    }
    const { reason: _reason, ...withoutReason } = domainPayload();
    expect(() => parse(withoutReason)).toThrow();
  });
});

describe('topology', () => {
  it('declares every work queue as a quorum queue with a dead-letter route', () => {
    for (const queue of Object.values(QUEUES)) {
      expect(queueArguments(queue)).toMatchObject({
        'x-queue-type': 'quorum',
        'x-dead-letter-routing-key': `${queue.name}.dlq`,
      });
    }
  });
});
