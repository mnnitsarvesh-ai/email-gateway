import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import { EventTypes, messageReceivedV1, messageScannedV1, policyDecidedV1 } from './events';
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
