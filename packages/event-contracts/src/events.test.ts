import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseEvent } from './envelope';
import { EventTypes, messageReceivedV1 } from './events';
import { QUEUES, queueArguments } from './topology';

const tenantId = randomUUID();

function envelope(payload: unknown) {
  return {
    eventId: randomUUID(),
    eventType: EventTypes.MessageReceived,
    occurredAt: new Date().toISOString(),
    correlationId: 'corr-12345678',
    tenantId,
    payload,
  };
}

describe('parseEvent', () => {
  it('accepts a valid message.received event', () => {
    const event = parseEvent(
      envelope({
        messageId: randomUUID(),
        receivedAt: new Date().toISOString(),
        direction: 'inbound',
        emlS3Key: `org/${tenantId}/eml/2026/11/01/x.eml`,
        sizeBytes: 1024,
        envelopeFrom: 'a@example.com',
        recipientCount: 1,
      }),
      messageReceivedV1,
    );
    expect(event.payload.direction).toBe('inbound');
  });

  it('rejects S3 keys that are not tenant-prefixed', () => {
    expect(() =>
      parseEvent(
        envelope({
          messageId: randomUUID(),
          receivedAt: new Date().toISOString(),
          direction: 'inbound',
          emlS3Key: 'eml/x.eml',
          sizeBytes: 1,
          envelopeFrom: 'a@example.com',
          recipientCount: 1,
        }),
        messageReceivedV1,
      ),
    ).toThrow();
  });

  it('rejects unversioned event types', () => {
    expect(() =>
      parseEvent({ ...envelope({}), eventType: 'mail.received' }, messageReceivedV1),
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
