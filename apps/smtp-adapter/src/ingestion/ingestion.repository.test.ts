import { createHash } from 'node:crypto';
import type { PrismaService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { type IngestCommit, IngestionRepository } from './ingestion.repository';

const RECEIVED_AT = new Date('2026-11-04T10:00:00.000Z');
const sha256 = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

const commit: IngestCommit = {
  organizationId: 7n,
  domainId: 3n,
  ingestKey: 'v2:key',
  receivedAt: RECEIVED_AT,
  direction: 'inbound',
  messageDirection: 'inbound',
  envelopeFrom: 'sender@external.test',
  internetMessageId: null,
  headerFrom: null,
  subject: null,
  sizeBytes: 10,
  emlObjectKey: 'org/7/eml/2026/11/04/x.eml',
  emlSha256: '0'.repeat(64),
  clientIp: null,
  clientHelo: null,
  clientName: 'mail.external.test',
  queueId: '4ZQ1',
  recipients: ['a@tenant.test'],
  recipientDirections: ['inbound'],
};

/** The writer as the commit sees it: every call in order, inside one transaction. */
function fakeWriter() {
  const calls: { model: string; method: string; args: Record<string, unknown> }[] = [];
  const model = (name: string, result: unknown = { id: 1n }) =>
    new Proxy(
      {},
      {
        get: (_t, method: string) => (args: Record<string, unknown>) => {
          calls.push({ model: name, method, args });
          return Promise.resolve(result);
        },
      },
    );
  const tx = {
    messageIdentity: model('messageIdentity', { id: 100n }),
    emailMessage: model('emailMessage'),
    emailMessageStatusHistory: model('emailMessageStatusHistory', { count: 2 }),
    emailRecipient: model('emailRecipient', { count: 1 }),
    emailEvent: model('emailEvent'),
    messageOutbox: model('messageOutbox'),
  };
  const transactions: unknown[] = [];
  const prisma = {
    $transaction: (fn: (t: typeof tx) => Promise<unknown>, options: unknown) => {
      transactions.push(options);
      return fn(tx);
    },
  };
  return { prisma: prisma as unknown as PrismaService, calls, transactions };
}

describe('IngestionRepository.commit lifecycle (step 3.3 L8.1)', () => {
  it('creates the message persisted (version 1) and its two history rows, nothing else added', async () => {
    const writer = fakeWriter();
    const { messageId, eventId } = await new IngestionRepository(writer.prisma).commit(
      commit,
      5000,
    );
    expect(messageId).toBe(100n);
    expect(writer.transactions).toEqual([{ timeout: 5000, maxWait: 5000 }]);
    // One statement more than step 2.2 (the history createMany), no lock, no read.
    expect(writer.calls.map((c) => `${c.model}.${c.method}`)).toEqual([
      'messageIdentity.create',
      'emailMessage.create',
      'emailMessageStatusHistory.createMany',
      'emailRecipient.createMany',
      'emailEvent.create',
      'messageOutbox.create',
    ]);
    const message = writer.calls[1]!.args.data as Record<string, unknown>;
    expect(message).toMatchObject({
      id: 100n,
      status: 'persisted',
      version: 1,
      lifecycleRound: 0,
      statusReason: 'committed',
      statusChangedAt: RECEIVED_AT,
      // Step 4.1 §3: XFORWARD NAME is a column of the same insert, no extra statement.
      clientName: 'mail.external.test',
    });
    const history = writer.calls[2]!.args.data as Record<string, unknown>[];
    expect(history).toEqual([
      expect.objectContaining({
        messageId: 100n,
        receivedAt: RECEIVED_AT,
        organizationId: 7n,
        version: 0,
        fromStatus: null,
        toStatus: 'received',
        reasonCode: 'smtp_accepted',
        actorRole: 'ingestion',
        actorService: 'smtp-adapter',
        actorType: 'system',
        eventId,
        correlationId: 'lmtp:4ZQ1',
        transitionKey: sha256('ingest:100:received'),
        stateEventId: null,
        occurredAt: RECEIVED_AT,
        changedAt: RECEIVED_AT,
      }),
      expect.objectContaining({
        version: 1,
        fromStatus: 'received',
        toStatus: 'persisted',
        reasonCode: 'committed',
        eventId,
        transitionKey: sha256('ingest:100:persisted'),
      }),
    ]);
    // The received event is the notification of `persisted`: no state_changed outbox row.
    const outbox = writer.calls[5]!.args.data as Record<string, unknown>;
    expect(outbox).toMatchObject({ eventId, eventType: 'mail.message.received.v1' });
  });
});
