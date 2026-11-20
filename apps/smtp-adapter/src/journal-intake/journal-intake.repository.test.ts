import type { PrismaService } from '@email-gateway/common';
import { JOURNAL_ENVELOPE_EXAMPLE, JOURNAL_INTAKE_PROOF_EXAMPLE } from '@email-gateway/archive';
import { messageReceivedV1 } from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import {
  type IntakeCommit,
  JournalIntakeRepository,
  scanRequestedOf,
} from './journal-intake.repository';

const RECEIVED_AT = new Date('2026-11-20T10:00:00.000Z');

const commit: IntakeCommit = {
  organizationId: 7n,
  domainId: 100n,
  ingestKey: 'v2:key',
  receivedAt: RECEIVED_AT,
  direction: 'outbound',
  envelopeFrom: 'journal-agent@example.com',
  internetMessageId: '<m1@example.com>',
  headerFrom: 'alice@example.com',
  subject: 'Synthetic',
  sizeBytes: 120,
  emlObjectKey: 'org/7/eml/2026/11/20/x.eml',
  emlSha256: '1'.repeat(64),
  clientIp: '198.51.100.70',
  clientHelo: 'mail.example.com',
  clientName: null,
  queueId: '4ZQ1',
  recipients: [
    { address: 'bob@example.org', direction: 'outbound' },
    { address: 'dave@example.com', direction: 'internal' },
    { address: 'x@elsewhere.example', direction: null },
  ],
  source: {
    id: 42n,
    publicId: '0190a0a0-0000-7000-8000-00000000a042',
    kind: 'microsoft_365_journal',
  },
  format: 'journal_report',
  envelope: JOURNAL_ENVELOPE_EXAMPLE,
  proof: JOURNAL_INTAKE_PROOF_EXAMPLE,
  reportSha256: '2'.repeat(64),
  reportSizeBytes: 400,
};

function fakeWriter(settings: unknown = null) {
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
    archiveSetting: model('archiveSetting', settings === null ? null : { settings }),
    emailMessage: model('emailMessage'),
    emailMessageStatusHistory: model('emailMessageStatusHistory', { count: 2 }),
    emailRecipient: model('emailRecipient', { count: 3 }),
    journalIntakeMessage: model('journalIntakeMessage', { messageId: 100n }),
    emailEvent: model('emailEvent'),
    messageOutbox: model('messageOutbox'),
  };
  const prisma = {
    $transaction: (fn: (t: typeof tx) => Promise<unknown>) => fn(tx),
  };
  return { prisma: prisma as unknown as PrismaService, calls };
}

const data = (calls: ReturnType<typeof fakeWriter>['calls'], model: string) =>
  calls.find((c) => c.model === model)!.args.data as Record<string, unknown>;

describe('JournalIntakeRepository.commit (D2.6 pass, D3)', () => {
  it('writes the registry, message, journaled recipients, intake row, event and outbox', async () => {
    const w = fakeWriter({ intake: { scanEnabled: true } });
    const result = await new JournalIntakeRepository(w.prisma).commit(commit, 5000);
    expect(result).toMatchObject({ messageId: 100n, scanRequested: true });
    expect(w.calls.map((c) => `${c.model}.${c.method}`)).toEqual([
      'messageIdentity.create',
      'archiveSetting.findUnique',
      'emailMessage.create',
      'emailMessageStatusHistory.createMany',
      'emailRecipient.createMany',
      'journalIntakeMessage.create',
      'emailEvent.create',
      'messageOutbox.create',
    ]);
    expect(data(w.calls, 'emailMessage')).toMatchObject({
      id: 100n,
      organizationId: 7n,
      domainId: 100n,
      direction: 'outbound',
      ingestSource: 'journal_intake',
      status: 'persisted',
      version: 1,
      recipientCount: 3,
      sizeBytes: 120,
      mtaQueueId: '4ZQ1',
    });
    const history = data(w.calls, 'emailMessageStatusHistory') as unknown as { toStatus: string }[];
    expect(history.map((row) => row.toStatus)).toEqual(['received', 'persisted']);
    expect(data(w.calls, 'emailRecipient')).toEqual([
      expect.objectContaining({
        rcptSeq: 0,
        address: 'bob@example.org',
        status: 'journaled',
        direction: 'outbound',
      }),
      expect.objectContaining({
        rcptSeq: 1,
        address: 'dave@example.com',
        status: 'journaled',
        direction: 'internal',
      }),
      expect.objectContaining({
        rcptSeq: 2,
        address: 'x@elsewhere.example',
        status: 'journaled',
        direction: null,
      }),
    ]);
    expect(data(w.calls, 'journalIntakeMessage')).toEqual({
      messageId: 100n,
      receivedAt: RECEIVED_AT,
      organizationId: 7n,
      sourceId: 42n,
      kind: 'microsoft_365_journal',
      format: 'journal_report',
      envelope: JOURNAL_ENVELOPE_EXAMPLE,
      proof: JOURNAL_INTAKE_PROOF_EXAMPLE,
      reportSha256: '2'.repeat(64),
      reportSizeBytes: 400,
      scanRequested: true,
    });
    expect(data(w.calls, 'emailEvent')).toMatchObject({
      eventType: 'received',
      details: {
        direction: 'journal',
        messageDirection: 'outbound',
        recipientCount: 3,
        intake: {
          sourceId: '0190a0a0-0000-7000-8000-00000000a042',
          kind: 'microsoft_365_journal',
          format: 'journal_report',
        },
      },
    });
    const outbox = data(w.calls, 'messageOutbox');
    expect(outbox).toMatchObject({ eventType: 'mail.message.received.v1', aggregateId: '100' });
    expect(messageReceivedV1.parse(outbox.payload)).toMatchObject({
      messageId: '100',
      direction: 'outbound',
      recipientCount: 3,
      ingestSource: 'journal_intake',
    });
    // Never an address of the envelope in the event details.
    expect(JSON.stringify(data(w.calls, 'emailEvent').details)).not.toContain('@');
  });

  it('writes no recipient rows for an envelope without recipients', async () => {
    const w = fakeWriter();
    const result = await new JournalIntakeRepository(w.prisma).commit(
      { ...commit, recipients: [] },
      5000,
    );
    expect(result.scanRequested).toBe(false);
    expect(w.calls.some((c) => c.model === 'emailRecipient')).toBe(false);
    expect(data(w.calls, 'emailMessage').recipientCount).toBe(0);
    const payload = data(w.calls, 'messageOutbox').payload as { recipientCount: number };
    expect(payload.recipientCount).toBe(1);
  });

  it('scanRequestedOf: off by default and for a document that does not parse', () => {
    expect(scanRequestedOf(null)).toBe(false);
    expect(scanRequestedOf({})).toBe(false);
    expect(scanRequestedOf({ intake: { scanEnabled: true } })).toBe(true);
    expect(scanRequestedOf({ intake: { scanEnabled: 'yes' } })).toBe(false);
  });
});
