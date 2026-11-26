import { NonRetryableError } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { EventTypes, messageCopyScannedV1 } from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import { type CopyScannedInput, isCopySource, writeCopyScannedOutbox } from './copy-scanned';

/**
 * `mail.message.copy_scanned.v1` writer of the email-worker (step API-1 D8, contracts §36,
 * docs/plan/steps/35-api-mode-protection.md): aggregate = the message public id, payload
 * validated by the strict contract, never written for a foreign or missing identity.
 */
const PUBLIC_ID = '0196f3a0-0000-7000-8000-0000000000aa';
const RECEIVED = new Date('2026-11-26T09:00:00.000Z');
const COMPLETED = new Date('2026-11-26T09:00:04.000Z');

function fakeTx(identity: { publicId: string; organizationId: bigint } | null) {
  const created: Array<Record<string, unknown>> = [];
  const tx = {
    messageIdentity: {
      findUnique: () => Promise.resolve(identity),
    },
    messageOutbox: {
      create: (args: { data: Record<string, unknown> }) => {
        created.push(args.data);
        return Promise.resolve({ id: 1n });
      },
    },
  } as unknown as Prisma.TransactionClient;
  return { tx, created };
}

const base: CopyScannedInput = {
  message: { id: 42n, receivedAt: RECEIVED, organizationId: 7n },
  ingestSource: 'mailbox_api',
  lifecycleRound: 0,
  scanId: 9n,
  outcome: 'scanned',
  verdict: 'phishing',
  riskScore: 870,
  completedAt: COMPLETED,
  correlationId: 'message:42',
};

describe('isCopySource', () => {
  it.each([
    ['journal_intake', true],
    ['mailbox_api', true],
    ['gateway', false],
    [undefined, false],
    [null, false],
  ] as const)('%s → %s', (source, expected) => {
    expect(isCopySource(source)).toBe(expected);
  });
});

describe('writeCopyScannedOutbox', () => {
  it('writes the strict payload with the public id as aggregate id', async () => {
    const { tx, created } = fakeTx({ publicId: PUBLIC_ID, organizationId: 7n });
    const eventId = await writeCopyScannedOutbox(tx, base);
    expect(created).toHaveLength(1);
    const row = created[0]!;
    expect(row).toMatchObject({
      eventId,
      organizationId: 7n,
      eventType: EventTypes.MessageCopyScanned,
      aggregateType: 'message',
      aggregateId: PUBLIC_ID,
      correlationId: 'message:42',
    });
    expect(row.payload).toEqual({
      messageId: '42',
      messagePublicId: PUBLIC_ID,
      receivedAt: RECEIVED.toISOString(),
      ingestSource: 'mailbox_api',
      lifecycleRound: 0,
      scanId: '9',
      outcome: 'scanned',
      verdict: 'phishing',
      riskScore: 870,
      completedAt: COMPLETED.toISOString(),
    });
    expect(messageCopyScannedV1.safeParse(row.payload).success).toBe(true);
  });

  it('writes parse_failed without scan, verdict or score (journal copy)', async () => {
    const { tx, created } = fakeTx({ publicId: PUBLIC_ID, organizationId: 7n });
    await writeCopyScannedOutbox(tx, {
      ...base,
      ingestSource: 'journal_intake',
      scanId: null,
      outcome: 'parse_failed',
      verdict: null,
      riskScore: null,
    });
    expect(created[0]?.payload).toMatchObject({
      ingestSource: 'journal_intake',
      outcome: 'parse_failed',
      scanId: null,
      verdict: null,
      riskScore: null,
    });
  });

  it('refuses a payload the contract rejects (nothing written)', async () => {
    const { tx, created } = fakeTx({ publicId: PUBLIC_ID, organizationId: 7n });
    await expect(writeCopyScannedOutbox(tx, { ...base, outcome: 'parse_failed' })).rejects.toThrow(
      new NonRetryableError('copy_scanned_payload_invalid'),
    );
    await expect(writeCopyScannedOutbox(tx, { ...base, verdict: null })).rejects.toThrow(
      NonRetryableError,
    );
    expect(created).toEqual([]);
  });

  it('refuses a missing or foreign identity (never another tenant’s public id)', async () => {
    const missing = fakeTx(null);
    await expect(writeCopyScannedOutbox(missing.tx, base)).rejects.toThrow(
      'copy_scanned_identity_missing',
    );
    const foreign = fakeTx({ publicId: PUBLIC_ID, organizationId: 8n });
    await expect(writeCopyScannedOutbox(foreign.tx, base)).rejects.toThrow(
      'copy_scanned_identity_missing',
    );
    expect([...missing.created, ...foreign.created]).toEqual([]);
  });
});
