import type { PrismaClient } from '@email-gateway/database';
import { describe, expect, it, vi } from 'vitest';
import {
  type ClaimedReinjection,
  DEFAULT_STORE_TX_TIMEOUT_MS,
  InconsistentReadError,
  ReinjectionStore,
} from './reinjection-store';

const RECEIVED = new Date('2026-11-05T10:00:00.000Z');
const CREATED = new Date('2026-11-05T10:00:05.000Z');

const row: ClaimedReinjection = {
  id: 70n,
  receivedAt: RECEIVED,
  publicId: '0195f0aa-0000-7000-8000-000000000070',
  messageId: 500n,
  organizationId: 9n,
  deliverySeq: 0,
  listener: 'reinject_outbound',
  direction: 'outbound',
  destinationKey: 'mx:ext.test',
  emlObjectKey: 'org/9/eml/2026/11/05/500.eml',
  approvalEventId: '0195f0aa-0000-7000-8000-0000000000aa',
  attempts: 1,
  startedAt: CREATED,
  createdAt: CREATED,
  lastErrorClass: null,
  recipientSetSha256: 'a'.repeat(64),
  idempotencyKey: 'k',
  leaseExpiresAt: null,
};

const messageRow = (overrides: Record<string, unknown> = {}) => ({
  id: 500n,
  receivedAt: new Date(RECEIVED),
  organizationId: 9n,
  envelopeFrom: 'alice@sender.example',
  clientIp: '203.0.113.7',
  clientHelo: 'mail.example.org',
  ...overrides,
});

const deliveryRow = (id: bigint, recipientId: bigint, overrides: Record<string, unknown> = {}) => ({
  id,
  receivedAt: new Date(RECEIVED),
  recipientId,
  reinjectionId: 70n,
  messageId: 500n,
  organizationId: 9n,
  status: 'pending',
  ...overrides,
});

const recipientRow = (id: bigint, overrides: Record<string, unknown> = {}) => ({
  id,
  rcptSeq: Number(id),
  address: `r${id}@ext.test`,
  messageId: 500n,
  receivedAt: new Date(RECEIVED),
  ...overrides,
});

/** A writer fake answering the store's reads with the given rows. */
function fakeWriter(rows: {
  message?: unknown;
  deliveries?: unknown[];
  recipients?: unknown[];
  approval?: unknown;
}) {
  const prisma = {
    emailMessage: { findFirst: vi.fn().mockResolvedValue(rows.message ?? null) },
    emailDelivery: { findMany: vi.fn().mockResolvedValue(rows.deliveries ?? []) },
    emailRecipient: { findMany: vi.fn().mockResolvedValue(rows.recipients ?? []) },
    deliveryReinjection: { findFirst: vi.fn().mockResolvedValue(rows.approval ?? null) },
    $transaction: vi.fn().mockResolvedValue([]),
  };
  return { prisma, store: new ReinjectionStore(prisma as unknown as PrismaClient) };
}

const consistent = () => ({
  message: messageRow(),
  deliveries: [deliveryRow(1n, 11n), deliveryRow(2n, 12n)],
  recipients: [recipientRow(12n), recipientRow(11n)],
});

describe('ReinjectionStore.context echo checks (step 4.2 §6.2 item 3)', () => {
  it('returns the context when every result echoes the request', async () => {
    const { store } = fakeWriter(consistent());
    await expect(store.context(row)).resolves.toEqual({
      envelopeFrom: 'alice@sender.example',
      clientIp: '203.0.113.7',
      clientHelo: 'mail.example.org',
      deliveries: [
        { id: 1n, receivedAt: RECEIVED, recipientId: 11n, rcptSeq: 11, address: 'r11@ext.test' },
        { id: 2n, receivedAt: RECEIVED, recipientId: 12n, rcptSeq: 12, address: 'r12@ext.test' },
      ],
    });
  });

  it('selects the identifying columns it checks', async () => {
    const { prisma, store } = fakeWriter(consistent());
    await store.context(row);
    expect(prisma.emailMessage.findFirst.mock.calls[0]![0].select).toMatchObject({
      id: true,
      receivedAt: true,
      organizationId: true,
    });
    expect(prisma.emailDelivery.findMany.mock.calls[0]![0].select).toMatchObject({
      reinjectionId: true,
      messageId: true,
      organizationId: true,
      status: true,
    });
    expect(prisma.emailRecipient.findMany.mock.calls[0]![0].select).toMatchObject({
      id: true,
      messageId: true,
      receivedAt: true,
    });
  });

  it('returns null when the message row is not found', async () => {
    const { store } = fakeWriter({ message: null });
    await expect(store.context(row)).resolves.toBeNull();
  });

  it.each([
    ['another message id', { id: 501n }],
    ['another organization', { organizationId: 10n }],
    ['another received_at', { receivedAt: new Date('2026-11-05T10:00:00.001Z') }],
  ])('refuses a message row of %s', async (_name, overrides) => {
    const { store } = fakeWriter({ ...consistent(), message: messageRow(overrides) });
    const error = await store.context(row).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(InconsistentReadError);
    expect(error).toMatchObject({ read: 'message' });
  });

  it.each([
    ['another reinjection', { reinjectionId: 71n }],
    ['another message', { messageId: 501n }],
    ['another organization', { organizationId: 10n }],
    ['another received_at', { receivedAt: new Date(0) }],
    ['a final status', { status: 'delivered' }],
  ])('refuses a delivery of %s', async (_name, overrides) => {
    const { store } = fakeWriter({
      ...consistent(),
      deliveries: [deliveryRow(1n, 11n), deliveryRow(2n, 12n, overrides)],
    });
    await expect(store.context(row)).rejects.toMatchObject({
      name: 'InconsistentReadError',
      read: 'deliveries',
    });
  });

  it.each([
    ['a recipient that was not requested', [recipientRow(11n), recipientRow(13n)]],
    ['a recipient of another message', [recipientRow(11n), recipientRow(12n, { messageId: 501n })]],
    ['a missing recipient', [recipientRow(11n)]],
    ['no recipients at all', []],
  ])('refuses %s', async (_name, recipients) => {
    const { store } = fakeWriter({ ...consistent(), recipients });
    await expect(store.context(row)).rejects.toMatchObject({
      name: 'InconsistentReadError',
      read: 'recipients',
    });
  });

  it('never puts row content into the error message', async () => {
    const { store } = fakeWriter({ ...consistent(), message: messageRow({ id: 501n }) });
    const error = (await store.context(row).catch((e: unknown) => e)) as Error;
    expect(error.message).toBe('inconsistent message read: identity echo');
  });
});

describe('ReinjectionStore.approvalTime echo checks', () => {
  const approval = (overrides: Record<string, unknown> = {}) => ({
    createdAt: new Date('2026-11-05T10:00:01.000Z'),
    approvalEventId: row.approvalEventId,
    messageId: 500n,
    receivedAt: new Date(RECEIVED),
    ...overrides,
  });

  it('returns the oldest row of the approval', async () => {
    const { store } = fakeWriter({ approval: approval() });
    await expect(store.approvalTime(row)).resolves.toEqual(new Date('2026-11-05T10:00:01.000Z'));
  });

  it.each([
    ['no row (the claimed row itself always matches)', null],
    [
      'another approval event',
      approval({ approvalEventId: '0195f0aa-0000-7000-8000-0000000000bb' }),
    ],
    ['another message', approval({ messageId: 501n })],
    ['another received_at', approval({ receivedAt: new Date(0) })],
    ['a row newer than the claimed row', approval({ createdAt: new Date('2026-11-05T11:00:00Z') })],
  ])('refuses %s', async (_name, result) => {
    const { store } = fakeWriter({ approval: result });
    await expect(store.approvalTime(row)).rejects.toMatchObject({
      name: 'InconsistentReadError',
      read: 'approval',
    });
  });
});

describe('ReinjectionStore.claim transaction budget (§6.2 F2)', () => {
  it('runs the claim with the store budget, never with Prisma defaults', async () => {
    const { prisma, store } = fakeWriter({});
    await store.claim(5, new Date(), 60);
    expect(prisma.$transaction).toHaveBeenCalledWith(expect.any(Function), {
      timeout: DEFAULT_STORE_TX_TIMEOUT_MS,
      maxWait: DEFAULT_STORE_TX_TIMEOUT_MS,
    });
  });

  it('uses the configured budget', async () => {
    const prisma = { $transaction: vi.fn().mockResolvedValue([]) };
    const store = new ReinjectionStore(prisma as unknown as PrismaClient, { txTimeoutMs: 90_000 });
    await store.claim(5, new Date(), 60);
    expect(prisma.$transaction.mock.calls[0]![1]).toEqual({ timeout: 90_000, maxWait: 90_000 });
  });
});
