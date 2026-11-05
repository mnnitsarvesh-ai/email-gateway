import { MetricsService } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import type * as MailRouting from '@email-gateway/mail-routing';
import type { DeliverySignal } from '@email-gateway/mail-routing';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';
import { DeliveryMetrics } from '../metrics/delivery-metrics';
import type { OutboundRateLimiter } from '../rate-limit/outbound-rate-limiter';
import {
  type ActiveDelivery,
  type ClaimedReinjection,
  InconsistentReadError,
  type ReinjectionStore,
} from './reinjection-store';
import { Reinjector, reinjectionDeferralClass } from './reinjector';

const reply = (code: number, enhancedStatus: string | null, text: string) => ({
  code,
  enhancedStatus,
  lines: [text],
  text,
});

describe('reinjectionDeferralClass (R9.2, §9 item 4)', () => {
  it('classifies the 10026 "Destination not configured" RCPT refusal as no_destination', () => {
    // As postfix-outbound 3.7 answers it (docs/deployment/mail-routing.md, V5).
    expect(
      reinjectionDeferralClass(
        reply(
          450,
          '4.4.1',
          '4.4.1 <user@example.test>: Recipient address rejected: Destination not configured',
        ),
      ),
    ).toBe('no_destination');
  });

  it('keeps every other temporary refusal reinjection_4xx', () => {
    expect(reinjectionDeferralClass(reply(451, '4.3.0', '4.3.0 Temporary lookup failure'))).toBe(
      'reinjection_4xx',
    );
    expect(reinjectionDeferralClass(reply(452, null, 'Insufficient system storage'))).toBe(
      'reinjection_4xx',
    );
    expect(reinjectionDeferralClass(undefined)).toBe('reinjection_4xx');
  });
});

// --- Step 4.2 §6.2 item 3: missing context and inconsistent reads -------------------------------

const recordDeliverySignal = vi.hoisted(() =>
  vi.fn<(client: unknown, signal: DeliverySignal) => Promise<unknown>>(),
);
vi.mock('@email-gateway/mail-routing', async (importOriginal) => ({
  ...(await importOriginal<typeof MailRouting>()),
  recordDeliverySignal,
}));

const RECEIVED = new Date('2026-11-05T10:00:00.000Z');

const claimed = (attempts: number): ClaimedReinjection => ({
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
  attempts,
  startedAt: RECEIVED,
  createdAt: RECEIVED,
  lastErrorClass: null,
  recipientSetSha256: 'a'.repeat(64),
  idempotencyKey: 'k',
  leaseExpiresAt: null,
});

const active: ActiveDelivery[] = [
  { id: 1n, receivedAt: RECEIVED, recipientId: 11n, rcptSeq: 0, address: 'a@ext.test' },
  { id: 2n, receivedAt: RECEIVED, recipientId: 12n, rcptSeq: 1, address: 'b@ext.test' },
];

function build(storeOverrides: Partial<Record<keyof ReinjectionStore, Mock>>) {
  const tx = { marker: 'tx' };
  const prisma = {
    $transaction: vi.fn((fn: (t: unknown) => Promise<unknown>) => fn(tx)),
  };
  const store = {
    context: vi.fn(),
    approvalTime: vi.fn(),
    activeDeliveries: vi.fn().mockResolvedValue(active),
    reschedule: vi.fn().mockResolvedValue(true),
    markFailed: vi.fn().mockResolvedValue(true),
    lockForResult: vi.fn((_tx: unknown, row: ClaimedReinjection) =>
      Promise.resolve({ status: 'in_progress', attempts: row.attempts }),
    ),
    failOrphanedDeliveries: vi.fn().mockResolvedValue(0),
    ...storeOverrides,
  };
  const metrics = new DeliveryMetrics(new MetricsService({ service: 'reinjector-test' }));
  const reinjector = new Reinjector({
    prisma: prisma as unknown as PrismaClient,
    store: store as unknown as ReinjectionStore,
    s3: { send: vi.fn() },
    bucket: 'mail',
    limiter: {} as OutboundRateLimiter,
    metrics,
    logger: createLogger({ service: 'reinjector-test', level: 'silent' }),
    config: {
      DELIVERY_REINJECT_HOST: 'postfix-outbound',
      DELIVERY_REINJECT_INBOUND_PORT: 10026,
      DELIVERY_REINJECT_OUTBOUND_PORT: 10027,
      DELIVERY_REINJECT_HELO: 'delivery.gateway.local',
      DELIVERY_REINJECT_COMMAND_TIMEOUT_MS: 1000,
      DELIVERY_REINJECT_DATA_TIMEOUT_MS: 1000,
      DELIVERY_REINJECT_RETRY_BASE_SECONDS: 30,
      DELIVERY_REINJECT_RETRY_MAX_SECONDS: 900,
      DELIVERY_REINJECT_MAX_AGE_SECONDS: 432_000,
      DELIVERY_REINJECT_MAX_ATTEMPTS: 3,
      ROUTING_MAX_RECEIVED_HEADERS: 25,
      ROUTING_MAX_GATEWAY_PASSES: 4,
      GATEWAY_TRACE_SECRET: 's'.repeat(32),
      GATEWAY_TRACE_ID: 'gw-test',
      INGEST_HEADER_MAX_BYTES: 65_536,
    },
    txTimeoutMs: 120_000,
    now: () => new Date('2026-11-05T10:01:00.000Z'),
    random: () => 0.5,
  });
  return { reinjector, store, prisma, tx, metrics };
}

describe('message of the reinjection not found (context_missing)', () => {
  beforeEach(() => {
    recordDeliverySignal.mockReset();
    recordDeliverySignal.mockResolvedValue({ result: 'applied', status: 'failed' });
  });

  it('reschedules with backoff below DELIVERY_REINJECT_MAX_ATTEMPTS; nothing is failed', async () => {
    const { reinjector, store, metrics } = build({ context: vi.fn().mockResolvedValue(null) });
    const inc = vi.spyOn(metrics.contextMissing, 'inc');
    await expect(reinjector.process(claimed(2))).resolves.toBe('retry');
    expect(store.reschedule).toHaveBeenCalledTimes(1);
    const [, options] = store.reschedule.mock.calls[0]!;
    expect(options).toMatchObject({ errorClass: 'context_missing', error: 'message not found' });
    expect(options.refundAttempt).toBeUndefined();
    expect((options.nextAttemptAt as Date).getTime()).toBeGreaterThan(
      new Date('2026-11-05T10:01:00.000Z').getTime(),
    );
    expect(store.markFailed).not.toHaveBeenCalled();
    expect(recordDeliverySignal).not.toHaveBeenCalled();
    expect(inc).toHaveBeenCalledWith({ result: 'retry' });
  });

  it('on the final attempt fails the row and its active deliveries in one transaction', async () => {
    const { reinjector, store, prisma, tx, metrics } = build({
      context: vi.fn().mockResolvedValue(null),
    });
    const inc = vi.spyOn(metrics.contextMissing, 'inc');
    await expect(reinjector.process(claimed(3))).resolves.toBe('failed');
    expect(store.reschedule).not.toHaveBeenCalled();
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(recordDeliverySignal).toHaveBeenCalledTimes(2);
    for (const [client, signal] of recordDeliverySignal.mock.calls) {
      expect(client).toBe(tx);
      expect(signal).toMatchObject({
        status: 'failed',
        failureReason: 'message_missing',
        source: 'reinjection',
      });
    }
    expect(recordDeliverySignal.mock.calls.map(([, s]) => s.match)).toEqual([
      { deliveryId: 1n, receivedAt: RECEIVED },
      { deliveryId: 2n, receivedAt: RECEIVED },
    ]);
    expect(store.markFailed).toHaveBeenCalledWith(
      expect.anything(),
      'context_missing',
      'message not found',
      tx,
    );
    // Deliveries the recorder could not resolve (message gone) are failed in the same tx.
    expect(store.failOrphanedDeliveries).toHaveBeenCalledWith(
      tx,
      expect.anything(),
      [1n, 2n],
      'message_missing',
      expect.any(Date),
    );
    expect(inc).toHaveBeenCalledWith({ result: 'failed' });
  });

  it('on the final attempt without active deliveries fails the row only', async () => {
    const { reinjector, store, prisma } = build({
      context: vi.fn().mockResolvedValue(null),
      activeDeliveries: vi.fn().mockResolvedValue([]),
    });
    await expect(reinjector.process(claimed(3))).resolves.toBe('failed');
    expect(prisma.$transaction).not.toHaveBeenCalled();
    expect(store.markFailed).toHaveBeenCalledWith(
      expect.anything(),
      'context_missing',
      'message not found',
    );
  });
});

describe('inconsistent writer reads', () => {
  it('reschedule the row with the attempt refunded and count the read', async () => {
    const { reinjector, store, metrics } = build({
      context: vi.fn().mockRejectedValue(new InconsistentReadError('deliveries', 'delivery echo')),
    });
    const inc = vi.spyOn(metrics.inconsistentReads, 'inc');
    await expect(reinjector.process(claimed(2))).resolves.toBe('retry');
    expect(store.reschedule).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        errorClass: 'inconsistent_read',
        error: 'inconsistent deliveries read: delivery echo',
        refundAttempt: true,
      }),
    );
    expect(store.markFailed).not.toHaveBeenCalled();
    expect(inc).toHaveBeenCalledWith({ read: 'deliveries' });
  });

  it('apply to the approval time read as well', async () => {
    const { reinjector, store, metrics } = build({
      context: vi.fn().mockResolvedValue({
        envelopeFrom: 'alice@sender.example',
        clientIp: null,
        clientHelo: null,
        deliveries: active,
      }),
      approvalTime: vi
        .fn()
        .mockRejectedValue(new InconsistentReadError('approval', 'approval echo')),
    });
    const inc = vi.spyOn(metrics.inconsistentReads, 'inc');
    await expect(reinjector.process(claimed(2))).resolves.toBe('retry');
    expect(store.reschedule.mock.calls[0]![1]).toMatchObject({ refundAttempt: true });
    expect(inc).toHaveBeenCalledWith({ read: 'approval' });
  });

  it('a context_missing on the final attempt with an inconsistent delivery read is rescheduled', async () => {
    const { reinjector, store } = build({
      context: vi.fn().mockResolvedValue(null),
      activeDeliveries: vi
        .fn()
        .mockRejectedValue(new InconsistentReadError('recipients', 'recipient missing')),
    });
    await expect(reinjector.process(claimed(3))).resolves.toBe('retry');
    expect(store.markFailed).not.toHaveBeenCalled();
    expect(store.reschedule.mock.calls[0]![1]).toMatchObject({ refundAttempt: true });
  });

  it('let other errors propagate', async () => {
    const { reinjector, store } = build({
      context: vi.fn().mockRejectedValue(new Error('db down')),
    });
    await expect(reinjector.process(claimed(2))).rejects.toThrow('db down');
    expect(store.reschedule).not.toHaveBeenCalled();
  });
});
