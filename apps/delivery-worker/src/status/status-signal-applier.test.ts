import { MetricsService } from '@email-gateway/common';
import type * as MailRouting from '@email-gateway/mail-routing';
import { createLogger } from '@email-gateway/logger';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DeliveryMetrics } from '../metrics/delivery-metrics';
import { parsePostfixLogLine, type PostfixLogEvent } from './postfix-log-parser';
import { StatusSignalApplier } from './status-signal-applier';

const recordDeliverySignal = vi.fn();
const bindReinjectionQueueId = vi.fn();
vi.mock('@email-gateway/mail-routing', async (importOriginal) => ({
  ...(await importOriginal<typeof MailRouting>()),
  recordDeliverySignal: (...args: unknown[]) => recordDeliverySignal(...args) as unknown,
  bindReinjectionQueueId: (...args: unknown[]) => bindReinjectionQueueId(...args) as unknown,
}));

const NOW = new Date('2026-11-03T12:00:00Z');
const ev = (line: string): PostfixLogEvent => parsePostfixLogLine(line, NOW) as PostfixLogEvent;
const RECEIVED_AT = new Date('2026-11-03T06:00:00Z');

function fakePrisma(
  bound: Record<string, { id: bigint }>,
  deliveries: {
    id: bigint;
    status: string;
    address: string;
    outboundQueueId?: string | null;
  }[] = [],
) {
  return {
    deliveryReinjection: {
      findFirst: vi.fn(({ where }: { where: { queueId: string } }) => {
        const hit = bound[where.queueId];
        return Promise.resolve(
          hit ? { ...hit, receivedAt: RECEIVED_AT, direction: 'outbound', status: 'queued' } : null,
        );
      }),
      updateMany: vi.fn(() => Promise.resolve({ count: 1 })),
    },
    emailDelivery: {
      findMany: vi.fn(({ where }: { where: { status?: { in: string[] } } }) =>
        Promise.resolve(
          deliveries
            .filter((d) => where.status === undefined || where.status.in.includes(d.status))
            .map((d) => ({
              id: d.id,
              receivedAt: RECEIVED_AT,
              recipientId: d.id + 1000n,
              status: d.status,
              outboundQueueId: d.outboundQueueId ?? null,
            })),
        ),
      ),
    },
    emailRecipient: {
      findMany: vi.fn(() =>
        Promise.resolve(deliveries.map((d) => ({ id: d.id + 1000n, address: d.address }))),
      ),
    },
  };
}

let clock = 0;
const applier = (prisma: ReturnType<typeof fakePrisma>) => {
  const metrics = new DeliveryMetrics(new MetricsService({ service: 't' }));
  return {
    metrics,
    applier: new StatusSignalApplier({
      prisma: prisma as never,
      metrics,
      logger: createLogger({ service: 't', level: 'silent' }),
      sourceId: 'out.gateway.local',
      unmatchedRetryMs: 60_000,
      recorderTimeoutMs: 15_000,
      clock: () => clock,
    }),
  };
};

beforeEach(() => {
  clock = 0;
  recordDeliverySignal.mockReset();
  bindReinjectionQueueId.mockReset();
  recordDeliverySignal.mockResolvedValue({ result: 'applied', status: 'delivered' });
});

const SENT =
  'Nov 03 06:22:01 out postfix/smtp[698]: 4jJdlD6Cp2zrsd: to=<user@it-wp2-e13b06-t.sink.test>, relay=mx.sink.test[172.31.250.25]:25, delay=0.16, delays=0.09/0.05/0.02/0.01, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 05221156A60)';
const DEFERRED_NONE =
  'Nov 03 06:30:54 out postfix/error[255]: 4jJdlD6Cp2zrsd: to=<user@it-wp2-e13b06-t.sink.test>, relay=none, delay=16, delays=16/0.02/0/0, dsn=4.4.1, status=deferred (Destination not configured)';
const BIND =
  'Nov 03 06:22:00 out postfix/reinject-outbound/smtpd[694]: 4jJdlD6Cp2zrsd: client=unknown[172.31.250.30], orig_queue_id=dw1-c0722beaeab545ec8914353368ec6afb';

describe('StatusSignalApplier', () => {
  it('records a sent line as delivered with a remote attempt, keyed by the raw line', async () => {
    const { applier: a } = applier(fakePrisma({ '4jJdlD6Cp2zrsd': { id: 1n } }));
    await a.apply([ev(SENT)]);
    const [, signal] = recordDeliverySignal.mock.calls[0] as [unknown, Record<string, unknown>];
    expect(signal).toMatchObject({
      match: { queueId: '4jJdlD6Cp2zrsd', address: 'user@it-wp2-e13b06-t.sink.test' },
      status: 'delivered',
      source: 'postfix_log',
      enhancedStatus: '2.0.0',
      smtpCode: 250,
      errorClass: null,
      attempt: { remoteHost: 'mx.sink.test', remoteIp: '172.31.250.25', outcome: 'success' },
    });
    // The same line again produces the same signal key (dedupe in the recorder).
    await a.apply([ev(SENT)]);
    const [, again] = recordDeliverySignal.mock.calls[1] as [unknown, Record<string, unknown>];
    expect(again.signalKey).toBe(signal.signalKey);
  });

  it('classifies the error transport line as no_destination without an attempt', async () => {
    const { applier: a } = applier(fakePrisma({ '4jJdlD6Cp2zrsd': { id: 1n } }));
    recordDeliverySignal.mockResolvedValue({ result: 'applied', status: 'deferred' });
    await a.apply([ev(DEFERRED_NONE)]);
    const [, signal] = recordDeliverySignal.mock.calls[0] as [unknown, Record<string, unknown>];
    expect(signal).toMatchObject({ status: 'deferred', errorClass: 'no_destination' });
    expect(signal.attempt).toBeUndefined();
  });

  it('ignores lines of queue ids never bound in this stream at once: one lookup, no retry', async () => {
    const prisma = fakePrisma({});
    const { applier: a, metrics } = applier(prisma);
    const lmtp = SENT.replace('postfix/smtp[698]', 'postfix/lmtp[698]');
    await a.apply([ev(SENT), ev(lmtp)]);
    expect(a.pendingRetries).toBe(0);
    expect(prisma.deliveryReinjection.findFirst).toHaveBeenCalledTimes(2);
    clock = 10_000;
    await a.retryPending();
    expect(prisma.deliveryReinjection.findFirst).toHaveBeenCalledTimes(2);
    expect(recordDeliverySignal).not.toHaveBeenCalled();
    expect((await metrics.signals.get()).values).toEqual([]);
  });

  it('retries unmatched lines of a bound queue id in memory and drops (counts) them after the window', async () => {
    bindReinjectionQueueId.mockResolvedValue({ result: 'bound', reinjectionId: 1n });
    const prisma = fakePrisma({});
    const { applier: a, metrics } = applier(prisma);
    await a.apply([ev(BIND), ev(SENT)]);
    expect(a.pendingRetries).toBe(1);
    expect(recordDeliverySignal).not.toHaveBeenCalled();
    clock = 1000;
    await a.retryPending(); // throttled (2 s)
    expect(prisma.deliveryReinjection.findFirst).toHaveBeenCalledTimes(1);
    clock = 30_000;
    await a.retryPending();
    expect(a.pendingRetries).toBe(1);
    clock = 60_000;
    await a.retryPending();
    expect(a.pendingRetries).toBe(0);
    const counted = await metrics.signals.get();
    expect(counted.values).toEqual([
      expect.objectContaining({ labels: { source: 'postfix_log', result: 'unmatched' }, value: 1 }),
    ]);
  });

  it('applies a delivery line once its binding committed later', async () => {
    bindReinjectionQueueId.mockResolvedValue({ result: 'bound', reinjectionId: 1n });
    const bound: Record<string, { id: bigint }> = {};
    const { applier: a } = applier(fakePrisma(bound));
    await a.apply([ev(BIND), ev(SENT)]);
    expect(a.pendingRetries).toBe(1);
    bound['4jJdlD6Cp2zrsd'] = { id: 1n };
    clock = 5000;
    await a.apply([]);
    expect(a.pendingRetries).toBe(0);
    expect(recordDeliverySignal).toHaveBeenCalledTimes(1);
  });

  it('binds through bindReinjectionQueueId; an unknown token is unmatched', async () => {
    bindReinjectionQueueId
      .mockResolvedValueOnce({ result: 'bound', reinjectionId: 1n })
      .mockResolvedValueOnce({ result: 'unmatched' });
    const { applier: a } = applier(fakePrisma({}));
    await a.apply([ev(BIND)]);
    expect(bindReinjectionQueueId).toHaveBeenCalledWith(
      expect.anything(),
      'dw1-c0722beaeab545ec8914353368ec6afb',
      '4jJdlD6Cp2zrsd',
      expect.anything(),
    );
    expect(a.pendingRetries).toBe(0);
    await a.apply([ev(BIND.replace('06:22:00', '06:22:09'))]);
    expect(a.pendingRetries).toBe(1);
  });

  it('expires every non-final delivery of a queue file, and records the sender DSN queue id', async () => {
    const deliveries = [
      { id: 10n, status: 'deferred', address: 'a@ext.test' },
      { id: 11n, status: 'delivered', address: 'b@ext.test' },
    ];
    const { applier: a } = applier(fakePrisma({ '4jJdpq5F5kzBLhX': { id: 2n } }, deliveries));
    recordDeliverySignal.mockResolvedValue({ result: 'applied', status: 'expired' });
    await a.apply([
      ev(
        'Nov 03 06:26:23 out postfix/qmgr[212]: 4jJdpq5F5kzBLhX: from=<alice@it-wp2-e13b06-out.sink.test>, status=expired, returned to sender',
      ),
    ]);
    expect(recordDeliverySignal).toHaveBeenCalledTimes(1);
    expect(recordDeliverySignal.mock.calls[0]![1]).toMatchObject({
      match: { deliveryId: 10n },
      status: 'expired',
      source: 'postfix_log',
    });

    deliveries[0]!.status = 'expired';
    await a.apply([
      ev(
        'Nov 03 06:26:23 out postfix/bounce[239]: 4jJdpq5F5kzBLhX: sender non-delivery notification: 4jJdrH47Xmzw7V',
      ),
    ]);
    expect(recordDeliverySignal.mock.calls[1]![1]).toMatchObject({
      match: { deliveryId: 10n },
      status: 'expired',
      dsnQueueId: '4jJdrH47Xmzw7V',
    });
    // Postmaster copies and delay notices are not DSNs to the sender: nothing recorded.
    await a.apply([
      ev(
        'Nov 03 06:24:03 out postfix/bounce[287]: 4jJdpq5F5kzBLhX: postmaster non-delivery notification: 4jJdnb5qlPzs5c',
      ),
    ]);
    expect(recordDeliverySignal).toHaveBeenCalledTimes(2);
  });

  it('turns non-final deliveries of a removed queue file into unknown (source reconciler)', async () => {
    const { applier: a, metrics } = applier(
      fakePrisma({ '4jJdlD6Cp2zrsd': { id: 1n } }, [
        { id: 10n, status: 'queued', address: 'a@ext.test' },
      ]),
    );
    recordDeliverySignal.mockResolvedValue({ result: 'applied', status: 'unknown' });
    await a.apply([ev('Nov 03 06:22:04 out postfix/qmgr[212]: 4jJdlD6Cp2zrsd: removed')]);
    expect(recordDeliverySignal.mock.calls[0]![1]).toMatchObject({
      status: 'unknown',
      source: 'reconciler',
      failureReason: 'status_signal_missing',
    });
    expect((await metrics.reconcilerActions.get()).values[0]).toMatchObject({
      labels: { action: 'removed_unknown' },
      value: 1,
    });
  });

  const ACTIVE = (nrcpt: number) =>
    `Nov 03 06:22:00 out postfix/qmgr[212]: 4jJdlD6Cp2zrsd: from=<alice@x.test>, size=466, nrcpt=${nrcpt} (queue active)`;

  it('queue active marks the in_progress reinjection queued, and the group queued when nrcpt covers it', async () => {
    const prisma = fakePrisma({ '4jJdlD6Cp2zrsd': { id: 1n } }, [
      { id: 10n, status: 'pending', address: 'a@ext.test' },
      { id: 11n, status: 'deferred', address: 'b@ext.test' },
      { id: 12n, status: 'failed', address: 'c@ext.test' },
    ]);
    const { applier: a } = applier(prisma);
    recordDeliverySignal.mockResolvedValue({ result: 'applied', status: 'queued' });
    await a.apply([ev(ACTIVE(2))]);
    expect(prisma.deliveryReinjection.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ status: 'in_progress', queueId: '4jJdlD6Cp2zrsd' }),
      }),
    );
    expect(recordDeliverySignal).toHaveBeenCalledTimes(2);
    expect(
      recordDeliverySignal.mock.calls.map((c) => (c as [unknown, { match: unknown }])[1].match),
    ).toEqual([
      { deliveryId: 10n, receivedAt: RECEIVED_AT },
      { deliveryId: 11n, receivedAt: RECEIVED_AT },
    ]);
    expect(recordDeliverySignal.mock.calls[0]![1]).toMatchObject({
      status: 'queued',
      source: 'postfix_log',
      queueId: '4jJdlD6Cp2zrsd',
    });
  });

  it('queue active with fewer recipients than the group (refused/deferred at RCPT) queues nobody', async () => {
    const prisma = fakePrisma({ '4jJdlD6Cp2zrsd': { id: 1n } }, [
      { id: 10n, status: 'pending', address: 'ok@ext.test' },
      { id: 11n, status: 'pending', address: 'soft@ext.test' },
      { id: 12n, status: 'pending', address: 'hard@ext.test' },
    ]);
    const { applier: a } = applier(prisma);
    await a.apply([ev(ACTIVE(1))]);
    // The file exists: the row is queued (never re-sent) ...
    expect(prisma.deliveryReinjection.updateMany).toHaveBeenCalledTimes(1);
    // ... but which recipient was accepted is only known from its own lines.
    expect(recordDeliverySignal).not.toHaveBeenCalled();
  });

  it('a later queue active of the same file (after a deferral) changes nothing', async () => {
    const prisma = fakePrisma({ '4jJdlD6Cp2zrsd': { id: 1n } }, [
      { id: 10n, status: 'deferred', address: 'a@ext.test', outboundQueueId: '4jJdlD6Cp2zrsd' },
    ]);
    const { applier: a } = applier(prisma);
    await a.apply([ev(ACTIVE(1))]);
    expect(recordDeliverySignal).not.toHaveBeenCalled();
  });
});
