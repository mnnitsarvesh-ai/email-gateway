import {
  deliveryApprovedV1,
  EventTypes,
  messageScannedV1,
  type MessageScannedV1,
  type EventEnvelope,
} from '@email-gateway/event-contracts';
import { type EventHandler, MetricsService } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import { createLogger, type Logger } from '@email-gateway/logger';
import {
  transitionMessage,
  type LifecycleSnapshot,
  type TransitionOutcome,
} from '@email-gateway/message-lifecycle';
import type * as Lifecycle from '@email-gateway/message-lifecycle';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { RECORDER_TX_TIMEOUT_MS } from '../delivery.module';
import { DeliveryMetrics } from '../metrics/delivery-metrics';
import type { ApprovalFeed } from './approval-feed';
import {
  DEV_PASSTHROUGH_CONSUMER,
  DEV_PASSTHROUGH_WARNING,
  DevPassThroughApprover,
} from './dev-passthrough.approver';

vi.mock('@email-gateway/message-lifecycle', async (original) => ({
  ...(await original<typeof Lifecycle>()),
  transitionMessage: vi.fn(),
}));

const NOW = new Date('2026-11-03T12:00:00Z');

const snapshot = (state: LifecycleSnapshot['state'], round = 0): LifecycleSnapshot => ({
  state,
  version: state === 'approved' ? 4 : 3,
  round,
  statusChangedAt: NOW,
  statusReason: null,
  direction: 'outbound',
  emlObjectKey: 'org/7/eml/2026/11/03/stored.eml',
});

const applied: TransitionOutcome = {
  result: 'applied',
  from: 'scanned',
  to: 'approved',
  version: 4,
  round: 0,
  historyId: 1n,
  stateEventId: '0190f0f0-0000-7000-8000-0000000000aa',
  snapshot: snapshot('approved'),
};
const transition = vi.mocked(transitionMessage);
beforeEach(() => {
  transition.mockReset();
  transition.mockResolvedValue(applied);
});

const metricsService = () => new MetricsService({ service: 't' });
const newMetrics = (service = metricsService()) => new DeliveryMetrics(service);
const scannedPayload = (overrides: Partial<MessageScannedV1> = {}): MessageScannedV1 =>
  messageScannedV1.parse({
    messageId: '100',
    receivedAt: '2026-11-03T11:59:00.000Z',
    direction: 'outbound',
    emlS3Key: 'org/7/eml/2026/11/03/abc.eml',
    lifecycleRound: 0,
    scanId: '900',
    scanKind: 'initial',
    outcome: 'scanned',
    verdict: 'spam',
    engines: [{ engine: 'rspamd', required: true, outcome: 'spam', attempts: 1 }],
    reasonCodes: ['spam.score'],
    completedAt: '2026-11-03T11:59:30.000Z',
    ...overrides,
  });

const event: EventEnvelope<MessageScannedV1> = {
  eventId: '0190f0f0-0000-7000-8000-000000000001',
  eventType: EventTypes.MessageScanned,
  occurredAt: NOW.toISOString(),
  correlationId: 'corr-12345678',
  organizationId: '7',
  payload: scannedPayload(),
};

const scanFailedEvent: EventEnvelope<MessageScannedV1> = {
  ...event,
  eventId: '0190f0f0-0000-7000-8000-000000000002',
  payload: scannedPayload({
    outcome: 'scan_failed',
    verdict: 'timeout',
    engines: [{ engine: 'rspamd', required: true, outcome: 'timeout', attempts: 6 }],
    reasonCodes: ['engine.timeout'],
  }),
};

function fakeTx(options: { recipients?: number; maxDeliverySeq?: number | null }) {
  const outbox: { data: Record<string, unknown> }[] = [];
  const events: { data: Record<string, unknown> }[] = [];
  const tx = {
    emailDelivery: {
      aggregate: vi.fn(() =>
        Promise.resolve({ _max: { deliverySeq: options.maxDeliverySeq ?? null } }),
      ),
    },
    emailRecipient: {
      findMany: vi.fn(() =>
        Promise.resolve(
          Array.from({ length: options.recipients ?? 2 }, (_, i) => ({
            id: BigInt(500 + i),
            rcptSeq: i,
          })),
        ),
      ),
    },
    messageOutbox: {
      create: vi.fn(
        (args: { data: Record<string, unknown> }) => (
          outbox.push(args),
          Promise.resolve({ id: 1n })
        ),
      ),
    },
    emailEvent: {
      create: vi.fn(
        (args: { data: Record<string, unknown> }) => (
          events.push(args),
          Promise.resolve({ id: 1n })
        ),
      ),
    },
  };
  return { tx, outbox, events };
}

const feed = (): ApprovalFeed<MessageScannedV1> & {
  started: number;
  handler?: EventHandler<MessageScannedV1>;
} => ({
  started: 0,
  start(handler) {
    this.started += 1;
    this.handler = handler;
  },
  stop: () => Promise.resolve(),
});

/** The writer as processOnce sees it: one interactive transaction per event, with a ledger. */
function fakeWriter(tx: object) {
  const ledger: { consumer: string; eventId: string }[] = [];
  const options: unknown[] = [];
  const prisma = {
    $transaction(fn: (t: unknown) => Promise<unknown>, opts?: unknown) {
      options.push(opts);
      return fn({
        ...tx,
        messageIdempotency: {
          create: ({ data }: { data: { consumer: string; eventId: string } }) => (
            ledger.push(data),
            Promise.resolve(data)
          ),
        },
      });
    },
  };
  return { prisma: prisma as unknown as PrismaClient, ledger, options };
}

const noWriter = {} as PrismaClient;

describe('DevPassThroughApprover (R5, step 4.1 S15, development only)', () => {
  it('writes one approval for every pending recipient, from the stored message row', async () => {
    const { tx, outbox, events } = fakeTx({});
    const approver = new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      createLogger({ service: 't', level: 'silent' }),
      newMetrics(),
      () => NOW,
    );
    const result = await approver.approve(event, tx as never);
    expect(result.recipients).toBe(2);
    expect(result.approvals).toHaveLength(1);
    // E27 first, for the envelope's organization and the scan round (step 4.1 S15).
    expect(transition).toHaveBeenCalledTimes(1);
    expect(transition.mock.calls[0]![0]).toBe(tx);
    expect(transition.mock.calls[0]![1]).toEqual({
      message: { id: 100n, receivedAt: new Date(event.payload.receivedAt), organizationId: 7n },
      to: 'approved',
      reason: 'dev_passthrough',
      actor: { role: 'dev_passthrough', service: 'delivery-worker', type: 'system' },
      transitionKey: `evt:${event.eventId}:approved`,
      causationEventId: event.eventId,
      correlationId: 'corr-12345678',
      expectedRound: 0,
      expectedFrom: ['scanned'],
    });
    // Only pending recipients.
    expect(tx.emailRecipient.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ status: 'pending', organizationId: 7n }),
      }),
    );
    const row = outbox[0]!.data;
    expect(row).toMatchObject({
      eventId: result.approvals[0],
      organizationId: 7n,
      eventType: EventTypes.DeliveryApproved,
      aggregateType: 'message',
      aggregateId: '100',
      correlationId: 'corr-12345678',
    });
    const payload = deliveryApprovedV1.parse(row.payload);
    expect(payload).toEqual({
      messageId: '100',
      receivedAt: '2026-11-03T11:59:00.000Z',
      deliverySeq: 0,
      lifecycleRound: 0,
      source: 'dev_passthrough',
      emlS3Key: 'org/7/eml/2026/11/03/stored.eml',
      recipients: [
        { recipientId: '500', rcptSeq: 0 },
        { recipientId: '501', rcptSeq: 1 },
      ],
      approvedAt: NOW.toISOString(),
    });
    expect(events[0]!.data).toMatchObject({
      eventType: 'delivery.approved',
      sourceService: 'delivery-worker',
      eventId: result.approvals[0],
      details: {
        source: 'dev_passthrough',
        approvalEventId: result.approvals[0],
        deliverySeq: 0,
        lifecycleRound: 0,
        recipientCount: 2,
      },
    });
  });

  it('splits more than 1000 recipients into several approvals', async () => {
    const { tx, outbox } = fakeTx({ recipients: 2500 });
    const approver = new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      createLogger({ service: 't', level: 'silent' }),
      newMetrics(),
      () => NOW,
    );
    const result = await approver.approve(event, tx as never);
    expect(result.approvals).toHaveLength(3);
    expect(new Set(result.approvals).size).toBe(3);
    expect(
      outbox.map((o) => (o.data.payload as { recipients: unknown[] }).recipients.length),
    ).toEqual([1000, 1000, 500]);
  });

  it('approves nothing for an unknown message or without pending recipients', async () => {
    transition.mockResolvedValueOnce({ result: 'not_found' });
    const approver = new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      createLogger({ service: 't', level: 'silent' }),
      newMetrics(),
      () => NOW,
    );
    const missing = fakeTx({});
    expect(await approver.approve(event, missing.tx as never)).toEqual({
      approvals: [],
      recipients: 0,
    });
    const none = fakeTx({ recipients: 0 });
    expect(await approver.approve(event, none.tx as never)).toEqual({
      approvals: [],
      recipients: 0,
    });
    expect(missing.outbox).toHaveLength(0);
    expect(missing.tx.emailRecipient.findMany).not.toHaveBeenCalled();
    expect(none.outbox).toHaveLength(0);
  });

  it('skips a message the lifecycle does not let it approve (not scanned, older round), counting the reason', async () => {
    const service = metricsService();
    const approver = new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      createLogger({ service: 't', level: 'silent' }),
      newMetrics(service),
      () => NOW,
    );
    const outcomes: TransitionOutcome[] = [
      { result: 'stale', why: 'overtaken', snapshot: snapshot('delivery_pending') },
      { result: 'invalid', why: 'unexpected_from', snapshot: snapshot('delivery_retry') },
      { result: 'stale', why: 'older_round', snapshot: snapshot('approved') },
      { result: 'not_found' },
      // A re-run after a committed approval: nothing more, not counted as skipped.
      { result: 'duplicate', why: 'transition_key', snapshot: snapshot('approved') },
    ];
    for (const outcome of outcomes) {
      transition.mockResolvedValueOnce(outcome);
      const t = fakeTx({});
      expect(await approver.approve(event, t.tx as never)).toEqual({
        approvals: [],
        recipients: 0,
      });
      expect(t.outbox).toHaveLength(0);
      expect(t.events).toHaveLength(0);
      expect(t.tx.emailRecipient.findMany).not.toHaveBeenCalled();
    }
    const text = await service.metrics();
    expect(text).toContain(
      'delivery_approvals_skipped_total{reason="lifecycle_stale",service="t"} 2',
    );
    expect(text).toContain(
      'delivery_approvals_skipped_total{reason="lifecycle_invalid",service="t"} 1',
    );
    expect(text).toContain(
      'delivery_approvals_skipped_total{reason="lifecycle_not_found",service="t"} 1',
    );
    expect(text).not.toContain('reason="lifecycle_duplicate"');
  });

  it('approves a rescan round with that round, after the existing deliveries', async () => {
    transition.mockResolvedValueOnce({ ...applied, round: 2, snapshot: snapshot('approved', 2) });
    const { tx, outbox, events } = fakeTx({ recipients: 1, maxDeliverySeq: 1 });
    const approver = new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      createLogger({ service: 't', level: 'silent' }),
      newMetrics(),
      () => NOW,
    );
    const rescan: EventEnvelope<MessageScannedV1> = {
      ...event,
      payload: scannedPayload({ lifecycleRound: 2, scanKind: 'rescan', verdict: 'clean' }),
    };
    const result = await approver.approve(rescan, tx as never);
    expect(result.approvals).toHaveLength(1);
    expect(transition.mock.calls[0]![1]).toMatchObject({
      expectedRound: 2,
      expectedFrom: ['scanned'],
      transitionKey: `evt:${event.eventId}:approved`,
    });
    expect(deliveryApprovedV1.parse(outbox[0]!.data.payload)).toMatchObject({
      lifecycleRound: 2,
      deliverySeq: 2,
    });
    expect(events[0]!.data.details).toMatchObject({ lifecycleRound: 2, deliverySeq: 2 });
  });

  it('approves every verdict of a complete scan (the pass-through stands in for policy)', async () => {
    const approver = new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      createLogger({ service: 't', level: 'silent' }),
      newMetrics(),
      () => NOW,
    );
    for (const verdict of ['clean', 'suspicious', 'malicious', 'unknown'] as const) {
      const t = fakeTx({ recipients: 1 });
      const result = await approver.approve(
        {
          ...event,
          payload: scannedPayload({
            verdict,
            engines: [{ engine: 'rspamd', required: true, outcome: verdict, attempts: 1 }],
          }),
        },
        t.tx as never,
      );
      expect(result.approvals).toHaveLength(1);
    }
  });

  it('never approves a failed scan: no transition, no approval, counted as scan_failed', async () => {
    const service = metricsService();
    const approver = new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      createLogger({ service: 't', level: 'silent' }),
      newMetrics(service),
      () => NOW,
    );
    const t = fakeTx({});
    expect(await approver.approve(scanFailedEvent, t.tx as never)).toEqual({
      approvals: [],
      recipients: 0,
    });
    expect(transition).not.toHaveBeenCalled();
    expect(t.outbox).toHaveLength(0);
    expect(t.events).toHaveLength(0);
    expect(t.tx.emailRecipient.findMany).not.toHaveBeenCalled();
    expect(await service.metrics()).toContain(
      'delivery_approvals_skipped_total{reason="scan_failed",service="t"} 1',
    );
  });

  it('logs the startup warning when started', () => {
    const warn = vi.fn();
    const logger = { child: () => ({ warn, info: vi.fn() }) } as unknown as Logger;
    const f = feed();
    new DevPassThroughApprover(f, noWriter, RECORDER_TX_TIMEOUT_MS, logger, newMetrics()).start();
    expect(warn).toHaveBeenCalledWith(DEV_PASSTHROUGH_WARNING);
    expect(f.started).toBe(1);
  });

  it('approves inside the dev-passthrough idempotency transaction with the recorder budget', async () => {
    const { tx, outbox } = fakeTx({});
    const writer = fakeWriter(tx);
    const f = feed();
    new DevPassThroughApprover(
      f,
      writer.prisma,
      RECORDER_TX_TIMEOUT_MS,
      createLogger({ service: 't', level: 'silent' }),
      newMetrics(),
      () => NOW,
    ).start();
    expect(await f.handler!(event)).toBe('handled');
    expect(writer.ledger).toEqual([{ consumer: DEV_PASSTHROUGH_CONSUMER, eventId: event.eventId }]);
    expect(writer.options).toEqual([
      { timeout: RECORDER_TX_TIMEOUT_MS, maxWait: RECORDER_TX_TIMEOUT_MS },
    ]);
    expect(outbox).toHaveLength(1);
    // A failed scan commits its ledger row too (handled once, never approved).
    expect(await f.handler!(scanFailedEvent)).toBe('handled');
    expect(writer.ledger).toHaveLength(2);
    expect(outbox).toHaveLength(1);
  });

  it('uses its own consumer name and warns that mail is delivered after scanning', () => {
    expect(DEV_PASSTHROUGH_CONSUMER).toBe('delivery-worker.dev-passthrough-scanned');
    expect(DEV_PASSTHROUGH_WARNING).toContain('after scanning but without policy');
  });
});
