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
  becHoldDecision,
  heldBecOutcome,
  dlpHoldDecision,
  dlpResultApplies,
  InconsistentBecResultReadError,
  InconsistentDlpResultReadError,
  InconsistentRewriteReadError,
  InconsistentRiskReadError,
  isRewriteKeyOf,
  riskHoldAction,
  riskHoldDecision,
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

/** The round's `bec_scan_results` verdicts as the email-worker writes them (echo columns). */
const becRow = (deterministicVerdict: string, overrides: Record<string, unknown> = {}) => ({
  scanId: 900n,
  receivedAt: new Date('2026-11-03T11:59:00.000Z'),
  messageId: 100n,
  organizationId: 7n,
  lifecycleRound: 0,
  deterministicVerdict,
  verdict: 'suspicious',
  ...overrides,
});

/** The round's `dlp_scan_results` action as the email-worker writes it (echo columns). */
const dlpRow = (action: string, overrides: Record<string, unknown> = {}) => ({
  scanId: 900n,
  receivedAt: new Date('2026-11-03T11:59:00.000Z'),
  messageId: 100n,
  organizationId: 7n,
  lifecycleRound: 0,
  action,
  ...overrides,
});

/** The round's revision-0 `message_risk_scores` row as the email-worker writes it (echo columns). */
const riskRow = (
  recommendedAction: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> => ({
  scanId: 900n,
  receivedAt: new Date('2026-11-03T11:59:00.000Z'),
  messageId: 100n,
  organizationId: 7n,
  lifecycleRound: 0,
  revision: 0,
  status: 'scored',
  level: recommendedAction === 'deliver' ? 'none' : 'high',
  recommendedAction,
  hardBlocks: [],
  ...overrides,
});

function fakeTx(options: {
  recipients?: number;
  maxDeliverySeq?: number | null;
  rewrite?: Record<string, unknown> | null;
  /** Default: a deterministic `suspicious` row of the round. */
  bec?: Record<string, unknown> | null;
  /** Default: an `allow` row of the round. */
  dlp?: Record<string, unknown> | null;
  /** Default: a revision-0 `deliver` risk score of the round asked for (step 5.1). */
  risk?: Record<string, unknown> | null;
}) {
  const outbox: { data: Record<string, unknown> }[] = [];
  const events: { data: Record<string, unknown> }[] = [];
  const tx = {
    urlRewrite: {
      findFirst: vi.fn((_args: unknown) => Promise.resolve(options.rewrite ?? null)),
    },
    becScanResult: {
      findFirst: vi.fn((_args: unknown) =>
        Promise.resolve(options.bec === undefined ? becRow('suspicious') : options.bec),
      ),
    },
    dlpScanResult: {
      findFirst: vi.fn((_args: unknown) =>
        Promise.resolve(options.dlp === undefined ? dlpRow('allow') : options.dlp),
      ),
    },
    messageRiskScore: {
      // Default: the `deliver` row of exactly the round asked for (any round of the test).
      findFirst: vi.fn((args: { where: Record<string, unknown> }) =>
        Promise.resolve(
          options.risk === undefined ? riskRow('deliver', { ...args.where }) : options.risk,
        ),
      ),
    },
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

  it('approves every non-malicious verdict of a complete scan (the pass-through stands in for policy)', async () => {
    const approver = new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      createLogger({ service: 't', level: 'silent' }),
      newMetrics(),
      () => NOW,
    );
    for (const verdict of ['clean', 'spam', 'suspicious', 'unknown'] as const) {
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

  it('holds a malicious verdict (step 4.2 A15): no transition, no approval, counted, logged with ids', async () => {
    const service = metricsService();
    const info = vi.fn();
    const logger = { child: () => ({ warn: vi.fn(), info }) } as unknown as Logger;
    const approver = new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      logger,
      newMetrics(service),
      () => NOW,
    );
    const t = fakeTx({ recipients: 2 });
    const malicious = {
      ...event,
      payload: scannedPayload({
        verdict: 'malicious',
        engines: [
          { engine: 'rspamd', required: true, outcome: 'clean', attempts: 1 },
          { engine: 'attachment', required: true, outcome: 'malicious', attempts: 1 },
        ],
      }),
    };
    expect(await approver.approve(malicious, t.tx as never)).toEqual({
      approvals: [],
      recipients: 0,
    });
    expect(transition).not.toHaveBeenCalled();
    expect(t.outbox).toHaveLength(0);
    expect(t.events).toHaveLength(0);
    expect(t.tx.emailRecipient.findMany).not.toHaveBeenCalled();
    expect(await service.metrics()).toContain(
      'delivery_approvals_skipped_total{reason="malicious_verdict",service="t"} 1',
    );
    expect(info).toHaveBeenCalledWith(
      {
        eventId: malicious.eventId,
        messageId: malicious.payload.messageId,
        scanId: malicious.payload.scanId,
        round: malicious.payload.lifecycleRound,
        outcome: 'scanned',
        verdict: 'malicious',
      },
      expect.stringContaining('malicious verdict'),
    );
  });

  it('commits the ledger row of a held malicious verdict (handled once, never approved)', async () => {
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
    const malicious = { ...event, payload: scannedPayload({ verdict: 'malicious' }) };
    expect(await f.handler!(malicious)).toBe('handled');
    expect(writer.ledger).toEqual([
      { consumer: DEV_PASSTHROUGH_CONSUMER, eventId: malicious.eventId },
    ]);
    expect(outbox).toHaveLength(0);
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
    expect(DEV_PASSTHROUGH_WARNING).toContain('delivered after scanning without policy');
    expect(DEV_PASSTHROUGH_WARNING).toContain('malicious verdicts are held in scanned');
    expect(DEV_PASSTHROUGH_WARNING).toContain('suspicious or malicious BEC results');
    expect(DEV_PASSTHROUGH_WARNING).toContain('DLP actions require_approval, quarantine and block');
    expect(DEV_PASSTHROUGH_WARNING).toContain('risk recommendations require_approval');
    expect(DEV_PASSTHROUGH_WARNING).toContain('missing risk scores');
  });
});

describe('DevPassThroughApprover: BEC verdicts (step 4.4 B17)', () => {
  const engines = (bec: 'clean' | 'suspicious' | 'malicious' | 'unknown' | 'skipped') => [
    { engine: 'rspamd', required: true, outcome: 'clean' as const, attempts: 1 },
    { engine: 'url', required: true, outcome: 'suspicious' as const, attempts: 1 },
    { engine: 'bec', required: true, outcome: bec, attempts: 1 },
  ];
  const becEvent = (
    bec: 'clean' | 'suspicious' | 'malicious' | 'unknown' | 'skipped',
    verdict: MessageScannedV1['verdict'] = 'suspicious',
  ): EventEnvelope<MessageScannedV1> => ({
    ...event,
    payload: scannedPayload({ verdict, engines: engines(bec), reasonCodes: [] }),
  });

  it('heldBecOutcome is the bec outcome when suspicious or malicious, else null', () => {
    expect(heldBecOutcome(scannedPayload({ engines: engines('suspicious') }))).toBe('suspicious');
    expect(heldBecOutcome(scannedPayload({ engines: engines('malicious') }))).toBe('malicious');
    for (const outcome of ['clean', 'unknown', 'skipped'] as const) {
      expect(heldBecOutcome(scannedPayload({ engines: engines(outcome) }))).toBeNull();
    }
    expect(heldBecOutcome(scannedPayload())).toBeNull();
  });

  it.each(['suspicious', 'malicious'] as const)(
    'holds a %s bec result: no transition, no approval, counted bec_verdict, logged with ids',
    async (bec) => {
      const service = metricsService();
      const info = vi.fn();
      const logger = { child: () => ({ warn: vi.fn(), info }) } as unknown as Logger;
      const approver = new DevPassThroughApprover(
        feed(),
        noWriter,
        RECORDER_TX_TIMEOUT_MS,
        logger,
        newMetrics(service),
        () => NOW,
      );
      const t = fakeTx({ recipients: 2 });
      const held = becEvent(bec);
      expect(await approver.approve(held, t.tx as never)).toEqual({ approvals: [], recipients: 0 });
      expect(transition).not.toHaveBeenCalled();
      expect(t.outbox).toHaveLength(0);
      expect(t.events).toHaveLength(0);
      expect(t.tx.emailRecipient.findMany).not.toHaveBeenCalled();
      expect(t.tx.urlRewrite.findFirst).not.toHaveBeenCalled();
      expect(await service.metrics()).toContain(
        'delivery_approvals_skipped_total{reason="bec_verdict",service="t"} 1',
      );
      expect(info).toHaveBeenCalledWith(
        {
          eventId: held.eventId,
          messageId: held.payload.messageId,
          scanId: held.payload.scanId,
          round: held.payload.lifecycleRound,
          outcome: 'scanned',
          verdict: 'suspicious',
          becOutcome: bec,
        },
        expect.stringContaining('BEC result'),
      );
    },
  );

  it.each(['clean', 'unknown', 'skipped'] as const)(
    'approves a %s bec result even when the url engine is suspicious',
    async (bec) => {
      const approver = new DevPassThroughApprover(
        feed(),
        noWriter,
        RECORDER_TX_TIMEOUT_MS,
        createLogger({ service: 't', level: 'silent' }),
        newMetrics(),
        () => NOW,
      );
      const t = fakeTx({ recipients: 1 });
      const result = await approver.approve(becEvent(bec), t.tx as never);
      expect(result.approvals).toHaveLength(1);
      expect(transition).toHaveBeenCalledTimes(1);
    },
  );

  it('a malicious verdict is still counted as malicious_verdict; a failed scan as scan_failed', async () => {
    const service = metricsService();
    const approver = new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      createLogger({ service: 't', level: 'silent' }),
      newMetrics(service),
      () => NOW,
    );
    await approver.approve(becEvent('malicious', 'malicious'), fakeTx({}).tx as never);
    await approver.approve(scanFailedEvent, fakeTx({}).tx as never);
    const text = await service.metrics();
    expect(text).toContain(
      'delivery_approvals_skipped_total{reason="malicious_verdict",service="t"} 1',
    );
    expect(text).toContain('delivery_approvals_skipped_total{reason="scan_failed",service="t"} 1');
    expect(text).not.toContain('reason="bec_verdict"');
  });

  it('becHoldDecision: held only for a deterministic suspicious/malicious verdict; missing is held', () => {
    expect(becHoldDecision(null)).toBe('missing');
    expect(becHoldDecision({ deterministicVerdict: 'suspicious', verdict: 'suspicious' })).toBe(
      'held',
    );
    expect(becHoldDecision({ deterministicVerdict: 'suspicious', verdict: 'malicious' })).toBe(
      'held',
    );
    expect(becHoldDecision({ deterministicVerdict: 'malicious', verdict: 'malicious' })).toBe(
      'held',
    );
    for (const deterministicVerdict of ['clean', 'unknown']) {
      expect(becHoldDecision({ deterministicVerdict, verdict: 'suspicious' })).toBe('ai_only');
    }
  });

  it.each(['clean', 'unknown'] as const)(
    'approves a bec result raised to suspicious by the AI layer alone (deterministic %s; ADR-0034)',
    async (deterministic) => {
      const service = metricsService();
      const approver = new DevPassThroughApprover(
        feed(),
        noWriter,
        RECORDER_TX_TIMEOUT_MS,
        createLogger({ service: 't', level: 'silent' }),
        newMetrics(service),
        () => NOW,
      );
      const t = fakeTx({ recipients: 1, bec: becRow(deterministic) });
      const result = await approver.approve(becEvent('suspicious'), t.tx as never);
      expect(result.approvals).toHaveLength(1);
      expect(transition).toHaveBeenCalledTimes(1);
      expect(t.tx.becScanResult.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            scanId: 900n,
            receivedAt: new Date('2026-11-03T11:59:00.000Z'),
            messageId: 100n,
            organizationId: 7n,
            lifecycleRound: 0,
          },
        }),
      );
      const text = await service.metrics();
      expect(text).toContain('delivery_bec_ai_only_not_held_total{service="t"} 1');
      expect(text).not.toContain('reason="bec_verdict"');
    },
  );

  it('holds when the bec result row is missing (fail-safe); a shifted read is inconsistent', async () => {
    const service = metricsService();
    const warn = vi.fn();
    const logger = { child: () => ({ warn, info: vi.fn() }) } as unknown as Logger;
    const approver = new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      logger,
      newMetrics(service),
      () => NOW,
    );
    const missing = fakeTx({ bec: null });
    expect(await approver.approve(becEvent('suspicious'), missing.tx as never)).toEqual({
      approvals: [],
      recipients: 0,
    });
    expect(transition).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ becOutcome: 'suspicious' }),
      expect.stringContaining('fail-safe'),
    );
    const shifted = fakeTx({ bec: becRow('clean', { organizationId: 8n }) });
    await expect(approver.approve(becEvent('suspicious'), shifted.tx as never)).rejects.toThrow(
      InconsistentBecResultReadError,
    );
    expect(transition).not.toHaveBeenCalled();
    expect(await service.metrics()).toContain(
      'delivery_inconsistent_reads_total{read="bec_result",service="t"} 1',
    );
  });

  it('commits the ledger row of a held bec result (handled once, never approved)', async () => {
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
    const held = becEvent('suspicious');
    expect(await f.handler!(held)).toBe('handled');
    expect(writer.ledger).toEqual([{ consumer: DEV_PASSTHROUGH_CONSUMER, eventId: held.eventId }]);
    expect(outbox).toHaveLength(0);
  });
});

describe('DevPassThroughApprover: DLP actions (step 4.5 D13)', () => {
  type DlpOutcome = 'clean' | 'suspicious' | 'unknown' | 'skipped';
  const engines = (dlp: DlpOutcome, bec: 'clean' | 'suspicious' = 'clean') => [
    { engine: 'rspamd', required: true, outcome: 'clean' as const, attempts: 1 },
    { engine: 'bec', required: true, outcome: bec, attempts: 1 },
    { engine: 'dlp', required: true, outcome: dlp, attempts: 1 },
  ];
  const dlpEvent = (
    dlp: DlpOutcome,
    verdict: MessageScannedV1['verdict'] = 'suspicious',
    bec: 'clean' | 'suspicious' = 'clean',
  ): EventEnvelope<MessageScannedV1> => ({
    ...event,
    payload: scannedPayload({ verdict, engines: engines(dlp, bec), reasonCodes: [] }),
  });
  const approverWith = (service: MetricsService, logger?: Logger) =>
    new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      logger ?? createLogger({ service: 't', level: 'silent' }),
      newMetrics(service),
      () => NOW,
    );
  const where = {
    scanId: 900n,
    receivedAt: new Date('2026-11-03T11:59:00.000Z'),
    messageId: 100n,
    organizationId: 7n,
    lifecycleRound: 0,
  };

  it('dlpResultApplies: a definite dlp outcome other than skipped; absent entry ignored', () => {
    for (const outcome of ['clean', 'suspicious', 'unknown'] as const) {
      expect(dlpResultApplies(scannedPayload({ engines: engines(outcome) }))).toBe(true);
    }
    expect(dlpResultApplies(scannedPayload({ engines: engines('skipped') }))).toBe(false);
    expect(dlpResultApplies(scannedPayload())).toBe(false);
  });

  it('dlpHoldDecision: allow/alert approve, require_approval/quarantine/block hold, missing holds', () => {
    expect(dlpHoldDecision('allow')).toBe('approve');
    expect(dlpHoldDecision('alert')).toBe('alert');
    for (const action of ['require_approval', 'quarantine', 'block']) {
      expect(dlpHoldDecision(action)).toBe('held');
    }
    expect(dlpHoldDecision(null)).toBe('missing');
  });

  it.each(['require_approval', 'quarantine', 'block'] as const)(
    'holds a %s action: no transition, no approval, counted dlp_action and by action, logged',
    async (action) => {
      const service = metricsService();
      const info = vi.fn();
      const logger = { child: () => ({ warn: vi.fn(), info }) } as unknown as Logger;
      const t = fakeTx({ recipients: 2, dlp: dlpRow(action) });
      const held = dlpEvent('suspicious');
      expect(await approverWith(service, logger).approve(held, t.tx as never)).toEqual({
        approvals: [],
        recipients: 0,
      });
      expect(transition).not.toHaveBeenCalled();
      expect(t.outbox).toHaveLength(0);
      expect(t.events).toHaveLength(0);
      expect(t.tx.emailRecipient.findMany).not.toHaveBeenCalled();
      expect(t.tx.dlpScanResult.findFirst).toHaveBeenCalledWith(expect.objectContaining({ where }));
      const text = await service.metrics();
      expect(text).toContain('delivery_approvals_skipped_total{reason="dlp_action",service="t"} 1');
      expect(text).toContain(`delivery_dlp_holds_total{action="${action}",service="t"} 1`);
      expect(info).toHaveBeenCalledWith(
        {
          eventId: held.eventId,
          messageId: held.payload.messageId,
          scanId: held.payload.scanId,
          round: held.payload.lifecycleRound,
          outcome: 'scanned',
          verdict: 'suspicious',
          dlpAction: action,
        },
        expect.stringContaining('DLP action holds'),
      );
    },
  );

  it('approves allow; approves alert and counts it with an info log of the ids and action', async () => {
    const service = metricsService();
    const info = vi.fn();
    const logger = {
      child: () => ({ warn: vi.fn(), info }),
    } as unknown as Logger;
    const allow = fakeTx({ recipients: 1, dlp: dlpRow('allow') });
    expect(
      (await approverWith(service, logger).approve(dlpEvent('clean', 'clean'), allow.tx as never))
        .approvals,
    ).toHaveLength(1);
    const alert = fakeTx({ recipients: 1, dlp: dlpRow('alert') });
    const alerted = dlpEvent('suspicious');
    expect(
      (await approverWith(service, logger).approve(alerted, alert.tx as never)).approvals,
    ).toHaveLength(1);
    expect(transition).toHaveBeenCalledTimes(2);
    const text = await service.metrics();
    expect(text).toContain('delivery_dlp_alerts_approved_total{service="t"} 1');
    expect(text).not.toContain('reason="dlp_action"');
    expect(info).toHaveBeenCalledWith(
      expect.objectContaining({ messageId: '100', scanId: '900', dlpAction: 'alert' }),
      expect.stringContaining('DLP alert'),
    );
  });

  it('holds when the dlp result row is missing (fail-safe, warn); a shifted read throws', async () => {
    const service = metricsService();
    const warn = vi.fn();
    const logger = { child: () => ({ warn, info: vi.fn() }) } as unknown as Logger;
    const approver = approverWith(service, logger);
    const missing = fakeTx({ dlp: null });
    expect(await approver.approve(dlpEvent('unknown', 'unknown'), missing.tx as never)).toEqual({
      approvals: [],
      recipients: 0,
    });
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ messageId: '100' }),
      expect.stringContaining('fail-safe'),
    );
    for (const shift of [
      { organizationId: 8n },
      { messageId: 101n },
      { scanId: 901n },
      { lifecycleRound: 1 },
      { receivedAt: new Date('2026-11-03T11:59:00.001Z') },
    ]) {
      const shifted = fakeTx({ dlp: dlpRow('allow', shift) });
      await expect(
        approver.approve(dlpEvent('clean', 'clean'), shifted.tx as never),
      ).rejects.toThrow(InconsistentDlpResultReadError);
    }
    expect(transition).not.toHaveBeenCalled();
    const text = await service.metrics();
    expect(text).toContain('delivery_dlp_holds_total{action="missing",service="t"} 1');
    expect(text).toContain('delivery_approvals_skipped_total{reason="dlp_action",service="t"} 1');
    expect(text).toContain('delivery_inconsistent_reads_total{read="dlp_result",service="t"} 5');
  });

  it('ignores a skipped dlp entry and rounds without dlp (no read)', async () => {
    const t = fakeTx({ recipients: 1, dlp: dlpRow('block') });
    const result = await approverWith(metricsService()).approve(
      dlpEvent('skipped', 'clean'),
      t.tx as never,
    );
    expect(result.approvals).toHaveLength(1);
    expect(t.tx.dlpScanResult.findFirst).not.toHaveBeenCalled();
    const plain = fakeTx({ recipients: 1, dlp: dlpRow('block') });
    expect(
      (await approverWith(metricsService()).approve(event, plain.tx as never)).approvals,
    ).toHaveLength(1);
    expect(plain.tx.dlpScanResult.findFirst).not.toHaveBeenCalled();
  });

  it('keeps the order: scan_failed, malicious and BEC holds keep their reasons and skip the DLP read', async () => {
    const service = metricsService();
    const approver = approverWith(service);
    const failed = fakeTx({ dlp: dlpRow('block') });
    await approver.approve(scanFailedEvent, failed.tx as never);
    const malicious = fakeTx({ dlp: dlpRow('block') });
    await approver.approve(dlpEvent('suspicious', 'malicious'), malicious.tx as never);
    const bec = fakeTx({ dlp: dlpRow('block') });
    await approver.approve(dlpEvent('suspicious', 'suspicious', 'suspicious'), bec.tx as never);
    for (const t of [failed, malicious, bec]) {
      expect(t.tx.dlpScanResult.findFirst).not.toHaveBeenCalled();
    }
    const text = await service.metrics();
    expect(text).toContain('delivery_approvals_skipped_total{reason="scan_failed",service="t"} 1');
    expect(text).toContain(
      'delivery_approvals_skipped_total{reason="malicious_verdict",service="t"} 1',
    );
    expect(text).toContain('delivery_approvals_skipped_total{reason="bec_verdict",service="t"} 1');
    expect(text).not.toContain('reason="dlp_action"');
  });

  it('commits the ledger row of a DLP hold (handled once, never approved)', async () => {
    const { tx, outbox } = fakeTx({ dlp: dlpRow('quarantine') });
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
    const held = dlpEvent('suspicious');
    expect(await f.handler!(held)).toBe('handled');
    expect(writer.ledger).toEqual([{ consumer: DEV_PASSTHROUGH_CONSUMER, eventId: held.eventId }]);
    expect(outbox).toHaveLength(0);
  });
});

describe('DevPassThroughApprover: risk recommendation (step 5.1 R17)', () => {
  const approverWith = (
    service = metricsService(),
    logger: Logger = createLogger({ service: 't', level: 'silent' }),
    riskHold = true,
  ) =>
    new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      logger,
      newMetrics(service),
      () => NOW,
      { riskHold },
    );

  it('decides on the recommendation, hard blocks and error rows (decision table)', () => {
    const row = (recommendedAction: string, extra: Record<string, unknown> = {}) => ({
      status: 'scored',
      level: 'high',
      recommendedAction,
      hardBlocks: [],
      ...extra,
    });
    expect(riskHoldDecision(null)).toBe('missing');
    expect(riskHoldAction(null)).toBe('missing');
    for (const action of ['deliver', 'tag']) {
      expect(riskHoldDecision(row(action)), action).toBe('approve');
    }
    for (const action of ['require_approval', 'quarantine', 'block']) {
      expect(riskHoldDecision(row(action)), action).toBe('held');
      expect(riskHoldAction(row(action)), action).toBe(action);
    }
    const hardBlock = row('tag', {
      hardBlocks: [{ id: 'hb.known_phishing', verdict: 'phishing', action: 'quarantine' }],
    });
    expect(riskHoldDecision(hardBlock)).toBe('held');
    expect(riskHoldAction(hardBlock)).toBe('hard_block');
    const error = row('quarantine', { status: 'error' });
    expect(riskHoldDecision(error)).toBe('held');
    expect(riskHoldAction(error)).toBe('error');
    expect(riskHoldDecision(row('deliver', { status: 'error' }))).toBe('held');
    // A malformed hard_blocks value is not a hard block; the action still decides.
    expect(riskHoldDecision(row('deliver', { hardBlocks: 'x' }))).toBe('approve');
  });

  it('approves deliver and tag, reading the revision-0 row of the round only', async () => {
    for (const action of ['deliver', 'tag']) {
      const t = fakeTx({ recipients: 1, risk: riskRow(action) });
      const result = await approverWith().approve(event, t.tx as never);
      expect(result.approvals, action).toHaveLength(1);
      expect(t.tx.messageRiskScore.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            scanId: 900n,
            receivedAt: new Date('2026-11-03T11:59:00.000Z'),
            messageId: 100n,
            organizationId: 7n,
            lifecycleRound: 0,
            revision: 0,
          },
        }),
      );
    }
    expect(transition).toHaveBeenCalledTimes(2);
  });

  it.each(['require_approval', 'quarantine', 'block'])(
    'holds a %s recommendation (counted, info log with ids, level and action only)',
    async (action) => {
      const service = metricsService();
      const info = vi.fn();
      const logger = { child: () => ({ info, warn: vi.fn() }) } as unknown as Logger;
      const t = fakeTx({ risk: riskRow(action) });
      expect(await approverWith(service, logger).approve(event, t.tx as never)).toEqual({
        approvals: [],
        recipients: 0,
      });
      expect(transition).not.toHaveBeenCalled();
      expect(t.outbox).toHaveLength(0);
      const text = await service.metrics();
      expect(text).toContain(
        'delivery_approvals_skipped_total{reason="risk_recommendation",service="t"} 1',
      );
      expect(text).toContain(`delivery_risk_holds_total{action="${action}",service="t"} 1`);
      const [fields] = info.mock.calls.at(-1)! as [Record<string, unknown>];
      expect(fields).toEqual({
        eventId: event.eventId,
        messageId: '100',
        scanId: '900',
        round: 0,
        riskLevel: 'high',
        riskAction: action,
      });
    },
  );

  it('holds a hard block and an error row; holds a missing row with a warning', async () => {
    const service = metricsService();
    const warn = vi.fn();
    const logger = { child: () => ({ info: vi.fn(), warn }) } as unknown as Logger;
    const approver = approverWith(service, logger);
    await approver.approve(
      event,
      fakeTx({
        risk: riskRow('tag', {
          hardBlocks: [{ id: 'hb.dmarc_reject', verdict: 'phishing', action: 'quarantine' }],
        }),
      }).tx as never,
    );
    await approver.approve(
      event,
      fakeTx({ risk: riskRow('quarantine', { status: 'error' }) }).tx as never,
    );
    const missing = fakeTx({ risk: null });
    expect(await approver.approve(event, missing.tx as never)).toEqual({
      approvals: [],
      recipients: 0,
    });
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ messageId: '100', scanId: '900' }),
      expect.stringContaining('fail-safe'),
    );
    expect(transition).not.toHaveBeenCalled();
    const text = await service.metrics();
    expect(text).toContain('delivery_risk_holds_total{action="hard_block",service="t"} 1');
    expect(text).toContain('delivery_risk_holds_total{action="error",service="t"} 1');
    expect(text).toContain('delivery_risk_holds_total{action="missing",service="t"} 1');
    expect(text).toContain(
      'delivery_approvals_skipped_total{reason="risk_recommendation",service="t"} 2',
    );
    expect(text).toContain('delivery_approvals_skipped_total{reason="risk_missing",service="t"} 1');
  });

  it.each([
    ['organization', { organizationId: 8n }],
    ['message', { messageId: 101n }],
    ['scan', { scanId: 901n }],
    ['round', { lifecycleRound: 1 }],
    ['revision', { revision: 1 }],
    ['receivedAt', { receivedAt: new Date('2026-11-03T11:59:00.001Z') }],
  ])('throws on a shifted read (%s): redelivered, nothing approved', async (_label, shift) => {
    const service = metricsService();
    const t = fakeTx({ risk: riskRow('deliver', shift) });
    await expect(approverWith(service).approve(event, t.tx as never)).rejects.toThrow(
      InconsistentRiskReadError,
    );
    expect(transition).not.toHaveBeenCalled();
    expect(t.outbox).toHaveLength(0);
    expect(await service.metrics()).toContain(
      'delivery_inconsistent_reads_total{read="risk_score",service="t"} 1',
    );
  });

  it('keeps the order: every 4.x hold keeps its reason and skips the risk read', async () => {
    const service = metricsService();
    const approver = approverWith(service);
    const dlpEvent = {
      ...event,
      payload: scannedPayload({
        verdict: 'suspicious',
        engines: [
          { engine: 'rspamd', required: true, outcome: 'clean', attempts: 1 },
          { engine: 'bec', required: true, outcome: 'suspicious', attempts: 1 },
          { engine: 'dlp', required: true, outcome: 'suspicious', attempts: 1 },
        ],
      }),
    };
    const cases = [
      { e: scanFailedEvent, t: fakeTx({ risk: riskRow('block') }) },
      {
        e: { ...event, payload: scannedPayload({ verdict: 'malicious' }) },
        t: fakeTx({ risk: riskRow('block') }),
      },
      { e: dlpEvent, t: fakeTx({ risk: riskRow('block') }) },
      {
        e: dlpEvent,
        t: fakeTx({ risk: riskRow('block'), bec: becRow('clean'), dlp: dlpRow('quarantine') }),
      },
    ];
    for (const { e, t } of cases) {
      await approver.approve(e, t.tx as never);
      expect(t.tx.messageRiskScore.findFirst).not.toHaveBeenCalled();
    }
    const text = await service.metrics();
    for (const reason of ['scan_failed', 'malicious_verdict', 'bec_verdict', 'dlp_action']) {
      expect(text).toContain(`delivery_approvals_skipped_total{reason="${reason}",service="t"} 1`);
    }
    expect(text).not.toContain('reason="risk_recommendation"');
    // After the 4.x checks pass (an AI-only BEC raise, a DLP alert), the risk row decides.
    const after = fakeTx({
      risk: riskRow('quarantine'),
      bec: becRow('clean'),
      dlp: dlpRow('alert'),
    });
    expect((await approver.approve(dlpEvent, after.tx as never)).approvals).toEqual([]);
    expect(after.tx.messageRiskScore.findFirst).toHaveBeenCalledTimes(1);
  });

  it('with DELIVERY_DEV_PASSTHROUGH_RISK_HOLD=false behaves as step 4.6 (no risk read)', async () => {
    const t = fakeTx({ recipients: 1, risk: riskRow('block') });
    const result = await approverWith(metricsService(), undefined, false).approve(
      event,
      t.tx as never,
    );
    expect(result.approvals).toHaveLength(1);
    expect(t.tx.messageRiskScore.findFirst).not.toHaveBeenCalled();
  });

  it('defaults to holding on risk when constructed without options', async () => {
    const t = fakeTx({ risk: riskRow('quarantine') });
    const approver = new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      createLogger({ service: 't', level: 'silent' }),
      newMetrics(),
    );
    expect((await approver.approve(event, t.tx as never)).approvals).toEqual([]);
  });
});

describe('DevPassThroughApprover: rewritten copy of the round (step 4.3 U11, U20)', () => {
  const REWRITE_KEY = 'org/7/rewrite/2026/11/03/100/r0-0190f0f0-0000-7000-8000-0000000000ff.eml';
  const rewriteRow = (overrides: Record<string, unknown> = {}) => ({
    messageId: 100n,
    receivedAt: new Date(event.payload.receivedAt),
    organizationId: 7n,
    lifecycleRound: 0,
    scanId: 900n,
    status: 'rewritten',
    objectKey: REWRITE_KEY,
    ...overrides,
  });
  const approverWith = (metrics = newMetrics()) =>
    new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      createLogger({ service: 't', level: 'silent' }),
      metrics,
      () => NOW,
    );

  it('approves the rewritten object of the round, read for (message, org, round, scan)', async () => {
    const { tx, outbox, events } = fakeTx({ rewrite: rewriteRow() });
    const result = await approverWith().approve(event, tx as never);
    expect(result.approvals).toHaveLength(1);
    expect(tx.urlRewrite.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          messageId: 100n,
          receivedAt: new Date(event.payload.receivedAt),
          organizationId: 7n,
          lifecycleRound: 0,
          scanId: 900n,
          status: 'rewritten',
        },
      }),
    );
    expect(deliveryApprovedV1.parse(outbox[0]!.data.payload).emlS3Key).toBe(REWRITE_KEY);
    expect(events).toHaveLength(1);
  });

  it('approves the original when the round has no rewritten copy (skipped or absent)', async () => {
    const { tx, outbox } = fakeTx({ rewrite: null });
    await approverWith().approve(event, tx as never);
    expect(deliveryApprovedV1.parse(outbox[0]!.data.payload).emlS3Key).toBe(
      'org/7/eml/2026/11/03/stored.eml',
    );
  });

  it.each([
    ['another organization prefix', 'org/8/rewrite/2026/11/03/100/r0-x.eml'],
    ['not a rewrite object', 'org/7/eml/2026/11/03/other.eml'],
    ['a dot-dot segment', 'org/7/rewrite/../eml/x.eml'],
    ['no key', null],
  ])('falls back to the original for %s', async (_label, objectKey) => {
    const { tx, outbox } = fakeTx({ rewrite: rewriteRow({ objectKey }) });
    await approverWith().approve(event, tx as never);
    expect(deliveryApprovedV1.parse(outbox[0]!.data.payload).emlS3Key).toBe(
      'org/7/eml/2026/11/03/stored.eml',
    );
  });

  it.each([
    ['message', { messageId: 101n }],
    ['organization', { organizationId: 8n }],
    ['round', { lifecycleRound: 1 }],
    ['scan', { scanId: 901n }],
    ['receivedAt', { receivedAt: new Date(0) }],
    ['status', { status: 'skipped' }],
  ])('throws (redelivered, nothing approved) on a shifted read: %s', async (_label, overrides) => {
    const service = metricsService();
    const { tx, outbox } = fakeTx({ rewrite: rewriteRow(overrides) });
    await expect(
      approverWith(newMetrics(service)).approve(event, tx as never),
    ).rejects.toBeInstanceOf(InconsistentRewriteReadError);
    expect(outbox).toHaveLength(0);
    expect(
      await service.registry.getSingleMetricAsString('delivery_inconsistent_reads_total'),
    ).toContain('read="url_rewrite"');
  });

  it('still holds malicious and skips scan_failed without reading the rewrite', async () => {
    const malicious = fakeTx({ rewrite: rewriteRow() });
    await approverWith().approve(
      { ...event, payload: scannedPayload({ verdict: 'malicious' }) },
      malicious.tx as never,
    );
    expect(malicious.outbox).toHaveLength(0);
    expect(malicious.tx.urlRewrite.findFirst).not.toHaveBeenCalled();
    const failed = fakeTx({ rewrite: rewriteRow() });
    await approverWith().approve(scanFailedEvent, failed.tx as never);
    expect(failed.outbox).toHaveLength(0);
    expect(failed.tx.urlRewrite.findFirst).not.toHaveBeenCalled();
  });

  it('isRewriteKeyOf accepts only org/<org>/rewrite/ keys without dot segments', () => {
    expect(isRewriteKeyOf(REWRITE_KEY, 7n)).toBe(true);
    expect(isRewriteKeyOf(REWRITE_KEY, 70n)).toBe(false);
    expect(isRewriteKeyOf('org/7/rewrite//x.eml', 7n)).toBe(false);
    expect(isRewriteKeyOf('org/7/rewriteX/x.eml', 7n)).toBe(false);
  });
});
