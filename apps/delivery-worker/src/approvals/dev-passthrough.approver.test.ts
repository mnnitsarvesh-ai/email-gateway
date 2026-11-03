import {
  deliveryApprovedV1,
  EventTypes,
  type MessageReceivedV1,
  type EventEnvelope,
} from '@email-gateway/event-contracts';
import type { EventHandler } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import { createLogger, type Logger } from '@email-gateway/logger';
import { describe, expect, it, vi } from 'vitest';
import { RECORDER_TX_TIMEOUT_MS } from '../delivery.module';
import type { ApprovalFeed } from './approval-feed';
import {
  DEV_PASSTHROUGH_CONSUMER,
  DEV_PASSTHROUGH_WARNING,
  DevPassThroughApprover,
} from './dev-passthrough.approver';

const NOW = new Date('2026-11-03T12:00:00Z');
const event: EventEnvelope<MessageReceivedV1> = {
  eventId: '0190f0f0-0000-7000-8000-000000000001',
  eventType: EventTypes.MessageReceived,
  occurredAt: NOW.toISOString(),
  correlationId: 'corr-12345678',
  organizationId: '7',
  payload: {
    messageId: '100',
    receivedAt: '2026-11-03T11:59:00.000Z',
    direction: 'outbound',
    emlS3Key: 'org/7/eml/2026/11/03/abc.eml',
    sizeBytes: 10,
    envelopeFrom: 'a@x.test',
    recipientCount: 2,
  },
};

function fakeTx(options: { message?: boolean; recipients?: number }) {
  const outbox: { data: Record<string, unknown> }[] = [];
  const events: { data: Record<string, unknown> }[] = [];
  const tx = {
    emailMessage: {
      findFirst: vi.fn(() =>
        Promise.resolve(
          options.message === false ? null : { emlObjectKey: 'org/7/eml/2026/11/03/stored.eml' },
        ),
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

const feed = (): ApprovalFeed<MessageReceivedV1> & {
  started: number;
  handler?: EventHandler<MessageReceivedV1>;
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

describe('DevPassThroughApprover (R5, development only)', () => {
  it('writes one approval for every pending recipient, from the stored message row', async () => {
    const { tx, outbox, events } = fakeTx({});
    const approver = new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      createLogger({ service: 't', level: 'silent' }),
      () => NOW,
    );
    const result = await approver.approve(event, tx as never);
    expect(result.recipients).toBe(2);
    expect(result.approvals).toHaveLength(1);
    // Loaded with the envelope's organization; only pending recipients.
    expect(tx.emailMessage.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 100n, receivedAt: new Date(event.payload.receivedAt), organizationId: 7n },
      }),
    );
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
    const approver = new DevPassThroughApprover(
      feed(),
      noWriter,
      RECORDER_TX_TIMEOUT_MS,
      createLogger({ service: 't', level: 'silent' }),
      () => NOW,
    );
    const missing = fakeTx({ message: false });
    expect(await approver.approve(event, missing.tx as never)).toEqual({
      approvals: [],
      recipients: 0,
    });
    const none = fakeTx({ recipients: 0 });
    expect(await approver.approve(event, none.tx as never)).toEqual({
      approvals: [],
      recipients: 0,
    });
    expect(none.outbox).toHaveLength(0);
  });

  it('logs the startup warning when started', () => {
    const warn = vi.fn();
    const logger = { child: () => ({ warn, info: vi.fn() }) } as unknown as Logger;
    const f = feed();
    new DevPassThroughApprover(f, noWriter, RECORDER_TX_TIMEOUT_MS, logger).start();
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
      () => NOW,
    ).start();
    expect(await f.handler!(event)).toBe('handled');
    expect(writer.ledger).toEqual([{ consumer: DEV_PASSTHROUGH_CONSUMER, eventId: event.eventId }]);
    expect(writer.options).toEqual([
      { timeout: RECORDER_TX_TIMEOUT_MS, maxWait: RECORDER_TX_TIMEOUT_MS },
    ]);
    expect(outbox).toHaveLength(1);
  });
});
