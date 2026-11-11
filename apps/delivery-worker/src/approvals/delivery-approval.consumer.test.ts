import type { EventHandler } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import {
  type DeliveryApprovedV1,
  type EventEnvelope,
  EventTypes,
} from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import { PLANNING_TX_TIMEOUT_MS } from '../delivery.module';
import type { DeliveryPlanner } from '../planning/delivery-planner';
import type { ApprovalFeed } from './approval-feed';
import { DeliveryApprovalConsumer, PLANNER_CONSUMER } from './delivery-approval.consumer';

const event: EventEnvelope<DeliveryApprovedV1> = {
  eventId: '0190f0f0-0000-7000-8000-000000000009',
  eventType: EventTypes.DeliveryApproved,
  occurredAt: '2026-11-03T12:00:00.000Z',
  correlationId: 'corr-12345678',
  organizationId: '7',
  payload: {
    messageId: '100',
    receivedAt: '2026-11-03T11:59:00.000Z',
    deliverySeq: 0,
    source: 'policy',
    emlS3Key: 'org/7/eml/2026/11/03/abc.eml',
    recipients: [{ recipientId: '500', rcptSeq: 0 }],
    approvedAt: '2026-11-03T12:00:00.000Z',
  },
};

/** The writer with a processOnce ledger that commits only when the handler succeeds. */
function fakeWriter() {
  const ledger = new Set<string>();
  const options: unknown[] = [];
  const prisma = {
    async $transaction(fn: (tx: unknown) => Promise<unknown>, opts?: unknown) {
      options.push(opts);
      const pending: string[] = [];
      const tx = {
        marker: 'tx',
        messageIdempotency: {
          create: ({ data }: { data: { consumer: string; eventId: string } }) => {
            const key = `${data.consumer}|${data.eventId}`;
            if (ledger.has(key)) {
              return Promise.reject(
                new Prisma.PrismaClientKnownRequestError('duplicate', {
                  code: 'P2002',
                  clientVersion: 'test',
                }),
              );
            }
            pending.push(key);
            return Promise.resolve(data);
          },
        },
      };
      const result = await fn(tx);
      for (const key of pending) ledger.add(key);
      return result;
    },
  };
  return { prisma: prisma as unknown as PrismaClient, ledger, options };
}

function capturingFeed() {
  const feed: ApprovalFeed<DeliveryApprovedV1> & { handler?: EventHandler<DeliveryApprovedV1> } = {
    start(handler) {
      feed.handler = handler;
    },
    stop: () => Promise.resolve(),
  };
  return feed;
}

describe('DeliveryApprovalConsumer (R5, R7)', () => {
  it('plans each approval once inside the planner idempotency transaction', async () => {
    const writer = fakeWriter();
    const feed = capturingFeed();
    const planned: { eventId: string; tx: unknown }[] = [];
    let fail = true;
    const planner = {
      plan: (e: EventEnvelope<DeliveryApprovedV1>, tx: { marker: string }) => {
        if (fail) return Promise.reject(new Error('writer down'));
        planned.push({ eventId: e.eventId, tx: tx.marker });
        return Promise.resolve({});
      },
    } as unknown as DeliveryPlanner;
    new DeliveryApprovalConsumer(feed, planner, writer.prisma, PLANNING_TX_TIMEOUT_MS).start();

    // A failing plan rolls back the ledger row: the feed retries the event.
    await expect(feed.handler!(event)).rejects.toThrow('writer down');
    expect(writer.ledger.size).toBe(0);
    fail = false;
    expect(await feed.handler!(event)).toBe('handled');
    expect(await feed.handler!(event)).toBe('duplicate');
    expect(planned).toEqual([{ eventId: event.eventId, tx: 'tx' }]);
    expect([...writer.ledger]).toEqual([`${PLANNER_CONSUMER}|${event.eventId}`]);
    expect(writer.options[0]).toEqual({
      timeout: PLANNING_TX_TIMEOUT_MS,
      maxWait: PLANNING_TX_TIMEOUT_MS,
    });
  });
});
