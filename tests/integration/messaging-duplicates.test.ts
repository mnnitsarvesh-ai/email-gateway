import { EventTypes } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { waitFor } from './support/compose';
import { sinkFiles } from './support/mail-sink';
import { MessagingScenario } from './support/messaging-scenario';
import {
  envelopeOfRow,
  messagingStackGate,
  pipelineCounts,
  QUEUES,
  record,
  sleep,
  waitForPipeline,
} from './support/messaging-stack';
import { metricValue } from './support/metrics';
import { sendInbound } from './support/routing';
import { SmtpFixtures } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';

/**
 * Duplicate events through the live stack (docs/plan/steps/07-rabbitmq.md §10 "Duplicate
 * event", WP5): one message goes the whole way (parsed, approved, planned, delivered); then the
 * administrator publishes EXACT copies of its real `mail.message.received.v1` and
 * `mail.delivery.approved.v1` events (the envelope the relay built from the outbox rows, same
 * event id, routing key and headers) twice. The consumers record ledger duplicates
 * (`amqp_consumer_messages_total{outcome="duplicate"}`) and nothing else changes: no second
 * parse, approval, delivery, reinjection, outbox row or sink file; no dead letter.
 */
const gate = await messagingStackGate();
const fx = new SmtpFixtures();
const scenario = new MessagingScenario('messaging-duplicates', fx);

const duplicates = (service: 'email-worker' | 'delivery-worker', queue: string) =>
  metricValue(service, 'amqp_consumer_messages_total', { queue, outcome: 'duplicate' });

beforeAll(async () => {
  assertStackReady(gate);
  await scenario.setup('mq-dup');
}, 120_000);

afterAll(async () => {
  if (!gate.skip) await scenario.teardown();
}, 300_000);

describe.skipIf(gate.skip)('messaging stack: duplicate events', { timeout: 600_000 }, () => {
  it('an exact copy of a real received event and approval has no second effect', async () => {
    await sendInbound({
      from: 'dup-sender@example.org',
      to: [scenario.recipient],
      subject: 'Messaging duplicates',
    });
    await waitForPipeline(fx.prisma, [scenario.org], 1, 400_000);
    const before = await pipelineCounts(fx.prisma, [scenario.org]);
    const rows = await fx.prisma.messageOutbox.findMany({
      where: {
        organizationId: scenario.org,
        eventType: { in: [EventTypes.MessageReceived, EventTypes.DeliveryApproved] },
      },
      orderBy: { id: 'asc' },
    });
    expect(rows.map((r) => r.eventType)).toEqual([
      EventTypes.MessageReceived,
      EventTypes.DeliveryApproved,
    ]);
    expect(rows.every((r) => r.publishedAt !== null)).toBe(true);
    const copies = rows.map(envelopeOfRow);

    const deadLetters = await scenario.broker.depth(QUEUES.deadLetter);
    const mimeBefore = await duplicates('email-worker', QUEUES.received);
    const plannerBefore = await duplicates('delivery-worker', QUEUES.pending);

    // Twice: a redelivery-like copy and a relay-retry-like copy.
    await scenario.broker.publish(copies);
    await scenario.broker.publish(copies);

    await waitFor(
      'two ledger duplicates in each consumer',
      async () =>
        (await duplicates('email-worker', QUEUES.received)) >= mimeBefore + 2 &&
        (await duplicates('delivery-worker', QUEUES.pending)) >= plannerBefore + 2,
      { timeoutMs: 60_000, intervalMs: 500 },
    );
    await sleep(3_000);
    const after = await pipelineCounts(fx.prisma, [scenario.org]);
    expect(after).toEqual(before);
    expect(await scenario.broker.depth(QUEUES.deadLetter)).toBe(deadLetters);
    expect(await scenario.broker.depth(QUEUES.received)).toBe(0);
    expect(await scenario.broker.depth(QUEUES.pending)).toBe(0);
    expect(await sinkFiles(scenario.recipient)).toHaveLength(1);
    record('messaging-duplicates', {
      copies_published: 4,
      mime_duplicates: (await duplicates('email-worker', QUEUES.received)) - mimeBefore,
      planner_duplicates: (await duplicates('delivery-worker', QUEUES.pending)) - plannerBefore,
      second_effects: 0,
    });
  });
});
