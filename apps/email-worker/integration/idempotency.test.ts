import type { HandleOutcome } from '@email-gateway/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Fixtures, type MessageFixture } from './support/fixtures';
import { multipartMessage } from './support/messages';
import { Broker, MimePipeline, withPipeline } from './support/pipeline';

let fx: Fixtures;
let org: bigint;
let broker: Broker;

beforeAll(async () => {
  fx = new Fixtures();
  org = await fx.organization('idem');
  broker = await Broker.start();
});

afterAll(async () => {
  await broker?.close();
  await fx?.cleanup();
});

const eml = () =>
  multipartMessage({
    attachments: [
      { filename: 'a.pdf', contentType: 'application/pdf', bytes: Buffer.from('%PDF-1.4 a') },
    ],
  });

/** What must not change on a duplicate (M12): rows, the one event, the one outbox row, objects. */
async function snapshot(message: MessageFixture) {
  const state = await fx.state(message);
  return {
    parses: state.parses.map((p) => ({ id: p.id, status: p.status, completedAt: p.completedAt })),
    headers: state.headers.map((h) => ({ id: h.id, seq: h.seq, name: h.name, value: h.value })),
    attachments: state.attachments.map((a) => ({
      id: a.id,
      partIndex: a.partIndex,
      sha256: a.sha256,
      objectKey: a.objectKey,
    })),
    events: state.events.map((e) => ({ id: e.id, eventType: e.eventType })),
    outbox: state.outbox.map((o) => o.eventId),
    objects: state.objects,
  };
}

function expectSingleParse(snap: Awaited<ReturnType<typeof snapshot>>) {
  expect(snap.parses).toHaveLength(1);
  expect(snap.parses[0]!.status).toBe('parsed');
  expect(snap.events).toEqual([expect.objectContaining({ eventType: 'parsed' })]);
  expect(snap.outbox).toHaveLength(1);
  expect(snap.headers.length).toBeGreaterThan(0);
  expect(snap.attachments).toHaveLength(1);
  expect(snap.objects).toHaveLength(3);
}

describe('duplicate delivery through RabbitMQ (design M12, step 3.2 Q13)', () => {
  it('the same event twice: one parse, then duplicate with nothing changed', async () => {
    const message = await fx.message(org, { eml: eml() });
    const event = fx.received(message);

    await withPipeline(fx, broker, {}, async (p) => {
      await expect(p.deliver(broker, event)).resolves.toBe('handled');
      const first = await snapshot(message);
      expectSingleParse(first);
      // The same envelope again (a relay retry or a redelivery): a ledger duplicate.
      await broker.publish([event]);
      await p.outcome(event.eventId, 2);
      expect(p.outcomes(event.eventId)).toEqual(['handled', 'duplicate']);
      expect(await snapshot(message)).toEqual(first);
      expect(await fx.ledgerRows(p.service.consumer, [event.eventId])).toBe(1);
    });
  });

  it('the same envelope delivered twice at once (prefetch 4): exactly one effect', async () => {
    const message = await fx.message(org, { eml: eml() });
    const event = fx.received(message);

    await withPipeline(fx, broker, { overrides: { MIME_CONCURRENCY: '4' } }, async (p) => {
      await broker.publish([event, event]);
      await p.outcome(event.eventId, 2);
      expect([...p.outcomes(event.eventId)].sort()).toEqual(['duplicate', 'handled']);
      const snap = await snapshot(message);
      expectSingleParse(snap);
      expect(await fx.ledgerRows(p.service.consumer, [event.eventId])).toBe(1);
      // A second round of both changes nothing either.
      await broker.publish([event, event]);
      await p.outcome(event.eventId, 4);
      expect(p.outcomes(event.eventId).slice(2)).toEqual(['duplicate', 'duplicate']);
      expect(await snapshot(message)).toEqual(snap);
    });
    expect(await broker.depth('email.received')).toBe(0);
    expect(await broker.depth('email.dead-letter')).toBe(0);
  });

  it('two competing consumers on the same message with different events: one wins', async () => {
    const message = await fx.message(org, { eml: eml() });
    const consumer = fx.consumer('race');
    const a = await MimePipeline.start(fx, broker, { consumer });
    const b = await MimePipeline.start(fx, broker, { consumer });
    try {
      const events = [fx.received(message), fx.received(message)];
      await broker.publish(events);
      const outcomes: HandleOutcome[] = [];
      for (const event of events) {
        const deadline = Date.now() + 60_000;
        while (a.outcomes(event.eventId).length + b.outcomes(event.eventId).length < 1) {
          if (Date.now() > deadline) throw new Error('event not handled');
          await new Promise((r) => setTimeout(r, 50));
        }
        outcomes.push(...a.outcomes(event.eventId), ...b.outcomes(event.eventId));
      }
      expect([...outcomes].sort()).toEqual(['duplicate', 'handled']);
      expectSingleParse(await snapshot(message));
    } finally {
      await a.stop();
      await b.stop();
    }
  });

  it('a second event id for the same message: duplicate (final parse row)', async () => {
    const message = await fx.message(org, { eml: eml() });
    await withPipeline(fx, broker, {}, async (p) => {
      await p.deliver(broker, fx.received(message));
      const first = await snapshot(message);

      const second = fx.received(message);
      await expect(p.deliver(broker, second)).resolves.toBe('duplicate');
      expect(await snapshot(message)).toEqual(first);
      // Recorded in the ledger, so a later redelivery stops at the pre-check.
      expect(
        await fx.prisma.messageIdempotency.count({
          where: { consumer: p.service.consumer, eventId: second.eventId },
        }),
      ).toBe(1);
    });
  });

  it('a redelivery to a fresh consumer (new connection and process state): no effect', async () => {
    const consumer = fx.consumer('reread');
    const message = await fx.message(org, { eml: eml() });
    const event = fx.received(message);
    await withPipeline(fx, broker, { consumer }, (p) => p.deliver(broker, event));
    const snap = await snapshot(message);
    expectSingleParse(snap);

    await expect(
      withPipeline(fx, broker, { consumer }, (p) => p.deliver(broker, event)),
    ).resolves.toBe('duplicate');
    expect(await snapshot(message)).toEqual(snap);
    expect(await fx.ledgerRows(consumer, [event.eventId])).toBe(1);
  });
});
