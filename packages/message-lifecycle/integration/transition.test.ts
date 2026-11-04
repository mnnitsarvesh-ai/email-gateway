import { randomUUID } from 'node:crypto';
import { EventTypes, messageStateChangedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  applyDerivedDeliveryState,
  lockLifecycle,
  transitionKeyHash,
  transitionMessage,
  transitionMessageWithRetry,
  type LifecycleMetrics,
  type TransitionRequest,
} from '../src';
import { Fixtures, type MessageFixture } from './support/fixtures';

/** §9 items 7 and 10 against the real MySQL writer. */

const fx = new Fixtures();
const prisma = fx.prisma;
let org: bigint;
let otherOrg: bigint;
const TX = { timeoutMs: 15_000 };

beforeAll(async () => {
  org = await fx.organization('tr');
  otherOrg = await fx.organization('tr-other');
});
afterAll(async () => {
  await fx.cleanup();
});

const devPassThrough = (m: MessageFixture, eventId = randomUUID()): TransitionRequest => ({
  message: m,
  to: 'approved',
  reason: 'dev_passthrough',
  actor: { role: 'dev_passthrough', service: 'delivery-worker', type: 'system' },
  transitionKey: `evt:${eventId}:approved`,
  causationEventId: eventId,
  correlationId: `it-corr-${eventId.slice(0, 8)}`,
  expectedRound: 0,
  expectedFrom: ['persisted'],
});

function recordingMetrics() {
  const calls: string[] = [];
  const metrics: LifecycleMetrics = {
    transition: (from, to, result) => calls.push(`${from}>${to}:${result}`),
    ignored: (reason) => calls.push(`ignored:${reason}`),
    versionConflict: () => calls.push('conflict'),
    derivedSkipped: (state) => calls.push(`skipped:${state}`),
  };
  return { metrics, calls };
}

describe('transitionMessage: an applied transition (§9 item 7)', () => {
  it('writes the row, one history row with every column, one event and one outbox row', async () => {
    const m = await fx.message(org);
    const eventId = randomUUID();
    const occurredAt = new Date(Date.now() - 5000);
    const { metrics, calls } = recordingMetrics();
    const before = Date.now();
    const outcome = await prisma.$transaction((tx) =>
      transitionMessage(tx, { ...devPassThrough(m, eventId), occurredAt }, { metrics }),
    );
    expect(outcome).toMatchObject({
      result: 'applied',
      from: 'persisted',
      to: 'approved',
      version: 2,
      round: 0,
    });
    if (outcome.result !== 'applied') throw new Error('not applied');
    expect(calls).toEqual(['persisted>approved:applied']);

    const row = await fx.row(m);
    expect(row).toMatchObject({
      status: 'approved',
      version: 2,
      lifecycleRound: 0,
      statusReason: 'dev_passthrough',
    });
    expect(row.statusChangedAt.getTime()).toBeGreaterThanOrEqual(before - 1000);

    const history = await fx.history(m);
    expect(history.map((h) => h.version)).toEqual([0, 1, 2]);
    const h = history[2]!;
    expect(h).toMatchObject({
      id: outcome.historyId,
      organizationId: org,
      fromStatus: 'persisted',
      toStatus: 'approved',
      reasonCode: 'dev_passthrough',
      lifecycleRound: 0,
      actorRole: 'dev_passthrough',
      actorService: 'delivery-worker',
      actorType: 'system',
      actorId: null,
      eventId,
      correlationId: `it-corr-${eventId.slice(0, 8)}`,
      transitionKey: transitionKeyHash(`evt:${eventId}:approved`),
      stateEventId: outcome.stateEventId,
      occurredAt,
    });
    expect(h.changedAt.getTime()).toBe(row.statusChangedAt.getTime());

    const events = await fx.events(m);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      eventType: 'lifecycle.approved',
      sourceService: 'delivery-worker',
      eventId,
      actorType: 'system',
      actorId: null,
      details: {
        from: 'persisted',
        to: 'approved',
        version: 2,
        round: 0,
        reason: 'dev_passthrough',
        actorRole: 'dev_passthrough',
      },
    });
    expect(events[0]!.occurredAt.getTime()).toBe(h.changedAt.getTime());

    const outbox = await fx.outbox(m);
    expect(outbox).toHaveLength(1);
    expect(outbox[0]).toMatchObject({
      eventId: outcome.stateEventId,
      eventType: EventTypes.MessageStateChanged,
      aggregateType: 'message',
      aggregateId: m.id.toString(),
      correlationId: `it-corr-${eventId.slice(0, 8)}`,
      publishedAt: null,
    });
    const payload = messageStateChangedV1.parse(outbox[0]!.payload);
    expect(payload).toEqual({
      messageId: m.id.toString(),
      receivedAt: m.receivedAt.toISOString(),
      direction: 'outbound',
      previousState: 'persisted',
      state: 'approved',
      version: 2,
      lifecycleRound: 0,
      reasonCode: 'dev_passthrough',
      actorRole: 'dev_passthrough',
      actorType: 'system',
      actorService: 'delivery-worker',
      causationEventId: eventId,
      changedAt: h.changedAt.toISOString(),
    });
  });

  it('defaults the outbox correlation id to message:<id> and records an operator actor id', async () => {
    const m = await fx.message(org, { state: 'quarantined' });
    const outcome = await transitionMessageWithRetry(
      prisma,
      {
        message: m,
        to: 'approved',
        reason: 'quarantine_release',
        actor: { role: 'operator', service: 'api', type: 'user', id: randomUUID() },
        transitionKey: `api:${org.toString()}:release:${randomUUID()}`,
        expectedVersion: 2,
        expectedFrom: ['quarantined', 'held_for_review'],
        recordIgnored: false,
      },
      TX,
    );
    expect(outcome).toMatchObject({ result: 'applied', version: 3, round: 1 });
    const [h] = (await fx.history(m)).slice(-1);
    expect(h).toMatchObject({ actorType: 'user', correlationId: null, lifecycleRound: 1 });
    expect(h!.actorId).toMatch(/^[0-9a-f-]{36}$/);
    const [o] = await fx.outbox(m);
    expect(o!.correlationId).toBe(`message:${m.id.toString()}`);
    expect(messageStateChangedV1.parse(o!.payload)).toMatchObject({
      actorType: 'user',
      causationEventId: null,
      lifecycleRound: 1,
    });
    // No actor id in the event.
    expect(JSON.stringify(o!.payload)).not.toContain(h!.actorId!);
  });

  it('is not_found for another organization and for an unknown row (nothing written)', async () => {
    const m = await fx.message(org);
    const foreign = { ...m, organizationId: otherOrg };
    const outcome = await transitionMessageWithRetry(prisma, devPassThrough(foreign), TX);
    expect(outcome).toEqual({ result: 'not_found' });
    const unknown = { ...m, id: m.id + 1_000_000_000n };
    expect(await transitionMessageWithRetry(prisma, devPassThrough(unknown), TX)).toEqual({
      result: 'not_found',
    });
    expect((await fx.row(m)).version).toBe(1);
    expect(await fx.events(m)).toHaveLength(0);
    expect(await prisma.$transaction((tx) => lockLifecycle(tx, foreign))).toBeNull();
  });

  it('answers duplicate/transition_key for the same key (metric only, nothing written)', async () => {
    const m = await fx.message(org);
    const request = devPassThrough(m);
    await transitionMessageWithRetry(prisma, request, TX);
    const { metrics, calls } = recordingMetrics();
    const again = await transitionMessageWithRetry(prisma, request, TX, { metrics });
    expect(again).toMatchObject({ result: 'duplicate', why: 'transition_key' });
    expect(calls).toEqual(['approved>approved:duplicate']);
    expect(await fx.history(m)).toHaveLength(3);
    expect(await fx.events(m)).toHaveLength(1);
    expect(await fx.outbox(m)).toHaveLength(1);
  });
});

describe('ignored transitions (§9 item 10, L6)', () => {
  it('a stale request writes exactly one lifecycle.ignored row and counts it', async () => {
    const m = await fx.message(org, { state: 'delivered', recipients: ['delivered'] });
    const eventId = randomUUID();
    const { metrics, calls } = recordingMetrics();
    const outcome = await transitionMessageWithRetry(
      prisma,
      {
        message: m,
        to: 'delivery_retry',
        reason: 'delivery_deferred',
        actor: { role: 'delivery', service: 'delivery-worker', type: 'system' },
        transitionKey: `signal:1:${eventId}:delivery_retry`,
        causationEventId: eventId,
      },
      TX,
      { metrics },
    );
    expect(outcome).toMatchObject({ result: 'stale', why: 'final_state' });
    expect(calls).toEqual(['delivered>delivery_retry:stale', 'ignored:final_state']);
    const events = await fx.events(m);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      eventType: 'lifecycle.ignored',
      sourceService: 'delivery-worker',
      eventId,
      details: {
        requested: 'delivery_retry',
        current: 'delivered',
        result: 'stale',
        why: 'final_state',
        version: 2,
        round: 0,
        expectedRound: null,
        expectedVersion: null,
        reason: 'delivery_deferred',
        actorRole: 'delivery',
      },
    });
    expect(await fx.history(m)).toHaveLength(3);
    expect(await fx.outbox(m)).toHaveLength(0);
    expect((await fx.row(m)).version).toBe(2);
  });

  it('an invalid request is recorded too, and recordIgnored: false writes nothing', async () => {
    const m = await fx.message(org);
    const invalid: TransitionRequest = {
      message: m,
      to: 'delivery_pending',
      reason: 'delivery_planned',
      actor: { role: 'delivery', service: 'delivery-worker', type: 'system' },
      transitionKey: `evt:${randomUUID()}:delivery_pending`,
      expectedRound: 0,
      expectedFrom: ['approved'],
    };
    const warnings: Record<string, unknown>[] = [];
    const logger = { warn: (details: Record<string, unknown>) => void warnings.push(details) };
    expect(await transitionMessageWithRetry(prisma, invalid, TX, { logger })).toMatchObject({
      result: 'invalid',
      why: 'unexpected_from',
    });
    expect(warnings).toHaveLength(1);
    expect(Object.keys(warnings[0]!).sort()).toEqual(
      [
        'actorRole',
        'actorService',
        'causationEventId',
        'from',
        'messageId',
        'organizationId',
        'result',
        'round',
        'to',
        'version',
        'why',
      ].sort(),
    );
    expect(await fx.events(m, 'lifecycle.ignored')).toHaveLength(1);

    const quiet = await transitionMessageWithRetry(
      prisma,
      { ...invalid, transitionKey: `evt:${randomUUID()}:x`, recordIgnored: false },
      TX,
    );
    expect(quiet).toMatchObject({ result: 'invalid', why: 'unexpected_from' });
    expect(await fx.events(m, 'lifecycle.ignored')).toHaveLength(1);
  });

  it('a duplicate/same_state only counts (no event row)', async () => {
    const m = await fx.message(org, { state: 'approved' });
    expect(await transitionMessageWithRetry(prisma, devPassThrough(m), TX)).toMatchObject({
      result: 'duplicate',
      why: 'same_state',
    });
    expect(await fx.events(m)).toHaveLength(0);
  });
});

describe('applyDerivedDeliveryState (L9)', () => {
  const recovery = { role: 'recovery', service: 'event-relay', type: 'system' } as const;

  it('derives from the recipients under the lock and transitions with the caller key', async () => {
    const m = await fx.message(org, {
      state: 'delivery_pending',
      recipients: ['delivered', 'bounced', 'quarantined'],
    });
    const outcome = await prisma.$transaction(async (tx) => {
      await lockLifecycle(tx, m);
      return applyDerivedDeliveryState(tx, m, {
        actor: recovery,
        transitionKey: (d, s) => `recover:${m.id.toString()}:${s.version}:${d.state}`,
      });
    });
    expect(outcome).toMatchObject({
      result: 'transition',
      derived: { state: 'delivered', reason: 'delivery_partial' },
      outcome: { result: 'applied', from: 'delivery_pending', to: 'delivered', version: 3 },
    });
    const [h] = (await fx.history(m)).slice(-1);
    expect(h).toMatchObject({
      actorRole: 'recovery',
      reasonCode: 'delivery_partial',
      transitionKey: transitionKeyHash(`recover:${m.id.toString()}:2:delivered`),
    });
  });

  it('is unchanged when the derived state is current and skipped outside the delivery phase', async () => {
    const { metrics, calls } = recordingMetrics();
    const pending = await fx.message(org, { state: 'delivery_pending', recipients: ['pending'] });
    const key = () => 'unused';
    expect(
      await prisma.$transaction((tx) =>
        applyDerivedDeliveryState(
          tx,
          pending,
          { actor: recovery, transitionKey: key },
          { metrics },
        ),
      ),
    ).toMatchObject({ result: 'unchanged', derived: { state: 'delivery_pending' } });
    const expired = await fx.message(org, { state: 'expired', recipients: ['delivered'] });
    expect(
      await prisma.$transaction((tx) =>
        applyDerivedDeliveryState(
          tx,
          expired,
          { actor: recovery, transitionKey: key },
          { metrics },
        ),
      ),
    ).toMatchObject({ result: 'skipped', state: 'expired' });
    expect(calls).toEqual(['skipped:expired']);
    expect(await fx.events(expired)).toHaveLength(0);
    expect(await fx.history(pending)).toHaveLength(3);
  });
});
