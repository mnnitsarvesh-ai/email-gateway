import { createLogger } from '@email-gateway/logger';
import { describe, expect, it, vi } from 'vitest';
import { DisabledBackend } from '../backends/disabled.backend';
import type { BackendSelfTest } from '../backends/backend';
import { BackendHealth } from '../health/backend-health';
import { NOOP_METRICS } from '../metrics/controller-metrics';
import { ControllerLifecycle, type ControllerRuntime } from '../app.module';
import type { ReaperService } from '../reaper/reaper.service';
import type { TaskHandler } from './task-handler';
import { TaskConsumer, type TaskSubscription } from './task-consumer';

const logger = createLogger({ service: 'task-consumer-test', level: 'silent' });

/**
 * A subscription double with the `QueueConsumer` semantics the pause relies on: after `stop()`
 * it takes no new delivery (a delivery offered then stays on the queue — modelled by `offer`
 * returning false), and `stop()` resolves only when the in-flight deliveries are settled.
 */
class FakeSubscription implements TaskSubscription {
  handler: TaskHandler['handle'] | null = null;
  starts = 0;
  stops = 0;
  private stopped = false;
  private readonly inFlight = new Set<Promise<unknown>>();

  start(handler: TaskHandler['handle']): void {
    this.starts += 1;
    this.handler = handler;
  }

  /** The broker offers a delivery: taken (true) or left queued (false; never nacked). */
  offer(settle: Promise<unknown>): boolean {
    if (this.stopped || this.handler === null) return false;
    const tracked = settle.finally(() => this.inFlight.delete(tracked));
    this.inFlight.add(tracked);
    return true;
  }

  async stop(): Promise<void> {
    this.stops += 1;
    this.stopped = true;
    await Promise.allSettled([...this.inFlight]);
  }
}

function consumerWithFakes() {
  const subscriptions: FakeSubscription[] = [];
  const handler = { handle: vi.fn(), inFlightCount: 0 } as unknown as TaskHandler;
  const consumer = new TaskConsumer({
    connection: {} as never,
    publisher: {} as never,
    metrics: null,
    handler,
    prefetch: 1,
    stopTimeoutMs: 1_000,
    logger,
    createSubscription: () => {
      const s = new FakeSubscription();
      subscriptions.push(s);
      return s;
    },
  });
  return { consumer, subscriptions, handler };
}

const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
};

describe('TaskConsumer pause / resume (X1, X7: no nack loop against a broken backend)', () => {
  it('resume subscribes exactly once, however often it is called', async () => {
    const { consumer, subscriptions, handler } = consumerWithFakes();
    await Promise.all([consumer.resume(), consumer.resume(), consumer.resume()]);
    expect(consumer.consuming).toBe(true);
    expect(subscriptions).toHaveLength(1);
    expect(subscriptions[0]!.starts).toBe(1);
    expect(subscriptions[0]!.handler).toBe(handler.handle);
  });

  it('pause while idle cancels the subscription; a repeated pause is a no-op', async () => {
    const { consumer, subscriptions } = consumerWithFakes();
    await consumer.resume();
    await consumer.pause();
    await consumer.pause();
    expect(consumer.consuming).toBe(false);
    expect(subscriptions).toHaveLength(1);
    expect(subscriptions[0]!.stops).toBe(1);
    // A delivery offered after the pause is not taken: it stays queued (not nacked).
    expect(subscriptions[0]!.offer(Promise.resolve())).toBe(false);
  });

  it('pause with a task in flight takes nothing new and resolves only when the task settles', async () => {
    const { consumer, subscriptions } = consumerWithFakes();
    await consumer.resume();
    const task = deferred();
    expect(subscriptions[0]!.offer(task.promise)).toBe(true);
    let paused = false;
    const pausing = consumer.pause().then(() => (paused = true));
    await new Promise((r) => setImmediate(r));
    expect(consumer.consuming).toBe(false);
    expect(paused).toBe(false);
    expect(subscriptions[0]!.offer(Promise.resolve())).toBe(false);
    task.resolve();
    await pausing;
    expect(paused).toBe(true);
    expect(subscriptions[0]!.stops).toBe(1);
  });

  it('resume after a pause subscribes a fresh consumer; the cancelled one is never restarted', async () => {
    const { consumer, subscriptions } = consumerWithFakes();
    await consumer.resume();
    await consumer.pause();
    await consumer.resume();
    expect(consumer.consuming).toBe(true);
    expect(subscriptions).toHaveLength(2);
    expect(subscriptions[0]!).toMatchObject({ starts: 1, stops: 1 });
    expect(subscriptions[1]!).toMatchObject({ starts: 1, stops: 0 });
    expect(subscriptions[1]!.offer(Promise.resolve())).toBe(true);
  });

  it('rapid flips are serialized: the last one wins, every replaced subscription stopped once', async () => {
    const { consumer, subscriptions } = consumerWithFakes();
    const flips = [
      consumer.resume(),
      consumer.pause(),
      consumer.pause(),
      consumer.resume(),
      consumer.resume(),
      consumer.pause(),
      consumer.resume(),
    ];
    await Promise.all(flips);
    expect(consumer.consuming).toBe(true);
    expect(subscriptions).toHaveLength(3);
    expect(subscriptions.map((s) => [s.starts, s.stops])).toEqual([
      [1, 1],
      [1, 1],
      [1, 0],
    ]);
  });

  it('after stop() a resume never subscribes again', async () => {
    const { consumer, subscriptions } = consumerWithFakes();
    await consumer.resume();
    await consumer.stop();
    await consumer.resume();
    expect(consumer.consuming).toBe(false);
    expect(subscriptions).toHaveLength(1);
    expect(subscriptions[0]!.stops).toBe(1);
  });
});

describe('ControllerLifecycle: the backend self-test drives the consumer (X1, X7)', () => {
  function lifecycle(initial: BackendSelfTest) {
    const backend = new DisabledBackend();
    let next: BackendSelfTest = initial;
    backend.selfTest = () => Promise.resolve(next);
    const health = new BackendHealth(backend, initial, NOOP_METRICS, logger, 3_600_000);
    const { consumer, subscriptions, handler } = consumerWithFakes();
    const reaper = {
      run: vi.fn(() => Promise.resolve({})),
      start: vi.fn(),
      stop: vi.fn(() => Promise.resolve()),
    } as unknown as ReaperService;
    const runtime = {
      backend: { close: vi.fn(() => Promise.resolve()) },
    } as unknown as ControllerRuntime;
    const shutdown = new AbortController();
    const life = new ControllerLifecycle(
      consumer,
      handler,
      reaper,
      health,
      runtime,
      shutdown,
      null,
      logger,
    );
    const selfTest = async (result: BackendSelfTest) => {
      next = result;
      await health.runSelfTest();
      // The listener schedules the transition; let it settle.
      await new Promise((r) => setImmediate(r));
    };
    return { life, consumer, subscriptions, health, shutdown, selfTest };
  }

  const OK: BackendSelfTest = { ok: true, code: 'ok', details: {} };
  const BROKEN: BackendSelfTest = { ok: false, code: 'self_test_failed', details: {} };

  it('a runtime self-test failure cancels the consumer; recovery resubscribes exactly once', async () => {
    const t = lifecycle(OK);
    await t.life.onApplicationBootstrap();
    expect(t.consumer.consuming).toBe(true);
    expect(t.subscriptions).toHaveLength(1);

    await t.selfTest(BROKEN);
    await vi.waitFor(() => expect(t.consumer.consuming).toBe(false));
    expect(t.subscriptions[0]!.stops).toBe(1);
    // While broken, a queued task is not taken (it stays on scan.sandbox, never nacked or
    // dead-lettered), and further failing self-tests change nothing.
    expect(t.subscriptions[0]!.offer(Promise.resolve())).toBe(false);
    await t.selfTest(BROKEN);
    expect(t.subscriptions).toHaveLength(1);
    await expect(t.health.checkHealth()).rejects.toThrow('sandbox backend not ready');

    await t.selfTest(OK);
    await vi.waitFor(() => expect(t.consumer.consuming).toBe(true));
    expect(t.subscriptions).toHaveLength(2);
    expect(t.subscriptions[1]!.offer(Promise.resolve())).toBe(true);
    // A passing self-test without a flip does not subscribe again.
    await t.selfTest(OK);
    expect(t.subscriptions).toHaveLength(2);
    expect(t.subscriptions[1]!.starts).toBe(1);
    await t.life.onModuleDestroy();
  });

  it('a backend not ready at startup stays unsubscribed until its self-test passes', async () => {
    const t = lifecycle(BROKEN);
    await t.life.onApplicationBootstrap();
    expect(t.consumer.consuming).toBe(false);
    expect(t.subscriptions).toHaveLength(0);
    await t.selfTest(OK);
    await vi.waitFor(() => expect(t.consumer.consuming).toBe(true));
    expect(t.subscriptions).toHaveLength(1);
    await t.life.onModuleDestroy();
  });

  it('after shutdown, readiness flips no longer touch the consumer', async () => {
    const t = lifecycle(OK);
    await t.life.onApplicationBootstrap();
    await t.life.onModuleDestroy();
    expect(t.consumer.consuming).toBe(false);
    expect(t.shutdown.signal.aborted).toBe(true);
    await t.selfTest(BROKEN);
    await t.selfTest(OK);
    expect(t.consumer.consuming).toBe(false);
    expect(t.subscriptions).toHaveLength(1);
  });
});
