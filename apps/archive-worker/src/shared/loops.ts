import { backoffDelay, sleep as defaultSleep } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import { errorFields } from './errors';

/** The subset of `AdvisoryLocks` the leader-elected jobs need (GET_LOCK on its own connection). */
export interface LeaderLock {
  ensure(name: string): Promise<boolean>;
  release(name: string): Promise<void>;
}

export type SleepFn = (ms: number, signal: AbortSignal) => Promise<boolean>;

/**
 * Runs `task` every `intervalMs` until stopped. When the task reports more work (`true`), the
 * next pass starts immediately; a failing pass is logged (class name and code only) and retried
 * with backoff. `stop()` waits for the pass in progress.
 */
export class Periodic {
  private abort = new AbortController();
  private loop: Promise<void> | undefined;
  private failures = 0;

  constructor(
    readonly name: string,
    private readonly intervalMs: number,
    private readonly task: () => Promise<boolean | void>,
    private readonly logger: Logger,
    private readonly sleep: SleepFn = defaultSleep,
  ) {
    // A missing or non-finite interval would make every idle pass a NaN sleep (≈ 1 ms): a busy
    // loop against MySQL. Refused at construction (step 8.1 WP6 fix).
    if (!Number.isFinite(intervalMs) || intervalMs <= 0) {
      throw new Error(`Periodic ${name}: intervalMs must be a positive finite number`);
    }
  }

  get running(): boolean {
    return this.loop !== undefined;
  }

  start(): void {
    if (this.loop) return;
    this.abort = new AbortController();
    this.loop = this.run(this.abort.signal);
  }

  async stop(): Promise<void> {
    this.abort.abort();
    await this.loop;
    this.loop = undefined;
  }

  private async run(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      let delay = this.intervalMs;
      try {
        const more = await this.task();
        this.failures = 0;
        if (more === true) delay = 0;
      } catch (error) {
        this.failures += 1;
        delay = Math.max(delay, backoffDelay(this.failures, { baseMs: 1_000, maxMs: 60_000 }));
        this.logger.warn(
          { task: this.name, ...errorFields(error) },
          'archive task failed; retried',
        );
      }
      if (delay === 0) {
        if (signal.aborted) break;
        await new Promise((resolve) => setImmediate(resolve));
        continue;
      }
      if (!(await this.sleep(delay, signal))) break;
    }
  }
}

/**
 * A leader-elected periodic job: each pass first re-checks (or acquires) `GET_LOCK(lockName)`
 * on the dedicated lock connection; only the holder runs the task. Releases the lock on stop.
 */
export class LeaderJob {
  private readonly periodic: Periodic;
  private leader = false;

  constructor(
    readonly name: string,
    readonly lockName: string,
    intervalMs: number,
    private readonly task: () => Promise<boolean | void>,
    private readonly options: {
      locks: LeaderLock;
      logger: Logger;
      onLeadership?: (leader: boolean) => void;
      sleep?: SleepFn;
    },
  ) {
    this.periodic = new Periodic(
      name,
      intervalMs,
      async () => (await this.runOnce()) === true,
      options.logger,
      options.sleep,
    );
  }

  get running(): boolean {
    return this.periodic.running;
  }

  get isLeader(): boolean {
    return this.leader;
  }

  start(): void {
    this.periodic.start();
  }

  async stop(): Promise<void> {
    await this.periodic.stop();
    await this.options.locks.release(this.lockName).catch(() => undefined);
    this.setLeader(false);
  }

  /** One pass: `not_leader` when another replica holds the lock. */
  async runOnce(): Promise<boolean | 'not_leader'> {
    let leader: boolean;
    try {
      leader = await this.options.locks.ensure(this.lockName);
    } catch (error) {
      this.setLeader(false);
      throw error;
    }
    this.setLeader(leader);
    if (!leader) return 'not_leader';
    return (await this.task()) === true;
  }

  private setLeader(leader: boolean): void {
    if (leader !== this.leader) this.options.onLeadership?.(leader);
    this.leader = leader;
  }
}

/** Runs `fn` over `items` with at most `concurrency` in flight; results in input order. */
export async function mapLimit<T, R>(
  items: readonly T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const i = next;
      next += 1;
      if (i >= items.length) return;
      results[i] = await fn(items[i]!, i);
    }
  };
  await Promise.all(
    Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, () => worker()),
  );
  return results;
}
