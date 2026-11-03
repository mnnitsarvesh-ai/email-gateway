import type { Logger } from '@email-gateway/logger';
import { sleep } from '../shared/backoff';
import type { Reinjector } from './reinjector';
import type { ClaimScope, ClaimedReinjection, ReinjectionStore } from './reinjection-store';

export interface SchedulerConfig {
  DELIVERY_POLL_INTERVAL_MS: number;
  DELIVERY_REINJECT_CONCURRENCY: number;
  DELIVERY_REINJECT_LEASE_SECONDS: number;
}

/** In-flight sessions get this long to finish at shutdown before they are aborted. */
export const SHUTDOWN_GRACE_MS = 20_000;

interface InFlight {
  row: ClaimedReinjection;
  controller: AbortController;
  done: Promise<void>;
}

/**
 * Claims due reinjections and runs up to `DELIVERY_REINJECT_CONCURRENCY` sessions (step 2.3 R8).
 * Every `DELIVERY_POLL_INTERVAL_MS` it claims as many rows as there are free slots
 * (`FOR UPDATE SKIP LOCKED`, so replicas never claim the same row). While a session runs, its
 * lease is renewed every third of `DELIVERY_REINJECT_LEASE_SECONDS`, so the reconciler never
 * takes over a live session (a long DATA phase can exceed the lease); after an ambiguous end
 * the lease simply runs out and the reconciler resolves the row. A renewal that finds the claim
 * gone (the row was released or re-claimed) aborts the session; a renewal error only logs.
 *
 * Shutdown: no new claims; in-flight sessions get `SHUTDOWN_GRACE_MS` to finish, then they are
 * aborted (a session aborted before the final dot is released to `pending` at once; one after
 * the dot stays for the reconciler).
 */
export class ReinjectionScheduler {
  private readonly logger: Logger;
  private readonly inFlight = new Map<string, InFlight>();
  private timer: NodeJS.Timeout | undefined;
  private ticking: Promise<void> | undefined;
  private stopped = false;

  constructor(
    private readonly store: ReinjectionStore,
    private readonly reinjector: Reinjector,
    private readonly config: SchedulerConfig,
    logger: Logger,
    private readonly now: () => Date = () => new Date(),
    private readonly scope?: ClaimScope,
  ) {
    this.logger = logger.child({ component: 'reinjection-scheduler' });
  }

  get active(): number {
    return this.inFlight.size;
  }

  start(): void {
    this.stopped = false;
    this.schedule(0);
  }

  async stop(graceMs: number = SHUTDOWN_GRACE_MS): Promise<void> {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    await this.ticking;
    const pending = [...this.inFlight.values()];
    if (pending.length === 0) return;
    this.logger.info({ sessions: pending.length }, 'waiting for in-flight reinjections');
    const all = Promise.all(pending.map((s) => s.done));
    const graceful = await Promise.race([all.then(() => true), sleep(graceMs).then(() => false)]);
    if (!graceful) {
      for (const session of this.inFlight.values()) session.controller.abort();
      await all;
    }
  }

  /** One claim round (public for tests): claims and starts sessions; returns the claimed rows. */
  async tick(): Promise<ClaimedReinjection[]> {
    const free = this.config.DELIVERY_REINJECT_CONCURRENCY - this.inFlight.size;
    if (free <= 0 || this.stopped) return [];
    const rows = await this.store.claim(
      free,
      this.now(),
      this.config.DELIVERY_REINJECT_LEASE_SECONDS,
      this.scope,
    );
    for (const row of rows) this.launch(row);
    return rows;
  }

  /** Resolves when every session started so far has finished (tests). */
  async drain(): Promise<void> {
    while (this.inFlight.size > 0)
      await Promise.all([...this.inFlight.values()].map((s) => s.done));
  }

  private launch(row: ClaimedReinjection): void {
    const key = `${row.id.toString()}|${row.receivedAt.getTime()}`;
    const controller = new AbortController();
    const leaseMs = this.config.DELIVERY_REINJECT_LEASE_SECONDS * 1000;
    const renew = setInterval(
      () => {
        void this.store
          .renewLease(row, new Date(this.now().getTime() + leaseMs))
          .then((held) => {
            if (held || controller.signal.aborted) return;
            // The reconciler released the row (or another worker claimed it): stop the session
            // (before the final dot Postfix discards it; the result commit records nothing).
            this.logger.warn(
              { reinjectionId: row.id.toString() },
              'reinjection lease lost; session aborted',
            );
            controller.abort();
          })
          .catch((err: unknown) =>
            this.logger.warn({ err, reinjectionId: row.id.toString() }, 'lease renewal failed'),
          );
      },
      Math.max(1000, Math.floor(leaseMs / 3)),
    );
    renew.unref();
    const done = this.reinjector
      .process(row, controller.signal)
      .then(() => undefined)
      .catch((err: unknown) =>
        this.logger.error(
          { err, reinjectionId: row.id.toString() },
          'reinjection failed unexpectedly; the lease expires and the reconciler resolves it',
        ),
      )
      .finally(() => {
        clearInterval(renew);
        this.inFlight.delete(key);
      });
    this.inFlight.set(key, { row, controller, done });
  }

  private schedule(delayMs: number): void {
    if (this.stopped) return;
    this.timer = setTimeout(() => {
      this.ticking = this.tick()
        .then(() => undefined)
        .catch((err: unknown) => this.logger.warn({ err }, 'reinjection claim failed; retrying'))
        .finally(() => {
          this.ticking = undefined;
          this.schedule(this.config.DELIVERY_POLL_INTERVAL_MS);
        });
    }, delayMs);
    this.timer.unref();
  }
}
