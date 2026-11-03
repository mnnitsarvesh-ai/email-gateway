import type { EventFeed, EventHandler } from './event-feed';
import { OutboxPoller, type OutboxPollerMetrics, type OutboxPollerOptions } from './outbox-poller';

export interface ShardedOutboxFeedOptions<T> extends Omit<OutboxPollerOptions<T>, 'shard'> {
  /** Number of shards `n` (>= 1): one poller per `MOD(id, n)` residue. */
  shards: number;
}

/**
 * One consumer's outbox stream split into `shards` pollers (step 3.1 M2): shard `i` reads the
 * rows with `MOD(id, shards) = i` under its own cursor `outbox:<consumer>#i/n` and lock
 * `<lockPrefix>:outbox:<consumer>#i/n`, all with the same handler. With `maxHeldLocks` each
 * replica runs at most that many shards, so several replicas share the stream; a shard whose
 * lock is held elsewhere idles. `shards = 1` is a single unsharded `OutboxPoller`.
 *
 * The lag reported for the consumer is the maximum over all shards: the ones this process runs,
 * and the others measured from their durable cursors (a shard no replica runs shows a growing
 * lag). Every shard needs a runner: replicas x maxHeldLocks >= shards.
 */
export class ShardedOutboxFeed<T> implements EventFeed<T> {
  readonly pollers: readonly OutboxPoller<T>[];

  constructor(options: ShardedOutboxFeedOptions<T>) {
    const { shards, ...pollerOptions } = options;
    if (!Number.isInteger(shards) || shards < 1) {
      throw new Error('ShardedOutboxFeed needs an integer shard count >= 1');
    }
    const lags = new Array<number>(shards).fill(0);
    this.pollers = Array.from({ length: shards }, (_, index) => {
      const metrics: OutboxPollerMetrics =
        shards === 1
          ? options.metrics
          : {
              pollLag: (consumer, seconds) => {
                lags[index] = seconds;
                options.metrics.pollLag(consumer, Math.max(...lags));
              },
              invalid: (consumer) => options.metrics.invalid(consumer),
            };
      return new OutboxPoller<T>({
        ...pollerOptions,
        metrics,
        shard: { index, count: shards },
      });
    });
  }

  start(handler: EventHandler<T>): void {
    for (const poller of this.pollers) poller.start(handler);
  }

  async stop(): Promise<void> {
    await Promise.all(this.pollers.map((poller) => poller.stop()));
  }
}
