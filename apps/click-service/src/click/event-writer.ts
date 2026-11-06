import type { Logger } from '@email-gateway/logger';
import type { ClickMetrics } from './click-metrics';
import type { ClickEventRecord, ClickRepository, OutboxRecord } from './click-repository';

/**
 * Bounded asynchronous click logging (U14 step 7): the response waits for the event write at
 * most CLICK_EVENT_WRITE_WAIT_MS; the write continues in the background. At most
 * CLICK_EVENT_MAX_PENDING writes are in flight per process; above that a new event is dropped
 * and counted (`click_events_total{result="dropped"}`) — logging never blocks a click.
 */
export class ClickEventWriter {
  private pending = 0;
  private readonly inFlight = new Set<Promise<void>>();

  constructor(
    private readonly repository: ClickRepository,
    private readonly metrics: ClickMetrics,
    private readonly logger: Logger,
    private readonly options: {
      waitMs: number;
      maxPending: number;
      txTimeoutMs: number;
      maxWaitMs: number;
    },
  ) {}

  get pendingCount(): number {
    return this.pending;
  }

  /** Starts the write; resolves when it finished or after `waitMs`, whichever comes first. */
  submit(event: ClickEventRecord, outbox: OutboxRecord): Promise<void> {
    if (this.pending >= this.options.maxPending) {
      this.metrics.event('dropped');
      this.logger.warn(
        { clickId: event.publicId, pending: this.pending },
        'click event dropped: too many pending writes',
      );
      return Promise.resolve();
    }
    this.pending += 1;
    this.metrics.setPending(this.pending);
    const write = this.repository
      .writeClick(event, outbox, {
        timeoutMs: this.options.txTimeoutMs,
        maxWaitMs: this.options.maxWaitMs,
      })
      .then(
        () => this.metrics.event('written'),
        (error: unknown) => {
          this.metrics.event('error');
          this.logger.error(
            {
              clickId: event.publicId,
              organizationId: event.organizationId.toString(),
              messageId: event.messageId.toString(),
              errName: error instanceof Error ? error.name : typeof error,
              errCode: (error as { code?: unknown } | null)?.code,
            },
            'click event write failed',
          );
        },
      )
      .finally(() => {
        this.pending -= 1;
        this.metrics.setPending(this.pending);
        this.inFlight.delete(write);
      });
    this.inFlight.add(write);
    if (this.options.waitMs <= 0) return Promise.resolve();
    let timer: NodeJS.Timeout | undefined;
    return Promise.race([
      write,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, this.options.waitMs);
      }),
    ]).finally(() => clearTimeout(timer));
  }

  /** Waits for in-flight writes (shutdown), at most `timeoutMs`. */
  async drain(timeoutMs: number): Promise<boolean> {
    if (this.inFlight.size === 0) return true;
    let timer: NodeJS.Timeout | undefined;
    const done = await Promise.race([
      Promise.allSettled([...this.inFlight]).then(() => true),
      new Promise<boolean>((resolve) => {
        timer = setTimeout(() => resolve(false), timeoutMs);
      }),
    ]);
    clearTimeout(timer);
    return done;
  }
}
