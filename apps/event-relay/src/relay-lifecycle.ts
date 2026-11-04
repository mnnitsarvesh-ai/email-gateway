import type { Logger } from '@email-gateway/logger';

/** Something that runs in the background and stops gracefully. */
export interface Startable {
  start(): void;
  stop(): Promise<void>;
}

export interface Closable {
  close(): Promise<void>;
}

export interface RelayComponents {
  /** Present when `RELAY_ENABLED`. */
  relay?: Startable;
  /** Present when `RECONCILE_ENABLED`. */
  reconciler?: Startable;
  /** The dedicated lock connection (`AdvisoryLocks`). */
  locks: Closable;
  /** `ConfirmPublisher`, then `AmqpConnection`. */
  publisher: Closable;
  connection: Closable;
}

type Step = 'relay' | 'reconciler' | 'locks' | 'publisher' | 'connection';

/**
 * Starts the enabled roles after the application bootstrapped and stops them in the order of
 * step 3.2 §WP3: relay loops (an in-flight batch finishes and is marked), reconciler, lock
 * connection, AMQP (publisher, then connection); the database closes last (Nest's
 * `PrismaService` hook). Each step runs once; a failing step is logged and the next one runs.
 */
export class RelayLifecycle {
  private readonly started = new Set<'relay' | 'reconciler'>();
  private stopped = false;

  constructor(
    private readonly components: RelayComponents,
    private readonly logger: Logger,
  ) {}

  get startedRoles(): string[] {
    return [...this.started];
  }

  start(): void {
    if (this.components.relay) {
      this.components.relay.start();
      this.started.add('relay');
    }
    if (this.components.reconciler) {
      this.components.reconciler.start();
      this.started.add('reconciler');
    }
    this.logger.info({ roles: this.startedRoles }, 'event-relay roles started');
  }

  async stop(): Promise<void> {
    if (this.stopped) return;
    this.stopped = true;
    const c = this.components;
    const step = async (name: Step, fn: (() => Promise<void>) | undefined): Promise<void> => {
      if (!fn) return;
      try {
        await fn();
      } catch (err) {
        this.logger.warn(
          { step: name, errName: err instanceof Error ? err.name : typeof err },
          'shutdown step failed',
        );
      }
    };
    await step('relay', this.started.delete('relay') ? () => c.relay!.stop() : undefined);
    await step(
      'reconciler',
      this.started.delete('reconciler') ? () => c.reconciler!.stop() : undefined,
    );
    await step('locks', () => c.locks.close());
    await step('publisher', () => c.publisher.close());
    await step('connection', () => c.connection.close());
  }
}
