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
  /** Present when `LIFECYCLE_EXPIRY_ENABLED` (step 3.3 L13). */
  expiry?: Startable;
  /** Present when `LIFECYCLE_CHECK_ENABLED` (step 3.3 L14). */
  lifecycleCheck?: Startable;
  /** The dedicated lock connection (`AdvisoryLocks`). */
  locks: Closable;
  /** `ConfirmPublisher`, then `AmqpConnection`. */
  publisher: Closable;
  connection: Closable;
}

type Role = 'relay' | 'reconciler' | 'expiry' | 'lifecycleCheck';
type Step = Role | 'locks' | 'publisher' | 'connection';

const ROLES: readonly Role[] = ['relay', 'reconciler', 'expiry', 'lifecycleCheck'];

/**
 * Starts the enabled roles after the application bootstrapped and stops them in the order of
 * step 3.2 §WP3: relay loops (an in-flight batch finishes and is marked), reconciler, the step 3.3
 * lifecycle jobs (expiry sweeper, lifecycle check), lock connection, AMQP (publisher, then
 * connection); the database closes last (Nest's
 * `PrismaService` hook). Each step runs once; a failing step is logged and the next one runs.
 */
export class RelayLifecycle {
  private readonly started = new Set<Role>();
  private stopped = false;

  constructor(
    private readonly components: RelayComponents,
    private readonly logger: Logger,
  ) {}

  get startedRoles(): string[] {
    return [...this.started];
  }

  start(): void {
    for (const role of ROLES) {
      const component = this.components[role];
      if (!component) continue;
      component.start();
      this.started.add(role);
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
    for (const role of ROLES) {
      const component = c[role];
      await step(role, this.started.delete(role) && component ? () => component.stop() : undefined);
    }
    await step('locks', () => c.locks.close());
    await step('publisher', () => c.publisher.close());
    await step('connection', () => c.connection.close());
  }
}
