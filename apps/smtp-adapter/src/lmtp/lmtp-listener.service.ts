import type { OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import type { HealthIndicator } from '@email-gateway/common';

/** The part of `LmtpListener` the service lifecycle needs. */
export interface ManagedLmtpListener {
  readonly accepting: boolean;
  start(): Promise<void>;
  close(): Promise<void>;
  port(): number;
}

/**
 * Base class of the Nest providers that own one LMTP listener: starts it with the module,
 * closes it gracefully on shutdown, and reports readiness under the listener's name (the
 * health check fails while the listener is not accepting, including while it drains).
 */
export abstract class LmtpListenerService
  implements OnModuleInit, OnModuleDestroy, HealthIndicator
{
  abstract readonly healthName: string;

  protected abstract readonly listener: ManagedLmtpListener;

  async onModuleInit(): Promise<void> {
    await this.listener.start();
  }

  async onModuleDestroy(): Promise<void> {
    await this.listener.close();
  }

  checkHealth(): Promise<void> {
    return this.listener.accepting
      ? Promise.resolve()
      : Promise.reject(new Error(`${this.healthName} is not accepting connections`));
  }

  /** Bound port (useful when configured with port 0 in tests). */
  port(): number {
    return this.listener.port();
  }
}
