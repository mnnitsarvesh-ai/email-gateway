import { Inject, Injectable, type OnModuleDestroy } from '@nestjs/common';
import { type Counter, MetricsService } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import { Redis } from 'ioredis';
import { ADAPTER_CONFIG, ADAPTER_LOGGER, type SmtpAdapterConfig } from '../config';

/** Hash written by the api's DKIM signing publisher: field `<domain>` → selector (D12). */
export const DKIM_SELECTORS_KEY = 'dkim_selectors';
/** A probe must never hold a policy decision for long (the decision budget is 3 s). */
export const DKIM_PROBE_TIMEOUT_MS = 500;
const ERROR_LOG_INTERVAL_MS = 60_000;

/** Factory for the probe client (tests inject their own). */
export const DKIM_PROBE_CLIENT_FACTORY = Symbol('DKIM_PROBE_CLIENT_FACTORY');
export type DkimProbeClient = Pick<Redis, 'hexists' | 'quit' | 'disconnect' | 'on'>;
export type DkimProbeClientFactory = (url: string) => DkimProbeClient;

export const createDkimProbeClient: DkimProbeClientFactory = (url) =>
  new Redis(url, {
    lazyConnect: true,
    // The dkim-probe ACL user may not run INFO (ioredis' ready check).
    enableReadyCheck: false,
    connectTimeout: 2000,
    commandTimeout: DKIM_PROBE_TIMEOUT_MS,
    maxRetriesPerRequest: 1,
    retryStrategy: (times) => Math.min(times * 200, 2000),
  });

/**
 * DKIM signing readiness for the reinject-outbound policy (step 2.2 D11, D12):
 * `HEXISTS dkim_selectors <senderDomain>` on redis-dkim with the `dkim-probe` ACL user (it can
 * read selectors, never keys). Missing selector, no REDIS_DKIM_PROBE_URL, or any redis-dkim
 * error → not ready (the policy defers; mail is never sent unsigned). Errors are counted in
 * `smtp_dkim_probe_errors_total`.
 *
 * Deliberately NOT a readiness indicator: redis-dkim being down must defer outbound
 * reinjection only, not take the whole adapter (inbound mail) out of rotation.
 */
@Injectable()
export class DkimReadinessService implements OnModuleDestroy {
  private readonly client: DkimProbeClient | null;
  private readonly logger: Logger;
  private readonly errors: Counter;
  private lastErrorLogAt = 0;

  constructor(
    @Inject(ADAPTER_CONFIG) config: Pick<SmtpAdapterConfig, 'REDIS_DKIM_PROBE_URL'>,
    metrics: MetricsService,
    @Inject(ADAPTER_LOGGER) logger: Logger,
    @Inject(DKIM_PROBE_CLIENT_FACTORY) factory: DkimProbeClientFactory,
  ) {
    this.logger = logger.child({ component: 'dkim-readiness' });
    this.errors = metrics.counter(
      'smtp_dkim_probe_errors_total',
      'redis-dkim selector probes that failed (treated as "signing key not available")',
    );
    if (config.REDIS_DKIM_PROBE_URL) {
      this.client = factory(config.REDIS_DKIM_PROBE_URL);
      this.client.on('error', (err: unknown) => this.logThrottled(err, 'redis-dkim connection'));
    } else {
      this.client = null;
      this.logger.warn('REDIS_DKIM_PROBE_URL is not set: reinject-outbound always defers');
    }
  }

  /** True when redis-dkim has a selector for the (normalized ASCII) domain. Never throws. */
  async isReady(domain: string): Promise<boolean> {
    if (!this.client) return false;
    try {
      return (await this.client.hexists(DKIM_SELECTORS_KEY, domain)) === 1;
    } catch (err) {
      this.errors.inc();
      this.logThrottled(err, 'redis-dkim probe');
      return false;
    }
  }

  async onModuleDestroy(): Promise<void> {
    if (!this.client) return;
    try {
      await this.client.quit();
    } catch {
      this.client.disconnect();
    }
  }

  private logThrottled(err: unknown, what: string): void {
    const now = Date.now();
    if (now - this.lastErrorLogAt < ERROR_LOG_INTERVAL_MS) return;
    this.lastErrorLogAt = now;
    this.logger.warn({ err }, `${what} failed; outbound signing treated as not ready`);
  }
}
