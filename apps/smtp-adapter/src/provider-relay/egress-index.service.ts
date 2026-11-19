import { Inject, Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import {
  egressRangesFromCidrs,
  type EgressRangeInput,
  isRelayProvider,
  ProviderEgressIndex,
  RELAY_PROVIDERS,
} from '@email-gateway/mail-routing';
import { ADAPTER_CONFIG, ADAPTER_LOGGER } from '../config';
import type { ProviderRelayConfig } from './provider-relay.config';
import { ProviderRelayMetrics } from './provider-relay.metrics';

/** No egress set was ever loaded: provider relay decisions fail closed (tempfail). */
export class EgressIndexUnavailableError extends Error {
  constructor() {
    super('provider egress ranges not loaded yet');
  }
}

export type EgressIndexConfig = Pick<
  ProviderRelayConfig,
  'PROVIDER_EGRESS_CACHE_SECONDS' | 'PROVIDER_EGRESS_EXTRA_RANGES' | 'PROVIDER_RELAY_ENABLED'
>;

/**
 * The provider egress ranges in memory (step 8.2 D7.2): the ranges of the `active`
 * `provider_egress_range_sets` row of each provider, read from the writer at start and every
 * PROVIDER_EGRESS_CACHE_SECONDS, plus PROVIDER_EGRESS_EXTRA_RANGES (local/ci only, enforced by
 * the config). A failed load keeps the last loaded index (logged, counted); an empty set means no
 * provider relay for that provider. Before the first successful load `current()` throws, so the
 * relay tempfails instead of refusing provider mail permanently.
 */
@Injectable()
export class EgressIndexService implements OnModuleInit, OnModuleDestroy {
  private readonly logger: Logger;
  private index: ProviderEgressIndex | null = null;
  private timer: NodeJS.Timeout | undefined;
  private loading: Promise<void> | null = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly metrics: ProviderRelayMetrics,
    @Inject(ADAPTER_CONFIG) private readonly config: EgressIndexConfig,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.logger = logger.child({ component: 'provider-egress' });
  }

  async onModuleInit(): Promise<void> {
    if (!this.config.PROVIDER_RELAY_ENABLED) return;
    await this.refresh();
    this.timer = setInterval(() => {
      void this.refresh();
    }, this.config.PROVIDER_EGRESS_CACHE_SECONDS * 1000);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    clearInterval(this.timer);
  }

  /** True once a set was loaded. */
  get loaded(): boolean {
    return this.index !== null;
  }

  /** The last loaded index; throws `EgressIndexUnavailableError` before the first load. */
  current(): ProviderEgressIndex {
    if (this.index === null) throw new EgressIndexUnavailableError();
    return this.index;
  }

  /** Reloads the active sets; never throws (a failure keeps the previous index). */
  refresh(): Promise<void> {
    this.loading ??= this.load().finally(() => {
      this.loading = null;
    });
    return this.loading;
  }

  private async load(): Promise<void> {
    try {
      const rows = await this.prisma.providerEgressRange.findMany({
        where: { set: { status: 'active' } },
        select: { provider: true, ipVersion: true, rangeStart: true, rangeEnd: true },
      });
      const ranges: EgressRangeInput[] = [];
      for (const row of rows) {
        if (!isRelayProvider(row.provider) || (row.ipVersion !== 4 && row.ipVersion !== 6)) {
          throw new Error('unexpected provider egress range row');
        }
        ranges.push({
          provider: row.provider,
          ipVersion: row.ipVersion,
          rangeStart: row.rangeStart,
          rangeEnd: row.rangeEnd,
        });
      }
      for (const provider of RELAY_PROVIDERS) {
        ranges.push(
          ...egressRangesFromCidrs(
            provider,
            this.config.PROVIDER_EGRESS_EXTRA_RANGES[provider] ?? [],
          ),
        );
      }
      const index = ProviderEgressIndex.build(ranges);
      const first = this.index === null;
      this.index = index;
      for (const provider of RELAY_PROVIDERS) {
        this.metrics.egressLoaded(provider, index.count(provider));
      }
      if (first) {
        this.logger.info(
          Object.fromEntries(RELAY_PROVIDERS.map((p) => [p, index.count(p)])),
          'provider egress ranges loaded',
        );
      }
    } catch (err) {
      this.metrics.egressLoadFailed();
      this.logger.error(
        { err, keptPrevious: this.index !== null },
        'provider egress range load failed; keeping the last loaded set',
      );
    }
  }
}
