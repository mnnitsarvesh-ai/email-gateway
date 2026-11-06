import { createHash } from 'node:crypto';
import { type GuardedFetcher } from '../net/fetcher';
import { type RestrictedResolver } from '../net/resolver';
import { CircuitBreaker, type BreakerState } from './breaker';
import { type UrlCache } from './cache';
import { DnsblProvider, parseDnsblZones, parseErrorCodes } from './dnsbl';
import { LocalFeedProvider, type FeedQuery } from './local-feed';
import { RdapProvider } from './rdap';
import {
  errorAnswer,
  type ProviderAnswer,
  type ReputationItem,
  type ReputationProvider,
} from './types';

/**
 * Provider registry and lookup service (U6): providers from configuration, each behind its own
 * circuit breaker and timeout; cacheable providers go through the authenticated Redis cache.
 * An open breaker, a timeout or a thrown provider is `error` for its items — never `clear`.
 */

export const IMPLEMENTED_PROVIDERS = ['local_feed', 'dnsbl', 'rdap'] as const;
/** Documented in docs/deployment/url-protection.md, configuration shape only (§10). */
export const DOCUMENTED_PROVIDERS = [
  'google_safe_browsing',
  'phishtank',
  'urlhaus',
  'openphish',
  'commercial',
] as const;

export interface ReputationConfig {
  /** URL_REPUTATION_PROVIDERS. */
  providers: readonly string[];
  dnsblDomainZones?: string | null;
  dnsblIpZones?: string | null;
  dnsblErrorCodes?: string | null;
  /** URL_RDAP_BASE_URL (rdap is enabled only when listed and this is set). */
  rdapBaseUrl?: string | null;
  newDomainDays?: number;
  /** URL_PROVIDER_CONCURRENCY. */
  concurrency?: number;
}

export interface ProviderDeps {
  resolver: RestrictedResolver;
  /** Required by rdap. */
  fetcher?: GuardedFetcher | null;
  /** Required by local_feed. */
  feedQuery?: FeedQuery | null;
  now?: () => number;
}

export function createReputationProviders(
  config: ReputationConfig,
  deps: ProviderDeps,
): ReputationProvider[] {
  const providers: ReputationProvider[] = [];
  const seen = new Set<string>();
  for (const raw of config.providers) {
    const id = raw.trim().toLowerCase();
    if (!id) continue;
    if (seen.has(id)) throw new Error(`reputation provider ${id} listed twice`);
    seen.add(id);
    switch (id) {
      case 'local_feed':
        if (!deps.feedQuery) throw new Error('local_feed needs a feed query function');
        providers.push(new LocalFeedProvider(deps.feedQuery));
        break;
      case 'dnsbl': {
        const domainZones = parseDnsblZones(config.dnsblDomainZones);
        const ipZones = parseDnsblZones(config.dnsblIpZones);
        if (domainZones.length + ipZones.length === 0)
          throw new Error('dnsbl is enabled without zones');
        const errorCodes = config.dnsblErrorCodes
          ? parseErrorCodes(config.dnsblErrorCodes)
          : undefined;
        providers.push(
          new DnsblProvider(deps.resolver, {
            domainZones,
            ipZones,
            ...(errorCodes ? { errorCodes } : {}),
            ...(config.concurrency ? { concurrency: config.concurrency } : {}),
          }),
        );
        break;
      }
      case 'rdap':
        // Enabled only when listed AND a base URL is configured.
        if (!config.rdapBaseUrl) break;
        if (!deps.fetcher) throw new Error('rdap needs the guarded fetcher');
        providers.push(
          new RdapProvider(deps.fetcher, {
            baseUrl: config.rdapBaseUrl,
            newDomainDays: config.newDomainDays ?? 30,
            ...(deps.now ? { now: deps.now } : {}),
          }),
        );
        break;
      default:
        if ((DOCUMENTED_PROVIDERS as readonly string[]).includes(id)) {
          throw new Error(
            `reputation provider ${id} is documented but not implemented (step 4.3 §10)`,
          );
        }
        throw new Error(`unknown reputation provider ${id}`);
    }
  }
  return providers;
}

/** One provider's answer for one item, as stored in `url_scan_results.reputation`. */
export interface ReputationLookup extends ProviderAnswer {
  provider: string;
  version: string;
  /** Internal only (never returned to tenants, U16). */
  cache: 'hit' | 'miss' | 'none';
}

export interface ReputationServiceOptions {
  /** URL_PROVIDER_TIMEOUT_MS. */
  timeoutMs: number;
  breakerThreshold: number;
  breakerResetMs: number;
  cache?: UrlCache | null;
  now?: () => number;
  hooks?: {
    onLookup?: (provider: string, status: ProviderAnswer['status'], seconds: number) => void;
    onBreakerState?: (provider: string, state: BreakerState) => void;
  };
}

export class ReputationService {
  private readonly breakers = new Map<string, CircuitBreaker>();

  constructor(
    readonly providers: readonly ReputationProvider[],
    private readonly options: ReputationServiceOptions,
  ) {
    for (const provider of providers) {
      this.breakers.set(
        provider.id,
        new CircuitBreaker(options.breakerThreshold, options.breakerResetMs, options.now, (state) =>
          options.hooks?.onBreakerState?.(provider.id, state),
        ),
      );
    }
  }

  breakerState(providerId: string): BreakerState | null {
    return this.breakers.get(providerId)?.state ?? null;
  }

  /** `<8 hex>` over the provider ids and versions (part of the engine version, U10). */
  get versionsHash(): string {
    const text = this.providers.map((p) => `${p.id}=${p.version}`).join(',');
    return createHash('sha256').update(text).digest('hex').slice(0, 8);
  }

  async lookup(items: readonly ReputationItem[], signal: AbortSignal): Promise<ReputationLookup[]> {
    const perProvider = await Promise.all(
      this.providers.map((provider) => this.lookupProvider(provider, items, signal)),
    );
    return perProvider.flat();
  }

  private async lookupProvider(
    provider: ReputationProvider,
    allItems: readonly ReputationItem[],
    signal: AbortSignal,
  ): Promise<ReputationLookup[]> {
    const items = allItems.filter((item) => provider.kinds.includes(item.kind));
    if (items.length === 0) return [];
    const cache = provider.cacheable ? (this.options.cache ?? null) : null;
    const results = new Array<ReputationLookup | undefined>(items.length);
    const misses: number[] = [];
    if (cache) {
      const reads = await Promise.all(
        items.map((item) => cache.getAnswer(provider.id, provider.version, item.kind, item.value)),
      );
      reads.forEach((read, index) => {
        if (read.result === 'hit')
          results[index] = {
            ...read.value,
            provider: provider.id,
            version: provider.version,
            cache: 'hit',
          };
        else misses.push(index);
      });
    } else {
      items.forEach((_, index) => misses.push(index));
    }

    if (misses.length > 0) {
      const query = misses.map((index) => items[index] as ReputationItem);
      const breaker = this.breakers.get(provider.id) as CircuitBreaker;
      let answers: ProviderAnswer[];
      let fromProvider = false;
      const started = Date.now();
      if (!breaker.tryAcquire()) {
        answers = query.map((item) => errorAnswer(item, 'breaker_open'));
      } else {
        fromProvider = true;
        const timeout = AbortSignal.timeout(this.options.timeoutMs);
        const combined = AbortSignal.any([signal, timeout]);
        try {
          answers = await Promise.race([
            provider.lookup(query, combined),
            new Promise<never>((_, reject) => {
              if (combined.aborted) reject(new Error('aborted'));
              combined.addEventListener('abort', () => reject(new Error('timeout')), {
                once: true,
              });
            }),
          ]);
          if (answers.length !== query.length)
            throw new Error('provider answered a different item count');
        } catch {
          answers = query.map((item) =>
            errorAnswer(item, timeout.aborted ? 'timeout' : 'provider_error'),
          );
        }
        if (answers.every((answer) => answer.status === 'error')) breaker.failure();
        else breaker.success();
      }
      const seconds = (Date.now() - started) / 1000;
      answers.forEach((answer, i) => {
        const index = misses[i] as number;
        const item = items[index] as ReputationItem;
        // The answer is always attributed to the queried item (a provider cannot redirect it).
        const fixed: ProviderAnswer = { ...answer, kind: item.kind, value: item.value };
        results[index] = {
          ...fixed,
          provider: provider.id,
          version: provider.version,
          cache: cache ? 'miss' : 'none',
        };
        this.options.hooks?.onLookup?.(provider.id, fixed.status, seconds);
        if (cache && fromProvider && !signal.aborted)
          void cache.setAnswer(provider.id, provider.version, fixed);
      });
    }
    return results as ReputationLookup[];
  }
}
