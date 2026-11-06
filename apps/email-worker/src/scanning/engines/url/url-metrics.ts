import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';
import { URL_REASON_CODES, URL_SOURCES, URL_VERDICTS } from '@email-gateway/security-contracts';
import {
  BLOCKED_REASONS,
  type BlockedReason,
  type BreakerState,
  type CacheName,
  type CacheResult,
  IMPLEMENTED_PROVIDERS,
  REWRITE_SKIP_REASONS,
} from '@email-gateway/url-security';

/**
 * The URL engine's series of the email-worker (step 4.3 U18; a contract for
 * `infrastructure/monitoring/rules/url-scanning.rules.yml` and docs/runbooks/url-scanning.md),
 * registered once per worker registry. Labels are bounded enums only (verdicts, sources, U10
 * reason codes, provider ids, answer statuses, fetch results, components, guard reasons, cache
 * names and results, rewrite results, link part kinds, inspection statuses, read names); never a
 * URL, a host, a hash or an id. A value outside its enum is counted as `other` (codes, sources,
 * reasons) or dropped (providers), never used as a label.
 */

export const FETCH_COMPONENTS = ['engine', 'click', 'rdap', 'proxy'] as const;
export type FetchComponent = (typeof FETCH_COMPONENTS)[number];
export type FetchResultLabel = 'completed' | 'error' | 'blocked';
export const DYNAMIC_STATUSES = ['requested', 'completed', 'failed', 'expired', 'dropped'] as const;
export type DynamicStatus = (typeof DYNAMIC_STATUSES)[number];
export const URL_READS = [
  'parse',
  'attachments',
  'message_urls',
  'domains',
  'feed',
  'inspection',
  'scan_result',
] as const;
export type UrlRead = (typeof URL_READS)[number];
export const REWRITE_RESULTS = ['rewritten', ...REWRITE_SKIP_REASONS] as const;
export type RewriteResultLabel = (typeof REWRITE_RESULTS)[number];

/** Breaker state values of `url_provider_breaker_state` (as `scan_engine_circuit_state`). */
export const BREAKER_STATE_VALUE: Readonly<Record<BreakerState, number>> = {
  closed: 0,
  half_open: 1,
  open: 2,
};

const DURATION_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30];

const CODES: ReadonlySet<string> = new Set(URL_REASON_CODES);
const SOURCES: ReadonlySet<string> = new Set(URL_SOURCES);
const PROVIDERS: ReadonlySet<string> = new Set(IMPLEMENTED_PROVIDERS);
const REASONS: ReadonlySet<string> = new Set(BLOCKED_REASONS);
const REWRITES: ReadonlySet<string> = new Set(REWRITE_RESULTS);

const registries = new WeakMap<MetricsService, UrlMetrics>();

export class UrlMetrics {
  readonly urls: Counter<'verdict'>;
  readonly extracted: Counter<'source'>;
  readonly findings: Counter<'code'>;
  readonly reputationLookups: Counter<'provider' | 'result'>;
  readonly reputationDuration: Histogram<'provider' | 'result'>;
  readonly breakerState: Gauge<'provider'>;
  readonly fetches: Counter<'result' | 'component'>;
  readonly fetchDuration: Histogram<'result' | 'component'>;
  readonly fetchBlocked: Counter<'reason' | 'component'>;
  readonly cache: Counter<'cache' | 'result'>;
  readonly rewrites: Counter<'result'>;
  readonly rewrittenLinks: Counter<'part'>;
  readonly dynamicInspections: Counter<'status'>;
  readonly inconsistentReads: Counter<'read'>;

  /** One instance per registry (the engine, the results consumer and the sweeper share it). */
  static for(registry: MetricsService): UrlMetrics {
    let metrics = registries.get(registry);
    if (!metrics) {
      metrics = new UrlMetrics(registry);
      registries.set(registry, metrics);
    }
    return metrics;
  }

  private constructor(registry: MetricsService) {
    this.urls = registry.counter(
      'scan_url_urls_total',
      'URLs mapped by the url engine, by URL verdict (clean, suspicious, malicious, unknown)',
      ['verdict'],
    );
    this.extracted = registry.counter(
      'scan_url_extracted_total',
      'URL occurrences extracted, by source (text, html_href, html_src, form_action, meta_refresh, srcset, attachment)',
      ['source'],
    );
    this.findings = registry.counter(
      'scan_url_findings_total',
      'URL reason codes recorded per URL, by code (the bounded url-map/1 enum)',
      ['code'],
    );
    this.reputationLookups = registry.counter(
      'url_reputation_lookups_total',
      'Reputation answers by provider (local_feed, dnsbl, rdap) and result (listed, clear, error)',
      ['provider', 'result'],
    );
    this.reputationDuration = registry.histogram(
      'url_reputation_duration_seconds',
      'Duration of one provider lookup batch, by provider and result',
      ['provider', 'result'],
      DURATION_BUCKETS,
    );
    this.breakerState = registry.gauge(
      'url_provider_breaker_state',
      'Reputation provider circuit breaker state (0 closed, 1 half_open, 2 open), by provider',
      ['provider'],
    );
    this.fetches = registry.counter(
      'url_fetch_total',
      'Guarded fetches (redirect chains, RDAP resources) by result (completed, error, blocked) and component (engine, click, rdap, proxy)',
      ['result', 'component'],
    );
    this.fetchDuration = registry.histogram(
      'url_fetch_duration_seconds',
      'Duration of one guarded fetch, by result and component',
      ['result', 'component'],
      DURATION_BUCKETS,
    );
    this.fetchBlocked = registry.counter(
      'url_fetch_blocked_total',
      'Targets refused by the SSRF guard, by reason (U8 enum) and component',
      ['reason', 'component'],
    );
    this.cache = registry.counter(
      'url_cache_total',
      'URL cache operations by cache (reputation, chain, dynamic) and result (hit, miss, set, error, rejected)',
      ['cache', 'result'],
    );
    this.rewrites = registry.counter(
      'scan_url_rewrites_total',
      'URL rewrite decisions per round, by result (rewritten or the skip reason)',
      ['result'],
    );
    this.rewrittenLinks = registry.counter(
      'scan_url_rewritten_links_total',
      'Links rewritten to the click service, by part kind (text, html)',
      ['part'],
    );
    this.dynamicInspections = registry.counter(
      'scan_url_dynamic_inspections_total',
      'Dynamic inspections by status (requested, completed, failed, expired, dropped)',
      ['status'],
    );
    this.inconsistentReads = registry.counter(
      'scan_url_inconsistent_reads_total',
      'Writer reads of the url engine and its results consumer whose rows did not belong to the request (retried), by read',
      ['read'],
    );
    // Zero series so the alert rules see them before the first event.
    for (const read of URL_READS) this.inconsistentReads.inc({ read }, 0);
    for (const status of DYNAMIC_STATUSES) this.dynamicInspections.inc({ status }, 0);
    for (const result of REWRITE_RESULTS) this.rewrites.inc({ result }, 0);
    for (const cache of ['reputation', 'chain', 'dynamic'] as const) {
      for (const result of ['hit', 'miss', 'set', 'error', 'rejected'] as const) {
        this.cache.inc({ cache, result }, 0);
      }
    }
    for (const verdict of URL_VERDICTS) this.urls.inc({ verdict }, 0);
  }

  /** A provider's breaker is known (gauge at 0 before its first transition). */
  provider(provider: string): void {
    if (PROVIDERS.has(provider)) this.breakerState.set({ provider }, 0);
  }

  breaker(provider: string, state: BreakerState): void {
    if (PROVIDERS.has(provider)) this.breakerState.set({ provider }, BREAKER_STATE_VALUE[state]);
  }

  lookup(provider: string, result: 'listed' | 'clear' | 'error', seconds: number): void {
    if (!PROVIDERS.has(provider)) return;
    this.reputationLookups.inc({ provider, result });
    this.reputationDuration.observe({ provider, result }, Math.max(0, seconds));
  }

  url(verdict: string, codes: readonly string[]): void {
    if ((URL_VERDICTS as readonly string[]).includes(verdict)) this.urls.inc({ verdict });
    for (const code of codes) this.findings.inc({ code: CODES.has(code) ? code : 'other' });
  }

  extractedFrom(source: string, count: number): void {
    if (count > 0) this.extracted.inc({ source: SOURCES.has(source) ? source : 'other' }, count);
  }

  fetch(component: FetchComponent, result: FetchResultLabel, seconds: number): void {
    this.fetches.inc({ result, component });
    this.fetchDuration.observe({ result, component }, Math.max(0, seconds));
  }

  blocked(component: FetchComponent, reason: BlockedReason): void {
    this.fetchBlocked.inc({ reason: REASONS.has(reason) ? reason : 'other', component });
  }

  cacheResult(cache: CacheName, result: CacheResult): void {
    this.cache.inc({ cache, result });
  }

  rewrite(result: string): void {
    this.rewrites.inc({ result: REWRITES.has(result) ? result : 'error' });
  }

  links(part: 'text' | 'html', count: number): void {
    if (count > 0) this.rewrittenLinks.inc({ part }, count);
  }

  dynamic(status: DynamicStatus, count = 1): void {
    if (count > 0) this.dynamicInspections.inc({ status }, count);
  }

  inconsistent(read: UrlRead): void {
    this.inconsistentReads.inc({ read });
  }
}
