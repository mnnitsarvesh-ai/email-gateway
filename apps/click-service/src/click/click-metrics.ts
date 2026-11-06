import { Injectable } from '@nestjs/common';
import { MetricsService } from '@email-gateway/common';
import type { BreakerState, CacheName, CacheResult } from '@email-gateway/url-security';

/** `click_requests_total{decision}` values (U18). */
export const CLICK_REQUEST_DECISIONS = [
  'allowed',
  'warned',
  'blocked',
  'continued',
  'expired',
  'invalid',
  'not_found',
  'rate_limited',
  'unavailable',
] as const;
export type ClickRequestDecision = (typeof CLICK_REQUEST_DECISIONS)[number];

export type InvalidTokenReason = 'malformed' | 'bad_mac' | 'unknown_kid' | 'bad_version';
export type ClickEventResult = 'written' | 'error' | 'dropped';
export type RecheckPart = 'scan_result' | 'dynamic' | 'reputation' | 'chain' | 'settings';
export type RecheckResult = 'ok' | 'cached' | 'skipped' | 'error' | 'timeout';

const BREAKER_VALUE: Readonly<Record<BreakerState, number>> = { closed: 0, half_open: 1, open: 2 };

/**
 * click-service series (step 4.3 U18): `click_*` plus the shared `url_*` series of the
 * reputation service, the guarded fetcher and the cache with `component="click"` where the
 * series has that label. Labels are bounded enums; never a URL, token, host or tenant id.
 */
@Injectable()
export class ClickMetrics {
  private readonly requests;
  private readonly duration;
  private readonly invalid;
  private readonly events;
  private readonly pending;
  private readonly recheck;
  private readonly limiterErrors;
  private readonly lookups;
  private readonly lookupDuration;
  private readonly breaker;
  private readonly fetches;
  private readonly fetchDuration;
  private readonly fetchBlocked;
  private readonly cache;

  constructor(metrics: MetricsService) {
    this.requests = metrics.counter('click_requests_total', 'Click requests by decision', [
      'decision',
    ]);
    this.duration = metrics.histogram(
      'click_request_duration_seconds',
      'Click request duration by decision',
      ['decision'],
      [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 1.5, 2.5, 5, 10],
    );
    this.invalid = metrics.counter('click_token_invalid_total', 'Invalid click tokens by reason', [
      'reason',
    ]);
    this.events = metrics.counter('click_events_total', 'Click event writes by result', ['result']);
    this.pending = metrics.gauge('click_events_pending', 'Click event writes in flight');
    this.recheck = metrics.counter('click_recheck_total', 'Click-time recheck parts by result', [
      'part',
      'result',
    ]);
    this.limiterErrors = metrics.counter(
      'click_rate_limiter_errors_total',
      'Rate limiter Redis errors (the limiter failed open)',
    );
    this.lookups = metrics.counter('url_reputation_lookups_total', 'Reputation lookups', [
      'provider',
      'result',
    ]);
    this.lookupDuration = metrics.histogram(
      'url_reputation_duration_seconds',
      'Reputation provider call duration',
      ['provider', 'result'],
      [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
    );
    this.breaker = metrics.gauge(
      'url_provider_breaker_state',
      'Provider breaker state (0 closed, 1 half-open, 2 open)',
      ['provider'],
    );
    this.fetches = metrics.counter('url_fetch_total', 'Guarded fetches', ['result', 'component']);
    this.fetchDuration = metrics.histogram(
      'url_fetch_duration_seconds',
      'Guarded fetch duration',
      ['result', 'component'],
      [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20],
    );
    this.fetchBlocked = metrics.counter(
      'url_fetch_blocked_total',
      'Targets refused by the SSRF guard',
      ['reason', 'component'],
    );
    this.cache = metrics.counter('url_cache_total', 'URL cache operations', ['cache', 'result']);
    this.pending.set(0);
  }

  request(decision: ClickRequestDecision, seconds: number): void {
    this.requests.inc({ decision });
    this.duration.observe({ decision }, seconds);
  }

  invalidToken(reason: InvalidTokenReason): void {
    this.invalid.inc({ reason });
  }

  event(result: ClickEventResult): void {
    this.events.inc({ result });
  }

  setPending(count: number): void {
    this.pending.set(count);
  }

  recheckPart(part: RecheckPart, result: RecheckResult): void {
    this.recheck.inc({ part, result });
  }

  rateLimiterError(): void {
    this.limiterErrors.inc();
  }

  reputationLookup(provider: string, result: string, seconds: number): void {
    this.lookups.inc({ provider, result });
    this.lookupDuration.observe({ provider, result }, seconds);
  }

  breakerState(provider: string, state: BreakerState): void {
    this.breaker.set({ provider }, BREAKER_VALUE[state]);
  }

  fetch(result: string, seconds: number): void {
    this.fetches.inc({ result, component: 'click' });
    this.fetchDuration.observe({ result, component: 'click' }, seconds);
  }

  fetchBlockedReason(reason: string): void {
    this.fetchBlocked.inc({ reason, component: 'click' });
  }

  cacheResult(cache: CacheName, result: CacheResult): void {
    this.cache.inc({ cache, result });
  }
}
