import type { UrlEffectiveSettings } from '@email-gateway/security-contracts';
import {
  addressItems,
  chainHosts,
  chainItems,
  detectLookalikes,
  FETCHER_VERSION,
  isShortener,
  mapUrlVerdict,
  mergeLookalike,
  normalizeUrl,
  ProtectedSet,
  reputationItemsFor,
  sortCodes,
  uniqueItems,
  type FetchResult,
  type LookalikeResult,
  type NormalizedUrl,
  type ReputationItem,
  type ReputationLookup,
  type UrlMapInput,
  type UrlReasonCode,
  type UrlVerdict,
} from '@email-gateway/url-security';
import type { ClickMetrics, RecheckPart } from './click-metrics';
import type { ClickRepository, ScanResultRow, UrlKey, UrlRow } from './click-repository';
import {
  fetchForMapper,
  parseCodes,
  parseDynamic,
  parseStoredLookalike,
  storedFetch,
} from './stored-result';
import type { UrlRuntime } from './url-runtime';

/** `url_click_events.recheck` (U14 step 4 / §3 item 6). */
export interface RecheckSummary {
  reputation: 'fresh' | 'cached' | 'error';
  chain: 'fresh' | 'cached' | 'skipped' | 'error';
  dynamic: 'used' | 'none';
}

export interface Evaluation {
  verdict: UrlVerdict;
  reasonCodes: UrlReasonCode[];
  recheck: RecheckSummary;
}

type Settled<T> = { ok: true; value: T } | { ok: false; reason: 'timeout' | 'error' };

/** Resolves with the value, or `timeout` once the budget is spent, or `error` on a throw. */
export function withinBudget<T>(promise: Promise<T>, budget: AbortSignal): Promise<Settled<T>> {
  if (budget.aborted) {
    promise.catch(() => undefined);
    return Promise.resolve({ ok: false, reason: 'timeout' });
  }
  return new Promise((resolve) => {
    const onAbort = (): void => resolve({ ok: false, reason: 'timeout' });
    budget.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => {
        budget.removeEventListener('abort', onAbort);
        resolve({ ok: true, value });
      },
      () => {
        budget.removeEventListener('abort', onAbort);
        resolve({ ok: false, reason: 'error' });
      },
    );
  });
}

/**
 * Click-time re-evaluation (U14 step 4, brief item 10) within CLICK_RECHECK_BUDGET_MS: the
 * latest scan result of the URL (stored lookalike), the latest finished dynamic inspection, and
 * — for every URL that may be fetched (not truncated, U4) — the redirect chain re-resolved
 * through the guarded fetcher (chain cache U6, clean answers ≤ URL_CACHE_CLEAN_TTL_SECONDS), so a
 * link re-pointed after delivery is followed at click time. Fresh reputation (local feed
 * uncached, dnsbl/rdap through the shared cache) for the URL, the public addresses its host
 * resolves to, and the chain (final URL, later hop hosts and their addresses); lookalike
 * detection of a final host that differs from the URL, merged with the stored findings. Mapped
 * with `url-map/1` (incl. M5/S9/U3) using the tenant's live lists. Anything not answered within
 * the budget is an error: the verdict is then never `clean`.
 */
export class Rechecker {
  constructor(
    private readonly repository: ClickRepository,
    private readonly runtime: UrlRuntime,
    private readonly metrics: ClickMetrics,
    private readonly options: { budgetMs: number; suspiciousHops: number; highScore: number },
  ) {}

  async evaluate(input: {
    key: UrlKey;
    url: UrlRow;
    normalized: NormalizedUrl;
    settings: UrlEffectiveSettings;
  }): Promise<Evaluation> {
    const { key, url, normalized, settings } = input;
    const budget = AbortSignal.timeout(this.options.budgetMs);
    const unanswered = new Set<RecheckPart>();
    const record = (part: RecheckPart, settled: Settled<unknown>): void => {
      if (!settled.ok) unanswered.add(part);
      this.metrics.recheckPart(part, settled.ok ? 'ok' : settled.reason);
    };

    // Independent reads, the URL's own reputation and its host's addresses start together.
    const scanP = withinBudget(this.repository.latestScanResult(key, url.urlSha256), budget);
    const dynamicP = withinBudget(this.repository.latestDynamic(key, url.urlSha256), budget);
    const urlItems = reputationItemsFor(normalized);
    const reputationP = withinBudget(this.runtime.reputation.lookup(urlItems, budget), budget);
    // The host's public addresses, looked up as soon as they resolve (in parallel with the
    // chain). A resolution that fails or runs out of budget yields no address (the host's domain
    // reputation and the chain still decide); NXDOMAIN is "no address".
    const addressesP = withinBudget(
      this.runtime.addresses.resolve(url.hostKind === 'domain' ? [url.host] : [], budget),
      budget,
    ).then((settled) => (settled.ok ? settled.value : new Map<string, string[]>()));
    const hostIpItems: ReputationItem[] = [];
    const hostIpReputationP = addressesP.then((found) => {
      hostIpItems.push(...addressItems([url.host], found));
      return hostIpItems.length > 0
        ? withinBudget(this.runtime.reputation.lookup(hostIpItems, budget), budget)
        : null;
    });
    let domainsP: Promise<Settled<string[]>> | null = null;
    const tenantDomains = (): Promise<Settled<string[]>> => {
      domainsP ??= withinBudget(this.repository.activeDomains(key.organizationId), budget);
      return domainsP;
    };

    const scan = await scanP;
    record('scan_result', scan);
    const scanRow: ScanResultRow | null = scan.ok ? scan.value : null;

    const shortened = isShortener(url.host, this.runtime.shorteners);
    // Every URL that may be fetched is re-resolved (a truncated URL never is, U4).
    let chainState: RecheckSummary['chain'] = 'skipped';
    let fetchResult: UrlMapInput['fetch']['result'] = null;
    let fetchRequired = shortened;
    let fresh = false;
    if (!url.truncated) {
      fetchRequired = true;
      const chain = await this.chain(normalized, budget);
      record('chain', chain.ok ? chain : { ok: false, reason: chain.reason });
      if (chain.ok) {
        fresh = true;
        chainState = chain.value.cached ? 'cached' : 'fresh';
        fetchResult = fetchForMapper(chain.value.result);
        if (chain.value.result.status === 'error' && chain.value.result.error === 'timeout')
          chainState = 'error';
      } else {
        // Not answered within the budget (or the cache/fetcher threw): an incomplete fetch.
        chainState = 'error';
        fetchResult = {
          status: 'error',
          error: chain.reason === 'timeout' ? 'timeout' : 'connection_error',
          blockedReason: null,
          hops: [],
          finalUrl: null,
          landing: null,
        };
      }
    } else {
      if (scanRow !== null) fetchResult = storedFetch(scanRow);
      this.metrics.recheckPart('chain', 'skipped');
    }

    // Lookalike: the stored findings (recomputed when there is no readable scan result), merged
    // with those of a re-resolved final URL whose host differs (as the engine does, U10).
    const finalNormalized =
      fresh && fetchResult?.finalUrl ? normalizeUrl(fetchResult.finalUrl) : null;
    const finalUrl =
      finalNormalized?.ok && finalNormalized.url.sha256 !== normalized.sha256
        ? finalNormalized.url
        : null;
    let protectedSet: ProtectedSet | null = null;
    if (scanRow === null || finalUrl !== null) {
      const domains = await tenantDomains();
      record('settings', domains);
      protectedSet = new ProtectedSet({
        brands: this.runtime.brands,
        tenantDomains: domains.ok ? domains.value : [],
        extraDomains: [
          ...this.runtime.platformProtected.entries
            .filter((e) => e.kind === 'extra')
            .map((e) => e.targetDomain),
          ...settings.lookalike.extraProtectedDomains,
        ],
      });
    }
    const storedCodes = scanRow ? parseCodes(scanRow.reasonCodes) : [];
    let lookalike: LookalikeResult;
    if (scanRow !== null) {
      const stored = parseStoredLookalike(scanRow.lookalike, storedCodes, this.options.highScore);
      lookalike = { ...stored, findings: [...stored.findings], codes: [] };
    } else {
      lookalike = detectLookalikes(
        { host: url.host, hostKind: url.hostKind, registrableDomain: url.registrableDomain },
        protectedSet as ProtectedSet,
        this.runtime.lookalikeParams,
        settings.allowedDomains,
      );
    }
    if (finalUrl !== null && protectedSet !== null) {
      lookalike = mergeLookalike(
        lookalike,
        detectLookalikes(
          finalUrl,
          protectedSet,
          this.runtime.lookalikeParams,
          settings.allowedDomains,
        ),
      );
    }

    // Reputation of the URL, plus its host's addresses and the chain's items (final URL, later
    // hop hosts, and the addresses of those domain hosts).
    const reputation: ReputationLookup[] = [];
    const urlReputation = await reputationP;
    record('reputation', urlReputation);
    if (urlReputation.ok) reputation.push(...urlReputation.value);
    const hostIpReputation = await hostIpReputationP;
    if (hostIpReputation !== null) {
      record('reputation', hostIpReputation);
      if (hostIpReputation.ok) reputation.push(...hostIpReputation.value);
    }
    const addresses = new Map<string, string[]>(await addressesP);
    const hosts = fetchResult ? chainHosts(fetchResult).filter((h) => h !== url.host) : [];
    if (hosts.length > 0) {
      const more = await withinBudget(this.runtime.addresses.resolve(hosts, budget), budget);
      if (more.ok) for (const [host, ips] of more.value) addresses.set(host, ips);
    }
    const known = [...urlItems, ...hostIpItems];
    const extraItems = uniqueItems([fetchResult ? chainItems(fetchResult, addresses) : []]).filter(
      (item) => !known.some((u) => u.kind === item.kind && u.value === item.value),
    );
    if (extraItems.length > 0) {
      const extraReputation = await withinBudget(
        this.runtime.reputation.lookup(extraItems, budget),
        budget,
      );
      record('reputation', extraReputation);
      if (extraReputation.ok) reputation.push(...extraReputation.value);
    }
    const reputationErrored =
      !urlReputation.ok ||
      unanswered.has('reputation') ||
      reputation.some((a) => a.status === 'error');

    const dynamicRead = await dynamicP;
    record('dynamic', dynamicRead);
    const dynamic = dynamicRead.ok ? parseDynamic(dynamicRead.value) : null;

    const mapped = mapUrlVerdict({
      phase: 'click',
      url: {
        host: url.host,
        hostKind: url.hostKind,
        registrableDomain: url.registrableDomain,
        truncated: url.truncated,
      },
      flags: parseCodes(url.flags),
      reputation: reputation.map((answer) => ({
        provider: answer.provider,
        status: answer.status,
        category: answer.category,
        severity: answer.severity,
        detail: answer.detail,
      })),
      lookalike,
      shortened,
      fetch: { required: fetchRequired, skippedLimit: false, result: fetchResult },
      dynamic,
      tenant: { allowedDomains: settings.allowedDomains, blockedDomains: settings.blockedDomains },
      suspiciousHops: this.options.suspiciousHops,
    });

    let { verdict, reasonCodes } = mapped;
    if (!urlReputation.ok && verdict === 'clean') {
      // The URL's own reputation never answered: never clean (U14 step 4).
      verdict = 'unknown';
      reasonCodes = sortCodes([
        ...reasonCodes.filter((c) => c !== 'clean.no_findings'),
        'url.reputation_unavailable',
      ]) as UrlReasonCode[];
    } else if (unanswered.size > 0 && verdict === 'clean') {
      // Another part (stored result, dynamic result, tenant domains) was not answered.
      verdict = 'unknown';
      reasonCodes = sortCodes([
        ...reasonCodes.filter((c) => c !== 'clean.no_findings'),
        'url.reputation_unavailable',
      ]) as UrlReasonCode[];
    }
    const anyCached = reputation.some((a) => a.cache === 'hit');
    return {
      verdict,
      reasonCodes,
      recheck: {
        reputation: reputationErrored ? 'error' : anyCached ? 'cached' : 'fresh',
        chain: chainState,
        dynamic: dynamic !== null ? 'used' : 'none',
      },
    };
  }

  /** Chain cache first (U6), else the guarded fetcher; the result is cached for later clicks. */
  private async chain(
    normalized: NormalizedUrl,
    budget: AbortSignal,
  ): Promise<Settled<{ result: FetchResult; cached: boolean }>> {
    const cached = await withinBudget(
      this.runtime.cache.getChain(FETCHER_VERSION, normalized.identity),
      budget,
    );
    if (cached.ok && cached.value.result === 'hit') {
      return { ok: true, value: { result: cached.value.value, cached: true } };
    }
    const fetched = await withinBudget(
      this.runtime.fetcher.fetchChain(normalized.identity, { signal: budget, landing: true }),
      budget,
    );
    if (!fetched.ok) return fetched;
    // Only answers that were not cut by the budget are cached.
    if (!budget.aborted)
      void this.runtime.cache.setChain(FETCHER_VERSION, normalized.identity, fetched.value);
    return { ok: true, value: { result: fetched.value, cached: false } };
  }
}

/** Re-parses the stored URL for the recheck (identity form, flags). */
export const normalizeStored = (url: string): NormalizedUrl | null => {
  const result = normalizeUrl(url);
  return result.ok ? result.url : null;
};
