import { AsyncLocalStorage } from 'node:async_hooks';
import { performance } from 'node:perf_hooks';
import { assertMetadataOnly, uuidv7 } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import {
  normalizedEngineResultSchema,
  type UrlEffectiveSettings,
  URL_MAPPING_VERSION,
} from '@email-gateway/security-contracts';
import {
  aggregateUrlEngine,
  detectLookalikes,
  EXTRACTOR_VERSION,
  extractMessageUrls,
  type ExtractionPart,
  type FeedQuery,
  type FetchResult,
  FETCHER_VERSION,
  isShortener,
  type LookalikeParams,
  type LookalikeResult,
  mapUrlVerdict,
  normalizeUrl,
  ProtectedSet,
  type Brand,
  type ReputationItem,
  reputationItemsFor,
  type ReputationLookup,
  type ReputationService,
  rewriteEml,
  type RewriteResult,
  selectScanTimeFetch,
  signToken,
  type TokenKey,
  tokenExpiry,
  type UrlCache,
  uniqueItems,
  checkRewriteEligibility,
  chainHosts,
  decodeText,
  type HostAddresses,
} from '@email-gateway/url-security';
import { errorFields } from '../../../mime-ingestion/error-fields';
import {
  EmlUnavailableError,
  type EngineFailure,
  type EngineHealthCheck,
  type EngineScanContext,
  type EngineScanOutcome,
  type MessageUrlInput,
  type ScanEngineAdapter,
  type UrlInspectionInput,
  type UrlRewriteInput,
  type UrlScanResultInput,
} from '../../engine';
import type { PartSource } from '../../parts/part-reader';
import type { UrlMetrics } from './url-metrics';
import {
  answersByItem,
  answersFor,
  assignSeqs,
  chainItems,
  hashPrefix,
  mergeLookalike,
  parseComplete,
  rewriteObjectKey,
  selectExtraParts,
  staticRisk,
  storedFetch,
  storedLookalike,
  storedReputation,
} from './url-rows';
import type { RewriteStore } from './rewrite-store';
import { InconsistentUrlReadError, type BodyRef, type UrlStore } from './url-store';

/** Bounds of one engine call (U4, U9, U11, U15; validated configuration). */
export interface UrlEngineLimits {
  maxUrls: number;
  maxOccurrences: number;
  maxLength: number;
  /** URL_MAX_PART_BYTES (bodies). */
  maxPartBytes: number;
  maxExtraParts: number;
  extraPartMaxBytes: number;
  extractTimeoutMs: number;
  fetchMaxPerMessage: number;
  suspiciousHops: number;
  dynamicMaxPerMessage: number;
  dynamicPendingTtlSeconds: number;
  rewriteMaxMessageBytes: number;
  rewriteMaxPartBytes: number;
  /** MIME_MAX_HEADER_BLOCK_BYTES (the rewriter's splitter header limit). */
  maxHeadSize: number;
  /** URL_TOKEN_MAX_EXPIRY_DAYS. */
  maxExpiryDays: number;
}

/** Collects internal (MySQL) failures of the local feed during one engine call (U3 failure classes). */
export class FeedErrorScope {
  private readonly storage = new AsyncLocalStorage<{ error: unknown }>();

  /** Runs `task`; the first feed error recorded inside it is returned (or null). */
  async run<T>(task: () => Promise<T>): Promise<{ value: T; error: unknown }> {
    const slot: { error: unknown } = { error: null };
    const value = await this.storage.run(slot, task);
    return { value, error: slot.error };
  }

  record(error: unknown): void {
    const slot = this.storage.getStore();
    if (slot && slot.error === null) slot.error = error;
  }

  /** Wraps the store's feed query: a failure is recorded for the engine call, then rethrown. */
  wrap(query: FeedQuery): FeedQuery {
    return async (kind, hashes, signal) => {
      try {
        return await query(kind, hashes, signal);
      } catch (error) {
        this.record(error);
        throw error;
      }
    };
  }
}

export interface UrlEngineOptions {
  store: UrlStore;
  parts: PartSource;
  reputation: ReputationService;
  /** The engine's guarded fetcher (component `engine`). */
  fetcher: { fetchChain(input: string, options?: { signal?: AbortSignal }): Promise<FetchResult> };
  /**
   * Addresses of domain hosts for IP reputation (HostAddressResolver over the restricted
   * resolver; public answers only). URL hosts before the first lookup, chain hosts after the
   * fetches.
   */
  addresses: {
    resolve(hosts: Iterable<string>, signal?: AbortSignal): Promise<Map<string, string[]>>;
  };
  /** Null when URL_CACHE_ENABLED=false. */
  cache: UrlCache | null;
  rewriteStore: RewriteStore;
  feedErrors: FeedErrorScope;
  brands: readonly Brand[];
  /** URL_PROTECTED_EXTRA_DOMAINS. */
  extraDomains: readonly string[];
  shorteners: readonly string[];
  lookalike: LookalikeParams;
  limits: UrlEngineLimits;
  /** URL_TOKEN_KEY_CURRENT (+ id); null when rewriting is disabled on the platform. */
  tokenKey: TokenKey | null;
  clickBaseUrl: string;
  engineVersion: string;
  /** Readiness probes (Redis when the cache is enabled; the DNS resolver, non-fatal). */
  probes: {
    redis: (() => Promise<void>) | null;
    dns: () => Promise<'ok' | 'unreachable'>;
    mode: 'direct' | 'proxy';
  };
  metrics: UrlMetrics;
  logger: Logger;
  now?: () => Date;
}

/** Engine-level failure codes that are not retryable (U10 "Failures"). */
const NOT_RETRYABLE = new Set([
  'parse_row_missing',
  'part_unavailable',
  'part_integrity',
  'part_key_mismatch',
  'eml_unavailable',
  'result_invalid',
]);

interface Failed {
  outcome: 'timeout' | 'error';
  errorCode: string;
  engineFault: boolean;
}
const fail = (outcome: 'timeout' | 'error', errorCode: string, engineFault = true): Failed => ({
  outcome,
  errorCode,
  engineFault,
});

class AttemptFailure extends Error {
  constructor(readonly failure: Failed) {
    super(failure.errorCode);
  }
}

/** One URL of the message in the engine's working set (never logged, never stored whole). */
interface WorkUrl {
  seq: number;
  isNew: boolean;
  url: ReturnType<typeof extractMessageUrls>['urls'][number];
  items: ReputationItem[];
  lookalike: LookalikeResult;
  shortened: boolean;
  fetch: FetchResult | null;
  fetchCache: 'hit' | 'miss' | 'none';
  fetchMs: number;
}

/**
 * The url engine adapter (step 4.3 U3): for one round of one message it loads the parse row,
 * the html/text attachment rows, the `message_urls` rows of earlier rounds and the tenant's
 * active domains from the writer (organization from the trusted envelope, echo-checked), reads
 * the stored bodies and extra parts from S3 (org prefix, SHA-256 and size verified), extracts and
 * normalizes the URLs (U4, U5), assigns stable seqs, runs the static analysis (U7), the
 * reputation providers (U6, breaker + authenticated cache), the fetch selection and the guarded
 * fetcher (U8, U9; final URLs through reputation too), maps every URL with `url-map/1` and
 * aggregates (U10), streams the rewritten copy to S3 when eligible (U11) and selects the dynamic
 * inspections (U15). Nothing is persisted here: the rows travel as `childRows.urls` to the
 * finalize transaction (U16).
 *
 * Failure classes (U3): internal infrastructure (S3, MySQL, a wrong read) is an attempt failure
 * or a thrown transient error; an external problem (a site, a DNSBL or RDAP outage, an open
 * provider breaker) is a definite per-URL `unknown` with its code — never `clean`. Logs carry
 * ids, counts, codes and 12-character hash prefixes only (never a URL).
 */
export class UrlEngine implements ScanEngineAdapter {
  readonly name = 'url' as const;
  private readonly logger: Logger;
  private readonly now: () => Date;

  constructor(private readonly options: UrlEngineOptions) {
    this.logger = options.logger.child({ component: 'url-engine' });
    this.now = options.now ?? (() => new Date());
  }

  /** The authenticated cache (shared with the results consumer, U15). */
  get cache(): UrlCache | null {
    return this.options.cache;
  }

  healthChecks(): EngineHealthCheck[] {
    const { probes } = this.options;
    return [
      {
        name: 'url-engine',
        check: async () => {
          if (probes.redis) await probes.redis();
          const dns = await probes.dns().catch(() => 'unreachable' as const);
          return {
            cache: probes.redis ? 'ok' : 'disabled',
            dns,
            egress: probes.mode,
          };
        },
      },
    ];
  }

  async scan(ctx: EngineScanContext, signal: AbortSignal): Promise<EngineScanOutcome> {
    const started = performance.now();
    const elapsed = (): number => Math.max(0, Math.round(performance.now() - started));
    const failure = (f: Failed): EngineFailure => ({
      kind: 'failure',
      outcome: f.outcome,
      errorCode: f.errorCode,
      retryable: !NOT_RETRYABLE.has(f.errorCode),
      engineFault: f.engineFault,
      durationMs: elapsed(),
      engineVersion: this.options.engineVersion,
    });
    try {
      return await this.scanRound(ctx, signal, elapsed);
    } catch (error) {
      if (error instanceof AttemptFailure) return failure(error.failure);
      if (error instanceof InconsistentUrlReadError) {
        this.options.metrics.inconsistent(error.read);
        this.logger.warn(
          {
            messageId: ctx.messageId.toString(),
            round: ctx.round,
            read: error.read,
            check: error.check,
          },
          'url engine: inconsistent writer read, attempt retried',
        );
        return failure(fail('error', 'inconsistent_read', false));
      }
      if (error instanceof EmlUnavailableError) {
        return failure(fail('error', 'eml_unavailable', false));
      }
      if (signal.aborted) return failure(fail('timeout', 'timeout'));
      throw error;
    }
  }

  private checkAborted(signal: AbortSignal): void {
    if (signal.aborted) throw new AttemptFailure(fail('timeout', 'timeout'));
  }

  private async readBody(
    ref: BodyRef,
    prefix: string,
    signal: AbortSignal,
  ): Promise<string | null> {
    if (ref.key === null) return null;
    if (ref.sha256 === null || ref.sizeBytes === null) {
      throw new InconsistentUrlReadError('parse', 'body without hash or size');
    }
    if (!ref.key.startsWith(prefix) || ref.key.includes('..')) {
      throw new AttemptFailure(fail('error', 'part_key_mismatch', false));
    }
    const read = await this.options.parts.read(ref.key, ref.sizeBytes, ref.sha256, signal);
    if (read.kind === 'missing') throw new AttemptFailure(fail('error', 'part_unavailable', false));
    if (read.kind === 'integrity') throw new AttemptFailure(fail('error', 'part_integrity', false));
    // Stored bodies are transfer-decoded and converted to UTF-8 (step 3.1 M8).
    return read.bytes.toString('utf8');
  }

  private async scanRound(
    ctx: EngineScanContext,
    signal: AbortSignal,
    elapsed: () => number,
  ): Promise<EngineScanOutcome> {
    const { options } = this;
    const { store, limits, metrics } = options;
    const settings = ctx.settings as UrlEffectiveSettings;
    const ids = { messageId: ctx.messageId.toString(), round: ctx.round };
    const now = this.now();

    // 1. Writer reads (echo-checked).
    const parse = await store.loadParse(ctx.messageId, ctx.receivedAt, ctx.organizationId);
    if (!parse) {
      this.logger.warn(ids, 'url engine: the message has no parse row');
      throw new AttemptFailure(fail('error', 'parse_row_missing', false));
    }
    const attachments = await store.loadAttachments(
      ctx.messageId,
      ctx.receivedAt,
      ctx.organizationId,
      1_000,
    );
    if (
      parse.attachmentCount !== null &&
      attachments.length !== Math.min(parse.attachmentCount, 1_000)
    ) {
      throw new InconsistentUrlReadError('attachments', 'attachment count');
    }
    const existing = await store.loadMessageUrls(ctx.messageId, ctx.receivedAt, ctx.organizationId);
    const tenantDomains = await store.activeDomains(ctx.organizationId);

    // 2. Parts from S3 (org prefix, SHA-256 and size verified).
    const prefix = `org/${ctx.organizationId.toString()}/part/`;
    let contentComplete = parseComplete(parse.status, parse.limitsExceeded);
    const parts: ExtractionPart[] = [];
    const bodies: Array<string | null> = [];
    for (const [kind, ref] of [
      ['text', parse.textBody],
      ['html', parse.htmlBody],
    ] as const) {
      if (ref.key !== null && ref.sizeBytes !== null && ref.sizeBytes > limits.maxPartBytes) {
        // A body above URL_MAX_PART_BYTES is not scanned: the extraction is incomplete (E1).
        contentComplete = false;
        continue;
      }
      const text = await this.readBody(ref, prefix, signal);
      bodies.push(text);
      if (text !== null) parts.push({ kind, origin: 'body', content: text });
    }
    const extras = selectExtraParts(attachments, limits.maxExtraParts, limits.extraPartMaxBytes);
    const charsetOf = (partIndex: number): string | null =>
      parse.structure?.find((n) => n.index === partIndex)?.charset ?? null;
    for (const { row, kind } of extras) {
      const key = row.objectKey as string;
      if (!key.startsWith(prefix) || key.includes('..')) {
        throw new AttemptFailure(fail('error', 'part_key_mismatch', false));
      }
      const read = await options.parts.read(key, row.sizeBytes, row.sha256, signal);
      if (read.kind === 'missing')
        throw new AttemptFailure(fail('error', 'part_unavailable', false));
      if (read.kind === 'integrity')
        throw new AttemptFailure(fail('error', 'part_integrity', false));
      const decoded = decodeText(read.bytes, charsetOf(row.partIndex), kind);
      parts.push({
        kind,
        origin: 'attachment',
        content: decoded.text,
        charsetGuess: decoded.guessed,
      });
    }
    this.checkAborted(signal);

    // 3. Extraction and normalization (U4, U5); synchronous and bounded by the part sizes, so
    // its duration is checked after the run (extract_timeout, retryable).
    const extractStarted = performance.now();
    const extraction = extractMessageUrls(parts, {
      maxOccurrences: limits.maxOccurrences,
      maxUrls: limits.maxUrls,
      maxLength: limits.maxLength,
    });
    if (performance.now() - extractStarted > limits.extractTimeoutMs) {
      throw new AttemptFailure(fail('timeout', 'extract_timeout', false));
    }
    for (const [source, count] of Object.entries(extraction.sourceCounts)) {
      metrics.extractedFrom(source, count ?? 0);
    }
    const messageCodes: Partial<Record<string, number>> = { ...extraction.messageCodes };
    const assigned = assignSeqs(
      extraction.urls.map((u) => u.url.sha256),
      existing,
    );
    if (assigned.overflow > 0) messageCodes['limit.url_count'] = 1;

    // 4. Static analysis per URL (U7, U9).
    const protectedSet = new ProtectedSet({
      brands: options.brands,
      tenantDomains,
      extraDomains: [...options.extraDomains, ...settings.lookalike.extraProtectedDomains],
    });
    const work: WorkUrl[] = [];
    extraction.urls.forEach((url, index) => {
      const seq = assigned.seqs[index];
      if (seq === null || seq === undefined) return;
      work.push({
        seq,
        isNew: assigned.isNew[index] ?? false,
        url,
        items: reputationItemsFor(url.url),
        lookalike: detectLookalikes(
          url.url,
          protectedSet,
          options.lookalike,
          settings.allowedDomains,
        ),
        shortened: isShortener(url.url.host, options.shorteners),
        fetch: null,
        fetchCache: 'none',
        fetchMs: 0,
      });
    });

    // 5. Reputation of every unique item (U6); a local-feed MySQL failure is internal (U3).
    // Items: the URL, its host or literal IP, and the public addresses its host resolves to.
    const urlHosts = work.filter((w) => w.url.url.hostKind === 'domain').map((w) => w.url.url.host);
    const addresses = new Map<string, string[]>(await options.addresses.resolve(urlHosts, signal));
    const resolvedHosts = new Set(urlHosts);
    this.checkAborted(signal);
    for (const w of work) {
      const ips = w.url.url.hostKind === 'domain' ? (addresses.get(w.url.url.host) ?? []) : [];
      if (ips.length > 0) w.items = reputationItemsFor(w.url.url, ips);
    }
    const firstAnswers = await this.lookup(uniqueItems(work.map((w) => w.items)), signal);
    let index = answersByItem(firstAnswers);
    this.checkAborted(signal);

    // 6. Fetch selection and the guarded fetcher (U8, U9).
    const selection = selectScanTimeFetch(
      work.map((w) => ({
        seq: w.seq,
        url: w.url.url,
        shortened: w.shortened,
        risk: staticRisk({
          flags: w.url.flags,
          hostKind: w.url.url.hostKind,
          lookalike: w.lookalike,
          reputation: answersFor(index, w.items),
        }),
      })),
      settings.scanTimeFetch,
      limits.fetchMaxPerMessage,
    );
    const bySeq = new Map(work.map((w) => [w.seq, w]));
    await Promise.all(
      selection.fetch.map(async (seq) => {
        const w = bySeq.get(seq);
        if (w) await this.fetchOne(w, signal);
      }),
    );
    this.checkAborted(signal);

    // Final URLs and chain hops through reputation too; their lookalikes are merged.
    const known = new Set(firstAnswers.map((a) => `${a.kind}\u0000${a.value}`));
    const unresolved = [
      ...new Set(work.flatMap((w) => (w.fetch ? chainHosts(w.fetch) : []))),
    ].filter((host) => !resolvedHosts.has(host));
    if (unresolved.length > 0) {
      for (const [host, ips] of await options.addresses.resolve(unresolved, signal))
        addresses.set(host, ips);
      this.checkAborted(signal);
    }
    const chainAddresses: HostAddresses = addresses;
    const chainItemLists = work.map((w) => (w.fetch ? chainItems(w.fetch, chainAddresses) : []));
    const extra = uniqueItems(chainItemLists).filter(
      (item) => !known.has(`${item.kind}\u0000${item.value}`),
    );
    if (extra.length > 0) {
      index = answersByItem([...firstAnswers, ...(await this.lookup(extra, signal))]);
      this.checkAborted(signal);
    }

    // 7. Map every URL (U10) and aggregate.
    const required = new Set(selection.required);
    const skippedLimit = new Set(selection.skippedLimit);
    const mapped = work.map((w, i) => {
      const finalLookalike = this.finalLookalike(w, protectedSet, settings);
      const lookalike = mergeLookalike(w.lookalike, finalLookalike);
      const answers: ReputationLookup[] = [
        ...answersFor(index, w.items),
        ...answersFor(index, chainItemLists[i] ?? []),
      ];
      const result = mapUrlVerdict({
        phase: 'scan',
        url: {
          host: w.url.url.host,
          hostKind: w.url.url.hostKind,
          registrableDomain: w.url.url.registrableDomain,
          truncated: w.url.url.truncated,
        },
        flags: w.url.flags,
        reputation: answers,
        lookalike,
        shortened: w.shortened,
        fetch: {
          required: required.has(w.seq),
          skippedLimit: skippedLimit.has(w.seq),
          result: w.fetch,
        },
        tenant: {
          allowedDomains: settings.allowedDomains,
          blockedDomains: settings.blockedDomains,
        },
        suspiciousHops: limits.suspiciousHops,
      });
      metrics.url(result.verdict, result.reasonCodes);
      return { w, lookalike, answers, verdict: result.verdict, reasonCodes: result.reasonCodes };
    });
    const engine = aggregateUrlEngine({
      contentComplete,
      urls: mapped.map((m) => ({ seq: m.w.seq, verdict: m.verdict, reasonCodes: m.reasonCodes })),
      messageCodes,
    });

    // 8. Rewrite (U11): outside any transaction; an S3 upload error is thrown (transient).
    const rewrite = await this.rewrite(
      ctx,
      settings,
      parse.structure,
      bodies,
      contentComplete,
      mapped,
      signal,
      now,
    );
    this.checkAborted(signal);
    const rewrittenSeqs = new Set(rewrite.result?.rewrittenSeqs ?? []);

    // 9. Dynamic inspection requests (U15): suspicious first, then unknown, by seq.
    const inspections: UrlInspectionInput[] = [];
    if (settings.dynamicInspection && limits.dynamicMaxPerMessage > 0) {
      const candidates = mapped
        .filter(
          (m) => (m.verdict === 'suspicious' || m.verdict === 'unknown') && !m.w.url.url.truncated,
        )
        .sort(
          (a, b) =>
            (a.verdict === 'suspicious' ? 0 : 1) - (b.verdict === 'suspicious' ? 0 : 1) ||
            a.w.seq - b.w.seq,
        );
      for (const m of candidates) {
        if (inspections.length >= limits.dynamicMaxPerMessage) break;
        const url = m.w.url.url.stored;
        try {
          // The relay's content guard must accept the event (a long base64-like URL is refused).
          assertMetadataOnly({ url });
        } catch {
          continue;
        }
        inspections.push({
          urlSeq: m.w.seq,
          urlSha256: m.w.url.url.sha256,
          url,
          requestedAt: now,
          deadlineAt: new Date(now.getTime() + limits.dynamicPendingTtlSeconds * 1000),
        });
      }
      metrics.dynamic('requested', inspections.length);
    }
    const inspected = new Set(inspections.map((i) => i.urlSeq));

    // 10. Result and child rows (U16).
    const messageUrls: MessageUrlInput[] = mapped
      .filter((m) => m.w.isNew)
      .map(({ w }) => ({
        urlSeq: w.seq,
        url: w.url.url.stored,
        urlSha256: w.url.url.sha256,
        scheme: w.url.url.scheme,
        host: w.url.url.host,
        unicodeHost: w.url.url.unicodeHost,
        registrableDomain: w.url.url.registrableDomain,
        hostKind: w.url.url.hostKind,
        port: w.url.url.port,
        truncated: w.url.url.truncated,
        flags: w.url.flags.slice(0, 32),
        sources: w.url.sources,
        occurrences: w.url.occurrences,
        firstLifecycleRound: ctx.round,
        extractorVersion: EXTRACTOR_VERSION,
      }));
    const results: UrlScanResultInput[] = mapped.map((m) => ({
      urlSeq: m.w.seq,
      urlSha256: m.w.url.url.sha256,
      verdict: m.verdict,
      reasonCodes: m.reasonCodes.slice(0, 32),
      reputation: storedReputation(m.answers),
      lookalike: storedLookalike(m.lookalike),
      ...storedFetch(m.w.fetch),
      rewritten: rewrittenSeqs.has(m.w.seq),
      dynamicRequested: inspected.has(m.w.seq),
      fetchCache: m.w.fetchCache,
      durationMs: m.w.fetchMs,
    }));

    const base = {
      engine: this.name,
      engineVersion: options.engineVersion,
      score: null,
      requiredScore: null,
      action: null,
      reasonCodes: engine.reasonCodes,
      signals: engine.signals,
      durationMs: elapsed(),
      settingsVersion: ctx.settingsVersion,
      mappingVersion: URL_MAPPING_VERSION,
    };
    const childRows = {
      urls: { messageUrls, results, rewrite: rewrite.row, inspections },
    };
    this.logger.debug(
      {
        ...ids,
        outcome: engine.outcome,
        urls: mapped.length,
        fetched: selection.fetch.length,
        rewrite: rewrite.row.status === 'rewritten' ? 'rewritten' : rewrite.row.skipReason,
        inspections: inspections.length,
        reasonCodes: engine.reasonCodes,
      },
      'url engine result',
    );
    if (engine.outcome === 'skipped') {
      return { kind: 'definite', result: { ...base, outcome: 'skipped' }, childRows };
    }
    const parsed = normalizedEngineResultSchema.safeParse({ ...base, outcome: engine.outcome });
    if (!parsed.success) {
      this.logger.error(ids, 'url engine result violates its contract');
      throw new AttemptFailure(fail('error', 'result_invalid', false));
    }
    return { kind: 'definite', result: parsed.data, childRows };
  }

  /** Reputation lookup with local-feed MySQL failures surfaced as internal errors (U3). */
  private async lookup(items: ReputationItem[], signal: AbortSignal): Promise<ReputationLookup[]> {
    if (items.length === 0) return [];
    const { value, error } = await this.options.feedErrors.run(() =>
      this.options.reputation.lookup(items, signal),
    );
    if (error !== null) throw error instanceof Error ? error : new Error('local feed query failed');
    return value;
  }

  private async fetchOne(w: WorkUrl, signal: AbortSignal): Promise<void> {
    const { cache, fetcher } = this.options;
    const identity = w.url.url.identity;
    if (cache) {
      const cached = await cache.getChain(FETCHER_VERSION, identity);
      if (cached.result === 'hit') {
        w.fetch = cached.value;
        w.fetchCache = 'hit';
        return;
      }
      if (cached.result === 'rejected') {
        this.logger.warn(
          { url: hashPrefix(w.url.url.sha256) },
          'url chain cache entry rejected (MAC or shape invalid); fetched again',
        );
      }
    }
    const started = performance.now();
    const result = await fetcher.fetchChain(identity, { signal });
    w.fetchMs = Math.round(performance.now() - started);
    w.fetch = result;
    w.fetchCache = cache ? 'miss' : 'none';
    if (cache && !signal.aborted) await cache.setChain(FETCHER_VERSION, identity, result);
  }

  private finalLookalike(
    w: WorkUrl,
    set: ProtectedSet,
    settings: UrlEffectiveSettings,
  ): LookalikeResult | null {
    const finalUrl = w.fetch?.finalUrl;
    if (!finalUrl) return null;
    const final = normalizeUrl(finalUrl);
    if (!final.ok || final.url.sha256 === w.url.url.sha256) return null;
    return detectLookalikes(final.url, set, this.options.lookalike, settings.allowedDomains);
  }

  /** U11: eligibility, then the streaming rewrite into a new S3 object. */
  private async rewrite(
    ctx: EngineScanContext,
    settings: UrlEffectiveSettings,
    structure: ReadonlyArray<{ contentType: string }> | null,
    bodies: ReadonlyArray<string | null>,
    contentComplete: boolean,
    mapped: ReadonlyArray<{ w: WorkUrl }>,
    signal: AbortSignal,
    now: Date,
  ): Promise<{ row: UrlRewriteInput; result: RewriteResult | null }> {
    const { options } = this;
    const skipped = (
      reason: string,
      dkimSigned = false,
    ): {
      row: UrlRewriteInput;
      result: null;
    } => {
      options.metrics.rewrite(reason);
      return {
        row: {
          status: 'skipped',
          skipReason: reason,
          objectKey: null,
          objectSha256: null,
          objectSizeBytes: null,
          linksRewritten: 0,
          linksUnmapped: 0,
          partsRewritten: 0,
          partsSkipped: 0,
          dkimSigned,
          tokenKid: null,
          expiresAt: null,
          settingsVersion: ctx.settingsVersion,
        },
        result: null,
      };
    };
    const eligibleUrls = mapped.filter(
      ({ w }) =>
        !w.url.attachmentOnly &&
        !w.url.url.truncated &&
        ((w.url.sources.html_href ?? 0) > 0 || (w.url.sources.text ?? 0) > 0),
    ).length;
    const reason = checkRewriteEligibility({
      enabled: settings.rewrite.enabled && options.tokenKey !== null,
      direction: ctx.direction,
      directions: settings.rewrite.directions,
      contentComplete,
      messageSizeBytes: ctx.eml.sizeBytes,
      maxMessageBytes: options.limits.rewriteMaxMessageBytes,
      contentTypes: (structure ?? []).map((n) => n.contentType),
      bodies,
      eligibleUrls,
    });
    if (reason !== null) return skipped(reason);
    if (structure === null) return skipped('structure_mismatch');

    const key = options.tokenKey as TokenKey;
    const expiresAt = tokenExpiry(now, settings.rewrite.expiryDays, options.limits.maxExpiryDays);
    const urlMap = new Map(
      mapped.map(({ w }) => [w.url.url.sha256, { seq: w.seq, truncated: w.url.url.truncated }]),
    );
    const objectKey = rewriteObjectKey(
      ctx.organizationId,
      ctx.messageId,
      ctx.receivedAt,
      ctx.round,
      uuidv7(now.getTime()),
    );
    const source = await ctx.eml.open(signal);
    let result: RewriteResult;
    try {
      result = await options.rewriteStore.write(
        objectKey,
        (sink) =>
          rewriteEml({
            source,
            sink,
            urlMap,
            policy: {
              plainText: settings.rewrite.plainText,
              excludedDomains: settings.rewrite.excludedDomains,
              allowedDomains: settings.allowedDomains,
              dkimSignedPolicy: settings.rewrite.dkimSignedPolicy,
            },
            clickBaseUrl: options.clickBaseUrl,
            sign: (seq) =>
              signToken(
                {
                  organizationId: ctx.organizationId,
                  messageId: ctx.messageId,
                  receivedAtMs: ctx.receivedAt.getTime(),
                  urlSeq: seq,
                  expiresAt,
                },
                key,
              ),
            limits: {
              maxMessageBytes: options.limits.rewriteMaxMessageBytes,
              maxPartBytes: options.limits.rewriteMaxPartBytes,
            },
            structure,
            maxHeadSize: options.limits.maxHeadSize,
          }),
        signal,
      );
    } finally {
      if (!source.destroyed) source.destroy();
    }
    if (signal.aborted) throw new AttemptFailure(fail('timeout', 'timeout'));
    if (result.status !== 'rewritten') {
      if (result.skipReason === 'error') {
        this.logger.warn(
          { messageId: ctx.messageId.toString(), round: ctx.round, ...errorFields(result.error) },
          'url rewrite failed unexpectedly; the message is delivered unrewritten',
        );
      }
      const out = skipped(result.skipReason ?? 'error', result.dkimSigned);
      out.row.linksUnmapped = result.linksUnmapped;
      out.row.partsSkipped = result.partsSkipped;
      return out;
    }
    options.metrics.rewrite('rewritten');
    options.metrics.links('html', result.linksByPart.html);
    options.metrics.links('text', result.linksByPart.text);
    return {
      row: {
        status: 'rewritten',
        skipReason: null,
        objectKey,
        objectSha256: result.sha256,
        objectSizeBytes: result.sizeBytes,
        linksRewritten: result.linksRewritten,
        linksUnmapped: result.linksUnmapped,
        partsRewritten: result.partsRewritten,
        partsSkipped: result.partsSkipped,
        dkimSigned: result.dkimSigned,
        tokenKid: key.id,
        expiresAt: new Date(expiresAt * 1000),
        settingsVersion: ctx.settingsVersion,
      },
      result,
    };
  }
}
