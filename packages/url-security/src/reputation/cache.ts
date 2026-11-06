import { createHmac, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { sha256Hex } from '../normalize/url';
import { FETCH_ERRORS, type FetchResult } from '../net/fetcher';
import { BLOCKED_REASONS } from '../net/ssrf-guard';
import {
  ANSWER_STATUSES,
  DETAIL_PATTERN,
  REPUTATION_KINDS,
  THREAT_CATEGORIES,
  THREAT_SEVERITIES,
  type ProviderAnswer,
} from './types';

/**
 * The authenticated URL cache in the shared Redis (U6). Keys:
 *   eg:url:rep:v1:<providerId>:<providerVersion>:<kind>:<sha256(value)>   provider answers
 *   eg:url:chain:v1:<fetcherVersion>:<sha256(identity url)>             redirect chains
 *   eg:url:dyn:v1:<url sha256>                                          dynamic inspection results
 * Value `<mac>.<json>`, mac = hex HMAC-SHA256 under URL_CACHE_HMAC_KEY over `key \n json`,
 * verified in constant time, then strictly schema-checked; a wrong MAC or shape is `rejected`
 * (the caller looks up again and overwrites). Redis errors and timeouts bypass the cache
 * (`error`), never a verdict. Entries hold no tenant data; their hit/miss is never shown to tenants.
 */

export type CacheName = 'reputation' | 'chain' | 'dynamic';
export type CacheResult = 'hit' | 'miss' | 'set' | 'error' | 'rejected';

export type CacheRead<T> =
  { result: 'hit'; value: T } | { result: 'miss' } | { result: 'error' } | { result: 'rejected' };

/** The subset of ioredis used here. */
export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode: 'EX', seconds: number): Promise<unknown>;
}

export interface CacheTtls {
  /** URL_CACHE_CLEAN_TTL_SECONDS (≤ 3 600). */
  cleanSeconds: number;
  /** URL_CACHE_MALICIOUS_TTL_SECONDS (≤ 604 800). */
  maliciousSeconds: number;
  /** URL_CACHE_OTHER_TTL_SECONDS (≤ 3 600). */
  otherSeconds: number;
  /** URL_CACHE_ERROR_TTL_SECONDS (≤ 120). */
  errorSeconds: number;
}

export const CACHE_TTL_BOUNDS: Readonly<Record<keyof CacheTtls, number>> = {
  cleanSeconds: 3600,
  maliciousSeconds: 604_800,
  otherSeconds: 3600,
  errorSeconds: 120,
};

export const DEFAULT_CACHE_TTLS: CacheTtls = {
  cleanSeconds: 900,
  maliciousSeconds: 86_400,
  otherSeconds: 300,
  errorSeconds: 30,
};

export interface ReputationCacheOptions {
  client: RedisLike;
  /** URL_CACHE_HMAC_KEY (≥ 32 characters). */
  hmacKey: string;
  enabled?: boolean;
  ttls?: CacheTtls;
  /** URL_CACHE_TIMEOUT_MS. */
  timeoutMs?: number;
  onResult?: (cache: CacheName, result: CacheResult) => void;
}

export const reputationCacheKey = (
  providerId: string,
  providerVersion: string,
  kind: string,
  value: string,
): string => `eg:url:rep:v1:${providerId}:${providerVersion}:${kind}:${sha256Hex(value)}`;
export const chainCacheKey = (fetcherVersion: string, identityUrl: string): string =>
  `eg:url:chain:v1:${fetcherVersion}:${sha256Hex(identityUrl)}`;
export const dynamicCacheKey = (urlSha256: string): string => `eg:url:dyn:v1:${urlSha256}`;

const nullableEnum = <T extends readonly [string, ...string[]]>(values: T) =>
  z.enum(values).nullable();

export const providerAnswerSchema = z.strictObject({
  kind: z.enum(REPUTATION_KINDS),
  value: z.string().min(1).max(2048),
  status: z.enum(ANSWER_STATUSES),
  category: nullableEnum(THREAT_CATEGORIES),
  severity: nullableEnum(THREAT_SEVERITIES),
  detail: z.string().regex(DETAIL_PATTERN).nullable(),
});

const hostSchema = z.string().max(253);
export const landingSchema = z.strictObject({
  passwordFields: z.number().int().min(0).max(100_000),
  forms: z.number().int().min(0).max(100_000),
  crossOriginFormAction: z.boolean(),
  formActionHosts: z.array(hostSchema).max(5),
  titleBrandMatches: z.array(z.string().max(253)).max(5),
});

export const fetchResultSchema = z.strictObject({
  status: z.enum(['completed', 'error', 'blocked']),
  error: nullableEnum(FETCH_ERRORS),
  blockedReason: nullableEnum(BLOCKED_REASONS),
  hops: z
    .array(
      z.strictObject({
        host: hostSchema,
        port: z.number().int().min(1).max(65535).nullable(),
        status: z.number().int().min(100).max(999).nullable(),
        kind: z.enum(['initial', 'http', 'meta']),
        blocked: nullableEnum(BLOCKED_REASONS),
      }),
    )
    .max(32),
  finalUrl: z.string().max(8192).nullable(),
  finalStatus: z.number().int().min(100).max(999).nullable(),
  landing: landingSchema.nullable(),
  durationMs: z.number().int().min(0),
});

export const DYNAMIC_VERDICTS = ['clean', 'unknown', 'suspicious', 'malicious'] as const;

export const dynamicSignalsSchema = z.strictObject({
  passwordFields: z.number().int().min(0).max(1000),
  forms: z.number().int().min(0).max(1000),
  crossOriginFormAction: z.boolean(),
  formActionHosts: z.array(hostSchema).max(5),
  downloadAttempted: z.boolean(),
  blockedRequests: z.number().int().min(0).max(100_000),
  requests: z.number().int().min(0).max(100_000),
  bytes: z.number().int().min(0),
  titleBrandMatches: z.array(z.string().max(253)).max(5),
  jsRedirect: z.boolean(),
  dialogs: z.number().int().min(0).max(1000),
});
export type DynamicSignals = z.infer<typeof dynamicSignalsSchema>;

/** The dynamic inspection result cached for click time (written by the results consumer, U15). */
export const dynamicCacheValueSchema = z.strictObject({
  inspectionId: z.string().regex(/^[1-9][0-9]{0,19}$/),
  status: z.enum(['completed', 'failed']),
  verdict: z.enum(DYNAMIC_VERDICTS).nullable(),
  reasonCodes: z.array(z.string().max(64)).max(16),
  signals: dynamicSignalsSchema.nullable(),
  finalUrlSha256: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .nullable(),
  finalHost: hostSchema.nullable(),
  completedAt: z.iso.datetime(),
});
export type DynamicCacheValue = z.infer<typeof dynamicCacheValueSchema>;

export function validateCacheTtls(ttls: CacheTtls): CacheTtls {
  for (const [name, max] of Object.entries(CACHE_TTL_BOUNDS) as [keyof CacheTtls, number][]) {
    const value = ttls[name];
    if (!Number.isInteger(value) || value < 1 || value > max) {
      throw new Error(`cache TTL ${name} must be an integer in 1..${max}, got ${value}`);
    }
  }
  return ttls;
}

/** TTL of a provider answer (U6). */
export function answerTtl(
  answer: Pick<ProviderAnswer, 'status' | 'category' | 'severity'>,
  ttls: CacheTtls,
): number {
  if (answer.status === 'clear') return ttls.cleanSeconds;
  if (answer.status === 'error') return ttls.errorSeconds;
  const malicious =
    answer.category === 'phishing' ||
    answer.category === 'malware' ||
    answer.category === 'c2' ||
    answer.severity === 'high' ||
    answer.severity === 'critical';
  return malicious ? ttls.maliciousSeconds : ttls.otherSeconds;
}

/** TTL of a chain: completed ≤ the clean TTL, blocked the other TTL, errors the error TTL. */
export function chainTtl(result: Pick<FetchResult, 'status'>, ttls: CacheTtls): number {
  if (result.status === 'completed') return ttls.cleanSeconds;
  if (result.status === 'blocked') return ttls.otherSeconds;
  return ttls.errorSeconds;
}

export function dynamicTtl(value: Pick<DynamicCacheValue, 'verdict'>, ttls: CacheTtls): number {
  return value.verdict === 'malicious' ? ttls.maliciousSeconds : ttls.otherSeconds;
}

export class UrlCache {
  private readonly key: Buffer;
  private readonly enabled: boolean;
  private readonly ttls: CacheTtls;
  private readonly timeoutMs: number;

  constructor(private readonly options: ReputationCacheOptions) {
    if (options.hmacKey.length < 32)
      throw new Error('URL_CACHE_HMAC_KEY must be at least 32 characters');
    this.key = Buffer.from(options.hmacKey, 'utf8');
    this.enabled = options.enabled ?? true;
    this.ttls = validateCacheTtls(options.ttls ?? DEFAULT_CACHE_TTLS);
    this.timeoutMs = options.timeoutMs ?? 200;
  }

  get cacheTtls(): CacheTtls {
    return this.ttls;
  }

  mac(key: string, json: string): string {
    return createHmac('sha256', this.key).update(key).update('\n').update(json).digest('hex');
  }

  /** `<mac>.<json>` for `key` (exported for tests and tools). */
  seal(key: string, value: unknown): string {
    const json = JSON.stringify(value);
    return `${this.mac(key, json)}.${json}`;
  }

  /** Verifies the MAC in constant time, then the schema. */
  open<T>(key: string, raw: string, schema: z.ZodType<T>): T | null {
    if (raw.indexOf('.') !== 64 || !/^[0-9a-f]{64}$/.test(raw.slice(0, 64))) return null;
    const given = Buffer.from(raw.slice(0, 64), 'utf8');
    const json = raw.slice(65);
    const expected = Buffer.from(this.mac(key, json), 'utf8');
    if (!timingSafeEqual(given, expected)) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch {
      return null;
    }
    const result = schema.safeParse(parsed);
    return result.success ? result.data : null;
  }

  private withTimeout<T>(promise: Promise<T>): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    return Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error('cache timeout')), this.timeoutMs);
      }),
    ]).finally(() => clearTimeout(timer));
  }

  private async read<T>(
    cache: CacheName,
    key: string,
    schema: z.ZodType<T>,
  ): Promise<CacheRead<T>> {
    if (!this.enabled) return { result: 'miss' };
    let raw: string | null;
    try {
      raw = await this.withTimeout(this.options.client.get(key));
    } catch {
      this.options.onResult?.(cache, 'error');
      return { result: 'error' };
    }
    if (raw === null) {
      this.options.onResult?.(cache, 'miss');
      return { result: 'miss' };
    }
    const value = this.open(key, raw, schema);
    if (value === null) {
      this.options.onResult?.(cache, 'rejected');
      return { result: 'rejected' };
    }
    this.options.onResult?.(cache, 'hit');
    return { result: 'hit', value };
  }

  private async write(
    cache: CacheName,
    key: string,
    value: unknown,
    ttl: number,
  ): Promise<boolean> {
    if (!this.enabled) return false;
    try {
      await this.withTimeout(this.options.client.set(key, this.seal(key, value), 'EX', ttl));
      this.options.onResult?.(cache, 'set');
      return true;
    } catch {
      this.options.onResult?.(cache, 'error');
      return false;
    }
  }

  getAnswer(
    providerId: string,
    version: string,
    kind: string,
    value: string,
  ): Promise<CacheRead<ProviderAnswer>> {
    return this.read(
      'reputation',
      reputationCacheKey(providerId, version, kind, value),
      providerAnswerSchema,
    ).then((r) =>
      // A value moved under another key fails the MAC; this also checks the item itself.
      r.result === 'hit' && (r.value.kind !== kind || r.value.value !== value)
        ? { result: 'rejected' as const }
        : r,
    );
  }

  setAnswer(providerId: string, version: string, answer: ProviderAnswer): Promise<boolean> {
    return this.write(
      'reputation',
      reputationCacheKey(providerId, version, answer.kind, answer.value),
      answer,
      answerTtl(answer, this.ttls),
    );
  }

  getChain(fetcherVersion: string, identityUrl: string): Promise<CacheRead<FetchResult>> {
    return this.read('chain', chainCacheKey(fetcherVersion, identityUrl), fetchResultSchema);
  }

  setChain(fetcherVersion: string, identityUrl: string, result: FetchResult): Promise<boolean> {
    return this.write(
      'chain',
      chainCacheKey(fetcherVersion, identityUrl),
      result,
      chainTtl(result, this.ttls),
    );
  }

  getDynamic(urlSha256: string): Promise<CacheRead<DynamicCacheValue>> {
    return this.read('dynamic', dynamicCacheKey(urlSha256), dynamicCacheValueSchema);
  }

  setDynamic(urlSha256: string, value: DynamicCacheValue): Promise<boolean> {
    return this.write(
      'dynamic',
      dynamicCacheKey(urlSha256),
      dynamicCacheValueSchema.parse(value),
      dynamicTtl(value, this.ttls),
    );
  }
}

/** The design calls it the reputation cache; it also holds chains and dynamic results. */
export { UrlCache as ReputationCache };
