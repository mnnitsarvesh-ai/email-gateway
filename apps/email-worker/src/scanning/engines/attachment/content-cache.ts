import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { AttachmentVerdict } from '@email-gateway/security-contracts';
import type { ContentResult, InspectLimits } from './content';
import { contentResultSchema } from './content-schema';

/**
 * The attachment content cache (step 4.2 A10): tenant-independent content results in the shared
 * app Redis under `eg:scan:att:v2:<sha256>:<contentVersion>`, ≤ 128 KiB, a TTL by the verdict
 * the content alone implies, plain `SET … EX` (last writer wins: identical inputs give identical
 * results). Redis errors and timeouts (ATTACHMENT_CACHE_TIMEOUT_MS) bypass the cache: they never
 * fail an attempt and never produce `clean`. Holds no tenant or message data.
 *
 * Values are authenticated: `<mac>.<json>` with `mac` = base64url HMAC-SHA256 under
 * ATTACHMENT_CACHE_HMAC_KEY (held by the email-worker only, never by the api or other services
 * that share the Redis credentials) over the key and the JSON. A value with a missing or wrong
 * MAC, or JSON that is not exactly a `ContentResult` (`contentResultSchema`), is `rejected` and
 * treated as a miss: the attachment is scanned again and the entry overwritten. So a planted
 * entry cannot replace a ClamAV/YARA scan. (`v2`: the authenticated format; `v1` entries of the
 * unauthenticated format are never read and expire by their TTL.)
 */

export const CACHE_PREFIX = 'eg:scan:att:v2:';
/** Minimum length of ATTACHMENT_CACHE_HMAC_KEY (characters). */
export const MIN_CACHE_KEY_LENGTH = 32;
/** Values above this size are not cached (`too_large`). */
export const MAX_CACHE_VALUE_BYTES = 131_072;

/** The parts of an ioredis client the cache uses. */
export interface CacheRedis {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode: 'EX', seconds: number): Promise<unknown>;
}

export interface ContentCacheTtls {
  cleanSeconds: number;
  maliciousSeconds: number;
  otherSeconds: number;
}

export type CacheGet =
  | { kind: 'hit'; content: ContentResult }
  | { kind: 'miss' }
  /** An entry whose MAC or shape is invalid (never written by this code with this key). */
  | { kind: 'rejected' }
  | { kind: 'error' };

export type CacheSet = 'set' | 'too_large' | 'error';

/** The inputs of the content version (A9). */
export interface ContentVersionInput {
  inspectorVersion: string;
  clamavEngine: string;
  clamavDb: number;
  yaraX: string;
  bundleId: string;
  limits: InspectLimits;
}

const canonical = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
  }
  return JSON.stringify(value);
};

/**
 * Content version (A9): the first 16 hex of SHA-256 over the inspector version, the ClamAV
 * engine and database versions, the YARA-X version, the bundle id and the canonical platform
 * archive/CPU/memory limits. A new ClamAV database or YARA bundle changes it, so old keys become
 * unreachable at once and expire by their TTL.
 */
export function contentVersion(input: ContentVersionInput): string {
  const text = canonical({
    inspector: input.inspectorVersion,
    clamav: `${input.clamavEngine}/${String(input.clamavDb)}`,
    yaraX: input.yaraX,
    bundle: input.bundleId,
    limits: input.limits,
  });
  return createHash('sha256').update(text, 'utf8').digest('hex').slice(0, 16);
}

export const cacheKey = (sha256: string, version: string): string =>
  `${CACHE_PREFIX}${sha256}:${version}`;

/** TTL of a content result by the verdict the content implies (A10); kills use `other`. */
export function ttlSeconds(
  verdict: AttachmentVerdict,
  content: ContentResult,
  ttls: ContentCacheTtls,
): number {
  if (content.limits.includes('limit.cpu_time') || content.limits.includes('limit.memory')) {
    return ttls.otherSeconds;
  }
  if (verdict === 'clean') return ttls.cleanSeconds;
  if (verdict === 'malicious') return ttls.maliciousSeconds;
  return ttls.otherSeconds;
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([
    promise,
    new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error('cache timeout')), ms);
      timer.unref();
    }),
  ]).finally(() => clearTimeout(timer));
}

const MAC_BYTES = 32;

export class ContentCache {
  private readonly hmacKey: Buffer;

  constructor(
    private readonly redis: CacheRedis,
    private readonly ttls: ContentCacheTtls,
    private readonly timeoutMs: number,
    hmacKey: string,
  ) {
    if (hmacKey.length < MIN_CACHE_KEY_LENGTH) {
      throw new Error(
        `the content cache MAC key must have at least ${String(MIN_CACHE_KEY_LENGTH)} characters`,
      );
    }
    this.hmacKey = Buffer.from(hmacKey, 'utf8');
  }

  private mac(key: string, json: string): Buffer {
    return createHmac('sha256', this.hmacKey)
      .update(key, 'utf8')
      .update('\n')
      .update(json, 'utf8')
      .digest();
  }

  /** Verifies `<mac>.<json>` for `key`; the parsed content result, or null. */
  private open(key: string, raw: string): ContentResult | null {
    const dot = raw.indexOf('.');
    if (dot <= 0) return null;
    const given = Buffer.from(raw.slice(0, dot), 'base64url');
    const json = raw.slice(dot + 1);
    if (given.length !== MAC_BYTES || !timingSafeEqual(given, this.mac(key, json))) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch {
      return null;
    }
    const valid = contentResultSchema.safeParse(parsed);
    return valid.success ? valid.data : null;
  }

  async get(sha256: string, version: string): Promise<CacheGet> {
    const key = cacheKey(sha256, version);
    let raw: string | null;
    try {
      raw = await withTimeout(this.redis.get(key), this.timeoutMs);
    } catch {
      return { kind: 'error' };
    }
    if (raw === null) return { kind: 'miss' };
    const content = this.open(key, raw);
    return content ? { kind: 'hit', content } : { kind: 'rejected' };
  }

  async set(
    sha256: string,
    version: string,
    content: ContentResult,
    verdict: AttachmentVerdict,
  ): Promise<CacheSet> {
    const key = cacheKey(sha256, version);
    const json = JSON.stringify(content);
    const value = `${this.mac(key, json).toString('base64url')}.${json}`;
    if (Buffer.byteLength(value, 'utf8') > MAX_CACHE_VALUE_BYTES) return 'too_large';
    try {
      await withTimeout(
        this.redis.set(key, value, 'EX', ttlSeconds(verdict, content, this.ttls)),
        this.timeoutMs,
      );
      return 'set';
    } catch {
      return 'error';
    }
  }
}
