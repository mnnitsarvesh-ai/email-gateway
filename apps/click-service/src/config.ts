import { baseConfigSchema, loadConfig, redisConfigSchema } from '@email-gateway/config';
import { MAX_DATABASE_SOCKET_TIMEOUT_SECONDS } from '@email-gateway/database';
import {
  urlPlatformSettingsFromEnv,
  type UrlPlatformSettings,
} from '@email-gateway/security-contracts';
import {
  CACHE_TTL_BOUNDS,
  parseDialMap,
  parseDnsblZones,
  parseErrorCodes,
  parseTokenKey,
  testSeamsAllowed,
  validateTestAllowCidrs,
  validateTokenKeys,
  type TokenKeys,
} from '@email-gateway/url-security';
import { z } from 'zod';

const int = z.coerce.number().int();
const port = int.min(1).max(65535);
const flag = z
  .enum(['true', 'false', '1', '0', 'on', 'off'])
  .transform((v) => v === 'true' || v === '1' || v === 'on');
const list = z.string().transform((value) =>
  value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0),
);
const hex64 = z.string().regex(/^[0-9a-fA-F]{64}$/, 'must be 64 hexadecimal characters');

/** Lower bound of `CLICK_DB_TX_TIMEOUT_MS` (above `innodb_lock_wait_timeout` 50 s; 4.2 §6). */
export const MIN_CLICK_DB_TX_TIMEOUT_MS = 60_000;
/** Prisma `maxWait` of the click event transaction (U14 step 7). */
export const CLICK_DB_TX_MAX_WAIT_MS = 10_000;

/**
 * click-service configuration (step 4.3 §5, U14; `.env.example` section "URL protection (step
 * 4.3)"): every `CLICK_*` key and the shared `URL_*` keys the click-time recheck uses (reputation
 * providers, cache, restricted resolver, guarded fetcher, lookalike data, tokens). Values are
 * never echoed in errors (`loadConfig`).
 */
export const clickConfigSchema = baseConfigSchema
  .extend(redisConfigSchema.shape)
  .extend({
    HTTP_HOST: z.string().default('0.0.0.0'),
    /** Public listener: `GET /c/:token`, `GET /c/:token/continue`, static CSS only. */
    CLICK_HTTP_PORT: port.default(3080),
    /** Admin listener: `/health/live`, `/health/ready`, `/metrics` (never behind the Ingress). */
    CLICK_ADMIN_PORT: port.default(3081),
    /** The `gateway_click` account on the writer (table grants only, U14). */
    CLICK_DATABASE_URL: z
      .string()
      .startsWith('mysql://', 'CLICK_DATABASE_URL must be a mysql:// URL'),
    /** `socket_timeout` of the writer client; 0 = none (4.2 §6: no socket timeout). */
    DATABASE_SOCKET_TIMEOUT_SECONDS: int.min(0).max(MAX_DATABASE_SOCKET_TIMEOUT_SECONDS).default(0),
    CLICK_DB_TX_TIMEOUT_MS: int.min(MIN_CLICK_DB_TX_TIMEOUT_MS).max(900_000).default(120_000),
    CLICK_RATE_LIMIT_IP_PER_MINUTE: int.min(1).max(1_000_000).default(120),
    CLICK_RATE_LIMIT_TOKEN_PER_MINUTE: int.min(1).max(1_000_000).default(30),
    CLICK_RATE_LIMIT_INVALID_PER_MINUTE: int.min(1).max(1_000_000).default(20),
    CLICK_RECHECK_BUDGET_MS: int.min(100).max(30_000).default(2500),
    CLICK_EVENT_WRITE_WAIT_MS: int.min(0).max(10_000).default(300),
    CLICK_EVENT_MAX_PENDING: int.min(1).max(100_000).default(1000),
    CLICK_CONTINUE_TTL_SECONDS: int.min(30).max(86_400).default(600),
    /** Reverse-proxy hops trusted for the client address (Express `trust proxy`). */
    CLICK_TRUST_PROXY: int.min(0).max(10).default(0),
    CLICK_STORE_CLIENT_NETWORK: flag.default(true),

    // Reputation providers (U6).
    URL_REPUTATION_PROVIDERS: list.default(['local_feed', 'dnsbl']),
    URL_DNSBL_DOMAIN_ZONES: z.string().optional(),
    URL_DNSBL_IP_ZONES: z.string().optional(),
    URL_DNSBL_ERROR_CODES: z.string().optional(),
    URL_RDAP_BASE_URL: z.url().optional(),
    URL_NEW_DOMAIN_DAYS: int.min(1).max(3650).default(30),
    URL_PROVIDER_TIMEOUT_MS: int.min(100).max(60_000).default(3000),
    URL_PROVIDER_CONCURRENCY: int.min(1).max(256).default(16),
    URL_PROVIDER_BREAKER_THRESHOLD: int.min(1).max(1000).default(5),
    URL_PROVIDER_BREAKER_RESET_MS: int.min(1000).max(3_600_000).default(30_000),

    // Restricted resolver (U8).
    URL_DNS_SERVERS: list.default([]),
    URL_DNS_TIMEOUT_MS: int.min(100).max(30_000).default(2000),
    URL_DNS_TRIES: int.min(1).max(5).default(2),

    // Authenticated cache (U6).
    URL_CACHE_ENABLED: flag.default(true),
    URL_CACHE_CLEAN_TTL_SECONDS: int.min(1).max(CACHE_TTL_BOUNDS.cleanSeconds).default(900),
    URL_CACHE_MALICIOUS_TTL_SECONDS: int
      .min(1)
      .max(CACHE_TTL_BOUNDS.maliciousSeconds)
      .default(86_400),
    URL_CACHE_OTHER_TTL_SECONDS: int.min(1).max(CACHE_TTL_BOUNDS.otherSeconds).default(300),
    URL_CACHE_ERROR_TTL_SECONDS: int.min(1).max(CACHE_TTL_BOUNDS.errorSeconds).default(30),
    URL_CACHE_TIMEOUT_MS: int.min(10).max(5000).default(200),
    URL_CACHE_HMAC_KEY: z.string().min(32, 'URL_CACHE_HMAC_KEY must be at least 32 characters'),

    // Guarded fetcher (U8).
    URL_FETCH_MAX_HOPS: int.min(1).max(20).default(8),
    URL_FETCH_SUSPICIOUS_HOPS: int.min(1).max(20).default(4),
    URL_FETCH_CONNECT_TIMEOUT_MS: int.min(100).max(60_000).default(3000),
    URL_FETCH_HEADER_TIMEOUT_MS: int.min(100).max(60_000).default(5000),
    URL_FETCH_TOTAL_TIMEOUT_MS: int.min(100).max(120_000).default(10_000),
    URL_FETCH_MAX_BODY_BYTES: int.min(1024).max(10_485_760).default(262_144),
    URL_FETCH_MAX_HEADER_BYTES: int.min(1024).max(65_536).default(16_384),
    URL_FETCH_CONCURRENCY: int.min(1).max(256).default(8),
    URL_FETCH_ALLOWED_PORTS: list.default(['80', '443']),
    URL_FETCH_DENY_CIDRS: list.default([]),
    URL_FETCH_DENY_HOSTS: list.default([]),
    URL_FETCH_USER_AGENT: z
      .string()
      .min(1)
      .max(256)
      .default('Mozilla/5.0 (compatible; EmailGatewayLinkScanner/1.0)'),
    URL_FETCH_EGRESS_PROXY_URL: z.url().optional(),
    URL_EGRESS_PROXY_TOKEN: z.string().min(16).optional(),
    URL_FETCH_CA_FILE: z.string().min(1).optional(),
    /** TEST-ONLY (documentation ranges only; refused outside APP_ENV local/ci). */
    URL_FETCH_TEST_ALLOW_CIDRS: list.default([]),
    /** TEST-ONLY host-run dial map (refused outside APP_ENV local/ci). */
    URL_FETCH_TEST_DIAL_MAP: z.string().optional(),

    // Shorteners and lookalike data (U7, U9).
    URL_SHORTENER_HOSTS_FILE: z.string().min(1).optional(),
    URL_SHORTENER_EXTRA_HOSTS: list.default([]),
    URL_PROTECTED_BRANDS_FILE: z.string().min(1).optional(),
    URL_PROTECTED_EXTRA_DOMAINS: list.default([]),
    URL_LOOKALIKE_MIN_LABEL: int.min(2).max(63).default(5),
    URL_LOOKALIKE_LONG_LABEL: int.min(2).max(63).default(9),
    URL_LOOKALIKE_MAX_DISTANCE_SHORT: int.min(0).max(5).default(1),
    URL_LOOKALIKE_MAX_DISTANCE_LONG: int.min(0).max(5).default(2),
    URL_LOOKALIKE_HIGH_SCORE: z.coerce.number().min(0).max(1).default(0.85),

    // Click host and tokens (U12).
    URL_CLICK_BASE_URL: z.url(),
    URL_TOKEN_KEY_CURRENT: hex64,
    URL_TOKEN_KEY_CURRENT_ID: int.min(1).max(255).default(1),
    URL_TOKEN_KEY_PREVIOUS: hex64.optional(),
    URL_TOKEN_KEY_PREVIOUS_ID: int.min(1).max(255).optional(),
  })
  .superRefine((c, ctx) => {
    const seams = testSeamsAllowed({ nodeEnv: c.NODE_ENV, appEnv: c.APP_ENV });
    const issue = (path: string, message: string): void =>
      ctx.addIssue({ code: 'custom', path: [path], message });
    if (c.CLICK_HTTP_PORT === c.CLICK_ADMIN_PORT)
      issue('CLICK_ADMIN_PORT', 'must differ from CLICK_HTTP_PORT (separate admin listener)');
    if (!seams) {
      if (c.URL_FETCH_TEST_ALLOW_CIDRS.length > 0)
        issue('URL_FETCH_TEST_ALLOW_CIDRS', 'is a test seam and is refused in production');
      if (c.URL_FETCH_TEST_DIAL_MAP)
        issue('URL_FETCH_TEST_DIAL_MAP', 'is a test seam and is refused in production');
      if (new URL(c.URL_CLICK_BASE_URL).protocol !== 'https:')
        issue('URL_CLICK_BASE_URL', 'must be https:// in production');
    }
    const base = new URL(c.URL_CLICK_BASE_URL);
    if (base.protocol !== 'https:' && base.protocol !== 'http:')
      issue('URL_CLICK_BASE_URL', 'must be an http(s) URL');
    if (base.username || base.password || base.search || base.hash)
      issue('URL_CLICK_BASE_URL', 'must not carry credentials, a query or a fragment');
    if ((c.URL_TOKEN_KEY_PREVIOUS === undefined) !== (c.URL_TOKEN_KEY_PREVIOUS_ID === undefined))
      issue('URL_TOKEN_KEY_PREVIOUS_ID', 'URL_TOKEN_KEY_PREVIOUS and its id are set together');
    if (c.URL_FETCH_SUSPICIOUS_HOPS > c.URL_FETCH_MAX_HOPS)
      issue('URL_FETCH_SUSPICIOUS_HOPS', 'must not exceed URL_FETCH_MAX_HOPS');
    if (c.URL_FETCH_EGRESS_PROXY_URL && !c.URL_EGRESS_PROXY_TOKEN)
      issue('URL_EGRESS_PROXY_TOKEN', 'is required with URL_FETCH_EGRESS_PROXY_URL');
    for (const value of c.URL_FETCH_ALLOWED_PORTS) {
      const n = Number(value);
      if (!Number.isInteger(n) || n < 1 || n > 65535)
        issue('URL_FETCH_ALLOWED_PORTS', 'must list ports 1..65535');
    }
    const unknownProviders = c.URL_REPUTATION_PROVIDERS.filter(
      (p) => !['local_feed', 'dnsbl', 'rdap'].includes(p),
    );
    if (unknownProviders.length > 0)
      issue('URL_REPUTATION_PROVIDERS', 'lists a provider that is not implemented (step 4.3 §10)');
    try {
      if (c.URL_REPUTATION_PROVIDERS.includes('dnsbl')) {
        const zones = [
          ...parseDnsblZones(c.URL_DNSBL_DOMAIN_ZONES),
          ...parseDnsblZones(c.URL_DNSBL_IP_ZONES),
        ];
        if (zones.length === 0) issue('URL_DNSBL_DOMAIN_ZONES', 'dnsbl is enabled without zones');
      }
      if (c.URL_DNSBL_ERROR_CODES) parseErrorCodes(c.URL_DNSBL_ERROR_CODES);
    } catch {
      issue('URL_DNSBL_DOMAIN_ZONES', 'invalid DNSBL zone or error code syntax');
    }
    if (seams) {
      try {
        validateTestAllowCidrs(c.URL_FETCH_TEST_ALLOW_CIDRS, {
          nodeEnv: c.NODE_ENV,
          appEnv: c.APP_ENV,
        });
      } catch {
        issue('URL_FETCH_TEST_ALLOW_CIDRS', 'may only contain documentation ranges');
      }
      try {
        parseDialMap(c.URL_FETCH_TEST_DIAL_MAP, { nodeEnv: c.NODE_ENV, appEnv: c.APP_ENV });
      } catch {
        issue('URL_FETCH_TEST_DIAL_MAP', 'invalid dial map');
      }
    }
  });

export type ClickEnv = z.infer<typeof clickConfigSchema>;

export interface ClickConfig extends ClickEnv {
  /** Platform URL settings (U13; `URL_SCAN_TIME_FETCH`, `URL_REWRITE_*`, …). */
  platform: UrlPlatformSettings;
  tokenKeys: TokenKeys;
  /** Host of `URL_CLICK_BASE_URL` (the guard refuses it: loop prevention). */
  clickHost: string;
}

/** Validates the environment once; refuses to start on any invalid or forbidden key. */
export function loadClickConfig(env: NodeJS.ProcessEnv = process.env): Readonly<ClickConfig> {
  // APP_ENV defaults to `local` in the shared base schema; with NODE_ENV=production and no
  // APP_ENV the click-service assumes production, so test seams are never enabled by omission.
  const appEnv = env.APP_ENV?.trim() || (env.NODE_ENV === 'production' ? 'production' : undefined);
  const parsed = loadConfig(clickConfigSchema, appEnv ? { ...env, APP_ENV: appEnv } : env);
  let platform: UrlPlatformSettings;
  try {
    platform = urlPlatformSettingsFromEnv(env);
  } catch {
    throw new Error(
      'Invalid configuration: URL platform settings (URL_SCAN_TIME_FETCH, URL_REWRITE_*, URL_TOKEN_*_EXPIRY_DAYS, URL_DYNAMIC_INSPECTION)',
    );
  }
  let tokenKeys: TokenKeys;
  try {
    tokenKeys = validateTokenKeys({
      current: parseTokenKey(parsed.URL_TOKEN_KEY_CURRENT, parsed.URL_TOKEN_KEY_CURRENT_ID),
      previous:
        parsed.URL_TOKEN_KEY_PREVIOUS && parsed.URL_TOKEN_KEY_PREVIOUS_ID
          ? parseTokenKey(parsed.URL_TOKEN_KEY_PREVIOUS, parsed.URL_TOKEN_KEY_PREVIOUS_ID)
          : null,
    });
  } catch (error) {
    // The message names the rule only (never a key value).
    throw new Error(
      `Invalid configuration: URL_TOKEN_KEY_*: ${error instanceof Error ? error.message : 'invalid'}`,
    );
  }
  return Object.freeze({
    ...parsed,
    platform,
    tokenKeys,
    clickHost: new URL(parsed.URL_CLICK_BASE_URL).hostname.replace(/^\[|\]$/g, ''),
  });
}
