import { isIP } from 'node:net';
import {
  CACHE_TTL_BOUNDS,
  DOCUMENTED_PROVIDERS,
  IMPLEMENTED_PROVIDERS,
  parseCidr,
  parseDialMap,
  parseDnsblZones,
  parseErrorCodes,
  parseTokenKey,
  SCAN_TIME_FETCH_MODES,
  testSeamsAllowed,
  validateTestAllowCidrs,
  validateTokenKeys,
} from '@email-gateway/url-security';
import {
  DKIM_SIGNED_POLICIES,
  MESSAGE_DIRECTIONS,
  type UrlPlatformSettings,
  urlPlatformSettingsSchema,
  URL_PLATFORM_DEFAULTS,
  URL_TOKEN_EXPIRY_DAYS_CEILING,
} from '@email-gateway/security-contracts';
import { z } from 'zod';

/**
 * The URL engine's keys (step 4.3 §5, U1, U4, U6–U9, U11–U13, U15, U17; `.env.example` section
 * "URL protection (step 4.3)"), as the email-worker uses them. Every key has the design default
 * and an explicit bound; the cross-field rules are in `validateUrlConfig`. The click-service and
 * the browser worker validate their own keys (WP4).
 */

const int = z.coerce.number().int();
const positiveInt = int.min(1);
const flag = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');
const onOff = z
  .enum(['on', 'off', 'true', 'false', '1', '0'])
  .transform((v) => v === 'on' || v === 'true' || v === '1');
const list = (fallback = '') =>
  z
    .string()
    .default(fallback)
    .transform((value) =>
      value
        .split(',')
        .map((v) => v.trim())
        .filter((v) => v.length > 0),
    );
const lowerList = (fallback = '') =>
  list(fallback).transform((values) => values.map((v) => v.toLowerCase().replace(/\.+$/, '')));
const hex64 = z.string().regex(/^[0-9a-fA-F]{64}$/, 'must be 64 hexadecimal characters');
const noControl = (value: string): boolean =>
  [...value].every((c) => c.charCodeAt(0) >= 0x20 && c.charCodeAt(0) !== 0x7f);
const hostName =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

/** One `URL_DNS_SERVERS` entry: `ip`, `ip:port` or `[v6]:port` (setServers syntax). */
export function isDnsServer(value: string): boolean {
  if (isIP(value) !== 0) return true;
  const v6 = /^\[([0-9a-fA-F:.]+)\]:(\d{1,5})$/.exec(value);
  const v4 = /^([0-9.]+):(\d{1,5})$/.exec(value);
  const match = v6 ?? v4;
  if (!match) return false;
  const port = Number(match[2]);
  return isIP(match[1] as string) !== 0 && port >= 1 && port <= 65_535;
}

export function urlConfigShape() {
  return {
    // The engine's budgets (U17): prefetch, engine-call timeout, attempts (< queue limit 10).
    SCAN_URL_CONCURRENCY: positiveInt.max(64).default(4),
    SCAN_URL_TIMEOUT_MS: int.min(1_000).max(600_000).default(120_000),
    SCAN_URL_MAX_ATTEMPTS: positiveInt.default(6),

    // Extraction bounds (U4).
    URL_MAX_PER_MESSAGE: positiveInt.max(200).default(200),
    URL_MAX_OCCURRENCES: positiveInt.max(100_000).default(5_000),
    URL_MAX_LENGTH: int.min(256).max(2_048).default(2_048),
    URL_MAX_PART_BYTES: positiveInt.max(104_857_600).default(10_485_760),
    URL_MAX_EXTRA_PARTS: int.min(0).max(20).default(5),
    URL_EXTRA_PART_MAX_BYTES: positiveInt.max(104_857_600).default(2_097_152),
    URL_EXTRACT_TIMEOUT_MS: int.min(100).max(120_000).default(5_000),

    // Reputation providers (U6).
    URL_REPUTATION_PROVIDERS: lowerList('local_feed,dnsbl'),
    // Empty by default: a production config never falls back to the local test zones; dnsbl
    // listed without any zone is refused (`.env.example` sets the dns-sink test zones).
    URL_DNSBL_DOMAIN_ZONES: z.string().default(''),
    URL_DNSBL_IP_ZONES: z.string().default(''),
    URL_DNSBL_ERROR_CODES: z
      .string()
      .default('127.255.255.252,127.255.255.254,127.255.255.255,127.0.1.255'),
    URL_RDAP_BASE_URL: z.url({ protocol: /^https?$/ }).optional(),
    URL_NEW_DOMAIN_DAYS: positiveInt.max(3_650).default(30),
    URL_PROVIDER_TIMEOUT_MS: int.min(100).max(60_000).default(3_000),
    URL_PROVIDER_CONCURRENCY: positiveInt.max(128).default(16),
    URL_PROVIDER_BREAKER_THRESHOLD: positiveInt.max(1_000).default(5),
    URL_PROVIDER_BREAKER_RESET_MS: int.min(1_000).max(3_600_000).default(30_000),

    // Restricted resolver (U8): explicit servers, never getaddrinfo.
    URL_DNS_SERVERS: list(),
    URL_DNS_TIMEOUT_MS: int.min(100).max(30_000).default(2_000),
    URL_DNS_TRIES: positiveInt.max(5).default(2),

    // Authenticated Redis cache (U6).
    URL_CACHE_ENABLED: flag.default(true),
    URL_CACHE_CLEAN_TTL_SECONDS: positiveInt.max(CACHE_TTL_BOUNDS.cleanSeconds).default(900),
    URL_CACHE_MALICIOUS_TTL_SECONDS: positiveInt
      .max(CACHE_TTL_BOUNDS.maliciousSeconds)
      .default(86_400),
    URL_CACHE_OTHER_TTL_SECONDS: positiveInt.max(CACHE_TTL_BOUNDS.otherSeconds).default(300),
    URL_CACHE_ERROR_TTL_SECONDS: positiveInt.max(CACHE_TTL_BOUNDS.errorSeconds).default(30),
    URL_CACHE_TIMEOUT_MS: int.min(10).max(10_000).default(200),
    /** Secret (≥ 32 characters): only the URL-consuming worker and the click-service hold it. */
    URL_CACHE_HMAC_KEY: z.string().min(32).optional(),

    // Fetch selection and the guarded fetcher (U8, U9).
    URL_SCAN_TIME_FETCH: z.enum(SCAN_TIME_FETCH_MODES).default(URL_PLATFORM_DEFAULTS.scanTimeFetch),
    URL_FETCH_MAX_PER_MESSAGE: int.min(0).max(50).default(10),
    URL_FETCH_MAX_HOPS: positiveInt.max(20).default(8),
    URL_FETCH_SUSPICIOUS_HOPS: positiveInt.max(20).default(4),
    URL_FETCH_CONNECT_TIMEOUT_MS: int.min(100).max(60_000).default(3_000),
    URL_FETCH_HEADER_TIMEOUT_MS: int.min(100).max(60_000).default(5_000),
    URL_FETCH_TOTAL_TIMEOUT_MS: int.min(500).max(120_000).default(10_000),
    URL_FETCH_MAX_BODY_BYTES: int.min(1_024).max(10_485_760).default(262_144),
    URL_FETCH_MAX_HEADER_BYTES: int.min(1_024).max(1_048_576).default(16_384),
    URL_FETCH_CONCURRENCY: positiveInt.max(256).default(8),
    URL_FETCH_ALLOWED_PORTS: list('80,443'),
    URL_FETCH_DENY_CIDRS: list(),
    URL_FETCH_DENY_HOSTS: lowerList(),
    URL_FETCH_USER_AGENT: z
      .string()
      .min(1)
      .max(256)
      .refine(noControl, 'must not contain control characters')
      .default('Mozilla/5.0 (compatible; EmailGatewayLinkScanner/1.0)'),
    /** Empty = direct mode (in-process guard + NetworkPolicy); `http://host:port` = proxy mode. */
    URL_FETCH_EGRESS_PROXY_URL: z.url({ protocol: /^http$/ }).optional(),
    URL_EGRESS_PROXY_TOKEN: z.string().min(16).max(512).optional(),
    URL_FETCH_CA_FILE: z.string().trim().min(1).optional(),
    /** TEST-ONLY: documentation ranges only, refused outside APP_ENV local/ci. */
    URL_FETCH_TEST_ALLOW_CIDRS: list(),
    /** TEST-ONLY: `ip:port=host:port,…`, refused outside APP_ENV local/ci. */
    URL_FETCH_TEST_DIAL_MAP: z.string().default(''),

    // Shorteners and the protected set (U7, U9).
    URL_SHORTENER_HOSTS_FILE: z.string().trim().min(1).optional(),
    URL_SHORTENER_EXTRA_HOSTS: lowerList(),
    URL_PROTECTED_BRANDS_FILE: z.string().trim().min(1).optional(),
    URL_PROTECTED_EXTRA_DOMAINS: lowerList(),
    URL_LOOKALIKE_MIN_LABEL: int.min(3).max(63).default(5),
    URL_LOOKALIKE_LONG_LABEL: int.min(3).max(63).default(9),
    URL_LOOKALIKE_MAX_DISTANCE_SHORT: int.min(1).max(3).default(1),
    URL_LOOKALIKE_MAX_DISTANCE_LONG: int.min(1).max(4).default(2),
    URL_LOOKALIKE_HIGH_SCORE: z.coerce.number().gt(0).max(1).default(0.85),

    // Rewriting (U11) and tokens (U12); platform settings validated by the contract (U13).
    URL_REWRITE_ENABLED: flag.default(URL_PLATFORM_DEFAULTS.rewrite.enabled),
    URL_REWRITE_DIRECTIONS: list('inbound'),
    URL_REWRITE_DKIM_SIGNED: z
      .enum(DKIM_SIGNED_POLICIES)
      .default(URL_PLATFORM_DEFAULTS.rewrite.dkimSignedPolicy),
    URL_REWRITE_MAX_MESSAGE_BYTES: positiveInt.max(104_857_600).default(26_214_400),
    URL_REWRITE_MAX_PART_BYTES: positiveInt.max(52_428_800).default(5_242_880),
    /** `https://protect.<domain>` in production (https required). */
    URL_CLICK_BASE_URL: z.url({ protocol: /^https?$/ }).default('http://localhost:3080'),
    URL_TOKEN_KEY_CURRENT: hex64.optional(),
    URL_TOKEN_KEY_CURRENT_ID: int.min(1).max(255).default(1),
    URL_TOKEN_KEY_PREVIOUS: hex64.optional(),
    URL_TOKEN_KEY_PREVIOUS_ID: int.min(1).max(255).optional(),
    URL_TOKEN_DEFAULT_EXPIRY_DAYS: positiveInt
      .max(URL_TOKEN_EXPIRY_DAYS_CEILING)
      .default(URL_PLATFORM_DEFAULTS.rewrite.defaultExpiryDays),
    URL_TOKEN_MAX_EXPIRY_DAYS: positiveInt
      .max(URL_TOKEN_EXPIRY_DAYS_CEILING)
      .default(URL_PLATFORM_DEFAULTS.rewrite.maxExpiryDays),

    // Dynamic inspection requests, results consumer and sweeper (U15).
    URL_DYNAMIC_INSPECTION: onOff.default(URL_PLATFORM_DEFAULTS.dynamicInspection),
    URL_DYNAMIC_MAX_PER_MESSAGE: int.min(0).max(10).default(3),
    URL_DYNAMIC_PENDING_TTL_SECONDS: int.min(60).max(86_400).default(3_600),
    URL_DYNAMIC_SWEEP_INTERVAL_MS: int.min(1_000).max(3_600_000).default(60_000),
  };
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars -- only its type is used
const urlObject = z.object(urlConfigShape());
export type UrlShapeConfig = z.infer<typeof urlObject>;

/** The platform URL settings of the config (U13). Not validated (see the schema). */
export function urlPlatformFromConfig(cfg: UrlShapeConfig): UrlPlatformSettings {
  return {
    scanTimeFetch: cfg.URL_SCAN_TIME_FETCH,
    rewrite: {
      enabled: cfg.URL_REWRITE_ENABLED,
      directions: cfg.URL_REWRITE_DIRECTIONS as UrlPlatformSettings['rewrite']['directions'],
      defaultExpiryDays: cfg.URL_TOKEN_DEFAULT_EXPIRY_DAYS,
      maxExpiryDays: cfg.URL_TOKEN_MAX_EXPIRY_DAYS,
      dkimSignedPolicy: cfg.URL_REWRITE_DKIM_SIGNED,
    },
    dynamicInspection: cfg.URL_DYNAMIC_INSPECTION,
  };
}

const PLATFORM_PATHS: Readonly<Record<string, keyof UrlShapeConfig>> = {
  scanTimeFetch: 'URL_SCAN_TIME_FETCH',
  'rewrite.enabled': 'URL_REWRITE_ENABLED',
  'rewrite.directions': 'URL_REWRITE_DIRECTIONS',
  'rewrite.defaultExpiryDays': 'URL_TOKEN_DEFAULT_EXPIRY_DAYS',
  'rewrite.maxExpiryDays': 'URL_TOKEN_MAX_EXPIRY_DAYS',
  'rewrite.dkimSignedPolicy': 'URL_REWRITE_DKIM_SIGNED',
  dynamicInspection: 'URL_DYNAMIC_INSPECTION',
};

/** The environment a test seam decision depends on (step 4.3 WP2 deviation 4). */
export interface UrlEnv {
  NODE_ENV: string;
  APP_ENV: string;
}

/**
 * Production-like: test seams refused and an https click host required. NODE_ENV=production
 * counts as production unless APP_ENV is `local` or `ci` (the local Compose containers run
 * NODE_ENV=production with APP_ENV=local); APP_ENV staging/production always does.
 */
export const urlProductionLike = (cfg: UrlEnv): boolean =>
  !testSeamsAllowed({ nodeEnv: cfg.NODE_ENV, appEnv: cfg.APP_ENV });

type UrlValidationConfig = UrlShapeConfig &
  UrlEnv & {
    MIME_MAX_BODY_BYTES: number;
    SCAN_S3_TIMEOUT_MS: number;
  };

/**
 * The cross-field refusals of the URL engine (startup fails with every violated rule listed).
 * `consumes`: this replica runs the `url` consumer (secrets are required only there).
 */
export function validateUrlConfig(
  cfg: UrlValidationConfig,
  consumes: boolean,
  queueMaxAttempts: number,
  refuse: (path: string, message: string) => void,
): void {
  const production = urlProductionLike(cfg);
  const seamEnv = { nodeEnv: cfg.NODE_ENV, appEnv: cfg.APP_ENV };

  if (cfg.SCAN_URL_MAX_ATTEMPTS >= queueMaxAttempts) {
    refuse(
      'SCAN_URL_MAX_ATTEMPTS',
      `must be below ${String(queueMaxAttempts)}, the attempt limit of queue scan.url ` +
        '(the engine must finalize its result before the consumer dead-letters)',
    );
  }
  if (cfg.SCAN_S3_TIMEOUT_MS >= cfg.SCAN_URL_TIMEOUT_MS) {
    refuse('SCAN_S3_TIMEOUT_MS', 'must be below SCAN_URL_TIMEOUT_MS');
  }
  if (cfg.URL_EXTRACT_TIMEOUT_MS >= cfg.SCAN_URL_TIMEOUT_MS) {
    refuse('URL_EXTRACT_TIMEOUT_MS', 'must be below SCAN_URL_TIMEOUT_MS');
  }
  if (cfg.URL_FETCH_TOTAL_TIMEOUT_MS >= cfg.SCAN_URL_TIMEOUT_MS) {
    refuse('URL_FETCH_TOTAL_TIMEOUT_MS', 'must be below SCAN_URL_TIMEOUT_MS');
  }
  if (cfg.URL_PROVIDER_TIMEOUT_MS >= cfg.SCAN_URL_TIMEOUT_MS) {
    refuse('URL_PROVIDER_TIMEOUT_MS', 'must be below SCAN_URL_TIMEOUT_MS');
  }
  if (cfg.URL_MAX_PART_BYTES > cfg.MIME_MAX_BODY_BYTES) {
    refuse('URL_MAX_PART_BYTES', 'must not exceed MIME_MAX_BODY_BYTES');
  }
  if (cfg.URL_EXTRA_PART_MAX_BYTES > cfg.URL_MAX_PART_BYTES) {
    refuse('URL_EXTRA_PART_MAX_BYTES', 'must not exceed URL_MAX_PART_BYTES');
  }

  // Providers (U6).
  for (const id of cfg.URL_REPUTATION_PROVIDERS) {
    if ((DOCUMENTED_PROVIDERS as readonly string[]).includes(id)) {
      refuse('URL_REPUTATION_PROVIDERS', `${id} is documented but not implemented (step 4.3 §10)`);
    } else if (!(IMPLEMENTED_PROVIDERS as readonly string[]).includes(id)) {
      refuse('URL_REPUTATION_PROVIDERS', `unknown provider ${id}`);
    }
  }
  if (new Set(cfg.URL_REPUTATION_PROVIDERS).size !== cfg.URL_REPUTATION_PROVIDERS.length) {
    refuse('URL_REPUTATION_PROVIDERS', 'lists a provider twice');
  }
  let zones = 0;
  for (const key of ['URL_DNSBL_DOMAIN_ZONES', 'URL_DNSBL_IP_ZONES'] as const) {
    try {
      zones += parseDnsblZones(cfg[key]).length;
    } catch {
      // Not echoed: a zone name may carry a DQS key (Spamhaus).
      refuse(key, 'must be zone=code:category[,code:category…] entries separated by ;');
    }
  }
  try {
    parseErrorCodes(cfg.URL_DNSBL_ERROR_CODES);
  } catch {
    refuse('URL_DNSBL_ERROR_CODES', 'must be IPv4 addresses separated by commas');
  }
  if (cfg.URL_REPUTATION_PROVIDERS.includes('dnsbl') && zones === 0) {
    refuse('URL_DNSBL_DOMAIN_ZONES', 'dnsbl is enabled without any zone');
  }

  // Resolver and fetcher (U8).
  for (const server of cfg.URL_DNS_SERVERS) {
    if (!isDnsServer(server)) refuse('URL_DNS_SERVERS', 'entries must be ip, ip:port or [v6]:port');
  }
  for (const port of cfg.URL_FETCH_ALLOWED_PORTS) {
    const n = Number(port);
    if (!/^\d{1,5}$/.test(port) || n < 1 || n > 65_535) {
      refuse('URL_FETCH_ALLOWED_PORTS', 'entries must be ports 1..65535');
    }
  }
  if (cfg.URL_FETCH_ALLOWED_PORTS.length === 0) {
    refuse('URL_FETCH_ALLOWED_PORTS', 'must list at least one port');
  }
  for (const cidr of cfg.URL_FETCH_DENY_CIDRS) {
    try {
      parseCidr(cidr);
    } catch {
      refuse('URL_FETCH_DENY_CIDRS', 'entries must be CIDRs');
    }
  }
  for (const host of [...cfg.URL_FETCH_DENY_HOSTS, ...cfg.URL_SHORTENER_EXTRA_HOSTS]) {
    if (!hostName.test(host)) refuse('URL_FETCH_DENY_HOSTS', 'entries must be host names');
  }
  for (const domain of cfg.URL_PROTECTED_EXTRA_DOMAINS) {
    if (!hostName.test(domain)) refuse('URL_PROTECTED_EXTRA_DOMAINS', 'entries must be domains');
  }
  if (cfg.URL_FETCH_HEADER_TIMEOUT_MS > cfg.URL_FETCH_TOTAL_TIMEOUT_MS) {
    refuse('URL_FETCH_HEADER_TIMEOUT_MS', 'must not exceed URL_FETCH_TOTAL_TIMEOUT_MS');
  }
  if (cfg.URL_FETCH_CONNECT_TIMEOUT_MS > cfg.URL_FETCH_TOTAL_TIMEOUT_MS) {
    refuse('URL_FETCH_CONNECT_TIMEOUT_MS', 'must not exceed URL_FETCH_TOTAL_TIMEOUT_MS');
  }
  if (cfg.URL_FETCH_SUSPICIOUS_HOPS > cfg.URL_FETCH_MAX_HOPS) {
    refuse('URL_FETCH_SUSPICIOUS_HOPS', 'must not exceed URL_FETCH_MAX_HOPS');
  }
  if (cfg.URL_FETCH_EGRESS_PROXY_URL !== undefined && cfg.URL_EGRESS_PROXY_TOKEN === undefined) {
    refuse('URL_EGRESS_PROXY_TOKEN', 'is required with URL_FETCH_EGRESS_PROXY_URL');
  }
  try {
    validateTestAllowCidrs(cfg.URL_FETCH_TEST_ALLOW_CIDRS, seamEnv);
  } catch (err) {
    refuse('URL_FETCH_TEST_ALLOW_CIDRS', (err as Error).message);
  }
  try {
    parseDialMap(cfg.URL_FETCH_TEST_DIAL_MAP, seamEnv);
  } catch (err) {
    refuse('URL_FETCH_TEST_DIAL_MAP', (err as Error).message);
  }

  // Lookalike thresholds (U7).
  if (cfg.URL_LOOKALIKE_LONG_LABEL < cfg.URL_LOOKALIKE_MIN_LABEL) {
    refuse('URL_LOOKALIKE_LONG_LABEL', 'must be at least URL_LOOKALIKE_MIN_LABEL');
  }
  if (cfg.URL_LOOKALIKE_MAX_DISTANCE_LONG < cfg.URL_LOOKALIKE_MAX_DISTANCE_SHORT) {
    refuse('URL_LOOKALIKE_MAX_DISTANCE_LONG', 'must be at least URL_LOOKALIKE_MAX_DISTANCE_SHORT');
  }

  // Rewriting and tokens (U11, U12, U13).
  if (cfg.URL_REWRITE_MAX_PART_BYTES > cfg.URL_REWRITE_MAX_MESSAGE_BYTES) {
    refuse('URL_REWRITE_MAX_PART_BYTES', 'must not exceed URL_REWRITE_MAX_MESSAGE_BYTES');
  }
  for (const direction of cfg.URL_REWRITE_DIRECTIONS) {
    if (!(MESSAGE_DIRECTIONS as readonly string[]).includes(direction)) {
      refuse('URL_REWRITE_DIRECTIONS', `unknown direction ${direction}`);
    }
  }
  const platform = urlPlatformSettingsSchema.safeParse(urlPlatformFromConfig(cfg));
  if (!platform.success) {
    for (const issue of platform.error.issues) {
      const key = PLATFORM_PATHS[issue.path.join('.')] ?? PLATFORM_PATHS[String(issue.path[0])];
      refuse(key ?? 'URL_REWRITE_ENABLED', issue.message);
    }
  }
  const clickUrl = new URL(cfg.URL_CLICK_BASE_URL);
  if (production && clickUrl.protocol !== 'https:') {
    refuse('URL_CLICK_BASE_URL', 'must be https in production');
  }
  if (clickUrl.search !== '' || clickUrl.hash !== '' || clickUrl.username !== '') {
    refuse('URL_CLICK_BASE_URL', 'must not carry userinfo, a query or a fragment');
  }
  if (
    (cfg.URL_TOKEN_KEY_PREVIOUS === undefined) !==
    (cfg.URL_TOKEN_KEY_PREVIOUS_ID === undefined)
  ) {
    refuse('URL_TOKEN_KEY_PREVIOUS_ID', 'URL_TOKEN_KEY_PREVIOUS and its id are set together');
  }
  if (cfg.URL_TOKEN_KEY_CURRENT !== undefined) {
    try {
      validateTokenKeys({
        current: parseTokenKey(cfg.URL_TOKEN_KEY_CURRENT, cfg.URL_TOKEN_KEY_CURRENT_ID),
        previous:
          cfg.URL_TOKEN_KEY_PREVIOUS !== undefined && cfg.URL_TOKEN_KEY_PREVIOUS_ID !== undefined
            ? parseTokenKey(cfg.URL_TOKEN_KEY_PREVIOUS, cfg.URL_TOKEN_KEY_PREVIOUS_ID)
            : null,
      });
    } catch (err) {
      refuse('URL_TOKEN_KEY_PREVIOUS', (err as Error).message);
    }
  }

  if (!consumes) return;
  if (cfg.URL_CACHE_ENABLED && cfg.URL_CACHE_HMAC_KEY === undefined) {
    refuse(
      'URL_CACHE_HMAC_KEY',
      'is required when the url engine consumes with URL_CACHE_ENABLED=true',
    );
  }
  if (cfg.URL_REWRITE_ENABLED && cfg.URL_TOKEN_KEY_CURRENT === undefined) {
    refuse(
      'URL_TOKEN_KEY_CURRENT',
      'is required when the url engine consumes with URL_REWRITE_ENABLED=true',
    );
  }
}
