import {
  amqpUrlListSchema,
  baseConfigSchema,
  ConfigValidationError,
  loadConfig,
} from '@email-gateway/config';
import {
  parseDialMap,
  testSeamsAllowed,
  validateTestAllowCidrs,
} from '@email-gateway/url-security';
import { z } from 'zod';

const int = z.coerce.number().int();
const port = int.min(1).max(65535);
const list = z.string().transform((value) =>
  value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0),
);

/**
 * Keys the isolated browser worker must never hold (U15): database, S3, Redis, click tokens and
 * the URL cache key. A browser exploit must find nothing to steal; the process refuses to start
 * when any of them is set (non-empty). `S3_*` and `URL_TOKEN_*` are prefixes.
 */
export const FORBIDDEN_KEYS = [
  'DATABASE_URL',
  'DATABASE_READ_URL',
  'CLICK_DATABASE_URL',
  'REDIS_URL',
  'URL_CACHE_HMAC_KEY',
] as const;
export const FORBIDDEN_PREFIXES = ['S3_', 'URL_TOKEN_'] as const;

/**
 * Names (never values) of forbidden keys present in `env`, including their `<KEY>_FILE` secret
 * indirection (`resolveFileSecrets`).
 */
export function forbiddenKeysPresent(env: NodeJS.ProcessEnv): string[] {
  return Object.keys(env)
    .filter((key) => (env[key] ?? '') !== '')
    .filter((key) => {
      const base = key.endsWith('_FILE') ? key.slice(0, -'_FILE'.length) : key;
      return (
        (FORBIDDEN_KEYS as readonly string[]).includes(base) ||
        FORBIDDEN_PREFIXES.some((prefix) => base.startsWith(prefix))
      );
    })
    .sort();
}

function refuseForbidden(env: NodeJS.ProcessEnv): void {
  const present = forbiddenKeysPresent(env);
  if (present.length > 0) {
    throw new ConfigValidationError(
      present.map(
        (key) =>
          `${key}: must not be set for the isolated browser worker / egress proxy (step 4.3 U15)`,
      ),
    );
  }
}

/** APP_ENV of the test-seam rule: NODE_ENV=production without APP_ENV counts as production. */
function withAppEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const appEnv = env.APP_ENV?.trim() || (env.NODE_ENV === 'production' ? 'production' : undefined);
  return appEnv ? { ...env, APP_ENV: appEnv } : env;
}

/**
 * url-browser-worker configuration (step 4.3 §5, U15): its broker user, the egress proxy and the
 * browser limits. Nothing else: no database, S3, Redis or token/cache key (refused).
 */
export const workerConfigSchema = baseConfigSchema
  .extend({
    HTTP_HOST: z.string().default('0.0.0.0'),
    /** Health and metrics. */
    URL_BROWSER_HTTP_PORT: port.default(3090),
    /** The `eg-url-browser` user: read `scan.url.inspect`, publish inspection results only. */
    RABBITMQ_URL_BROWSER_URL: amqpUrlListSchema,
    /** The egress proxy (`http://host:port`); every browser request goes through it. */
    URL_BROWSER_PROXY_URL: z.url(),
    URL_EGRESS_PROXY_TOKEN: z
      .string()
      .min(16, 'URL_EGRESS_PROXY_TOKEN must be at least 16 characters'),
    /** Browser contexts at a time = prefetch of the consumer (U15: 1, max 4). */
    URL_BROWSER_CONCURRENCY: int.min(1).max(4).default(1),
    URL_BROWSER_JOB_TIMEOUT_MS: int.min(1000).max(120_000).default(20_000),
    URL_BROWSER_NAVIGATION_TIMEOUT_MS: int.min(1000).max(120_000).default(15_000),
    URL_BROWSER_MAX_JOBS_PER_BROWSER: int.min(1).max(10_000).default(50),
    URL_BROWSER_MAX_RSS_MB: int.min(128).max(16_384).default(768),
    /** Brand data for `titleBrandMatches` (U9; the packaged data/brands.json by default). */
    URL_PROTECTED_BRANDS_FILE: z.string().min(1).optional(),
    URL_PROTECTED_EXTRA_DOMAINS: list.default([]),
  })
  .superRefine((c, ctx) => {
    const proxy = new URL(c.URL_BROWSER_PROXY_URL);
    if (proxy.protocol !== 'http:')
      ctx.addIssue({
        code: 'custom',
        path: ['URL_BROWSER_PROXY_URL'],
        message: 'must be http://host:port',
      });
    if (proxy.username || proxy.password)
      ctx.addIssue({
        code: 'custom',
        path: ['URL_BROWSER_PROXY_URL'],
        message: 'must not carry credentials (URL_EGRESS_PROXY_TOKEN is used)',
      });
  });

export type WorkerConfig = z.infer<typeof workerConfigSchema>;

/** Wait after `load` for further (JS/meta) navigations (U15: "up to 3 s"). */
export const SETTLE_MS = 3000;

export function loadWorkerConfig(env: NodeJS.ProcessEnv = process.env): Readonly<WorkerConfig> {
  refuseForbidden(env);
  return loadConfig(workerConfigSchema, withAppEnv(env));
}

/**
 * url-egress-proxy configuration (U8 egress mode 2, U15): listener, admin port, auth token, caps
 * and the guard/resolver settings shared with the fetchers.
 */
export const proxyConfigSchema = baseConfigSchema
  .extend({
    HTTP_HOST: z.string().default('0.0.0.0'),
    URL_EGRESS_PORT: port.default(3128),
    URL_EGRESS_ADMIN_PORT: port.default(3091),
    URL_EGRESS_PROXY_TOKEN: z
      .string()
      .min(16, 'URL_EGRESS_PROXY_TOKEN must be at least 16 characters'),
    URL_EGRESS_MAX_CONNECTIONS: int.min(1).max(10_000).default(64),
    URL_EGRESS_MAX_BYTES_PER_CONNECTION: int.min(1024).max(1_073_741_824).default(10_485_760),
    URL_EGRESS_IDLE_TIMEOUT_MS: int.min(100).max(600_000).default(15_000),
    URL_EGRESS_MAX_CONNECTION_MS: int.min(100).max(3_600_000).default(30_000),
    URL_DNS_SERVERS: list.default([]),
    URL_DNS_TIMEOUT_MS: int.min(100).max(30_000).default(2000),
    URL_DNS_TRIES: int.min(1).max(5).default(2),
    URL_FETCH_ALLOWED_PORTS: list.default(['80', '443']),
    URL_FETCH_DENY_CIDRS: list.default([]),
    URL_FETCH_DENY_HOSTS: list.default([]),
    URL_FETCH_CONNECT_TIMEOUT_MS: int.min(100).max(60_000).default(3000),
    /** TEST-ONLY (documentation ranges only; refused outside APP_ENV local/ci). */
    URL_FETCH_TEST_ALLOW_CIDRS: list.default([]),
    /** TEST-ONLY dial map (refused outside APP_ENV local/ci). */
    URL_FETCH_TEST_DIAL_MAP: z.string().optional(),
    /** The click host is refused (loop prevention), as in every fetcher. */
    URL_CLICK_BASE_URL: z.url().optional(),
  })
  .superRefine((c, ctx) => {
    const env = { nodeEnv: c.NODE_ENV, appEnv: c.APP_ENV };
    const issue = (path: string, message: string): void =>
      ctx.addIssue({ code: 'custom', path: [path], message });
    if (c.URL_EGRESS_PORT === c.URL_EGRESS_ADMIN_PORT)
      issue('URL_EGRESS_ADMIN_PORT', 'must differ from URL_EGRESS_PORT');
    for (const value of c.URL_FETCH_ALLOWED_PORTS) {
      const n = Number(value);
      if (!Number.isInteger(n) || n < 1 || n > 65535)
        issue('URL_FETCH_ALLOWED_PORTS', 'must list ports 1..65535');
    }
    if (!testSeamsAllowed(env)) {
      if (c.URL_FETCH_TEST_ALLOW_CIDRS.length > 0)
        issue('URL_FETCH_TEST_ALLOW_CIDRS', 'is a test seam and is refused in production');
      if (c.URL_FETCH_TEST_DIAL_MAP)
        issue('URL_FETCH_TEST_DIAL_MAP', 'is a test seam and is refused in production');
      return;
    }
    try {
      validateTestAllowCidrs(c.URL_FETCH_TEST_ALLOW_CIDRS, env);
    } catch {
      issue('URL_FETCH_TEST_ALLOW_CIDRS', 'may only contain documentation ranges');
    }
    try {
      parseDialMap(c.URL_FETCH_TEST_DIAL_MAP, env);
    } catch {
      issue('URL_FETCH_TEST_DIAL_MAP', 'invalid dial map');
    }
  });

export type ProxyConfig = z.infer<typeof proxyConfigSchema>;

export function loadProxyConfig(env: NodeJS.ProcessEnv = process.env): Readonly<ProxyConfig> {
  refuseForbidden(env);
  return loadConfig(proxyConfigSchema, withAppEnv(env));
}
