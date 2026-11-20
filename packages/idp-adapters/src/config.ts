/**
 * Adapter configuration (design note §4.2, D2, D12): `idpAdapterConfigSchema` reads the
 * `ATO_IDP_*` keys. Endpoint override rule (D12, ADR-0086): an `ATO_IDP_*_BASE_URL` different from
 * its production default is refused unless `APP_ENV ∈ {local, ci}`; `http:` only when
 * `allowHttpEndpoints` (8.2's `PROVIDER_ALLOW_HTTP_ENDPOINTS`, wired by WP3) and in local/ci.
 */
import { z } from 'zod';
import type { OriginFamily } from './core/http';
import type { ApiFamily } from './port/state-ports';

export const PRODUCTION_BASE_URLS: Readonly<Record<OriginFamily, string>> = {
  graph: 'https://graph.microsoft.com',
  o365: 'https://manage.office.com',
  google_admin: 'https://admin.googleapis.com',
  gmail: 'https://gmail.googleapis.com',
};

const BASE_URL_KEYS: Readonly<Record<OriginFamily, string>> = {
  graph: 'ATO_IDP_GRAPH_BASE_URL',
  o365: 'ATO_IDP_O365_MANAGEMENT_BASE_URL',
  google_admin: 'ATO_IDP_GOOGLE_ADMIN_BASE_URL',
  gmail: 'ATO_IDP_GMAIL_BASE_URL',
};

const intKey = (fallback: number, min: number, max: number) =>
  z.coerce.number().int().min(min).max(max).default(fallback);

const boolKey = (fallback: boolean) =>
  z
    .enum(['true', 'false', '1', '0'])
    .default(fallback ? 'true' : 'false')
    .transform((value) => value === 'true' || value === '1');

const emptyAsUndefined = (value: unknown) =>
  typeof value === 'string' && value.trim() === '' ? undefined : value;

const urlKey = (fallback: string) =>
  z
    .preprocess(emptyAsUndefined, z.url().max(512).default(fallback))
    .transform((value) => value.replace(/\/+$/, ''));

/** Raw keys (strings from the environment) → typed values with defaults. */
export const idpAdapterEnvSchema = z.object({
  ATO_IDP_ADAPTERS_ENABLED: boolKey(true),
  ATO_IDP_GRAPH_BASE_URL: urlKey(PRODUCTION_BASE_URLS.graph),
  ATO_IDP_O365_MANAGEMENT_BASE_URL: urlKey(PRODUCTION_BASE_URLS.o365),
  ATO_IDP_GOOGLE_ADMIN_BASE_URL: urlKey(PRODUCTION_BASE_URLS.google_admin),
  ATO_IDP_GMAIL_BASE_URL: urlKey(PRODUCTION_BASE_URLS.gmail),
  ATO_IDP_HTTP_TIMEOUT_MS: intKey(15_000, 1_000, 120_000),
  ATO_IDP_HTTP_MAX_RESPONSE_BYTES: intKey(8_388_608, 65_536, 67_108_864),
  ATO_IDP_MAX_BACKOFF_MS: intKey(900_000, 1_000, 3_600_000),
  ATO_IDP_RATE_GRAPH_PER_SECOND: intKey(5, 1, 1_000),
  ATO_IDP_RATE_O365_PER_SECOND: intKey(2, 1, 1_000),
  ATO_IDP_RATE_GOOGLE_REPORTS_PER_SECOND: intKey(2, 1, 1_000),
  ATO_IDP_RATE_GOOGLE_DIRECTORY_PER_SECOND: intKey(5, 1, 1_000),
  ATO_IDP_RATE_GMAIL_PER_SECOND: intKey(10, 1, 1_000),
  ATO_IDP_PAGE_MAX_EVENTS: intKey(200, 1, 1_000),
  ATO_IDP_CLAIM_BATCH: intKey(10, 1, 100),
  ATO_IDP_SNAPSHOT_MAX_USERS_PER_POLL: intKey(200, 1, 1_000),
  ATO_IDP_GMAIL_TOKEN_CACHE_MAX: intKey(2_000, 10, 100_000),
  ATO_IDP_HEALTH_INTERVAL_SECONDS: intKey(900, 60, 86_400),
  ATO_IDP_STREAM_LAG_WARN_SECONDS: intKey(3_600, 60, 604_800),
  ATO_IDP_BACKFILL_MAX_DAYS: intKey(30, 0, 30),
  ATO_IDP_HISTORICAL_SIGNAL_AGE_HOURS: intKey(24, 1, 720),
  ATO_IDP_CONFIRM_TIMEOUT_MINUTES: intKey(30, 1, 1_440),
  ATO_IDP_MAX_INTEGRATIONS_PER_ORG: intKey(5, 1, 50),
});

export interface IdpAdapterConfig {
  enabled: boolean;
  baseUrls: Readonly<Record<OriginFamily, string>>;
  allowHttpEndpoints: boolean;
  httpTimeoutMs: number;
  httpMaxResponseBytes: number;
  maxBackoffMs: number;
  ratePerSecond: Readonly<Record<ApiFamily, number>>;
  pageMaxEvents: number;
  claimBatch: number;
  snapshotMaxUsersPerPoll: number;
  gmailTokenCacheMax: number;
  healthIntervalSeconds: number;
  streamLagWarnSeconds: number;
  backfillMaxDays: number;
  historicalSignalAgeHours: number;
  confirmTimeoutMinutes: number;
  maxIntegrationsPerOrg: number;
}

export const TEST_ENDPOINT_APP_ENVS: readonly string[] = ['local', 'ci'];

export class IdpConfigError extends Error {
  constructor(
    readonly code:
      | 'ato_idp_config_invalid'
      | 'ato_idp_endpoint_override_refused'
      | 'ato_idp_http_endpoint_refused',
    readonly key?: string,
  ) {
    super(key ? `${code}: ${key}` : code);
    this.name = 'IdpConfigError';
  }
}

/**
 * Schema over `{ env, appEnv, allowHttpEndpoints }` producing `IdpAdapterConfig`. Error messages
 * name keys only, never values.
 */
export const idpAdapterConfigSchema = z
  .object({
    env: z.record(z.string(), z.string().optional()),
    appEnv: z.string().min(1),
    allowHttpEndpoints: z.boolean().default(false),
  })
  .transform((input, ctx): IdpAdapterConfig => {
    const parsed = idpAdapterEnvSchema.safeParse(input.env);
    if (!parsed.success) {
      for (const issue of parsed.error.issues) {
        ctx.addIssue({ code: 'custom', message: `invalid ${issue.path.map(String).join('.')}` });
      }
      return z.NEVER;
    }
    const env = parsed.data;
    const testEnv = TEST_ENDPOINT_APP_ENVS.includes(input.appEnv);
    const allowHttp = input.allowHttpEndpoints && testEnv;
    if (input.allowHttpEndpoints && !testEnv) {
      ctx.addIssue({
        code: 'custom',
        message: 'ato_idp_http_endpoint_refused PROVIDER_ALLOW_HTTP_ENDPOINTS',
      });
      return z.NEVER;
    }
    const baseUrls = {} as Record<OriginFamily, string>;
    for (const family of Object.keys(BASE_URL_KEYS) as OriginFamily[]) {
      const key = BASE_URL_KEYS[family];
      const value = env[key as keyof typeof env] as string;
      if (value !== PRODUCTION_BASE_URLS[family] && !testEnv) {
        ctx.addIssue({ code: 'custom', message: `ato_idp_endpoint_override_refused ${key}` });
        return z.NEVER;
      }
      const protocol = new URL(value).protocol;
      if (protocol !== 'https:' && !(protocol === 'http:' && allowHttp)) {
        ctx.addIssue({ code: 'custom', message: `ato_idp_http_endpoint_refused ${key}` });
        return z.NEVER;
      }
      baseUrls[family] = value;
    }
    return {
      enabled: env.ATO_IDP_ADAPTERS_ENABLED,
      baseUrls,
      allowHttpEndpoints: allowHttp,
      httpTimeoutMs: env.ATO_IDP_HTTP_TIMEOUT_MS,
      httpMaxResponseBytes: env.ATO_IDP_HTTP_MAX_RESPONSE_BYTES,
      maxBackoffMs: env.ATO_IDP_MAX_BACKOFF_MS,
      ratePerSecond: {
        graph: env.ATO_IDP_RATE_GRAPH_PER_SECOND,
        o365: env.ATO_IDP_RATE_O365_PER_SECOND,
        google_reports: env.ATO_IDP_RATE_GOOGLE_REPORTS_PER_SECOND,
        google_directory: env.ATO_IDP_RATE_GOOGLE_DIRECTORY_PER_SECOND,
        gmail: env.ATO_IDP_RATE_GMAIL_PER_SECOND,
      },
      pageMaxEvents: env.ATO_IDP_PAGE_MAX_EVENTS,
      claimBatch: env.ATO_IDP_CLAIM_BATCH,
      snapshotMaxUsersPerPoll: env.ATO_IDP_SNAPSHOT_MAX_USERS_PER_POLL,
      gmailTokenCacheMax: env.ATO_IDP_GMAIL_TOKEN_CACHE_MAX,
      healthIntervalSeconds: env.ATO_IDP_HEALTH_INTERVAL_SECONDS,
      streamLagWarnSeconds: env.ATO_IDP_STREAM_LAG_WARN_SECONDS,
      backfillMaxDays: env.ATO_IDP_BACKFILL_MAX_DAYS,
      historicalSignalAgeHours: env.ATO_IDP_HISTORICAL_SIGNAL_AGE_HOURS,
      confirmTimeoutMinutes: env.ATO_IDP_CONFIRM_TIMEOUT_MINUTES,
      maxIntegrationsPerOrg: env.ATO_IDP_MAX_INTEGRATIONS_PER_ORG,
    };
  });

/** Parses the configuration or throws `IdpConfigError` (refuse to start, D12). */
export function loadIdpAdapterConfig(input: {
  env: Readonly<Record<string, string | undefined>>;
  appEnv: string;
  allowHttpEndpoints?: boolean;
}): IdpAdapterConfig {
  const result = idpAdapterConfigSchema.safeParse({
    env: { ...input.env },
    appEnv: input.appEnv,
    allowHttpEndpoints: input.allowHttpEndpoints ?? false,
  });
  if (result.success) return result.data;
  const message = result.error.issues[0]?.message ?? 'ato_idp_config_invalid';
  const [code, key] = message.split(' ');
  if (code === 'ato_idp_endpoint_override_refused' || code === 'ato_idp_http_endpoint_refused') {
    throw new IdpConfigError(code, key);
  }
  throw new IdpConfigError('ato_idp_config_invalid', message.replace(/^invalid /, ''));
}
