import {
  amqpUrlListSchema,
  baseConfigSchema,
  databaseConfigSchema,
  httpConfigSchema,
  loadConfig,
  redisConfigSchema,
} from '@email-gateway/config';
import { idpAdapterEnvSchema, loadIdpAdapterConfig } from '@email-gateway/idp-adapters';
import { parseDnsblZones } from '@email-gateway/url-security';
import { z } from 'zod';

const int = (min: number, max: number) => z.coerce.number().int().min(min).max(max);
const flag = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');
const list = z.string().transform((value) =>
  value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0),
);

/** Roles of one ato-worker process (step 8.4 D3). */
export const ATO_WORKER_ROLES = ['detect', 'respond', 'maintenance', 'provider'] as const;
export type AtoWorkerRole = (typeof ATO_WORKER_ROLES)[number];

const roles = list.transform((entries, ctx): AtoWorkerRole[] => {
  if (entries.length === 0) {
    ctx.addIssue({
      code: 'custom',
      message: 'must list at least one of detect, respond, maintenance, provider',
    });
    return z.NEVER;
  }
  for (const entry of entries) {
    if (!(ATO_WORKER_ROLES as readonly string[]).includes(entry)) {
      ctx.addIssue({
        code: 'custom',
        message: 'may only list detect, respond, maintenance and provider',
      });
      return z.NEVER;
    }
  }
  if (new Set(entries).size !== entries.length) {
    ctx.addIssue({ code: 'custom', message: 'lists a role twice' });
    return z.NEVER;
  }
  return entries as AtoWorkerRole[];
});

/** `ip`, `ip:port` or `[v6]:port` (the restricted resolver's syntax); empty = system resolver. */
const DNS_SERVER =
  /^(\d{1,3}(\.\d{1,3}){3}(:\d{1,5})?|\[[0-9a-fA-F:]+\](:\d{1,5})?|[0-9a-fA-F:]+)$/;

/** Environments where test seams (documentation ranges, the fake provider) are allowed. */
const TEST_ENVIRONMENTS = ['local', 'ci'];

const hex64 = z.string().regex(/^[0-9a-fA-F]{64}$/, 'must be 64 hexadecimal characters (32 bytes)');
const optionalText = (max: number) =>
  z.preprocess(
    (v) => (typeof v === 'string' && v.trim() === '' ? undefined : v),
    z.string().max(max).optional(),
  );
const providerUrl = (fallback: string) =>
  z.preprocess(
    (v) => (typeof v === 'string' && v.trim() === '' ? undefined : v),
    z.url().max(512).default(fallback),
  );

/**
 * Operator-provided platform credentials of the six ATO permission profiles (step 8.5 D5, §4.2;
 * key names of `profiles/ato.ts` `platformApp`, deviation WP3-6). Empty = that platform app or
 * service account is unavailable (customer-owned methods still work). Read only where a role
 * that calls providers runs (`ato-respond` in Kubernetes, R3).
 */
export const ATO_PLATFORM_CREDENTIAL_KEYS = [
  'PROVIDER_M365_ATO_TELEMETRY_APP_CLIENT_ID',
  'PROVIDER_M365_ATO_TELEMETRY_APP_CLIENT_SECRET',
  'PROVIDER_M365_ATO_TELEMETRY_APP_CERT_PATH',
  'PROVIDER_M365_ATO_TELEMETRY_APP_CERT_THUMBPRINT',
  'PROVIDER_M365_ATO_RESPONSE_APP_CLIENT_ID',
  'PROVIDER_M365_ATO_RESPONSE_APP_CLIENT_SECRET',
  'PROVIDER_M365_ATO_RESPONSE_APP_CERT_PATH',
  'PROVIDER_M365_ATO_RESPONSE_APP_CERT_THUMBPRINT',
  'PROVIDER_M365_ATO_RESPONSE_EXTENDED_APP_CLIENT_ID',
  'PROVIDER_M365_ATO_RESPONSE_EXTENDED_APP_CLIENT_SECRET',
  'PROVIDER_M365_ATO_RESPONSE_EXTENDED_APP_CERT_PATH',
  'PROVIDER_M365_ATO_RESPONSE_EXTENDED_APP_CERT_THUMBPRINT',
  'PROVIDER_GOOGLE_ATO_TELEMETRY_SA_KEY_PATH',
  'PROVIDER_GOOGLE_ATO_TELEMETRY_SA_CLIENT_ID',
  'PROVIDER_GOOGLE_ATO_RESPONSE_SA_KEY_PATH',
  'PROVIDER_GOOGLE_ATO_RESPONSE_SA_CLIENT_ID',
  'PROVIDER_GOOGLE_ATO_RESPONSE_EXTENDED_SA_KEY_PATH',
  'PROVIDER_GOOGLE_ATO_RESPONSE_EXTENDED_SA_CLIENT_ID',
] as const;

const platformCredentialShape = Object.fromEntries(
  ATO_PLATFORM_CREDENTIAL_KEYS.map((key) => [key, optionalText(4096)]),
) as Record<(typeof ATO_PLATFORM_CREDENTIAL_KEYS)[number], ReturnType<typeof optionalText>>;

/** Roles that call identity providers (polls, probes, actions, confirmations). */
export const PROVIDER_CALLING_ROLES = ['provider', 'respond', 'maintenance'] as const;

/**
 * ato-worker (step 8.4 §4.2, D3, D7, D8, D13, D15, D16, D22; docs/plan/steps/24-account-takeover-core.md).
 * The MySQL **writer** only (data plane, ADR-0014), Redis (windows, attribution, the namespaced
 * reputation cache), its broker user `eg-ato` (`RABBITMQ_ATO_URL`: read `ato.events`, `ato.mail`,
 * `ato.responses`; write retry and dead-letter copies) for the detect and respond roles, the
 * operator-provided GeoIP databases (optional; honest `unavailable` without them) and the bounded
 * tuning knobs. Test seams (`ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES`, `ATO_PROVIDER_FAKE_ENABLED`) are
 * refused unless `APP_ENV` is `local` or `ci`.
 */
export const configSchema = baseConfigSchema
  .extend(httpConfigSchema(3085).shape)
  .extend(databaseConfigSchema.shape)
  .extend(redisConfigSchema.shape)
  .extend({
    /** amqp(s) URL(s) of the `eg-ato` broker user (comma list = cluster nodes). */
    RABBITMQ_ATO_URL: amqpUrlListSchema.optional(),
    ATO_WORKER_ROLES: roles.default([...ATO_WORKER_ROLES]),
    ATO_EVENTS_PREFETCH: int(1, 256).default(32),
    ATO_MAIL_PREFETCH: int(1, 256).default(32),
    ATO_RESPONSES_PREFETCH: int(1, 64).default(4),
    /** Budget of every writer transaction (≥ 120 s, the 4.2 §6 wrong-read rule). */
    ATO_TX_TIMEOUT_MS: int(120_000, 600_000).default(120_000),
    /** Per-organization feature/mode/time-zone cache of the no-op fast paths. */
    ATO_SETTINGS_CACHE_SECONDS: int(1, 600).default(30),
    /** HMAC key of Redis members (recipient domains, subject keys, attempted e-mails) and of the
     * `ato` reputation cache namespace. Secret, ≥ 32 characters. */
    ATO_HMAC_KEY: z.string().min(32, 'ATO_HMAC_KEY must be at least 32 characters'),
    ATO_GEOIP_CITY_DB_PATH: z.string().min(1).optional(),
    ATO_GEOIP_ASN_DB_PATH: z.string().min(1).optional(),
    ATO_GEOIP_ANONYMOUS_DB_PATH: z.string().min(1).optional(),
    ATO_GEOIP_RELOAD_SECONDS: int(60, 86_400).default(3600),
    ATO_GEOIP_MAX_AGE_DAYS: int(1, 365).default(35),
    /** Tests only: geolocate RFC 5737 / RFC 3849 documentation ranges (synthetic database). */
    ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES: flag.default(false),
    /** DNSBL zones of exploited hosts only (`zone=code:category[,…]` separated by `;`). */
    ATO_DNSBL_IP_ZONES: z.string().min(1).optional(),
    ATO_DNS_SERVERS: list.default([]),
    ATO_REPUTATION_TIMEOUT_MS: int(100, 10_000).default(1500),
    ATO_IP_CAMPAIGN_MIN_ACCOUNTS: int(2, 1000).default(10),
    ATO_IP_CAMPAIGN_WINDOW_MINUTES: int(10, 240).default(60),
    ATO_IP_CAMPAIGN_FLAG_HOURS: int(1, 168).default(24),
    ATO_AUTOMATED_RESPONSES_ENABLED: flag.default(true),
    ATO_MAX_AUTOMATED_RESPONSES_PER_ORG_PER_HOUR: int(0, 100).default(10),
    ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG: int(1, 5000).default(500),
    ATO_APPROVAL_TTL_HOURS: int(1, 168).default(24),
    ATO_DECAY_SWEEP_INTERVAL_SECONDS: int(60, 86_400).default(900),
    ATO_BASELINE_REBUILD_HOUR_UTC: int(0, 23).default(2),
    ATO_BASELINE_BATCH: int(10, 10_000).default(500),
    ATO_MAINTENANCE_INTERVAL_SECONDS: int(10, 3600).default(60),
    ATO_RETENTION_INCIDENT_DAYS: int(30, 3650).default(730),
    ATO_MAIL_CATCHUP_INTERVAL_SECONDS: int(30, 86_400).default(600),
    ATO_MAIL_CATCHUP_LAG_SECONDS: int(60, 86_400).default(900),
    ATO_MAIL_CATCHUP_BATCH: int(10, 10_000).default(1000),
    ATO_MAIL_CATCHUP_MAX_AGE_HOURS: int(1, 720).default(24),
    /** Local and CI only: register the fake identity provider adapter (D15). */
    ATO_PROVIDER_FAKE_ENABLED: flag.default(false),
    ATO_PROVIDER_POLL_INTERVAL_SECONDS: int(10, 3600).default(60),
    ATO_PROVIDER_MAX_PAGES_PER_POLL: int(1, 100).default(10),
    ATO_PROVIDER_MAX_CONSECUTIVE_FAILURES: int(1, 100).default(10),
    ATO_DIGEST_ENABLED: flag.default(true),

    // Step 8.5 identity-provider adapters (§4.2, D2, D12; ADR-0082, ADR-0086): the ATO_IDP_* keys
    // of @email-gateway/idp-adapters (endpoint override rule checked below).
    ...idpAdapterEnvSchema.shape,
    // 8.2's credential custody (R3): decrypts customer-owned ATO credentials; the previous key
    // only during a rotation. Required where a provider-calling role runs with the adapters on.
    PROVIDER_CREDENTIAL_ENCRYPTION_KEY: z.preprocess(
      (v) => (typeof v === 'string' && v.trim() === '' ? undefined : v),
      hex64.optional(),
    ),
    PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS: z.preprocess(
      (v) => (typeof v === 'string' && v.trim() === '' ? undefined : v),
      hex64.optional(),
    ),
    // 8.2's token endpoints (tokens through 8.2's token service, §0.4) and the Office 365
    // Management token resource (R1).
    PROVIDER_M365_LOGIN_URL: providerUrl('https://login.microsoftonline.com'),
    PROVIDER_M365_GRAPH_URL: providerUrl('https://graph.microsoft.com'),
    PROVIDER_M365_MANAGEMENT_URL: providerUrl('https://manage.office.com'),
    PROVIDER_GOOGLE_TOKEN_URL: providerUrl('https://oauth2.googleapis.com/token'),
    PROVIDER_GOOGLE_ADMIN_URL: providerUrl('https://admin.googleapis.com'),
    PROVIDER_ALLOW_HTTP_ENDPOINTS: flag.default(false),
    PROVIDER_M365_ALLOW_PLATFORM_SECRET: flag.default(false),
    ...platformCredentialShape,
  })
  .superRefine((cfg, ctx) => {
    const testEnv = TEST_ENVIRONMENTS.includes(cfg.APP_ENV);
    if (cfg.ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES && !testEnv) {
      ctx.addIssue({
        code: 'custom',
        path: ['ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES'],
        message: 'is allowed only when APP_ENV is local or ci (synthetic test databases)',
      });
    }
    if (cfg.ATO_PROVIDER_FAKE_ENABLED && !testEnv) {
      ctx.addIssue({
        code: 'custom',
        path: ['ATO_PROVIDER_FAKE_ENABLED'],
        message: 'is allowed only when APP_ENV is local or ci',
      });
    }
    const needsBroker =
      cfg.ATO_WORKER_ROLES.includes('detect') || cfg.ATO_WORKER_ROLES.includes('respond');
    if (needsBroker && (cfg.RABBITMQ_ATO_URL === undefined || cfg.RABBITMQ_ATO_URL.length === 0)) {
      ctx.addIssue({
        code: 'custom',
        path: ['RABBITMQ_ATO_URL'],
        message: 'is required for the detect and respond roles',
      });
    }
    if (cfg.ATO_DNSBL_IP_ZONES !== undefined) {
      try {
        if (parseDnsblZones(cfg.ATO_DNSBL_IP_ZONES).length === 0) {
          ctx.addIssue({
            code: 'custom',
            path: ['ATO_DNSBL_IP_ZONES'],
            message: 'lists no zone',
          });
        }
      } catch (error) {
        ctx.addIssue({
          code: 'custom',
          path: ['ATO_DNSBL_IP_ZONES'],
          message: error instanceof Error ? error.message : 'is malformed',
        });
      }
    }
    // Step 8.5 (D2, D12): endpoint overrides only in local/ci, http only with
    // PROVIDER_ALLOW_HTTP_ENDPOINTS (itself local/ci only). Messages name keys, never values.
    if (cfg.PROVIDER_ALLOW_HTTP_ENDPOINTS && !testEnv) {
      ctx.addIssue({
        code: 'custom',
        path: ['PROVIDER_ALLOW_HTTP_ENDPOINTS'],
        message: 'is allowed only when APP_ENV is local or ci',
      });
    }
    try {
      loadIdpAdapterConfig({
        env: idpEnvOf(cfg),
        appEnv: cfg.APP_ENV,
        allowHttpEndpoints: cfg.PROVIDER_ALLOW_HTTP_ENDPOINTS && testEnv,
      });
    } catch (error) {
      const key = (error as { key?: unknown }).key;
      ctx.addIssue({
        code: 'custom',
        path: [
          typeof key === 'string' && /^[A-Z0-9_]+$/.test(key) ? key : 'ATO_IDP_ADAPTERS_ENABLED',
        ],
        message: `refused: ${(error as { code?: string }).code ?? 'ato_idp_config_invalid'} (production origins only outside local/ci; https only)`,
      });
    }
    const callsProviders = PROVIDER_CALLING_ROLES.some((r) => cfg.ATO_WORKER_ROLES.includes(r));
    if (
      cfg.ATO_IDP_ADAPTERS_ENABLED &&
      callsProviders &&
      cfg.PROVIDER_CREDENTIAL_ENCRYPTION_KEY === undefined
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['PROVIDER_CREDENTIAL_ENCRYPTION_KEY'],
        message:
          'is required for the provider, respond and maintenance roles while ATO_IDP_ADAPTERS_ENABLED is true',
      });
    }
    for (const [index, server] of cfg.ATO_DNS_SERVERS.entries()) {
      if (!DNS_SERVER.test(server)) {
        ctx.addIssue({
          code: 'custom',
          path: ['ATO_DNS_SERVERS'],
          message: `entry ${index + 1} is not ip, ip:port or [v6]:port`,
        });
      }
    }
  });

export type WorkerConfig = z.infer<typeof configSchema>;

/** The `ATO_IDP_*` values of a parsed configuration as the adapter configuration reads them. */
export function idpEnvOf(cfg: Record<string, unknown>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of Object.keys(idpAdapterEnvSchema.shape)) {
    const value = cfg[key];
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      env[key] = String(value);
    }
  }
  return env;
}

/** Whether this process runs a role that calls identity providers with the adapters on (R3). */
export const callsIdentityProviders = (
  config: Pick<WorkerConfig, 'ATO_WORKER_ROLES' | 'ATO_IDP_ADAPTERS_ENABLED'>,
): boolean =>
  config.ATO_IDP_ADAPTERS_ENABLED &&
  PROVIDER_CALLING_ROLES.some((role) => config.ATO_WORKER_ROLES.includes(role));

export const loadWorkerConfig = (env: NodeJS.ProcessEnv = process.env): Readonly<WorkerConfig> =>
  loadConfig(configSchema, env);

export const hasRole = (config: Pick<WorkerConfig, 'ATO_WORKER_ROLES'>, role: AtoWorkerRole) =>
  config.ATO_WORKER_ROLES.includes(role);
