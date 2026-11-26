import {
  amqpUrlListSchema,
  baseConfigSchema,
  databaseConfigSchema,
  loadConfig,
  redisConfigSchema,
  s3ConfigSchema,
} from '@email-gateway/config';
import { z } from 'zod';

const int = (min: number, max: number) => z.coerce.number().int().min(min).max(max);
const flag = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');
const list = z.string().transform((value) =>
  value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0),
);
const hex64 = z.string().regex(/^[0-9a-fA-F]{64}$/, 'must be 64 hexadecimal characters (32 bytes)');
const blankToUndefined = (v: unknown) => (typeof v === 'string' && v.trim() === '' ? undefined : v);
const optionalText = (max: number) =>
  z.preprocess(blankToUndefined, z.string().max(max).optional());
const url = (fallback: string) =>
  z.preprocess(blankToUndefined, z.url().max(512).default(fallback));

/** Roles of one mailbox-worker process (design D5; API-2 adds `remediate`). */
export const MAILBOX_WORKER_ROLES = ['copies', 'feeds', 'inventory', 'health'] as const;
export type MailboxWorkerRole = (typeof MAILBOX_WORKER_ROLES)[number];

const roles = list.transform((entries, ctx): MailboxWorkerRole[] => {
  if (entries.length === 0) {
    ctx.addIssue({
      code: 'custom',
      message: 'must list at least one of copies, feeds, inventory, health',
    });
    return z.NEVER;
  }
  for (const entry of entries) {
    if (!(MAILBOX_WORKER_ROLES as readonly string[]).includes(entry)) {
      ctx.addIssue({
        code: 'custom',
        message: 'may only list copies, feeds, inventory and health',
      });
      return z.NEVER;
    }
  }
  if (new Set(entries).size !== entries.length) {
    ctx.addIssue({ code: 'custom', message: 'lists a role twice' });
    return z.NEVER;
  }
  return entries as MailboxWorkerRole[];
});

/** Environments where http: endpoints and non-production provider origins are allowed. */
export const TEST_ENVIRONMENTS: readonly string[] = ['local', 'ci'];

/** The production provider origins per API family (D16); anything else only in local/ci. */
export const PRODUCTION_PROVIDER_URLS = {
  API_MODE_GRAPH_URL: 'https://graph.microsoft.com',
  API_MODE_GMAIL_URL: 'https://gmail.googleapis.com',
  API_MODE_GOOGLE_ADMIN_URL: 'https://admin.googleapis.com',
} as const;

/**
 * Platform credential keys of the two `mailbox_remediation` profiles (D4, D16; key names of
 * `profiles/mailbox.ts`). Empty = that platform app / service account is unavailable
 * (customer-owned methods still work).
 */
export const MAILBOX_PLATFORM_CREDENTIAL_KEYS = [
  'PROVIDER_M365_MAILBOX_APP_CLIENT_ID',
  'PROVIDER_M365_MAILBOX_APP_CLIENT_SECRET',
  'PROVIDER_M365_MAILBOX_APP_CERT_PATH',
  'PROVIDER_M365_MAILBOX_APP_CERT_THUMBPRINT',
  'PROVIDER_GOOGLE_MAILBOX_SA_CLIENT_ID',
  'PROVIDER_GOOGLE_MAILBOX_SA_KEY_PATH',
] as const;

const platformCredentialShape = Object.fromEntries(
  MAILBOX_PLATFORM_CREDENTIAL_KEYS.map((key) => [key, optionalText(4096)]),
) as Record<(typeof MAILBOX_PLATFORM_CREDENTIAL_KEYS)[number], ReturnType<typeof optionalText>>;

/** Roles that call provider APIs (and therefore decrypt grants). */
export const PROVIDER_CALLING_ROLES: readonly MailboxWorkerRole[] = ['feeds', 'inventory'];

/**
 * mailbox-worker (step API-1 D5, D16; docs/plan/steps/35-api-mode-protection.md, ADR-0100). The
 * MySQL **writer** only (data plane, ADR-0014), Redis (budgets, throttle pauses, counters), its
 * broker user `eg-mailbox` for the copies role, the mail bucket (fetched copies, bounded header
 * reads) and provider HTTPS through `@email-gateway/mailbox-api`. Secrets: the 8.2 credential key
 * (decrypting `*.mailbox_remediation` grants, ADR-0099) and `API_MODE_NOTIFICATION_SECRET`.
 * Messages of refused values name keys, never values.
 */
export const configSchema = baseConfigSchema
  .extend(databaseConfigSchema.shape)
  .extend(redisConfigSchema.shape)
  .extend(s3ConfigSchema.shape)
  .extend({
    /** HTTP port of /health/live, /health/ready and /metrics. */
    MAILBOX_WORKER_HTTP_PORT: int(1, 65_535).default(3087),
    HTTP_HOST: z.string().default('0.0.0.0'),
    MAILBOX_WORKER_ROLES: roles.default([...MAILBOX_WORKER_ROLES]),
    /** amqp(s) URL(s) of the `eg-mailbox` broker user (comma list = cluster nodes). */
    RABBITMQ_MAILBOX_URL: amqpUrlListSchema.optional(),

    // 8.2 credential custody (ADR-0077 as amended by ADR-0099): the provider-calling roles decrypt.
    PROVIDER_CREDENTIAL_ENCRYPTION_KEY: z.preprocess(blankToUndefined, hex64.optional()),
    PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS: z.preprocess(blankToUndefined, hex64.optional()),
    PROVIDER_M365_LOGIN_URL: url('https://login.microsoftonline.com'),
    PROVIDER_M365_GRAPH_URL: url('https://graph.microsoft.com'),
    PROVIDER_GOOGLE_TOKEN_URL: url('https://oauth2.googleapis.com/token'),
    PROVIDER_GOOGLE_ADMIN_URL: url('https://admin.googleapis.com'),
    PROVIDER_ALLOW_HTTP_ENDPOINTS: flag.default(false),
    PROVIDER_M365_ALLOW_PLATFORM_SECRET: flag.default(false),
    ...platformCredentialShape,

    /** Header bytes read for the lag's topmost `Received:` (bounded S3 range GET, D7.8). */
    INGEST_HEADER_MAX_BYTES: int(4096, 1_048_576).default(65_536),

    API_MODE_NOTIFICATION_SECRET: optionalText(256),
    API_MODE_GRAPH_NOTIFICATION_URL: z.preprocess(blankToUndefined, z.url().max(512).optional()),
    API_MODE_GRAPH_URL: url(PRODUCTION_PROVIDER_URLS.API_MODE_GRAPH_URL),
    API_MODE_GMAIL_URL: url(PRODUCTION_PROVIDER_URLS.API_MODE_GMAIL_URL),
    API_MODE_GOOGLE_ADMIN_URL: url(PRODUCTION_PROVIDER_URLS.API_MODE_GOOGLE_ADMIN_URL),
    API_MODE_ALLOW_HTTP_ENDPOINTS: flag.default(false),
    API_MODE_GRAPH_SUBSCRIPTION_MINUTES: int(45, 4230).default(4230),
    API_MODE_SUBSCRIPTION_RENEW_BEFORE_MINUTES: int(5, 4000).default(720),
    API_MODE_FEED_TICK_MS: int(200, 600_000).default(5000),
    API_MODE_FEED_BATCH: int(1, 1000).default(50),
    API_MODE_FEED_POLL_SECONDS: int(10, 86_400).default(300),
    API_MODE_FEED_SAFETY_POLL_SECONDS: int(60, 86_400).default(3600),
    API_MODE_FETCH_CONCURRENCY: int(1, 256).default(16),
    API_MODE_FETCH_CONCURRENCY_PER_CONNECTION: int(1, 64).default(4),
    API_MODE_GRAPH_REQUESTS_PER_SECOND: int(1, 1000).default(8),
    API_MODE_GMAIL_REQUESTS_PER_SECOND: int(1, 1000).default(10),
    API_MODE_DIRECTORY_REQUESTS_PER_SECOND: int(1, 1000).default(5),
    API_MODE_MAX_MESSAGE_BYTES: int(65_536, 157_286_400).default(52_428_800),
    API_MODE_INVENTORY_INTERVAL_HOURS: int(1, 168).default(6),
    API_MODE_MAX_MAILBOXES_PER_CONNECTION: int(1, 1_000_000).default(50_000),
    API_MODE_HEALTH_INTERVAL_MS: int(1000, 3_600_000).default(60_000),
    API_MODE_ALERT_MIN_INTERVAL_HOURS: int(1, 168).default(24),
    API_MODE_JOURNAL_COVERAGE_DAYS: int(1, 90).default(7),
    API_MODE_COVERAGE_WARN_PERCENT: int(1, 100).default(95),
    API_MODE_COVERAGE_FAIL_PERCENT: int(0, 100).default(50),
    API_MODE_LAG_WARN_SECONDS: int(1, 604_800).default(900),
    API_MODE_LAG_FAIL_SECONDS: int(1, 604_800).default(3600),
    API_MODE_THROTTLE_WARN_PER_HOUR: int(0, 1_000_000).default(20),
    API_MODE_DEDUPE_WINDOW_HOURS: int(1, 2160).default(168),
    API_MODE_HYBRID_LINK_WINDOW_HOURS: int(1, 720).default(72),
    API_MODE_COUNTER_FLUSH_SECONDS: int(1, 3600).default(30),
  })
  .superRefine((cfg, ctx) => {
    const testEnv = TEST_ENVIRONMENTS.includes(cfg.APP_ENV);
    const refuse = (path: string, message: string) =>
      ctx.addIssue({ code: 'custom', path: [path], message });
    if (cfg.API_MODE_ALLOW_HTTP_ENDPOINTS && !testEnv) {
      refuse('API_MODE_ALLOW_HTTP_ENDPOINTS', 'is allowed only when APP_ENV is local or ci');
    }
    if (cfg.PROVIDER_ALLOW_HTTP_ENDPOINTS && !testEnv) {
      refuse('PROVIDER_ALLOW_HTTP_ENDPOINTS', 'is allowed only when APP_ENV is local or ci');
    }
    for (const [key, production] of Object.entries(PRODUCTION_PROVIDER_URLS)) {
      const value = cfg[key as keyof typeof PRODUCTION_PROVIDER_URLS];
      let parsed: URL;
      try {
        parsed = new URL(value);
      } catch {
        refuse(key, 'must be a URL');
        continue;
      }
      if (!testEnv && parsed.origin !== production) {
        refuse(key, `must be ${production} unless APP_ENV is local or ci`);
      }
      if (parsed.protocol === 'http:' && !(testEnv && cfg.API_MODE_ALLOW_HTTP_ENDPOINTS)) {
        refuse(key, 'http: needs API_MODE_ALLOW_HTTP_ENDPOINTS=true (local/ci only)');
      } else if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        refuse(key, 'must be an https: URL');
      }
    }
    if (cfg.API_MODE_GRAPH_NOTIFICATION_URL !== undefined) {
      const parsed = new URL(cfg.API_MODE_GRAPH_NOTIFICATION_URL);
      if (parsed.protocol === 'http:' && !testEnv) {
        refuse('API_MODE_GRAPH_NOTIFICATION_URL', 'http: is refused unless APP_ENV is local or ci');
      } else if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        refuse('API_MODE_GRAPH_NOTIFICATION_URL', 'must be an https: URL');
      }
      if (parsed.search !== '' || parsed.hash !== '' || parsed.username || parsed.password) {
        refuse('API_MODE_GRAPH_NOTIFICATION_URL', 'must not carry credentials, a query or a hash');
      }
    }
    const callsProviders = PROVIDER_CALLING_ROLES.some((r) => cfg.MAILBOX_WORKER_ROLES.includes(r));
    if (callsProviders && cfg.PROVIDER_CREDENTIAL_ENCRYPTION_KEY === undefined) {
      refuse(
        'PROVIDER_CREDENTIAL_ENCRYPTION_KEY',
        'is required for the feeds and inventory roles (decrypting mailbox access grants)',
      );
    }
    if (
      cfg.MAILBOX_WORKER_ROLES.includes('feeds') &&
      cfg.API_MODE_GRAPH_NOTIFICATION_URL !== undefined &&
      (cfg.API_MODE_NOTIFICATION_SECRET === undefined ||
        cfg.API_MODE_NOTIFICATION_SECRET.length < 32)
    ) {
      refuse(
        'API_MODE_NOTIFICATION_SECRET',
        'must be set (at least 32 characters) when API_MODE_GRAPH_NOTIFICATION_URL is set',
      );
    }
    if (cfg.MAILBOX_WORKER_ROLES.includes('copies') && cfg.RABBITMQ_MAILBOX_URL === undefined) {
      refuse('RABBITMQ_MAILBOX_URL', 'is required for the copies role');
    }
    if (cfg.API_MODE_COVERAGE_FAIL_PERCENT > cfg.API_MODE_COVERAGE_WARN_PERCENT) {
      refuse('API_MODE_COVERAGE_FAIL_PERCENT', 'must not exceed API_MODE_COVERAGE_WARN_PERCENT');
    }
    if (cfg.API_MODE_LAG_FAIL_SECONDS < cfg.API_MODE_LAG_WARN_SECONDS) {
      refuse('API_MODE_LAG_FAIL_SECONDS', 'must not be below API_MODE_LAG_WARN_SECONDS');
    }
    if (cfg.API_MODE_SUBSCRIPTION_RENEW_BEFORE_MINUTES >= cfg.API_MODE_GRAPH_SUBSCRIPTION_MINUTES) {
      refuse(
        'API_MODE_SUBSCRIPTION_RENEW_BEFORE_MINUTES',
        'must be below API_MODE_GRAPH_SUBSCRIPTION_MINUTES',
      );
    }
  });

export type WorkerConfig = z.infer<typeof configSchema>;

export function loadWorkerConfig(env: NodeJS.ProcessEnv = process.env): Readonly<WorkerConfig> {
  // With NODE_ENV=production and no APP_ENV the worker assumes production, so the local-only
  // switches are never enabled by omission.
  const appEnv = env.APP_ENV?.trim() || (env.NODE_ENV === 'production' ? 'production' : undefined);
  return loadConfig(configSchema, appEnv ? { ...env, APP_ENV: appEnv } : env);
}

export function hasRole(
  cfg: Pick<WorkerConfig, 'MAILBOX_WORKER_ROLES'>,
  role: MailboxWorkerRole,
): boolean {
  return cfg.MAILBOX_WORKER_ROLES.includes(role);
}

export const isTestEnv = (cfg: Pick<WorkerConfig, 'APP_ENV'>): boolean =>
  TEST_ENVIRONMENTS.includes(cfg.APP_ENV);

/** Notifications are used only with a configured URL (D10.4; Microsoft only). */
export const notificationsAvailable = (
  cfg: Pick<WorkerConfig, 'API_MODE_GRAPH_NOTIFICATION_URL' | 'API_MODE_NOTIFICATION_SECRET'>,
): boolean =>
  cfg.API_MODE_GRAPH_NOTIFICATION_URL !== undefined &&
  cfg.API_MODE_NOTIFICATION_SECRET !== undefined;
