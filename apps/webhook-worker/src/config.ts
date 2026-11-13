import { isIP } from 'node:net';
import {
  amqpUrlListSchema,
  baseConfigSchema,
  databaseConfigSchema,
  httpConfigSchema,
  loadConfig,
  redisConfigSchema,
} from '@email-gateway/config';
import { parseDialMap, validateTestAllowCidrs } from '@email-gateway/url-security';
import type { WebhookRetryConfig } from '@email-gateway/webhooks';
import { z } from 'zod';

const int = (min: number, max: number) => z.coerce.number().int().min(min).max(max);
const flag = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');
const list = z.string().transform((value) =>
  value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0),
);
const hex64 = z.string().regex(/^[0-9a-fA-F]{64}$/, 'must be exactly 64 hex characters');

/** Roles of one webhook-worker process (W1). */
export const WEBHOOK_WORKER_ROLES = ['fanout', 'delivery'] as const;
export type WebhookWorkerRole = (typeof WEBHOOK_WORKER_ROLES)[number];

const roles = list.transform((entries, ctx): WebhookWorkerRole[] => {
  if (entries.length === 0) {
    ctx.addIssue({ code: 'custom', message: 'must list at least one of fanout, delivery' });
    return z.NEVER;
  }
  for (const entry of entries) {
    if (!(WEBHOOK_WORKER_ROLES as readonly string[]).includes(entry)) {
      ctx.addIssue({ code: 'custom', message: 'may only list fanout and delivery' });
      return z.NEVER;
    }
  }
  if (new Set(entries).size !== entries.length) {
    ctx.addIssue({ code: 'custom', message: 'lists a role twice' });
    return z.NEVER;
  }
  return entries as WebhookWorkerRole[];
});

const ports = list.transform((entries, ctx): number[] => {
  const values = entries.map(Number);
  if (values.length === 0 || values.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) {
    ctx.addIssue({ code: 'custom', message: 'must list ports 1..65535' });
    return z.NEVER;
  }
  return [...new Set(values)];
});

/** `ip`, `ip:port` or `[ipv6]:port` (the restricted resolver's servers). */
function isDnsServer(value: string): boolean {
  if (isIP(value) !== 0) return true;
  const match = /^(\[[0-9a-fA-F:.]+\]|[0-9.]+):(\d{1,5})$/.exec(value);
  if (!match) return false;
  const host = (match[1] as string).replace(/^\[|\]$/g, '');
  const port = Number(match[2]);
  return isIP(host) !== 0 && port >= 1 && port <= 65535;
}

/**
 * Test seams (W9) are accepted only when APP_ENV is `local` or `ci`; `loadWorkerConfig` treats a
 * missing APP_ENV with NODE_ENV=production as production, so a seam is never enabled by omission.
 */
const seamsAllowed = (appEnv: string): boolean => appEnv === 'local' || appEnv === 'ci';

/**
 * webhook-worker configuration (step 6.2 §4.4, docs/plan/steps/19-webhooks-notifications.md;
 * `.env.example` section "Webhooks and notifications"): the writer database, Redis (in-flight and
 * rate counters), the `eg-webhook` broker user, the roles, the fanout, delivery, retry,
 * auto-disable, backlog, replay and maintenance bounds, the guarded POST client (ports, timeouts,
 * resolver, response cap) and its TEST-ONLY seams, and the secret cipher keys (this process
 * decrypts; the api encrypts; nobody else holds them). Start-up errors name keys, never values.
 */
export const configSchema = baseConfigSchema
  .extend(httpConfigSchema(3075).shape)
  .extend(databaseConfigSchema.shape)
  .extend(redisConfigSchema.shape)
  .extend({
    /** amqp(s) URL(s) of the `eg-webhook` broker user (comma list = cluster nodes). */
    RABBITMQ_WEBHOOK_URL: amqpUrlListSchema,
    /** `fanout` (email.webhooks consumer) and/or `delivery` (the database-driven loop). */
    WEBHOOK_WORKER_ROLES: roles.default(['fanout', 'delivery']),

    // Secret custody (W7): decrypt only.
    /** AES-256-GCM key of `secret_ciphertext` (64 hex characters, `_FILE` accepted). */
    WEBHOOK_SECRET_ENCRYPTION_KEY: hex64,
    /** Decrypts only, while rotating WEBHOOK_SECRET_ENCRYPTION_KEY; empty = none. */
    WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS: hex64.optional(),

    // Fanout (W1, W3, W5).
    WEBHOOK_FANOUT_PREFETCH: int(1, 64).default(16),
    /** Budget of one fanout transaction (≥ 120 s, the 4.2 §6 rule). */
    WEBHOOK_FANOUT_TX_TIMEOUT_MS: int(120_000, 600_000).default(120_000),
    WEBHOOK_SUBSCRIPTION_CACHE_SECONDS: int(1, 60).default(5),

    // Delivery loop (W8).
    WEBHOOK_DELIVERY_POLL_INTERVAL_MS: int(100, 10_000).default(500),
    WEBHOOK_DELIVERY_CONCURRENCY: int(1, 256).default(32),
    WEBHOOK_MAX_INFLIGHT_PER_ORG: int(1, 128).default(16),
    WEBHOOK_MAX_INFLIGHT_PER_SUBSCRIPTION: int(1, 32).default(4),
    WEBHOOK_RATE_PER_SUBSCRIPTION_PER_MINUTE: int(1, 6_000).default(600),

    // Guarded POST client (W9).
    /** Destination ports allowed (default 443; local .env 443,80). */
    WEBHOOK_ALLOWED_PORTS: ports.default([443]),
    /** Plain http:// endpoints (TEST-ONLY: refused outside APP_ENV local/ci). */
    WEBHOOK_ALLOW_HTTP: flag.default(false),
    WEBHOOK_HTTP_CONNECT_TIMEOUT_MS: int(500, 10_000).default(3_000),
    WEBHOOK_HTTP_TOTAL_TIMEOUT_MS: int(1_000, 30_000).default(10_000),
    WEBHOOK_RESPONSE_MAX_BYTES: int(256, 65_536).default(4_096),
    /** Restricted resolver servers (`ip`, `ip:port`); empty = the system resolver. */
    WEBHOOK_DNS_SERVERS: list.default([]),

    // Retries and dead letters (W10).
    WEBHOOK_MAX_ATTEMPTS: int(1, 15).default(8),
    WEBHOOK_RETRY_BASE_SECONDS: int(1, 600).default(30),
    WEBHOOK_RETRY_MAX_DELAY_SECONDS: int(60, 86_400).default(21_600),
    WEBHOOK_RETRY_AFTER_MAX_SECONDS: int(1, 86_400).default(3_600),
    WEBHOOK_MAX_RETRY_AGE_HOURS: int(1, 72).default(24),
    WEBHOOK_MAX_PENDING_PER_SUBSCRIPTION: int(1_000, 1_000_000).default(50_000),

    // Auto-disable (W11).
    WEBHOOK_DISABLE_AFTER_FAILURES: int(5, 10_000).default(50),
    WEBHOOK_DISABLE_AFTER_HOURS: int(1, 168).default(24),

    // Replay and maintenance (W12, W13).
    WEBHOOK_REPLAY_MAX_EVENTS: int(1, 100_000).default(10_000),
    /** Replays of one event per subscription (shared with the api's single replay, W12). */
    WEBHOOK_REPLAY_MAX_PER_DELIVERY: int(1, 50).default(10),
    WEBHOOK_MAINTENANCE_INTERVAL_MS: int(10_000, 3_600_000).default(60_000),
    WEBHOOK_DELETED_RETENTION_DAYS: int(62, 365).default(62),

    // TEST-ONLY seams (refused outside APP_ENV local/ci).
    /** Documentation ranges only (`validateTestAllowCidrs`); local: 203.0.113.0/24. */
    WEBHOOK_TEST_ALLOW_CIDRS: list.default([]),
    /** `ip:port=host:port,…` after the guard validated the address. */
    WEBHOOK_TEST_DIAL_MAP: z.string().optional(),
    /** Extra trusted CA (PEM path); local: the test-pki CA. */
    WEBHOOK_EXTRA_CA_PATH: z.string().min(1).optional(),
  })
  .superRefine((cfg, ctx) => {
    const issue = (path: string, message: string): void =>
      ctx.addIssue({ code: 'custom', path: [path], message });
    if (cfg.WEBHOOK_RETRY_BASE_SECONDS > cfg.WEBHOOK_RETRY_MAX_DELAY_SECONDS) {
      issue('WEBHOOK_RETRY_BASE_SECONDS', 'must not exceed WEBHOOK_RETRY_MAX_DELAY_SECONDS');
    }
    if (cfg.WEBHOOK_HTTP_CONNECT_TIMEOUT_MS >= cfg.WEBHOOK_HTTP_TOTAL_TIMEOUT_MS) {
      issue('WEBHOOK_HTTP_CONNECT_TIMEOUT_MS', 'must be below WEBHOOK_HTTP_TOTAL_TIMEOUT_MS');
    }
    if (
      cfg.WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS !== undefined &&
      cfg.WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS.toLowerCase() ===
        cfg.WEBHOOK_SECRET_ENCRYPTION_KEY.toLowerCase()
    ) {
      issue('WEBHOOK_SECRET_ENCRYPTION_KEY_PREVIOUS', 'must differ from the current key');
    }
    if (cfg.WEBHOOK_DNS_SERVERS.some((server) => !isDnsServer(server))) {
      issue('WEBHOOK_DNS_SERVERS', 'must list IP addresses (optionally with :port)');
    }
    const env = { nodeEnv: cfg.NODE_ENV, appEnv: cfg.APP_ENV };
    if (!seamsAllowed(cfg.APP_ENV)) {
      const refused = 'is a test seam and is refused outside APP_ENV local/ci';
      if (cfg.WEBHOOK_ALLOW_HTTP) issue('WEBHOOK_ALLOW_HTTP', refused);
      if (cfg.WEBHOOK_TEST_ALLOW_CIDRS.length > 0) issue('WEBHOOK_TEST_ALLOW_CIDRS', refused);
      if (cfg.WEBHOOK_TEST_DIAL_MAP) issue('WEBHOOK_TEST_DIAL_MAP', refused);
      if (cfg.WEBHOOK_EXTRA_CA_PATH) issue('WEBHOOK_EXTRA_CA_PATH', refused);
      return;
    }
    try {
      validateTestAllowCidrs(cfg.WEBHOOK_TEST_ALLOW_CIDRS, env);
    } catch {
      issue('WEBHOOK_TEST_ALLOW_CIDRS', 'may only contain documentation ranges');
    }
    try {
      parseDialMap(cfg.WEBHOOK_TEST_DIAL_MAP, env);
    } catch {
      issue('WEBHOOK_TEST_DIAL_MAP', 'invalid dial map');
    }
  });

export type WorkerConfig = z.infer<typeof configSchema>;

/** Validates the environment once; refuses to start on any invalid or forbidden key. */
export function loadWorkerConfig(env: NodeJS.ProcessEnv = process.env): Readonly<WorkerConfig> {
  // APP_ENV defaults to `local` in the shared base schema; with NODE_ENV=production and no APP_ENV
  // the worker assumes production, so the test seams are never enabled by omission.
  const appEnv = env.APP_ENV?.trim() || (env.NODE_ENV === 'production' ? 'production' : undefined);
  return loadConfig(configSchema, appEnv ? { ...env, APP_ENV: appEnv } : env);
}

/** The retry schedule of `@email-gateway/webhooks` from the configuration (W10). */
export function webhookRetryConfig(cfg: Readonly<WorkerConfig>): WebhookRetryConfig {
  return {
    baseSeconds: cfg.WEBHOOK_RETRY_BASE_SECONDS,
    maxDelaySeconds: cfg.WEBHOOK_RETRY_MAX_DELAY_SECONDS,
    retryAfterMaxSeconds: cfg.WEBHOOK_RETRY_AFTER_MAX_SECONDS,
    maxAttempts: cfg.WEBHOOK_MAX_ATTEMPTS,
    maxRetryAgeHours: cfg.WEBHOOK_MAX_RETRY_AGE_HOURS,
  };
}

/** True when this process runs `role` (W1: Compose runs both, Kubernetes one per Deployment). */
export function hasRole(
  cfg: Pick<WorkerConfig, 'WEBHOOK_WORKER_ROLES'>,
  role: WebhookWorkerRole,
): boolean {
  return cfg.WEBHOOK_WORKER_ROLES.includes(role);
}
