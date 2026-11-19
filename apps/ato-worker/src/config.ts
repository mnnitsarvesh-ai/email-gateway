import {
  amqpUrlListSchema,
  baseConfigSchema,
  databaseConfigSchema,
  httpConfigSchema,
  loadConfig,
  redisConfigSchema,
} from '@email-gateway/config';
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

export const loadWorkerConfig = (env: NodeJS.ProcessEnv = process.env): Readonly<WorkerConfig> =>
  loadConfig(configSchema, env);

export const hasRole = (config: Pick<WorkerConfig, 'ATO_WORKER_ROLES'>, role: AtoWorkerRole) =>
  config.ATO_WORKER_ROLES.includes(role);
