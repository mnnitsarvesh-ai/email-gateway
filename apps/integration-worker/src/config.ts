import {
  baseConfigSchema,
  databaseConfigSchema,
  databaseReadConfigSchema,
  httpConfigSchema,
  loadConfig,
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
const hex64 = z.string().regex(/^[0-9a-fA-F]{64}$/, 'must be 64 hex characters');

const HOST_NAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;
const normalizeHost = (value: string): string => value.trim().toLowerCase().replace(/\.$/, '');
const hostName = z
  .string()
  .transform(normalizeHost)
  .refine((v) => HOST_NAME.test(v), 'must be a host name');

/** Roles of one integration-worker process (D11). */
export const INTEGRATION_WORKER_ROLES = ['tasks', 'health', 'maintenance'] as const;
export type IntegrationWorkerRole = (typeof INTEGRATION_WORKER_ROLES)[number];

const roles = list.transform((entries, ctx): IntegrationWorkerRole[] => {
  if (entries.length === 0) {
    ctx.addIssue({
      code: 'custom',
      message: 'must list at least one of tasks, health, maintenance',
    });
    return z.NEVER;
  }
  for (const entry of entries) {
    if (!(INTEGRATION_WORKER_ROLES as readonly string[]).includes(entry)) {
      ctx.addIssue({ code: 'custom', message: 'may only list tasks, health and maintenance' });
      return z.NEVER;
    }
  }
  if (new Set(entries).size !== entries.length) {
    ctx.addIssue({ code: 'custom', message: 'lists a role twice' });
    return z.NEVER;
  }
  return entries as IntegrationWorkerRole[];
});

/** `GATEWAY_MX_HOSTS` (`prio:host,prio:host`, the api's format): the host names. */
export function parseGatewayMxHosts(value: string | undefined): string[] {
  if (value === undefined || value.trim() === '') return [];
  return value.split(',').map((entry) => {
    const trimmed = entry.trim();
    const colon = trimmed.indexOf(':');
    const priority = colon === -1 ? '' : trimmed.slice(0, colon);
    const host = normalizeHost(colon === -1 ? trimmed : trimmed.slice(colon + 1));
    if (!/^\d{1,5}$/.test(priority) || !HOST_NAME.test(host)) {
      throw new Error('GATEWAY_MX_HOSTS entries must be prio:host');
    }
    return host;
  });
}

const mxHosts = z.string().transform((value, ctx): string[] => {
  try {
    const hosts = parseGatewayMxHosts(value);
    if (hosts.length === 0) throw new Error('empty');
    return hosts;
  } catch {
    ctx.addIssue({ code: 'custom', message: 'must be a non-empty prio:host list' });
    return z.NEVER;
  }
});

/** `ip` or `ip:port` / `[v6]:port` resolver addresses (comma list; empty = the system resolver). */
const dnsServers = list.transform((entries, ctx): string[] => {
  for (const entry of entries) {
    if (
      !/^(?:\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?|\[[0-9a-fA-F:]+\](?::\d{1,5})?|[0-9a-fA-F:]+)$/.test(
        entry,
      )
    ) {
      ctx.addIssue({ code: 'custom', message: 'must list IP addresses (optionally with :port)' });
      return z.NEVER;
    }
  }
  return entries;
});

const url = z.string().refine((value) => {
  try {
    const parsed = new URL(value);
    return (parsed.protocol === 'https:' || parsed.protocol === 'http:') && !parsed.search;
  } catch {
    return false;
  }
}, 'must be an http(s) URL without a query string');

const LOCAL_ENVS: ReadonlySet<string> = new Set(['local', 'ci']);

/**
 * integration-worker configuration (step 8.2 §4.4, D2, D10, D11, D15; `.env.example` section
 * "Step 8.2: provider integrations"): the writer (claims, updates, audit, outbox) and the reader
 * (delivery statistics), the credential key (decrypt; the previous key during a rotation), the
 * provider endpoints (https only unless `PROVIDER_ALLOW_HTTP_ENDPOINTS` in local/ci), the
 * platform app and service account of the mail-flow profiles (the worker is their only holder,
 * ADR-0077), the probe domain, the gateway values the checks compare against and every worker
 * bound of §4.4. Start-up errors name keys, never values.
 */
export const configSchema = baseConfigSchema
  .extend(httpConfigSchema(3086).shape)
  .extend(databaseConfigSchema.shape)
  .extend(databaseReadConfigSchema.shape)
  .extend({
    INTEGRATION_WORKER_ROLES: roles.default(['tasks', 'health', 'maintenance']),
    /** HTTP port of /health/live, /health/ready and /metrics (D11). */
    INTEGRATION_WORKER_HTTP_PORT: int(1, 65_535).default(3086),

    // Credential custody (D5, ADR-0077): the worker decrypts.
    PROVIDER_CREDENTIAL_ENCRYPTION_KEY: hex64,
    PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS: hex64.optional(),

    // Provider endpoints (D2): configuration, never tenant input.
    PROVIDER_M365_LOGIN_URL: url.default('https://login.microsoftonline.com'),
    PROVIDER_M365_GRAPH_URL: url.default('https://graph.microsoft.com'),
    PROVIDER_GOOGLE_TOKEN_URL: url.default('https://oauth2.googleapis.com/token'),
    PROVIDER_GOOGLE_ADMIN_URL: url.default('https://admin.googleapis.com'),
    PROVIDER_ALLOW_HTTP_ENDPOINTS: flag.default(false),

    // Platform credentials of the mail-flow profiles (read by key name, platformCredentialsFromEnv).
    PROVIDER_M365_MAILFLOW_APP_CLIENT_ID: z.string().max(128).optional(),
    PROVIDER_M365_MAILFLOW_APP_CLIENT_SECRET: z.string().max(1024).optional(),
    PROVIDER_M365_MAILFLOW_APP_CERT_PATH: z.string().max(1024).optional(),
    PROVIDER_M365_MAILFLOW_APP_CERT_THUMBPRINT: z.string().max(64).optional(),
    PROVIDER_M365_ALLOW_PLATFORM_SECRET: flag.default(false),
    PROVIDER_GOOGLE_MAILFLOW_SA_KEY_PATH: z.string().max(1024).optional(),
    PROVIDER_GOOGLE_MAILFLOW_SA_CLIENT_ID: z.string().max(128).optional(),

    // Probes (D10).
    PROVIDER_PROBE_DOMAIN: hostName.default('probe.mail-gateway.test'),
    PROVIDER_PROBE_TTL_SECONDS: int(300, 7 * 86_400).default(86_400),
    PROVIDER_EGRESS_MAX_AGE_DAYS: int(1, 365).default(45),

    // Tasks (D11).
    INTEGRATION_TASK_POLL_MS: int(200, 60_000).default(2_000),
    INTEGRATION_TASK_CONCURRENCY: int(1, 32).default(4),
    INTEGRATION_TX_TIMEOUT_MS: int(120_000, 600_000).default(120_000),

    // Health (D11, D15).
    INTEGRATION_HEALTH_TICK_SECONDS: int(1, 3_600).default(60),
    INTEGRATION_HEALTH_INTERVAL_SECONDS: int(10, 86_400).default(900),
    INTEGRATION_HEALTH_ERROR_GRACE_MINUTES: int(0, 1_440).default(60),
    INTEGRATION_RELAY_IDLE_WARN_HOURS: int(1, 720).default(72),

    // Provider HTTP (D2).
    INTEGRATION_HTTP_TIMEOUT_MS: int(1_000, 60_000).default(10_000),
    INTEGRATION_HTTP_MAX_RESPONSE_BYTES: int(16_384, 16_777_216).default(1_048_576),

    // SMTP reachability probes (D10).
    INTEGRATION_SMTP_PROBE_TIMEOUT_MS: int(1_000, 120_000).default(15_000),
    INTEGRATION_PROBE_DNS_SERVERS: dnsServers.default([]),
    INTEGRATION_PROBE_HELO: hostName.optional(),
    INTEGRATION_PROBE_CA_PATH: z.string().max(1024).optional(),

    // Gateway values the checks compare against (step 2.1, step 2.3).
    GATEWAY_MX_HOSTS: mxHosts,
    /** SPF `include:` target (labels may start with `_`, e.g. `_spf.example.net`). */
    GATEWAY_SPF_INCLUDE: z
      .string()
      .transform(normalizeHost)
      .refine(
        (v) => /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,62})\.)+[a-z0-9-]{2,63}$/.test(v),
        'must be a DNS name',
      )
      .optional(),
    POSTFIX_MYHOSTNAME: hostName.default('mx.gateway.local'),
    POSTFIX_OUTBOUND_MYHOSTNAME: hostName.default('out.gateway.local'),
    POSTFIX_BOUNCE_DOMAIN: hostName.optional(),
    ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS: flag.default(false),
    ROUTING_DENIED_DESTINATION_SUFFIXES: list.default([]),
  })
  .superRefine((cfg, ctx) => {
    const issue = (path: string, message: string): void =>
      ctx.addIssue({ code: 'custom', path: [path], message });
    const local = LOCAL_ENVS.has(cfg.APP_ENV);
    if (cfg.PROVIDER_ALLOW_HTTP_ENDPOINTS && !local) {
      issue('PROVIDER_ALLOW_HTTP_ENDPOINTS', 'is refused unless APP_ENV is local or ci');
    }
    for (const key of [
      'PROVIDER_M365_LOGIN_URL',
      'PROVIDER_M365_GRAPH_URL',
      'PROVIDER_GOOGLE_TOKEN_URL',
      'PROVIDER_GOOGLE_ADMIN_URL',
    ] as const) {
      if (!cfg.PROVIDER_ALLOW_HTTP_ENDPOINTS && !cfg[key].startsWith('https:')) {
        issue(
          key,
          'must be an https: URL (http: only with PROVIDER_ALLOW_HTTP_ENDPOINTS in local/ci)',
        );
      }
    }
    if (cfg.INTEGRATION_PROBE_CA_PATH !== undefined && !local) {
      issue('INTEGRATION_PROBE_CA_PATH', 'is refused unless APP_ENV is local or ci');
    }
    if (
      cfg.PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS !== undefined &&
      cfg.PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS.toLowerCase() ===
        cfg.PROVIDER_CREDENTIAL_ENCRYPTION_KEY.toLowerCase()
    ) {
      issue('PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS', 'must differ from the current key');
    }
    if (
      cfg.PROVIDER_M365_MAILFLOW_APP_CLIENT_SECRET !== undefined &&
      !cfg.PROVIDER_M365_ALLOW_PLATFORM_SECRET
    ) {
      issue(
        'PROVIDER_M365_MAILFLOW_APP_CLIENT_SECRET',
        'is refused unless PROVIDER_M365_ALLOW_PLATFORM_SECRET=true (use the certificate)',
      );
    }
    if (cfg.INTEGRATION_HEALTH_TICK_SECONDS > cfg.INTEGRATION_HEALTH_INTERVAL_SECONDS) {
      issue(
        'INTEGRATION_HEALTH_TICK_SECONDS',
        'must not exceed INTEGRATION_HEALTH_INTERVAL_SECONDS',
      );
    }
  });

export type WorkerConfig = z.infer<typeof configSchema>;

/** Validates the environment once; refuses to start on any invalid or forbidden key. */
export function loadWorkerConfig(env: NodeJS.ProcessEnv = process.env): Readonly<WorkerConfig> {
  // APP_ENV defaults to `local` in the base schema; with NODE_ENV=production and no APP_ENV the
  // worker assumes production, so the local-only switches are never enabled by omission.
  const appEnv = env.APP_ENV?.trim() || (env.NODE_ENV === 'production' ? 'production' : undefined);
  return loadConfig(configSchema, appEnv ? { ...env, APP_ENV: appEnv } : env);
}

export function hasRole(
  cfg: Pick<WorkerConfig, 'INTEGRATION_WORKER_ROLES'>,
  role: IntegrationWorkerRole,
): boolean {
  return cfg.INTEGRATION_WORKER_ROLES.includes(role);
}

/** True in local and CI (test stand-ins on private Compose networks). */
export const isLocalEnv = (cfg: Pick<WorkerConfig, 'APP_ENV'>): boolean =>
  LOCAL_ENVS.has(cfg.APP_ENV);

/** The EHLO name of SMTP probes (`INTEGRATION_PROBE_HELO`, default the outbound MTA's name). */
export const probeHelo = (
  cfg: Pick<WorkerConfig, 'INTEGRATION_PROBE_HELO' | 'POSTFIX_OUTBOUND_MYHOSTNAME'>,
): string => cfg.INTEGRATION_PROBE_HELO ?? cfg.POSTFIX_OUTBOUND_MYHOSTNAME;
