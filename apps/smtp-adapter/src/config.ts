import {
  baseConfigSchema,
  databaseConfigSchema,
  httpConfigSchema,
  loadConfig,
  redisConfigSchema,
  s3ConfigSchema,
} from '@email-gateway/config';
import {
  parseAllowedDestinationPorts,
  type ValidateDestinationHostOptions,
} from '@email-gateway/mail-routing';
import { z } from 'zod';
import { bouncesConfigShape } from './bounces/bounces.config';
import { ingestionConfigShape } from './ingestion/ingestion.config';
import { parseNetworkList } from './shared/internal-networks';

const port = z.coerce.number().int().min(1).max(65535);
const nonNegativeInt = z.coerce.number().int().min(0);
const positiveInt = z.coerce.number().int().min(1);
const flag = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');

/** Loopback + RFC 1918 (step 2.2 §5, D20). */
export const DEFAULT_INTERNAL_CLIENT_NETWORKS =
  '127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16';

const HOST_NAME =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

/** Lower-case, no trailing dot: the form compared by the transport self-routing guard. */
export function normalizeHostName(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * Host names of `GATEWAY_MX_HOSTS` (`prio:host,prio:host`, the format the api publishes in the
 * domain onboarding instructions). Only the host names matter here: the transport socketmap
 * never routes a tenant domain to one of the gateway's own hosts (D11). Throws on invalid input.
 */
export function parseGatewayMxHosts(value: string | undefined): string[] {
  if (value === undefined || value.trim() === '') return [];
  return value.split(',').map((entry) => {
    const trimmed = entry.trim();
    const colon = trimmed.indexOf(':');
    const priority = colon === -1 ? '' : trimmed.slice(0, colon);
    const host = normalizeHostName(colon === -1 ? trimmed : trimmed.slice(colon + 1));
    if (!/^\d{1,5}$/.test(priority) || !HOST_NAME.test(host) || host.length > 253) {
      throw new Error(`Invalid GATEWAY_MX_HOSTS entry "${trimmed}" (expected prio:host)`);
    }
    return host;
  });
}

const validNetworkList = (value: string): boolean => {
  try {
    parseNetworkList(value);
    return true;
  } catch {
    return false;
  }
};

const validMxHosts = (value: string): boolean => {
  try {
    parseGatewayMxHosts(value);
    return true;
  } catch {
    return false;
  }
};

const hostName = z
  .string()
  .transform(normalizeHostName)
  .refine((v) => HOST_NAME.test(v) && v.length <= 253, 'must be a host name');

/** In-session services (policy, socketmap, SASL) and caches of step 2.2 (§5). */
export const inSessionConfigShape = {
  POLICY_PORT: port.default(10040),
  POLICY_HOST: z.string().default('0.0.0.0'),
  SOCKETMAP_PORT: port.default(10041),
  SASL_AUTH_PORT: port.default(10042),
  /** Bind address of the socketmap, SASL and LMTP listeners (D20). */
  MAIL_LISTEN_HOST: z.string().default('0.0.0.0'),
  /** Peers allowed on every internal listener (comma-separated CIDRs, D20). */
  SMTP_INTERNAL_CLIENT_NETWORKS: z
    .string()
    .default(DEFAULT_INTERNAL_CLIENT_NETWORKS)
    .refine(validNetworkList, 'must be a comma-separated list of IPv4/IPv6 CIDRs'),

  SMTP_DOMAIN_CACHE_TTL_SECONDS: positiveInt.max(3600).default(60),
  SMTP_NEGATIVE_CACHE_TTL_SECONDS: positiveInt.max(3600).default(30),
  /** Outbox tail interval of the domain cache invalidator; 0 disables it (TTL only). */
  SMTP_CACHE_INVALIDATION_POLL_MS: nonNegativeInt.max(600_000).default(5000),
  /** Overall budget of one policy decision; exceeded → tempfail (Postfix waits up to 10 s). */
  SMTP_POLICY_DECISION_TIMEOUT_MS: positiveInt.max(9000).default(3000),

  SMTP_RATE_CLIENT_RCPT_PER_MINUTE: nonNegativeInt.default(3000),
  SMTP_RATE_TENANT_INBOUND_RCPT_PER_MINUTE: nonNegativeInt.default(6000),
  SMTP_RATE_TENANT_OUTBOUND_RCPT_PER_MINUTE: nonNegativeInt.default(600),
  SMTP_RATE_TENANT_OUTBOUND_RCPT_PER_DAY: nonNegativeInt.default(100_000),

  /**
   * Address extension delimiter characters (like Postfix `recipient_delimiter`): the allow-list
   * lookup retries with the part before the first of them. An explicitly empty value disables
   * the retry (see `loadSmtpAdapterConfig`).
   */
  SMTP_RECIPIENT_DELIMITER: z
    .string()
    .max(8)
    .refine((v) => !/[\s@"\\\0]/.test(v), 'must not contain whitespace, @, quotes or backslashes')
    .default('+'),
  /** Refuse outbound mail of sender domains without an active DKIM key (D11 step 4). */
  SMTP_OUTBOUND_REQUIRE_DKIM: flag.default(true),

  SMTP_AUTH_FAILURE_DELAY_MS: nonNegativeInt.max(30_000).default(2000),
  SMTP_AUTH_MAX_FAILURES_PER_IP: positiveInt.default(20),
  SMTP_AUTH_FAILURE_WINDOW_SECONDS: positiveInt.max(86_400).default(900),
  /** Process-local cache of successful Argon2id verifications; 0 disables it. */
  SMTP_AUTH_VERIFY_CACHE_SECONDS: nonNegativeInt.max(3600).default(300),

  /** redis-dkim probe account (`dkim-probe`). Unset: signing is never ready (10027 defers). */
  REDIS_DKIM_PROBE_URL: z
    .string()
    .regex(/^rediss?:\/\//, 'REDIS_DKIM_PROBE_URL must be a redis(s):// URL')
    .optional(),

  /** `prio:host` list; only the host names are used (transport self-routing guard). */
  GATEWAY_MX_HOSTS: z.string().refine(validMxHosts, 'must be a prio:host list').optional(),
  POSTFIX_MYHOSTNAME: hostName.default('mx.gateway.local'),
  POSTFIX_OUTBOUND_MYHOSTNAME: hostName.default('out.gateway.local'),
};

/** A DNS suffix of `ROUTING_DENIED_DESTINATION_SUFFIXES` (leading dot optional). */
const DENIED_SUFFIX =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

/**
 * `ROUTING_DENIED_DESTINATION_SUFFIXES`: comma-separated DNS suffixes, lower-cased, without a
 * leading or trailing dot (`.test, example` → `['test', 'example']`). Throws on invalid input.
 */
export function parseDeniedSuffixes(value: string | undefined): string[] {
  if (value === undefined || value.trim() === '') return [];
  return value.split(',').flatMap((entry) => {
    const suffix = entry.trim().toLowerCase().replace(/^\./, '').replace(/\.$/, '');
    if (suffix === '') return [];
    if (!DENIED_SUFFIX.test(suffix) || suffix.length > 253) {
      throw new Error(`Invalid ROUTING_DENIED_DESTINATION_SUFFIXES entry "${entry.trim()}"`);
    }
    return [suffix];
  });
}

const validSuffixList = (value: string): boolean => {
  try {
    parseDeniedSuffixes(value);
    return true;
  } catch {
    return false;
  }
};

/**
 * Destination host safety (step 2.3 R2, R3): re-validation of every destination server before
 * the transport map answers Postfix. Same keys and defaults as the api, which validates on write.
 */
export const routingConfigShape = {
  /** Accept non-public IP literals as destinations (dedicated deployments); never metadata. */
  ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS: flag.default(false),
  /** Extra refused destination suffixes (comma list), on top of the built-in internal names. */
  ROUTING_DENIED_DESTINATION_SUFFIXES: z
    .string()
    .default('')
    .refine(validSuffixList, 'must be a comma-separated list of DNS suffixes')
    .transform(parseDeniedSuffixes),
  /** Ports a custom destination may use (default 25,587,2525; internal gateway ports never). */
  ROUTING_ALLOWED_DESTINATION_PORTS: z
    .string()
    .default('')
    .refine((value) => {
      try {
        parseAllowedDestinationPorts(value);
        return true;
      } catch {
        return false;
      }
    }, 'must be a comma-separated list of ports (internal gateway ports are refused)')
    .transform(parseAllowedDestinationPorts),
  /** Next hops per domain in a transport answer (the api allows as many servers). */
  ROUTING_MAX_DESTINATIONS_PER_DOMAIN: positiveInt.max(10).default(10),
};

export const configSchema = baseConfigSchema
  .extend(httpConfigSchema(3010).shape)
  .extend(databaseConfigSchema.shape)
  .extend(redisConfigSchema.shape)
  .extend(s3ConfigSchema.shape)
  .extend(inSessionConfigShape)
  .extend(ingestionConfigShape)
  .extend(bouncesConfigShape)
  .extend(routingConfigShape);

export type SmtpAdapterConfig = z.infer<typeof configSchema>;

/**
 * Only the adapter's own keys (and their `<KEY>_FILE` secret indirections) are handed to
 * `loadConfig`. The shared `.env` holds many keys of other services; a foreign key that ends in
 * `_FILE` would otherwise be read as a secret file of this service and fail on the host. (The
 * Postfix certificate paths were renamed to `POSTFIX_*TLS_*_PATH` in step 2.2 WP6 for the same
 * reason; this filter stays as a defence for any other service's keys.)
 */
function ownEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const keys = new Set(Object.keys(configSchema.shape));
  return Object.fromEntries(
    Object.entries(env).filter(
      ([key]) => keys.has(key) || (key.endsWith('_FILE') && keys.has(key.slice(0, -5))),
    ),
  );
}

/**
 * Validates the environment once at startup. `loadConfig` treats empty values as unset, which
 * would turn `SMTP_RECIPIENT_DELIMITER=` into the default `+`; an explicitly empty delimiter
 * means "no address extensions", so it is honoured here.
 */
export const loadSmtpAdapterConfig = (
  env: NodeJS.ProcessEnv = process.env,
): Readonly<SmtpAdapterConfig> => {
  const config = loadConfig(configSchema, ownEnv(env));
  if (env.SMTP_RECIPIENT_DELIMITER === '') {
    return Object.freeze({ ...config, SMTP_RECIPIENT_DELIMITER: '' });
  }
  return config;
};

/** Host names the transport map must never route a tenant domain to (D11, D14). */
export function gatewayOwnHosts(
  config: Pick<
    SmtpAdapterConfig,
    'GATEWAY_MX_HOSTS' | 'POSTFIX_MYHOSTNAME' | 'POSTFIX_OUTBOUND_MYHOSTNAME'
  >,
): ReadonlySet<string> {
  return new Set([
    ...parseGatewayMxHosts(config.GATEWAY_MX_HOSTS),
    config.POSTFIX_MYHOSTNAME,
    config.POSTFIX_OUTBOUND_MYHOSTNAME,
  ]);
}

// --- Injection tokens shared by the in-session modules ----------------------------------------

/** The validated `SmtpAdapterConfig`. */
export const ADAPTER_CONFIG = Symbol('ADAPTER_CONFIG');
/** Root pino logger of the adapter (components derive `.child({ component })`). */
export const ADAPTER_LOGGER = Symbol('ADAPTER_LOGGER');
/** `BlockList` parsed from SMTP_INTERNAL_CLIENT_NETWORKS. */
export const INTERNAL_NETWORKS = Symbol('INTERNAL_NETWORKS');

/**
 * validateDestinationHost options of the map answers (step 2.3 R3): the gateway's own hosts,
 * the bounce domain, the denied suffixes and the non-public flag. No provider: a preset's host
 * patterns are enforced by the api on write; the adapter re-checks safety only.
 */
export function destinationHostOptions(
  config: Pick<
    SmtpAdapterConfig,
    | 'GATEWAY_MX_HOSTS'
    | 'POSTFIX_MYHOSTNAME'
    | 'POSTFIX_OUTBOUND_MYHOSTNAME'
    | 'POSTFIX_BOUNCE_DOMAIN'
    | 'ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS'
    | 'ROUTING_DENIED_DESTINATION_SUFFIXES'
    | 'ROUTING_ALLOWED_DESTINATION_PORTS'
  >,
): ValidateDestinationHostOptions {
  return {
    allowNonPublic: config.ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS,
    deniedSuffixes: config.ROUTING_DENIED_DESTINATION_SUFFIXES,
    allowedPorts: config.ROUTING_ALLOWED_DESTINATION_PORTS,
    gatewayHosts: gatewayOwnHosts(config),
    bounceDomain: config.POSTFIX_BOUNCE_DOMAIN,
  };
}
