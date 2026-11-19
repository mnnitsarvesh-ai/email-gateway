import { isIP } from 'node:net';
import { ConfigValidationError } from '@email-gateway/config';
import {
  egressRangesFromCidrs,
  RELAY_PROVIDERS,
  type RelayProvider,
} from '@email-gateway/mail-routing';
import { z } from 'zod';

const positiveInt = z.coerce.number().int().min(1);
const flag = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');

const DOMAIN_LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
/** At least two labels (a reserved operator subdomain such as `probe.<gateway domain>`). */
const MULTI_LABEL_DOMAIN = new RegExp(`^${DOMAIN_LABEL}(?:\\.${DOMAIN_LABEL})+$`);

/**
 * `PROVIDER_RELAY_DNS_SERVERS`: comma-separated resolver addresses (`1.2.3.4`, `1.2.3.4:5353`,
 * `::1`, `[::1]:5353`) for the DKIM key lookups of the proof; empty = the system resolvers.
 * Throws on invalid input.
 */
export function parseDnsServers(value: string | undefined): string[] {
  if (value === undefined || value.trim() === '') return [];
  return value.split(',').map((entry) => {
    const server = entry.trim();
    const bracketed = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(server);
    const hostPort = /^([^:]+):(\d{1,5})$/.exec(server);
    const [host, port] = bracketed
      ? [bracketed[1]!, bracketed[2]]
      : hostPort
        ? [hostPort[1]!, hostPort[2]]
        : [server, undefined];
    if (isIP(host) === 0 || (port !== undefined && (Number(port) < 1 || Number(port) > 65535))) {
      throw new Error(`Invalid PROVIDER_RELAY_DNS_SERVERS entry "${server}"`);
    }
    return server;
  });
}

export type ExtraEgressRanges = Partial<Record<RelayProvider, string[]>>;

const extraRangesSchema = z
  .object(
    Object.fromEntries(
      RELAY_PROVIDERS.map((provider) => [provider, z.array(z.string()).max(64).optional()]),
    ) as Record<RelayProvider, z.ZodOptional<z.ZodArray<z.ZodString>>>,
  )
  .strict();

/**
 * `PROVIDER_EGRESS_EXTRA_RANGES`: JSON `{ "microsoft_365": ["cidr", …], "google_workspace": […] }`
 * of canonical CIDRs added to the loaded egress ranges (local/ci only, so the Compose test
 * clients count as provider infrastructure). Throws on invalid input.
 */
export function parseExtraEgressRanges(value: string | undefined): ExtraEgressRanges {
  if (value === undefined || value.trim() === '') return {};
  const parsed = extraRangesSchema.parse(JSON.parse(value));
  for (const provider of RELAY_PROVIDERS) egressRangesFromCidrs(provider, parsed[provider] ?? []);
  return parsed;
}

const valid = (parse: (value: string) => unknown) => (value: string) => {
  try {
    parse(value);
    return true;
  } catch {
    return false;
  }
};

/**
 * Provider relay keys of the smtp-adapter (step 8.2 §4.4; `.env.example` section "Step 8.2:
 * provider integrations"). `APP_ENV` is part of the base schema.
 */
export const providerRelayConfigShape = {
  /** Resolve `provider_relay` connectors on the relay listener (D7). */
  PROVIDER_RELAY_ENABLED: flag.default(true),
  PROVIDER_RELAY_DNS_SERVERS: z
    .string()
    .default('')
    .refine(valid(parseDnsServers), 'must be a comma-separated list of IP[:port] resolvers')
    .transform(parseDnsServers),
  PROVIDER_RELAY_DNS_TIMEOUT_MS: positiveInt.min(100).max(30_000).default(2000),
  /**
   * Lifetime of the relay marker. The store never writes less than Postfix's
   * `maximal_queue_lifetime` (RELAY_MARKER_RETRY_TTL_SECONDS, 5 d): a queue file whose first LMTP
   * delivery is late must still find its marker (review finding).
   */
  PROVIDER_RELAY_MARKER_TTL_SECONDS: positiveInt.min(60).max(2_592_000).default(432_000),
  PROVIDER_EGRESS_CACHE_SECONDS: positiveInt.max(3600).default(60),
  PROVIDER_RELAY_COUNTER_FLUSH_SECONDS: positiveInt.max(3600).default(30),
  PROVIDER_RELAY_DKIM_REPLAY_WINDOW_SECONDS: positiveInt.min(3600).max(2_592_000).default(604_800),
  PROVIDER_EGRESS_EXTRA_RANGES: z
    .string()
    .default('')
    .refine(
      valid(parseExtraEgressRanges),
      'must be JSON {"microsoft_365":[cidr…],"google_workspace":[cidr…]} of canonical CIDRs',
    )
    .transform(parseExtraEgressRanges),
  /** Reserved domain of validation probe addresses (D10); never a tenant domain. */
  PROVIDER_PROBE_DOMAIN: z
    .string()
    .transform((value) => value.trim().toLowerCase().replace(/\.$/, ''))
    .refine((v) => MULTI_LABEL_DOMAIN.test(v) && v.length <= 253, 'must be a multi-label domain')
    .default('probe.mail-gateway.test'),
  PROVIDER_PROBE_TTL_SECONDS: positiveInt.min(300).max(604_800).default(86_400),
};

export type ProviderRelayConfig = z.infer<z.ZodObject<typeof providerRelayConfigShape>> & {
  APP_ENV: 'local' | 'ci' | 'staging' | 'production';
};

/** Cross-field rules: extra egress ranges only in `APP_ENV` local or ci (§4.4). */
export function assertProviderRelayConfig(config: ProviderRelayConfig): void {
  const extra = Object.values(config.PROVIDER_EGRESS_EXTRA_RANGES).some(
    (list) => (list?.length ?? 0) > 0,
  );
  if (extra && config.APP_ENV !== 'local' && config.APP_ENV !== 'ci') {
    throw new ConfigValidationError([
      'PROVIDER_EGRESS_EXTRA_RANGES: is allowed only when APP_ENV is local or ci',
    ]);
  }
}
