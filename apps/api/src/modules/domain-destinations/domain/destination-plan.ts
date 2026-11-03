import type { MailDestinationProvider, TlsMode } from '@email-gateway/database';
import {
  type DestinationHostResult,
  type MailDestinationPresetView,
  matchesProviderHost,
  normalizeHostForComparison,
  type ValidateDestinationHostOptions,
  validateDestinationHost,
} from '@email-gateway/mail-routing';
import {
  CUSTOM_DEFAULTS,
  type DestinationRefusalReason,
  PRESET_SINGLE_SERVER_PRIORITY,
} from '../domain-destinations.constants';
import type { PutDestinationsInput } from '../dto/domain-destinations.schemas';

/** One destination row to write (`domain_mail_servers`, role `inbound_destination`). */
export interface PlannedServer {
  host: string;
  port: number;
  priority: number;
  tlsMode: TlsMode;
  tlsVerifyNames: string | null;
  provider: MailDestinationProvider;
}

export type DestinationPlan =
  | { ok: true; provider: MailDestinationProvider; servers: PlannedServer[] }
  | { ok: false; reason: DestinationRefusalReason; field: string };

/** Host safety options without a provider (the planner adds the preset per request). */
export type HostRules = Omit<ValidateDestinationHostOptions, 'provider'>;

const refuse = (reason: DestinationRefusalReason, field: string): DestinationPlan => ({
  ok: false,
  reason,
  field,
});

/**
 * validateDestinationHost with the gateway's own names checked first, so a gateway host under
 * a refused suffix (`mx.gateway.local`) is reported as `gateway_host` (the R10 self-routing
 * case), not as `internal_suffix`.
 */
function checkHost(
  host: string,
  port: number,
  options: ValidateDestinationHostOptions,
): DestinationHostResult {
  const normalized = normalizeHostForComparison(host);
  const bounce = options.bounceDomain;
  const isGateway =
    [...options.gatewayHosts].some((own) => normalizeHostForComparison(own) === normalized) ||
    (bounce !== undefined && (normalized === bounce || normalized.endsWith(`.${bounce}`)));
  return isGateway
    ? { ok: false, reason: 'gateway_host' }
    : validateDestinationHost(host, port, options);
}

/** The first server whose normalized host:port repeats an earlier one, or -1. */
function duplicateIndex(servers: readonly PlannedServer[]): number {
  const seen = new Set<string>();
  for (const [index, server] of servers.entries()) {
    const key = `${server.host}|${server.port}`;
    if (seen.has(key)) return index;
    seen.add(key);
  }
  return -1;
}

/**
 * Turns a `PUT /domains/{id}/destinations` body into the rows to write (step 2.3 R2, R3), or a
 * refusal with a stable reason and the request field it applies to. Pure: presets and rules
 * are passed in.
 *
 * - `microsoft_365 { host }`: one host matching the preset's patterns; the preset's port,
 *   `verify` and its verify names are forced.
 * - `google_workspace {}`: the preset's default servers (re-validated like any host).
 * - `custom { servers }`: each host validated (defaults: port 25, priority 10, opportunistic,
 *   verify names only with `verify`); a host matching any preset's patterns is
 *   `host_reserved_for_provider`.
 *
 * Every host is normalized by validateDestinationHost (lower case, IDNA, canonical IP); a
 * repeated host:port is `duplicate_server`. A missing or disabled preset is
 * `provider_unavailable`.
 */
export function planDestinations(
  input: PutDestinationsInput,
  presets: readonly MailDestinationPresetView[],
  rules: HostRules,
): DestinationPlan {
  if (input.provider === 'custom') {
    const servers: PlannedServer[] = [];
    for (const [index, server] of input.servers.entries()) {
      const port = server.port ?? CUSTOM_DEFAULTS.port;
      const checked = checkHost(server.host, port, rules);
      if (!checked.ok) {
        const field = checked.reason === 'port_not_allowed' ? 'port' : 'host';
        return refuse(checked.reason, `servers.${index}.${field}`);
      }
      // A preset's hosts carry the preset's fixed TLS policy (shared by every tenant using
      // them); a custom row could otherwise change Postfix's policy for all of them.
      if (presets.some((preset) => matchesProviderHost(preset, checked.host))) {
        return refuse('host_reserved_for_provider', `servers.${index}.host`);
      }
      const tlsMode = server.tlsMode ?? CUSTOM_DEFAULTS.tlsMode;
      servers.push({
        host: checked.host,
        port: checked.port,
        priority: server.priority ?? CUSTOM_DEFAULTS.priority,
        tlsMode,
        tlsVerifyNames: tlsMode === 'verify' ? (server.tlsVerifyNames ?? null) : null,
        provider: 'custom',
      });
    }
    const duplicate = duplicateIndex(servers);
    if (duplicate !== -1) return refuse('duplicate_server', `servers.${duplicate}.host`);
    return { ok: true, provider: 'custom', servers };
  }

  const preset = presets.find((candidate) => candidate.provider === input.provider);
  if (!preset) return refuse('provider_unavailable', 'provider');
  const options = { ...rules, provider: preset };
  const fromPreset = (host: string, priority: number): PlannedServer | DestinationRefusalReason => {
    const checked = checkHost(host, preset.port, options);
    if (!checked.ok) return checked.reason;
    return {
      host: checked.host,
      port: checked.port,
      priority,
      tlsMode: preset.tlsMode,
      tlsVerifyNames: preset.tlsMode === 'verify' ? preset.tlsVerifyNames : null,
      provider: preset.provider,
    };
  };

  if (input.provider === 'microsoft_365') {
    const server = fromPreset(input.host, PRESET_SINGLE_SERVER_PRIORITY);
    if (typeof server === 'string') return refuse(server, 'host');
    return { ok: true, provider: preset.provider, servers: [server] };
  }

  // google_workspace: the preset's own servers.
  const defaults = preset.defaultServers;
  if (defaults === null || defaults.length === 0) return refuse('provider_unavailable', 'provider');
  const servers: PlannedServer[] = [];
  for (const entry of defaults.slice(0, preset.maxServers)) {
    const server = fromPreset(entry.host, entry.priority);
    // Seeded data that fails the rules is a configuration error: refuse, never write it.
    if (typeof server === 'string') return refuse('provider_unavailable', 'provider');
    servers.push(server);
  }
  if (duplicateIndex(servers) !== -1) return refuse('provider_unavailable', 'provider');
  return { ok: true, provider: preset.provider, servers };
}

/** The TLS policy of one destination row, as Postfix's `tls_policy` answer depends on it. */
export interface DestinationTlsPolicy {
  host: string;
  port: number;
  tlsMode: TlsMode;
  tlsVerifyNames: string | null;
  provider: MailDestinationProvider;
}

const samePolicy = (a: DestinationTlsPolicy, b: DestinationTlsPolicy): boolean =>
  a.tlsMode === b.tlsMode &&
  (a.tlsMode !== 'verify' || (a.tlsVerifyNames ?? null) === (b.tlsVerifyNames ?? null));

/**
 * The index of the first planned server whose host:port is also a destination of another
 * organization with a different TLS policy, or -1 (review fix of step 2.3 R2). The smtp-adapter
 * answers one `tls_policy` per `[host]:port` for every tenant (Postfix has no tenant context
 * there), so a tenant must never be able to make that answer stricter (cross-tenant denial of
 * delivery) or weaker (downgrade) for another tenant. Preset servers are exempt: their policy
 * is the preset's, identical for every tenant, and custom rows cannot use preset hosts.
 */
export function tlsConflictIndex(
  planned: readonly DestinationTlsPolicy[],
  others: readonly DestinationTlsPolicy[],
): number {
  return planned.findIndex(
    (server) =>
      server.provider === 'custom' &&
      others.some(
        (other) =>
          other.host === server.host && other.port === server.port && !samePolicy(server, other),
      ),
  );
}
