import { Inject, Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { MailDestinationProvider, TlsMode } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  loadDestinationPresets,
  loadInboundDestinations,
  normalizeHostForComparison,
  renderTlsPolicy,
  renderTransportNexthops,
  strictestTlsMode,
  TLS_MODES,
  type ValidateDestinationHostOptions,
  validateDestinationHost,
} from '@email-gateway/mail-routing';
import { z } from 'zod';
import {
  ADAPTER_CONFIG,
  ADAPTER_LOGGER,
  destinationHostOptions,
  type SmtpAdapterConfig,
} from '../config';
import { parseIpKey } from '../connectors/addresses';
import { ConnectorResolver } from '../connectors/connector-resolver.service';
import {
  SOCKETMAP_NOTFOUND,
  SOCKETMAP_RELAY_DOMAIN_OK,
  SOCKETMAP_UNKNOWN_MAP,
  TRANSPORT_DESTINATION_NOT_CONFIGURED,
} from '../shared/replies';
import { cacheKeys } from '../tenancy/cache-keys';
import { DomainPolicyService } from '../tenancy/domain-policy.service';
import { RedisJsonCache } from '../tenancy/redis-json-cache';

export const SOCKETMAP_MAPS = [
  'relay_domain',
  'transport',
  'tls_policy',
  'relay_client',
  'relay_ccert',
] as const;
export type SocketmapMap = (typeof SOCKETMAP_MAPS)[number];

export const isSocketmapMap = (name: string): name is SocketmapMap =>
  (SOCKETMAP_MAPS as readonly string[]).includes(name);

/** A normalized next-hop host inside `[...]`: a host name or an IP literal (v4 or v6). */
const NEXTHOP_HOST = /^[a-z0-9.:-]{1,253}$/;
/** `[host]:port` or `[host]` (port 25), the next-hop form of our transport answers. */
const BRACKETED_NEXTHOP = /^\[([^\][\s]{1,253})\](?::(\d{1,5}))?$/;
/** Postfix `match=` list (validated again by renderTlsPolicy). */
const TLS_VERIFY_NAMES = /^[A-Za-z0-9.:-]{1,512}$/;
/** Rows read per host for the TLS policy answers. */
const MAX_TLS_ROWS = 500;

/**
 * Access-map answer for `relay_client` / `relay_ccert`. Postfix's socketmap client splits the
 * reply at the first space and returns the rest as the lookup value; a bare `OK` (the shared
 * `SOCKETMAP_OK` constant) has no value and Postfix treats it as "not found". The access(5)
 * action `OK` (permit relay) is therefore sent as the value: `OK OK`.
 */
export const SOCKETMAP_ACCESS_OK = 'OK OK';

/** Transport answer for a tenant domain that must not be delivered now (`OK <transport>`). */
const DEFER_DELIVERY = `OK ${TRANSPORT_DESTINATION_NOT_CONFIGURED}`;

/**
 * Cached transport DTO (`sa:route:v2:{name}`): the enabled destination rows as stored, in
 * next-hop order. Hosts are re-validated on every answer, so a configuration change (gateway
 * hosts, denied suffixes) applies at once and a row written directly to the database is never
 * trusted because it was cached.
 */
const routeDto = z.object({
  servers: z
    .array(z.object({ host: z.string().min(1).max(255), port: z.number().int() }))
    .min(1)
    .max(100),
});
type RouteDto = z.infer<typeof routeDto>;

/** Cached TLS DTO (`sa:tls:v2:{host}`): the decided policy per port of one host. */
const tlsDto = z.object({
  policies: z
    .array(
      z.object({
        port: z.number().int().min(1).max(65_535),
        mode: z.enum(TLS_MODES),
        verifyNames: z.string().regex(TLS_VERIFY_NAMES).nullable(),
      }),
    )
    .min(1)
    .max(MAX_TLS_ROWS),
});
type TlsDto = z.infer<typeof tlsDto>;

export type SocketmapLookupConfig = Pick<
  SmtpAdapterConfig,
  | 'SMTP_DOMAIN_CACHE_TTL_SECONDS'
  | 'SMTP_NEGATIVE_CACHE_TTL_SECONDS'
  | 'GATEWAY_MX_HOSTS'
  | 'POSTFIX_MYHOSTNAME'
  | 'POSTFIX_OUTBOUND_MYHOSTNAME'
  | 'POSTFIX_BOUNCE_DOMAIN'
  | 'ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS'
  | 'ROUTING_DENIED_DESTINATION_SUFFIXES'
  | 'ROUTING_ALLOWED_DESTINATION_PORTS'
  | 'ROUTING_MAX_DESTINATIONS_PER_DOMAIN'
>;

interface TlsRow {
  organizationId: bigint;
  port: number;
  tlsMode: TlsMode;
  tlsVerifyNames: string | null;
  provider: MailDestinationProvider;
}

/** Keys Postfix probes that we never match: `.parent` domains, `user@domain`, `*`, empty. */
function isPlainDomainKey(key: string): boolean {
  return key.length > 0 && !key.startsWith('.') && !key.includes('@') && key !== '*';
}

/**
 * Domain of a `transport` lookup key. Postfix sends socketmap tables the FULL recipient address
 * (`user@domain`): socketmap is a non-indexed table type, so trivial-rewrite performs one lookup
 * with the entire address and never probes the bare domain or parent domains (transport(5),
 * "TCP-BASED TABLES"). Found by the step 2.2 stack tests (WP6): with domain-only keys every
 * reinject-inbound delivery fell through to an MX lookup of the tenant domain. A bare domain key
 * (postmap -q, operators) is still accepted. `.parent`, `*`, empty and malformed keys → null.
 */
function transportDomainKey(key: string): string | null {
  const at = key.lastIndexOf('@');
  const domain = at === -1 ? key : key.slice(at + 1);
  if (at === 0 || (at !== -1 && key.slice(0, at).includes('@'))) return null;
  return isPlainDomainKey(domain) ? domain : null;
}

/**
 * Socketmap tables served to Postfix (step 2.2 D2, D11). Every method answers a protocol reply
 * text (`OK …`, `NOTFOUND `); database errors propagate and the server answers
 * `TEMP Lookup failed` (Postfix defers: fail closed).
 */
@Injectable()
export class SocketmapLookupService {
  private readonly logger: Logger;
  private readonly hostOptions: ValidateDestinationHostOptions;

  constructor(
    private readonly prisma: PrismaService,
    private readonly domains: DomainPolicyService,
    private readonly connectors: ConnectorResolver,
    private readonly cache: RedisJsonCache,
    @Inject(ADAPTER_CONFIG) private readonly config: SocketmapLookupConfig,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.logger = logger.child({ component: 'socketmap' });
    this.hostOptions = destinationHostOptions(config);
  }

  async lookup(map: string, key: string): Promise<string> {
    if (!isSocketmapMap(map)) return SOCKETMAP_UNKNOWN_MAP;
    switch (map) {
      case 'relay_domain':
        return this.relayDomain(key);
      case 'transport':
        return this.transport(key);
      case 'tls_policy':
        return this.tlsPolicy(key);
      case 'relay_client':
        return this.relayClient(key);
      case 'relay_ccert':
        return this.relayCcert(key);
    }
  }

  /** Inbound `relay_domains`: active tenant domain with inbound enabled. */
  private async relayDomain(key: string): Promise<string> {
    if (!isPlainDomainKey(key)) return SOCKETMAP_NOTFOUND;
    const domain = await this.domains.get(key);
    return domain?.inboundEnabled ? SOCKETMAP_RELAY_DOMAIN_OK : SOCKETMAP_NOTFOUND;
  }

  /**
   * Outbound `transport_maps` (step 2.3 R2, R3): an active tenant domain → every enabled
   * `inbound_destination` server, ordered by (priority, id), as a Postfix next-hop list
   * (`OK smtp:[h1]:25,[h2]:2525`, failover in that order), at most
   * ROUTING_MAX_DESTINATIONS_PER_DOMAIN. Each host is re-validated with
   * validateDestinationHost; invalid rows are skipped and logged. No valid server left, or any
   * server is one of the gateway's own hosts (never looped back, never sent to its public MX =
   * us) → `OK retry:4.4.1 Destination not configured`. Everything else is NOTFOUND (Postfix's
   * own MX resolution).
   */
  private async transport(key: string): Promise<string> {
    const domainKey = transportDomainKey(key);
    if (domainKey === null) return SOCKETMAP_NOTFOUND;
    const domain = await this.domains.get(domainKey);
    if (!domain) return SOCKETMAP_NOTFOUND;
    const route = await this.cache.getOrLoad<RouteDto>({
      cache: 'route',
      key: cacheKeys.route(domain.name),
      ttlSeconds: this.config.SMTP_DOMAIN_CACHE_TTL_SECONDS,
      negativeTtlSeconds: this.config.SMTP_NEGATIVE_CACHE_TTL_SECONDS,
      schema: routeDto,
      load: async () => {
        const rows = await loadInboundDestinations(this.prisma, domain.domainId);
        return rows.length === 0
          ? null
          : { servers: rows.map((row) => ({ host: row.host, port: row.port })) };
      },
    });
    const log = { domainId: String(domain.domainId), domain: domain.name };
    if (!route) {
      this.logger.error(log, 'tenant domain has no inbound destination; deferring delivery');
      return DEFER_DELIVERY;
    }
    const nexthops: { host: string; port: number }[] = [];
    const seen = new Set<string>();
    for (const server of route.servers) {
      if (this.isGatewayHost(server.host)) {
        this.logger.error(log, 'tenant destination is the gateway itself; deferring delivery');
        return DEFER_DELIVERY;
      }
      const checked = validateDestinationHost(server.host, server.port, this.hostOptions);
      if (!checked.ok) {
        if (checked.reason === 'gateway_host') {
          this.logger.error(log, 'tenant destination is the gateway itself; deferring delivery');
          return DEFER_DELIVERY;
        }
        this.logger.error(
          { ...log, host: server.host.slice(0, 255), port: server.port, reason: checked.reason },
          'tenant destination refused by the destination host rules; skipped',
        );
        continue;
      }
      const hop = `${checked.host}:${checked.port}`;
      if (seen.has(hop) || !NEXTHOP_HOST.test(checked.host)) continue;
      seen.add(hop);
      nexthops.push({ host: checked.host, port: checked.port });
    }
    if (nexthops.length === 0) {
      this.logger.error(log, 'tenant domain has no valid inbound destination; deferring delivery');
      return DEFER_DELIVERY;
    }
    const max = this.config.ROUTING_MAX_DESTINATIONS_PER_DOMAIN;
    if (nexthops.length > max) {
      this.logger.warn(
        { ...log, servers: nexthops.length, max },
        'more destinations than ROUTING_MAX_DESTINATIONS_PER_DOMAIN; extra next hops dropped',
      );
    }
    return `OK ${renderTransportNexthops(nexthops.slice(0, max))}`;
  }

  /** One of GATEWAY_MX_HOSTS, POSTFIX_MYHOSTNAME, POSTFIX_OUTBOUND_MYHOSTNAME or the bounce domain. */
  private isGatewayHost(host: string): boolean {
    const normalized = normalizeHostForComparison(host);
    for (const own of this.hostOptions.gatewayHosts) {
      if (normalizeHostForComparison(own) === normalized) return true;
    }
    const bounce = this.hostOptions.bounceDomain;
    return bounce !== undefined && (normalized === bounce || normalized.endsWith(`.${bounce}`));
  }

  /**
   * Outbound `smtp_tls_policy_maps` (step 2.3 R2): `[host]:port` of a tenant destination → the
   * strictest `tls_mode` of the enabled destinations sharing it (of active domains of active
   * organizations); `verify` renders `secure match=<tls_verify_names or nexthop>`. Postfix
   * looks the policy up for every next hop of a list (WP2 V2), so each host has its own answer.
   * MX-resolved next hops (bare domains) → NOTFOUND (global `may`).
   */
  private async tlsPolicy(key: string): Promise<string> {
    const match = BRACKETED_NEXTHOP.exec(key);
    if (!match) return SOCKETMAP_NOTFOUND;
    const host = normalizeHostForComparison(match[1]!);
    const port = match[2] === undefined ? 25 : Number(match[2]);
    if (!NEXTHOP_HOST.test(host) || port < 1 || port > 65535) return SOCKETMAP_NOTFOUND;
    const policies = await this.cache.getOrLoad<TlsDto>({
      cache: 'tls_policy',
      key: cacheKeys.tlsPolicy(host),
      ttlSeconds: this.config.SMTP_DOMAIN_CACHE_TTL_SECONDS,
      negativeTtlSeconds: this.config.SMTP_NEGATIVE_CACHE_TTL_SECONDS,
      schema: tlsDto,
      load: () => this.loadTlsPolicies(host),
    });
    const policy = policies?.policies.find((entry) => entry.port === port);
    return policy ? `OK ${renderTlsPolicy(policy.mode, policy.verifyNames)}` : SOCKETMAP_NOTFOUND;
  }

  /** The decided policy per port of every enabled destination row with this host. */
  private async loadTlsPolicies(host: string): Promise<TlsDto | null> {
    const rows: TlsRow[] = await this.prisma.domainMailServer.findMany({
      where: {
        role: 'inbound_destination',
        enabled: true,
        host,
        domain: { status: 'active', organization: { status: 'active' } },
      },
      select: {
        organizationId: true,
        port: true,
        tlsMode: true,
        tlsVerifyNames: true,
        provider: true,
      },
      orderBy: { id: 'asc' },
      take: MAX_TLS_ROWS,
    });
    if (rows.length === 0) return null;
    const byPort = new Map<number, TlsRow[]>();
    for (const row of rows) {
      if (row.port < 1 || row.port > 65_535) continue;
      byPort.set(row.port, [...(byPort.get(row.port) ?? []), row]);
    }
    const policies: TlsDto['policies'] = [];
    for (const [port, group] of byPort) {
      this.warnCrossTenantConflict(host, port, group);
      const mode = strictestTlsMode(group.map((row) => row.tlsMode))!;
      const verifyNames =
        mode === 'verify'
          ? await this.verifyNames(
              host,
              port,
              group.filter((row) => row.tlsMode === 'verify'),
            )
          : null;
      policies.push({ port, mode, verifyNames });
    }
    return policies.length === 0 ? null : { policies };
  }

  /**
   * Rows of several organizations disagreeing on one next hop's policy. The api refuses such a
   * write (`destination_tls_conflict`), so only rows written around it (direct SQL, data from
   * before the check) get here. The answer stays the strictest mode (never a downgrade); the
   * error names ids only, for an operator to resolve.
   */
  private warnCrossTenantConflict(host: string, port: number, rows: readonly TlsRow[]): void {
    const organizations = new Set(rows.map((row) => String(row.organizationId)));
    if (organizations.size < 2) return;
    const policies = new Set(
      rows.map((row) => `${row.tlsMode}|${row.tlsMode === 'verify' ? row.tlsVerifyNames : ''}`),
    );
    if (policies.size < 2) return;
    this.logger.error(
      { host, port, organizations: [...organizations].slice(0, 20) },
      'destinations of several organizations disagree on the TLS policy of a shared next hop',
    );
  }

  /**
   * The `match=` list of the `verify` rows sharing `[host]:port`: theirs when they agree (NULL =
   * `nexthop`); when they disagree, the preset's names if every row comes from the same preset
   * provider, else `nexthop` (warned). Names that are not a safe `match=` list → `nexthop`.
   */
  private async verifyNames(
    host: string,
    port: number,
    rows: readonly TlsRow[],
  ): Promise<string | null> {
    const distinct = new Set(rows.map((row) => row.tlsVerifyNames));
    let names: string | null;
    if (distinct.size === 1) {
      names = rows[0]!.tlsVerifyNames;
    } else {
      const providers = new Set(rows.map((row) => row.provider));
      const provider = providers.size === 1 ? [...providers][0]! : null;
      const preset =
        provider !== null && provider !== 'custom'
          ? (await loadDestinationPresets(this.prisma)).find((p) => p.provider === provider)
          : undefined;
      names = preset?.tlsVerifyNames ?? null;
      this.logger.warn(
        { host, port, rows: rows.length, provider, using: names ?? 'nexthop' },
        'destinations sharing a next hop disagree on tls_verify_names',
      );
    }
    if (names !== null && !TLS_VERIFY_NAMES.test(names)) {
      this.logger.error({ host, port }, 'invalid tls_verify_names; verifying with nexthop');
      return null;
    }
    return names;
  }

  /** Port 25 `check_client_access`: full IP inside an active source_ip connector network. */
  private async relayClient(key: string): Promise<string> {
    const ip = parseIpKey(key);
    if (!ip) return SOCKETMAP_NOTFOUND;
    return (await this.connectors.byClientAddress(ip)) ? SOCKETMAP_ACCESS_OK : SOCKETMAP_NOTFOUND;
  }

  /** Port 25 `check_ccert_access`: fingerprint of an active client_certificate connector. */
  private async relayCcert(key: string): Promise<string> {
    return (await this.connectors.byCertificateFingerprint(key))
      ? SOCKETMAP_ACCESS_OK
      : SOCKETMAP_NOTFOUND;
  }
}
