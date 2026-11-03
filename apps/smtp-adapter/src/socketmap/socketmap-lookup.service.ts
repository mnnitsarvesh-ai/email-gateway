import { Inject, Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { TlsMode } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { z } from 'zod';
import {
  ADAPTER_CONFIG,
  ADAPTER_LOGGER,
  gatewayOwnHosts,
  normalizeHostName,
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

/** Postfix `smtp_tls_policy_maps` value per `domain_mail_servers.tls_mode` (D11). */
export const TLS_POLICY: Readonly<Record<TlsMode, string>> = {
  none: 'none',
  opportunistic: 'may',
  required: 'encrypt protocols=>=TLSv1.2',
  verify: 'secure match=nexthop protocols=>=TLSv1.2',
};
const TLS_STRICTNESS: readonly TlsMode[] = ['none', 'opportunistic', 'required', 'verify'];

/** A host name we are willing to put into a transport or TLS policy answer. */
const DESTINATION_HOST =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
/** `[host]:port` or `[host]` (port 25), the next-hop form of our transport answers. */
const BRACKETED_NEXTHOP = /^\[([^\][\s]{1,253})\](?::(\d{1,5}))?$/;

/**
 * Access-map answer for `relay_client` / `relay_ccert`. Postfix's socketmap client splits the
 * reply at the first space and returns the rest as the lookup value; a bare `OK` (the shared
 * `SOCKETMAP_OK` constant) has no value and Postfix treats it as "not found". The access(5)
 * action `OK` (permit relay) is therefore sent as the value: `OK OK`.
 */
export const SOCKETMAP_ACCESS_OK = 'OK OK';

/** Transport answer for a tenant domain that must not be delivered now (`OK <transport>`). */
const DEFER_DELIVERY = `OK ${TRANSPORT_DESTINATION_NOT_CONFIGURED}`;

const destinationDto = z.object({ host: z.string(), port: z.number().int() });
type Destination = z.infer<typeof destinationDto>;
const tlsDto = z.object({ mode: z.enum(['none', 'opportunistic', 'required', 'verify']) });

export type SocketmapLookupConfig = Pick<
  SmtpAdapterConfig,
  | 'SMTP_DOMAIN_CACHE_TTL_SECONDS'
  | 'SMTP_NEGATIVE_CACHE_TTL_SECONDS'
  | 'GATEWAY_MX_HOSTS'
  | 'POSTFIX_MYHOSTNAME'
  | 'POSTFIX_OUTBOUND_MYHOSTNAME'
>;

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
  private readonly ownHosts: ReadonlySet<string>;

  constructor(
    private readonly prisma: PrismaService,
    private readonly domains: DomainPolicyService,
    private readonly connectors: ConnectorResolver,
    private readonly cache: RedisJsonCache,
    @Inject(ADAPTER_CONFIG) private readonly config: SocketmapLookupConfig,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.logger = logger.child({ component: 'socketmap' });
    this.ownHosts = gatewayOwnHosts(config);
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
   * Outbound `transport_maps`: an active tenant domain → its highest-priority enabled
   * `inbound_destination` server. A tenant domain without one, or pointing at the gateway
   * itself, is deferred (never looped back, never sent to its public MX = us); everything else
   * is NOTFOUND (Postfix's own MX resolution).
   */
  private async transport(key: string): Promise<string> {
    const domainKey = transportDomainKey(key);
    if (domainKey === null) return SOCKETMAP_NOTFOUND;
    const domain = await this.domains.get(domainKey);
    if (!domain) return SOCKETMAP_NOTFOUND;
    const destination = await this.cache.getOrLoad<Destination>({
      cache: 'route',
      key: cacheKeys.route(domain.name),
      ttlSeconds: this.config.SMTP_DOMAIN_CACHE_TTL_SECONDS,
      negativeTtlSeconds: this.config.SMTP_NEGATIVE_CACHE_TTL_SECONDS,
      schema: destinationDto,
      load: async () => {
        const server = await this.prisma.domainMailServer.findFirst({
          where: {
            domainId: domain.domainId,
            role: 'inbound_destination',
            enabled: true,
            host: { not: null },
          },
          orderBy: [{ priority: 'asc' }, { id: 'asc' }],
          select: { host: true, port: true },
        });
        return server?.host ? { host: normalizeHostName(server.host), port: server.port } : null;
      },
    });
    const log = { domainId: String(domain.domainId), domain: domain.name };
    if (!destination) {
      this.logger.error(log, 'tenant domain has no inbound destination; deferring delivery');
      return DEFER_DELIVERY;
    }
    if (this.ownHosts.has(destination.host)) {
      this.logger.error(log, 'tenant destination is the gateway itself; deferring delivery');
      return DEFER_DELIVERY;
    }
    if (
      !DESTINATION_HOST.test(destination.host) ||
      destination.port < 1 ||
      destination.port > 65535
    ) {
      this.logger.error(log, 'tenant destination is not a valid host:port; deferring delivery');
      return DEFER_DELIVERY;
    }
    return `OK smtp:[${destination.host}]:${destination.port}`;
  }

  /**
   * Outbound `smtp_tls_policy_maps`: `[host]:port` of a tenant destination → the strictest
   * `tls_mode` of the enabled destinations sharing it (of active domains of active
   * organizations). MX-resolved next hops (bare domains) → NOTFOUND (global `may`).
   */
  private async tlsPolicy(key: string): Promise<string> {
    const match = BRACKETED_NEXTHOP.exec(key);
    if (!match) return SOCKETMAP_NOTFOUND;
    const host = normalizeHostName(match[1]!);
    const port = match[2] === undefined ? 25 : Number(match[2]);
    if (!DESTINATION_HOST.test(host) || port < 1 || port > 65535) return SOCKETMAP_NOTFOUND;
    const policy = await this.cache.getOrLoad({
      cache: 'tls_policy',
      key: cacheKeys.tlsPolicy(host, port),
      ttlSeconds: this.config.SMTP_DOMAIN_CACHE_TTL_SECONDS,
      negativeTtlSeconds: this.config.SMTP_NEGATIVE_CACHE_TTL_SECONDS,
      schema: tlsDto,
      load: async () => {
        const rows = await this.prisma.domainMailServer.findMany({
          where: {
            role: 'inbound_destination',
            enabled: true,
            host,
            port,
            domain: { status: 'active', organization: { status: 'active' } },
          },
          select: { tlsMode: true },
          take: 100,
        });
        if (rows.length === 0) return null;
        const strictest = rows.reduce<TlsMode>(
          (mode, row) =>
            TLS_STRICTNESS.indexOf(row.tlsMode) > TLS_STRICTNESS.indexOf(mode) ? row.tlsMode : mode,
          'none',
        );
        return { mode: strictest };
      },
    });
    return policy ? `OK ${TLS_POLICY[policy.mode]}` : SOCKETMAP_NOTFOUND;
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
