import { Inject, Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import { isRelayProvider, type RelayProvider } from '@email-gateway/mail-routing';
import { z } from 'zod';
import { ADAPTER_CONFIG } from '../config';
import { type IpKey, parseIpKey } from '../connectors/addresses';
import type { ConnectorView } from '../connectors/connector-resolver.service';
import type { PolicyRequest } from '../policy/policy-protocol';
import { DomainPolicyService } from '../tenancy/domain-policy.service';
import { RedisJsonCache } from '../tenancy/redis-json-cache';
import { EgressIndexService } from './egress-index.service';
import type { ProviderRelayConfig } from './provider-relay.config';

/** Provider relay resolution cache TTL (D7.3), like the connector cache of step 2.2. */
export const PROVIDER_RELAY_CACHE_TTL_SECONDS = 30;

/** Redis key of one (provider, sender domain) resolution. */
export const providerRelayCacheKey = (provider: RelayProvider, domain: string): string =>
  `sa:prelay:conn:${provider}:${domain}`;

/** Outbound modes in which a provider-relay session resolves (D7.3, D7.4). */
export type RelayOutboundMode = 'probe_only' | 'active' | 'suspended';

/** What a provider-relay session knows about its connection. */
export interface ProviderRelaySession {
  provider: RelayProvider;
  connectionId: bigint;
  connectionPublicId: string;
  outboundMode: RelayOutboundMode;
  /** Verified provider tenant / customer id. */
  tenantId: string | null;
}

/** The `provider_relay` connector of a session, with its connection. */
export interface ProviderRelayConnectorView extends ConnectorView {
  authType: 'provider_relay';
  providerRelay: ProviderRelaySession;
}

export const isProviderRelayConnector = (
  connector: ConnectorView | null | undefined,
): connector is ProviderRelayConnectorView =>
  connector?.authType === 'provider_relay' && 'providerRelay' in connector;

const decimal = z.string().regex(/^\d{1,20}$/);
const dto = z.object({
  connectorId: decimal,
  connectorPublicId: z.string(),
  organizationId: decimal,
  requireTls: z.boolean(),
  provider: z.enum(['microsoft_365', 'google_workspace']),
  connectionId: decimal,
  connectionPublicId: z.string(),
  outboundMode: z.enum(['probe_only', 'active', 'suspended']),
  tenantId: z.string().nullable(),
});
type Dto = z.infer<typeof dto>;

const RESOLVING_MODES: ReadonlySet<string> = new Set(['probe_only', 'active', 'suspended']);

/**
 * Provider relay resolution on the `relay` listener (step 8.2 D7.3, ADR-0078 decision 1), asked
 * only after certificate and source-IP connectors found nothing. Resolves when relay is enabled,
 * the client address is in the active egress set of provider P, the envelope sender is not empty
 * and its domain D is an active, outbound-enabled domain of an active organization O, D is
 * linked to an `active` connection C of O with provider P and outbound mode `probe_only`,
 * `active` or `suspended` (the last two answered by the policy, D7.4), and C's `provider_relay`
 * connector is active. Results (also null) are cached 30 s per (P, D) under
 * `sa:prelay:conn:{P}:{D}`; database errors propagate (the policy fails closed).
 */
@Injectable()
export class ProviderRelayResolver {
  constructor(
    private readonly prisma: PrismaService,
    private readonly cache: RedisJsonCache,
    private readonly domains: DomainPolicyService,
    private readonly egress: EgressIndexService,
    @Inject(ADAPTER_CONFIG)
    private readonly config: Pick<ProviderRelayConfig, 'PROVIDER_RELAY_ENABLED'>,
  ) {}

  get enabled(): boolean {
    return this.config.PROVIDER_RELAY_ENABLED;
  }

  /** Providers whose egress ranges contain the client (empty when relay is disabled). */
  providersOf(clientAddress: string | undefined): RelayProvider[] {
    if (!this.enabled) return [];
    const ip = parseIpKey(clientAddress);
    return ip ? this.egress.current().providersFor(ip) : [];
  }

  async resolve(request: PolicyRequest): Promise<ProviderRelayConnectorView | null> {
    if (!this.enabled) return null;
    const ip: IpKey | null = parseIpKey(request.client_address);
    if (!ip) return null;
    const providers = this.egress.current().providersFor(ip);
    if (providers.length === 0) return null;
    const sender = request.sender ?? '';
    const at = sender.lastIndexOf('@');
    if (at <= 0 || at === sender.length - 1) return null;
    const domain = DomainPolicyService.normalize(sender.slice(at + 1));
    if (domain === null) return null;
    for (const provider of providers) {
      const found = await this.cache.getOrLoad({
        cache: 'connector',
        key: providerRelayCacheKey(provider, domain),
        ttlSeconds: PROVIDER_RELAY_CACHE_TTL_SECONDS,
        negativeTtlSeconds: PROVIDER_RELAY_CACHE_TTL_SECONDS,
        schema: dto,
        load: () => this.load(provider, domain),
      });
      if (found) return fromDto(found);
    }
    return null;
  }

  private async load(provider: RelayProvider, domainName: string): Promise<Dto | null> {
    const domain = await this.domains.get(domainName);
    if (!domain || !domain.outboundEnabled) return null;
    const link = await this.prisma.providerConnectionDomain.findUnique({
      where: { domainId: domain.domainId },
      select: {
        connection: {
          select: {
            id: true,
            publicId: true,
            organizationId: true,
            provider: true,
            status: true,
            outboundMode: true,
            externalTenantId: true,
            organization: { select: { status: true } },
            smtpConnector: {
              select: {
                id: true,
                publicId: true,
                organizationId: true,
                authType: true,
                status: true,
                requireTls: true,
              },
            },
          },
        },
      },
    });
    const connection = link?.connection;
    const connector = connection?.smtpConnector;
    if (
      !connection ||
      !connector ||
      connection.provider !== provider ||
      !isRelayProvider(connection.provider) ||
      connection.organizationId !== domain.organizationId ||
      connection.status !== 'active' ||
      connection.organization.status !== 'active' ||
      !RESOLVING_MODES.has(connection.outboundMode) ||
      connector.authType !== 'provider_relay' ||
      connector.status !== 'active' ||
      connector.organizationId !== domain.organizationId
    ) {
      return null;
    }
    return {
      connectorId: connector.id.toString(),
      connectorPublicId: connector.publicId,
      organizationId: domain.organizationId.toString(),
      requireTls: connector.requireTls,
      provider,
      connectionId: connection.id.toString(),
      connectionPublicId: connection.publicId,
      outboundMode: connection.outboundMode as RelayOutboundMode,
      tenantId: connection.externalTenantId,
    };
  }
}

function fromDto(value: Dto): ProviderRelayConnectorView {
  return {
    id: BigInt(value.connectorId),
    publicId: value.connectorPublicId,
    organizationId: BigInt(value.organizationId),
    authType: 'provider_relay',
    requireTls: value.requireTls,
    networks: [],
    providerRelay: {
      provider: value.provider,
      connectionId: BigInt(value.connectionId),
      connectionPublicId: value.connectionPublicId,
      outboundMode: value.outboundMode,
      tenantId: value.tenantId,
    },
  };
}
