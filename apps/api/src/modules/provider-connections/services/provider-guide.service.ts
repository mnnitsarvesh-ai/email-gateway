import { Inject, Injectable } from '@nestjs/common';
import { deriveRouteToken } from '@email-gateway/mail-routing';
import {
  generateSetupGuide,
  isMailFlowGrant,
  renderSetupGuideMarkdown,
  type SetupGuide,
  setupGuideFileName,
} from '@email-gateway/provider-integrations';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { attestationsOf } from '../provider-connections.mapper';
import { INTEGRATION_MANAGE } from '../provider-connections.constants';
import { ProviderConnectionsRepository } from '../repositories/provider-connections.repository';
import { ProviderConnectionsService } from './provider-connections.service';

export type ProviderGuideConfig = Pick<
  ApiConfig,
  | 'PROVIDER_ROUTE_TOKEN_KEY'
  | 'PROVIDER_M365_MAILFLOW_APP_CLIENT_ID'
  | 'PROVIDER_GOOGLE_MAILFLOW_SA_CLIENT_ID'
  | 'GATEWAY_MX_HOSTS'
  | 'GATEWAY_EGRESS_NETWORKS'
  | 'GATEWAY_RELAY_HOSTS'
  | 'GATEWAY_RELAY_TLS_NAME'
  | 'GATEWAY_SPF_INCLUDE'
>;

/** The Markdown rendering of a guide with its download name (D14). */
export interface MarkdownGuide {
  fileName: string;
  markdown: string;
}

/**
 * Customer-specific setup guides (step 8.2 D14, ADR-0080 decision 4): `setup-guide/1` generated
 * by the pure library generator from the connection's own values (provider, tenant, linked
 * domains with their destinations and the tenant's MX target, the gateway values, the platform
 * client id, attestations) and, for Microsoft 365, the route token: revealed only to callers
 * holding `integration:manage`, masked (`••••` + last 4) otherwise. The single-use probe address
 * is never in a guide (only its SHA-256 is stored; it is shown once when a run is created).
 */
@Injectable()
export class ProviderGuideService {
  constructor(
    @Inject(API_CONFIG) private readonly config: ProviderGuideConfig,
    private readonly connections: ProviderConnectionsRepository,
    private readonly base: ProviderConnectionsService,
  ) {}

  now(): Date {
    return new Date();
  }

  async guide(principal: Principal, scope: TenantScope, rawId: unknown): Promise<SetupGuide> {
    const aggregate = await this.base.load(scope, rawId);
    const c = aggregate.connection;
    const grant = aggregate.grants.find((g) => isMailFlowGrant(g) && g.status !== 'revoked');
    const destinations = await this.connections.destinations(
      scope,
      aggregate.domains.map((d) => d.domainId),
    );
    const routeToken =
      c.provider === 'microsoft_365'
        ? {
            current: deriveRouteToken(
              this.config.PROVIDER_ROUTE_TOKEN_KEY,
              c.publicId,
              c.routeTokenVersion,
            ),
            pending:
              c.routeTokenPendingVersion === null
                ? null
                : deriveRouteToken(
                    this.config.PROVIDER_ROUTE_TOKEN_KEY,
                    c.publicId,
                    c.routeTokenPendingVersion,
                  ),
            reveal: principal.permissions.has(INTEGRATION_MANAGE),
          }
        : null;
    return generateSetupGuide({
      provider: c.provider,
      connection: {
        publicId: c.publicId,
        displayName: c.displayName,
        tenantId: c.externalTenantId,
        tenantName: c.externalTenantName,
        outboundMode: c.outboundMode,
        internalRouting: c.internalRouting,
      },
      grant: grant
        ? { authMethod: grant.authMethod, status: grant.status, subjectEmail: null }
        : null,
      platformClientId:
        (c.provider === 'microsoft_365'
          ? this.config.PROVIDER_M365_MAILFLOW_APP_CLIENT_ID
          : this.config.PROVIDER_GOOGLE_MAILFLOW_SA_CLIENT_ID) ?? null,
      domains: aggregate.domains.map((d) => {
        const rows = destinations.get(d.domainId) ?? [];
        return {
          name: d.name,
          gatewayStatus: d.gatewayStatus,
          providerVerification: d.providerVerification,
          providerMxHost: d.providerMxHost,
          ...(rows.length > 0 &&
            rows[0]!.provider === c.provider && {
              destinations: rows.map((r) => ({ host: r.host, priority: r.priority })),
            }),
        };
      }),
      gateway: {
        mxHosts: this.config.GATEWAY_MX_HOSTS.map((mx) => mx.host),
        egressNetworks: this.config.GATEWAY_EGRESS_NETWORKS,
        relayHosts: this.config.GATEWAY_RELAY_HOSTS,
        relayTlsName: this.config.GATEWAY_RELAY_TLS_NAME,
        spfInclude: this.config.GATEWAY_SPF_INCLUDE,
      },
      probeAddress: null,
      routeToken,
      attestations: attestationsOf(c.attestations).map((a) => ({ code: a.code, at: a.at })),
      generatedAt: this.now(),
    });
  }

  async markdown(principal: Principal, scope: TenantScope, rawId: unknown): Promise<MarkdownGuide> {
    const guide = await this.guide(principal, scope, rawId);
    return { fileName: setupGuideFileName(guide), markdown: renderSetupGuideMarkdown(guide) };
  }
}
