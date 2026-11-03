import { randomUUID } from 'node:crypto';
import { BadRequestException, ConflictException, Inject, Injectable, Logger } from '@nestjs/common';
import type { MailDestinationProvider, Prisma } from '@email-gateway/database';
import { getCorrelationId } from '@email-gateway/logger';
import type { MailDestinationPresetView } from '@email-gateway/mail-routing';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { TransactionRunner } from '../../../database/transaction-runner';
import type { ClientContext } from '../../auth/services/session.service';
import { DOMAIN_RESOURCE_TYPE } from '../../domains/domains.constants';
import { domainNotFound } from '../../domains/domains.errors';
import { DomainOutboxRepository } from '../../domains/repositories/domain-outbox.repository';
import {
  type HostRules,
  type PlannedServer,
  planDestinations,
  tlsConflictIndex,
} from '../domain/destination-plan';
import { DestinationAuditAction, MAX_EVENT_HOSTS } from '../domain-destinations.constants';
import {
  DESTINATIONS_DOMAIN_DELETED,
  DestinationRefusedException,
} from '../domain-destinations.errors';
import type {
  DestinationProviderList,
  DestinationProviderView,
  DomainDestinationsView,
  PutDestinationsInput,
} from '../dto/domain-destinations.schemas';
import {
  type DestinationDomainRow,
  DomainDestinationsRepository,
  type DestinationServerRow,
} from '../repositories/domain-destinations.repository';

type Client = Prisma.TransactionClient;

export type DomainDestinationsConfig = Pick<
  ApiConfig,
  | 'GATEWAY_MX_HOSTS'
  | 'POSTFIX_MYHOSTNAME'
  | 'POSTFIX_OUTBOUND_MYHOSTNAME'
  | 'POSTFIX_BOUNCE_DOMAIN'
  | 'ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS'
  | 'ROUTING_DENIED_DESTINATION_SUFFIXES'
  | 'ROUTING_ALLOWED_DESTINATION_PORTS'
  | 'ROUTING_MAX_DESTINATIONS_PER_DOMAIN'
>;

/** validateDestinationHost rules of the api (R3): the gateway's own names, suffixes, flag. */
export function hostRulesFrom(config: DomainDestinationsConfig): HostRules {
  return {
    allowNonPublic: config.ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS,
    deniedSuffixes: config.ROUTING_DENIED_DESTINATION_SUFFIXES,
    allowedPorts: config.ROUTING_ALLOWED_DESTINATION_PORTS,
    gatewayHosts: new Set([
      ...config.GATEWAY_MX_HOSTS.map((mx) => mx.host),
      config.POSTFIX_MYHOSTNAME,
      config.POSTFIX_OUTBOUND_MYHOSTNAME,
    ]),
    bounceDomain: config.POSTFIX_BOUNCE_DOMAIN,
  };
}

const toServerView = (row: DestinationServerRow) => ({
  id: row.publicId,
  host: row.host ?? '',
  port: row.port,
  priority: row.priority,
  tlsMode: row.tlsMode,
  tlsVerifyNames: row.tlsVerifyNames,
  enabled: row.enabled,
  createdAt: row.createdAt.toISOString(),
  updatedAt: row.updatedAt.toISOString(),
});

/** `{ provider, servers }`: one provider per domain (the first row's; null without rows). */
export function toDestinationsView(rows: readonly DestinationServerRow[]): DomainDestinationsView {
  return {
    provider: rows[0]?.provider ?? null,
    servers: rows.filter((row) => row.host !== null).map(toServerView),
  };
}

export function toProviderView(preset: MailDestinationPresetView): DestinationProviderView {
  return {
    provider: preset.provider,
    displayName: preset.displayName,
    hostHint: preset.hostHint,
    hostPatterns: preset.hostPatterns.map((pattern) => pattern.source),
    port: preset.port,
    tlsMode: preset.tlsMode,
    tlsVerifyNames: preset.tlsVerifyNames,
    maxServers: preset.maxServers,
    defaultServers:
      preset.defaultServers?.map(({ host, priority }) => ({ host, priority })) ?? null,
    documentationUrl: preset.documentationUrl,
  };
}

/** Same rows in the same order (what a replacement would write equals what is stored). */
function sameServers(current: readonly DestinationServerRow[], next: readonly PlannedServer[]) {
  return (
    current.length === next.length &&
    current.every((row, index) => {
      const server = next[index]!;
      return (
        row.enabled &&
        row.host === server.host &&
        row.port === server.port &&
        row.priority === server.priority &&
        row.tlsMode === server.tlsMode &&
        row.tlsVerifyNames === server.tlsVerifyNames &&
        row.provider === server.provider
      );
    })
  );
}

/** Ordered like the transport answer: priority, then request order (stable). */
const inDeliveryOrder = (servers: readonly PlannedServer[]): PlannedServer[] =>
  [...servers].sort((a, b) => a.priority - b.priority);

const hostsOf = (rows: readonly { host: string | null }[]): string[] => [
  ...new Set(rows.flatMap((row) => (row.host === null ? [] : [row.host]))),
];

/**
 * Where a domain's inbound and internal mail is delivered (step 2.3 R2, R3, R13): the
 * provider presets and the domain's destination servers. Tenant from the scope only: another
 * tenant's domain is `404`. Every change locks the domain row, writes the rows, the audit
 * entry and `domain.routing.changed.v1` (the adapter's cache invalidation) in one writer
 * transaction.
 */
@Injectable()
export class DomainDestinationsService {
  private readonly logger = new Logger(DomainDestinationsService.name);
  private readonly rules: HostRules;

  constructor(
    @Inject(API_CONFIG) private readonly config: DomainDestinationsConfig,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
    private readonly destinations: DomainDestinationsRepository,
    private readonly outbox: DomainOutboxRepository,
  ) {
    this.rules = hostRulesFrom(config);
  }

  /** `GET /destination-providers` (replica). */
  async providers(): Promise<DestinationProviderList> {
    return { data: (await this.destinations.presets()).map(toProviderView) };
  }

  /** `GET /domains/{id}/destinations` (replica). */
  async get(scope: TenantScope, publicId: string): Promise<DomainDestinationsView> {
    const domain = await this.destinations.findDomain(scope, publicId);
    if (!domain) throw domainNotFound();
    return toDestinationsView(await this.destinations.listServers(scope, domain.id));
  }

  /**
   * `PUT /domains/{id}/destinations`: atomic replacement. `404` unknown or foreign domain, `409`
   * deleted domain, `422` with a `reason` for a refused host (R3) or for a custom host:port that
   * another organization already uses with a different TLS policy (`destination_tls_conflict`),
   * `400` for more custom servers than ROUTING_MAX_DESTINATIONS_PER_DOMAIN. A body equal to the
   * stored rows writes nothing.
   */
  async replace(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    input: PutDestinationsInput,
    client: ClientContext,
  ): Promise<DomainDestinationsView> {
    const max = this.config.ROUTING_MAX_DESTINATIONS_PER_DOMAIN;
    if (input.provider === 'custom' && input.servers.length > max) {
      throw new BadRequestException([
        `servers: at most ${max} servers (ROUTING_MAX_DESTINATIONS_PER_DOMAIN)`,
      ]);
    }
    return this.transactions.run(async (tx) => {
      const domain = await this.lockWritable(tx, scope, publicId);
      const plan = planDestinations(input, await this.destinations.presets(tx), this.rules);
      if (!plan.ok) throw new DestinationRefusedException(plan.reason, plan.field);
      const shared = await this.destinations.lockSharedDestinations(
        tx,
        scope,
        hostsOf(plan.servers.filter((server) => server.provider === 'custom')),
      );
      const conflict = tlsConflictIndex(plan.servers, shared);
      if (conflict !== -1) {
        throw new DestinationRefusedException(
          'destination_tls_conflict',
          `servers.${conflict}.tlsMode`,
        );
      }
      const servers = inDeliveryOrder(plan.servers);
      const current = await this.destinations.listServers(scope, domain.id, tx);
      if (sameServers(current, servers)) return toDestinationsView(current);

      await this.destinations.replaceServers(tx, scope, domain.id, plan.servers);
      const hosts = hostsOf(plan.servers);
      await this.record(tx, principal, scope, client, domain, DestinationAuditAction.Replaced, {
        provider: plan.provider,
        hosts,
        count: plan.servers.length,
        previous: { provider: current[0]?.provider ?? null, hosts: hostsOf(current) },
      });
      await this.event(tx, scope, domain, [...hosts, ...hostsOf(current)]);
      return toDestinationsView(await this.destinations.listServers(scope, domain.id, tx));
    });
  }

  /**
   * `DELETE /domains/{id}/destinations`: removes every inbound destination (mail for the
   * domain then defers with `no_destination`). Nothing to remove → no audit, no event.
   */
  async remove(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    client: ClientContext,
  ): Promise<void> {
    await this.transactions.run(async (tx) => {
      const domain = await this.lockWritable(tx, scope, publicId);
      const current = await this.destinations.listServers(scope, domain.id, tx);
      if (current.length === 0) return;
      await this.destinations.deleteServers(tx, scope, domain.id);
      const hosts = hostsOf(current);
      await this.record(tx, principal, scope, client, domain, DestinationAuditAction.Removed, {
        provider: current[0]?.provider ?? null,
        hosts,
        count: current.length,
      });
      await this.event(tx, scope, domain, hosts);
    });
  }

  private async lockWritable(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<DestinationDomainRow> {
    const domain = await this.destinations.lockDomain(tx, scope, publicId);
    if (!domain) throw domainNotFound();
    if (domain.status === 'deleted') throw new ConflictException(DESTINATIONS_DOMAIN_DELETED);
    return domain;
  }

  private async record(
    tx: Client,
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
    domain: DestinationDomainRow,
    action: DestinationAuditAction,
    metadata: {
      provider: MailDestinationProvider | null;
      hosts: string[];
      count: number;
      previous?: { provider: MailDestinationProvider | null; hosts: string[] };
    },
  ): Promise<void> {
    await this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action,
        resourceType: DOMAIN_RESOURCE_TYPE,
        resourceId: domain.publicId,
        sourceIp: client.ip,
        metadata: { name: domain.name, ...metadata },
      },
      tx,
    );
  }

  /** `domain.routing.changed.v1` naming the old and new hosts (new first; at most 20). */
  private async event(
    tx: Client,
    scope: TenantScope,
    domain: DestinationDomainRow,
    hosts: readonly string[],
  ): Promise<void> {
    const unique = [...new Set(hosts)];
    if (unique.length > MAX_EVENT_HOSTS) {
      this.logger.warn(
        `domain ${domain.publicId}: ${unique.length} hosts changed; the event names ` +
          `${MAX_EVENT_HOSTS} (the adapter's TLS cache TTL covers the rest)`,
      );
    }
    await this.outbox.insertRoutingChanged(tx, {
      organizationId: scope.organizationId,
      correlationId: getCorrelationId() ?? `domain:${randomUUID()}`,
      payload: {
        domainId: domain.id.toString(10),
        domainPublicId: domain.publicId,
        name: domain.name,
        hosts: unique.slice(0, MAX_EVENT_HOSTS),
        changedAt: new Date().toISOString(),
      },
    });
  }
}
