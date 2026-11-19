import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import {
  type DnsRecordPurpose,
  type IntegrationProvider,
  Prisma,
  type ProviderConnectionStatus,
  type ProviderDomainVerification,
  type ProviderHealthStatus,
  type ProviderOutboundMode,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';

type Tx = Prisma.TransactionClient;
type Reader = PrismaReadService['client'];

const connectionSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  provider: true,
  displayName: true,
  status: true,
  externalTenantId: true,
  externalTenantName: true,
  tenantVerifiedAt: true,
  activeTenantKey: true,
  outboundMode: true,
  internalRouting: true,
  relayProof: true,
  routeTokenVersion: true,
  routeTokenPendingVersion: true,
  attestations: true,
  healthStatus: true,
  healthCheckedAt: true,
  healthChangedAt: true,
  nextHealthCheckAt: true,
  lastRelayAcceptedAt: true,
  disabledAt: true,
  rowVersion: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.ProviderConnectionSelect;

export type ConnectionRow = Prisma.ProviderConnectionGetPayload<{
  select: typeof connectionSelect;
}>;

/**
 * The grant columns the api reads. `credential_ciphertext` is NEVER selected (ADR-0077: the api
 * encrypts and never decrypts; mappers cannot emit what was not read).
 */
export const grantSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  connectionId: true,
  profile: true,
  profileVersion: true,
  authMethod: true,
  status: true,
  clientId: true,
  subjectEmail: true,
  credentialKeyId: true,
  credentialVersion: true,
  credentialFingerprint: true,
  credentialSetAt: true,
  credentialExpiresAt: true,
  requestedPermissions: true,
  observedPermissions: true,
  missingPermissions: true,
  excessPermissions: true,
  claimedTenantId: true,
  consentedAt: true,
  verifyRequestedAt: true,
  verifiedAt: true,
  lastErrorCode: true,
  rowVersion: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.ProviderConnectionGrantSelect;

export type GrantRow = Prisma.ProviderConnectionGrantGetPayload<{ select: typeof grantSelect }>;

/** A linked domain with the gateway facts the api shows. */
export interface LinkedDomainRow {
  domainId: bigint;
  domainPublicId: string;
  name: string;
  gatewayStatus: string;
  outboundEnabled: boolean;
  providerVerification: ProviderDomainVerification;
  providerCheckedAt: Date | null;
  providerMxHost: string | null;
  inboundAppliedAt: Date | null;
}

/** The provider_relay connector of a connection (D7.1). */
export interface RelayConnectorRow {
  id: bigint;
  publicId: string;
  status: 'active' | 'disabled';
}

/** One connection with its grants, linked domains and relay connector. */
export interface ConnectionAggregate {
  connection: ConnectionRow;
  grants: GrantRow[];
  domains: LinkedDomainRow[];
  connector: RelayConnectorRow | null;
}

export interface ConnectionListRow extends ConnectionRow {
  domainCount: number;
}

export interface ConnectionChanges {
  displayName?: string;
  status?: ProviderConnectionStatus;
  outboundMode?: ProviderOutboundMode;
  internalRouting?: boolean;
  relayProof?: Prisma.InputJsonValue | null;
  attestations?: Prisma.InputJsonValue | null;
  routeTokenVersion?: number;
  routeTokenPendingVersion?: number | null;
  activeTenantKey?: string | null;
  nextHealthCheckAt?: Date | null;
  disabledAt?: Date | null;
  disabledByUserId?: bigint | null;
}

/** A gateway domain of the scope (for linking). */
export interface ScopeDomainRow {
  id: bigint;
  publicId: string;
  name: string;
  status: string;
  /** The connection the domain is linked to, if any. */
  linkedConnectionId: bigint | null;
}

/** Statuses of a domain's MX, SPF and DKIM records (stored step 2.1 results). */
export interface DomainDnsSummary {
  mx: string | null;
  spf: string | null;
  dkim: string | null;
}

/** Destinations of a domain (role `inbound_destination`), in delivery order. */
export interface DomainDestinationRow {
  host: string;
  port: number;
  priority: number;
  tlsMode: string;
  provider: 'custom' | 'microsoft_365' | 'google_workspace';
}

/**
 * Tenant-scoped access to `provider_connections`, `provider_connection_domains` and the
 * connection's `provider_relay` row of `smtp_connectors` (step 8.2 §3, D4, D7.1). Reads from the
 * replica unless a transaction is given; writes inside the caller's writer transaction. Every
 * method takes the scope first; another organization's connection is simply not found.
 */
@Injectable()
export class ProviderConnectionsRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  /** Newest first, keyset on id (reader). */
  async list(
    scope: TenantScope,
    page: {
      take: number;
      beforeId?: bigint;
      providers?: IntegrationProvider[];
      statuses?: ProviderConnectionStatus[];
      health?: ProviderHealthStatus[];
    },
  ): Promise<ConnectionListRow[]> {
    const rows = await this.reader.client.providerConnection.findMany({
      where: tenantWhere(scope, {
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
        ...(page.providers && { provider: { in: page.providers } }),
        ...(page.statuses && { status: { in: page.statuses } }),
        ...(page.health && { healthStatus: { in: page.health } }),
      }),
      select: { ...connectionSelect, _count: { select: { domains: true } } },
      orderBy: { id: 'desc' },
      take: page.take,
    });
    return rows.map(({ _count, ...row }) => ({ ...row, domainCount: _count.domains }));
  }

  /** One connection with grants, domains and connector (reader unless `client`). */
  async aggregate(
    scope: TenantScope,
    publicId: string,
    client: Tx | Reader = this.reader.client,
  ): Promise<ConnectionAggregate | null> {
    const connection = await client.providerConnection.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: connectionSelect,
    });
    if (!connection) return null;
    return this.aggregateOf(scope, connection, client);
  }

  /** Locks the scope's connection (`SELECT … FOR UPDATE`) and loads its aggregate. */
  async lock(tx: Tx, scope: TenantScope, publicId: string): Promise<ConnectionAggregate | null> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM provider_connections
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
      FOR UPDATE`;
    const id = rows[0]?.id;
    if (id === undefined) return null;
    const connection = await tx.providerConnection.findFirst({
      where: tenantWhere(scope, { id }),
      select: connectionSelect,
    });
    if (!connection) return null;
    return this.aggregateOf(scope, connection, tx);
  }

  private async aggregateOf(
    scope: TenantScope,
    connection: ConnectionRow,
    client: Tx | Reader,
  ): Promise<ConnectionAggregate> {
    const [grants, links, connector] = await Promise.all([
      client.providerConnectionGrant.findMany({
        where: tenantWhere(scope, { connectionId: connection.id }),
        select: grantSelect,
        orderBy: { id: 'asc' },
      }),
      client.providerConnectionDomain.findMany({
        where: tenantWhere(scope, { connectionId: connection.id }),
        select: {
          providerVerification: true,
          providerCheckedAt: true,
          providerMxHost: true,
          inboundAppliedAt: true,
          domain: {
            select: {
              id: true,
              publicId: true,
              name: true,
              status: true,
              outboundEnabled: true,
              organizationId: true,
            },
          },
        },
        orderBy: { id: 'asc' },
      }),
      client.smtpConnector.findFirst({
        where: tenantWhere(scope, { providerConnectionId: connection.id }),
        select: { id: true, publicId: true, status: true },
      }),
    ]);
    return {
      connection,
      grants,
      domains: links
        .filter((l) => l.domain.organizationId === scope.organizationId)
        .map((l) => ({
          domainId: l.domain.id,
          domainPublicId: l.domain.publicId,
          name: l.domain.name,
          gatewayStatus: l.domain.status,
          outboundEnabled: l.domain.outboundEnabled,
          providerVerification: l.providerVerification,
          providerCheckedAt: l.providerCheckedAt,
          providerMxHost: l.providerMxHost,
          inboundAppliedAt: l.inboundAppliedAt,
        })),
      connector,
    };
  }

  /** Connections of the scope that are not `disabled` (the per-organization cap). */
  countLive(tx: Tx, scope: TenantScope): Promise<number> {
    return tx.providerConnection.count({
      where: tenantWhere(scope, { status: { not: 'disabled' as const } }),
    });
  }

  async nameTaken(tx: Tx, scope: TenantScope, name: string, exceptId?: bigint): Promise<boolean> {
    const row = await tx.providerConnection.findFirst({
      where: tenantWhere(scope, {
        displayName: name,
        ...(exceptId !== undefined && { id: { not: exceptId } }),
      }),
      select: { id: true },
    });
    return row !== null;
  }

  create(
    tx: Tx,
    scope: TenantScope,
    data: {
      publicId: string;
      provider: IntegrationProvider;
      displayName: string;
      createdByUserId: bigint | null;
    },
  ): Promise<{ id: bigint; publicId: string }> {
    return tx.providerConnection.create({
      data: { organizationId: scope.organizationId, status: 'draft', ...data },
      select: { id: true, publicId: true },
    });
  }

  /** CAS update on `row_version` (incremented); false when the version moved. */
  async update(
    tx: Tx,
    scope: TenantScope,
    id: bigint,
    rowVersion: number,
    changes: ConnectionChanges,
  ): Promise<boolean> {
    const { relayProof, attestations, ...rest } = changes;
    const { count } = await tx.providerConnection.updateMany({
      where: tenantWhere(scope, { id, rowVersion }),
      data: {
        ...rest,
        ...(relayProof !== undefined && {
          relayProof: relayProof === null ? Prisma.DbNull : relayProof,
        }),
        ...(attestations !== undefined && {
          attestations: attestations === null ? Prisma.DbNull : attestations,
        }),
        rowVersion: { increment: 1 },
      },
    });
    return count === 1;
  }

  // ---- Linked domains (D4) ---------------------------------------------------------------

  /** Domains of the scope by public id (any status except deleted), with their current link. */
  async scopeDomains(
    tx: Tx,
    scope: TenantScope,
    publicIds: readonly string[],
  ): Promise<ScopeDomainRow[]> {
    if (publicIds.length === 0) return [];
    const rows = await tx.domain.findMany({
      where: tenantWhere(scope, {
        publicId: { in: [...publicIds] },
        status: { not: 'deleted' as const },
      }),
      select: {
        id: true,
        publicId: true,
        name: true,
        status: true,
        providerConnectionDomain: { select: { connectionId: true, organizationId: true } },
      },
    });
    return rows.map((r) => ({
      id: r.id,
      publicId: r.publicId,
      name: r.name,
      status: r.status,
      linkedConnectionId:
        r.providerConnectionDomain?.organizationId === scope.organizationId
          ? r.providerConnectionDomain.connectionId
          : null,
    }));
  }

  async linkDomains(
    tx: Tx,
    scope: TenantScope,
    connectionId: bigint,
    domainIds: readonly bigint[],
  ): Promise<void> {
    if (domainIds.length === 0) return;
    await tx.providerConnectionDomain.createMany({
      data: domainIds.map((domainId) => ({
        organizationId: scope.organizationId,
        connectionId,
        domainId,
      })),
    });
  }

  async unlinkDomains(
    tx: Tx,
    scope: TenantScope,
    connectionId: bigint,
    domainIds: readonly bigint[],
  ): Promise<void> {
    if (domainIds.length === 0) return;
    await tx.providerConnectionDomain.deleteMany({
      where: tenantWhere(scope, { connectionId, domainId: { in: [...domainIds] } }),
    });
  }

  async markInboundApplied(
    tx: Tx,
    scope: TenantScope,
    connectionId: bigint,
    domainIds: readonly bigint[],
    userId: bigint | null,
    at: Date,
  ): Promise<void> {
    if (domainIds.length === 0) return;
    await tx.providerConnectionDomain.updateMany({
      where: tenantWhere(scope, { connectionId, domainId: { in: [...domainIds] } }),
      data: { inboundAppliedAt: at, inboundAppliedByUserId: userId },
    });
  }

  /** MX/SPF/DKIM record statuses per domain id (worst status per purpose). */
  async dnsSummaries(
    scope: TenantScope,
    domainIds: readonly bigint[],
    client: Tx | Reader = this.reader.client,
  ): Promise<Map<bigint, DomainDnsSummary>> {
    const out = new Map<bigint, DomainDnsSummary>();
    if (domainIds.length === 0) return out;
    const rows = await client.domainDnsRecord.findMany({
      where: tenantWhere(scope, {
        domainId: { in: [...domainIds] },
        purpose: { in: ['mx', 'spf', 'dkim'] as DnsRecordPurpose[] },
      }),
      select: { domainId: true, purpose: true, status: true },
    });
    const rank: Record<string, number> = { valid: 0, pending: 1, missing: 2, invalid: 3 };
    for (const id of domainIds) out.set(id, { mx: null, spf: null, dkim: null });
    for (const row of rows) {
      const summary = out.get(row.domainId);
      if (!summary) continue;
      const key = row.purpose as keyof DomainDnsSummary;
      const current = summary[key];
      if (current === null || (rank[row.status] ?? 0) > (rank[current] ?? 0)) {
        summary[key] = row.status;
      }
    }
    return out;
  }

  /** Current inbound destinations per domain id (delivery order). */
  async destinations(
    scope: TenantScope,
    domainIds: readonly bigint[],
    client: Tx | Reader = this.reader.client,
  ): Promise<Map<bigint, DomainDestinationRow[]>> {
    const out = new Map<bigint, DomainDestinationRow[]>();
    if (domainIds.length === 0) return out;
    const rows = await client.domainMailServer.findMany({
      where: tenantWhere(scope, {
        domainId: { in: [...domainIds] },
        role: 'inbound_destination' as const,
        enabled: true,
      }),
      select: {
        domainId: true,
        host: true,
        port: true,
        priority: true,
        tlsMode: true,
        provider: true,
      },
      orderBy: [{ priority: 'asc' }, { id: 'asc' }],
    });
    for (const id of domainIds) out.set(id, []);
    for (const row of rows) {
      if (row.host === null) continue;
      out.get(row.domainId)?.push({
        host: row.host,
        port: row.port,
        priority: row.priority,
        tlsMode: row.tlsMode,
        provider: row.provider,
      });
    }
    return out;
  }

  // ---- The provider_relay connector (D7.1) -----------------------------------------------

  countConnectors(tx: Tx, scope: TenantScope): Promise<number> {
    return tx.smtpConnector.count({ where: tenantWhere(scope) });
  }

  createRelayConnector(
    tx: Tx,
    scope: TenantScope,
    data: { name: string; providerConnectionId: bigint; createdByUserId: bigint | null },
  ): Promise<{ id: bigint; publicId: string }> {
    return tx.smtpConnector.create({
      data: {
        organizationId: scope.organizationId,
        name: data.name,
        authType: 'provider_relay',
        status: 'active',
        requireTls: true,
        providerConnectionId: data.providerConnectionId,
        createdByUserId: data.createdByUserId,
      },
      select: { id: true, publicId: true },
    });
  }

  async setRelayConnectorStatus(
    tx: Tx,
    scope: TenantScope,
    connectorId: bigint,
    status: 'active' | 'disabled',
  ): Promise<void> {
    await tx.smtpConnector.updateMany({
      where: tenantWhere(scope, { id: connectorId, authType: 'provider_relay' as const }),
      data: { status },
    });
  }

  /** The writer client (services pass it to read-after-write). */
  get writer(): PrismaService {
    return this.prisma;
  }
}
