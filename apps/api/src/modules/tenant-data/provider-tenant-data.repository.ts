import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { TenantScope } from '../../auth-contracts/tenant-scope';

/**
 * The organization's Microsoft 365 / Google Workspace connection tables in the order the
 * organization purge deletes them (step 8.2 §3.3, docs/runbooks/organization-deletion.md): the
 * per-connection evidence and history first, then consent states, linked domains and grants,
 * then the connections. Every child table references `provider_connections` with CASCADE, but
 * the purge deletes them explicitly in short batches (no single cascading statement over a large
 * history). `smtp_connectors.provider_connection_id` references the connection with RESTRICT, so
 * the relay connectors are detached (`provider_connection_id = NULL`) before the connections go;
 * the connectors themselves are purged with the organization's other connectors.
 */
export const PROVIDER_PURGE_ORDER = [
  'provider_relay_counters',
  'provider_probe_observations',
  'provider_health_events',
  'provider_health_checks',
  'provider_validation_runs',
  'provider_consent_states',
  'provider_connection_domains',
  'provider_connection_grants',
] as const;
export type ProviderPurgeTable = (typeof PROVIDER_PURGE_ORDER)[number];

/** Rows one purge statement deletes (short statements, no long row locks). */
export const PROVIDER_PURGE_BATCH = 500;

export type ProviderPurgeCounts = Record<
  ProviderPurgeTable | 'smtp_connectors_detached' | 'provider_connections',
  number
>;

/** Rows of one export section (newest first per connection; bounded by retention, §3.3). */
const EXPORT_PAGE = 500;

/**
 * The organization's connection data for a tenant data export (step 8.2 §3.3): connections,
 * grants WITHOUT any credential material (no ciphertext, key id or fingerprint input; only the
 * 12-hex public fingerprint shown in the api), linked domains, validation runs (results and
 * summaries; never the probe token hash) and health transitions. Ids are public ids; dates ISO.
 */
export interface ProviderTenantExport {
  schema: 'provider-tenant-export/1';
  connections: Array<{
    id: string;
    provider: string;
    displayName: string;
    status: string;
    externalTenantId: string | null;
    externalTenantName: string | null;
    tenantVerifiedAt: string | null;
    outboundMode: string;
    internalRouting: boolean;
    relayProof: unknown;
    routeTokenVersion: number;
    attestations: unknown;
    healthStatus: string;
    healthChangedAt: string | null;
    disabledAt: string | null;
    createdAt: string;
    updatedAt: string;
  }>;
  grants: Array<{
    id: string;
    connectionId: string;
    profile: string;
    profileVersion: number;
    authMethod: string;
    status: string;
    clientId: string | null;
    subjectEmail: string | null;
    credentialVersion: number;
    credentialFingerprint: string | null;
    credentialSetAt: string | null;
    credentialExpiresAt: string | null;
    requestedPermissions: unknown;
    observedPermissions: unknown;
    missingPermissions: unknown;
    excessPermissions: unknown;
    consentedAt: string | null;
    verifiedAt: string | null;
    lastErrorCode: string | null;
    createdAt: string;
  }>;
  domains: Array<{
    connectionId: string;
    domainId: string;
    name: string;
    providerVerification: string;
    providerCheckedAt: string | null;
    providerMxHost: string | null;
    inboundAppliedAt: string | null;
    createdAt: string;
  }>;
  validationRuns: Array<{
    id: string;
    connectionId: string;
    kind: string;
    status: string;
    requestedByType: string;
    requestedById: string | null;
    results: unknown;
    summary: unknown;
    startedAt: string | null;
    completedAt: string | null;
    createdAt: string;
  }>;
  healthEvents: Array<{
    connectionId: string;
    fromStatus: string;
    toStatus: string;
    failingChecks: unknown;
    createdAt: string;
  }>;
}

const iso = (d: Date | null): string | null => (d === null ? null : d.toISOString());

/**
 * Deletes and exports an organization's provider-connection rows (step 8.2 §3.3) for the
 * organization purge and the tenant data export (docs/runbooks/organization-deletion.md). Writer
 * only, `systemScope` of the organization; each purge statement is its own autocommit `DELETE …
 * WHERE connection_id = ? AND organization_id = ? ORDER BY id LIMIT n` on an index whose leading
 * column is `connection_id`, repeated until fewer than n rows go, so a crash leaves a resumable,
 * consistent state and a re-run continues where it stopped. Never touches another organization's
 * rows; never reads credential ciphertext.
 */
@Injectable()
export class ProviderTenantDataRepository {
  constructor(private readonly prisma: PrismaService) {}

  async purgeOrganization(
    scope: TenantScope,
    batch: number = PROVIDER_PURGE_BATCH,
  ): Promise<ProviderPurgeCounts> {
    if (!Number.isSafeInteger(batch) || batch < 1) throw new Error('batch must be positive');
    const organizationId = scope.organizationId;
    const counts = {
      ...Object.fromEntries(PROVIDER_PURGE_ORDER.map((t) => [t, 0])),
      smtp_connectors_detached: 0,
      provider_connections: 0,
    } as ProviderPurgeCounts;
    const connectionIds = await this.connectionIds(organizationId);
    for (const table of PROVIDER_PURGE_ORDER) {
      for (const connectionId of connectionIds) {
        for (;;) {
          const deleted = await this.deleteBatch(table, organizationId, connectionId, batch);
          counts[table] += deleted;
          if (deleted < batch) break;
        }
      }
    }
    counts.smtp_connectors_detached = await this.prisma.$executeRaw`UPDATE smtp_connectors
      SET provider_connection_id = NULL
      WHERE organization_id = ${organizationId} AND provider_connection_id IS NOT NULL`;
    for (;;) {
      const deleted = await this.prisma.$executeRaw`DELETE FROM provider_connections
        WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      counts.provider_connections += deleted;
      if (deleted < batch) break;
    }
    return counts;
  }

  /** The organization's connection ids (also those a previous, interrupted purge left). */
  private async connectionIds(organizationId: bigint): Promise<bigint[]> {
    const rows = await this.prisma.providerConnection.findMany({
      where: { organizationId },
      select: { id: true },
      orderBy: { id: 'asc' },
    });
    return rows.map((r) => r.id);
  }

  /** One batch; the table name comes from the fixed PROVIDER_PURGE_ORDER list, never from input. */
  private deleteBatch(
    table: ProviderPurgeTable,
    organizationId: bigint,
    connectionId: bigint,
    batch: number,
  ): Promise<number> {
    switch (table) {
      case 'provider_relay_counters':
        return this.prisma.$executeRaw`DELETE FROM provider_relay_counters
          WHERE connection_id = ${connectionId} AND organization_id = ${organizationId}
          ORDER BY id LIMIT ${batch}`;
      case 'provider_probe_observations':
        return this.prisma.$executeRaw`DELETE FROM provider_probe_observations
          WHERE connection_id = ${connectionId} AND organization_id = ${organizationId}
          ORDER BY id LIMIT ${batch}`;
      case 'provider_health_events':
        return this.prisma.$executeRaw`DELETE FROM provider_health_events
          WHERE connection_id = ${connectionId} AND organization_id = ${organizationId}
          ORDER BY id LIMIT ${batch}`;
      case 'provider_health_checks':
        return this.prisma.$executeRaw`DELETE FROM provider_health_checks
          WHERE connection_id = ${connectionId} AND organization_id = ${organizationId}
          ORDER BY id LIMIT ${batch}`;
      case 'provider_validation_runs':
        return this.prisma.$executeRaw`DELETE FROM provider_validation_runs
          WHERE connection_id = ${connectionId} AND organization_id = ${organizationId}
          ORDER BY id LIMIT ${batch}`;
      case 'provider_consent_states':
        return this.prisma.$executeRaw`DELETE FROM provider_consent_states
          WHERE connection_id = ${connectionId} AND organization_id = ${organizationId}
          ORDER BY id LIMIT ${batch}`;
      case 'provider_connection_domains':
        return this.prisma.$executeRaw`DELETE FROM provider_connection_domains
          WHERE connection_id = ${connectionId} AND organization_id = ${organizationId}
          ORDER BY id LIMIT ${batch}`;
      case 'provider_connection_grants':
        return this.prisma.$executeRaw`DELETE FROM provider_connection_grants
          WHERE connection_id = ${connectionId} AND organization_id = ${organizationId}
          ORDER BY id LIMIT ${batch}`;
    }
  }

  /**
   * The organization's connection data (§3.3 export): connections, grants without credential
   * material, linked domains, validation runs and health events. Writer reads (the export runs
   * after a write freeze), paged by id.
   */
  async exportOrganization(scope: TenantScope): Promise<ProviderTenantExport> {
    const organizationId = scope.organizationId;
    const connections = await this.prisma.providerConnection.findMany({
      where: { organizationId },
      select: {
        id: true,
        publicId: true,
        provider: true,
        displayName: true,
        status: true,
        externalTenantId: true,
        externalTenantName: true,
        tenantVerifiedAt: true,
        outboundMode: true,
        internalRouting: true,
        relayProof: true,
        routeTokenVersion: true,
        attestations: true,
        healthStatus: true,
        healthChangedAt: true,
        disabledAt: true,
        createdAt: true,
        updatedAt: true,
      },
      orderBy: { id: 'asc' },
    });
    const publicIdOf = new Map(connections.map((c) => [c.id, c.publicId]));
    const out: ProviderTenantExport = {
      schema: 'provider-tenant-export/1',
      connections: connections.map((c) => ({
        id: c.publicId,
        provider: c.provider,
        displayName: c.displayName,
        status: c.status,
        externalTenantId: c.externalTenantId,
        externalTenantName: c.externalTenantName,
        tenantVerifiedAt: iso(c.tenantVerifiedAt),
        outboundMode: c.outboundMode,
        internalRouting: c.internalRouting,
        relayProof: c.relayProof,
        routeTokenVersion: c.routeTokenVersion,
        attestations: c.attestations,
        healthStatus: c.healthStatus,
        healthChangedAt: iso(c.healthChangedAt),
        disabledAt: iso(c.disabledAt),
        createdAt: c.createdAt.toISOString(),
        updatedAt: c.updatedAt.toISOString(),
      })),
      grants: [],
      domains: [],
      validationRuns: [],
      healthEvents: [],
    };
    for (const connection of connections) {
      const connectionId = connection.id;
      const connectionPublicId = publicIdOf.get(connectionId)!;
      const grants = await this.prisma.providerConnectionGrant.findMany({
        where: { organizationId, connectionId },
        // Never `credentialCiphertext` / `credentialKeyId` (ADR-0077).
        select: {
          publicId: true,
          profile: true,
          profileVersion: true,
          authMethod: true,
          status: true,
          clientId: true,
          subjectEmail: true,
          credentialVersion: true,
          credentialFingerprint: true,
          credentialSetAt: true,
          credentialExpiresAt: true,
          requestedPermissions: true,
          observedPermissions: true,
          missingPermissions: true,
          excessPermissions: true,
          consentedAt: true,
          verifiedAt: true,
          lastErrorCode: true,
          createdAt: true,
        },
        orderBy: { id: 'asc' },
      });
      for (const g of grants) {
        out.grants.push({
          id: g.publicId,
          connectionId: connectionPublicId,
          profile: g.profile,
          profileVersion: g.profileVersion,
          authMethod: g.authMethod,
          status: g.status,
          clientId: g.clientId,
          subjectEmail: g.subjectEmail,
          credentialVersion: g.credentialVersion,
          credentialFingerprint: g.credentialFingerprint?.slice(0, 12) ?? null,
          credentialSetAt: iso(g.credentialSetAt),
          credentialExpiresAt: iso(g.credentialExpiresAt),
          requestedPermissions: g.requestedPermissions,
          observedPermissions: g.observedPermissions,
          missingPermissions: g.missingPermissions,
          excessPermissions: g.excessPermissions,
          consentedAt: iso(g.consentedAt),
          verifiedAt: iso(g.verifiedAt),
          lastErrorCode: g.lastErrorCode,
          createdAt: g.createdAt.toISOString(),
        });
      }
      const links = await this.prisma.providerConnectionDomain.findMany({
        where: { organizationId, connectionId },
        select: {
          providerVerification: true,
          providerCheckedAt: true,
          providerMxHost: true,
          inboundAppliedAt: true,
          createdAt: true,
          domain: { select: { publicId: true, name: true } },
        },
        orderBy: { id: 'asc' },
      });
      for (const l of links) {
        out.domains.push({
          connectionId: connectionPublicId,
          domainId: l.domain.publicId,
          name: l.domain.name,
          providerVerification: l.providerVerification,
          providerCheckedAt: iso(l.providerCheckedAt),
          providerMxHost: l.providerMxHost,
          inboundAppliedAt: iso(l.inboundAppliedAt),
          createdAt: l.createdAt.toISOString(),
        });
      }
      for (let after: bigint | undefined; ;) {
        const runs = await this.prisma.providerValidationRun.findMany({
          where: {
            organizationId,
            connectionId,
            ...(after !== undefined && { id: { gt: after } }),
          },
          // Never `probeTokenSha256`.
          select: {
            id: true,
            publicId: true,
            kind: true,
            status: true,
            requestedByType: true,
            requestedById: true,
            results: true,
            summary: true,
            startedAt: true,
            completedAt: true,
            createdAt: true,
          },
          orderBy: { id: 'asc' },
          take: EXPORT_PAGE,
        });
        for (const r of runs) {
          out.validationRuns.push({
            id: r.publicId,
            connectionId: connectionPublicId,
            kind: r.kind,
            status: r.status,
            requestedByType: r.requestedByType,
            requestedById: r.requestedById,
            results: r.results,
            summary: r.summary,
            startedAt: iso(r.startedAt),
            completedAt: iso(r.completedAt),
            createdAt: r.createdAt.toISOString(),
          });
        }
        if (runs.length < EXPORT_PAGE) break;
        after = runs[runs.length - 1]!.id;
      }
      for (let after: bigint | undefined; ;) {
        const events = await this.prisma.providerHealthEvent.findMany({
          where: {
            organizationId,
            connectionId,
            ...(after !== undefined && { id: { gt: after } }),
          },
          select: {
            id: true,
            fromStatus: true,
            toStatus: true,
            failingChecks: true,
            createdAt: true,
          },
          orderBy: { id: 'asc' },
          take: EXPORT_PAGE,
        });
        for (const e of events) {
          out.healthEvents.push({
            connectionId: connectionPublicId,
            fromStatus: e.fromStatus,
            toStatus: e.toStatus,
            failingChecks: e.failingChecks,
            createdAt: e.createdAt.toISOString(),
          });
        }
        if (events.length < EXPORT_PAGE) break;
        after = events[events.length - 1]!.id;
      }
    }
    return out;
  }
}
