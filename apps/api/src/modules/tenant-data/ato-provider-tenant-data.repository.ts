import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { TenantScope } from '../../auth-contracts/tenant-scope';

/**
 * The organization's ATO identity-provider tables in the order the organization purge deletes
 * them (step 8.5 §4.1 "Purge and export", docs/runbooks/organization-deletion.md): the mailbox
 * items and the stream rows of each integration first (both reference the integration with
 * CASCADE, deleted explicitly in short batches), then the account identities (they reference the
 * integration with SET NULL and the account with CASCADE) and finally the integration rows, which
 * reference `organizations` with RESTRICT. `ato_response_actions.integration_id` has no foreign
 * key: action history is purged with the other `ato_*` rows by the 8.4 part of the purge.
 */
export const ATO_PROVIDER_PURGE_ORDER = [
  'ato_provider_mailbox_items',
  'ato_provider_streams',
  'ato_account_identities',
  'ato_provider_integrations',
] as const;
export type AtoProviderPurgeTable = (typeof ATO_PROVIDER_PURGE_ORDER)[number];
export type AtoProviderPurgeCounts = Record<AtoProviderPurgeTable, number>;

/** Rows one purge statement deletes (short statements, no long row locks). */
export const ATO_PROVIDER_PURGE_BATCH = 500;

/** Rows of one export page (paged by id). */
const EXPORT_PAGE = 500;

/**
 * The organization's identity-provider data for a tenant data export (§4.1): integrations
 * (settings, health, the permission NAMES observed on the grants, the provider-verified domains
 * of the tenant's own directory), stream status rows and mailbox state items (hashes, kinds,
 * target domains and trait codes). Never a provider token, credential, cursor, provider item id
 * or address. Ids are public ids; dates ISO; counters decimal strings.
 */
export interface AtoProviderTenantExport {
  schema: 'ato-provider-tenant-export/1';
  integrations: Array<{
    id: string;
    provider: string;
    connectionId: string | null;
    displayName: string | null;
    status: string;
    pausedReason: string | null;
    disabledReason: string | null;
    disabledAt: string | null;
    settings: unknown;
    settingsVersion: number;
    healthStatus: string;
    healthCheckedAt: string | null;
    grantedPermissions: unknown;
    directoryDomains: unknown;
    createdAt: string;
    updatedAt: string;
  }>;
  streams: Array<{
    integrationId: string;
    stream: string;
    role: string;
    enabled: boolean;
    status: string;
    availability: string;
    availabilityCode: string | null;
    watermarkAt: string | null;
    backfillFrom: string | null;
    backfillCompletedAt: string | null;
    lastSuccessAt: string | null;
    lastEventAt: string | null;
    lastErrorCode: string | null;
    eventsTotal: string;
    pagesTotal: string;
  }>;
  mailboxItems: Array<{
    id: string;
    integrationId: string;
    accountId: string | null;
    identityHash: string;
    kind: string;
    itemHash: string;
    targetDomain: string | null;
    traits: unknown;
    enabled: boolean | null;
    state: string;
    source: string;
    lastChange: string;
    firstSeenAt: string;
    lastSeenAt: string;
    removedAt: string | null;
  }>;
}

const iso = (d: Date | null): string | null => (d === null ? null : d.toISOString());

/**
 * Deletes and exports an organization's ATO identity-provider rows (step 8.5 §4.1) for the
 * organization purge and the tenant data export. Writer only, `systemScope` of the organization;
 * each purge statement is its own autocommit `DELETE … ORDER BY id LIMIT n`, repeated until fewer
 * than n rows go, so a crash leaves a consistent state and a re-run continues where it stopped.
 * Never touches another organization's rows.
 */
@Injectable()
export class AtoProviderTenantDataRepository {
  constructor(private readonly prisma: PrismaService) {}

  async purgeOrganization(
    scope: TenantScope,
    batch: number = ATO_PROVIDER_PURGE_BATCH,
  ): Promise<AtoProviderPurgeCounts> {
    if (!Number.isSafeInteger(batch) || batch < 1) throw new Error('batch must be positive');
    const organizationId = scope.organizationId;
    const counts = Object.fromEntries(
      ATO_PROVIDER_PURGE_ORDER.map((t) => [t, 0]),
    ) as AtoProviderPurgeCounts;
    const integrationIds = await this.integrationIds(organizationId);
    for (const table of ['ato_provider_mailbox_items', 'ato_provider_streams'] as const) {
      for (const integrationId of integrationIds) {
        for (;;) {
          const deleted = await this.deleteChildBatch(table, organizationId, integrationId, batch);
          counts[table] += deleted;
          if (deleted < batch) break;
        }
      }
    }
    for (;;) {
      const deleted = await this.prisma.$executeRaw`DELETE FROM ato_account_identities
        WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      counts.ato_account_identities += deleted;
      if (deleted < batch) break;
    }
    for (;;) {
      const deleted = await this.prisma.$executeRaw`DELETE FROM ato_provider_integrations
        WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      counts.ato_provider_integrations += deleted;
      if (deleted < batch) break;
    }
    return counts;
  }

  /** The organization's integration ids (also those a previous, interrupted purge left). */
  private async integrationIds(organizationId: bigint): Promise<bigint[]> {
    const rows = await this.prisma.atoProviderIntegration.findMany({
      where: { organizationId },
      select: { id: true },
      orderBy: { id: 'asc' },
    });
    return rows.map((r) => r.id);
  }

  /** One batch of a per-integration table (the name comes from the fixed list, never input). */
  private deleteChildBatch(
    table: 'ato_provider_mailbox_items' | 'ato_provider_streams',
    organizationId: bigint,
    integrationId: bigint,
    batch: number,
  ): Promise<number> {
    switch (table) {
      case 'ato_provider_mailbox_items':
        return this.prisma.$executeRaw`DELETE FROM ato_provider_mailbox_items
          WHERE integration_id = ${integrationId} AND organization_id = ${organizationId}
          ORDER BY id LIMIT ${batch}`;
      case 'ato_provider_streams':
        return this.prisma.$executeRaw`DELETE FROM ato_provider_streams
          WHERE integration_id = ${integrationId} AND organization_id = ${organizationId}
          ORDER BY id LIMIT ${batch}`;
    }
  }

  /**
   * The organization's identity-provider data (§4.1 export). Writer reads (the export runs after
   * a write freeze), paged by id.
   */
  async exportOrganization(scope: TenantScope): Promise<AtoProviderTenantExport> {
    const organizationId = scope.organizationId;
    const integrations = await this.prisma.atoProviderIntegration.findMany({
      where: { organizationId },
      orderBy: { id: 'asc' },
    });
    const publicIdOf = new Map(integrations.map((i) => [i.id, i.publicId]));
    const out: AtoProviderTenantExport = {
      schema: 'ato-provider-tenant-export/1',
      integrations: integrations.map((i) => ({
        id: i.publicId,
        provider: i.provider,
        connectionId: i.connectorRef,
        displayName: i.displayName,
        status: i.status,
        pausedReason: i.pausedReason,
        disabledReason: i.disabledReason,
        disabledAt: iso(i.disabledAt),
        settings: i.settings,
        settingsVersion: i.settingsVersion,
        healthStatus: i.healthStatus,
        healthCheckedAt: iso(i.healthCheckedAt),
        grantedPermissions: i.grantedPermissions ?? [],
        directoryDomains: i.directoryDomains ?? [],
        createdAt: i.createdAt.toISOString(),
        updatedAt: i.updatedAt.toISOString(),
      })),
      streams: [],
      mailboxItems: [],
    };
    if (integrations.length === 0) return out;
    const streams = await this.prisma.atoProviderStream.findMany({
      where: { organizationId },
      orderBy: { id: 'asc' },
    });
    out.streams = streams.flatMap((s) => {
      const integrationId = publicIdOf.get(s.integrationId);
      return integrationId === undefined
        ? []
        : [
            {
              integrationId,
              stream: s.stream,
              role: s.role,
              enabled: s.enabled,
              status: s.status,
              availability: s.availability,
              availabilityCode: s.availabilityCode,
              watermarkAt: iso(s.watermarkAt),
              backfillFrom: iso(s.backfillFrom),
              backfillCompletedAt: iso(s.backfillCompletedAt),
              lastSuccessAt: iso(s.lastSuccessAt),
              lastEventAt: iso(s.lastEventAt),
              lastErrorCode: s.lastErrorCode,
              eventsTotal: s.eventsTotal.toString(),
              pagesTotal: s.pagesTotal.toString(),
            },
          ];
    });
    let after = 0n;
    for (;;) {
      const page = await this.prisma.atoProviderMailboxItem.findMany({
        where: { organizationId, id: { gt: after } },
        orderBy: { id: 'asc' },
        take: EXPORT_PAGE,
      });
      if (page.length === 0) break;
      const accountIds = [
        ...new Set(page.flatMap((i) => (i.accountId === null ? [] : [i.accountId]))),
      ];
      const accounts =
        accountIds.length === 0
          ? []
          : await this.prisma.atoAccount.findMany({
              where: { organizationId, id: { in: accountIds } },
              select: { id: true, publicId: true },
            });
      const accountPublicId = new Map(accounts.map((a) => [a.id, a.publicId]));
      for (const i of page) {
        const integrationId = publicIdOf.get(i.integrationId);
        if (integrationId === undefined) continue;
        out.mailboxItems.push({
          id: i.publicId,
          integrationId,
          accountId: i.accountId === null ? null : (accountPublicId.get(i.accountId) ?? null),
          identityHash: i.identityExternalIdHash,
          kind: i.itemKind,
          itemHash: i.itemHash,
          targetDomain: i.targetDomain,
          traits: i.traits,
          enabled: i.enabled,
          state: i.state,
          source: i.source,
          lastChange: i.lastChange,
          firstSeenAt: i.firstSeenAt.toISOString(),
          lastSeenAt: i.lastSeenAt.toISOString(),
          removedAt: iso(i.removedAt),
        });
      }
      after = page[page.length - 1]!.id;
      if (page.length < EXPORT_PAGE) break;
    }
    return out;
  }
}
