import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import {
  type DomainStatus,
  type MailDestinationProvider,
  Prisma,
  type TlsMode,
} from '@email-gateway/database';
import {
  loadDestinationPresets,
  type MailDestinationPresetView,
} from '@email-gateway/mail-routing';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type { PlannedServer } from '../domain/destination-plan';

type Client = Prisma.TransactionClient;

/** The domain fields the destinations module needs. */
export interface DestinationDomainRow {
  id: bigint;
  publicId: string;
  name: string;
  status: DomainStatus;
}

const domainSelect = { id: true, publicId: true, name: true, status: true } as const;

const serverSelect = {
  publicId: true,
  host: true,
  port: true,
  priority: true,
  tlsMode: true,
  tlsVerifyNames: true,
  provider: true,
  enabled: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.DomainMailServerSelect;

export type DestinationServerRow = Prisma.DomainMailServerGetPayload<{
  select: typeof serverSelect;
}>;

/** TLS policy of another organization's destination on a shared host:port (nothing else). */
export interface SharedDestinationPolicy {
  host: string;
  port: number;
  tlsMode: TlsMode;
  tlsVerifyNames: string | null;
  provider: MailDestinationProvider;
}

/** Only inbound destinations; deprecated `outbound_source` rows are never read or touched. */
const ROLE = 'inbound_destination' as const;

/**
 * Tenant-scoped access to a domain's destination servers (`domain_mail_servers`, role
 * `inbound_destination`, step 2.3 R2) and the provider presets. Reads from the replica,
 * writes inside the caller's writer transaction.
 */
@Injectable()
export class DomainDestinationsRepository {
  constructor(private readonly reader: PrismaReadService) {}

  /** The scope's non-deleted domain (reader). */
  findDomain(scope: TenantScope, publicId: string): Promise<DestinationDomainRow | null> {
    return this.reader.client.domain.findFirst({
      where: tenantWhere(scope, { publicId, status: { not: 'deleted' as const } }),
      select: domainSelect,
    });
  }

  /**
   * Locks the scope's domain row in ANY status (`SELECT … FOR UPDATE`) so concurrent
   * replacements serialize; the caller refuses a deleted domain with `409`.
   */
  async lockDomain(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<DestinationDomainRow | null> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM domains
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
      FOR UPDATE`;
    const id = rows[0]?.id;
    if (id === undefined) return null;
    return tx.domain.findFirst({ where: tenantWhere(scope, { id }), select: domainSelect });
  }

  /** Every inbound destination of the domain in delivery order (priority, id). */
  listServers(
    scope: TenantScope,
    domainId: bigint,
    client: Client | PrismaReadService['client'] = this.reader.client,
  ): Promise<DestinationServerRow[]> {
    return client.domainMailServer.findMany({
      where: tenantWhere(scope, { domainId, role: ROLE }),
      select: serverSelect,
      orderBy: [{ priority: 'asc' }, { id: 'asc' }],
    });
  }

  /** Replaces every inbound destination of the domain (rows inserted in request order). */
  async replaceServers(
    tx: Client,
    scope: TenantScope,
    domainId: bigint,
    servers: readonly PlannedServer[],
  ): Promise<void> {
    await this.deleteServers(tx, scope, domainId);
    for (const server of servers) {
      // One insert per row (≤ 10) keeps ids in request order: ties in priority fail over in it.
      await tx.domainMailServer.create({
        data: {
          organizationId: scope.organizationId,
          domainId,
          role: ROLE,
          host: server.host,
          port: server.port,
          priority: server.priority,
          tlsMode: server.tlsMode,
          tlsVerifyNames: server.tlsVerifyNames,
          provider: server.provider,
          enabled: true,
        },
        select: { id: true },
      });
    }
  }

  /**
   * Locks the enabled inbound destinations of OTHER organizations on `hosts` (non-deleted
   * domains; `FOR UPDATE OF` the server rows only, through the (host, port) index, so a
   * concurrent write of the same host by another tenant serializes behind this transaction) and
   * returns their TLS policies. Postfix's `tls_policy` lookup is keyed by next hop, not by
   * tenant, so the caller refuses a write that would make a shared next hop disagree (review fix
   * of step 2.3). Only host, port and the TLS policy are read: no other tenant's ids or names.
   */
  async lockSharedDestinations(
    tx: Client,
    scope: TenantScope,
    hosts: readonly string[],
  ): Promise<SharedDestinationPolicy[]> {
    if (hosts.length === 0) return [];
    const rows = await tx.$queryRaw<
      Array<{
        host: string;
        port: number;
        tls_mode: TlsMode;
        tls_verify_names: string | null;
        provider: MailDestinationProvider;
      }>
    >`
      SELECT s.host, s.port, s.tls_mode, s.tls_verify_names, s.provider
      FROM domain_mail_servers s
      JOIN domains d ON d.id = s.domain_id
      WHERE s.host IN (${Prisma.join([...hosts])})
        AND s.role = ${ROLE}
        AND s.enabled = TRUE
        AND s.organization_id <> ${scope.organizationId}
        AND d.status <> 'deleted'
      FOR UPDATE OF s`;
    return rows.map((row) => ({
      host: row.host,
      port: Number(row.port),
      tlsMode: row.tls_mode,
      tlsVerifyNames: row.tls_verify_names,
      provider: row.provider,
    }));
  }

  /** Deletes every inbound destination of the domain; returns the count. */
  async deleteServers(tx: Client, scope: TenantScope, domainId: bigint): Promise<number> {
    const { count } = await tx.domainMailServer.deleteMany({
      where: tenantWhere(scope, { domainId, role: ROLE }),
    });
    return count;
  }

  /** The enabled presets (reader unless a transaction is given). */
  presets(client?: Client): Promise<MailDestinationPresetView[]> {
    return loadDestinationPresets(client ?? this.reader.client);
  }
}
