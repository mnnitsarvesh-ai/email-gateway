import { Injectable } from '@nestjs/common';
import { PrismaReadService, uuidv7 } from '@email-gateway/common';
import {
  type ApiModeScopeKind,
  type DomainOwnershipMethod,
  type DomainStatus,
  Prisma,
  type ProtectionMode,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';

type Client = Prisma.TransactionClient;
type Reader = PrismaReadService['client'];

/** A domain as the coverage and onboarding views read it (ids, names, codes). */
export interface OnboardingDomainRow {
  id: bigint;
  publicId: string;
  name: string;
  status: DomainStatus;
  configuredMode: ProtectionMode | null;
  organizationMode: ProtectionMode;
  inboundEnabled: boolean;
  outboundEnabled: boolean;
  ownershipMethod: DomainOwnershipMethod | null;
  createdAt: Date;
  activatedAt: Date | null;
  /** null: no MX observation stored; else whether one points to the gateway. */
  mxPointsToGateway: boolean | null;
  /** `provider_connections.id` of the linked connection, or null. */
  linkedConnectionId: bigint | null;
}

/** Per-domain mailbox figures (non-deleted mailboxes; counts only). */
export interface DomainMailboxStats {
  total: number;
  inScope: number;
  excluded: number;
  covered: number;
  gap: number;
  feedsActive: number;
  selected: number;
  lastSeenAt: Date | null;
}

export interface DomainSettingsRow {
  domainId: bigint;
  scopeKind: ApiModeScopeKind;
  scopeDepartmentIds: Prisma.JsonValue;
  scopeRecomputeRequestedAt: Date | null;
  firstCopyId: bigint | null;
  firstCopyReceivedAt: Date | null;
  rowVersion: number;
  updatedAt: Date;
}

/** The first copy as the onboarding view shows it (no address, no content). */
export interface FirstCopyRow {
  publicId: string;
  receivedAt: Date;
  verdict: string | null;
  lagMs: number | null;
  source: 'journal' | 'graph' | 'gmail';
  policyState: string;
  remediationState: string;
}

export interface JournalSourceRow {
  publicId: string;
  status: 'pending_verification' | 'active' | 'paused' | 'disabled';
  healthStatus: 'unknown' | 'healthy' | 'silent' | 'failing' | 'paused';
  verifiedAt: Date | null;
  lastAcceptedAt: Date | null;
}

const EMPTY_STATS: DomainMailboxStats = Object.freeze({
  total: 0,
  inScope: 0,
  excluded: 0,
  covered: 0,
  gap: 0,
  feedsActive: 0,
  selected: 0,
  lastSeenAt: null,
});

const num = (v: unknown): number => (v === null || v === undefined ? 0 : Number(v));
const DAY_MS = 86_400_000;

/**
 * Reads and writes of the API-mode onboarding routes (step API-4 A10, B6, B8; ADR-0107): the
 * organization's domains with their mode, MX and link facts, per-domain mailbox figures and
 * `api_mode_domain_settings` (scope, first copy), the first-copy fallback, journal sources,
 * departments of a scope, and the scope write (row upsert with CAS, `scope_selected` clear + set).
 * Every query is filtered by the scope's organization (foreign ids read as missing); views read
 * the replica, the scope PUT the writer inside the caller's transaction.
 */
@Injectable()
export class ApiModeOnboardingRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private domainSql(scope: TenantScope, where: Prisma.Sql, limit: number): Prisma.Sql {
    return Prisma.sql`
      SELECT d.id, d.public_id AS publicId, d.name, d.status, d.protection_mode AS configuredMode,
             o.protection_mode AS organizationMode, d.inbound_enabled AS inboundEnabled,
             d.outbound_enabled AS outboundEnabled, d.ownership_method AS ownershipMethod,
             d.created_at AS createdAt, d.activated_at AS activatedAt,
             (SELECT MAX(mx.points_to_gateway) FROM domain_mx_records mx
               WHERE mx.domain_id = d.id AND mx.organization_id = d.organization_id) AS mxGateway,
             (SELECT pcd.connection_id FROM provider_connection_domains pcd
               WHERE pcd.domain_id = d.id AND pcd.organization_id = d.organization_id
               LIMIT 1) AS linkedConnectionId
      FROM domains d
      JOIN organizations o ON o.id = d.organization_id
      WHERE d.organization_id = ${scope.organizationId} AND d.status <> 'deleted' AND ${where}
      ORDER BY d.id DESC
      LIMIT ${limit}`;
  }

  private async domainRows(client: Client | Reader, sql: Prisma.Sql) {
    const rows = await client.$queryRaw<Array<Record<string, unknown>>>(sql);
    return rows.map((r): OnboardingDomainRow => ({
      id: BigInt(r.id as bigint),
      publicId: r.publicId as string,
      name: r.name as string,
      status: r.status as DomainStatus,
      configuredMode: (r.configuredMode as ProtectionMode | null) ?? null,
      organizationMode: (r.organizationMode as ProtectionMode | null) ?? 'inline',
      inboundEnabled: Boolean(r.inboundEnabled),
      outboundEnabled: Boolean(r.outboundEnabled),
      ownershipMethod: (r.ownershipMethod as DomainOwnershipMethod | null) ?? null,
      createdAt: r.createdAt as Date,
      activatedAt: (r.activatedAt as Date | null) ?? null,
      mxPointsToGateway: r.mxGateway === null ? null : Number(r.mxGateway) === 1,
      linkedConnectionId:
        r.linkedConnectionId === null ? null : BigInt(r.linkedConnectionId as bigint),
    }));
  }

  /** A page of non-deleted domains, newest first (keyset on id), optionally by effective mode. */
  domains(
    scope: TenantScope,
    page: { take: number; beforeId?: bigint; modes?: ProtectionMode[] },
  ): Promise<OnboardingDomainRow[]> {
    const terms: Prisma.Sql[] = [Prisma.sql`1 = 1`];
    if (page.beforeId !== undefined) terms.push(Prisma.sql`d.id < ${page.beforeId}`);
    if (page.modes) {
      terms.push(
        Prisma.sql`COALESCE(d.protection_mode, o.protection_mode) IN (${Prisma.join(page.modes)})`,
      );
    }
    return this.domainRows(
      this.reader.client,
      this.domainSql(scope, Prisma.join(terms, ' AND '), page.take),
    );
  }

  /** One non-deleted domain by public id (replica). */
  async domain(scope: TenantScope, publicId: string): Promise<OnboardingDomainRow | null> {
    const rows = await this.domainRows(
      this.reader.client,
      this.domainSql(scope, Prisma.sql`d.public_id = ${publicId}`, 1),
    );
    return rows[0] ?? null;
  }

  /** The non-deleted domain by public id, locked (`FOR UPDATE`) in the caller's transaction. */
  async lockDomain(tx: Client, scope: TenantScope, publicId: string) {
    const ids = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM domains
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
        AND status <> 'deleted'
      FOR UPDATE`;
    if (ids.length === 0) return null;
    const rows = await this.domainRows(
      tx,
      this.domainSql(scope, Prisma.sql`d.id = ${BigInt(ids[0]!.id)}`, 1),
    );
    return rows[0] ?? null;
  }

  /** Per-domain mailbox figures (replica unless `client`). */
  async mailboxStats(
    scope: TenantScope,
    domainIds: readonly bigint[],
    client: Client | Reader = this.reader.client,
  ): Promise<Map<bigint, DomainMailboxStats>> {
    const out = new Map<bigint, DomainMailboxStats>();
    if (domainIds.length === 0) return out;
    const rows = await client.$queryRaw<Array<Record<string, unknown>>>`
      SELECT domain_id AS domainId,
             COUNT(*) AS total,
             SUM(scope_state = 'in_scope') AS inScope,
             SUM(scope_state = 'excluded') AS excluded,
             SUM(status = 'active' AND scope_state = 'in_scope' AND coverage_state = 'covered')
               AS covered,
             SUM(status = 'active' AND scope_state = 'in_scope' AND coverage_state = 'gap') AS gap,
             SUM(status = 'active' AND scope_state = 'in_scope' AND feed_status = 'active')
               AS feedsActive,
             SUM(scope_selected = 1) AS selected,
             GREATEST(COALESCE(MAX(journal_last_seen_at), '1970-01-01'),
                      COALESCE(MAX(last_change_at), '1970-01-01')) AS lastSeenAt
      FROM api_mailboxes
      WHERE organization_id = ${scope.organizationId} AND status <> 'deleted'
        AND domain_id IN (${Prisma.join([...domainIds])})
      GROUP BY domain_id`;
    for (const r of rows) {
      const last = r.lastSeenAt as Date | string | null;
      const lastDate = last === null ? null : new Date(last);
      out.set(BigInt(r.domainId as bigint), {
        total: num(r.total),
        inScope: num(r.inScope),
        excluded: num(r.excluded),
        covered: num(r.covered),
        gap: num(r.gap),
        feedsActive: num(r.feedsActive),
        selected: num(r.selected),
        lastSeenAt: lastDate !== null && lastDate.getTime() > 0 ? lastDate : null,
      });
    }
    return out;
  }

  static emptyStats(): DomainMailboxStats {
    return { ...EMPTY_STATS };
  }

  /** `api_mode_domain_settings` of the domains (replica unless `client`). */
  async settings(
    scope: TenantScope,
    domainIds: readonly bigint[],
    client: Client | Reader = this.reader.client,
  ): Promise<Map<bigint, DomainSettingsRow>> {
    if (domainIds.length === 0) return new Map();
    const rows = await client.apiModeDomainSetting.findMany({
      where: tenantWhere(scope, { domainId: { in: [...domainIds] } }),
      select: {
        domainId: true,
        scopeKind: true,
        scopeDepartmentIds: true,
        scopeRecomputeRequestedAt: true,
        firstCopyId: true,
        firstCopyReceivedAt: true,
        rowVersion: true,
        updatedAt: true,
      },
    });
    return new Map(rows.map((r) => [r.domainId, r]));
  }

  /** The stored first copy (partitioned: id + received_at), or null when it is gone. */
  async copy(scope: TenantScope, id: bigint, receivedAt: Date): Promise<FirstCopyRow | null> {
    return this.reader.client.apiMessageCopy.findFirst({
      where: tenantWhere(scope, { id, receivedAt }),
      select: {
        publicId: true,
        receivedAt: true,
        verdict: true,
        lagMs: true,
        source: true,
        policyState: true,
        remediationState: true,
      },
    });
  }

  /**
   * B8 fallback without a stored first copy: the newest inbound/internal copy of at most 50 of
   * the domain's mailboxes in the last 7 days (index `(organization_id, mailbox_id,
   * received_at)`), or null.
   */
  async newestCopy(scope: TenantScope, domainId: bigint, now: Date): Promise<FirstCopyRow | null> {
    const mailboxes = await this.reader.client.apiMailbox.findMany({
      where: tenantWhere(scope, { domainId, status: { not: 'deleted' as const } }),
      select: { id: true },
      orderBy: { id: 'asc' },
      take: 50,
    });
    if (mailboxes.length === 0) return null;
    return this.reader.client.apiMessageCopy.findFirst({
      where: tenantWhere(scope, {
        mailboxId: { in: mailboxes.map((m) => m.id) },
        receivedAt: { gte: new Date(now.getTime() - 7 * DAY_MS) },
        direction: { in: ['inbound' as const, 'internal' as const] },
      }),
      select: {
        publicId: true,
        receivedAt: true,
        verdict: true,
        lagMs: true,
        source: true,
        policyState: true,
        remediationState: true,
      },
      orderBy: [{ receivedAt: 'desc' }, { id: 'desc' }],
    });
  }

  /** Copies of the API connection that failed to scan or parse since `since` (≤ cap). */
  async failedCopies(
    scope: TenantScope,
    apiConnectionId: bigint,
    since: Date,
    cap: number,
  ): Promise<number> {
    const rows = await this.reader.client.$queryRaw<Array<{ n: bigint | number }>>`
      SELECT COUNT(*) AS n FROM (
        SELECT 1 FROM api_message_copies
        WHERE organization_id = ${scope.organizationId} AND received_at >= ${since}
          AND api_connection_id = ${apiConnectionId}
          AND status IN ('scan_failed', 'parse_failed')
        LIMIT ${cap}
      ) t`;
    return num(rows[0]?.n);
  }

  /** The provider journal sources of a connection with their last acceptance. */
  journalSources(scope: TenantScope, connectionId: bigint): Promise<JournalSourceRow[]> {
    return this.reader.client.journalIntakeSource.findMany({
      where: tenantWhere(scope, { providerConnectionId: connectionId }),
      select: {
        publicId: true,
        status: true,
        healthStatus: true,
        verifiedAt: true,
        lastAcceptedAt: true,
      },
      orderBy: { id: 'asc' },
      take: 20,
    });
  }

  /** `*.mail_flow` grant status per provider connection (newest grant). */
  async mailFlowGrants(
    scope: TenantScope,
    connectionIds: readonly bigint[],
  ): Promise<Map<bigint, string>> {
    if (connectionIds.length === 0) return new Map();
    const rows = await this.reader.client.providerConnectionGrant.findMany({
      where: tenantWhere(scope, {
        connectionId: { in: [...connectionIds] },
        profile: { endsWith: '.mail_flow' },
      }),
      select: { connectionId: true, status: true },
      orderBy: { updatedAt: 'desc' },
    });
    const out = new Map<bigint, string>();
    for (const r of rows) if (!out.has(r.connectionId)) out.set(r.connectionId, r.status);
    return out;
  }

  // ---- scope (B6) ----------------------------------------------------------------------------

  /** Departments of the organization by public id with their member counts (replica/`client`). */
  async departments(
    scope: TenantScope,
    publicIds: readonly string[],
    client: Client | Reader = this.reader.client,
  ): Promise<Array<{ publicId: string; name: string; memberCount: number }>> {
    if (publicIds.length === 0) return [];
    const rows = await client.tenantDepartment.findMany({
      where: tenantWhere(scope, { publicId: { in: [...publicIds] } }),
      select: { publicId: true, name: true, _count: { select: { members: true } } },
    });
    return rows.map((r) => ({ publicId: r.publicId, name: r.name, memberCount: r._count.members }));
  }

  /**
   * The organization's departments among `publicIds`, locked `FOR SHARE` (a concurrent delete
   * waits for the scope write, or the write sees the delete): their public ids.
   */
  async lockDepartments(
    tx: Client,
    scope: TenantScope,
    publicIds: readonly string[],
  ): Promise<Set<string>> {
    if (publicIds.length === 0) return new Set();
    const rows = await tx.$queryRaw<Array<{ publicId: string }>>`
      SELECT public_id AS publicId FROM tenant_departments
      WHERE organization_id = ${scope.organizationId}
        AND public_id IN (${Prisma.join([...publicIds])})
      FOR SHARE`;
    return new Set(rows.map((r) => r.publicId.toLowerCase()));
  }

  /** The domain's settings row, locked (`FOR UPDATE`), or null. */
  async lockSettings(tx: Client, scope: TenantScope, domainId: bigint) {
    await tx.$queryRaw`SELECT id FROM api_mode_domain_settings
      WHERE organization_id = ${scope.organizationId} AND domain_id = ${domainId} FOR UPDATE`;
    return (await this.settings(scope, [domainId], tx)).get(domainId) ?? null;
  }

  /** Internal ids of the requested mailboxes that are non-deleted mailboxes of the domain. */
  async domainMailboxIds(
    tx: Client,
    scope: TenantScope,
    domainId: bigint,
    publicIds: readonly string[],
  ): Promise<bigint[]> {
    if (publicIds.length === 0) return [];
    const rows = await tx.apiMailbox.findMany({
      where: tenantWhere(scope, {
        domainId,
        status: { not: 'deleted' as const },
        publicId: { in: publicIds.map((id) => id.toLowerCase()) },
      }),
      select: { id: true },
    });
    return rows.map((r) => r.id);
  }

  /** Creates the row (CAS create) or updates it at `rowVersion` (+1); false on a lost race. */
  async writeSettings(
    tx: Client,
    scope: TenantScope,
    domainId: bigint,
    rowVersion: number | null,
    data: {
      scopeKind: ApiModeScopeKind;
      scopeDepartmentIds: string[] | null;
      now: Date;
      updatedByUserId: bigint | null;
    },
  ): Promise<boolean> {
    const values = {
      scopeKind: data.scopeKind,
      scopeDepartmentIds:
        data.scopeDepartmentIds === null
          ? Prisma.DbNull
          : (data.scopeDepartmentIds as Prisma.InputJsonValue),
      scopeChangedAt: data.now,
      scopeRecomputeRequestedAt: data.now,
      updatedByUserId: data.updatedByUserId,
    };
    if (rowVersion === null) {
      await tx.apiModeDomainSetting.create({
        data: {
          publicId: uuidv7(),
          organizationId: scope.organizationId,
          domainId,
          ...values,
        },
        select: { id: true },
      });
      return true;
    }
    const { count } = await tx.apiModeDomainSetting.updateMany({
      where: tenantWhere(scope, { domainId, rowVersion }),
      data: { ...values, rowVersion: { increment: 1 } },
    });
    return count === 1;
  }

  /** B6: clears `scope_selected` of the domain's mailboxes and sets it for `ids`. */
  async replaceSelection(
    tx: Client,
    scope: TenantScope,
    domainId: bigint,
    ids: readonly bigint[],
  ): Promise<{ cleared: number; selected: number }> {
    const cleared = await tx.apiMailbox.updateMany({
      where: tenantWhere(scope, { domainId, scopeSelected: true }),
      data: { scopeSelected: false },
    });
    let selected = 0;
    for (let i = 0; i < ids.length; i += 1000) {
      const chunk = ids.slice(i, i + 1000);
      const r = await tx.apiMailbox.updateMany({
        where: tenantWhere(scope, { domainId, id: { in: [...chunk] } }),
        data: { scopeSelected: true },
      });
      selected += r.count;
    }
    return { cleared: cleared.count, selected };
  }
}
