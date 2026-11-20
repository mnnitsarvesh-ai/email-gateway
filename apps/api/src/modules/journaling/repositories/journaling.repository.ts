import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import {
  type ArchiveIntentStatus,
  type JournalIntakeHealthStatus,
  type JournalIntakeSourceKind,
  type JournalIntakeSourceStatus,
  Prisma,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho } from '../../../http/listing/echo-check';

type Tx = Prisma.TransactionClient;
type Client = Tx | PrismaService | PrismaReadService['client'];

export const sourceSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  kind: true,
  displayName: true,
  status: true,
  providerConnectionId: true,
  networks: true,
  requireTls: true,
  clientCertFingerprints: true,
  maxMessageBytes: true,
  silenceAlertMinutes: true,
  addressVersion: true,
  previousValidUntil: true,
  verifiedAt: true,
  lastAcceptedAt: true,
  lastRefusedAt: true,
  lastRefusalCode: true,
  healthStatus: true,
  healthChangedAt: true,
  attestations: true,
  disabledAt: true,
  rowVersion: true,
  createdAt: true,
  updatedAt: true,
  providerConnection: { select: { publicId: true } },
} satisfies Prisma.JournalIntakeSourceSelect;

/** A `journal_intake_sources` row as the api reads it (never a hash). */
export type SourceRow = Prisma.JournalIntakeSourceGetPayload<{ select: typeof sourceSelect }>;

export interface SourceCreate {
  publicId: string;
  kind: JournalIntakeSourceKind;
  displayName: string;
  providerConnectionId: bigint | null;
  networks: Prisma.InputJsonValue | null;
  requireTls: boolean;
  clientCertFingerprints: string[] | null;
  maxMessageBytes: number | null;
  silenceAlertMinutes: number | null;
  addressHash: string;
  headerTokenHash: string | null;
  createdByUserId: bigint | null;
}

export interface SourceUpdate {
  displayName?: string;
  status?: JournalIntakeSourceStatus;
  networks?: Prisma.InputJsonValue | null;
  requireTls?: boolean;
  clientCertFingerprints?: string[] | null;
  maxMessageBytes?: number | null;
  silenceAlertMinutes?: number | null;
  attestations?: Prisma.InputJsonValue;
  addressVersion?: number;
  addressHash?: string;
  previousAddressHash?: string | null;
  headerTokenHash?: string | null;
  previousHeaderTokenHash?: string | null;
  previousValidUntil?: Date | null;
  healthStatus?: JournalIntakeHealthStatus;
  healthChangedAt?: Date;
  disabledAt?: Date;
  disabledByUserId?: bigint | null;
}

/** The facts of an 8.2 connection that decide whether a source may use it. */
export interface ConnectionRef {
  id: bigint;
  publicId: string;
  displayName: string;
  provider: 'microsoft_365' | 'google_workspace';
  status: 'draft' | 'connecting' | 'configuring' | 'active' | 'disabled';
  activeTenantKey: string | null;
  externalTenantId: string | null;
}

export interface CounterRow {
  day: Date;
  accepted: number;
  duplicates: number;
  bytes: bigint;
  refusedAddress: number;
  refusedNetwork: number;
  refusedTls: number;
  refusedSize: number;
  refusedRate: number;
  refusedUnavailable: number;
  droppedProof: number;
  unwrapFailed: number;
}

const counterSelect = {
  organizationId: true,
  sourceId: true,
  day: true,
  accepted: true,
  duplicates: true,
  bytes: true,
  refusedAddress: true,
  refusedNetwork: true,
  refusedTls: true,
  refusedSize: true,
  refusedRate: true,
  refusedUnavailable: true,
  droppedProof: true,
  unwrapFailed: true,
} satisfies Prisma.JournalIntakeCounterSelect;

/** TXT-verified domain statuses (D1 domain requirement). */
const VERIFIED_DOMAIN_STATUSES = ['verified', 'active'] as const;

/** Most domain names a guide lists. */
const GUIDE_DOMAINS = 50;

/**
 * Journal intake sources, their counters, and the facts the journaling rules read (connections,
 * verified and linked domains, provider egress ranges, capture intents) (step 8.6 D1, D10, D11).
 * Replica reads for views, writer/transaction reads for every deciding path; every row read is
 * echo-checked on the organization (D15). Only hashes of intake credentials are written; they
 * are never selected.
 */
@Injectable()
export class JournalingRepository {
  constructor(
    private readonly reader: PrismaReadService,
    private readonly writer: PrismaService,
  ) {}

  private client(on: 'replica' | 'writer' | Tx): Client {
    return on === 'replica' ? this.reader.client : on === 'writer' ? this.writer : on;
  }

  // ---- sources ---------------------------------------------------------------------------------

  async list(
    scope: TenantScope,
    page: {
      take: number;
      beforeId?: bigint;
      statuses?: JournalIntakeSourceStatus[];
      kinds?: JournalIntakeSourceKind[];
      health?: JournalIntakeHealthStatus[];
    },
  ): Promise<SourceRow[]> {
    const rows = await this.reader.client.journalIntakeSource.findMany({
      where: tenantWhere(scope, {
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
        ...(page.statuses && { status: { in: page.statuses } }),
        ...(page.kinds && { kind: { in: page.kinds } }),
        ...(page.health && { healthStatus: { in: page.health } }),
      }),
      select: sourceSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
    assertEcho('journaling.sources.list', rows, { organizationId: scope.organizationId });
    return rows;
  }

  async byPublicId(
    scope: TenantScope,
    publicId: string,
    on: 'replica' | 'writer' | Tx = 'replica',
  ): Promise<SourceRow | null> {
    const row = await this.client(on).journalIntakeSource.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: sourceSelect,
    });
    if (row === null) return null;
    assertEcho('journaling.source', [row], { organizationId: scope.organizationId, publicId });
    return row;
  }

  /** `SELECT … FOR UPDATE` on the scope's source, then its row (writer transaction). */
  async lock(tx: Tx, scope: TenantScope, publicId: string): Promise<SourceRow | null> {
    const ids = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM journal_intake_sources
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
      FOR UPDATE`;
    if (ids.length === 0) return null;
    return this.byPublicId(scope, publicId, tx);
  }

  /** Sources that are not `disabled` (the per-organization limit). */
  countLive(tx: Tx, scope: TenantScope): Promise<number> {
    return tx.journalIntakeSource.count({
      where: tenantWhere(scope, { status: { not: 'disabled' as const } }),
    });
  }

  async nameTaken(tx: Tx, scope: TenantScope, name: string, exceptId?: bigint): Promise<boolean> {
    const row = await tx.journalIntakeSource.findFirst({
      where: tenantWhere(scope, {
        displayName: name,
        ...(exceptId !== undefined && { id: { not: exceptId } }),
      }),
      select: { id: true },
    });
    return row !== null;
  }

  async create(tx: Tx, scope: TenantScope, data: SourceCreate): Promise<void> {
    await tx.journalIntakeSource.create({
      data: {
        organizationId: scope.organizationId,
        publicId: data.publicId,
        kind: data.kind,
        displayName: data.displayName,
        providerConnectionId: data.providerConnectionId,
        networks: data.networks ?? Prisma.DbNull,
        requireTls: data.requireTls,
        clientCertFingerprints: data.clientCertFingerprints ?? Prisma.DbNull,
        maxMessageBytes: data.maxMessageBytes,
        silenceAlertMinutes: data.silenceAlertMinutes,
        addressHash: data.addressHash,
        headerTokenHash: data.headerTokenHash,
        createdByUserId: data.createdByUserId,
      },
      select: { id: true },
    });
  }

  /** CAS update on `row_version` (+1); false when the row changed meanwhile. */
  async update(
    tx: Tx,
    scope: TenantScope,
    id: bigint,
    rowVersion: number,
    data: SourceUpdate,
  ): Promise<boolean> {
    const { networks, clientCertFingerprints, ...rest } = data;
    const result = await tx.journalIntakeSource.updateMany({
      where: tenantWhere(scope, { id, rowVersion }),
      data: {
        ...rest,
        ...(networks !== undefined && { networks: networks ?? Prisma.DbNull }),
        ...(clientCertFingerprints !== undefined && {
          clientCertFingerprints: clientCertFingerprints ?? Prisma.DbNull,
        }),
        rowVersion: { increment: 1 },
      },
    });
    return result.count === 1;
  }

  /** Daily counters of a source since `fromDay` (UTC date), newest first (replica). */
  async counters(scope: TenantScope, sourceId: bigint, fromDay: Date): Promise<CounterRow[]> {
    const rows = await this.reader.client.journalIntakeCounter.findMany({
      where: tenantWhere(scope, { sourceId, day: { gte: fromDay } }),
      select: counterSelect,
      orderBy: { day: 'desc' },
      take: 31,
    });
    assertEcho('journaling.counters', rows, { organizationId: scope.organizationId, sourceId });
    return rows;
  }

  // ---- facts of the rules ------------------------------------------------------------------------

  /** An 8.2 connection of the organization by public id, or null (unknown or foreign). */
  async connectionByPublicId(
    scope: TenantScope,
    publicId: string,
    on: 'replica' | 'writer' | Tx = 'replica',
  ): Promise<ConnectionRef | null> {
    return this.connection(scope, { publicId }, on);
  }

  async connectionById(
    scope: TenantScope,
    id: bigint,
    on: 'replica' | 'writer' | Tx = 'replica',
  ): Promise<ConnectionRef | null> {
    return this.connection(scope, { id }, on);
  }

  private async connection(
    scope: TenantScope,
    where: { publicId: string } | { id: bigint },
    on: 'replica' | 'writer' | Tx,
  ): Promise<ConnectionRef | null> {
    const row = await this.client(on).providerConnection.findFirst({
      where: tenantWhere(scope, where),
      select: {
        id: true,
        organizationId: true,
        publicId: true,
        displayName: true,
        provider: true,
        status: true,
        activeTenantKey: true,
        externalTenantId: true,
      },
    });
    if (row === null) return null;
    assertEcho('journaling.connection', [row], { organizationId: scope.organizationId });
    const { organizationId: _org, ...ref } = row;
    return ref;
  }

  /** TXT-verified (`verified`/`active`) domains of the organization. */
  verifiedDomainCount(scope: TenantScope, on: 'replica' | 'writer' | Tx = 'replica') {
    return this.client(on).domain.count({
      where: tenantWhere(scope, { status: { in: [...VERIFIED_DOMAIN_STATUSES] } }),
    });
  }

  /** Verified domains linked to a connection (provider kinds). */
  linkedVerifiedDomainCount(
    scope: TenantScope,
    connectionId: bigint,
    on: 'replica' | 'writer' | Tx = 'replica',
  ) {
    return this.client(on).providerConnectionDomain.count({
      where: tenantWhere(scope, {
        connectionId,
        domain: { status: { in: [...VERIFIED_DOMAIN_STATUSES] } },
      }),
    });
  }

  /** Names of the verified domains (linked to `connectionId` when given) for a guide. */
  async verifiedDomainNames(scope: TenantScope, connectionId: bigint | null): Promise<string[]> {
    const rows = await this.reader.client.domain.findMany({
      where: tenantWhere(scope, {
        status: { in: [...VERIFIED_DOMAIN_STATUSES] },
        ...(connectionId !== null && { providerConnectionDomain: { is: { connectionId } } }),
      }),
      select: { organizationId: true, name: true },
      orderBy: { id: 'asc' },
      take: GUIDE_DOMAINS,
    });
    assertEcho('journaling.domains', rows, { organizationId: scope.organizationId });
    return rows.map((r) => r.name);
  }

  /** Every range of the active provider egress sets (platform data; the D1 overlap rule). */
  async providerEgressRanges(on: 'replica' | 'writer' | Tx = 'replica'): Promise<string[]> {
    const rows = await this.client(on).providerEgressRange.findMany({
      where: { set: { status: 'active' } },
      select: { cidr: true },
    });
    return rows.map((r) => r.cidr);
  }

  // ---- status ---------------------------------------------------------------------------------

  async intentCounts(scope: TenantScope): Promise<{
    byStatus: Partial<Record<ArchiveIntentStatus, number>>;
    oldestPendingAt: Date | null;
  }> {
    const db = this.reader.client;
    const [groups, oldest] = await Promise.all([
      db.archiveCaptureIntent.groupBy({
        by: ['status'],
        where: tenantWhere(scope),
        _count: { _all: true },
      }),
      db.archiveCaptureIntent.findFirst({
        where: tenantWhere(scope, { status: 'pending' as const }),
        select: { organizationId: true, createdAt: true },
        orderBy: { createdAt: 'asc' },
      }),
    ]);
    if (oldest !== null) {
      assertEcho('journaling.intents.oldest', [oldest], { organizationId: scope.organizationId });
    }
    return {
      byStatus: Object.fromEntries(groups.map((g) => [g.status, g._count._all])),
      oldestPendingAt: oldest?.createdAt ?? null,
    };
  }

  async sourceCounts(scope: TenantScope): Promise<{
    byStatus: Partial<Record<JournalIntakeSourceStatus, number>>;
    byHealth: Partial<Record<JournalIntakeHealthStatus, number>>;
  }> {
    const groups = await this.reader.client.journalIntakeSource.groupBy({
      by: ['status', 'healthStatus'],
      where: tenantWhere(scope),
      _count: { _all: true },
    });
    const byStatus: Partial<Record<JournalIntakeSourceStatus, number>> = {};
    const byHealth: Partial<Record<JournalIntakeHealthStatus, number>> = {};
    for (const g of groups) {
      byStatus[g.status] = (byStatus[g.status] ?? 0) + g._count._all;
      if (g.status === 'disabled') continue;
      byHealth[g.healthStatus] = (byHealth[g.healthStatus] ?? 0) + g._count._all;
    }
    return { byStatus, byHealth };
  }

  /** The organization's counters of one UTC day, summed over its sources (replica). */
  async dayTotals(scope: TenantScope, day: Date): Promise<CounterRow> {
    const agg = await this.reader.client.journalIntakeCounter.aggregate({
      where: tenantWhere(scope, { day }),
      _sum: {
        accepted: true,
        duplicates: true,
        bytes: true,
        refusedAddress: true,
        refusedNetwork: true,
        refusedTls: true,
        refusedSize: true,
        refusedRate: true,
        refusedUnavailable: true,
        droppedProof: true,
        unwrapFailed: true,
      },
    });
    const s = agg._sum;
    return {
      day,
      accepted: s.accepted ?? 0,
      duplicates: s.duplicates ?? 0,
      bytes: s.bytes ?? 0n,
      refusedAddress: s.refusedAddress ?? 0,
      refusedNetwork: s.refusedNetwork ?? 0,
      refusedTls: s.refusedTls ?? 0,
      refusedSize: s.refusedSize ?? 0,
      refusedRate: s.refusedRate ?? 0,
      refusedUnavailable: s.refusedUnavailable ?? 0,
      droppedProof: s.droppedProof ?? 0,
      unwrapFailed: s.unwrapFailed ?? 0,
    };
  }
}
