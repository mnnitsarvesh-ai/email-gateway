import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import type { Prisma, QuarantineStatus } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ActionRow, ApprovalRow, EntryRow, ReleaseRow } from '../domain/entry';
import {
  approvalSelect,
  entrySelect,
  releaseSelect,
  toApprovalRow,
  toEntryRow,
  toReleaseRow,
} from './entry-select';

/** A keyset position `(t, id)` of `(quarantined_at|created_at DESC, id DESC)`. */
export interface Keyset {
  t: Date;
  id: bigint;
}

/** The search filter as the repository applies it (Q9; built by the service). */
export interface EntrySearch {
  from: Date;
  to: Date;
  states?: QuarantineStatus[];
  kind?: 'quarantine' | 'review';
  direction?: 'inbound' | 'outbound' | 'internal';
  reasons?: string[];
  riskLevels?: string[];
  primaryEngines?: string[];
  policyId?: string;
  ruleId?: string;
  sender?: string;
  headerFrom?: string;
  senderDomain?: string;
  recipient?: string;
  hasAttachments?: boolean;
  hasHardBlock?: boolean;
  messageId?: bigint;
  after?: Keyset;
  take: number;
}

export interface ApprovalSearch {
  statuses?: string[];
  kinds?: string[];
  from?: Date;
  to?: Date;
  after?: Keyset;
  take: number;
}

/** The caller's own identity (self-service, SoD): from the writer (fresh). */
export interface UserIdentity {
  id: bigint;
  email: string;
  emailVerified: boolean;
  active: boolean;
}

/**
 * Read-only, tenant-scoped quarantine reads (step 5.3 Q9, Q10, Q14, Q24, Q26) on the replica
 * (`PrismaReadService`, writer fallback above the lag threshold): keyset search, entry detail,
 * history, releases, approvals, the bounded summary, settings and preferences. An entry just
 * created may be missing for the replication lag (documented). `identity` reads the writer.
 */
@Injectable()
export class QuarantineReadRepository {
  constructor(
    private readonly reader: PrismaReadService,
    private readonly prisma: PrismaService,
  ) {}

  private get db(): Prisma.TransactionClient {
    return this.reader.client;
  }

  /** The replica client for the shared facts reads. */
  get client(): Prisma.TransactionClient {
    return this.reader.client;
  }

  // ------------------------------------------------------------------ entries

  async search(scope: TenantScope, f: EntrySearch): Promise<EntryRow[]> {
    const and: Prisma.QuarantineMessageWhereInput[] = [];
    if (f.senderDomain !== undefined) {
      and.push({ envelopeFrom: { endsWith: `@${f.senderDomain}` } });
    }
    if (f.after !== undefined) {
      and.push({
        OR: [
          { quarantinedAt: { lt: f.after.t } },
          { quarantinedAt: f.after.t, id: { lt: f.after.id } },
        ],
      });
    }
    const rows = await this.db.quarantineMessage.findMany({
      where: tenantWhere(scope, {
        quarantinedAt: { gte: f.from, lt: f.to },
        ...(f.states !== undefined && { status: { in: f.states } }),
        ...(f.kind !== undefined && { kind: f.kind }),
        ...(f.direction !== undefined && { direction: f.direction }),
        ...(f.reasons !== undefined && {
          reason: { in: f.reasons as Prisma.EnumQuarantineReasonFilter['in'] },
        }),
        ...(f.riskLevels !== undefined && {
          riskLevel: { in: f.riskLevels as Prisma.EnumRiskLevelNullableFilter['in'] },
        }),
        ...(f.primaryEngines !== undefined && {
          primaryEngine: {
            in: f.primaryEngines as Prisma.EnumQuarantinePrimaryEngineFilter['in'],
          },
        }),
        ...(f.policyId !== undefined && { decisivePolicyPublicId: f.policyId }),
        ...(f.ruleId !== undefined && { decisiveRuleId: f.ruleId }),
        ...(f.sender !== undefined && { envelopeFrom: f.sender }),
        ...(f.headerFrom !== undefined && { headerFrom: f.headerFrom }),
        ...(f.recipient !== undefined && { recipientAddress: f.recipient }),
        ...(f.hasAttachments !== undefined && { hasAttachments: f.hasAttachments }),
        ...(f.hasHardBlock !== undefined && { hasHardBlock: f.hasHardBlock }),
        ...(f.messageId !== undefined && { messageId: f.messageId }),
        ...(and.length > 0 && { AND: and }),
      }),
      select: entrySelect,
      orderBy: [{ quarantinedAt: 'desc' }, { id: 'desc' }],
      take: f.take,
    });
    return rows.map(toEntryRow);
  }

  async entry(
    scope: TenantScope,
    publicId: string,
    selfAddress: string | null = null,
  ): Promise<EntryRow | null> {
    const row = await this.db.quarantineMessage.findFirst({
      where: tenantWhere(scope, {
        publicId,
        ...(selfAddress !== null && { recipientAddress: selfAddress }),
      }),
      select: entrySelect,
    });
    return row === null ? null : toEntryRow(row);
  }

  /** Registry public ids of the messages (`message_identities`). */
  async messagePublicIds(scope: TenantScope, ids: readonly bigint[]): Promise<Map<bigint, string>> {
    if (ids.length === 0) return new Map();
    const rows = await this.db.messageIdentity.findMany({
      where: tenantWhere(scope, { id: { in: [...new Set(ids)] } }),
      select: { id: true, publicId: true },
    });
    return new Map(rows.map((r) => [r.id, r.publicId]));
  }

  async messageIdByPublicId(scope: TenantScope, publicId: string): Promise<bigint | null> {
    const row = await this.db.messageIdentity.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true },
    });
    return row?.id ?? null;
  }

  /** `email_messages.subject` by `(message_id, received_at)` (Q9: only where allowed). */
  async subjects(
    scope: TenantScope,
    refs: ReadonlyArray<{ messageId: bigint; receivedAt: Date }>,
  ): Promise<Map<bigint, string | null>> {
    if (refs.length === 0) return new Map();
    const rows = await this.db.emailMessage.findMany({
      where: tenantWhere(scope, {
        OR: refs.map((r) => ({ id: r.messageId, receivedAt: r.receivedAt })),
      }),
      select: { id: true, subject: true },
    });
    return new Map(rows.map((r) => [r.id, r.subject]));
  }

  async approvalPublicIds(
    scope: TenantScope,
    ids: readonly bigint[],
  ): Promise<Map<bigint, string>> {
    if (ids.length === 0) return new Map();
    const rows = await this.db.quarantineApprovalRequest.findMany({
      where: tenantWhere(scope, { id: { in: [...new Set(ids)] } }),
      select: { id: true, publicId: true },
    });
    return new Map(rows.map((r) => [r.id, r.publicId]));
  }

  // ------------------------------------------------------------------ history, releases

  async actions(scope: TenantScope, entryId: bigint): Promise<ActionRow[]> {
    const rows = await this.db.quarantineAction.findMany({
      where: tenantWhere(scope, { quarantineMessageId: entryId }),
      select: {
        id: true,
        action: true,
        actorType: true,
        actorId: true,
        reason: true,
        result: true,
        details: true,
        createdAt: true,
      },
      orderBy: { id: 'desc' },
      take: 500,
    });
    return rows.reverse();
  }

  async releasesOfEntry(scope: TenantScope, entryId: bigint): Promise<ReleaseRow[]> {
    const rows = await this.db.quarantineReleaseLog.findMany({
      where: tenantWhere(scope, { quarantineMessageId: entryId }),
      select: releaseSelect,
      orderBy: { id: 'desc' },
      take: 100,
    });
    const approvals = await this.approvalPublicIds(
      scope,
      rows.flatMap((r) => (r.approvalRequestId === null ? [] : [r.approvalRequestId])),
    );
    return rows.map((r) => toReleaseRow(r, approvals));
  }

  async release(scope: TenantScope, releasePublicId: string): Promise<ReleaseRow[]> {
    const rows = await this.db.quarantineReleaseLog.findMany({
      where: tenantWhere(scope, { releasePublicId }),
      select: releaseSelect,
      orderBy: { id: 'asc' },
      take: 1000,
    });
    const approvals = await this.approvalPublicIds(
      scope,
      rows.flatMap((r) => (r.approvalRequestId === null ? [] : [r.approvalRequestId])),
    );
    return rows.map((r) => toReleaseRow(r, approvals));
  }

  // ------------------------------------------------------------------ approvals

  async approvals(scope: TenantScope, f: ApprovalSearch): Promise<ApprovalRow[]> {
    const rows = await this.db.quarantineApprovalRequest.findMany({
      where: tenantWhere(scope, {
        ...(f.statuses !== undefined && {
          status: { in: f.statuses as Prisma.EnumQuarantineApprovalStatusFilter['in'] },
        }),
        ...(f.kinds !== undefined && {
          kind: { in: f.kinds as Prisma.EnumQuarantineApprovalKindFilter['in'] },
        }),
        ...((f.from !== undefined || f.to !== undefined) && {
          createdAt: {
            ...(f.from !== undefined && { gte: f.from }),
            ...(f.to !== undefined && { lt: f.to }),
          },
        }),
        ...(f.after !== undefined && {
          OR: [{ createdAt: { lt: f.after.t } }, { createdAt: f.after.t, id: { lt: f.after.id } }],
        }),
      }),
      select: approvalSelect,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: f.take,
    });
    return this.withApiKeys(scope, rows);
  }

  async approval(scope: TenantScope, publicId: string): Promise<ApprovalRow | null> {
    const row = await this.db.quarantineApprovalRequest.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: approvalSelect,
    });
    if (row === null) return null;
    return (await this.withApiKeys(scope, [row]))[0]!;
  }

  private async withApiKeys(
    scope: TenantScope,
    rows: Prisma.QuarantineApprovalRequestGetPayload<{ select: typeof approvalSelect }>[],
  ): Promise<ApprovalRow[]> {
    const keyIds = rows.flatMap((r) =>
      r.requestedByApiKeyId === null ? [] : [r.requestedByApiKeyId],
    );
    const keys =
      keyIds.length === 0
        ? []
        : await this.db.apiKey.findMany({
            where: tenantWhere(scope, { id: { in: keyIds } }),
            select: { id: true, publicId: true },
          });
    const map = new Map(keys.map((k) => [k.id, k.publicId]));
    return rows.map((r) => toApprovalRow(r, map));
  }

  // ------------------------------------------------------------------ summary, settings

  async countsByState(scope: TenantScope, from: Date, to: Date): Promise<Map<string, number>> {
    const rows = await this.db.quarantineMessage.groupBy({
      by: ['status'],
      where: tenantWhere(scope, { quarantinedAt: { gte: from, lt: to } }),
      _count: { _all: true },
    });
    return new Map(rows.map((r) => [r.status, r._count._all]));
  }

  pendingApprovals(scope: TenantScope): Promise<number> {
    return this.db.quarantineApprovalRequest.count({
      where: tenantWhere(scope, { status: 'pending' as const }),
    });
  }

  async settings(scope: TenantScope): Promise<{ settings: unknown; rowVersion: number } | null> {
    const row = await this.db.quarantineSettings.findFirst({
      where: tenantWhere(scope),
      select: { settings: true, rowVersion: true },
    });
    return row;
  }

  orgSettings(scope: TenantScope): Promise<{
    quarantineRetentionDays: number;
    digestEnabled: boolean;
    digestSchedule: string;
    timezone: string;
  } | null> {
    return this.db.organizationSetting.findFirst({
      where: tenantWhere(scope),
      select: {
        quarantineRetentionDays: true,
        digestEnabled: true,
        digestSchedule: true,
        timezone: true,
      },
    });
  }

  async preferences(scope: TenantScope, userId: bigint): Promise<boolean> {
    const row = await this.db.quarantineUserPreference.findFirst({
      where: tenantWhere(scope, { userId }),
      select: { digestOptOut: true },
    });
    return row?.digestOptOut ?? false;
  }

  /** The caller's user row on the writer (status, email, verification). */
  async identity(userId: bigint): Promise<UserIdentity | null> {
    const row = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
      select: { id: true, email: true, emailVerifiedAt: true, status: true },
    });
    if (row === null) return null;
    return {
      id: row.id,
      email: row.email.trim().toLowerCase(),
      emailVerified: row.emailVerifiedAt !== null,
      active: row.status === 'active',
    };
  }
}
