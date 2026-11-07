import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import type { Prisma, PrismaClient } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { InconsistentDlpReadError } from '../dlp.errors';
import {
  DLP_ID_KINDS,
  type DlpIdMaps,
  type DlpRefs,
  type DlpResultRowInput,
} from '../domain/dlp-result';

type Client = Prisma.TransactionClient;
type Reader = Pick<
  PrismaClient,
  'dlpPolicy' | 'dlpPolicyRule' | 'dlpException' | 'dlpCustomPattern' | 'dlpKeywordDictionary'
>;

/**
 * This organization's public ids of the policies, rules, exceptions, custom patterns and
 * dictionaries a stored result references (internal ids mapped, public ids verified). Every
 * query matches the scope's organization: another tenant's ids are never mapped.
 */
export async function resolveDlpIds(
  db: Reader,
  scope: TenantScope,
  refs: DlpRefs,
): Promise<DlpIdMaps> {
  const select = { id: true, publicId: true } as const;
  const where = (kind: keyof DlpRefs) => {
    const internal = [...refs[kind].internal].map((id) => BigInt(id));
    const known = [...refs[kind].public];
    if (internal.length === 0 && known.length === 0) return null;
    return tenantWhere(scope, {
      OR: [
        ...(internal.length > 0 ? [{ id: { in: internal } }] : []),
        ...(known.length > 0 ? [{ publicId: { in: known } }] : []),
      ],
    });
  };
  const run = async (kind: keyof DlpRefs): Promise<Array<{ id: bigint; publicId: string }>> => {
    const w = where(kind);
    if (w === null) return [];
    switch (kind) {
      case 'policy':
        return db.dlpPolicy.findMany({ where: w, select });
      case 'rule':
        return db.dlpPolicyRule.findMany({ where: w, select });
      case 'exception':
        return db.dlpException.findMany({ where: w, select });
      case 'pattern':
        return db.dlpCustomPattern.findMany({ where: w, select });
      case 'dictionary':
        return db.dlpKeywordDictionary.findMany({ where: w, select });
    }
  };
  const results = await Promise.all(DLP_ID_KINDS.map((kind) => run(kind)));
  return Object.fromEntries(
    DLP_ID_KINDS.map((kind, i) => {
      const rows = results[i]!;
      return [
        kind,
        {
          byInternal: new Map(rows.map((r) => [r.id.toString(), r.publicId.toLowerCase()])),
          known: new Set(rows.map((r) => r.publicId.toLowerCase())),
        },
      ];
    }),
  ) as DlpIdMaps;
}

export const dlpResultSelect = {
  id: true,
  scanId: true,
  receivedAt: true,
  messageId: true,
  lifecycleRound: true,
  direction: true,
  engineVersion: true,
  rulesVersion: true,
  settingsVersion: true,
  policyVersion: true,
  extractorVersion: true,
  verdict: true,
  action: true,
  actionSource: true,
  matchedPolicyId: true,
  matchedRuleId: true,
  coverage: true,
  coverageDetail: true,
  categories: true,
  findings: true,
  policy: true,
  findingCount: true,
  evidenceStatus: true,
  createdAt: true,
  // Not `duration_ms`: the DLP engine is a coarse engine (no durations, D20).
} satisfies Prisma.DlpScanResultSelect;

export type DlpResultRow = Prisma.DlpScanResultGetPayload<{ select: typeof dlpResultSelect }> &
  DlpResultRowInput;

export interface IncidentPage {
  take: number;
  before?: { receivedAt: Date; id: bigint };
  action?: 'alert' | 'require_approval' | 'quarantine' | 'block';
  direction?: 'inbound' | 'outbound' | 'internal';
  from?: Date;
  to?: Date;
}

export interface EvidenceMessage {
  id: bigint;
  publicId: string;
  receivedAt: Date;
}

const evidenceSelect = {
  id: true,
  receivedAt: true,
  organizationId: true,
  messageId: true,
  scanId: true,
  objectKey: true,
  objectSha256: true,
  objectSizeBytes: true,
  wrappedKey: true,
  keyId: true,
  algorithm: true,
  matchCount: true,
  expiresAt: true,
  purgedAt: true,
  purgeReason: true,
} satisfies Prisma.DlpEvidenceSelect;
export type EvidenceRow = Prisma.DlpEvidenceGetPayload<{ select: typeof evidenceSelect }>;

/**
 * Tenant-scoped reads of the DLP results (incidents, D21: replica) and the evidence rows (D16:
 * writer, echo-checked). Every query matches the scope's organization; the partitioned tables
 * are matched with their `received_at` where the key allows it.
 */
@Injectable()
export class DlpResultsRepository {
  constructor(
    private readonly reader: PrismaReadService,
    private readonly prisma: PrismaService,
  ) {}

  private get db() {
    return this.reader.client;
  }

  // --------------------------------------------------------------------------------- incidents

  /** Results with an action other than `allow`, newest first (received time, id). */
  listIncidents(scope: TenantScope, p: IncidentPage): Promise<DlpResultRow[]> {
    const received: Prisma.DateTimeFilter = {
      ...(p.from !== undefined && { gte: p.from }),
      ...(p.to !== undefined && { lt: p.to }),
    };
    return this.db.dlpScanResult.findMany({
      where: tenantWhere(scope, {
        action: p.action ?? { not: 'allow' as const },
        ...(p.direction !== undefined && { direction: p.direction }),
        ...(Object.keys(received).length > 0 && { receivedAt: received }),
        ...(p.before !== undefined && {
          OR: [
            { receivedAt: { lt: p.before.receivedAt } },
            { receivedAt: p.before.receivedAt, id: { lt: p.before.id } },
          ],
        }),
      }),
      select: dlpResultSelect,
      orderBy: [{ receivedAt: 'desc' }, { id: 'desc' }],
      take: p.take,
    });
  }

  /** Public ids of the organization's messages (`message_identities`). */
  async messagePublicIds(scope: TenantScope, ids: bigint[]): Promise<Map<string, string>> {
    if (ids.length === 0) return new Map();
    const rows = await this.db.messageIdentity.findMany({
      where: tenantWhere(scope, { id: { in: [...new Set(ids)] } }),
      select: { id: true, publicId: true },
    });
    return new Map(rows.map((r) => [r.id.toString(), r.publicId]));
  }

  publicIds(scope: TenantScope, refs: DlpRefs): Promise<DlpIdMaps> {
    return resolveDlpIds(this.db, scope, refs);
  }

  // ---------------------------------------------------------------------------------- evidence

  /** The organization's message by public id on the writer (echo-checked). */
  async findMessage(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<EvidenceMessage | null> {
    const row = await tx.messageIdentity.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: { id: true, publicId: true, receivedAt: true, organizationId: true },
    });
    if (row === null) return null;
    if (row.organizationId !== scope.organizationId || row.publicId !== publicId) {
      throw new InconsistentDlpReadError('message');
    }
    return { id: row.id, publicId: row.publicId, receivedAt: row.receivedAt };
  }

  /** True when the scan is a round of the message (writer; echo-checked). */
  async scanExists(
    tx: Client,
    scope: TenantScope,
    message: EvidenceMessage,
    scanId: bigint,
  ): Promise<boolean> {
    const row = await tx.emailScan.findFirst({
      where: tenantWhere(scope, {
        id: scanId,
        messageId: message.id,
        receivedAt: message.receivedAt,
      }),
      select: { id: true, messageId: true, receivedAt: true, organizationId: true },
    });
    if (row === null) return false;
    if (
      row.id !== scanId ||
      row.messageId !== message.id ||
      row.receivedAt.getTime() !== message.receivedAt.getTime() ||
      row.organizationId !== scope.organizationId
    ) {
      throw new InconsistentDlpReadError('scan');
    }
    return true;
  }

  /** The round's evidence row on the writer (`FOR UPDATE` when asked; echo-checked). */
  async evidenceOf(
    tx: Client,
    scope: TenantScope,
    message: EvidenceMessage,
    scanId: bigint,
    lock: boolean,
  ): Promise<EvidenceRow | null> {
    if (lock) {
      await tx.$queryRaw`SELECT id FROM dlp_evidence
        WHERE scan_id = ${scanId} AND received_at = ${message.receivedAt}
          AND organization_id = ${scope.organizationId} AND message_id = ${message.id} FOR UPDATE`;
    }
    const row = await tx.dlpEvidence.findFirst({
      where: tenantWhere(scope, { scanId, receivedAt: message.receivedAt, messageId: message.id }),
      select: evidenceSelect,
    });
    if (row === null) return null;
    if (
      row.organizationId !== scope.organizationId ||
      row.scanId !== scanId ||
      row.messageId !== message.id ||
      row.receivedAt.getTime() !== message.receivedAt.getTime()
    ) {
      throw new InconsistentDlpReadError('evidence');
    }
    return row;
  }

  /**
   * Crypto-shreds evidence rows (D16): `wrapped_key` NULL, `purged_at`, `purge_reason`. Rows
   * already shredded keep their first purge time and reason.
   */
  async shred(
    tx: Client,
    scope: TenantScope,
    rows: ReadonlyArray<Pick<EvidenceRow, 'id' | 'receivedAt'>>,
    reason: 'tenant_request' | 'organization_deleted',
    now: Date,
  ): Promise<number> {
    let count = 0;
    for (const row of rows) {
      const result = await tx.dlpEvidence.updateMany({
        where: tenantWhere(scope, { id: row.id, receivedAt: row.receivedAt, purgedAt: null }),
        data: { wrappedKey: null, purgedAt: now, purgeReason: reason },
      });
      count += result.count;
    }
    return count;
  }

  /**
   * The next batch of the organization's evidence rows after `afterId` (ascending) that still
   * need work for a tenant purge (`FOR UPDATE`, echo-checked): not yet shredded, or shredded with
   * the object not deleted yet. The cursor guarantees progress when a delete keeps failing.
   */
  async purgeBatch(
    tx: Client,
    scope: TenantScope,
    afterId: bigint,
    take: number,
  ): Promise<EvidenceRow[]> {
    const ids = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM dlp_evidence
      WHERE organization_id = ${scope.organizationId} AND id > ${afterId}
        AND (purged_at IS NULL OR object_key IS NOT NULL)
      ORDER BY id LIMIT ${take} FOR UPDATE`;
    if (ids.length === 0) return [];
    const rows = await tx.dlpEvidence.findMany({
      where: tenantWhere(scope, { id: { in: ids.map((r) => BigInt(r.id)) } }),
      select: evidenceSelect,
      orderBy: { id: 'asc' },
    });
    for (const row of rows) {
      if (row.organizationId !== scope.organizationId || row.id <= afterId) {
        throw new InconsistentDlpReadError('evidence_batch');
      }
    }
    return rows;
  }

  /** Clears `object_key` after the object was deleted (autocommit on the writer). */
  async clearObjectKey(
    scope: TenantScope,
    row: Pick<EvidenceRow, 'id' | 'receivedAt' | 'objectKey'>,
  ): Promise<void> {
    await this.prisma.dlpEvidence.updateMany({
      where: tenantWhere(scope, {
        id: row.id,
        receivedAt: row.receivedAt,
        objectKey: row.objectKey,
      }),
      data: { objectKey: null },
    });
  }
}
