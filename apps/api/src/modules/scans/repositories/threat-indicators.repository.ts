import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma, Severity, ThreatCategory } from '@email-gateway/database';
import type { ThreatIndicatorType } from '../dto/threat-indicators.schemas';

type Client = Prisma.TransactionClient;

/** The source of indicators added through this API (U16). */
export const ANALYST_SOURCE = 'analyst';

const indicatorSelect = {
  id: true,
  organizationId: true,
  indicatorType: true,
  value: true,
  valueSha256: true,
  severity: true,
  category: true,
  source: true,
  reason: true,
  expiresAt: true,
  firstSeenAt: true,
  lastSeenAt: true,
  createdAt: true,
  updatedAt: true,
  addedBy: { select: { publicId: true } },
} satisfies Prisma.ThreatIndicatorSelect;

export type ThreatIndicatorRow = Prisma.ThreatIndicatorGetPayload<{
  select: typeof indicatorSelect;
}>;

export interface NewThreatIndicator {
  type: ThreatIndicatorType;
  value: string;
  valueSha256: string;
  severity: Severity;
  category: ThreatCategory;
  reason: string;
  expiresAt: Date | null;
  addedByUserId: bigint;
  now: Date;
}

/**
 * A read on the writer returned a row other than the one asked for (step 4.2 §6: Prisma 6 may
 * hand back the reply of an abandoned statement). Never acted upon; the request fails and may be
 * retried.
 */
export class InconsistentIndicatorReadError extends Error {
  constructor(read: string) {
    super(`inconsistent read of threat_indicators (${read})`);
    this.name = 'InconsistentIndicatorReadError';
  }
}

/** Indicator types the API manages; `email` / `file_sha256` rows are never listed or touched. */
const MANAGED_TYPES: ThreatIndicatorType[] = ['url', 'domain', 'ip'];

/**
 * The platform threat-indicator catalog: rows of `threat_indicators` with `organization_id` NULL
 * (`org_scope = 0`, step 4.3 U16), consulted uncached by the URL engine's `local_feed` provider
 * and the click-service. Platform-wide, not tenant-scoped: only platform users with
 * `platform:threat_intel_manage` reach these queries. Lists read the replica (writer fallback
 * above the lag threshold); every change and its read-before-write runs on the writer transaction
 * the service passes, and every writer read is echo-checked (§6).
 */
@Injectable()
export class ThreatIndicatorsRepository {
  constructor(private readonly reader: PrismaReadService) {}

  /** Newest first (id descending), below `beforeId`, optionally one type, source or value hash. */
  list(page: {
    take: number;
    beforeId?: bigint;
    type?: ThreatIndicatorType;
    source?: string;
    valueSha256?: string;
  }): Promise<ThreatIndicatorRow[]> {
    return this.reader.client.threatIndicator.findMany({
      where: {
        organizationId: null,
        indicatorType: page.type ?? { in: MANAGED_TYPES },
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
        ...(page.source !== undefined && { source: page.source }),
        ...(page.valueSha256 !== undefined && { valueSha256: page.valueSha256 }),
      },
      select: indicatorSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  /**
   * The analyst row of a value on the writer (the unique key `(org_scope, source, type,
   * value_sha256)`), locked for the rest of the transaction; echo-checked.
   */
  async findAnalystForUpdate(
    tx: Client,
    type: ThreatIndicatorType,
    valueSha256: string,
  ): Promise<ThreatIndicatorRow | null> {
    await tx.$queryRaw`SELECT id FROM threat_indicators
      WHERE org_scope = 0 AND source = ${ANALYST_SOURCE} AND indicator_type = ${type}
        AND value_sha256 = ${valueSha256} FOR UPDATE`;
    const row = await tx.threatIndicator.findFirst({
      where: {
        organizationId: null,
        source: ANALYST_SOURCE,
        indicatorType: type,
        valueSha256,
      },
      select: indicatorSelect,
    });
    if (
      row !== null &&
      (row.organizationId !== null ||
        row.source !== ANALYST_SOURCE ||
        row.indicatorType !== type ||
        row.valueSha256 !== valueSha256)
    ) {
      throw new InconsistentIndicatorReadError('analyst_value');
    }
    return row;
  }

  /** A platform indicator of a managed type by id on the writer, locked; echo-checked. */
  async findPlatformForUpdate(tx: Client, id: bigint): Promise<ThreatIndicatorRow | null> {
    await tx.$queryRaw`SELECT id FROM threat_indicators WHERE id = ${id} FOR UPDATE`;
    const row = await tx.threatIndicator.findUnique({ where: { id }, select: indicatorSelect });
    if (row !== null && row.id !== id) throw new InconsistentIndicatorReadError('id');
    if (row === null || row.organizationId !== null) return null;
    if (!(MANAGED_TYPES as string[]).includes(row.indicatorType)) return null;
    return row;
  }

  /** An analyst indicator: platform scope, `source = analyst`, confidence 100, seen now. */
  create(tx: Client, input: NewThreatIndicator): Promise<ThreatIndicatorRow> {
    return tx.threatIndicator.create({
      data: {
        organizationId: null,
        indicatorType: input.type,
        value: input.value,
        valueSha256: input.valueSha256,
        source: ANALYST_SOURCE,
        severity: input.severity,
        category: input.category,
        confidence: 100,
        reason: input.reason,
        expiresAt: input.expiresAt,
        addedByUserId: input.addedByUserId,
        firstSeenAt: input.now,
        lastSeenAt: input.now,
      },
      select: indicatorSelect,
    });
  }

  /** Hard delete (the audit row keeps the before-image). */
  async remove(tx: Client, id: bigint): Promise<void> {
    await tx.threatIndicator.delete({ where: { id }, select: { id: true } });
  }
}
