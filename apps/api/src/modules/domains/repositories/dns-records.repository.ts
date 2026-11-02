import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import {
  type DnsCheckOutcome,
  type DnsRecordPurpose,
  type DnsRecordStatus,
  type DnsRecordType,
  Prisma,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';

type Client = Prisma.TransactionClient;

const recordSelect = {
  id: true,
  domainId: true,
  recordKey: true,
  purpose: true,
  recordType: true,
  host: true,
  dkimKeyId: true,
  expectedValue: true,
  observedValue: true,
  status: true,
  statusChangedAt: true,
  lastOutcome: true,
  lastError: true,
  evidence: true,
  lastCheckedAt: true,
  createdAt: true,
} satisfies Prisma.DomainDnsRecordSelect;

export type DnsRecordRow = Prisma.DomainDnsRecordGetPayload<{ select: typeof recordSelect }>;

/** One expected record (D6) as written by the configuration pass. */
export interface DnsRecordDefinition {
  recordKey: string;
  purpose: DnsRecordPurpose;
  recordType: DnsRecordType;
  host: string;
  expectedValue: string;
  dkimKeyId: bigint | null;
}

/** The result of a check for one record (D10). */
export interface DnsRecordResultWrite {
  status?: DnsRecordStatus;
  statusChangedAt?: Date;
  observedValue?: string | null;
  expectedValue?: string;
  lastOutcome: DnsCheckOutcome;
  lastCheckedAt: Date;
  lastError: string | null;
  evidence: Record<string, unknown>;
}

/**
 * `domain_dns_records` of the scope's domains: one row per published record, keyed by
 * `record_key` (D6). Callers hold the domain row lock when writing.
 */
@Injectable()
export class DnsRecordsRepository {
  constructor(private readonly prisma: PrismaService) {}

  listForDomain(
    scope: TenantScope,
    domainId: bigint,
    client: Client = this.prisma,
  ): Promise<DnsRecordRow[]> {
    return client.domainDnsRecord.findMany({
      where: tenantWhere(scope, { domainId }),
      select: recordSelect,
      orderBy: { id: 'asc' },
    });
  }

  /**
   * Inserts the record, or updates its definition (type, host, expected value, key) when it
   * exists. Never touches the check results: the status only changes through a check.
   */
  async upsert(
    tx: Client,
    scope: TenantScope,
    domainId: bigint,
    record: DnsRecordDefinition,
  ): Promise<void> {
    const existing = await tx.domainDnsRecord.findFirst({
      where: tenantWhere(scope, { domainId, recordKey: record.recordKey }),
      select: {
        id: true,
        purpose: true,
        recordType: true,
        host: true,
        expectedValue: true,
        dkimKeyId: true,
      },
    });
    if (!existing) {
      await tx.domainDnsRecord.create({
        data: { organizationId: scope.organizationId, domainId, status: 'pending', ...record },
      });
      return;
    }
    const unchanged =
      existing.purpose === record.purpose &&
      existing.recordType === record.recordType &&
      existing.host === record.host &&
      existing.expectedValue === record.expectedValue &&
      existing.dkimKeyId === record.dkimKeyId;
    if (unchanged) return;
    await tx.domainDnsRecord.updateMany({
      where: tenantWhere(scope, { id: existing.id }),
      data: {
        purpose: record.purpose,
        recordType: record.recordType,
        host: record.host,
        expectedValue: record.expectedValue,
        dkimKeyId: record.dkimKeyId,
      },
    });
  }

  async writeResult(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    data: DnsRecordResultWrite,
  ): Promise<void> {
    await tx.domainDnsRecord.updateMany({
      where: tenantWhere(scope, { id }),
      data: { ...data, evidence: data.evidence as Prisma.InputJsonValue },
    });
  }

  async deleteByKeys(
    tx: Client,
    scope: TenantScope,
    domainId: bigint,
    recordKeys: readonly string[],
  ): Promise<number> {
    if (recordKeys.length === 0) return 0;
    const { count } = await tx.domainDnsRecord.deleteMany({
      where: tenantWhere(scope, { domainId, recordKey: { in: [...recordKeys] } }),
    });
    return count;
  }
}
