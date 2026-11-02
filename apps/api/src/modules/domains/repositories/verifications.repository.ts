import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import {
  type DnsCheckOutcome,
  type DomainVerificationStatus,
  Prisma,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';

type Client = Prisma.TransactionClient;

const verificationSelect = {
  id: true,
  domainId: true,
  method: true,
  token: true,
  status: true,
  attempts: true,
  nextCheckAt: true,
  lastCheckedAt: true,
  lastError: true,
  lastOutcome: true,
  verifiedAt: true,
  expiresAt: true,
  createdAt: true,
} satisfies Prisma.DomainVerificationSelect;

export type VerificationRow = Prisma.DomainVerificationGetPayload<{
  select: typeof verificationSelect;
}>;

export interface VerificationWrite {
  attempts?: number;
  lastCheckedAt?: Date;
  lastOutcome?: DnsCheckOutcome | null;
  lastError?: string | null;
  evidence?: Record<string, unknown> | null;
  nextCheckAt?: Date | null;
  status?: DomainVerificationStatus;
  verifiedAt?: Date;
}

/**
 * `domain_verifications` of the scope's domains (D4). The newest row of a domain is its current
 * verification; a restart adds a row with the same token.
 */
@Injectable()
export class VerificationsRepository {
  constructor(private readonly prisma: PrismaService) {}

  findCurrent(
    scope: TenantScope,
    domainId: bigint,
    client: Client = this.prisma,
  ): Promise<VerificationRow | null> {
    return client.domainVerification.findFirst({
      where: tenantWhere(scope, { domainId }),
      select: verificationSelect,
      orderBy: { id: 'desc' },
    });
  }

  create(
    tx: Client,
    scope: TenantScope,
    data: {
      domainId: bigint;
      token: string;
      status: DomainVerificationStatus;
      expiresAt: Date;
      verifiedAt?: Date | null;
      nextCheckAt?: Date | null;
    },
  ): Promise<VerificationRow> {
    return tx.domainVerification.create({
      data: {
        organizationId: scope.organizationId,
        domainId: data.domainId,
        method: 'dns_txt',
        token: data.token,
        status: data.status,
        expiresAt: data.expiresAt,
        verifiedAt: data.verifiedAt ?? null,
        nextCheckAt: data.nextCheckAt ?? null,
      },
      select: verificationSelect,
    });
  }

  async update(tx: Client, scope: TenantScope, id: bigint, data: VerificationWrite): Promise<void> {
    const { evidence, ...rest } = data;
    await tx.domainVerification.updateMany({
      where: tenantWhere(scope, { id }),
      data: {
        ...rest,
        ...(evidence !== undefined && {
          evidence: evidence === null ? Prisma.DbNull : (evidence as Prisma.InputJsonValue),
        }),
      },
    });
  }

  /** Marks the domain's pending verifications `expired` (domain deletion, D3). */
  async expirePending(tx: Client, scope: TenantScope, domainId: bigint): Promise<number> {
    const { count } = await tx.domainVerification.updateMany({
      where: tenantWhere(scope, { domainId, status: 'pending' as const }),
      data: { status: 'expired', nextCheckAt: null },
    });
    return count;
  }
}
