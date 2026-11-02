import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { LoginOutcome, Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../auth-contracts/tenant-scope';

export interface LoginEventRecord {
  id: bigint;
  userId: bigint | null;
  emailAttempted: string;
  outcome: LoginOutcome;
  failureReason: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: Date;
}

export interface LoginEventFilter {
  from: Date;
  to: Date;
  outcome?: LoginOutcome;
  userId?: bigint;
}

/**
 * `login_audit_logs` of the scope organization (reader). Rows without an organization (unknown
 * accounts without a resolvable slug) belong to no tenant and are never listed.
 */
@Injectable()
export class LoginEventsRepository {
  constructor(private readonly reader: PrismaReadService) {}

  async list(
    scope: TenantScope,
    filter: LoginEventFilter,
    window: { take: number; beforeId?: bigint },
  ): Promise<LoginEventRecord[]> {
    const where: Prisma.LoginAuditLogWhereInput = {
      createdAt: { gte: filter.from, lt: filter.to },
      ...(filter.outcome && { outcome: filter.outcome }),
      ...(filter.userId !== undefined && { userId: filter.userId }),
      ...(window.beforeId !== undefined && { id: { lt: window.beforeId } }),
    };
    return this.reader.client.loginAuditLog.findMany({
      where: tenantWhere(scope, where),
      select: {
        id: true,
        userId: true,
        emailAttempted: true,
        outcome: true,
        failureReason: true,
        ipAddress: true,
        userAgent: true,
        createdAt: true,
      },
      orderBy: { id: 'desc' },
      take: window.take,
    });
  }
}
