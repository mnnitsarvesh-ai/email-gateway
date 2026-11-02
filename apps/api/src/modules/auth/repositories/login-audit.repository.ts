import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { LoginOutcome } from '@email-gateway/database';
import type { LoginFailureReason } from '../auth.constants';

export interface LoginAuditEntry {
  organizationId: bigint | null;
  userId: bigint | null;
  /** Lower-cased; clipped to the column size. Never a password, token or code. */
  emailAttempted: string;
  outcome: LoginOutcome;
  failureReason: LoginFailureReason | null;
  ipAddress: string | null;
  userAgent: string | null;
}

/** `login_audit_logs` (D6): one row per login attempt, on the writer. */
@Injectable()
export class LoginAuditRepository {
  constructor(private readonly prisma: PrismaService) {}

  async insert(entry: LoginAuditEntry): Promise<void> {
    await this.prisma.loginAuditLog.create({
      data: {
        ...entry,
        emailAttempted: entry.emailAttempted.toLowerCase().slice(0, 320),
        ipAddress: entry.ipAddress?.slice(0, 45) ?? null,
        userAgent: entry.userAgent?.slice(0, 512) ?? null,
      },
    });
  }

  async purgeOlderThan(before: Date, limit: number): Promise<number> {
    return this.prisma.$executeRaw`
      DELETE FROM login_audit_logs WHERE created_at < ${before} ORDER BY id LIMIT ${limit}`;
  }
}
