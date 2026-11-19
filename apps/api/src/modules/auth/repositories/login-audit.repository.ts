import { Injectable, Logger } from '@nestjs/common';
import { PrismaService, uuidv7 } from '@email-gateway/common';
import type { LoginOutcome, Prisma } from '@email-gateway/database';
import { authLoginRecordedV1, EventTypes } from '@email-gateway/event-contracts';
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
  /**
   * Step 8.4 D5: `portal` when the request came through the trusted forwarder, else `api`
   * (absent = `api`). Carried by `auth.login.recorded.v1` only; never stored in the row.
   */
  channel?: 'portal' | 'api';
}

/** Outbox aggregate of `auth.login.recorded.v1` (`aggregate_id` = `login_audit_logs.id`). */
export const LOGIN_AGGREGATE_TYPE = 'login';
/** A missing platform organization is looked up again after this long. */
const PLATFORM_NEGATIVE_CACHE_MS = 60_000;

/**
 * `login_audit_logs` (D6): one row per login attempt, on the writer.
 *
 * Step 8.4 D5 (ADR-0070): the row and its `auth.login.recorded.v1` outbox row are written in
 * **one** writer transaction (both or neither). The event carries ids and enums only (never the
 * attempted e-mail, the IP or the user agent: the ato-worker reads the row back). Its envelope
 * organization is the user's; for an unknown account (no `userId`) the platform organization
 * (`organizations.kind = 'platform'`, resolved once and cached). Without a platform organization
 * the event is skipped (warned) and the row is still written. A failure of the whole write never
 * changes the login answer (`LoginAuditService` logs it).
 */
@Injectable()
export class LoginAuditRepository {
  private readonly logger = new Logger(LoginAuditRepository.name);
  private platformId: bigint | undefined;
  private platformMissingUntil = 0;

  constructor(private readonly prisma: PrismaService) {}

  async insert(entry: LoginAuditEntry): Promise<void> {
    const { channel = 'api', ...row } = entry;
    const envelopeOrganizationId =
      row.userId !== null && row.organizationId !== null
        ? row.organizationId
        : await this.platformOrganizationId();
    await this.prisma.$transaction(async (tx) => {
      const created = await tx.loginAuditLog.create({
        data: {
          ...row,
          emailAttempted: row.emailAttempted.toLowerCase().slice(0, 320),
          ipAddress: row.ipAddress?.slice(0, 45) ?? null,
          userAgent: row.userAgent?.slice(0, 512) ?? null,
        },
        select: { id: true, createdAt: true },
      });
      if (envelopeOrganizationId === null) {
        this.logger.warn({
          message:
            'No platform organization: auth.login.recorded.v1 skipped for an unknown account',
          outcome: row.outcome,
        });
        return;
      }
      await writeLoginRecorded(tx, created, envelopeOrganizationId, row, channel);
    });
  }

  async purgeOlderThan(before: Date, limit: number): Promise<number> {
    return this.prisma.$executeRaw`
      DELETE FROM login_audit_logs WHERE created_at < ${before} ORDER BY id LIMIT ${limit}`;
  }

  /** The platform organization (`kind = 'platform'`), cached; null when it does not exist. */
  private async platformOrganizationId(): Promise<bigint | null> {
    if (this.platformId !== undefined) return this.platformId;
    const now = Date.now();
    if (now < this.platformMissingUntil) return null;
    const org = await this.prisma.organization.findFirst({
      where: { kind: 'platform' },
      select: { id: true },
      orderBy: { id: 'asc' },
    });
    if (!org) {
      this.platformMissingUntil = now + PLATFORM_NEGATIVE_CACHE_MS;
      return null;
    }
    this.platformId = org.id;
    return org.id;
  }
}

/** The `auth.login.recorded.v1` outbox row of one `login_audit_logs` row (same transaction). */
async function writeLoginRecorded(
  tx: Prisma.TransactionClient,
  created: { id: bigint; createdAt: Date },
  organizationId: bigint,
  row: Omit<LoginAuditEntry, 'channel'>,
  channel: 'portal' | 'api',
): Promise<void> {
  const known = row.userId !== null && row.organizationId !== null;
  const payload = authLoginRecordedV1.parse({
    loginAuditId: created.id.toString(),
    occurredAt: created.createdAt.toISOString(),
    outcome: row.outcome,
    failureReason:
      row.outcome === 'success' || row.outcome === 'mfa_required' ? null : row.failureReason,
    accountKnown: known,
    userId: known ? row.userId!.toString() : null,
    channel,
  });
  const eventId = uuidv7();
  await tx.messageOutbox.create({
    data: {
      eventId,
      organizationId,
      eventType: EventTypes.AuthLoginRecorded,
      aggregateType: LOGIN_AGGREGATE_TYPE,
      aggregateId: created.id.toString(),
      correlationId: `login:${created.id}`,
      payload,
    },
    select: { id: true },
  });
}
