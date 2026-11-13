import type { Prisma } from '@email-gateway/database';
import {
  QUARANTINE_PERMISSIONS,
  type QuarantineSettings,
  resolveQuarantineSettings,
} from '@email-gateway/quarantine';
import {
  findPermissionHolders,
  InconsistentNotificationReadError,
  type NoticeUser,
} from './notification-reads';

export type { NoticeUser } from './notification-reads';

type Tx = Prisma.TransactionClient;

const OPEN_STATES = ['held', 'pending_approval'] as const;

export interface DigestEntryRow {
  publicId: string;
  messageId: bigint;
  messageReceivedAt: Date;
  envelopeFrom: string;
  reason: string;
  expiresAt: Date;
  subject: string | null;
}

/**
 * The writer reads of the quarantine notices (step 5.3 Q20), inside the consumer's idempotency
 * transaction, each matched on the event's organization and echo-checked (§6).
 */
export class QuarantineNotificationReads {
  /** Effective quarantine settings of the organization (invalid stored settings → defaults). */
  async settings(tx: Tx, organizationId: bigint): Promise<QuarantineSettings> {
    const stored = await tx.quarantineSettings.findFirst({
      where: { organizationId },
      select: { organizationId: true, settings: true },
    });
    if (stored !== null && stored.organizationId !== organizationId) {
      throw new InconsistentNotificationReadError('quarantine_settings');
    }
    const org = await tx.organizationSetting.findFirst({
      where: { organizationId },
      select: {
        organizationId: true,
        quarantineRetentionDays: true,
        digestEnabled: true,
        digestSchedule: true,
        timezone: true,
      },
    });
    if (org !== null && org.organizationId !== organizationId) {
      throw new InconsistentNotificationReadError('organization_settings');
    }
    return resolveQuarantineSettings(stored?.settings ?? null, undefined, org).settings;
  }

  /** An active, e-mail-verified, not deleted user of the organization by public id. */
  async activeUser(tx: Tx, organizationId: bigint, publicId: string): Promise<NoticeUser | null> {
    const row = await tx.user.findFirst({
      where: { organizationId, publicId },
      select: {
        id: true,
        organizationId: true,
        publicId: true,
        email: true,
        status: true,
        deletedAt: true,
        emailVerifiedAt: true,
      },
    });
    if (row === null) return null;
    if (row.organizationId !== organizationId || row.publicId !== publicId) {
      throw new InconsistentNotificationReadError('user');
    }
    if (row.status !== 'active' || row.deletedAt !== null || row.emailVerifiedAt === null) {
      return null;
    }
    return { id: row.id, email: row.email.toLowerCase() };
  }

  /** As `activeUser`, by internal id. */
  async activeUserById(tx: Tx, organizationId: bigint, id: bigint): Promise<NoticeUser | null> {
    const row = await tx.user.findFirst({
      where: { organizationId, id },
      select: {
        id: true,
        organizationId: true,
        email: true,
        status: true,
        deletedAt: true,
        emailVerifiedAt: true,
      },
    });
    if (row === null) return null;
    if (row.organizationId !== organizationId || row.id !== id) {
      throw new InconsistentNotificationReadError('user');
    }
    if (row.status !== 'active' || row.deletedAt !== null || row.emailVerifiedAt === null) {
      return null;
    }
    return { id: row.id, email: row.email.toLowerCase() };
  }

  /** The digest row of a `user_digest` event (public id, the user it was written for). */
  async digest(
    tx: Tx,
    organizationId: bigint,
    publicId: string,
  ): Promise<{ userId: bigint } | null> {
    const row = await tx.quarantineDigest.findFirst({
      where: { organizationId, publicId },
      select: { organizationId: true, publicId: true, userId: true },
    });
    if (row === null) return null;
    if (row.organizationId !== organizationId || row.publicId !== publicId) {
      throw new InconsistentNotificationReadError('quarantine_digest');
    }
    return { userId: row.userId };
  }

  async digestOptOut(tx: Tx, organizationId: bigint, userId: bigint): Promise<boolean> {
    const row = await tx.quarantineUserPreference.findFirst({
      where: { organizationId, userId },
      select: { organizationId: true, userId: true, digestOptOut: true },
    });
    if (row !== null && (row.organizationId !== organizationId || row.userId !== userId)) {
      throw new InconsistentNotificationReadError('quarantine_preference');
    }
    return row?.digestOptOut ?? false;
  }

  /**
   * The user's `held`/`pending_approval` entries of the window (by quarantine time, newest
   * first, ≤ `limit` + the total), with the message subject (read at send time, Q20).
   */
  async digestEntries(
    tx: Tx,
    organizationId: bigint,
    address: string,
    window: { from: Date; to: Date },
    limit: number,
  ): Promise<{ entries: DigestEntryRow[]; total: number }> {
    const where = {
      organizationId,
      recipientAddress: address,
      status: { in: [...OPEN_STATES] },
      quarantinedAt: { gt: window.from, lte: window.to },
    };
    const total = await tx.quarantineMessage.count({ where });
    const rows = await tx.quarantineMessage.findMany({
      where,
      orderBy: [{ quarantinedAt: 'desc' }, { id: 'desc' }],
      take: limit,
      select: {
        publicId: true,
        organizationId: true,
        recipientAddress: true,
        status: true,
        messageId: true,
        messageReceivedAt: true,
        envelopeFrom: true,
        reason: true,
        expiresAt: true,
      },
    });
    const entries: DigestEntryRow[] = [];
    for (const r of rows) {
      if (
        r.organizationId !== organizationId ||
        r.recipientAddress !== address ||
        !(OPEN_STATES as readonly string[]).includes(r.status)
      ) {
        throw new InconsistentNotificationReadError('quarantine_entry');
      }
      const message = await tx.emailMessage.findFirst({
        where: { id: r.messageId, receivedAt: r.messageReceivedAt, organizationId },
        select: { id: true, organizationId: true, subject: true },
      });
      if (
        message !== null &&
        (message.id !== r.messageId || message.organizationId !== organizationId)
      ) {
        throw new InconsistentNotificationReadError('email_message');
      }
      entries.push({
        publicId: r.publicId,
        messageId: r.messageId,
        messageReceivedAt: r.messageReceivedAt,
        envelopeFrom: r.envelopeFrom,
        reason: r.reason,
        expiresAt: r.expiresAt,
        subject: message?.subject ?? null,
      });
    }
    return { entries, total };
  }

  /**
   * One page of the active, verified users of the organization holding `quarantine:approve`
   * through a role of the organization or a system role, excluding `excluded`, sorted by id,
   * after `afterId`, ≤ `take` (opt-outs are removed by `PreferenceFilter`, step 6.2 N4).
   */
  approvers(
    tx: Tx,
    organizationId: bigint,
    excluded: readonly bigint[],
    take: number,
    afterId: bigint | null = null,
  ): Promise<NoticeUser[]> {
    return findPermissionHolders(tx, organizationId, QUARANTINE_PERMISSIONS.approve, {
      take,
      afterId,
      excluded,
    });
  }

  /** Approval requests of the organization by public id, with their entry's reason. */
  async approvalRequests(
    tx: Tx,
    organizationId: bigint,
    publicIds: readonly string[],
  ): Promise<
    Array<{
      publicId: string;
      kind: string;
      status: string;
      approvalReasons: string[];
      requestedByUserId: bigint | null;
      reason: string;
    }>
  > {
    const rows = await tx.quarantineApprovalRequest.findMany({
      where: { organizationId, publicId: { in: [...publicIds] } },
      select: {
        publicId: true,
        organizationId: true,
        kind: true,
        status: true,
        approvalReasons: true,
        requestedByUserId: true,
        quarantineMessage: { select: { organizationId: true, reason: true } },
      },
      orderBy: { id: 'asc' },
    });
    return rows.map((r) => {
      if (
        r.organizationId !== organizationId ||
        r.quarantineMessage.organizationId !== organizationId ||
        !publicIds.includes(r.publicId)
      ) {
        throw new InconsistentNotificationReadError('approval_request');
      }
      return {
        publicId: r.publicId,
        kind: r.kind,
        status: r.status,
        approvalReasons: Array.isArray(r.approvalReasons)
          ? r.approvalReasons.filter((x): x is string => typeof x === 'string')
          : [],
        requestedByUserId: r.requestedByUserId,
        reason: r.quarantineMessage.reason,
      };
    });
  }

  /** The release logs of a release (status counts and the requester). */
  async release(
    tx: Tx,
    organizationId: bigint,
    releasePublicId: string,
  ): Promise<{
    outcomes: Record<string, number>;
    requestedByType: string | null;
    requestedById: string | null;
  }> {
    const rows = await tx.quarantineReleaseLog.findMany({
      where: { organizationId, releasePublicId },
      select: {
        organizationId: true,
        releasePublicId: true,
        status: true,
        requestedByType: true,
        requestedById: true,
      },
    });
    const outcomes: Record<string, number> = {};
    for (const r of rows) {
      if (r.organizationId !== organizationId || r.releasePublicId !== releasePublicId) {
        throw new InconsistentNotificationReadError('release_log');
      }
      outcomes[r.status] = (outcomes[r.status] ?? 0) + 1;
    }
    return {
      outcomes,
      requestedByType: rows[0]?.requestedByType ?? null,
      requestedById: rows[0]?.requestedById ?? null,
    };
  }

  /** Counts of an admin alert: new hard-block entries of the window, approvals older than 1 h. */
  async alertCounts(
    tx: Tx,
    organizationId: bigint,
    window: { from: Date; to: Date } | null,
    now: Date,
  ): Promise<{ hardBlocks: number; pendingApprovals: number }> {
    const hardBlocks = await tx.quarantineMessage.count({
      where: {
        organizationId,
        hasHardBlock: true,
        status: { in: [...OPEN_STATES] },
        ...(window === null ? {} : { quarantinedAt: { gt: window.from, lte: window.to } }),
      },
    });
    const pendingApprovals = await tx.quarantineApprovalRequest.count({
      where: {
        organizationId,
        status: 'pending',
        createdAt: { lte: new Date(now.getTime() - 3_600_000) },
      },
    });
    return { hardBlocks, pendingApprovals };
  }

  /** An entry of the organization (sender notice). */
  async entry(
    tx: Tx,
    organizationId: bigint,
    publicId: string,
  ): Promise<{
    messageId: bigint;
    messageReceivedAt: Date;
    direction: 'inbound' | 'outbound' | 'internal';
    status: string;
  } | null> {
    const row = await tx.quarantineMessage.findFirst({
      where: { organizationId, publicId },
      select: {
        organizationId: true,
        publicId: true,
        messageId: true,
        messageReceivedAt: true,
        direction: true,
        status: true,
      },
    });
    if (row === null) return null;
    if (row.organizationId !== organizationId || row.publicId !== publicId) {
      throw new InconsistentNotificationReadError('quarantine_entry');
    }
    return row;
  }
}
