import type { Prisma } from '@email-gateway/database';

type Tx = Prisma.TransactionClient;

/** A writer read returned a row other than the one asked for (4.2 §6): retryable. */
export class InconsistentNotificationReadError extends Error {
  override readonly name = 'InconsistentNotificationReadError';
  constructor(readonly read: string) {
    super(`inconsistent read (${read})`);
  }
}

/** The permission whose holders receive policy alerts (P25). */
export const ALERT_PERMISSION = 'policy:publish';

/** A recipient user: internal id (opt-out lookup, paging) and lower-cased e-mail. */
export interface NoticeUser {
  id: bigint;
  email: string;
}

/** A page of permission holders: after `afterId` (exclusive), at most `take`, minus `excluded`. */
export interface HolderPage {
  take: number;
  afterId?: bigint | null;
  excluded?: readonly bigint[];
}

/**
 * Active, non-deleted, e-mail-verified users of the organization holding `permission` through a
 * role of that organization or a system role, sorted by user id (keyset paging on `afterId`),
 * echo-checked (4.2 §6). Shared by the policy alert (P25), the quarantine approvers (Q20) and
 * the security alerts (step 6.2 N3).
 */
export async function findPermissionHolders(
  tx: Tx,
  organizationId: bigint,
  permission: string,
  page: HolderPage,
): Promise<NoticeUser[]> {
  const excluded = page.excluded ?? [];
  const afterId = page.afterId ?? null;
  const rows = await tx.user.findMany({
    where: {
      organizationId,
      status: 'active',
      deletedAt: null,
      emailVerifiedAt: { not: null },
      ...(afterId !== null || excluded.length > 0
        ? {
            id: {
              ...(afterId !== null ? { gt: afterId } : {}),
              ...(excluded.length > 0 ? { notIn: [...excluded] } : {}),
            },
          }
        : {}),
      userRoles: {
        some: {
          organizationId,
          role: {
            OR: [{ organizationId }, { organizationId: null }],
            permissions: { some: { permission: { key: permission } } },
          },
        },
      },
    },
    select: { id: true, organizationId: true, email: true, status: true },
    orderBy: { id: 'asc' },
    take: page.take,
  });
  for (const r of rows) {
    if (
      r.organizationId !== organizationId ||
      r.status !== 'active' ||
      excluded.includes(r.id) ||
      (afterId !== null && r.id <= afterId)
    ) {
      throw new InconsistentNotificationReadError('permission_holder');
    }
  }
  return rows.map((r) => ({ id: r.id, email: r.email.toLowerCase() }));
}

export interface NoticeMessage {
  id: bigint;
  publicId: string | null;
  organizationId: bigint;
  receivedAt: Date;
  direction: 'inbound' | 'outbound' | 'internal';
  envelopeFrom: string;
  internetMessageId: string | null;
  recipientCount: number;
}

/**
 * The writer reads of the notification handler (step 5.2 P25), inside its idempotency
 * transaction, each matched on the event's organization and echo-checked: the message row, its
 * public id, the organization's name, the decisive policy's name, the alert recipients (active,
 * non-deleted, email-verified users of the organization holding `policy:publish` through a role
 * of that organization or a system role, sorted by id, capped) and the active domains.
 */
export class NotificationReads {
  async message(
    tx: Tx,
    organizationId: bigint,
    id: bigint,
    receivedAt: Date,
  ): Promise<NoticeMessage | null> {
    const row = await tx.emailMessage.findFirst({
      where: { id, receivedAt, organizationId },
      select: {
        id: true,
        organizationId: true,
        receivedAt: true,
        direction: true,
        envelopeFrom: true,
        internetMessageId: true,
        recipientCount: true,
      },
    });
    if (row === null) return null;
    if (
      row.id !== id ||
      row.organizationId !== organizationId ||
      row.receivedAt.getTime() !== receivedAt.getTime()
    ) {
      throw new InconsistentNotificationReadError('email_message');
    }
    const identity = await tx.messageIdentity.findFirst({
      where: { id, organizationId },
      select: { id: true, organizationId: true, publicId: true },
    });
    if (identity !== null && (identity.id !== id || identity.organizationId !== organizationId)) {
      throw new InconsistentNotificationReadError('message_identity');
    }
    return { ...row, publicId: identity?.publicId ?? null };
  }

  async organizationName(tx: Tx, organizationId: bigint): Promise<string | null> {
    const row = await tx.organization.findFirst({
      where: { id: organizationId },
      select: { id: true, name: true },
    });
    if (row !== null && row.id !== organizationId) {
      throw new InconsistentNotificationReadError('organization');
    }
    return row?.name ?? null;
  }

  async policyName(tx: Tx, organizationId: bigint, publicId: string): Promise<string | null> {
    const row = await tx.emailPolicy.findFirst({
      where: { organizationId, publicId },
      select: { organizationId: true, publicId: true, name: true },
    });
    if (row !== null && (row.organizationId !== organizationId || row.publicId !== publicId)) {
      throw new InconsistentNotificationReadError('email_policy');
    }
    return row?.name ?? null;
  }

  /**
   * One page of the organization's policy administrators (P25): users holding `policy:publish`,
   * sorted by user id, after `afterId`, ≤ `take` (opt-outs are removed by `PreferenceFilter`).
   */
  alertRecipients(
    tx: Tx,
    organizationId: bigint,
    take: number,
    afterId: bigint | null = null,
  ): Promise<NoticeUser[]> {
    return findPermissionHolders(tx, organizationId, ALERT_PERMISSION, { take, afterId });
  }

  /** True when `domain` is an active, non-deleted domain of the organization. */
  async activeDomain(tx: Tx, organizationId: bigint, domain: string): Promise<boolean> {
    const row = await tx.domain.findFirst({
      where: { organizationId, name: domain, status: 'active', deletedAt: null },
      select: { organizationId: true, name: true },
    });
    if (
      row !== null &&
      (row.organizationId !== organizationId || row.name.toLowerCase() !== domain)
    ) {
      throw new InconsistentNotificationReadError('domain');
    }
    return row !== null;
  }
}
