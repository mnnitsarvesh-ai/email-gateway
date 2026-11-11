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

  /** Emails of the organization's policy administrators (P25), sorted by user id, ≤ `cap`. */
  async alertRecipients(tx: Tx, organizationId: bigint, cap: number): Promise<string[]> {
    const rows = await tx.user.findMany({
      where: {
        organizationId,
        status: 'active',
        deletedAt: null,
        emailVerifiedAt: { not: null },
        userRoles: {
          some: {
            organizationId,
            role: {
              OR: [{ organizationId }, { organizationId: null }],
              permissions: { some: { permission: { key: ALERT_PERMISSION } } },
            },
          },
        },
      },
      select: { id: true, organizationId: true, email: true, status: true },
      orderBy: { id: 'asc' },
      take: cap,
    });
    for (const r of rows) {
      if (r.organizationId !== organizationId || r.status !== 'active') {
        throw new InconsistentNotificationReadError('alert_recipient');
      }
    }
    return rows.map((r) => r.email.toLowerCase());
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
