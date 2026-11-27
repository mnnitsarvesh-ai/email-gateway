import type { Prisma } from '@email-gateway/database';
import { InconsistentNotificationReadError } from './notification-reads';

type Tx = Prisma.TransactionClient;

/** The fields of a user report the feedback needs (step API-3 C12); never content. */
export interface FeedbackReport {
  publicId: string;
  organizationId: bigint;
  /** `api_user_reports.status`. */
  status: string;
  /** Lower-cased reporter address (header From addr-spec, else envelope sender). */
  reporterAddress: string;
  /** `api_user_reports.analyst_verdict` (null until resolved). */
  analystVerdict: string | null;
  /** The report copy's `received_at`. */
  reportedAt: Date;
}

/** Domain statuses that make a domain the organization's own (verified or in service). */
const OWN_DOMAIN_STATUSES = ['verified', 'active'] as const;

/**
 * The writer reads of the reporter feedback (step API-3 C12), inside the consumer's idempotency
 * transaction, each scoped to the envelope's organization and echo-checked (4.2 §6): the report
 * by public id, the organization name, its own domain names and whether the reporter address
 * still resolves to an organization mailbox (`api_mailbox_addresses`, mailbox not deleted) or an
 * active organization user. Reads ids, states, the reporter address and dates only — never the
 * reported message's subject, sender, body or the report's `original` document.
 */
export class ReportFeedbackReads {
  async report(tx: Tx, organizationId: bigint, publicId: string): Promise<FeedbackReport | null> {
    const row = await tx.apiUserReport.findFirst({
      where: { publicId, organizationId },
      select: {
        publicId: true,
        organizationId: true,
        status: true,
        reporterAddress: true,
        analystVerdict: true,
        reportedAt: true,
      },
    });
    if (row === null) return null;
    if (row.publicId !== publicId || row.organizationId !== organizationId) {
      throw new InconsistentNotificationReadError('api_user_report');
    }
    return {
      publicId: row.publicId,
      organizationId: row.organizationId,
      status: row.status,
      reporterAddress: row.reporterAddress.trim().toLowerCase(),
      analystVerdict: row.analystVerdict,
      reportedAt: row.reportedAt,
    };
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

  /** True when `domain` is a verified or active, non-deleted domain of the organization. */
  async ownDomain(tx: Tx, organizationId: bigint, domain: string): Promise<boolean> {
    const row = await tx.domain.findFirst({
      where: {
        organizationId,
        name: domain,
        status: { in: [...OWN_DOMAIN_STATUSES] },
        deletedAt: null,
      },
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

  /**
   * True when the address still resolves to the organization: an address of one of its API-mode
   * mailboxes that is not deleted, or an active, non-deleted user with that e-mail.
   */
  async reporterResolves(tx: Tx, organizationId: bigint, address: string): Promise<boolean> {
    const mailboxAddress = await tx.apiMailboxAddress.findFirst({
      where: { organizationId, address },
      select: {
        organizationId: true,
        address: true,
        mailbox: { select: { organizationId: true, status: true, deletedAt: true } },
      },
    });
    if (mailboxAddress !== null) {
      if (
        mailboxAddress.organizationId !== organizationId ||
        mailboxAddress.address.toLowerCase() !== address ||
        mailboxAddress.mailbox.organizationId !== organizationId
      ) {
        throw new InconsistentNotificationReadError('api_mailbox_address');
      }
      if (
        mailboxAddress.mailbox.status !== 'deleted' &&
        mailboxAddress.mailbox.deletedAt === null
      ) {
        return true;
      }
    }
    const user = await tx.user.findFirst({
      where: { organizationId, email: address, status: 'active', deletedAt: null },
      select: { organizationId: true, email: true, status: true },
    });
    if (user === null) return false;
    if (
      user.organizationId !== organizationId ||
      user.email.toLowerCase() !== address ||
      user.status !== 'active'
    ) {
      throw new InconsistentNotificationReadError('user');
    }
    return true;
  }
}
