import type { Prisma } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { type PreferenceKind, resolveNotificationPreferences } from '@email-gateway/webhooks';
import type { NotificationMetrics } from './notification-metrics';
import { InconsistentNotificationReadError, type NoticeUser } from './notification-reads';

type Tx = Prisma.TransactionClient;

/** Loads one page of candidate users sorted by id: after `afterId` (exclusive), ≤ `take`. */
export type CandidatePage = (afterId: bigint | null, take: number) => Promise<NoticeUser[]>;

export interface FilteredRecipients {
  /** Lower-cased e-mails of the kept users, sorted by user id, ≤ the cap. */
  emails: string[];
  /** Users left out because they opted out of the kind (counted until the cap was reached). */
  optedOut: number;
}

/**
 * The per-user opt-outs of step 6.2 (N3, N4): removes the users whose
 * `notification_user_preferences.preferences.optOut` contains the kind, **before** the recipient
 * cap (so an opted-out administrator never shortens the list when more holders exist), and counts
 * them in `notification_alerts_suppressed_total{kind,reason="opt_out"}`. Shared by the security
 * alerts and the existing admin kinds (`policy_alert`, `quarantine_admin_alert`,
 * `quarantine_approval_requested`). The read is scoped to the event's organization and
 * echo-checked; a stored document that does not validate opts out of nothing (the api refuses to
 * write one; it is logged, never guessed).
 */
export class PreferenceFilter {
  constructor(
    private readonly metrics: Pick<NotificationMetrics, 'alertsSuppressed'>,
    private readonly logger?: Logger,
  ) {}

  /** Ids among `userIds` that opted out of `kind`. */
  async optedOut(
    tx: Tx,
    organizationId: bigint,
    userIds: readonly bigint[],
    kind: PreferenceKind,
  ): Promise<Set<bigint>> {
    if (userIds.length === 0) return new Set();
    const rows = await tx.notificationUserPreference.findMany({
      where: { organizationId, userId: { in: [...userIds] } },
      select: { organizationId: true, userId: true, preferences: true },
    });
    const out = new Set<bigint>();
    for (const row of rows) {
      if (row.organizationId !== organizationId || !userIds.includes(row.userId)) {
        throw new InconsistentNotificationReadError('notification_user_preference');
      }
      const resolved = resolveNotificationPreferences(row.preferences);
      if (resolved.invalidStored) {
        this.logger?.warn({
          message: 'stored notification preferences do not validate; no opt-out applied',
          organizationId: organizationId.toString(),
          userId: row.userId.toString(),
        });
      }
      if (resolved.optOut.includes(kind)) out.add(row.userId);
    }
    return out;
  }

  /**
   * Pages through the candidates (sorted by user id), drops opted-out users and stops at `cap`
   * kept users. Returns the kept e-mails and counts the opted-out users met on the way.
   */
  async collect(
    tx: Tx,
    organizationId: bigint,
    kind: PreferenceKind,
    page: CandidatePage,
    cap: number,
  ): Promise<FilteredRecipients> {
    const kept: string[] = [];
    let optedOut = 0;
    let afterId: bigint | null = null;
    while (kept.length < cap) {
      const rows = await page(afterId, cap);
      if (rows.length === 0) break;
      const excluded = await this.optedOut(
        tx,
        organizationId,
        rows.map((r) => r.id),
        kind,
      );
      for (const row of rows) {
        if (kept.length >= cap) break;
        if (excluded.has(row.id)) optedOut += 1;
        else kept.push(row.email);
      }
      if (rows.length < cap) break;
      afterId = rows[rows.length - 1]!.id;
    }
    if (optedOut > 0) this.metrics.alertsSuppressed.inc({ kind, reason: 'opt_out' }, optedOut);
    return { emails: kept, optedOut };
  }
}
