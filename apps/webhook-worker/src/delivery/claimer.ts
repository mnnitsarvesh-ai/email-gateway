import { withTransactionDefaults } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import { WEBHOOKS_FEATURE } from '../fanout/subscription-index';
import { idOf, type InconsistencySink, wrongRead } from '../shared/errors';
import type { InflightCounters, Reservation, ReserveResult } from './inflight';
import { deliveryKeyMatch } from './keys';
import type { SecretColumns } from './secrets';

/** Organizations with due work examined per tick (W8 step 1). */
export const DUE_ORGANIZATIONS_LIMIT = 200;
/** Budget of one claim transaction (short: row locks are held only while claiming). */
export const CLAIM_TX_TIMEOUT_MS = 15_000;
/** Extra lease beyond the total HTTP timeout (W8: `now + WEBHOOK_HTTP_TOTAL_TIMEOUT_MS + 60 s`). */
export const LEASE_EXTRA_MS = 60_000;

export interface SubscriptionForSend extends SecretColumns {
  url: string;
  status: 'active' | 'paused' | 'disabled' | 'deleted';
  maxConcurrency: number | null;
}

/** A delivery this process holds the lease of. */
export interface ClaimedDelivery {
  id: bigint;
  eventOccurredAt: Date;
  publicId: string;
  organizationId: bigint;
  subscriptionId: bigint;
  eventId: string;
  eventType: string;
  /** The attempt about to be made (1-based) = `attempt_count` after the claim (the CAS value). */
  attemptNo: number;
  firstAttemptAt: Date;
  claimedAt: Date;
  subscription: SubscriptionForSend;
  reservation: Reservation;
}

export type CancelReason =
  | 'subscription_disabled'
  | 'subscription_deleted'
  | 'subscription_missing'
  | 'organization_inactive'
  | 'webhooks_not_enabled';

export interface ClaimReport {
  claimed: ClaimedDelivery[];
  cancelled: Array<{ reason: CancelReason }>;
  limited: Array<Exclude<ReserveResult, 'ok'>>;
  /** Due rows of paused subscriptions parked (`next_attempt_at = NULL`) by this claim. */
  paused: number;
  lost: number;
}

interface DueRow {
  id: bigint;
  event_occurred_at: Date;
  public_id: string;
  subscription_id: bigint;
  organization_id: bigint;
  event_id: string;
  event_type: string;
  attempt_count: number | bigint;
  first_attempt_at: Date | null;
}

/** Fisher–Yates (fairness: every tick visits the due organizations in a new order). */
export function shuffle<T>(items: T[], random: () => number = Math.random): T[] {
  for (let i = items.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [items[i], items[j]] = [items[j] as T, items[i] as T];
  }
  return items;
}

/**
 * The claim side of the delivery loop (step 6.2 W8 steps 1–2), on the **writer**:
 *
 * 1. organizations with due work — one grouped query over `(status, organization_id,
 *    next_attempt_at)` (`webhook_deliveries_status_org_next_idx`, EXPLAIN-checked), at most 200
 *    per tick in `organization_id` order starting after the last organization of the previous
 *    tick (a rotating cursor that wraps around: with more than 200 due organizations every one is
 *    still visited within ⌈n / 200⌉ ticks);
 * 2. per organization, one short transaction: the organization (must be `active`) and its
 *    `webhooks` feature (must be enabled) — otherwise every due row read is `cancelled`
 *    (`organization_inactive` / `webhooks_not_enabled`; replayable once the organization is back),
 *    nothing is sent; the due rows `FOR UPDATE SKIP LOCKED` (another replica's claimed rows are
 *    skipped, never waited for), the subscriptions (echo-checked); `paused` → **parked**
 *    (`next_attempt_at = NULL`: out of the due index until the api's resume sets it to now, so a
 *    paused backlog never hides the organization's other subscriptions); `disabled` / `deleted`
 *    → `cancelled`; `active` → a Redis reservation (organization, subscription and rate caps) and
 *    the **lease**: `attempt_count + 1`, `first_attempt_at` (first time), `last_attempt_at = now`,
 *    `next_attempt_at = now + WEBHOOK_HTTP_TOTAL_TIMEOUT_MS + 60 s` (a crash leaves the lease to
 *    expire: at least once).
 *
 * Reservations of a rolled-back claim are given back.
 */
export class DeliveryClaimer {
  private readonly tx: PrismaClient;
  /** The last organization of the previous tick's due list (rotation cursor, per process). */
  private cursor: bigint | null = null;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly counters: InflightCounters,
    private readonly options: {
      totalTimeoutMs: number;
      maxPerSubscription: number;
      sink: InconsistencySink;
      /** Restricts the loop to these organizations (integration tests on the shared writer). */
      organizationIds?: readonly bigint[];
    },
  ) {
    this.tx = withTransactionDefaults(prisma, { timeoutMs: CLAIM_TX_TIMEOUT_MS });
  }

  private get orgFilter(): Prisma.Sql {
    const ids = this.options.organizationIds;
    if (ids === undefined) return Prisma.empty;
    // A restriction to no organization matches nothing (never every tenant).
    return ids.length === 0
      ? Prisma.sql`AND 1 = 0`
      : Prisma.sql`AND organization_id IN (${Prisma.join(ids)})`;
  }

  /**
   * The due-organizations query (exported text for the EXPLAIN test): `after` / `upTo` bound the
   * `organization_id` range of the rotating cursor.
   */
  dueOrganizationsSql(
    now: Date,
    range: { after?: bigint; upTo?: bigint } = {},
    limit: number = DUE_ORGANIZATIONS_LIMIT,
  ): Prisma.Sql {
    const after =
      range.after === undefined ? Prisma.empty : Prisma.sql`AND organization_id > ${range.after}`;
    const upTo =
      range.upTo === undefined ? Prisma.empty : Prisma.sql`AND organization_id <= ${range.upTo}`;
    return Prisma.sql`
      SELECT organization_id, MIN(next_attempt_at) AS due
      FROM webhook_deliveries
      WHERE status = 'pending' ${after} ${upTo} ${this.orgFilter}
      GROUP BY organization_id
      HAVING MIN(next_attempt_at) <= ${now}
      ORDER BY organization_id
      LIMIT ${limit}`;
  }

  /**
   * The claim query of one organization (exported text for the EXPLAIN test). The index is
   * forced: with few pending rows the optimizer may prefer `(status, next_attempt_at)`, and a
   * `FOR UPDATE` scan of that index under REPEATABLE READ would lock other organizations' rows
   * (which other replicas then skip), breaking per-organization fairness.
   */
  claimSql(organizationId: bigint, now: Date, limit: number, lock = true): Prisma.Sql {
    return Prisma.sql`
      SELECT id, event_occurred_at, public_id, subscription_id, organization_id, event_id,
             event_type, attempt_count, first_attempt_at
      FROM webhook_deliveries FORCE INDEX (webhook_deliveries_status_org_next_idx)
      WHERE status = 'pending' AND organization_id = ${organizationId}
        AND next_attempt_at <= ${now}
      ORDER BY next_attempt_at
      LIMIT ${limit}
      ${lock ? Prisma.sql`FOR UPDATE SKIP LOCKED` : Prisma.empty}`;
  }

  /**
   * Up to DUE_ORGANIZATIONS_LIMIT organizations with due work: those after the cursor first, then
   * (wrapping around) those from the start up to the cursor. The cursor moves to the last
   * organization returned when the list was cut by the limit, otherwise back to the start.
   */
  async dueOrganizations(now: Date): Promise<bigint[]> {
    const read = async (range: { after?: bigint; upTo?: bigint }, limit: number) =>
      (
        await this.prisma.$queryRaw<Array<{ organization_id: bigint }>>(
          this.dueOrganizationsSql(now, range, limit),
        )
      ).map((r) => idOf(r.organization_id));
    const cursor = this.cursor;
    const first = await read(cursor === null ? {} : { after: cursor }, DUE_ORGANIZATIONS_LIMIT);
    let out = first;
    let cut = first.length >= DUE_ORGANIZATIONS_LIMIT;
    if (!cut && cursor !== null) {
      const rest = DUE_ORGANIZATIONS_LIMIT - first.length;
      const wrapped = await read({ upTo: cursor }, rest);
      out = [...first, ...wrapped];
      cut = wrapped.length >= rest;
    }
    this.cursor = cut ? (out.at(-1) ?? null) : null;
    return out;
  }

  /** Why nothing of the organization may be sent (W5, suspension), or null when it may. */
  private async blocked(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
  ): Promise<'organization_inactive' | 'webhooks_not_enabled' | null> {
    const organization = await tx.organization.findUnique({
      where: { id: organizationId },
      select: { id: true, status: true },
    });
    if (organization !== null && organization.id !== organizationId) {
      wrongRead(this.options.sink, 'organization', 'organization id');
    }
    if (organization === null || organization.status !== 'active') return 'organization_inactive';
    const feature = await tx.organizationFeature.findUnique({
      where: {
        organizationId_featureKey: { organizationId, featureKey: WEBHOOKS_FEATURE },
      },
      select: { organizationId: true, featureKey: true, enabled: true },
    });
    if (
      feature !== null &&
      (feature.organizationId !== organizationId || feature.featureKey !== WEBHOOKS_FEATURE)
    ) {
      wrongRead(this.options.sink, 'organization', 'feature row');
    }
    return feature?.enabled === true ? null : 'webhooks_not_enabled';
  }

  private async cancel(
    tx: Prisma.TransactionClient,
    rows: readonly DueRow[],
    reason: CancelReason,
    now: Date,
  ): Promise<number> {
    if (rows.length === 0) return 0;
    return tx.$executeRaw`
      UPDATE webhook_deliveries
      SET status = 'cancelled', next_attempt_at = NULL, completed_at = ${now},
          last_error = ${reason}
      WHERE status = 'pending'
        AND ${deliveryKeyMatch(rows)}`;
  }

  /** Claims up to `limit` due deliveries of one organization. */
  async claim(organizationId: bigint, limit: number, now: Date): Promise<ClaimReport> {
    const reservations: Reservation[] = [];
    try {
      return await this.tx.$transaction(async (tx) => {
        const report: ClaimReport = { claimed: [], cancelled: [], limited: [], paused: 0, lost: 0 };
        // Read twice the slots: rows of capped or paused subscriptions are skipped.
        const rows = await tx.$queryRaw<DueRow[]>(
          this.claimSql(organizationId, now, Math.min(limit * 2, 200)),
        );
        if (rows.length === 0) return report;
        for (const row of rows) {
          if (idOf(row.organization_id) !== organizationId) {
            wrongRead(this.options.sink, 'claim', 'organization');
          }
        }
        // A suspended / deleted organization or a revoked feature: nothing leaves the platform.
        const blocked = await this.blocked(tx, organizationId);
        if (blocked !== null) {
          const n = await this.cancel(tx, rows, blocked, now);
          for (let i = 0; i < n; i += 1) report.cancelled.push({ reason: blocked });
          return report;
        }
        const subscriptionIds = [...new Set(rows.map((r) => idOf(r.subscription_id)))];
        const subs = await tx.webhookSubscription.findMany({
          where: { id: { in: subscriptionIds }, organizationId },
          select: {
            id: true,
            organizationId: true,
            publicId: true,
            url: true,
            status: true,
            maxConcurrency: true,
            secretVersion: true,
            secretCiphertext: true,
            previousSecretCiphertext: true,
            previousSecretExpiresAt: true,
          },
        });
        const byId = new Map<string, SubscriptionForSend>();
        for (const s of subs) {
          if (s.organizationId !== organizationId || !subscriptionIds.includes(s.id)) {
            wrongRead(this.options.sink, 'subscriptions', 'organization or id');
          }
          byId.set(s.id.toString(), s);
        }
        const lease = new Date(now.getTime() + this.options.totalTimeoutMs + LEASE_EXTRA_MS);
        const parked: DueRow[] = [];
        let orgCapped = false;
        for (const row of rows) {
          const sub = byId.get(idOf(row.subscription_id).toString());
          // Paused rows are parked even past the claim limit (they must leave the due range).
          if (sub?.status === 'paused') {
            parked.push(row);
            continue;
          }
          if (report.claimed.length >= limit) continue;
          const id = idOf(row.id);
          if (sub === undefined || sub.status === 'disabled' || sub.status === 'deleted') {
            const reason =
              sub === undefined
                ? 'subscription_missing'
                : sub.status === 'disabled'
                  ? 'subscription_disabled'
                  : 'subscription_deleted';
            const cancelled = await tx.$executeRaw`
              UPDATE webhook_deliveries
              SET status = 'cancelled', next_attempt_at = NULL, completed_at = ${now},
                  last_error = ${reason}
              WHERE id = ${id} AND event_occurred_at = ${row.event_occurred_at}
                AND status = 'pending'`;
            if (cancelled === 1) report.cancelled.push({ reason });
            continue;
          }
          const cap = Math.min(
            sub.maxConcurrency ?? this.options.maxPerSubscription,
            this.options.maxPerSubscription,
          );
          if (orgCapped) continue;
          const { result, reservation } = await this.counters.reserve(organizationId, sub.id, cap);
          if (reservation === null) {
            report.limited.push(result as Exclude<ReserveResult, 'ok'>);
            if (result === 'organization') orgCapped = true;
            continue;
          }
          reservations.push(reservation);
          const attempts = Number(row.attempt_count);
          const updated = await tx.$executeRaw`
            UPDATE webhook_deliveries
            SET attempt_count = attempt_count + 1, last_attempt_at = ${now},
                first_attempt_at = COALESCE(first_attempt_at, ${now}), next_attempt_at = ${lease}
            WHERE id = ${id} AND event_occurred_at = ${row.event_occurred_at}
              AND status = 'pending' AND attempt_count = ${attempts}`;
          if (updated !== 1) {
            report.lost += 1;
            this.options.sink('claim');
            reservations.pop();
            await this.counters.undo(reservation);
            continue;
          }
          report.claimed.push({
            id,
            eventOccurredAt: row.event_occurred_at,
            publicId: row.public_id,
            organizationId,
            subscriptionId: sub.id,
            eventId: row.event_id,
            eventType: row.event_type,
            attemptNo: attempts + 1,
            firstAttemptAt: row.first_attempt_at ?? now,
            claimedAt: now,
            subscription: sub,
            reservation,
          });
        }
        if (parked.length > 0) {
          report.paused = await tx.$executeRaw`
            UPDATE webhook_deliveries SET next_attempt_at = NULL
            WHERE status = 'pending'
              AND ${deliveryKeyMatch(parked)}`;
        }
        return report;
      });
    } catch (error) {
      await Promise.allSettled(reservations.map((r) => this.counters.undo(r)));
      throw error;
    }
  }
}
