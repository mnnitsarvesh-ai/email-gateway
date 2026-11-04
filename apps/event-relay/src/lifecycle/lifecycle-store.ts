import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { MessageState } from '@email-gateway/message-lifecycle';

/** A message row the lifecycle jobs consider (ids, state and version only). */
export interface LifecycleCandidate {
  id: bigint;
  receivedAt: Date;
  organizationId: bigint;
  state: MessageState;
  version: number;
  statusChangedAt: Date;
}

/** `organization_id IN (…)` scope: constructor-only (integration tests). */
export interface LifecycleScope {
  organizationIds?: readonly bigint[];
}

export interface ExpiryCandidatesQuery extends LifecycleScope {
  state: MessageState;
  /** The state's deadline. */
  olderThanSeconds: number;
  /**
   * `status_changed_at` lower bound in days (the state age, never `received_at`: a rescan or a
   * release re-enters the state machine at any message age).
   */
  lookbackDays: number;
  shard: { index: number; count: number };
  limit: number;
}

export interface CheckCandidatesQuery extends LifecycleScope {
  state: MessageState;
  olderThanSeconds: number;
  /** `status_changed_at` lower bound in hours (the state age, never `received_at`). */
  lookbackHours: number;
  /** Keyset position: rows after `(statusChangedAt, id)`. */
  after: { statusChangedAt: Date; id: bigint } | null;
  limit: number;
}

export interface StuckCountQuery extends LifecycleScope {
  state: MessageState;
  olderThanSeconds: number;
  cap: number;
}

/** The read queries of the expiry sweeper and the lifecycle check (writer, ADR-0014). */
export interface LifecycleStore {
  expiryCandidates(query: ExpiryCandidatesQuery): Promise<LifecycleCandidate[]>;
  checkCandidates(query: CheckCandidatesQuery): Promise<LifecycleCandidate[]>;
  countStuck(query: StuckCountQuery): Promise<number>;
}

interface CandidateRow {
  id: bigint;
  received_at: Date;
  organization_id: bigint;
  status: MessageState;
  version: number | bigint;
  status_changed_at: Date;
}

const toCandidate = (row: CandidateRow): LifecycleCandidate => ({
  id: BigInt(row.id),
  receivedAt: row.received_at,
  organizationId: BigInt(row.organization_id),
  state: row.status,
  version: Number(row.version),
  statusChangedAt: row.status_changed_at,
});

const scopeSql = (scope: LifecycleScope): Prisma.Sql =>
  scope.organizationIds === undefined
    ? Prisma.empty
    : scope.organizationIds.length === 0
      ? Prisma.sql`AND FALSE`
      : Prisma.sql`AND organization_id IN (${Prisma.join([...scope.organizationIds])})`;

/**
 * The queries on `email_messages` through the index `(status, status_changed_at)`: every bound is
 * a range on that index (one range scan per monthly partition, 6-month retention). No
 * `received_at` bound: a message released or rescanned long after it was received (quarantine
 * deadline 90 days, rescan from `expired`) must stay visible to both jobs.
 */
export class PrismaLifecycleStore implements LifecycleStore {
  constructor(private readonly prisma: PrismaClient) {}

  /**
   * L13 step 1: overdue messages of one state and one shard (`MOD(id, n) = i`), oldest first.
   * The deadline is passed in seconds (hours × 3600; integration tests use seconds).
   */
  async expiryCandidates(query: ExpiryCandidatesQuery): Promise<LifecycleCandidate[]> {
    const rows = await this.prisma.$queryRaw<CandidateRow[]>`
      SELECT id, received_at, organization_id, status, version, status_changed_at
      FROM email_messages
      WHERE status = ${query.state}
        AND status_changed_at < NOW(3) - INTERVAL ${query.olderThanSeconds} SECOND
        AND status_changed_at >= NOW(3) - INTERVAL ${query.lookbackDays} DAY
        AND MOD(id, ${query.shard.count}) = ${query.shard.index}
        ${scopeSql(query)}
      ORDER BY status_changed_at
      LIMIT ${query.limit}`;
    return rows.map(toCandidate);
  }

  /** L14 step 1: keyset on `(status_changed_at, id)` per state. */
  async checkCandidates(query: CheckCandidatesQuery): Promise<LifecycleCandidate[]> {
    const after = query.after
      ? Prisma.sql`AND (status_changed_at > ${query.after.statusChangedAt}
          OR (status_changed_at = ${query.after.statusChangedAt} AND id > ${query.after.id}))`
      : Prisma.empty;
    const rows = await this.prisma.$queryRaw<CandidateRow[]>`
      SELECT id, received_at, organization_id, status, version, status_changed_at
      FROM email_messages
      WHERE status = ${query.state}
        AND status_changed_at < NOW(3) - INTERVAL ${query.olderThanSeconds} SECOND
        AND status_changed_at >= NOW(3) - INTERVAL ${query.lookbackHours} HOUR
        ${after}
        ${scopeSql(query)}
      ORDER BY status_changed_at, id
      LIMIT ${query.limit}`;
    return rows.map(toCandidate);
  }

  /** L14 step 3: a `LIMIT`-bounded count over the index. */
  async countStuck(query: StuckCountQuery): Promise<number> {
    const rows = await this.prisma.$queryRaw<{ n: bigint | number }[]>`
      SELECT COUNT(*) AS n FROM (
        SELECT 1 FROM email_messages
        WHERE status = ${query.state}
          AND status_changed_at < NOW(3) - INTERVAL ${query.olderThanSeconds} SECOND
          ${scopeSql(query)}
        LIMIT ${query.cap}
      ) AS stuck`;
    return Number(rows[0]?.n ?? 0);
  }
}
