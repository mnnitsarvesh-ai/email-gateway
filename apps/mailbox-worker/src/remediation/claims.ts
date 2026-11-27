import { Prisma, type PrismaClient } from '@email-gateway/database';
import { big, TX_OPTIONS } from '../shared/db';

/** A claimed action: the key, its connection and the row version after the claim (CAS). */
export interface ClaimedAction {
  id: bigint;
  organizationId: bigint;
  apiConnectionId: bigint;
  rowVersion: number;
  leaseUntil: Date;
}

export interface ClaimOptions {
  now: Date;
  /** `API_MODE_REMEDIATION_BATCH`. */
  batch: number;
  /** `API_MODE_REMEDIATION_LEASE_SECONDS`. */
  leaseSeconds: number;
  /** `API_MODE_REMEDIATION_CONCURRENCY_PER_CONNECTION`: in-flight actions per connection. */
  perConnection: number;
  /** TEST SEAM: only these organizations. */
  organizationIds?: readonly bigint[];
}

/**
 * Pure: which candidates may be claimed given the in-flight actions per connection (leased
 * `in_progress` rows of every replica) and the per-connection cap. Keeps the candidates' order.
 */
export function selectWithinCaps<T extends { apiConnectionId: bigint }>(
  candidates: readonly T[],
  inFlight: ReadonlyMap<bigint, number>,
  perConnection: number,
  limit: number,
): T[] {
  const taken = new Map<bigint, number>();
  const out: T[] = [];
  for (const c of candidates) {
    if (out.length >= limit) break;
    const used = (inFlight.get(c.apiConnectionId) ?? 0) + (taken.get(c.apiConnectionId) ?? 0);
    if (used >= perConnection) continue;
    taken.set(c.apiConnectionId, (taken.get(c.apiConnectionId) ?? 0) + 1);
    out.push(c);
  }
  return out;
}

/**
 * The claim of the `remediate` role (step API-2 R1, R5.1; modelled on the feeds' mailbox lease):
 * in one writer transaction, due rows — `pending` with `next_attempt_at <= now`, or `in_progress`
 * whose lease expired (a crashed or stopped replica) — are locked `FOR UPDATE SKIP LOCKED` in due
 * order, capped per API connection by the leased in-flight rows of every replica
 * (`API_MODE_REMEDIATION_CONCURRENCY_PER_CONNECTION`), and moved to `in_progress` with a lease of
 * `API_MODE_REMEDIATION_LEASE_SECONDS` (`row_version + 1`, the CAS of the outcome). Another
 * replica skips the locked rows, so no action is executed twice concurrently; a re-claim after a
 * lease expiry re-reads the provider state first (R5.4), so it repeats nothing harmful. The
 * re-claim of an expired `in_progress` row counts one attempt (an execution that never wrote its
 * outcome): the executor fails the row `internal_error` once `API_MODE_REMEDIATION_MAX_ATTEMPTS`
 * is reached instead of re-claiming it forever.
 */
export async function claimDueActions(
  prisma: PrismaClient,
  options: ClaimOptions,
): Promise<ClaimedAction[]> {
  const { now } = options;
  const leaseUntil = new Date(now.getTime() + options.leaseSeconds * 1000);
  const orgs = options.organizationIds
    ? Prisma.sql`AND organization_id IN (${Prisma.join(options.organizationIds)})`
    : Prisma.empty;
  // Candidates beyond the batch so a busy connection at its cap does not starve the others.
  const scan = Math.min(options.batch * 4, 4000);
  return prisma.$transaction(async (tx) => {
    const rows = await tx.$queryRaw<
      Array<{
        id: bigint | number;
        organization_id: bigint | number;
        api_connection_id: bigint | number;
      }>
    >`
      SELECT id, organization_id, api_connection_id FROM (
        (SELECT id, organization_id, api_connection_id, next_attempt_at AS due
           FROM api_remediation_actions
          WHERE status = 'pending' AND next_attempt_at <= ${now}
            AND (lease_until IS NULL OR lease_until < ${now}) ${orgs}
          ORDER BY next_attempt_at, id
          LIMIT ${scan})
        UNION ALL
        (SELECT id, organization_id, api_connection_id, lease_until AS due
           FROM api_remediation_actions
          WHERE status = 'in_progress' AND lease_until < ${now} ${orgs}
          ORDER BY lease_until, id
          LIMIT ${scan})
      ) AS due_rows
      ORDER BY due, id
      LIMIT ${scan}`;
    if (rows.length === 0) return [];
    const ids = rows.map((r) => big(r.id));
    // Lock in id order (deadlock-free between replicas); rows another replica holds are skipped.
    const locked = await tx.$queryRaw<
      Array<{
        id: bigint | number;
        organization_id: bigint | number;
        api_connection_id: bigint | number;
        status: string;
        next_attempt_at: Date | null;
        lease_until: Date | null;
        row_version: number;
      }>
    >`
      SELECT id, organization_id, api_connection_id, status, next_attempt_at, lease_until,
             row_version
      FROM api_remediation_actions
      WHERE id IN (${Prisma.join(ids)})
      ORDER BY id
      FOR UPDATE SKIP LOCKED`;
    const due = new Map(
      locked
        .filter(
          (r) =>
            (r.status === 'pending' &&
              r.next_attempt_at !== null &&
              r.next_attempt_at <= now &&
              (r.lease_until === null || r.lease_until < now)) ||
            (r.status === 'in_progress' && r.lease_until !== null && r.lease_until < now),
        )
        .map((r) => [big(r.id), r] as const),
    );
    const candidates = ids
      .filter((id) => due.has(id))
      .map((id) => {
        const r = due.get(id)!;
        return {
          id,
          organizationId: big(r.organization_id),
          apiConnectionId: big(r.api_connection_id),
          rowVersion: Number(r.row_version),
        };
      });
    if (candidates.length === 0) return [];
    const connections = [...new Set(candidates.map((c) => c.apiConnectionId))];
    const flying = await tx.$queryRaw<
      Array<{ api_connection_id: bigint | number; n: bigint | number }>
    >`
      SELECT api_connection_id, COUNT(*) AS n FROM api_remediation_actions
      WHERE status = 'in_progress' AND lease_until >= ${now}
        AND api_connection_id IN (${Prisma.join(connections)})
      GROUP BY api_connection_id`;
    const inFlight = new Map(flying.map((f) => [big(f.api_connection_id), Number(f.n)]));
    const chosen = selectWithinCaps(candidates, inFlight, options.perConnection, options.batch);
    if (chosen.length === 0) return [];
    // MySQL applies SET assignments left to right: `attempts` reads the status before the claim.
    await tx.$executeRaw`
      UPDATE api_remediation_actions
      SET attempts = attempts + IF(status = 'in_progress', 1, 0),
          status = 'in_progress', lease_until = ${leaseUntil},
          started_at = COALESCE(started_at, ${now}), row_version = row_version + 1,
          updated_at = ${now}
      WHERE id IN (${Prisma.join(chosen.map((c) => c.id))})`;
    return chosen.map((c) => ({
      id: c.id,
      organizationId: c.organizationId,
      apiConnectionId: c.apiConnectionId,
      rowVersion: c.rowVersion + 1,
      leaseUntil,
    }));
  }, TX_OPTIONS);
}

/**
 * Extends the lease of an action still held by this claim (long plans, throttled waits): CAS on
 * `row_version` and `in_progress`; the version is not changed. False when the claim was lost.
 */
export async function renewLease(
  prisma: PrismaClient,
  claim: Pick<ClaimedAction, 'id' | 'rowVersion'>,
  leaseUntil: Date,
): Promise<boolean> {
  const n = await prisma.$executeRaw`
    UPDATE api_remediation_actions SET lease_until = ${leaseUntil}
    WHERE id = ${claim.id} AND row_version = ${claim.rowVersion} AND status = 'in_progress'`;
  return n === 1;
}

/**
 * Best effort, after an execution threw before writing its outcome: the error code on the row
 * still held by this claim (CAS on `row_version` and `in_progress`; the version is not changed,
 * so the lease and the claim stay as they were). The code only, never a message.
 */
export async function recordLastError(
  prisma: PrismaClient,
  claim: Pick<ClaimedAction, 'id' | 'rowVersion'>,
  code: string,
): Promise<boolean> {
  const n = await prisma.$executeRaw`
    UPDATE api_remediation_actions SET last_error_code = ${code.slice(0, 64)}
    WHERE id = ${claim.id} AND row_version = ${claim.rowVersion} AND status = 'in_progress'`;
  return n === 1;
}
