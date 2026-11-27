import { Prisma, type PrismaClient } from '@email-gateway/database';
import { big, TX_OPTIONS } from '../shared/db';

/** A clawback this replica holds: its lease is the claim token, `row_version` the CAS base. */
export interface ClaimedClawback {
  id: bigint;
  organizationId: bigint;
  rowVersion: number;
  leaseUntil: Date;
}

export interface ClawbackClaimOptions {
  now: Date;
  batch: number;
  /** `API_MODE_CLAWBACK_LEASE_SECONDS`. */
  leaseSeconds: number;
  /** TEST SEAM: only these organizations. */
  organizationIds?: readonly bigint[];
}

/** Statuses with work for the `clawback` role (C5.1). */
export const WORK_STATUSES = ['searching', 'queued', 'running'] as const;
/** Statuses an api cancellation request applies to (C5.6). */
export const CANCELLABLE_STATUSES = [
  'ready',
  'review_required',
  'pending_approval',
  'queued',
  'running',
] as const;

/**
 * The claim of the `clawback` role (note 37 C1, modelled on `remediation/claims.ts`): in one
 * writer transaction, due clawbacks — status `searching`/`queued`/`running` with
 * `next_step_at <= now`, a requested or running bulk restore, or a cancellation request on a
 * cancellable status — whose lease is free are locked `FOR UPDATE SKIP LOCKED` in id order and
 * leased for `API_MODE_CLAWBACK_LEASE_SECONDS`. The claim does **not** change `row_version`: the
 * api's compare-and-set (submit, approve, cancel, restore) keeps working against a clawback the
 * worker is processing; the worker's own state transitions are compare-and-sets on the version
 * read here (a concurrent api write makes them fail and the row is re-claimed next tick).
 */
export async function claimClawbacks(
  prisma: PrismaClient,
  options: ClawbackClaimOptions,
): Promise<ClaimedClawback[]> {
  const { now } = options;
  const leaseUntil = new Date(now.getTime() + options.leaseSeconds * 1000);
  const orgs = options.organizationIds
    ? Prisma.sql`AND organization_id IN (${Prisma.join(options.organizationIds)})`
    : Prisma.empty;
  const free = Prisma.sql`(lease_until IS NULL OR lease_until < ${now})`;
  const scan = Math.min(options.batch * 4, 1000);
  return prisma.$transaction(async (tx) => {
    const rows = await tx.$queryRaw<Array<{ id: bigint | number }>>`
      SELECT id FROM (
        (SELECT id FROM api_clawbacks
          WHERE status IN (${Prisma.join([...WORK_STATUSES])})
            AND (next_step_at IS NULL OR next_step_at <= ${now}) AND ${free} ${orgs}
          ORDER BY next_step_at, id LIMIT ${scan})
        UNION
        (SELECT id FROM api_clawbacks
          WHERE restore_status IN ('requested', 'running') AND ${free} ${orgs}
          ORDER BY id LIMIT ${scan})
        UNION
        (SELECT id FROM api_clawbacks
          WHERE cancel_requested_at IS NOT NULL
            AND status IN (${Prisma.join([...CANCELLABLE_STATUSES])}) AND ${free} ${orgs}
          ORDER BY id LIMIT ${scan})
      ) AS due_rows
      ORDER BY id
      LIMIT ${scan}`;
    if (rows.length === 0) return [];
    const locked = await tx.$queryRaw<
      Array<{
        id: bigint | number;
        organization_id: bigint | number;
        lease_until: Date | null;
        row_version: number;
      }>
    >`
      SELECT id, organization_id, lease_until, row_version FROM api_clawbacks
      WHERE id IN (${Prisma.join(rows.map((r) => big(r.id)))})
      ORDER BY id
      LIMIT ${options.batch}
      FOR UPDATE SKIP LOCKED`;
    const chosen = locked.filter((r) => r.lease_until === null || r.lease_until < now);
    if (chosen.length === 0) return [];
    await tx.$executeRaw`
      UPDATE api_clawbacks SET lease_until = ${leaseUntil}
      WHERE id IN (${Prisma.join(chosen.map((r) => big(r.id)))})`;
    return chosen.map((r) => ({
      id: big(r.id),
      organizationId: big(r.organization_id),
      rowVersion: Number(r.row_version),
      leaseUntil,
    }));
  }, TX_OPTIONS);
}

/** Extends the lease while it is still ours (long materializations). False when lost. */
export async function renewClawbackLease(
  prisma: PrismaClient,
  claim: ClaimedClawback,
  leaseUntil: Date,
): Promise<boolean> {
  const n = await prisma.$executeRaw`
    UPDATE api_clawbacks SET lease_until = ${leaseUntil}
    WHERE id = ${claim.id} AND lease_until = ${claim.leaseUntil}`;
  if (n === 1) claim.leaseUntil = leaseUntil;
  return n === 1;
}

/** Releases the lease and schedules the next look (`next_step_at`, null = nothing due). */
export async function releaseClawback(
  prisma: PrismaClient,
  claim: ClaimedClawback,
  nextStepAt: Date | null,
): Promise<void> {
  await prisma.$executeRaw`
    UPDATE api_clawbacks SET lease_until = NULL, next_step_at = ${nextStepAt}
    WHERE id = ${claim.id} AND lease_until = ${claim.leaseUntil}`;
}
