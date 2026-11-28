import { withTransactionDefaults } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  containerOf,
  createsQuarantineEntry,
  executedContainerOf,
  isRemediationAction,
  isReversal,
  REMEDIATION_ACTIONS,
  type ApiModeActionTrigger,
  type MessageVerdict,
  type ProviderRefContainer,
  type RemediationActionKind,
  type RemediationProvider,
} from '@email-gateway/mailbox-api';
import type { QuarantinePlatformBounds, QuarantineSettings } from '@email-gateway/quarantine';
import type { MailboxMetrics, RemediationResult } from '../metrics/mailbox-metrics';
import type { CounterDelta, CounterStore } from '../runtime/redis-stores';
import { big, systemAudit, TX_MAX_WAIT_MS, TX_TIMEOUT_MS } from '../shared/db';
import { InconsistentReadError } from '../shared/errors';
import {
  blockApprovedRestore,
  completeRestore,
  createMailboxEntry,
  policyLaneOfDecision,
  failRestore,
  staleRestore,
  type ApprovedRecheck,
  type LockedEntry,
  type MailboxEntryClawback,
  type ReleaseLogRow,
} from './quarantine-entries';

/** The action row as the executor loaded it (ids, enums and codes only). */
export interface ActionRow {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  apiConnectionId: bigint;
  mailboxId: bigint;
  copyId: bigint;
  copyReceivedAt: Date;
  messageId: bigint;
  action: RemediationActionKind;
  generation: number;
  /** Step API-3 adds `clawback` (automatic, policy-like) and `purge` (admin-like), C5.7. */
  trigger: ApiModeActionTrigger;
  status: string;
  decision: unknown;
  reversesActionId: bigint | null;
  quarantineEntryId: bigint | null;
  releaseLogId: bigint | null;
  attempts: number;
  locateAttempts: number;
  /** The last recorded error code (an outcome write that threw records its code here). */
  lastErrorCode: string | null;
  verdictAt: Date | null;
  rowVersion: number;
  /** Step API-3: the clawback that queued this action (`api_clawbacks.id`), else null. */
  clawbackId: bigint | null;
}

/** Everything an outcome writes about besides the action (public ids for the audit row). */
export interface OutcomeContext {
  action: ActionRow;
  provider: RemediationProvider;
  copy: {
    id: bigint;
    receivedAt: Date;
    publicId: string;
    messageId: bigint;
    mailboxId: bigint;
    verdict: MessageVerdict | null;
  };
  mailboxPublicId: string;
  connectionPublicId: string;
}

export interface ProviderRefs {
  before: string[];
  after: string[];
  container?: ProviderRefContainer;
}

/** The claim this replica holds (the CAS of every outcome). */
export interface HeldClaim {
  id: bigint;
  rowVersion: number;
}

/** The claim was lost (lease expired and re-claimed elsewhere): the outcome is discarded. */
export class ClaimLostError extends Error {
  readonly code = 'claim_lost';
  constructor() {
    super('remediation claim lost');
    this.name = 'ClaimLostError';
  }
}

const AUDIT_ACTION = 'api_mode.remediation_executed';

/** The rule id of a policy decision record (R2.4), else null. */
export function ruleIdOf(decision: unknown): string | null {
  if (decision && typeof decision === 'object') {
    const ruleId = (decision as { ruleId?: unknown }).ruleId;
    if (typeof ruleId === 'string' && /^[a-z0-9_-]{1,48}$/.test(ruleId)) return ruleId;
  }
  return null;
}

/**
 * The terminal and retry transitions of the `remediate` role (step API-2 R5.2, R5.6, R9, R10.3),
 * each in one writer transaction with a compare-and-set on the claimed `row_version` (a claim lost
 * to a lease expiry writes nothing): the action status, the copy (`remediated` / `restored` with
 * the next generation / `failed`), the reversal links, the mailbox quarantine entry (R9.1) or the
 * release completion (R10.3), and for `succeeded` / `failed` one system `audit_logs` row
 * `api_mode.remediation_executed` with public ids and codes. Counters and metrics follow the
 * commit (best effort, as everywhere in the worker).
 */
export class RemediationOutcomes {
  private readonly txPrisma: PrismaClient;

  constructor(
    private readonly deps: {
      prisma: PrismaClient;
      counters: CounterStore;
      metrics: MailboxMetrics | null;
      logger: Logger;
      bounds: QuarantinePlatformBounds;
    },
  ) {
    this.txPrisma = withTransactionDefaults(deps.prisma, {
      timeoutMs: TX_TIMEOUT_MS,
      maxWaitMs: TX_MAX_WAIT_MS,
    });
  }

  private async cas(
    tx: Prisma.TransactionClient,
    claim: HeldClaim,
    set: Prisma.Sql,
  ): Promise<void> {
    const n = await tx.$executeRaw`
      UPDATE api_remediation_actions SET ${set}, row_version = row_version + 1
      WHERE id = ${claim.id} AND row_version = ${claim.rowVersion} AND status = 'in_progress'`;
    if (n !== 1) throw new ClaimLostError();
  }

  private audit(
    tx: Prisma.TransactionClient,
    ctx: OutcomeContext,
    result: 'succeeded' | 'failed',
    reasonCode: string | null,
  ): Promise<void> {
    const a = ctx.action;
    return systemAudit(tx, {
      organizationId: a.organizationId,
      action: AUDIT_ACTION,
      resourceType: 'api_remediation_action',
      resourceId: a.publicId,
      correlationId: `api-remediation:${a.publicId}`,
      metadata: {
        actionId: a.publicId,
        action: a.action,
        trigger: a.trigger,
        result,
        reasonCode,
        copyId: ctx.copy.publicId,
        mailboxId: ctx.mailboxPublicId,
        connectionId: ctx.connectionPublicId,
      },
    });
  }

  private async run<T>(fn: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T | 'lost'> {
    try {
      return await this.txPrisma.$transaction(fn);
    } catch (error) {
      if (error instanceof ClaimLostError) return 'lost';
      throw error;
    }
  }

  /**
   * `succeeded` (R5.2, R5.4): remediations → copy `remediated` (+ the mailbox entry of R9.1 for
   * the quarantine folder, Junk and soft delete); reversals → copy `restored`,
   * `remediation_generation + 1`, the reversed action's `reversed_by_action_id`, and for a
   * release the entry `released` (R10.3).
   */
  async succeed(
    ctx: OutcomeContext,
    claim: HeldClaim,
    result: { refs: ProviderRefs; reasonCode: string | null; already: boolean },
    now: Date,
  ): Promise<'ok' | 'lost'> {
    const a = ctx.action;
    const reversal = isReversal(a.action);
    const providerId = result.refs.after[0] ?? null;
    let entryOutcome: string | null = null;
    const outcome = await this.run(async (tx) => {
      // The api's lock order: the copy first, then the action row (no deadlock with a request).
      await lockCopyRow(tx, a);
      await this.cas(
        tx,
        claim,
        Prisma.sql`status = 'succeeded', reason_code = ${result.reasonCode},
          provider_refs = ${JSON.stringify(result.refs)}, completed_at = ${now},
          lease_until = NULL, next_attempt_at = NULL, attempts = attempts + 1,
          last_error_code = NULL, last_http_status = NULL, updated_at = ${now}`,
      );
      if (!reversal) {
        await tx.$executeRaw`
          UPDATE api_message_copies
          SET remediation_state = 'remediated', remediation_action = ${a.action},
              last_action_id = ${a.id}, remediation_updated_at = ${now},
              provider_message_id = COALESCE(${providerId}, provider_message_id)
          WHERE id = ${ctx.copy.id} AND received_at = ${ctx.copy.receivedAt}
            AND organization_id = ${a.organizationId} AND remediation_generation = ${a.generation}`;
        const container = containerOf(a.action);
        // An entry delete's soft delete (trigger admin, entry already linked) changes no entry.
        if (
          createsQuarantineEntry(a.action) &&
          container !== null &&
          a.quarantineEntryId === null
        ) {
          const clawback =
            a.clawbackId === null
              ? null
              : await loadEntryClawback(tx, a.clawbackId, a.organizationId);
          const entry = await createMailboxEntry(tx, {
            organizationId: a.organizationId,
            actionId: a.id,
            actionPublicId: a.publicId,
            container,
            ruleId: a.trigger === 'policy' ? ruleIdOf(a.decision) : null,
            clawback,
            policyLane: a.trigger === 'policy' ? policyLaneOfDecision(a.decision) : null,
            copy: {
              id: ctx.copy.id,
              receivedAt: ctx.copy.receivedAt,
              messageId: ctx.copy.messageId,
              mailboxId: ctx.copy.mailboxId,
              verdict: ctx.copy.verdict,
              remediationGeneration: a.generation,
            },
            now,
            bounds: this.deps.bounds,
          });
          entryOutcome = entry ? (entry.created ? 'created' : 'adopted') : 'no_recipient';
          if (entry) {
            await tx.$executeRaw`
              UPDATE api_remediation_actions SET quarantine_entry_id = ${entry.entryId}
              WHERE id = ${a.id}`;
          }
        }
      } else {
        await tx.$executeRaw`
          UPDATE api_message_copies
          SET remediation_state = 'restored', remediation_generation = remediation_generation + 1,
              last_action_id = ${a.id}, remediation_updated_at = ${now},
              provider_message_id = COALESCE(${providerId}, provider_message_id)
          WHERE id = ${ctx.copy.id} AND received_at = ${ctx.copy.receivedAt}
            AND organization_id = ${a.organizationId} AND remediation_generation = ${a.generation}`;
        if (a.reversesActionId !== null) {
          await tx.$executeRaw`
            UPDATE api_remediation_actions
            SET reversed_by_action_id = ${a.id}, updated_at = ${now}
            WHERE id = ${a.reversesActionId} AND organization_id = ${a.organizationId}
              AND reversed_by_action_id IS NULL`;
        }
        if (a.action === 'restore_inbox' && a.quarantineEntryId !== null) {
          entryOutcome = await completeRestore(tx, {
            entryId: a.quarantineEntryId,
            organizationId: a.organizationId,
            releaseLogId: a.releaseLogId,
            actionPublicId: a.publicId,
            now,
          });
        }
      }
      await this.audit(tx, ctx, 'succeeded', result.reasonCode);
    });
    if (outcome === 'lost') return this.lost(ctx);
    if (entryOutcome === 'no_recipient') {
      this.deps.logger.warn(
        { actionId: a.publicId, action: a.action },
        'remediated message has no recipient row for the mailbox; no quarantine entry',
      );
    }
    const counters: CounterDelta = reversal
      ? { restores_succeeded: 1 }
      : { remediation_succeeded: 1 };
    if (!reversal && a.trigger === 'policy' && a.verdictAt !== null) {
      const ms = Math.max(0, now.getTime() - a.verdictAt.getTime());
      counters.remediation_latency_count = 1;
      counters.remediation_latency_sum_ms = ms;
      counters.remediation_latency_max_ms = ms;
      this.deps.metrics?.remediationLatency.observe({ provider: ctx.provider }, ms / 1000);
    }
    await this.deps.counters.add(a.apiConnectionId, counters);
    this.metric(ctx, result.already ? 'already_in_target' : 'succeeded');
    this.deps.metrics?.remediationAttempt(ctx.provider, 'ok');
    this.deps.logger.info(
      {
        actionId: a.publicId,
        action: a.action,
        trigger: a.trigger,
        provider: ctx.provider,
        reasonCode: result.reasonCode,
        entry: entryOutcome,
      },
      'remediation action succeeded',
    );
    return 'ok';
  }

  /**
   * `failed` (R5.2, R5.6): a remediation of the copy's current generation → copy `failed`; any
   * other failure (a reversal, a stale generation) gives the copy back the state its history
   * implies (`settleCopy`); a release's entry back to `held`.
   */
  async fail(
    ctx: OutcomeContext,
    claim: HeldClaim,
    failure: {
      code: string;
      counted: boolean;
      errorCode: string | null;
      httpStatus: number | null;
    },
    now: Date,
  ): Promise<'ok' | 'lost'> {
    const a = ctx.action;
    const reversal = isReversal(a.action);
    const outcome = await this.run(async (tx) => {
      // The api's lock order: the copy first, then the action row (no deadlock with a request).
      await lockCopyRow(tx, a);
      await this.cas(
        tx,
        claim,
        Prisma.sql`status = 'failed', reason_code = ${failure.code}, completed_at = ${now},
          lease_until = NULL, next_attempt_at = NULL,
          attempts = attempts + ${failure.counted ? 1 : 0},
          last_error_code = ${failure.errorCode}, last_http_status = ${failure.httpStatus},
          updated_at = ${now}`,
      );
      await settleCopy(tx, a, 'failed', now);
      if (reversal && a.action === 'restore_inbox' && a.quarantineEntryId !== null) {
        await failRestore(tx, {
          entryId: a.quarantineEntryId,
          organizationId: a.organizationId,
          releaseLogId: a.releaseLogId,
          actionPublicId: a.publicId,
          code: failure.code,
          now,
        });
      }
      await this.audit(tx, ctx, 'failed', failure.code);
    });
    if (outcome === 'lost') return this.lost(ctx);
    await this.deps.counters.add(
      a.apiConnectionId,
      reversal ? { restores_failed: 1 } : { remediation_failed: 1 },
    );
    this.metric(ctx, 'failed');
    this.deps.metrics?.remediationAttempt(ctx.provider, 'error');
    this.deps.logger.warn(
      {
        actionId: a.publicId,
        action: a.action,
        trigger: a.trigger,
        provider: ctx.provider,
        reasonCode: failure.code,
        errCode: failure.errorCode,
        status: failure.httpStatus,
      },
      'remediation action failed',
    );
    return 'ok';
  }

  /** Back to `pending` for a later attempt (R5.3 locate back-off, R5.6 retries). */
  async retry(
    ctx: OutcomeContext,
    claim: HeldClaim,
    retry: {
      nextAttemptAt: Date;
      attempts: number;
      locateAttempts: number;
      errorCode: string | null;
      httpStatus: number | null;
      outcome: 'retry' | 'throttled';
    },
    now: Date,
  ): Promise<'ok' | 'lost'> {
    const outcome = await this.run(async (tx) => {
      await this.cas(
        tx,
        claim,
        Prisma.sql`status = 'pending', next_attempt_at = ${retry.nextAttemptAt},
          lease_until = NULL, attempts = attempts + ${retry.attempts},
          locate_attempts = locate_attempts + ${retry.locateAttempts},
          last_error_code = ${retry.errorCode}, last_http_status = ${retry.httpStatus},
          updated_at = ${now}`,
      );
    });
    if (outcome === 'lost') return this.lost(ctx);
    this.deps.metrics?.remediationAttempt(ctx.provider, retry.outcome);
    return 'ok';
  }

  /** Back to `pending` without an attempt (paused connection, throttled family; R5.1). */
  async defer(
    ctx: OutcomeContext,
    claim: HeldClaim,
    until: Date,
    now: Date,
  ): Promise<'ok' | 'lost'> {
    const outcome = await this.run(async (tx) => {
      await this.cas(
        tx,
        claim,
        Prisma.sql`status = 'pending', next_attempt_at = ${until}, lease_until = NULL,
          updated_at = ${now}`,
      );
    });
    return outcome === 'lost' ? this.lost(ctx) : 'ok';
  }

  /**
   * `cancelled` (R5.2): a policy action whose copy was restored or remediated otherwise, a
   * reversal of a generation already reversed, or a restore whose entry left `releasing` (its
   * release log `stale`). `block`: the approved-mode re-check moved the entry back (R10.3). A copy
   * whose state points at the cancelled action gets the state its history implies (`settleCopy`).
   */
  async cancel(
    ctx: OutcomeContext,
    claim: HeldClaim,
    reasonCode: string | null,
    now: Date,
    extra: {
      staleLog?: boolean;
      block?: {
        entry: LockedEntry;
        log: ReleaseLogRow;
        recheck: ApprovedRecheck;
        settings: QuarantineSettings;
      };
    } = {},
  ): Promise<'ok' | 'lost'> {
    const a = ctx.action;
    const outcome = await this.run(async (tx) => {
      // The api's lock order: the copy first, then the action row (no deadlock with a request).
      await lockCopyRow(tx, a);
      await this.cas(
        tx,
        claim,
        Prisma.sql`status = 'cancelled', reason_code = ${reasonCode}, completed_at = ${now},
          lease_until = NULL, next_attempt_at = NULL, updated_at = ${now}`,
      );
      await settleCopy(tx, a, 'cancelled', now);
      if (extra.staleLog) {
        await staleRestore(tx, {
          organizationId: a.organizationId,
          releaseLogId: a.releaseLogId,
          now,
        });
      }
      if (extra.block) {
        await blockApprovedRestore(tx, {
          ...extra.block,
          correlationId: `api-remediation:${a.publicId}`,
          now,
        });
      }
    });
    if (outcome === 'lost') return this.lost(ctx);
    this.metric(ctx, 'cancelled');
    this.deps.logger.info(
      { actionId: a.publicId, action: a.action, trigger: a.trigger, reasonCode },
      'remediation action cancelled',
    );
    return 'ok';
  }

  private metric(ctx: OutcomeContext, result: RemediationResult): void {
    this.deps.metrics?.remediation(ctx.provider, ctx.action.action, result);
  }

  private lost(ctx: OutcomeContext): 'lost' {
    this.deps.logger.info(
      { actionId: ctx.action.publicId },
      'remediation claim lost (lease expired); outcome discarded',
    );
    return 'lost';
  }
}

/**
 * Step API-3 C5.5: what a mailbox entry created by a clawback action needs about its clawback
 * (public id, trigger, the signal verdict of policy mode; organization echo-checked). Null when
 * the clawback row is gone (retention), the entry then reads like an API-2 entry.
 */
async function loadEntryClawback(
  tx: Prisma.TransactionClient,
  clawbackId: bigint,
  organizationId: bigint,
): Promise<MailboxEntryClawback | null> {
  const row = await tx.apiClawback.findUnique({
    where: { id: clawbackId },
    select: { organizationId: true, publicId: true, trigger: true, signalVerdict: true },
  });
  if (!row) return null;
  if (row.organizationId !== organizationId) throw new InconsistentReadError('api_clawbacks');
  return { publicId: row.publicId, trigger: row.trigger, signalVerdict: row.signalVerdict };
}

type SettledState = 'none' | 'remediated' | 'restored' | 'failed' | 'simulated' | 'skipped';

/**
 * The copy's state after a non-success outcome of `a` (review fix, step API-2 R5.2, R12): the api
 * marks the copy `pending` with `last_action_id = a` when it queues a request, and the decision
 * of the policy does the same, so an action that ends `failed` or `cancelled` must not leave the
 * copy `pending` with nothing queued. Only a copy whose `last_action_id` is this action (or, for
 * a failed remediation, still none) is touched; the caller locked the copy row before the
 * action's CAS (`lockCopyRow`, the api's order). The state:
 * - a failed remediation of the copy's current generation → `failed` (this action);
 * - else a succeeded, unreversed remediation of the current generation → `remediated` (that
 *   action still applies: a failed `remove_tag` leaves the tag in place);
 * - else, after a restore (generation > 0), the latest succeeded reversal → `restored`;
 * - else the latest other decided row of the generation (`failed`, `simulated`, `skipped`);
 * - else `none` (the request found the copy undecided).
 */
/** Locks the action's copy row (`FOR UPDATE`) before the action's CAS: the api's lock order. */
async function lockCopyRow(
  tx: Prisma.TransactionClient,
  a: ActionRow,
): Promise<{ generation: number; lastActionId: bigint | null } | null> {
  const copies = await tx.$queryRaw<
    Array<{ remediation_generation: number | bigint; last_action_id: bigint | number | null }>
  >`
    SELECT remediation_generation, last_action_id FROM api_message_copies
    WHERE id = ${a.copyId} AND received_at = ${a.copyReceivedAt}
      AND organization_id = ${a.organizationId}
    FOR UPDATE`;
  const copy = copies[0];
  if (!copy) return null;
  return {
    generation: Number(copy.remediation_generation),
    lastActionId: copy.last_action_id === null ? null : big(copy.last_action_id),
  };
}

export async function settleCopy(
  tx: Prisma.TransactionClient,
  a: ActionRow,
  outcome: 'failed' | 'cancelled',
  now: Date,
): Promise<SettledState | null> {
  const copy = await lockCopyRow(tx, a);
  if (!copy) return null;
  const { generation, lastActionId } = copy;
  const remediation = isRemediationAction(a.action);
  const failedHere = outcome === 'failed' && remediation && generation === a.generation;
  if (lastActionId === null ? !failedHere : lastActionId !== a.id) return null;

  let state: SettledState;
  let action: string | null;
  let actionId: bigint | null;
  if (failedHere) {
    [state, action, actionId] = ['failed', a.action, a.id];
  } else {
    const remediations = Prisma.join([...REMEDIATION_ACTIONS]);
    const scope = Prisma.sql`copy_id = ${a.copyId} AND copy_received_at = ${a.copyReceivedAt}
      AND organization_id = ${a.organizationId} AND id <> ${a.id}`;
    type Row = { id: bigint | number; action: string; status: string; reversed?: string | null };
    const [applied] = await tx.$queryRaw<Row[]>`
      SELECT id, action, status FROM api_remediation_actions
      WHERE ${scope} AND generation = ${generation} AND status = 'succeeded'
        AND reversed_by_action_id IS NULL AND action IN (${remediations})
      ORDER BY id DESC LIMIT 1`;
    const [restore] =
      applied || generation === 0
        ? []
        : await tx.$queryRaw<Row[]>`
            SELECT r.id, r.action, r.status, rv.action AS reversed
            FROM api_remediation_actions r
            LEFT JOIN api_remediation_actions rv
              ON rv.id = r.reverses_action_id AND rv.organization_id = r.organization_id
            WHERE r.copy_id = ${a.copyId} AND r.copy_received_at = ${a.copyReceivedAt}
              AND r.organization_id = ${a.organizationId} AND r.id <> ${a.id}
              AND r.generation = ${generation - 1} AND r.status = 'succeeded'
              AND r.action NOT IN (${remediations})
            ORDER BY r.id DESC LIMIT 1`;
    const [decided] =
      applied || generation > 0
        ? []
        : await tx.$queryRaw<Row[]>`
            SELECT id, action, status FROM api_remediation_actions
            WHERE ${scope} AND generation = ${generation}
              AND status IN ('failed', 'simulated', 'skipped') AND action IN (${remediations})
            ORDER BY id DESC LIMIT 1`;
    if (applied) {
      [state, action, actionId] = ['remediated', applied.action, big(applied.id)];
    } else if (generation > 0) {
      // The restore of the previous generation is in effect; `remediation_action` is the action
      // it reversed (what a succeeded reversal leaves), else the column is kept.
      [state, action, actionId] = [
        'restored',
        restore?.reversed ?? null,
        restore ? big(restore.id) : a.id,
      ];
    } else if (decided) {
      [state, action, actionId] = [decided.status as SettledState, decided.action, big(decided.id)];
    } else {
      [state, action, actionId] = ['none', null, a.id];
    }
  }
  await tx.$executeRaw`
    UPDATE api_message_copies
    SET remediation_state = ${state},
        remediation_action = ${state === 'restored' && action === null ? Prisma.sql`remediation_action` : action},
        last_action_id = ${actionId}, remediation_updated_at = ${now}
    WHERE id = ${a.copyId} AND received_at = ${a.copyReceivedAt}
      AND organization_id = ${a.organizationId}`;
  return state;
}

/** `provider_refs` of an execution (opaque ids only, ≤ 5 each). */
export function providerRefsOf(
  action: RemediationActionKind,
  provider: RemediationProvider,
  before: readonly string[],
  after: readonly string[],
): ProviderRefs {
  const container = executedContainerOf(action, provider);
  return {
    before: before.slice(0, 5),
    after: after.slice(0, 5),
    ...(container !== null ? { container } : {}),
  };
}
