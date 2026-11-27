import { uuidv7, withTransactionDefaults } from '@email-gateway/common';
import {
  Prisma,
  type ApiClawbackStatus,
  type ApiClawbackTrigger,
  type ApiCopyRemediationState,
  type PrismaClient,
} from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  AUTOMATIC_CLAWBACK_TRIGGERS,
  buildDecisionRecord,
  CLAWBACK_MATCH_KEYS,
  clawbackCriteriaSchema,
  clawbackPolicyOutcome,
  clawbackWindowIssues,
  clawbackRemediationInput,
  clawbackSignalFactsSchema,
  decideRemediation,
  planClawbackTarget,
  remediationActionKey,
  targetEligibility,
  type ClawbackSignalFacts,
  type RemediationAction,
  type RemediationInput,
} from '@email-gateway/mailbox-api';
import type { QuarantinePlatformBounds } from '@email-gateway/quarantine';
import { loadOrgSettings } from '../domain/org-settings';
import type { MailboxMetrics } from '../metrics/mailbox-metrics';
import {
  connectionFacts,
  domainMode,
  loadDecisionContext,
  newDecisionMemo,
  type DecisionMemo,
} from '../remediation/decide';
import { settleCopy, type ActionRow } from '../remediation/outcomes';
import type { RemediationPolicyLoader } from '../remediation/policy-loader';
import type { CounterDelta, CounterStore } from '../runtime/redis-stores';
import { requestThrottledAlert } from '../shared/alerts';
import { big, retryLockConflict, systemAudit, TX_MAX_WAIT_MS, TX_TIMEOUT_MS } from '../shared/db';
import { errorCode, errorFields, InconsistentReadError } from '../shared/errors';
import {
  claimClawbacks,
  releaseClawback,
  renewClawbackLease,
  CANCELLABLE_STATUSES,
  type ClaimedClawback,
} from './claims';
import { ClawbackRestorer } from './clawback-restore';
import { searchCopies, type MatchedCopy } from './search';

/** Targets inserted per materialization transaction (C4.3). */
export const MATERIALIZE_PAGE = 1_000;
/** Terminal action statuses a target is reconciled from (C5.5). */
const TERMINAL_ACTION_STATUSES = ['succeeded', 'failed', 'cancelled', 'skipped', 'simulated'];
/** Approvals expired per tick (C6). */
const EXPIRY_BATCH = 100;
/** Clawbacks claimed per tick. */
const CLAIM_BATCH = 10;

export interface ClawbackConfig {
  tickMs: number;
  leaseSeconds: number;
  maxTargets: number;
  /** `API_MODE_CLAWBACK_MAX_WINDOW_DAYS` (C4.1; re-checked for admin/campaign/report). */
  maxWindowDays: number;
  queueBatch: number;
  maxPendingPerConnection: number;
  hardDeleteEnabled: boolean;
  approvalTtlHours: number;
  bounds: QuarantinePlatformBounds;
}

export interface ClawbackDeps {
  prisma: PrismaClient;
  policies: RemediationPolicyLoader;
  counters: CounterStore;
  metrics: MailboxMetrics | null;
  logger: Logger;
  now: () => Date;
  config: ClawbackConfig;
  organizationIds?: readonly bigint[];
}

/** The clawback columns the role reads (ids, enums, documents of hashes and keys only). */
export interface ClawbackRow {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  trigger: ApiClawbackTrigger;
  criteria: unknown;
  decisionMode: 'policy' | 'explicit' | null;
  action: 'move_quarantine' | 'move_junk' | 'soft_delete' | 'hard_delete' | null;
  signalVerdict: ClawbackSignalFacts['verdict'] | null;
  signalLevel: ClawbackSignalFacts['level'] | null;
  signalHardBlocks: unknown;
  status: ApiClawbackStatus;
  cancelRequestedAt: Date | null;
  restoreStatus: 'none' | 'requested' | 'running' | 'completed' | 'completed_with_errors';
  approvalStatus: string | null;
  requestedByType: 'system' | 'user' | 'api_key';
  requestedByUserId: bigint | null;
  submittedByUserId: bigint | null;
  requestReason: string | null;
  signalAt: Date;
  rowVersion: number;
}

const CLAWBACK_SELECT = {
  id: true,
  publicId: true,
  organizationId: true,
  trigger: true,
  criteria: true,
  decisionMode: true,
  action: true,
  signalVerdict: true,
  signalLevel: true,
  signalHardBlocks: true,
  status: true,
  cancelRequestedAt: true,
  restoreStatus: true,
  approvalStatus: true,
  requestedByType: true,
  requestedByUserId: true,
  submittedByUserId: true,
  requestReason: true,
  signalAt: true,
  rowVersion: true,
} as const;

export const isAutomatic = (trigger: ApiClawbackTrigger): boolean =>
  (AUTOMATIC_CLAWBACK_TRIGGERS as readonly string[]).includes(trigger);

/** The C3.1 facts stored on the clawback row (policy mode), null when none are stored. */
export function storedFacts(row: ClawbackRow): ClawbackSignalFacts | null {
  if (row.signalVerdict === null || row.signalLevel === null) return null;
  const parsed = clawbackSignalFactsSchema.safeParse({
    verdict: row.signalVerdict,
    level: row.signalLevel,
    hardBlocks: Array.isArray(row.signalHardBlocks) ? row.signalHardBlocks : [],
  });
  return parsed.success ? parsed.data : null;
}

/** The target row of one matched copy as materialization writes it. */
interface TargetPlan {
  copy: MatchedCopy;
  status: 'matched' | 'skipped' | 'simulated';
  reasonCode: string | null;
  plannedAction: RemediationAction | null;
}

/** Counts of a clawback's targets (C5.2, C5.5). */
export interface TargetCounts {
  total: number;
  mailboxes: number;
  eligible: number;
  mailboxesEligible: number;
  byStatus: Record<string, number>;
}

type QueueResult = 'queued' | 'skipped' | 'simulated' | 'capped';

/** A policy decision of one target (C3.2) — or why it is skipped. */
type PolicyPlan =
  | { kind: 'skip'; reason: string }
  | { kind: 'simulate'; action: RemediationAction }
  | {
      kind: 'act';
      action: RemediationAction;
      record: ReturnType<typeof buildDecisionRecord> | null;
    };

/**
 * The `clawback` role (step API-3, note 37 C1, C3–C7; ADR-0103). Every
 * `API_MODE_CLAWBACK_TICK_MS` it claims due clawbacks (`claimClawbacks`: `FOR UPDATE SKIP LOCKED`,
 * leases, CAS on `row_version` for its own transitions) and, per clawback:
 *
 * - **materializes** a `searching` clawback (C4.2/C4.3): indexed lookups bounded by the window,
 *   `too_broad` above `API_MODE_CLAWBACK_MAX_TARGETS`, `no_match` for none, else targets in pages
 *   of 1 000 `INSERT IGNORE`s with their preliminary eligibility (C5.2); automatic clawbacks are
 *   planned through the remediation policy at once (C3.2, C5.3) and go to `queued`, or to
 *   `review_required` (above `auto_max_mailboxes`, or `auto_clawback = review`) with the
 *   `api_mode_purge_approval` alert; admin, campaign and report clawbacks go to `ready`;
 * - **queues** targets of `queued`/`running` clawbacks (C5.4): per target one transaction (copy
 *   row locked first, R5.2), re-plan, `INSERT IGNORE` or re-arm the action row
 *   (`trigger = clawback` / `purge`, `clawback_id`) — never more than
 *   `API_MODE_CLAWBACK_MAX_PENDING_PER_CONNECTION` pending clawback/purge actions per connection;
 * - **reconciles** (C5.5) targets from their terminal actions, counts, `completed` /
 *   `completed_with_errors` with the system audit `api_mode.clawback_completed`;
 * - **cancels** (C5.6) on `cancel_requested_at`, **restores** in bulk (C7, `ClawbackRestorer`) and
 *   **expires** pending approvals (C6).
 *
 * It never calls a provider (C-I1): the `remediate` role executes every action row. Tenant from
 * the clawback row; every read echo-checked; content-free (ids, codes, hashes).
 */
export class ClawbackRunner {
  private readonly txPrisma: PrismaClient;
  readonly restorer: ClawbackRestorer;

  constructor(private readonly deps: ClawbackDeps) {
    this.txPrisma = withTransactionDefaults(deps.prisma, {
      timeoutMs: TX_TIMEOUT_MS,
      maxWaitMs: TX_MAX_WAIT_MS,
    });
    this.restorer = new ClawbackRestorer({
      prisma: deps.prisma,
      counters: deps.counters,
      metrics: deps.metrics,
      logger: deps.logger,
      now: deps.now,
      bounds: deps.config.bounds,
      batch: deps.config.queueBatch,
    });
  }

  /** One pass: approvals expired, then the claimed clawbacks; true when more work is due. */
  async tick(): Promise<boolean> {
    await this.expireApprovals();
    const claimed = await claimClawbacks(this.deps.prisma, {
      now: this.deps.now(),
      batch: CLAIM_BATCH,
      leaseSeconds: this.deps.config.leaseSeconds,
      ...(this.deps.organizationIds ? { organizationIds: this.deps.organizationIds } : {}),
    });
    for (const claim of claimed) {
      try {
        await this.process(claim);
      } catch (error) {
        this.deps.logger.warn(
          { clawbackId: claim.id.toString(), ...errorFields(error) },
          'clawback step not completed; retried after the lease',
        );
        await this.deps.prisma.$executeRaw`
          UPDATE api_clawbacks SET last_error_code = ${errorCode(error, 'internal_error').slice(0, 64)}
          WHERE id = ${claim.id} AND lease_until = ${claim.leaseUntil}`.catch(() => undefined);
      }
    }
    return claimed.length >= CLAIM_BATCH;
  }

  /** Runs every due step of one claimed clawback, then releases the lease. */
  async process(claim: ClaimedClawback): Promise<void> {
    let row = await this.load(claim);
    if (!row) return;
    const cancellable = (CANCELLABLE_STATUSES as readonly string[]).includes(row.status);
    if (row.cancelRequestedAt !== null && cancellable) {
      await this.cancel(claim, row);
    } else if (row.status === 'searching') {
      await this.materialize(claim, row);
    } else if (row.status === 'queued' || row.status === 'running') {
      await this.queue(claim, row);
      row = (await this.load(claim)) ?? row;
      await this.reconcile(claim, row);
    }
    row = (await this.load(claim)) ?? row;
    if (row.restoreStatus === 'requested' || row.restoreStatus === 'running') {
      await this.restorer.run(claim, row, (set, extra) => this.transition(claim, set, extra));
      row = (await this.load(claim)) ?? row;
    }
    const busy =
      row.status === 'searching' ||
      row.status === 'queued' ||
      row.status === 'running' ||
      row.restoreStatus === 'requested' ||
      row.restoreStatus === 'running';
    const now = this.deps.now();
    await releaseClawback(
      this.deps.prisma,
      claim,
      busy ? new Date(now.getTime() + this.deps.config.tickMs) : null,
    );
  }

  private async load(claim: ClaimedClawback): Promise<ClawbackRow | null> {
    const row = await this.deps.prisma.apiClawback.findUnique({
      where: { id: claim.id },
      select: CLAWBACK_SELECT,
    });
    if (!row) return null;
    if (row.organizationId !== claim.organizationId) {
      throw new InconsistentReadError('api_clawbacks');
    }
    claim.rowVersion = row.rowVersion;
    return row;
  }

  /**
   * A state transition of a claimed clawback: CAS on the claimed `row_version` and lease,
   * `row_version + 1`, optional writes in the same transaction. False when the api changed the
   * row meanwhile (re-claimed next tick).
   */
  async transition(
    claim: ClaimedClawback,
    set: Prisma.Sql,
    extra?: (tx: Prisma.TransactionClient) => Promise<void>,
  ): Promise<boolean> {
    const now = this.deps.now();
    const ok = await this.txPrisma
      .$transaction(async (tx) => {
        const n = await tx.$executeRaw`
          UPDATE api_clawbacks SET ${set}, row_version = row_version + 1, updated_at = ${now}
          WHERE id = ${claim.id} AND row_version = ${claim.rowVersion}
            AND lease_until = ${claim.leaseUntil}`;
        if (n !== 1) throw new CasLost();
        if (extra) await extra(tx);
        return true;
      })
      .catch((error: unknown) => {
        if (error instanceof CasLost) return false;
        throw error;
      });
    if (ok) claim.rowVersion += 1;
    return ok;
  }

  // ---------------------------------------------------------------- C4 materialization

  /** C4.2/C4.3, C5.2: the frozen target list of a `searching` clawback. */
  async materialize(claim: ClaimedClawback, row: ClawbackRow): Promise<void> {
    const prisma = this.deps.prisma;
    const now = this.deps.now();
    const parsed = clawbackCriteriaSchema.safeParse(row.criteria);
    // The api validated the window of an admin/campaign/report search (C4.1); re-checked here so
    // no stored document can widen a search beyond the platform bounds. Automatic windows are
    // built by the worker (`[anchor − lookback, now]`).
    const windowInvalid =
      parsed.success &&
      !isAutomatic(row.trigger) &&
      clawbackWindowIssues(parsed.data, {
        now: row.signalAt,
        maxWindowDays: this.deps.config.maxWindowDays,
        fromCampaignSeed: row.trigger === 'campaign',
      }).length > 0;
    if (!parsed.success || windowInvalid) {
      await this.transition(
        claim,
        Prisma.sql`status = 'failed', last_error_code = 'criteria_invalid', completed_at = ${now}`,
      );
      this.deps.metrics?.clawback(row.trigger, 'failed');
      return;
    }
    const search = await searchCopies(prisma, row.organizationId, parsed.data, {
      maxTargets: this.deps.config.maxTargets,
    });
    if (search.kind === 'too_broad' || search.copies.length === 0) {
      const status = search.kind === 'too_broad' ? 'too_broad' : 'no_match';
      await this.transition(
        claim,
        Prisma.sql`status = ${status}, completed_at = ${now}, targets_total = 0,
          mailboxes_total = 0, targets_eligible = 0, mailboxes_eligible = 0`,
      );
      this.deps.metrics?.clawback(row.trigger, status);
      this.deps.logger.info(
        { clawbackId: row.publicId, trigger: row.trigger, status },
        'clawback search finished without targets',
      );
      return;
    }
    const automatic = isAutomatic(row.trigger);
    const settings = await loadOrgSettings(prisma, row.organizationId);
    const facts = storedFacts(row);
    const memo = newDecisionMemo();
    const leaseMs = this.deps.config.leaseSeconds * 1000;
    for (let i = 0; i < search.copies.length; i += MATERIALIZE_PAGE) {
      const page = search.copies.slice(i, i + MATERIALIZE_PAGE);
      const plans = await this.planPage(row, page, {
        automatic,
        facts,
        internalMailEnabled: settings.internalMailEnabled,
        memo,
      });
      await this.insertTargets(row, plans, now);
      const renewed = await renewClawbackLease(
        prisma,
        claim,
        new Date(this.deps.now().getTime() + leaseMs),
      );
      if (!renewed) return;
    }
    const counts = await this.counts(row.id);
    let status: ApiClawbackStatus;
    let reasons: string[] | null = null;
    if (!automatic) {
      status = 'ready';
    } else if (
      settings.autoClawback === 'review' ||
      counts.mailboxesEligible > settings.autoMaxMailboxes
    ) {
      status = 'review_required';
      if (counts.mailboxesEligible > settings.autoMaxMailboxes) reasons = ['auto_cap'];
    } else {
      status = 'queued';
    }
    const done = await this.transition(
      claim,
      Prisma.sql`status = ${status}, ${this.countsSet(counts)},
        approval_reasons = ${reasons === null ? null : JSON.stringify(reasons)},
        last_error_code = NULL`,
      status === 'review_required'
        ? async (tx) => {
            await requestThrottledAlert(tx, {
              organizationId: row.organizationId,
              kind: 'api_mode_purge_approval',
              scopeKey: row.publicId,
              windowMinutes: this.deps.config.approvalTtlHours * 60,
              severity: 'medium',
              refs: { clawbackId: row.publicId },
              correlationId: `api-clawback:${row.publicId}`,
              now,
            });
          }
        : undefined,
    );
    if (!done) return;
    const m = this.deps.metrics;
    m?.clawback(
      row.trigger,
      status === 'queued' ? 'queued' : status === 'ready' ? 'ready' : 'review_required',
    );
    m?.clawbackTarget('matched', counts.byStatus.matched ?? 0);
    m?.clawbackTarget('skipped', counts.byStatus.skipped ?? 0);
    m?.clawbackTarget('simulated', counts.byStatus.simulated ?? 0);
    this.deps.logger.info(
      {
        clawbackId: row.publicId,
        trigger: row.trigger,
        status,
        targets: counts.total,
        eligible: counts.eligible,
        mailboxesEligible: counts.mailboxesEligible,
      },
      'clawback targets materialized',
    );
  }

  /** C5.2 eligibility and (automatic) C3.2/C5.3 planning of one page of matched copies. */
  private async planPage(
    row: ClawbackRow,
    page: readonly MatchedCopy[],
    input: {
      automatic: boolean;
      facts: ClawbackSignalFacts | null;
      internalMailEnabled: boolean;
      memo: DecisionMemo;
    },
  ): Promise<TargetPlan[]> {
    const prisma = this.deps.prisma;
    const org = row.organizationId;
    const mailboxIds = [...new Set(page.map((c) => c.mailboxId))];
    const mailboxes = new Map(
      (
        await prisma.apiMailbox.findMany({
          where: { id: { in: mailboxIds } },
          select: {
            id: true,
            organizationId: true,
            status: true,
            domainId: true,
            reportMailbox: true,
          },
        })
      ).map((m) => {
        if (m.organizationId !== org) throw new InconsistentReadError('api_mailboxes');
        return [m.id, m] as const;
      }),
    );
    const minAt = new Date(Math.min(...page.map((c) => c.receivedAt.getTime())));
    const maxAt = new Date(Math.max(...page.map((c) => c.receivedAt.getTime())));
    const states = await prisma.$queryRaw<
      Array<{
        id: bigint | number;
        received_at: Date;
        organization_id: bigint | number;
        remediation_state: ApiCopyRemediationState;
        remediation_action: RemediationAction | null;
        risk_score: number | null;
        direction: 'inbound' | 'internal';
      }>
    >`
      SELECT id, received_at, organization_id, remediation_state, remediation_action, risk_score,
             direction
      FROM api_message_copies
      WHERE organization_id = ${org} AND id IN (${Prisma.join(page.map((c) => c.id))})
        AND received_at >= ${minAt} AND received_at <= ${maxAt}`;
    const stateOf = new Map(
      states.map((s) => {
        if (big(s.organization_id) !== org) throw new InconsistentReadError('api_message_copies');
        return [`${big(s.id).toString()}:${s.received_at.getTime()}`, s] as const;
      }),
    );
    const plans: TargetPlan[] = [];
    for (const copy of page) {
      const state = stateOf.get(`${copy.id.toString()}:${copy.receivedAt.getTime()}`);
      const mailbox = mailboxes.get(copy.mailboxId);
      if (!state || !mailbox) {
        plans.push({
          copy,
          status: 'skipped',
          reasonCode: 'mailbox_inactive',
          plannedAction: null,
        });
        continue;
      }
      const connection = await connectionFacts(
        prisma,
        { organizationId: org, apiConnectionId: copy.apiConnectionId },
        input.memo,
      );
      const mode = await domainMode(prisma, org, mailbox.domainId, input.memo);
      const eligibility = targetEligibility({
        grantActive: connection.grantActive,
        domainEffectiveMode: mode,
        mailboxStatus: mailbox.status,
        reportMailbox: mailbox.reportMailbox,
      });
      if (!eligibility.eligible) {
        plans.push({
          copy,
          status: 'skipped',
          reasonCode: eligibility.reason,
          plannedAction: null,
        });
        continue;
      }
      if (!input.automatic) {
        // C5.2: the action of an admin/campaign/report clawback is chosen at submit; a copy with
        // an action in flight is not eligible, everything else is re-planned when queued.
        plans.push(
          state.remediation_state === 'pending'
            ? {
                copy,
                status: 'skipped',
                reasonCode: 'remediation_in_progress',
                plannedAction: null,
              }
            : { copy, status: 'matched', reasonCode: null, plannedAction: null },
        );
        continue;
      }
      const effective = await this.deps.policies.effective(prisma, org, mailbox.domainId);
      const decided = this.policyPlan(row, input.facts, {
        copyRiskScore: state.risk_score,
        direction: state.direction,
        context: {
          provider: connection.provider,
          grantActive: connection.grantActive,
          // C5.7: a paused connection does not make a copy ineligible; the row waits in remediate.
          remediationPaused: false,
          domainEffectiveMode: mode,
          mailboxStatus: mailbox.status,
          internalMailEnabled: input.internalMailEnabled,
        },
        effective,
      });
      if (decided.kind === 'skip') {
        plans.push({ copy, status: 'skipped', reasonCode: decided.reason, plannedAction: null });
        continue;
      }
      if (decided.kind === 'simulate') {
        plans.push({
          copy,
          status: 'simulated',
          reasonCode: 'simulated',
          plannedAction: decided.action,
        });
        continue;
      }
      const plan = planClawbackTarget({
        copyState: state.remediation_state,
        copyAction: state.remediation_action,
        lastRestoreCompletedAt:
          state.remediation_state === 'restored'
            ? await this.lastRestoreAt(prisma, org, copy)
            : null,
        signalAt: row.signalAt,
        action: decided.action,
        mode: 'policy',
        hardDeleteEnabled: this.deps.config.hardDeleteEnabled,
      });
      plans.push(
        plan.kind === 'skip'
          ? { copy, status: 'skipped', reasonCode: plan.reason, plannedAction: decided.action }
          : { copy, status: 'matched', reasonCode: null, plannedAction: plan.action },
      );
    }
    return plans;
  }

  /** C3.2: the remediation policy's decision for one target with the signal's facts. */
  private policyPlan(
    row: ClawbackRow,
    facts: ClawbackSignalFacts | null,
    input: {
      copyRiskScore: number | null;
      direction: 'inbound' | 'internal';
      context: RemediationInput['context'];
      effective: Parameters<typeof buildDecisionRecord>[0];
    },
  ): PolicyPlan {
    if (facts === null) return { kind: 'skip', reason: 'policy_none' };
    const remediationInput = clawbackRemediationInput({
      copyRiskScore: input.copyRiskScore,
      direction: input.direction,
      facts,
      context: input.context,
    });
    const decision = decideRemediation(remediationInput, input.effective.policy, {
      hardDeleteEnabled: this.deps.config.hardDeleteEnabled,
    });
    const outcome = clawbackPolicyOutcome(decision);
    if (outcome.kind === 'skip') return { kind: 'skip', reason: outcome.reason };
    if (outcome.kind === 'simulate') return { kind: 'simulate', action: outcome.action };
    return {
      kind: 'act',
      action: outcome.action,
      record: buildDecisionRecord(input.effective, remediationInput, decision, {
        source: 'clawback',
        clawbackId: row.publicId,
      }),
    };
  }

  /** Completion time of the copy's last succeeded reversal (C5.3 restore check). */
  private async lastRestoreAt(
    db: Prisma.TransactionClient | PrismaClient,
    organizationId: bigint,
    copy: { id: bigint; receivedAt: Date },
  ): Promise<Date | null> {
    const rows = await db.$queryRaw<Array<{ at: Date | null }>>`
      SELECT MAX(completed_at) AS at FROM api_remediation_actions
      WHERE organization_id = ${organizationId} AND copy_id = ${copy.id}
        AND copy_received_at = ${copy.receivedAt} AND status = 'succeeded'
        AND action IN ('restore_inbox', 'remove_tag')`;
    return rows[0]?.at ?? null;
  }

  /** One page of targets: `INSERT IGNORE` on UNIQUE (clawback_id, copy_id, copy_received_at). */
  private async insertTargets(row: ClawbackRow, plans: readonly TargetPlan[], now: Date) {
    if (plans.length === 0) return;
    const values = plans.map((p) => {
      const keys = CLAWBACK_MATCH_KEYS.filter((k) => p.copy.matchKeys.has(k));
      return Prisma.sql`(${row.id}, ${row.organizationId}, ${p.copy.apiConnectionId},
        ${p.copy.mailboxId}, ${p.copy.id}, ${p.copy.receivedAt}, ${p.copy.messageId},
        ${JSON.stringify(keys)}, ${p.status}, ${p.reasonCode}, ${p.plannedAction}, 'none', ${now},
        ${now})`;
    });
    await this.deps.prisma.$executeRaw`
      INSERT IGNORE INTO api_clawback_targets
        (clawback_id, organization_id, api_connection_id, mailbox_id, copy_id, copy_received_at,
         message_id, match_keys, status, reason_code, planned_action, restore_status, created_at,
         updated_at)
      VALUES ${Prisma.join(values)}`;
  }

  /** Counts of the clawback's targets by status (C5.2, C5.5). */
  async counts(clawbackId: bigint): Promise<TargetCounts> {
    const rows = await this.deps.prisma.$queryRaw<
      Array<{ status: string; n: bigint | number; mailboxes: bigint | number }>
    >`
      SELECT status, COUNT(*) AS n, COUNT(DISTINCT mailbox_id) AS mailboxes
      FROM api_clawback_targets WHERE clawback_id = ${clawbackId}
      GROUP BY status`;
    const all = await this.deps.prisma.$queryRaw<Array<{ mailboxes: bigint | number }>>`
      SELECT COUNT(DISTINCT mailbox_id) AS mailboxes FROM api_clawback_targets
      WHERE clawback_id = ${clawbackId}`;
    const byStatus: Record<string, number> = {};
    let total = 0;
    let mailboxesEligible = 0;
    for (const r of rows) {
      byStatus[r.status] = Number(r.n);
      total += Number(r.n);
      if (r.status === 'matched') mailboxesEligible = Number(r.mailboxes);
    }
    return {
      total,
      mailboxes: Number(all[0]?.mailboxes ?? 0),
      eligible: byStatus.matched ?? 0,
      mailboxesEligible,
      byStatus,
    };
  }

  /** The materialization counts (`targets_*`, `mailboxes_*`). */
  private countsSet(c: TargetCounts): Prisma.Sql {
    return Prisma.sql`targets_total = ${c.total}, mailboxes_total = ${c.mailboxes},
      targets_eligible = ${c.eligible}, mailboxes_eligible = ${c.mailboxesEligible},
      targets_skipped = ${c.byStatus.skipped ?? 0},
      targets_simulated = ${c.byStatus.simulated ?? 0}`;
  }

  /** The progress counts of C5.5 (queued, succeeded, failed, cancelled + skipped/simulated). */
  private progressSet(c: TargetCounts): Prisma.Sql {
    return Prisma.sql`targets_skipped = ${c.byStatus.skipped ?? 0},
      targets_simulated = ${c.byStatus.simulated ?? 0},
      targets_queued = ${c.byStatus.queued ?? 0},
      targets_succeeded = ${c.byStatus.succeeded ?? 0},
      targets_failed = ${c.byStatus.failed ?? 0},
      targets_cancelled = ${c.byStatus.cancelled ?? 0}`;
  }

  // ---------------------------------------------------------------- C5.4 queueing

  /** C5.4: queues up to `API_MODE_CLAWBACK_QUEUE_BATCH` matched targets of the clawback. */
  async queue(claim: ClaimedClawback, row: ClawbackRow): Promise<number> {
    const prisma = this.deps.prisma;
    const now = this.deps.now();
    if (row.status === 'queued') {
      const moved = await this.transition(
        claim,
        Prisma.sql`status = 'running', started_at = COALESCE(started_at, ${now})`,
      );
      if (!moved) return 0;
      row.status = 'running';
    }
    const cfg = this.deps.config;
    const pending = new Map(
      (
        await prisma.$queryRaw<Array<{ api_connection_id: bigint | number; n: bigint | number }>>`
          SELECT api_connection_id, COUNT(*) AS n FROM api_remediation_actions
          WHERE organization_id = ${row.organizationId} AND status IN ('pending', 'in_progress')
            AND \`trigger\` IN ('clawback', 'purge')
          GROUP BY api_connection_id`
      ).map((r) => [big(r.api_connection_id), Number(r.n)] as const),
    );
    const targets = await prisma.$queryRaw<
      Array<{
        id: bigint | number;
        organization_id: bigint | number;
        api_connection_id: bigint | number;
        mailbox_id: bigint | number;
        copy_id: bigint | number;
        copy_received_at: Date;
        message_id: bigint | number;
      }>
    >`
      SELECT id, organization_id, api_connection_id, mailbox_id, copy_id, copy_received_at,
             message_id
      FROM api_clawback_targets
      WHERE clawback_id = ${row.id} AND status = 'matched'
      ORDER BY id
      LIMIT ${Math.min(cfg.queueBatch * 4, 10_000)}`;
    if (targets.length === 0) return 0;
    const memo = newDecisionMemo();
    const facts = storedFacts(row);
    const queuedPerConnection = new Map<bigint, number>();
    const tally = { queued: 0, skipped: 0, simulated: 0 };
    for (const t of targets) {
      if (tally.queued >= cfg.queueBatch) break;
      if (big(t.organization_id) !== row.organizationId) {
        throw new InconsistentReadError('api_clawback_targets');
      }
      const connectionId = big(t.api_connection_id);
      if ((pending.get(connectionId) ?? 0) >= cfg.maxPendingPerConnection) continue;
      const target = {
        id: big(t.id),
        apiConnectionId: connectionId,
        mailboxId: big(t.mailbox_id),
        copyId: big(t.copy_id),
        copyReceivedAt: t.copy_received_at,
        messageId: big(t.message_id),
      };
      const result = await retryLockConflict(() =>
        this.txPrisma.$transaction((tx) => this.queueTarget(tx, row, target, facts, memo, now)),
      );
      if (result === 'queued') {
        tally.queued += 1;
        pending.set(connectionId, (pending.get(connectionId) ?? 0) + 1);
        queuedPerConnection.set(connectionId, (queuedPerConnection.get(connectionId) ?? 0) + 1);
      } else if (result === 'skipped') {
        tally.skipped += 1;
      } else if (result === 'simulated') {
        tally.simulated += 1;
      }
    }
    for (const [connectionId, n] of queuedPerConnection) {
      await this.deps.counters.add(connectionId, { clawback_targets_queued: n });
    }
    const m = this.deps.metrics;
    m?.clawbackTarget('queued', tally.queued);
    m?.clawbackTarget('skipped', tally.skipped);
    m?.clawbackTarget('simulated', tally.simulated);
    return tally.queued;
  }

  /**
   * One target, in one transaction (C5.4): the copy row is locked first (R5.2 lock order), the
   * target re-planned on the current state, then the action row is inserted, re-armed (an
   * existing `skipped`/`simulated`/`failed`/`cancelled` row of the same `action_key`) or linked
   * (`pending`/`in_progress` → skipped `remediation_in_progress`, `succeeded` →
   * `already_remediated`); the copy becomes `pending` on the action and the target `queued`.
   */
  private async queueTarget(
    tx: Prisma.TransactionClient,
    row: ClawbackRow,
    target: {
      id: bigint;
      apiConnectionId: bigint;
      mailboxId: bigint;
      copyId: bigint;
      copyReceivedAt: Date;
      messageId: bigint;
    },
    facts: ClawbackSignalFacts | null,
    memo: DecisionMemo,
    now: Date,
  ): Promise<QueueResult> {
    const org = row.organizationId;
    const copies = await tx.$queryRaw<
      Array<{
        public_id: string;
        organization_id: bigint | number;
        api_connection_id: bigint | number;
        mailbox_id: bigint | number;
        message_id: bigint | number;
        risk_score: number | null;
        direction: 'inbound' | 'internal';
        remediation_state: ApiCopyRemediationState;
        remediation_action: RemediationAction | null;
        remediation_generation: number;
        verdict_at: Date | null;
      }>
    >`
      SELECT public_id, organization_id, api_connection_id, mailbox_id, message_id, risk_score,
             direction, remediation_state, remediation_action, remediation_generation, verdict_at
      FROM api_message_copies
      WHERE id = ${target.copyId} AND received_at = ${target.copyReceivedAt}
        AND organization_id = ${org}
      FOR UPDATE`;
    const copy = copies[0];
    const skipTarget = async (reason: string, actionId: bigint | null = null) => {
      await tx.$executeRaw`
        UPDATE api_clawback_targets
        SET status = 'skipped', reason_code = ${reason.slice(0, 64)}, action_id = ${actionId},
            updated_at = ${now}
        WHERE id = ${target.id} AND clawback_id = ${row.id} AND status = 'matched'`;
      return 'skipped' as const;
    };
    if (!copy) return skipTarget('out_of_scope');
    if (
      big(copy.mailbox_id) !== target.mailboxId ||
      big(copy.message_id) !== target.messageId ||
      big(copy.api_connection_id) !== target.apiConnectionId
    ) {
      throw new InconsistentReadError('api_message_copies');
    }
    const ctx = await loadDecisionContext(
      tx,
      this.deps.policies,
      { organizationId: org, apiConnectionId: target.apiConnectionId, mailboxId: target.mailboxId },
      memo,
    );
    const eligibility = targetEligibility({
      grantActive: ctx.connection.grantActive,
      domainEffectiveMode: ctx.domainEffectiveMode,
      mailboxStatus: ctx.mailbox.status,
      reportMailbox: ctx.mailbox.reportMailbox,
    });
    if (!eligibility.eligible) return skipTarget(eligibility.reason);

    let action: RemediationAction;
    let decision: unknown;
    const mode = row.decisionMode ?? 'policy';
    if (mode === 'explicit') {
      if (row.action === null) return skipTarget('policy_none');
      action = row.action;
      decision = { requestedAction: action, reason: 'clawback', clawbackId: row.publicId };
    } else {
      const decided = this.policyPlan(row, facts, {
        copyRiskScore: copy.risk_score,
        direction: copy.direction,
        context: {
          provider: ctx.connection.provider,
          grantActive: ctx.connection.grantActive,
          remediationPaused: false,
          domainEffectiveMode: ctx.domainEffectiveMode,
          mailboxStatus: ctx.mailbox.status,
          internalMailEnabled: ctx.internalMailEnabled,
        },
        effective: ctx.effective,
      });
      if (decided.kind === 'skip') return skipTarget(decided.reason);
      if (decided.kind === 'simulate') {
        await tx.$executeRaw`
          UPDATE api_clawback_targets
          SET status = 'simulated', reason_code = 'simulated', planned_action = ${decided.action},
              updated_at = ${now}
          WHERE id = ${target.id} AND clawback_id = ${row.id} AND status = 'matched'`;
        return 'simulated';
      }
      action = decided.action;
      decision = decided.record;
    }
    const plan = planClawbackTarget({
      copyState: copy.remediation_state,
      copyAction: copy.remediation_action,
      lastRestoreCompletedAt:
        copy.remediation_state === 'restored'
          ? await this.lastRestoreAt(tx, org, {
              id: target.copyId,
              receivedAt: target.copyReceivedAt,
            })
          : null,
      signalAt: row.signalAt,
      action,
      mode,
      hardDeleteEnabled: this.deps.config.hardDeleteEnabled,
    });
    if (plan.kind === 'skip') return skipTarget(plan.reason);

    const generation = Number(copy.remediation_generation);
    const actionKey = remediationActionKey(copy.public_id, plan.action, generation);
    const automatic = isAutomatic(row.trigger);
    const trigger = automatic ? 'clawback' : 'purge';
    const requesterId = automatic ? null : (row.submittedByUserId ?? row.requestedByUserId);
    const requesterType = automatic
      ? 'system'
      : requesterId !== null
        ? 'user'
        : row.requestedByType;
    const existing = await tx.$queryRaw<
      Array<{ id: bigint | number; organization_id: bigint | number; status: string }>
    >`
      SELECT id, organization_id, status FROM api_remediation_actions
      WHERE action_key = ${actionKey} FOR UPDATE`;
    let actionId: bigint;
    const prior = existing[0];
    if (prior) {
      if (big(prior.organization_id) !== org) {
        throw new InconsistentReadError('api_remediation_actions');
      }
      actionId = big(prior.id);
      if (prior.status === 'pending' || prior.status === 'in_progress') {
        return skipTarget('remediation_in_progress', actionId);
      }
      if (prior.status === 'succeeded') return skipTarget('already_remediated', actionId);
      // Re-arm (note 36 §14.4 deviation 4): same key, now a clawback/purge request.
      await tx.$executeRaw`
        UPDATE api_remediation_actions
        SET status = 'pending', \`trigger\` = ${trigger}, clawback_id = ${row.id},
            decision = ${JSON.stringify(decision)}, reason_code = NULL, attempts = 0,
            locate_attempts = 0, lease_until = NULL, last_error_code = NULL,
            last_http_status = NULL, provider_refs = NULL, started_at = NULL, completed_at = NULL,
            next_attempt_at = ${now}, requested_by_type = ${requesterType},
            requested_by_user_id = ${requesterId}, request_reason = ${row.requestReason},
            row_version = row_version + 1, updated_at = ${now}
        WHERE id = ${actionId} AND status IN ('skipped', 'simulated', 'failed', 'cancelled')`;
    } else {
      await tx.$executeRaw`
        INSERT INTO api_remediation_actions
          (public_id, organization_id, api_connection_id, mailbox_id, copy_id, copy_received_at,
           message_id, action, generation, action_key, \`trigger\`, status, decision,
           requested_by_type, requested_by_user_id, request_reason, attempts, locate_attempts,
           next_attempt_at, verdict_at, clawback_id, row_version, created_at, updated_at)
        VALUES (${uuidv7(now.getTime())}, ${org}, ${target.apiConnectionId}, ${target.mailboxId},
                ${target.copyId}, ${target.copyReceivedAt}, ${target.messageId}, ${plan.action},
                ${generation}, ${actionKey}, ${trigger}, 'pending', ${JSON.stringify(decision)},
                ${requesterType}, ${requesterId}, ${row.requestReason}, 0, 0, ${now},
                ${copy.verdict_at}, ${row.id}, 1, ${now}, ${now})`;
      const inserted = await tx.$queryRaw<
        Array<{ id: bigint | number; organization_id: bigint | number }>
      >`SELECT id, organization_id FROM api_remediation_actions WHERE action_key = ${actionKey}`;
      if (!inserted[0] || big(inserted[0].organization_id) !== org) {
        throw new InconsistentReadError('api_remediation_actions');
      }
      actionId = big(inserted[0].id);
    }
    await tx.$executeRaw`
      UPDATE api_message_copies
      SET remediation_state = 'pending', remediation_action = ${plan.action},
          last_action_id = ${actionId}, remediation_updated_at = ${now}
      WHERE id = ${target.copyId} AND received_at = ${target.copyReceivedAt}
        AND organization_id = ${org}`;
    await tx.$executeRaw`
      UPDATE api_clawback_targets
      SET status = 'queued', action_id = ${actionId}, planned_action = ${plan.action},
          reason_code = NULL, updated_at = ${now}
      WHERE id = ${target.id} AND clawback_id = ${row.id} AND status = 'matched'`;
    return 'queued';
  }

  // ---------------------------------------------------------------- C5.5 reconcile

  /**
   * C5.5: targets `queued` whose action is terminal → `succeeded` (incl. `already_in_target`),
   * `failed` (the action's reason code) or `cancelled`; counts; no `queued`/`matched` target left
   * → `completed` / `completed_with_errors` with one system audit row
   * `api_mode.clawback_completed`. Counters `clawback_targets_succeeded` / `_failed`.
   */
  async reconcile(claim: ClaimedClawback, row: ClawbackRow): Promise<void> {
    await this.reconcileTargets(row);
    const counts = await this.counts(row.id);
    const open = (counts.byStatus.queued ?? 0) + (counts.byStatus.matched ?? 0);
    if (open > 0 || (row.status !== 'running' && row.status !== 'queued')) {
      await this.deps.prisma.$executeRaw`
        UPDATE api_clawbacks SET ${this.progressSet(counts)}, updated_at = ${this.deps.now()}
        WHERE id = ${row.id} AND row_version = ${claim.rowVersion}
          AND lease_until = ${claim.leaseUntil}`;
      return;
    }
    const now = this.deps.now();
    const failed = counts.byStatus.failed ?? 0;
    const status = failed > 0 ? 'completed_with_errors' : 'completed';
    const done = await this.transition(
      claim,
      Prisma.sql`status = ${status}, ${this.progressSet(counts)}, completed_at = ${now}`,
      (tx) =>
        systemAudit(tx, {
          organizationId: row.organizationId,
          action: 'api_mode.clawback_completed',
          resourceType: 'api_clawback',
          resourceId: row.publicId,
          correlationId: `api-clawback:${row.publicId}`,
          metadata: {
            clawbackId: row.publicId,
            trigger: row.trigger,
            status,
            counts: {
              total: counts.total,
              skipped: counts.byStatus.skipped ?? 0,
              simulated: counts.byStatus.simulated ?? 0,
              succeeded: counts.byStatus.succeeded ?? 0,
              failed,
              cancelled: counts.byStatus.cancelled ?? 0,
            },
          },
        }),
    );
    if (!done) return;
    this.deps.metrics?.clawback(row.trigger, status);
    this.deps.logger.info(
      { clawbackId: row.publicId, trigger: row.trigger, status },
      'clawback completed',
    );
  }

  /** Targets `queued` whose action reached a terminal status take that outcome. */
  private async reconcileTargets(row: ClawbackRow): Promise<void> {
    const prisma = this.deps.prisma;
    const now = this.deps.now();
    for (let pass = 0; pass < 20; pass++) {
      const rows = await prisma.$queryRaw<
        Array<{
          id: bigint | number;
          api_connection_id: bigint | number;
          a_status: string | null;
          a_reason: string | null;
          a_org: bigint | number | null;
        }>
      >`
        SELECT t.id, t.api_connection_id, a.status AS a_status, a.reason_code AS a_reason,
               a.organization_id AS a_org
        FROM api_clawback_targets t
        LEFT JOIN api_remediation_actions a ON a.id = t.action_id
        WHERE t.clawback_id = ${row.id} AND t.status = 'queued'
          AND (a.id IS NULL OR a.status IN (${Prisma.join(TERMINAL_ACTION_STATUSES)}))
        ORDER BY t.id
        LIMIT 1000`;
      if (rows.length === 0) return;
      const groups = new Map<string, bigint[]>();
      const counters = new Map<bigint, CounterDelta>();
      const tally = { succeeded: 0, failed: 0, cancelled: 0 };
      for (const r of rows) {
        if (r.a_org !== null && big(r.a_org) !== row.organizationId) {
          throw new InconsistentReadError('api_remediation_actions');
        }
        const status =
          r.a_status === 'succeeded'
            ? 'succeeded'
            : r.a_status === 'failed'
              ? 'failed'
              : r.a_status === null
                ? 'failed'
                : 'cancelled';
        const reason = r.a_status === null ? 'internal_error' : r.a_reason;
        const key = `${status}\u0000${reason ?? ''}`;
        const list = groups.get(key) ?? [];
        list.push(big(r.id));
        groups.set(key, list);
        tally[status] += 1;
        if (status !== 'cancelled') {
          const connection = big(r.api_connection_id);
          const delta = counters.get(connection) ?? {};
          const field =
            status === 'succeeded' ? 'clawback_targets_succeeded' : 'clawback_targets_failed';
          delta[field] = (delta[field] ?? 0) + 1;
          counters.set(connection, delta);
        }
      }
      for (const [key, ids] of groups) {
        const [status, reason] = key.split('\u0000') as [string, string];
        await prisma.$executeRaw`
          UPDATE api_clawback_targets
          SET status = ${status}, reason_code = ${reason === '' ? null : reason.slice(0, 64)},
              updated_at = ${now}
          WHERE id IN (${Prisma.join(ids)}) AND clawback_id = ${row.id} AND status = 'queued'`;
      }
      for (const [connection, delta] of counters) await this.deps.counters.add(connection, delta);
      const m = this.deps.metrics;
      m?.clawbackTarget('succeeded', tally.succeeded);
      m?.clawbackTarget('failed', tally.failed);
      m?.clawbackTarget('cancelled', tally.cancelled);
      if (rows.length < 1000) return;
    }
  }

  // ---------------------------------------------------------------- C5.6 cancel

  /**
   * C5.6: the api set `cancel_requested_at`. Every `pending` action of the clawback is cancelled
   * (copy row locked first, the copy's state recomputed by the R5.2 rule), unqueued targets
   * become `cancelled`, `in_progress` actions finish (reconciled); once no target is `queued` the
   * clawback is `cancelled` (a pending approval too).
   */
  async cancel(claim: ClaimedClawback, row: ClawbackRow): Promise<void> {
    const prisma = this.deps.prisma;
    const now = this.deps.now();
    const pending = await prisma.apiRemediationAction.findMany({
      where: { clawbackId: row.id, status: 'pending' },
      select: {
        id: true,
        organizationId: true,
        copyId: true,
        copyReceivedAt: true,
        generation: true,
        action: true,
      },
      orderBy: { id: 'asc' },
      take: 2000,
    });
    for (const a of pending) {
      if (a.organizationId !== row.organizationId) {
        throw new InconsistentReadError('api_remediation_actions');
      }
      await retryLockConflict(() =>
        this.txPrisma.$transaction(async (tx) => {
          await tx.$queryRaw`
            SELECT id FROM api_message_copies
            WHERE id = ${a.copyId} AND received_at = ${a.copyReceivedAt}
              AND organization_id = ${a.organizationId}
            FOR UPDATE`;
          const n = await tx.$executeRaw`
            UPDATE api_remediation_actions
            SET status = 'cancelled', completed_at = ${now}, lease_until = NULL,
                next_attempt_at = NULL, row_version = row_version + 1, updated_at = ${now}
            WHERE id = ${a.id} AND status = 'pending'`;
          if (n === 1) {
            await settleCopy(
              tx,
              {
                id: a.id,
                organizationId: a.organizationId,
                copyId: a.copyId,
                copyReceivedAt: a.copyReceivedAt,
                generation: a.generation,
                action: a.action,
              } as ActionRow,
              'cancelled',
              now,
            );
          }
        }),
      );
    }
    await prisma.$executeRaw`
      UPDATE api_clawback_targets SET status = 'cancelled', reason_code = 'cancelled',
        updated_at = ${now}
      WHERE clawback_id = ${row.id} AND status = 'matched'`;
    await this.reconcileTargets(row);
    const counts = await this.counts(row.id);
    if ((counts.byStatus.queued ?? 0) > 0) {
      await prisma.$executeRaw`
        UPDATE api_clawbacks SET ${this.progressSet(counts)}, updated_at = ${now}
        WHERE id = ${row.id} AND row_version = ${claim.rowVersion}
          AND lease_until = ${claim.leaseUntil}`;
      return;
    }
    const done = await this.transition(
      claim,
      Prisma.sql`status = 'cancelled', ${this.progressSet(counts)}, completed_at = ${now},
        approval_status = IF(approval_status = 'pending', 'cancelled', approval_status),
        approval_decided_at = IF(approval_status = 'cancelled' AND approval_decided_at IS NULL,
                                 ${now}, approval_decided_at)`,
    );
    if (done) {
      this.deps.metrics?.clawback(row.trigger, 'cancelled');
      this.deps.logger.info(
        { clawbackId: row.publicId, cancelledActions: pending.length },
        'clawback cancelled',
      );
    }
  }

  // ---------------------------------------------------------------- C6 approval expiry

  /**
   * C6: pending approvals past `approval_expires_at` → approval `expired`, clawback `expired`
   * (CAS on `row_version`, a clawback the api is deciding keeps its state), system audit
   * `api_mode.clawback_expired`.
   */
  async expireApprovals(): Promise<number> {
    const prisma = this.deps.prisma;
    const now = this.deps.now();
    const orgs = this.deps.organizationIds;
    const due = await prisma.apiClawback.findMany({
      where: {
        approvalStatus: 'pending',
        approvalExpiresAt: { lte: now },
        status: 'pending_approval',
        ...(orgs ? { organizationId: { in: [...orgs] } } : {}),
      },
      select: { id: true, publicId: true, organizationId: true, trigger: true, rowVersion: true },
      orderBy: { approvalExpiresAt: 'asc' },
      take: EXPIRY_BATCH,
    });
    let expired = 0;
    for (const c of due) {
      const done = await this.txPrisma.$transaction(async (tx) => {
        const n = await tx.$executeRaw`
          UPDATE api_clawbacks
          SET approval_status = 'expired', status = 'expired', approval_decided_at = ${now},
              completed_at = ${now}, row_version = row_version + 1, updated_at = ${now}
          WHERE id = ${c.id} AND organization_id = ${c.organizationId}
            AND row_version = ${c.rowVersion} AND approval_status = 'pending'
            AND status = 'pending_approval' AND approval_expires_at <= ${now}`;
        if (n !== 1) return false;
        await systemAudit(tx, {
          organizationId: c.organizationId,
          action: 'api_mode.clawback_expired',
          resourceType: 'api_clawback',
          resourceId: c.publicId,
          correlationId: `api-clawback:${c.publicId}`,
          metadata: { clawbackId: c.publicId, trigger: c.trigger },
        });
        return true;
      });
      if (done) {
        expired += 1;
        this.deps.metrics?.clawback(c.trigger, 'expired');
      }
    }
    return expired;
  }
}

/** A clawback CAS that lost against a concurrent write (rolled back, retried next tick). */
class CasLost extends Error {
  constructor() {
    super('clawback row changed');
    this.name = 'CasLost';
  }
}
