/**
 * Clawback targets (step API-3, design note 37 C3.2, C3.4, C5.2, C5.3): the preliminary
 * eligibility of a matched copy, the policy-mode input and outcome mapping, and the escalation-only
 * planning rule (C-I3). Pure; the mailbox-worker's `clawback` role calls these at materialization
 * and again under the copy-row lock when it queues a target (C5.4).
 */
import type { CopyDirection } from '../classify';
import type { RemediationDecision, RemediationInput } from '../remediation/policy';
import type {
  ApiMailboxStatus,
  CopyRemediationState,
  DomainEffectiveMode,
  RemediationAction,
  RemediationSkipReason,
} from '../remediation/vocabulary';
import type { ClawbackSignalFacts } from './criteria';
import {
  actionStrength,
  type ClawbackDecisionMode,
  type ClawbackEligibilitySkipCode,
  type ClawbackPlanSkipCode,
} from './vocabulary';

// ---------------------------------------------------------------------------------------------
// C5.2 / C3.4 preliminary eligibility
// ---------------------------------------------------------------------------------------------

export interface TargetEligibilityInput {
  /** The connection's `*.mailbox_remediation` grant is `active`. */
  grantActive: boolean;
  domainEffectiveMode: DomainEffectiveMode | null;
  mailboxStatus: ApiMailboxStatus;
  /** `api_mailboxes.report_mailbox`. */
  reportMailbox: boolean;
}

export type TargetEligibility =
  { eligible: true } | { eligible: false; reason: ClawbackEligibilitySkipCode };

/**
 * C5.2 (and C3.4 for explicit mode), in this order: no active grant → `no_mailbox_access`;
 * domain not `api`/`hybrid` → `out_of_scope`; mailbox `disabled`/`deleted` → `mailbox_inactive`;
 * a report mailbox → `report_mailbox`. A paused connection does not make a copy ineligible
 * (automatic rows wait in the `remediate` role; admin purges proceed, C3.4).
 */
export function targetEligibility(input: TargetEligibilityInput): TargetEligibility {
  if (!input.grantActive) return { eligible: false, reason: 'no_mailbox_access' };
  if (input.domainEffectiveMode !== 'api' && input.domainEffectiveMode !== 'hybrid') {
    return { eligible: false, reason: 'out_of_scope' };
  }
  if (input.mailboxStatus === 'disabled' || input.mailboxStatus === 'deleted') {
    return { eligible: false, reason: 'mailbox_inactive' };
  }
  if (input.reportMailbox) return { eligible: false, reason: 'report_mailbox' };
  return { eligible: true };
}

// ---------------------------------------------------------------------------------------------
// C3.2 policy mode
// ---------------------------------------------------------------------------------------------

export interface ClawbackRemediationInputArgs {
  /** The copy's own stored risk score (null when none). */
  copyRiskScore: number | null;
  /** `api_message_copies.direction`. */
  direction: CopyDirection;
  facts: ClawbackSignalFacts;
  /** The copy's real context (grant, pause, domain mode, mailbox status, internal-mail setting). */
  context: RemediationInput['context'];
}

/**
 * C3.2: the `decideRemediation` input of a clawback target: status `scanned`, the signal's
 * verdict, `riskScore = max(copy score, facts score)`, verdict authority `copy` (ADR-0103 (5):
 * the late signal supersedes an inline decision), `risk = { level, hardBlocks }` of the facts,
 * `policyOutcome: null` (PO-D2).
 */
export function clawbackRemediationInput(args: ClawbackRemediationInputArgs): RemediationInput {
  const scores = [args.copyRiskScore, args.facts.score ?? null].filter(
    (s): s is number => typeof s === 'number' && Number.isFinite(s),
  );
  return {
    copy: {
      status: 'scanned',
      verdict: args.facts.verdict,
      riskScore: scores.length > 0 ? Math.max(...scores) : null,
      verdictAuthority: 'copy',
      direction: args.direction,
    },
    risk: { level: args.facts.level, hardBlocks: [...args.facts.hardBlocks] },
    policyOutcome: null,
    context: { ...args.context },
  };
}

export type ClawbackPolicyOutcome =
  | { kind: 'skip'; reason: 'policy_none' | RemediationSkipReason }
  | { kind: 'simulate'; action: RemediationAction; ruleId: string }
  | { kind: 'act'; action: RemediationAction; ruleId: string };

/**
 * C3.2: `none` → skipped `policy_none`; `skip` → skipped with its reason; a simulated act →
 * `simulated`; an act → the planned action (then `planClawbackTarget`).
 */
export function clawbackPolicyOutcome(decision: RemediationDecision): ClawbackPolicyOutcome {
  if (decision.outcome === 'none') return { kind: 'skip', reason: 'policy_none' };
  if (decision.outcome === 'skip') return { kind: 'skip', reason: decision.reason };
  return decision.simulated
    ? { kind: 'simulate', action: decision.action, ruleId: decision.ruleId }
    : { kind: 'act', action: decision.action, ruleId: decision.ruleId };
}

// ---------------------------------------------------------------------------------------------
// C5.3 planning
// ---------------------------------------------------------------------------------------------

export interface PlanClawbackTargetInput {
  /** `api_message_copies.remediation_state`. */
  copyState: CopyRemediationState;
  /** `api_message_copies.remediation_action` (the copy's current remediation). */
  copyAction: RemediationAction | null;
  /** Completion time of the copy's last succeeded restore (null: none known). */
  lastRestoreCompletedAt: Date | null;
  /** `api_clawbacks.signal_at`. */
  signalAt: Date;
  /** The decided (policy mode) or explicit action. */
  action: RemediationAction;
  mode: ClawbackDecisionMode;
  /**
   * `API_MODE_HARD_DELETE_ENABLED` (C3.4). Optional: absent means the caller checks the setting
   * elsewhere (the `remediate` role re-checks a hard delete at execution, C5.7).
   */
  hardDeleteEnabled?: boolean;
}

export type ClawbackTargetPlan =
  { kind: 'act'; action: RemediationAction } | { kind: 'skip'; reason: ClawbackPlanSkipCode };

/**
 * C5.3 (escalation only, C-I3), in this order:
 * 1. a hard delete in policy mode → `hard_delete_not_allowed` (hard delete only in explicit mode);
 *    an explicit hard delete while the platform setting is off → `hard_delete_disabled`;
 * 2. copy `pending` (an action in flight) → `remediation_in_progress`;
 * 3. copy `remediated` with an action of equal or higher strength (or an unknown action) →
 *    `already_remediated`; a weaker one (e.g. `tag`) → act (escalation);
 * 4. copy `restored` whose restore completed after `signal_at` (or at an unknown time) →
 *    `restored_after_signal`; otherwise act;
 * 5. else act.
 */
export function planClawbackTarget(input: PlanClawbackTargetInput): ClawbackTargetPlan {
  if (input.action === 'hard_delete') {
    if (input.mode !== 'explicit') return { kind: 'skip', reason: 'hard_delete_not_allowed' };
    if (input.hardDeleteEnabled === false) return { kind: 'skip', reason: 'hard_delete_disabled' };
  }
  switch (input.copyState) {
    case 'pending':
      return { kind: 'skip', reason: 'remediation_in_progress' };
    case 'remediated':
      if (
        input.copyAction === null ||
        actionStrength(input.copyAction) >= actionStrength(input.action)
      ) {
        return { kind: 'skip', reason: 'already_remediated' };
      }
      return { kind: 'act', action: input.action };
    case 'restored':
      if (
        input.lastRestoreCompletedAt === null ||
        input.lastRestoreCompletedAt.getTime() > input.signalAt.getTime()
      ) {
        return { kind: 'skip', reason: 'restored_after_signal' };
      }
      return { kind: 'act', action: input.action };
    default:
      return { kind: 'act', action: input.action };
  }
}
