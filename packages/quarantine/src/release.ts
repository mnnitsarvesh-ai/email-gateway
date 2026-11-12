import {
  computeFloor,
  POLICY_DEFAULT_PLATFORM_ID,
  POLICY_PLATFORM_DEFAULTS,
  type PolicyEvaluationResult,
  type PolicyInput,
} from '@email-gateway/policy-dsl';
import { RISK_ACTIONS, RISK_LEVELS } from '@email-gateway/risk-scoring';
import { hardBlocksOf } from './reasons';
import type { QuarantineSettings } from './settings';
import {
  riskLevelRank,
  type MessageState,
  type QuarantineEntryKind,
  type QuarantineReason,
  type QuarantineReleaseMode,
  type QuarantineRiskLevel,
  type QuarantineState,
} from './vocabulary';

/**
 * Release re-validation (step 5.3 Q13.3–Q13.5, ADR-0047). `decideRelease` is pure: the caller
 * (api pre-check on replica facts, executor on writer facts) evaluates the latest completed scan
 * round with the **current** snapshot for the entry's recipient and passes the result, the
 * staleness facts, the message state, the mode and the tenant settings.
 */

/** Approval reasons (Q13.3), in this order. */
export const APPROVAL_REASONS = [
  'hard_block',
  'engine_failure',
  'risk_error',
  'risk_missing',
  'dlp_require_approval',
  'dlp_quarantine',
  'dlp_block',
  'dlp_missing',
  'scan_failed',
  'not_scanned',
  'policy_reject',
  'review',
  'stale_verdict',
  'no_scan_round',
] as const;
export type ApprovalReason = (typeof APPROVAL_REASONS)[number];

const FLOOR_REASON: Readonly<Record<string, ApprovalReason>> = Object.freeze({
  'policy.floor.hard_block': 'hard_block',
  'policy.floor.engine_failure': 'engine_failure',
  'policy.floor.unknown_engine': 'engine_failure',
  'policy.floor.risk_error': 'risk_error',
  'policy.floor.risk_missing': 'risk_missing',
  'policy.floor.dlp_require_approval': 'dlp_require_approval',
  'policy.floor.dlp_quarantine': 'dlp_quarantine',
  'policy.floor.dlp_block': 'dlp_block',
  'policy.floor.dlp_missing': 'dlp_missing',
  'policy.floor.scan_failed': 'scan_failed',
  'policy.floor.not_scanned': 'not_scanned',
});

const ordered = (reasons: Iterable<ApprovalReason>): ApprovalReason[] => {
  const set = new Set(reasons);
  return APPROVAL_REASONS.filter((r) => set.has(r));
};

/**
 * The approval reasons of a recipient's current result (Q13.3): the floor reasons that hold
 * (a floor reason whose own disposition is `allow` — the unknown-engine `tag` floor, DLP `alert`
 * — is not a reason) and `policy_reject` when the current disposition is reject. With the input,
 * each floor reason's own disposition is known exactly; without it a floor reason counts when
 * the floor as a whole holds.
 */
export function approvalReasonsFor(
  result: Pick<PolicyEvaluationResult, 'floor' | 'disposition' | 'versions'>,
  input?: PolicyInput | null,
): ApprovalReason[] {
  const out: ApprovalReason[] = [];
  if (input) {
    const pd =
      POLICY_PLATFORM_DEFAULTS[result.versions.platformDefault] ??
      POLICY_PLATFORM_DEFAULTS[POLICY_DEFAULT_PLATFORM_ID]!;
    for (const r of computeFloor(input, pd).reasons) {
      const mapped = FLOOR_REASON[r.code];
      if (mapped && r.disposition !== 'allow') out.push(mapped);
    }
  } else if (result.floor.disposition !== null && result.floor.disposition !== 'allow') {
    for (const code of result.floor.reasons) {
      const mapped = FLOOR_REASON[code];
      if (mapped) out.push(mapped);
    }
  }
  if (result.disposition === 'reject') out.push('policy_reject');
  return ordered(out);
}

// ---------------------------------------------------------------------------------------------
// Staleness (Q13.4)
// ---------------------------------------------------------------------------------------------

export const QUARANTINE_RELEASE_MAX_VERDICT_AGE_HOURS = 72;
export const QUARANTINE_RELEASE_SIGNATURE_MAX_LAG_HOURS = 24;

export interface StalenessFacts {
  hasAttachments: boolean;
  hasUrls: boolean;
  /** At least one attachment of the round was scanned by ClamAV. */
  hasScannedAttachments: boolean;
  /** `first_seen_at` of the newest `scan_signature_versions` row of `attachment/clamav_db`. */
  newestClamavDbFirstSeenAt: Date | null;
}

export interface StalenessBounds {
  maxVerdictAgeHours: number;
  signatureMaxLagHours: number;
}

export const DEFAULT_STALENESS_BOUNDS: Readonly<StalenessBounds> = Object.freeze({
  maxVerdictAgeHours: QUARANTINE_RELEASE_MAX_VERDICT_AGE_HOURS,
  signatureMaxLagHours: QUARANTINE_RELEASE_SIGNATURE_MAX_LAG_HOURS,
});

export interface Staleness {
  stale: boolean;
  causes: Array<'verdict_age' | 'signature_lag'>;
  /** Whole hours since the round completed (floor), null without a round. */
  verdictAgeHours: number | null;
  /** Whole hours the newest ClamAV database is newer than the round (floor), or null. */
  signatureLagHours: number | null;
}

const HOUR_MS = 3_600_000;

export function computeStaleness(
  facts: StalenessFacts,
  scanCompletedAt: Date | null,
  now: Date,
  bounds: StalenessBounds = DEFAULT_STALENESS_BOUNDS,
): Staleness {
  if (scanCompletedAt === null) {
    return { stale: false, causes: [], verdictAgeHours: null, signatureLagHours: null };
  }
  const ageMs = now.getTime() - scanCompletedAt.getTime();
  const causes: Staleness['causes'] = [];
  if ((facts.hasAttachments || facts.hasUrls) && ageMs > bounds.maxVerdictAgeHours * HOUR_MS) {
    causes.push('verdict_age');
  }
  const lagMs =
    facts.newestClamavDbFirstSeenAt === null
      ? null
      : facts.newestClamavDbFirstSeenAt.getTime() - scanCompletedAt.getTime();
  if (
    facts.hasScannedAttachments &&
    lagMs !== null &&
    lagMs > bounds.signatureMaxLagHours * HOUR_MS
  ) {
    causes.push('signature_lag');
  }
  return {
    stale: causes.length > 0,
    causes,
    verdictAgeHours: Math.max(0, Math.floor(ageMs / HOUR_MS)),
    signatureLagHours: lagMs === null ? null : Math.floor(lagMs / HOUR_MS),
  };
}

/** Message states from which a rescan (E19) is possible: stale → `rescan_required`. */
export const RESCAN_SOURCE_STATES: readonly MessageState[] = ['quarantined', 'held_for_review'];

// ---------------------------------------------------------------------------------------------
// Lifecycle per message state (Q5, Q13.5)
// ---------------------------------------------------------------------------------------------

export type ReleaseLifecycle =
  | { kind: 'edge'; edge: 'E14' | 'E15' | 'E28'; newRound: true }
  | { kind: 'no_transition' }
  | { kind: 'blocked'; reason: 'message_busy' | 'message_archived' };

/** Q5 "Release by message state". */
export function releaseLifecycleFor(state: MessageState): ReleaseLifecycle {
  switch (state) {
    case 'quarantined':
      return { kind: 'edge', edge: 'E14', newRound: true };
    case 'held_for_review':
      return { kind: 'edge', edge: 'E15', newRound: true };
    case 'approved':
    case 'delivery_pending':
    case 'delivery_retry':
      return { kind: 'no_transition' };
    case 'delivered':
    case 'rejected':
    case 'expired':
      return { kind: 'edge', edge: 'E28', newRound: true };
    case 'archived':
      return { kind: 'blocked', reason: 'message_archived' };
    default:
      return { kind: 'blocked', reason: 'message_busy' };
  }
}

// ---------------------------------------------------------------------------------------------
// decideRelease (Q13.3)
// ---------------------------------------------------------------------------------------------

export interface ReleaseSummary {
  disposition: PolicyEvaluationResult['disposition'];
  source: PolicyEvaluationResult['decisive']['source'];
  decisiveRuleRef: string | null;
  floorReasons: string[];
  hardBlocks: string[];
  level: QuarantineRiskLevel | null;
  score: number | null;
  recommendedAction: string | null;
  generation: string;
  snapshotSha256: string;
  inputSha256: string;
  evaluatorVersion: string;
  scanId: string | null;
  scanCompletedAt: string | null;
}

export interface DecideReleaseInput {
  entry: {
    kind: QuarantineEntryKind;
    reason: QuarantineReason;
    state: QuarantineState;
    /** The entry's stored level (creation time); null without a risk row. */
    riskLevel: QuarantineRiskLevel | null;
  };
  mode: QuarantineReleaseMode;
  /** `mode = approved`: the reasons the approval covered. */
  approvedReasons?: readonly ApprovalReason[];
  messageState: MessageState;
  /** The latest completed scan round; null (adopted entries without one) → `no_scan_round`. */
  scan: { scanId: string | null; completedAt: Date } | null;
  /** The recipient's result under the current snapshot (null without a scan round). */
  result: PolicyEvaluationResult | null;
  /** The input of `result` (exact floor reasons, hard blocks, levels). */
  input?: PolicyInput | null;
  staleness: StalenessFacts;
  now: Date;
  settings: Pick<QuarantineSettings, 'release' | 'endUser'>;
  bounds?: StalenessBounds;
}

export type ReleaseRefusalCode =
  | 'quarantine_hard_block_release_disabled'
  | 'quarantine_self_release_not_allowed'
  | 'quarantine_state_conflict';

export interface ReleaseDecision {
  outcome: 'release' | 'approval_required' | 'rescan_required' | 'refused';
  /** All approval reasons found (for `approval_required` in `approved` mode: the new ones only). */
  approvalReasons: ApprovalReason[];
  refusal?: { code: ReleaseRefusalCode; cause: string };
  staleness: Staleness;
  summary: ReleaseSummary | null;
}

function riskSummary(input: PolicyInput | null | undefined) {
  let level: QuarantineRiskLevel | null = null;
  let action: string | null = null;
  for (const rev of [input?.risk.rev0, input?.risk.rev1]) {
    if (!rev) continue;
    if (level === null || RISK_LEVELS.indexOf(rev.level) > RISK_LEVELS.indexOf(level)) {
      level = rev.level;
    }
    if (
      action === null ||
      RISK_ACTIONS.indexOf(rev.recommendedAction) >
        RISK_ACTIONS.indexOf(action as (typeof RISK_ACTIONS)[number])
    ) {
      action = rev.recommendedAction;
    }
  }
  return { level, action };
}

function summaryOf(input: DecideReleaseInput): ReleaseSummary | null {
  const r = input.result;
  if (r === null || input.scan === null) return null;
  const { level, action } = riskSummary(input.input);
  const d = r.decisive;
  return {
    disposition: r.disposition,
    source: d.source,
    decisiveRuleRef:
      d.source === 'tenant_rule' && d.policyPublicId !== null && d.versionNo !== null && d.ruleId
        ? `${d.policyPublicId}#${d.versionNo}/${d.ruleId}`
        : null,
    floorReasons: [...r.floor.reasons],
    hardBlocks: hardBlocksOf({ result: r, input: input.input ?? null }),
    level,
    score: r.riskScore,
    recommendedAction: action,
    generation: r.versions.generation,
    snapshotSha256: r.versions.snapshotSha256,
    inputSha256: r.inputSha256,
    evaluatorVersion: r.versions.evaluator,
    scanId: input.scan.scanId,
    scanCompletedAt: input.scan.completedAt.toISOString(),
  };
}

/**
 * Q13.3: `release`, `approval_required` (with the reasons), `rescan_required` (stale and the
 * message can be rescanned) or `refused` (hard blocks not releasable by the tenant; self-release
 * not allowed; the entry is not releasable in its state).
 */
export function decideRelease(input: DecideReleaseInput): ReleaseDecision {
  const bounds = input.bounds ?? DEFAULT_STALENESS_BOUNDS;
  const noRound = input.scan === null || input.result === null;
  const staleness = computeStaleness(
    input.staleness,
    noRound ? null : input.scan!.completedAt,
    input.now,
    bounds,
  );
  const summary = summaryOf(input);
  const refuse = (code: ReleaseRefusalCode, cause: string, reasons: ApprovalReason[]) => ({
    outcome: 'refused' as const,
    approvalReasons: reasons,
    refusal: { code, cause },
    staleness,
    summary,
  });

  const expectedState =
    input.mode === 'approved' ? ['pending_approval', 'releasing'] : ['held', 'releasing'];
  if (!expectedState.includes(input.entry.state)) {
    return refuse('quarantine_state_conflict', `state_${input.entry.state}`, []);
  }

  const rescanPossible = RESCAN_SOURCE_STATES.includes(input.messageState);
  const reasons: ApprovalReason[] = [];
  if (noRound) reasons.push('no_scan_round');
  else reasons.push(...approvalReasonsFor(input.result!, input.input));
  if (input.entry.kind === 'review') reasons.push('review');
  if (staleness.stale && !rescanPossible) reasons.push('stale_verdict');
  const all = ordered(reasons);

  // Hard blocks not releasable by tenant setting (every mode).
  if (all.includes('hard_block') && !input.settings.release.allowHardBlocks) {
    return refuse('quarantine_hard_block_release_disabled', 'hard_block', all);
  }

  if (input.mode === 'self') {
    const eu = input.settings.endUser;
    const level = maxLevel(input.entry.riskLevel, summary?.level ?? null);
    const cause = !eu.enabled
      ? 'end_user_disabled'
      : !eu.selfRelease
        ? 'self_release_disabled'
        : !(eu.selfReleaseReasons as readonly string[]).includes(input.entry.reason)
          ? 'reason_not_allowed'
          : level === null
            ? 'level_unknown'
            : riskLevelRank(level) > riskLevelRank(eu.selfReleaseMaxLevel)
              ? 'level_too_high'
              : staleness.stale
                ? 'stale'
                : all.length > 0
                  ? 'approval_required'
                  : null;
    if (cause !== null) return refuse('quarantine_self_release_not_allowed', cause, all);
    return { outcome: 'release', approvalReasons: [], staleness, summary };
  }

  if (staleness.stale && rescanPossible) {
    return { outcome: 'rescan_required', approvalReasons: all, staleness, summary };
  }

  if (input.mode === 'operator') {
    return all.length === 0
      ? { outcome: 'release', approvalReasons: [], staleness, summary }
      : { outcome: 'approval_required', approvalReasons: all, staleness, summary };
  }

  // mode = approved: the approval covers the reasons it saw; new ones need a new approval.
  const covered = new Set(input.approvedReasons ?? []);
  const uncovered = all.filter((r) => !covered.has(r));
  return uncovered.length === 0
    ? { outcome: 'release', approvalReasons: [], staleness, summary }
    : { outcome: 'approval_required', approvalReasons: uncovered, staleness, summary };
}

function maxLevel(
  a: QuarantineRiskLevel | null,
  b: QuarantineRiskLevel | null,
): QuarantineRiskLevel | null {
  if (a === null) return b;
  if (b === null) return a;
  return riskLevelRank(a) >= riskLevelRank(b) ? a : b;
}
