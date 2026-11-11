import type { RiskAction } from '@email-gateway/risk-scoring';
import type { PolicyInput, RiskFacts } from './input';
import type { PlatformDefault } from './platform';
import { POLICY_FLOOR_CODES, type PolicyFloorCode } from './reason-codes';
import { dispositionRank, stricterDisposition, type PolicyDisposition } from './vocabulary';

/**
 * The strictness floor (step 5.2 P9 step 5, §2.0 invariant 2; ADR-0043 decision 5; contract
 * §27 "Binding for policy 5.2"). Mandatory and never configurable: no setting, rule, exception
 * or override reaches this module, and the evaluator applies `applyFloor` after the tenant
 * rules on every path. The floor is computed from the facts only:
 *
 * - each present risk revision that is **not** level-only contributes its whole recommended
 *   action (hard blocks, failures, unknown engines, missing child rows, scoring error rows);
 * - the DLP binding of ADR-0037 (a DLP row of the round, or a definite DLP final without its
 *   row → quarantine);
 * - a scanned/scan-failed round without its revision-0 risk row → quarantine;
 * - a scan-failed round → at least quarantine; a parse failure → quarantine.
 *
 * Revision 1 joins by maximum only, so it can only raise the floor.
 */

export interface FloorReason {
  code: PolicyFloorCode;
  disposition: PolicyDisposition;
}

export interface Floor {
  /** Strictest floor disposition; null when nothing applies. */
  disposition: PolicyDisposition | null;
  /** Mandatory TAG labels (unknown-engine `tag` floor, DLP `alert`), sorted. */
  tagLabels: string[];
  /** Every floor reason with its own disposition, in `POLICY_FLOOR_CODES` order. */
  reasons: FloorReason[];
}

const ENGINE_FAILURE_STATUSES = new Set<string>(['timeout', 'error', 'missing', 'row_missing']);

/** The disposition a risk action maps to under the platform default (P9.4). */
export const mapRiskAction = (pd: PlatformDefault, action: RiskAction): PolicyDisposition =>
  pd.riskActionMap[action];

/** Floor reasons of one non-level-only revision (its whole recommendation binds). */
function revisionReasons(pd: PlatformDefault, r: RiskFacts): FloorReason[] {
  const whole = mapRiskAction(pd, r.recommendedAction);
  const out: FloorReason[] = [];
  if (r.hardBlocks.length > 0) {
    let strictest: PolicyDisposition = 'allow';
    for (const h of r.hardBlocks) {
      strictest = stricterDisposition(strictest, mapRiskAction(pd, h.action))!;
    }
    out.push({ code: 'policy.floor.hard_block', disposition: strictest });
  }
  if (r.status === 'error') out.push({ code: 'policy.floor.risk_error', disposition: whole });
  const engineFailure =
    r.failureStatuses.some((s) => ENGINE_FAILURE_STATUSES.has(s)) ||
    r.reasonCodes.some((c) => c.startsWith('risk.input.'));
  if (engineFailure) out.push({ code: 'policy.floor.engine_failure', disposition: whole });
  const unknownEngine = r.failureStatuses.includes('unknown');
  if (unknownEngine) out.push({ code: 'policy.floor.unknown_engine', disposition: whole });
  // A revision that is not level-only for a reason without a code (defence in depth): its whole
  // recommendation still binds, recorded as an engine failure.
  if (out.length === 0) out.push({ code: 'policy.floor.engine_failure', disposition: whole });
  return out;
}

/** Computes the floor of an input (P9 step 5). Pure; never reads settings or rules. */
export function computeFloor(input: PolicyInput, pd: PlatformDefault): Floor {
  const reasons: FloorReason[] = [];
  const tags = new Set<string>();
  for (const r of [input.risk.rev0, input.risk.rev1]) {
    if (r === null || r.levelOnly) continue;
    reasons.push(...revisionReasons(pd, r));
    if (pd.riskTagActions.includes(r.recommendedAction)) tags.add(`${pd.riskTagPrefix}${r.level}`);
  }
  if (input.dlp !== null) {
    const binding = pd.dlpBinding[input.dlp.action];
    if (binding !== null) {
      reasons.push({
        code: `policy.floor.dlp_${input.dlp.action}` as PolicyFloorCode,
        disposition: binding,
      });
      if (pd.dlpTagActions.includes(input.dlp.action)) tags.add(pd.dlpTagLabel);
    }
  } else if (input.dlpFinal === 'definite') {
    reasons.push({ code: 'policy.floor.dlp_missing', disposition: pd.dlpMissing });
  }
  if (input.trigger !== 'parse_failed' && input.risk.rev0 === null) {
    reasons.push({ code: 'policy.floor.risk_missing', disposition: pd.riskMissing });
  }
  if (input.trigger === 'scan_failed') {
    reasons.push({ code: 'policy.floor.scan_failed', disposition: pd.scanFailed });
  }
  if (input.trigger === 'parse_failed') {
    reasons.push({ code: 'policy.floor.not_scanned', disposition: pd.notScanned });
  }
  // One entry per code (the strictest), in catalog order.
  const byCode = new Map<PolicyFloorCode, PolicyDisposition>();
  for (const r of reasons) {
    byCode.set(r.code, stricterDisposition(byCode.get(r.code) ?? null, r.disposition)!);
  }
  const merged = POLICY_FLOOR_CODES.filter((c) => byCode.has(c)).map((code) => ({
    code,
    disposition: byCode.get(code)!,
  }));
  let disposition: PolicyDisposition | null = null;
  for (const r of merged) disposition = stricterDisposition(disposition, r.disposition);
  return { disposition, tagLabels: [...tags].sort(), reasons: merged };
}

/** The decisive floor reason: the strictest, ties broken by catalog order. */
export function decisiveFloorReason(floor: Floor): FloorReason | null {
  let best: FloorReason | null = null;
  for (const r of floor.reasons) {
    if (best === null || dispositionRank(r.disposition) > dispositionRank(best.disposition))
      best = r;
  }
  return best;
}

/**
 * Applies the floor to a disposition: the result is never weaker than `floor.disposition`.
 * Returns whether the floor raised it.
 */
export function applyFloor(
  disposition: PolicyDisposition,
  floor: Floor,
): { disposition: PolicyDisposition; raised: boolean } {
  if (floor.disposition === null) return { disposition, raised: false };
  if (dispositionRank(floor.disposition) > dispositionRank(disposition)) {
    return { disposition: floor.disposition, raised: true };
  }
  return { disposition, raised: false };
}
