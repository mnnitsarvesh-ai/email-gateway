import type {
  PolicyEvaluationResult,
  PolicyEvaluationView,
  PolicyInput,
  RecipientDecision,
} from '@email-gateway/policy-dsl';
import {
  approvalReasonsFor,
  type ApprovalReason,
  hardBlocksOf,
  primaryEngineFor,
  QUARANTINE_RISK_LEVELS,
  type QuarantinePrimaryEngine,
  type QuarantineReason,
  quarantineReasonFor,
} from '@email-gateway/quarantine';

/** `RiskLevel` / `RiskAction` in strictness order (step 5.1; Prisma enums). */
const RISK_LEVELS = QUARANTINE_RISK_LEVELS;
const RISK_ACTIONS = ['deliver', 'tag', 'require_approval', 'quarantine', 'block'] as const;

/** Column bounds of an entry (§3, Q6). */
export const ENTRY_LIMITS = Object.freeze({
  hardBlocks: 9,
  reasonCodes: 32,
  floorReasons: 16,
  explanationLines: 24,
  explanationText: 2048,
});

type RiskLevel = (typeof RISK_LEVELS)[number];
type RiskAction = (typeof RISK_ACTIONS)[number];

/**
 * The decision facts copied onto an entry (Q6): content-free by construction (ids, codes,
 * enums, integers and the evaluator's explanation, P10). Built from the recipient's evaluation
 * result (policy origin) or a stored evaluation row (adoption, Q8).
 */
export interface EntryFacts {
  reason: Exclude<QuarantineReason, 'manual'>;
  primaryEngine: QuarantinePrimaryEngine;
  hardBlocks: string[];
  reasonCodes: string[];
  floorReasons: string[];
  riskScore: number | null;
  riskLevel: RiskLevel | null;
  recommendedAction: RiskAction | null;
  riskVerdict: PolicyEvaluationResult['finalVerdict'] | null;
  decisionSource: PolicyEvaluationResult['decisive']['source'] | null;
  decisivePolicyPublicId: string | null;
  decisivePolicyVersionNo: number | null;
  decisiveRuleId: string | null;
  explanation: PolicyEvaluationResult['explanation']['lines'];
  explanationText: string | null;
  /** Reasons of the `policy_review` request of a review entry (Q6: `['review', …]`). */
  approvalReasons: ApprovalReason[];
}

const maxBy = <T extends string>(
  order: readonly T[],
  values: Array<T | null | undefined>,
): T | null => {
  let best: T | null = null;
  for (const v of values) {
    if (v === null || v === undefined) continue;
    if (best === null || order.indexOf(v) > order.indexOf(best)) best = v;
  }
  return best;
};

/** Q6: the facts of a policy entry from its recipient's result and the round's input. */
export function entryFactsFromResult(
  result: PolicyEvaluationResult,
  input: PolicyInput | null,
  decision: RecipientDecision | null,
  kind: 'quarantine' | 'review',
): EntryFacts {
  const evaluation = { result, input };
  const revisions = [input?.risk.rev0 ?? null, input?.risk.rev1 ?? null].filter(
    (r): r is NonNullable<typeof r> => r !== null,
  );
  const scores = revisions.map((r) => r.score);
  const d = result.decisive;
  return {
    reason: quarantineReasonFor(evaluation, decision),
    primaryEngine: primaryEngineFor(evaluation, decision),
    hardBlocks: hardBlocksOf(evaluation).slice(0, ENTRY_LIMITS.hardBlocks),
    reasonCodes: result.reasonCodes.slice(0, ENTRY_LIMITS.reasonCodes),
    floorReasons: result.floor.reasons.slice(0, ENTRY_LIMITS.floorReasons),
    riskScore: scores.length > 0 ? Math.max(...scores) : result.riskScore,
    riskLevel: maxBy(
      RISK_LEVELS,
      revisions.map((r) => r.level),
    ),
    recommendedAction: maxBy(
      RISK_ACTIONS,
      revisions.map((r) => r.recommendedAction),
    ),
    riskVerdict: result.finalVerdict,
    decisionSource: d.source,
    decisivePolicyPublicId: d.policyPublicId,
    decisivePolicyVersionNo: d.versionNo,
    decisiveRuleId: d.ruleId,
    explanation: result.explanation.lines.slice(0, ENTRY_LIMITS.explanationLines),
    explanationText: result.explanation.text.slice(0, ENTRY_LIMITS.explanationText),
    approvalReasons:
      kind === 'review'
        ? ([
            'review',
            ...approvalReasonsFor(result, input).filter((r) => r !== 'review'),
          ] as ApprovalReason[])
        : [],
  };
}

/** Q8: facts of an adopted entry from the round's stored evaluation view (null = no row). */
export function entryFactsFromView(
  view: PolicyEvaluationView | null,
  kind: 'quarantine' | 'review',
): EntryFacts {
  if (view === null) {
    return {
      reason: 'policy',
      primaryEngine: 'none',
      hardBlocks: [],
      reasonCodes: [],
      floorReasons: [],
      riskScore: null,
      riskLevel: null,
      recommendedAction: null,
      riskVerdict: null,
      decisionSource: null,
      decisivePolicyPublicId: null,
      decisivePolicyVersionNo: null,
      decisiveRuleId: null,
      explanation: [],
      explanationText: null,
      approvalReasons: kind === 'review' ? ['review'] : [],
    };
  }
  const facts = entryFactsFromResult(view, null, null, kind);
  return { ...facts, riskLevel: null, recommendedAction: null };
}
