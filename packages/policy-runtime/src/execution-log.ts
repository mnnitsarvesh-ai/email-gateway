import type { Prisma } from '@email-gateway/database';
import type {
  PerRecipientEvaluation,
  PolicyEvaluationRowJson,
  PolicyFinalAction,
  PolicyInput,
} from '@email-gateway/policy-dsl';
import { perRecipientToRowFields } from '@email-gateway/policy-dsl';

/** `policy_execution_logs.duration_us` is an INT UNSIGNED. */
const MAX_DURATION_US = 4_294_967_295;

/** Microseconds of a duration in seconds, clamped to the column. */
export const durationUsOf = (seconds: number): number =>
  Math.min(MAX_DURATION_US, Math.round(seconds * 1e6));

export interface ExecutionLogDataArgs {
  /** The message key (organization from the trusted envelope). */
  key: { messageId: bigint; receivedAt: Date; organizationId: bigint };
  /** `evaluationResultToRow` of the stored result. */
  row: PolicyEvaluationRowJson;
  /** `email_messages.final_action` of the round (the policy-engine's `roundOutcome`). */
  action: PolicyFinalAction;
  evaluation: PerRecipientEvaluation;
  input: PolicyInput;
  durationUs: number;
  evaluatedAt: Date;
}

/**
 * The `policy_execution_logs` create data of one evaluation (step 5.2 §3, step 5.3 Q4 columns,
 * step 8.4 D23 `ato_facts`): the one mapping the policy-engine (inline rows) and the
 * mailbox-worker (detect rows, `detectRowData`) share, so both store exactly the same columns.
 * The `evaluation_mode` column (step API-4) is left to its default (`inline`) here.
 */
export function policyExecutionLogData(
  args: ExecutionLogDataArgs,
): Prisma.PolicyExecutionLogUncheckedCreateInput {
  const { key, row, input } = args;
  const split = perRecipientToRowFields(args.evaluation);
  return {
    receivedAt: key.receivedAt,
    messageId: key.messageId,
    organizationId: key.organizationId,
    evaluationSeq: row.evaluationSeq,
    scanId: row.scanId === null ? null : BigInt(row.scanId),
    trigger: row.trigger,
    direction: row.direction,
    disposition: row.disposition,
    decisionSource: row.decisionSource,
    decisivePolicyVersionId:
      row.decisivePolicyVersionId === null ? null : BigInt(row.decisivePolicyVersionId),
    decisivePolicyPublicId: row.decisivePolicyPublicId,
    decisiveRuleId: row.decisiveRuleId,
    action: args.action,
    finalVerdict: row.finalVerdict,
    riskScore: row.riskScore,
    overrideApplied: row.overrideApplied,
    matchedPolicyVersionIds: row.matchedPolicyVersionIds,
    actions: row.actions,
    matchedRules: row.matchedRules,
    trace: row.trace,
    floor: row.floor,
    recommendation: row.recommendation,
    overrideDetail: row.overrideDetail === null ? undefined : row.overrideDetail,
    clamps: row.clamps,
    reasonCodes: row.reasonCodes,
    delivery: row.delivery === null ? undefined : row.delivery,
    deliveredObject: row.deliveredObject,
    objectKey: row.objectKey,
    explanation: row.explanation,
    explanationText: row.explanationText,
    policyGeneration: BigInt(row.policyGeneration),
    snapshotSha256: row.snapshotSha256,
    policyVersions: row.policyVersions,
    platformDefaultId: row.platformDefaultId,
    dslVersion: row.dslVersion,
    evaluatorVersion: row.evaluatorVersion,
    inputVersion: row.inputVersion,
    inputSha256: row.inputSha256,
    tzdataVersion: row.tzdataVersion,
    durationUs: args.durationUs,
    evaluatedAt: args.evaluatedAt,
    recipientSplit: split.recipientSplit,
    recipientDecisions: split.recipientDecisions === null ? undefined : split.recipientDecisions,
    // Step 8.4 D23: exactly the `ato` block the evaluation used (NULL when absent).
    ...(input.ato !== undefined ? { atoFacts: input.ato } : {}),
  };
}
