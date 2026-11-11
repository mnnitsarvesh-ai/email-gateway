import { type PolicyEvaluationView, rowToEvaluationView } from '@email-gateway/policy-dsl';

/** The stored evaluation columns the api selects (internal ids are never selected). */
export type SelectedEvaluationRow = Omit<
  Parameters<typeof rowToEvaluationView>[0],
  'decisivePolicyVersionId' | 'matchedPolicyVersionIds' | 'objectKey'
>;

/**
 * A stored `policy_execution_logs` row → the api view (P10, P16) through the library's one
 * mapping. The api never selects `decisive_policy_version_id`, `matched_policy_version_ids` or
 * `object_key` (internal ids and the S3 key); `rowToEvaluationView` does not read them either.
 * Returns null for a row whose JSON does not form a valid view (the engine validates on write).
 */
export function evaluationViewOf(row: SelectedEvaluationRow): PolicyEvaluationView | null {
  try {
    return rowToEvaluationView({
      ...row,
      decisivePolicyVersionId: null,
      matchedPolicyVersionIds: [],
      objectKey: null,
    });
  } catch {
    return null;
  }
}
