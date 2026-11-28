import {
  lifecycleOutcome,
  type LifecycleOutcome,
  type PerRecipientEvaluation,
} from '@email-gateway/policy-dsl';

/** The lifecycle outcome of a round (step 5.2 P18, step 5.3 Q5: `policy_partial`, `partial`). */
export interface RoundOutcome {
  edge: 'E10' | 'E11' | 'E12' | 'E13';
  to: LifecycleOutcome['to'];
  reason: LifecycleOutcome['reason'] | 'policy_partial';
  finalAction: LifecycleOutcome['finalAction'];
}

/**
 * The Q5 lifecycle mapping: not split → the P18 edge of the lifecycle disposition (the uniform
 * disposition of every recipient); split → E10 `policy_partial` when a recipient is allowed,
 * else E11 when one is quarantined, else E12; `final_action = partial` for every split.
 *
 * Moved unchanged from `apps/policy-engine` (step API-4 A2): the policy-engine applies the edge;
 * a detect evaluation of an API-mode copy only records `finalAction` (never applied).
 */
export function roundOutcome(
  evaluation: PerRecipientEvaluation,
  direction: 'inbound' | 'outbound' | 'internal',
): RoundOutcome {
  if (!evaluation.split) {
    const representative = evaluation.recipients?.[0]?.result ?? evaluation.message;
    return lifecycleOutcome(
      { disposition: evaluation.lifecycleDisposition, actions: representative.actions },
      direction,
    );
  }
  switch (evaluation.lifecycleDisposition) {
    case 'allow':
      return { edge: 'E10', to: 'approved', reason: 'policy_partial', finalAction: 'partial' };
    case 'quarantine':
      return {
        edge: 'E11',
        to: 'quarantined',
        reason: 'policy_quarantine',
        finalAction: 'partial',
      };
    default:
      return { edge: 'E12', to: 'held_for_review', reason: 'policy_hold', finalAction: 'partial' };
  }
}
