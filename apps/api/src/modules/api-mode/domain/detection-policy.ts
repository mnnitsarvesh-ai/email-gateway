import {
  type PostDeliveryEntry,
  postDeliveryStatusOf,
  POST_DELIVERY_EFFECTS,
  type PostDeliveryEffect,
  remediationDecisionRecordSchema,
} from '@email-gateway/mailbox-api';
import {
  evaluationViewOf,
  type SelectedEvaluationRow,
} from '../../policies/domain/evaluation-view';
import type { DetectionPolicyView } from '../dto/api-mode.schemas';

/**
 * Step API-4 (docs/plan/steps/38-api-mode-parity-onboarding.md A12): the detect-mode evaluation
 * of a copy's registry message as the detections detail shows it — the stored row through the
 * policies module's one mapping (`evaluationViewOf`), its actions with their stored statuses and
 * the A5 post-delivery reason, and the decision record's `postDelivery` list (`/2` records only;
 * empty for `/1`, manual or missing decisions). Pure; null when the stored row does not form a
 * valid view.
 */
export function detectionPolicyView(
  row: SelectedEvaluationRow & { id: bigint },
  decision: unknown,
): DetectionPolicyView | null {
  const view = evaluationViewOf(row);
  if (view === null) return null;
  const direction = view.direction;
  const record = remediationDecisionRecordSchema.safeParse(decision);
  const postDelivery: PostDeliveryEntry[] =
    record.success && record.data.v === 2 ? record.data.postDelivery : [];
  const decisiveRuleRef =
    view.decisive.policyPublicId !== null &&
    view.decisive.versionNo !== null &&
    view.decisive.ruleId !== null
      ? `${view.decisive.policyPublicId}#${view.decisive.versionNo}/${view.decisive.ruleId}`
      : null;
  return {
    evaluationId: row.id.toString(),
    evaluationMode: 'detect',
    disposition: view.disposition,
    decisionSource: view.decisive.source,
    decisiveRuleRef,
    overrideApplied: view.override !== null,
    matchedRules: view.matchedRules.map((m) => ({ ruleRef: m.ref, actions: [...m.actionTypes] })),
    actions: view.actions.map((a, i) => ({
      type: a.type,
      status: view.actionStatuses[i] ?? 'recorded',
      reason: (POST_DELIVERY_EFFECTS as readonly string[]).includes(a.type)
        ? postDeliveryStatusOf(a.type as PostDeliveryEffect, direction).reason
        : null,
    })),
    explanation: view.explanation.text,
    postDelivery: postDelivery.map((p) => ({ type: p.type, status: p.status, reason: p.reason })),
    evaluatedAt: new Date(view.evaluatedAt).toISOString(),
  };
}
