import type { MetricsService } from '@email-gateway/common';
import type { LifecycleMetrics } from '@email-gateway/message-lifecycle';

/**
 * The shared lifecycle series (step 3.3 L5.5, L9) on this deployable's registry, for the
 * transitions the shared delivery recorder applies here (bounce notices derive the message
 * state, L8.5). Same names, help and labels as in every deployable (a contract for
 * `infrastructure/monitoring/rules/lifecycle.rules.yml`). The SMTP commit's creation rows are
 * not transitions of the service and are not counted (L5.2).
 */
export function lifecycleMetrics(metrics: MetricsService): LifecycleMetrics {
  const transitions = metrics.counter(
    'lifecycle_transitions_total',
    'Message lifecycle transition requests by current state, target and result (applied, duplicate, stale, invalid)',
    ['from', 'to', 'result'],
  );
  const ignored = metrics.counter(
    'lifecycle_transitions_ignored_total',
    'Stale or invalid lifecycle transition requests by reason (older_round, version_mismatch, overtaken, final_state, edge_not_allowed, actor_not_allowed, reason_not_allowed, unexpected_from, future_round)',
    ['reason'],
  );
  const conflicts = metrics.counter(
    'lifecycle_version_conflicts_total',
    'Lifecycle transactions retried after a compare-and-set conflict, deadlock, lock wait timeout or concurrent duplicate',
  );
  const derivedSkipped = metrics.counter(
    'lifecycle_derived_skipped_total',
    'Derived delivery states not applied because the message is outside the delivery phase, by its state',
    ['state'],
  );
  return {
    transition: (from, to, result) => transitions.inc({ from, to, result }),
    ignored: (reason) => ignored.inc({ reason }),
    versionConflict: () => conflicts.inc(),
    derivedSkipped: (state) => derivedSkipped.inc({ state }),
  };
}
