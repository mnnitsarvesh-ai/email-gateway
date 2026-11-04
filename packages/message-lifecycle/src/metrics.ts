import type { InvalidReason, StaleReason } from './decide';
import type { MessageState } from './states';

export type TransitionMetricResult = 'applied' | 'duplicate' | 'stale' | 'invalid';

/**
 * Lifecycle series (L5.5, L9), injected; each deployable adapts it to its metrics registry:
 *
 * - `lifecycle_transitions_total{from,to,result}` (`from` = the current state);
 * - `lifecycle_transitions_ignored_total{reason}` (the `why` of stale/invalid);
 * - `lifecycle_version_conflicts_total` (CAS failures and retried deadlocks);
 * - `lifecycle_derived_skipped_total{state}` (a derived delivery state outside the delivery
 *   phase).
 */
export interface LifecycleMetrics {
  transition(from: MessageState, to: MessageState, result: TransitionMetricResult): void;
  ignored(reason: StaleReason | InvalidReason): void;
  versionConflict(): void;
  derivedSkipped(state: MessageState): void;
}

/** Counts nothing (callers without a registry, unit tests). */
export const noopLifecycleMetrics: LifecycleMetrics = {
  transition: () => undefined,
  ignored: () => undefined,
  versionConflict: () => undefined,
  derivedSkipped: () => undefined,
};
