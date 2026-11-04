import { Injectable } from '@nestjs/common';
import { type Counter, MetricsService } from '@email-gateway/common';
import type { LifecycleMetrics } from '@email-gateway/message-lifecycle';
import type { LifecycleOperation } from './domain/lifecycle-operations';

/** `outcome` of `api_message_lifecycle_operations_total` (L10.1). */
export type OperationOutcome =
  'applied' | 'replayed' | 'conflict' | 'not_found' | 'invalid_request';

/**
 * The api's lifecycle series (step 3.3 L5.5, L10.1) on its registry (`GET /metrics`): the shared
 * transition-service series (same names as in every deployable, `service="api"`) and
 * `api_message_lifecycle_operations_total{operation,outcome}`.
 */
@Injectable()
export class ApiLifecycleMetrics {
  readonly operations: Counter<'operation' | 'outcome'>;
  private readonly transitionsTotal: Counter<'from' | 'to' | 'result'>;
  private readonly ignoredTotal: Counter<'reason'>;
  private readonly versionConflicts: Counter;
  private readonly derivedSkipped: Counter<'state'>;

  constructor(metrics: MetricsService) {
    this.operations = metrics.counter(
      'api_message_lifecycle_operations_total',
      'Administrative lifecycle operations (rescan, release) by outcome (applied, replayed, conflict, not_found, invalid_request)',
      ['operation', 'outcome'],
    );
    this.transitionsTotal = metrics.counter(
      'lifecycle_transitions_total',
      'Message lifecycle transition requests by current state, target and result (applied, duplicate, stale, invalid)',
      ['from', 'to', 'result'],
    );
    this.ignoredTotal = metrics.counter(
      'lifecycle_transitions_ignored_total',
      'Stale or invalid lifecycle transition requests by reason (older_round, version_mismatch, overtaken, final_state, edge_not_allowed, actor_not_allowed, reason_not_allowed, unexpected_from, future_round)',
      ['reason'],
    );
    this.versionConflicts = metrics.counter(
      'lifecycle_version_conflicts_total',
      'Lifecycle transactions retried after a compare-and-set conflict, deadlock, lock wait timeout or concurrent duplicate',
    );
    this.derivedSkipped = metrics.counter(
      'lifecycle_derived_skipped_total',
      'Derived delivery states not applied because the message is outside the delivery phase, by its state',
      ['state'],
    );
  }

  operation(operation: LifecycleOperation, outcome: OperationOutcome): void {
    this.operations.inc({ operation, outcome });
  }

  /** The transition service's metrics interface on the api registry. */
  get transitions(): LifecycleMetrics {
    return {
      transition: (from, to, result) => this.transitionsTotal.inc({ from, to, result }),
      ignored: (reason) => this.ignoredTotal.inc({ reason }),
      versionConflict: () => this.versionConflicts.inc(),
      derivedSkipped: (state) => this.derivedSkipped.inc({ state }),
    };
  }
}
