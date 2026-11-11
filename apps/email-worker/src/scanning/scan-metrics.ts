import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';
import type { LifecycleMetrics } from '@email-gateway/message-lifecycle';
import { engineCatalogEntry, isStage2Engine } from '@email-gateway/security-contracts';
import { CIRCUIT_STATE_VALUE, type CircuitState } from './circuit-breaker';
import type { FailureMetricReason } from './engine';
import { RiskMetrics } from './risk/risk-metrics';

const ENGINE_BUCKETS = [0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30, 60];
const ROUND_BUCKETS = [0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 900, 1800, 3600];
const LAG_BUCKETS = [0.05, 0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 900, 3600];

/** `scan_events_skipped_total{reason}`: bounded codes (S5 steps 2, 3). */
export type SkipReason =
  | 'message_not_found'
  | 'older_round'
  | 'already_final'
  | 'duplicate'
  /** Step 4.4 B2: a stage event for another stage-2 engine (never expected on a queue). */
  | 'other_stage_engine'
  /** Step 4.4 B2: the stage event names a round that does not exist with its scan id. */
  | 'stage_round_missing'
  | `lifecycle_${string}`;

/**
 * The scan stage series of step 4.1 S17 (a contract for
 * `infrastructure/monitoring/rules/scanning.rules.yml` and docs/runbooks/scan-pipeline.md),
 * registered once on the worker's MetricsService. Labels are bounded enums only: engine names,
 * verdicts, outcomes, reason codes of failures, circuit states, versions; never symbols, symbol
 * options, addresses or ids.
 */
export class ScanMetrics {
  readonly results: Counter<'engine' | 'outcome' | 'final'>;
  readonly engineDuration: Histogram<'engine' | 'outcome'>;
  readonly failures: Counter<'engine' | 'reason'>;
  readonly circuitState: Gauge<'engine'>;
  readonly circuitTransitions: Counter<'engine' | 'to'>;
  readonly rounds: Counter<'outcome' | 'verdict' | 'scan_kind'>;
  readonly roundDuration: Histogram<'outcome'>;
  readonly eventLag: Histogram<'engine'>;
  readonly skipped: Counter<'engine' | 'reason'>;
  readonly superseded: Counter<'engine'>;
  readonly deadlineFinalized: Counter<'engine'>;
  readonly settingsCache: Counter<'result'>;
  readonly settingsInvalid: Counter<'engine'>;
  readonly engineInfo: Gauge<'engine' | 'version'>;
  readonly sweeperErrors: Counter;
  readonly stageTriggers: Counter<'engine'>;
  // The transition service's series (step 3.3 L5.5), shared names with the other writers.
  readonly transitionsTotal: Counter<'from' | 'to' | 'result'>;
  readonly ignoredTotal: Counter<'reason'>;
  readonly versionConflicts: Counter;
  readonly derivedSkipped: Counter<'state'>;
  /** The risk scorer's series (step 5.1 R19), on the same registry. */
  readonly risk: RiskMetrics;
  private readonly versions = new Map<string, string>();

  constructor(metrics: MetricsService) {
    this.results = metrics.counter(
      'scan_engine_results_total',
      'Engine results recorded, by engine, outcome (the seven verdicts) and final (true: the final result of the round; false: a failed attempt that is retried)',
      ['engine', 'outcome', 'final'],
    );
    this.engineDuration = metrics.histogram(
      'scan_engine_duration_seconds',
      'Duration of one engine call (EML stream and scan), by engine and outcome',
      ['engine', 'outcome'],
      ENGINE_BUCKETS,
    );
    this.failures = metrics.counter(
      'scan_engine_failures_total',
      'Engine attempt failures by engine and reason (timeout, error, protocol_error, circuit_open, soft_reject, eml_unavailable, deadline_exceeded)',
      ['engine', 'reason'],
    );
    this.circuitState = metrics.gauge(
      'scan_engine_circuit_state',
      'Circuit breaker state per engine in this worker (0 closed, 1 half-open, 2 open)',
      ['engine'],
    );
    this.circuitTransitions = metrics.counter(
      'scan_engine_circuit_transitions_total',
      'Circuit breaker transitions by engine and target state',
      ['engine', 'to'],
    );
    this.rounds = metrics.counter(
      'scan_rounds_completed_total',
      'Scan rounds completed, by lifecycle outcome (scanned, scan_failed), aggregate verdict and scan kind',
      ['outcome', 'verdict', 'scan_kind'],
    );
    this.roundDuration = metrics.histogram(
      'scan_round_duration_seconds',
      'Duration of a scan round from its opening to its completion, by outcome',
      ['outcome'],
      ROUND_BUCKETS,
    );
    this.eventLag = metrics.histogram(
      'scan_event_lag_seconds',
      'Age of the triggering event (now - occurredAt) when an engine delivery starts (queue lag)',
      ['engine'],
      LAG_BUCKETS,
    );
    this.skipped = metrics.counter(
      'scan_events_skipped_total',
      'Scan deliveries that did nothing, by engine and reason (message_not_found, older_round, lifecycle_<state>, already_final, duplicate, other_stage_engine, stage_round_missing)',
      ['engine', 'reason'],
    );
    this.superseded = metrics.counter(
      'scan_rounds_superseded_total',
      'Rounds completed after a newer round or another state superseded them (no scanned event)',
      ['engine'],
    );
    this.deadlineFinalized = metrics.counter(
      'scan_deadline_finalized_total',
      'Required engines finalized as timeout by the round deadline sweeper, by engine',
      ['engine'],
    );
    this.settingsCache = metrics.counter(
      'scan_settings_cache_total',
      'Tenant scan settings lookups by result (hit, miss)',
      ['result'],
    );
    this.settingsInvalid = metrics.counter(
      'scan_settings_invalid_total',
      'Tenant scan settings rows that failed validation at use (platform settings applied), by engine',
      ['engine'],
    );
    this.engineInfo = metrics.gauge(
      'scan_engine_info',
      'Engine version in use by this worker (value 1)',
      ['engine', 'version'],
    );
    this.sweeperErrors = metrics.counter(
      'scan_deadline_sweeper_errors_total',
      'Database errors of the round deadline sweeper (it backs off and continues)',
    );
    this.stageTriggers = metrics.counter(
      'scan_stage_triggers_total',
      'Stage-2 engine triggers (mail.message.scan_stage_ready.v1 outbox rows) written when the last dependency final of a round was inserted, by triggered engine (step 4.4 B2)',
      ['engine'],
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
    this.risk = RiskMetrics.for(metrics);
  }

  /** The transition service's metrics interface on this registry. */
  get lifecycle(): LifecycleMetrics {
    return {
      transition: (from, to, result) => this.transitionsTotal.inc({ from, to, result }),
      ignored: (reason) => this.ignoredTotal.inc({ reason }),
      versionConflict: () => this.versionConflicts.inc(),
      derivedSkipped: (state) => this.derivedSkipped.inc({ state }),
    };
  }

  /** Zero series for an engine so dashboards and alerts see it before its first result. */
  registerEngine(engine: string): void {
    this.circuitState.set({ engine }, 0);
    this.failures.inc({ engine, reason: 'timeout' }, 0);
    this.failures.inc({ engine, reason: 'error' }, 0);
    this.deadlineFinalized.inc({ engine }, 0);
    const entry = engineCatalogEntry(engine);
    if (entry && isStage2Engine(entry)) this.stageTriggers.inc({ engine }, 0);
  }

  stageTriggered(engine: string): void {
    this.stageTriggers.inc({ engine });
  }

  result(engine: string, outcome: string, final: boolean, seconds: number | null): void {
    this.results.inc({ engine, outcome, final: final ? 'true' : 'false' });
    if (seconds !== null) this.engineDuration.observe({ engine, outcome }, seconds);
  }

  failure(engine: string, reason: FailureMetricReason): void {
    this.failures.inc({ engine, reason });
  }

  circuit(engine: string, to: CircuitState): void {
    this.circuitState.set({ engine }, CIRCUIT_STATE_VALUE[to]);
    this.circuitTransitions.inc({ engine, to });
  }

  /**
   * Records the engine version; returns the previous one when it changed (the caller logs the
   * change at info).
   */
  engineVersion(engine: string, version: string): string | null {
    const previous = this.versions.get(engine);
    if (previous === version) return null;
    if (previous !== undefined) this.engineInfo.remove({ engine, version: previous });
    this.versions.set(engine, version);
    this.engineInfo.set({ engine, version }, 1);
    return previous ?? null;
  }

  skip(engine: string, reason: SkipReason): void {
    this.skipped.inc({ engine, reason });
  }

  round(outcome: string, verdict: string, scanKind: string, seconds: number | null): void {
    this.rounds.inc({ outcome, verdict, scan_kind: scanKind });
    if (seconds !== null) this.roundDuration.observe({ outcome }, Math.max(0, seconds));
  }
}
