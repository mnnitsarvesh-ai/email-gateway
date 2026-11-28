import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';
import type { ApiFamily, IdpMetricsSink } from '@email-gateway/idp-adapters';

/** `api_mode_lag_seconds` buckets (D11.5). */
export const LAG_SECONDS_BUCKETS = [60, 300, 900, 3600, 14_400];

/** `api_mode_remediation_latency_seconds` buckets (step API-2 R14). */
export const REMEDIATION_LATENCY_BUCKETS = [5, 30, 60, 300, 900, 3600];

/** `result` values of `api_mode_remediations_total` (R14). */
export const REMEDIATION_RESULTS = [
  'succeeded',
  'failed',
  'skipped',
  'simulated',
  'cancelled',
  'already_in_target',
] as const;
export type RemediationResult = (typeof REMEDIATION_RESULTS)[number];

/** `outcome` values of `api_mode_remediation_attempts_total` (R14). */
export const REMEDIATION_ATTEMPT_OUTCOMES = ['ok', 'throttled', 'retry', 'error'] as const;
export type RemediationAttemptOutcome = (typeof REMEDIATION_ATTEMPT_OUTCOMES)[number];

/** `result` values of `api_mode_copies_total`. */
export const COPY_RESULTS = [
  'recorded',
  'duplicate',
  'skipped_internal',
  'not_active',
  'no_connection',
  'no_recipient',
  'no_copy',
  'too_large',
  'ingested',
  'already_ingested',
  // Step API-3 (C8, C9.2, C10.4).
  'recorded_internal',
  'outbound_only',
  'report_received',
  'report_scanned',
  // Step API-4 (A6.2): an outbound journal message recorded as a detection on the sender mailbox.
  'outbound_detection',
] as const;
export type CopyResult = (typeof COPY_RESULTS)[number];

/** `result` values of `api_mode_policy_evaluations_total` (step API-4 A3.3). */
export const POLICY_EVALUATION_RESULTS = [
  'evaluated',
  'failed',
  'disabled',
  'inline',
  'not_applicable',
] as const;
export type PolicyEvaluationResult = (typeof POLICY_EVALUATION_RESULTS)[number];

/** `api_mode_policy_evaluation_seconds` buckets (A11). */
export const POLICY_EVALUATION_BUCKETS = [0.01, 0.05, 0.1, 0.5, 1, 5];

/** `kind` values of `api_mode_copy_detections_total` (A11). */
export const COPY_DETECTION_KINDS = ['threat', 'dlp', 'policy'] as const;
export type CopyDetectionKind = (typeof COPY_DETECTION_KINDS)[number];

/** `api_mode_report_triage_seconds` buckets (step API-3 C13). */
export const REPORT_TRIAGE_BUCKETS = [300, 3600, 14_400, 86_400, 259_200];

/** `result` values of `api_mode_late_signals_total` (C2.1). */
export const LATE_SIGNAL_RESULTS = [
  'created',
  'duplicate',
  'not_active',
  'skipped_off',
  'no_message',
] as const;
export type LateSignalResult = (typeof LATE_SIGNAL_RESULTS)[number];

/** `result` values of `api_mode_clawbacks_total` (C13): the state a clawback reached. */
export const CLAWBACK_RESULTS = [
  'created',
  'no_match',
  'too_broad',
  'ready',
  'review_required',
  'queued',
  'completed',
  'completed_with_errors',
  'cancelled',
  'expired',
  'failed',
  'restore_completed',
  'restore_completed_with_errors',
] as const;
export type ClawbackResult = (typeof CLAWBACK_RESULTS)[number];

/** `result` values of `api_mode_clawback_targets_total` (C13). */
export const CLAWBACK_TARGET_RESULTS = [
  'matched',
  'skipped',
  'simulated',
  'queued',
  'succeeded',
  'failed',
  'cancelled',
  'restore_queued',
  'restore_succeeded',
  'restore_failed',
  'restore_skipped',
] as const;
export type ClawbackTargetResult = (typeof CLAWBACK_TARGET_RESULTS)[number];

/** `result` values of `api_mode_reports_total` (C13). */
export const REPORT_RESULTS = [
  'received',
  'rejected',
  'matched',
  'ingested',
  'no_original',
  'pending_triage',
  'scan_timeout',
  'failed',
] as const;
export type ReportResult = (typeof REPORT_RESULTS)[number];

/** Bounded label value: a lower-case code, else `other` (labels never carry free text). */
export const label = (value: string, max = 48): string =>
  /^[a-z0-9_]{1,64}$/.test(value) ? value.slice(0, max) : 'other';

/**
 * The series of the mailbox-worker (design D11.5; contract of
 * `infrastructure/monitoring/rules/api-mode.rules.yml`). Labels are bounded enums only (source,
 * result, provider, family, status class, coverage, health, subscription state): never an
 * organization, connection, mailbox, address or message. Implements the HTTP client's
 * `IdpMetricsSink` for `api_mode_provider_requests_total` / `api_mode_throttled_total`.
 */
export class MailboxMetrics implements IdpMetricsSink {
  readonly copies: Counter<'source' | 'result'>;
  readonly lag: Histogram<'source'>;
  readonly providerRequests: Counter<'provider' | 'family' | 'status_class'>;
  readonly throttledTotal: Counter<'provider' | 'family'>;
  readonly feedSyncs: Counter<'provider' | 'result'>;
  readonly cursorResets: Counter<'provider'>;
  readonly fetchBytes: Counter<'provider'>;
  readonly subscriptions: Gauge<'state'>;
  readonly mailboxes: Gauge<'coverage'>;
  readonly connections: Gauge<'health'>;
  readonly inventoryRuns: Counter<'provider' | 'result'>;
  readonly healthTransitions: Counter<'health'>;
  readonly alerts: Counter<'result'>;
  readonly leader: Gauge<'job'>;
  readonly budgetWaits: Counter<'family'>;
  readonly remediations: Counter<'provider' | 'action' | 'result'>;
  readonly remediationLatency: Histogram<'provider'>;
  readonly remediationBacklog: Gauge<'provider'>;
  readonly remediationOldestPending: Gauge<'provider'>;
  readonly remediationAttempts: Counter<'provider' | 'outcome'>;
  readonly lateSignals: Counter<'kind' | 'result'>;
  readonly clawbacks: Counter<'trigger' | 'result'>;
  readonly clawbackTargets: Counter<'result'>;
  readonly clawbackActive: Gauge<'status'>;
  readonly reports: Counter<'result'>;
  readonly reportsPending: Gauge;
  readonly reportsOldestPending: Gauge;
  readonly reportTriage: Histogram;
  readonly policyEvaluations: Counter<'result'>;
  readonly policyEvaluationSeconds: Histogram;
  readonly policyInconsistentReads: Counter<'read'>;
  readonly copyDetections: Counter<'kind' | 'direction'>;
  readonly outboundDetections: Counter;
  readonly scopeMailboxes: Gauge<'state'>;
  readonly detectOnlyPolicies: Gauge<'then'>;

  constructor(metrics: MetricsService) {
    this.copies = metrics.counter(
      'api_mode_copies_total',
      'API-mode copies by source (journal, graph, gmail) and result (recorded, duplicate, skipped_internal, not_active, no_connection, no_recipient, no_copy, too_large, ingested, already_ingested)',
      ['source', 'result'],
    );
    this.lag = metrics.histogram(
      'api_mode_lag_seconds',
      'Lag from provider delivery to the copy verdict, by source',
      ['source'],
      LAG_SECONDS_BUCKETS,
    );
    this.providerRequests = metrics.counter(
      'api_mode_provider_requests_total',
      'Provider mailbox API requests by provider, API family and status class (2xx, 4xx, 5xx, network)',
      ['provider', 'family', 'status_class'],
    );
    this.throttledTotal = metrics.counter(
      'api_mode_throttled_total',
      'Provider throttling answers (429, Google rate limits, 503 with Retry-After) that paused a connection family',
      ['provider', 'family'],
    );
    this.feedSyncs = metrics.counter(
      'api_mode_feed_syncs_total',
      'Mailbox feed syncs by provider and result (ok, initialized, throttled, error, revoked, skipped)',
      ['provider', 'result'],
    );
    this.cursorResets = metrics.counter(
      'api_mode_cursor_resets_total',
      'Expired mailbox feed cursors re-initialized without backfill, by provider',
      ['provider'],
    );
    this.fetchBytes = metrics.counter(
      'api_mode_fetch_bytes_total',
      'Message bytes fetched from provider mailboxes, by provider',
      ['provider'],
    );
    this.subscriptions = metrics.gauge(
      'api_mode_subscriptions',
      'Graph change-notification subscriptions of feed mailboxes by state (active, expiring, missing)',
      ['state'],
    );
    this.mailboxes = metrics.gauge(
      'api_mode_mailboxes',
      'API-mode mailboxes by coverage state (covered, gap, out_of_scope)',
      ['coverage'],
    );
    this.connections = metrics.gauge(
      'api_mode_connections',
      'API-mode connections by health (unknown, healthy, degraded, failing)',
      ['health'],
    );
    this.inventoryRuns = metrics.counter(
      'api_mode_inventory_runs_total',
      'Mailbox inventory runs by provider and result (ok, failed, unavailable, throttled, limit)',
      ['provider', 'result'],
    );
    this.healthTransitions = metrics.counter(
      'api_mode_health_transitions_total',
      'API-mode connection health transitions by the new health',
      ['health'],
    );
    this.alerts = metrics.counter(
      'api_mode_alerts_total',
      'api_mode_unhealthy alert requests by result (requested, throttled)',
      ['result'],
    );
    this.leader = metrics.gauge(
      'api_mode_leader',
      '1 while this replica holds the leader lock of a job (health)',
      ['job'],
    );
    this.budgetWaits = metrics.counter(
      'api_mode_rate_budget_waits_total',
      'Provider requests that waited for the per-connection rate budget, by API family',
      ['family'],
    );
    this.remediations = metrics.counter(
      'api_mode_remediations_total',
      'API-mode remediation actions by provider, action (move_quarantine, move_junk, tag, soft_delete, hard_delete, restore_inbox, remove_tag) and result (succeeded, failed, skipped, simulated, cancelled, already_in_target)',
      ['provider', 'action', 'result'],
    );
    this.remediationLatency = metrics.histogram(
      'api_mode_remediation_latency_seconds',
      'Time from the copy verdict to a completed policy remediation, by provider',
      ['provider'],
      REMEDIATION_LATENCY_BUCKETS,
    );
    this.remediationBacklog = metrics.gauge(
      'api_mode_remediation_backlog',
      'Pending or in-progress API-mode remediation actions by provider (health leader)',
      ['provider'],
    );
    this.remediationOldestPending = metrics.gauge(
      'api_mode_remediation_oldest_pending_seconds',
      'Age of the oldest pending or in-progress API-mode remediation action by provider (health leader; 0 when none)',
      ['provider'],
    );
    this.remediationAttempts = metrics.counter(
      'api_mode_remediation_attempts_total',
      'Executions of API-mode remediation actions by provider and outcome (ok, throttled, retry, error)',
      ['provider', 'outcome'],
    );
    this.lateSignals = metrics.counter(
      'api_mode_late_signals_total',
      'Late sandbox/URL verdict signals consumed by the copies role, by kind (sandbox_revision, url_dynamic) and result (created, duplicate, not_active, skipped_off, no_message)',
      ['kind', 'result'],
    );
    this.clawbacks = metrics.counter(
      'api_mode_clawbacks_total',
      'API-mode clawbacks by trigger (late_verdict, threat_intel, campaign, report, admin) and the state reached',
      ['trigger', 'result'],
    );
    this.clawbackTargets = metrics.counter(
      'api_mode_clawback_targets_total',
      'API-mode clawback targets by result (matched, skipped, simulated, queued, succeeded, failed, cancelled, restore_*)',
      ['result'],
    );
    this.clawbackActive = metrics.gauge(
      'api_mode_clawback_active',
      'Active API-mode clawbacks by status (searching, ready, review_required, pending_approval, queued, running; health leader)',
      ['status'],
    );
    this.reports = metrics.counter(
      'api_mode_reports_total',
      'User reports handled by the reports role, by result (received, rejected, matched, ingested, no_original, pending_triage, scan_timeout, failed)',
      ['result'],
    );
    this.reportsPending = metrics.gauge(
      'api_mode_reports_pending',
      'User reports pending triage (health leader)',
    );
    this.reportsOldestPending = metrics.gauge(
      'api_mode_reports_oldest_pending_seconds',
      'Age of the oldest user report pending triage (health leader; 0 when none)',
    );
    this.reportTriage = metrics.histogram(
      'api_mode_report_triage_seconds',
      'Time from a user report to the end of its automatic processing (pending_triage)',
      [],
      REPORT_TRIAGE_BUCKETS,
    );
    this.policyEvaluations = metrics.counter(
      'api_mode_policy_evaluations_total',
      'Detect-mode policy evaluations of API-mode copy messages by result (evaluated, failed, disabled, inline, not_applicable)',
      ['result'],
    );
    this.policyEvaluationSeconds = metrics.histogram(
      'api_mode_policy_evaluation_seconds',
      'Duration of detect-mode policy evaluations of API-mode copy messages',
      [],
      POLICY_EVALUATION_BUCKETS,
    );
    this.policyInconsistentReads = metrics.counter(
      'api_mode_policy_inconsistent_reads_total',
      'Policy runtime reads of the copies role that failed their echo check (the event is retried), by read',
      ['read'],
    );
    this.copyDetections = metrics.counter(
      'api_mode_copy_detections_total',
      'API-mode copy messages with a detection (mail.message.copy_detected.v1) by kind (threat, dlp, policy) and direction',
      ['kind', 'direction'],
    );
    this.outboundDetections = metrics.counter(
      'api_mode_outbound_detections_total',
      'Outbound journal messages recorded as detections on the sender mailbox',
    );
    this.scopeMailboxes = metrics.gauge(
      'api_mode_scope_mailboxes',
      'API-mode mailboxes by protection scope state (in_scope, excluded; health leader)',
      ['state'],
    );
    this.detectOnlyPolicies = metrics.gauge(
      'api_mode_detect_only_policies',
      'Remediation policies in a running detect-only start period by what follows it (remind, enforce; health leader)',
      ['then'],
    );
  }

  // ------------------------------------------------------------------ IdpMetricsSink

  httpRequest(labels: { provider: string; family: ApiFamily; statusClass: string }): void {
    this.providerRequests.inc({
      provider: label(labels.provider),
      family: label(labels.family),
      status_class: label(labels.statusClass, 16),
    });
  }

  /**
   * The HTTP client's throttling hook is not counted here: `api_mode_throttled_total` counts the
   * pauses recorded by the throttle gate (one per provider answer that paused a family).
   */
  throttled(): void {}

  /** One pause of a connection family (the Redis throttle gate). */
  pause(provider: string, family: string): void {
    this.throttledTotal.inc({ provider: label(provider), family: label(family) });
  }

  rateBudgetWait(labels: { family: ApiFamily }): void {
    this.budgetWaits.inc({ family: label(labels.family) });
  }

  copy(source: string, result: CopyResult, count = 1): void {
    if (count > 0) this.copies.inc({ source: label(source), result }, count);
  }

  /** One remediation action outcome (no organization label). */
  remediation(provider: string, action: string, result: RemediationResult, count = 1): void {
    if (count > 0) {
      this.remediations.inc({ provider: label(provider), action: label(action), result }, count);
    }
  }

  /** One late signal (no organization label). */
  lateSignal(kind: string, result: LateSignalResult): void {
    this.lateSignals.inc({ kind: label(kind), result });
  }

  clawback(trigger: string, result: ClawbackResult, count = 1): void {
    if (count > 0) this.clawbacks.inc({ trigger: label(trigger), result }, count);
  }

  clawbackTarget(result: ClawbackTargetResult, count = 1): void {
    if (count > 0) this.clawbackTargets.inc({ result }, count);
  }

  report(result: ReportResult, count = 1): void {
    if (count > 0) this.reports.inc({ result }, count);
  }

  /** One detect evaluation outcome of a copy message (no organization label). */
  policyEvaluation(result: PolicyEvaluationResult, seconds: number | null = null): void {
    this.policyEvaluations.inc({ result });
    if (seconds !== null) this.policyEvaluationSeconds.observe(seconds);
  }

  /** One copy detection (`kind` per applying classification, A8.1). */
  copyDetection(kind: CopyDetectionKind, direction: string): void {
    this.copyDetections.inc({ kind, direction: label(direction) });
  }

  /** One execution attempt of a remediation action. */
  remediationAttempt(provider: string, outcome: RemediationAttemptOutcome): void {
    this.remediationAttempts.inc({ provider: label(provider), outcome });
  }
}
