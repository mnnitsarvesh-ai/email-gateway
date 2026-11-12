import type { Counter, Histogram, MetricsService } from '@email-gateway/common';
import type { LifecycleMetrics } from '@email-gateway/message-lifecycle';

/** Reads echo-checked by the engine (§6); the `read` label of `policy_inconsistent_reads_total`. */
export type PolicyRead =
  | 'message'
  | 'message_update'
  | 'recipients'
  | 'scan'
  | 'parse'
  | 'finals'
  | 'auth'
  | 'bec'
  | 'dlp'
  | 'risk'
  | 'attachments'
  | 'attachment_results'
  | 'urls'
  | 'url_results'
  | 'url_rewrite'
  | 'settings'
  | 'policies'
  | 'versions'
  | 'departments'
  | 'members'
  | 'users'
  | 'lifecycle'
  | 'parse_structure'
  | 'message_urls'
  | 'url_settings';

/**
 * The policy-engine's series (step 5.2 P24; names fixed by the design, labels bounded enums,
 * never tenant ids) plus the shared lifecycle series of the transitions it applies (E5, E8–E13).
 */
export class PolicyMetrics {
  readonly evaluations: Counter<'trigger' | 'disposition' | 'source' | 'direction'>;
  readonly duration: Histogram;
  readonly floorRaises: Counter<'reason'>;
  readonly overrides: Counter<'result'>;
  readonly actions: Counter<'type' | 'status'>;
  readonly lifecycleSkipped: Counter<'result'>;
  readonly inconsistentReads: Counter<'read'>;
  readonly inputErrors: Counter;
  readonly snapshotCache: Counter<'result'>;
  readonly snapshotInvalidVersions: Counter;
  readonly copies: Counter<'result'>;
  readonly urlRewrites: Counter<'result'>;
  readonly bodyBanners: Counter<'result'>;
  readonly recipientSplit: Counter<'result'>;
  readonly riskMissing: Counter;
  readonly lifecycle: LifecycleMetrics;

  constructor(metrics: MetricsService) {
    this.evaluations = metrics.counter(
      'policy_evaluations_total',
      'Committed policy evaluations by trigger (scanned, scan_failed, parse_failed), final disposition, decision source (tenant_rule, platform_default, floor) and direction',
      ['trigger', 'disposition', 'source', 'direction'],
    );
    this.duration = metrics.histogram(
      'policy_evaluation_duration_seconds',
      'Duration of one evaluation: fact reads, snapshot, directory and evaluatePolicy (the S3 policy copy excluded)',
      [],
      [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
    );
    this.floorRaises = metrics.counter(
      'policy_floor_raises_total',
      'Strictness floor reasons present in committed evaluations (hard_block, risk_error, engine_failure, unknown_engine, dlp_*, risk_missing, scan_failed, not_scanned)',
      ['reason'],
    );
    this.overrides = metrics.counter(
      'policy_overrides_total',
      'Tenant overrides of the recommendation: applied, or clamped (refused and recorded)',
      ['result'],
    );
    this.actions = metrics.counter(
      'policy_actions_total',
      'Stored actions of committed evaluations by type and status (enforced, requested, recorded, not_applicable; ADR-0045)',
      ['type', 'status'],
    );
    this.lifecycleSkipped = metrics.counter(
      'policy_lifecycle_skipped_total',
      'Trigger events not evaluated because the first lifecycle edge was not applied (stale, invalid, duplicate, not_found): ledger row only',
      ['result'],
    );
    this.inconsistentReads = metrics.counter(
      'policy_inconsistent_reads_total',
      'Writer reads whose identifying columns did not echo the request (step 4.2 §6); the event is retried',
      ['read'],
    );
    this.inputErrors = metrics.counter(
      'policy_input_errors_total',
      'Rounds whose stored facts could not be turned into a policy input (PolicyInputError) or not evaluated; the event is dead-lettered and the message stays held',
    );
    this.snapshotCache = metrics.counter(
      'policy_snapshot_cache_total',
      'Compiled snapshot lookups keyed (organization, generation): hit or miss',
      ['result'],
    );
    this.snapshotInvalidVersions = metrics.counter(
      'policy_snapshot_invalid_versions_total',
      'Active policy versions excluded from a compiled snapshot because they no longer validate (counted per compilation)',
    );
    this.copies = metrics.counter(
      'policy_copy_total',
      'Policy copies of the delivered object (header edits, WARN banner, policy URL rewrite, release header): written, or refused as too_large / header_too_large (TAG/WARN/banner recorded)',
      ['result'],
    );
    this.urlRewrites = metrics.counter(
      'policy_url_rewrite_total',
      'URL_REWRITE after the scan (step 5.3 Q23): rewritten, a skip reason of the policy rewrite (signed_smime, too_large, no_urls, …), disabled (POLICY_URL_REWRITE_ENABLED=false) or not_eligible (the round skip cannot be fixed by the policy)',
      ['result'],
    );
    this.bodyBanners = metrics.counter(
      'policy_body_banner_total',
      'WARN body banners of delivered copies (step 5.3 Q22): applied or skipped_signed / skipped_encrypted / skipped_too_large / skipped_no_text_part / skipped_part',
      ['result'],
    );
    this.recipientSplit = metrics.counter(
      'policy_recipient_split_total',
      'Per-recipient evaluation of committed evaluations (step 5.3 Q4): split, uniform, not_scoped, disabled, too_many',
      ['result'],
    );
    this.riskMissing = metrics.counter(
      'policy_risk_missing_total',
      'Scanned or scan-failed rounds evaluated without a revision-0 risk row (a step 5.1 defect; held by the floor)',
    );
    const transitions = metrics.counter(
      'lifecycle_transitions_total',
      'Message lifecycle transition requests by current state, target and result (applied, duplicate, stale, invalid)',
      ['from', 'to', 'result'],
    );
    const ignored = metrics.counter(
      'lifecycle_transitions_ignored_total',
      'Stale or invalid lifecycle transition requests by reason',
      ['reason'],
    );
    const conflicts = metrics.counter(
      'lifecycle_version_conflicts_total',
      'Lifecycle transactions retried after a compare-and-set conflict, deadlock, lock wait timeout or concurrent duplicate',
    );
    const derived = metrics.counter(
      'lifecycle_derived_skipped_total',
      'Derived delivery states not applied because the message is outside the delivery phase, by its state',
      ['state'],
    );
    this.lifecycle = {
      transition: (from, to, result) => transitions.inc({ from, to, result }),
      ignored: (reason) => ignored.inc({ reason }),
      versionConflict: () => conflicts.inc(),
      derivedSkipped: (state) => derived.inc({ state }),
    };
  }
}
