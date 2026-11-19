import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';

/** `source` label values of `ato_events_total` and the lag/duration histograms (D19). */
export const ATO_EVENT_SOURCES = [
  'portal_login',
  'account_change',
  'smtp_auth',
  'smtp_submission',
  'outbound_message',
  'provider',
] as const;
export type AtoEventSource = (typeof ATO_EVENT_SOURCES)[number];

/** `result` label values of `ato_events_total` (D19). */
export const ATO_EVENT_RESULTS = [
  'processed',
  'skipped_feature',
  'skipped_direction',
  'skipped_org',
  'duplicate',
  'unattributed',
  'error',
] as const;
export type AtoEventResult = (typeof ATO_EVENT_RESULTS)[number];

const SECONDS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30];
const LAG = [0.5, 1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600, 21_600];

/**
 * The ato-worker series (step 8.4 D19). Names are a contract of
 * `infrastructure/monitoring/rules/ato.rules.yml`; labels are bounded enums only — never a
 * tenant, account, address or IP.
 */
export class AtoMetrics {
  readonly events: Counter<'source' | 'result'>;
  readonly detectionDuration: Histogram<'source'>;
  readonly detectionLag: Histogram<'source'>;
  readonly signals: Counter<'category' | 'strength'>;
  readonly incidentsOpened: Counter<'severity'>;
  readonly incidentsResolved: Counter<'resolution'>;
  readonly incidentsActive: Gauge<'severity'>;
  readonly responses: Counter<'action' | 'outcome'>;
  readonly responsesPendingApproval: Gauge;
  readonly restrictionsActive: Gauge<'kind'>;
  readonly automationGuard: Counter<'reason'>;
  readonly geoipLookups: Counter<'database' | 'result'>;
  readonly geoipAge: Gauge<'database'>;
  readonly geoipLoaded: Gauge<'database'>;
  readonly reputationLookups: Counter<'provider' | 'result'>;
  readonly redisSeconds: Histogram<'operation'>;
  readonly redisErrors: Counter<'operation'>;
  readonly dbSeconds: Histogram<'query'>;
  readonly ipCampaignsFlagged: Counter;
  readonly catchupProcessed: Counter;
  readonly catchupLag: Gauge;
  readonly baselineRebuild: Counter<'result'>;
  readonly providerOperations: Counter<'provider' | 'operation' | 'outcome'>;
  readonly providerPollSeconds: Histogram<'provider'>;
  readonly maintenanceRuns: Counter<'job' | 'result'>;
  readonly leader: Gauge<'job'>;

  constructor(metrics: MetricsService) {
    this.events = metrics.counter(
      'ato_events_total',
      'ATO source events by source (portal_login, account_change, smtp_auth, smtp_submission, outbound_message, provider) and result (processed, skipped_feature, skipped_direction, skipped_org, duplicate, unattributed, error)',
      ['source', 'result'],
    );
    this.detectionDuration = metrics.histogram(
      'ato_detection_duration_seconds',
      'Duration of one detection (reads, windows, rules, writer transaction) by source',
      ['source'],
      SECONDS,
    );
    this.detectionLag = metrics.histogram(
      'ato_detection_lag_seconds',
      'Time from the source event to the commit of its detection, by source',
      ['source'],
      LAG,
    );
    this.signals = metrics.counter(
      'ato_signals_total',
      'New ATO risk signals (deduplicated repetitions not counted) by category and strength',
      ['category', 'strength'],
    );
    this.incidentsOpened = metrics.counter(
      'ato_incidents_opened_total',
      'account_takeover security incidents opened by detection, by severity',
      ['severity'],
    );
    this.incidentsResolved = metrics.counter(
      'ato_incidents_resolved_total',
      'account_takeover security incidents closed, by resolution code (counted by the maintenance pass from incident rows)',
      ['resolution'],
    );
    this.incidentsActive = metrics.gauge(
      'ato_incidents_active',
      'Active account_takeover security incidents by severity (written by the maintenance leader)',
      ['severity'],
    );
    this.responses = metrics.counter(
      'ato_responses_total',
      'ATO response actions executed or settled by the worker, by action type and outcome',
      ['action', 'outcome'],
    );
    this.responsesPendingApproval = metrics.gauge(
      'ato_responses_pending_approval',
      'ATO response actions waiting for an approval (written by the maintenance leader)',
    );
    this.restrictionsActive = metrics.gauge(
      'ato_restrictions_active',
      'Active ATO SMTP restrictions by kind (send_block, auth_block)',
      ['kind'],
    );
    this.automationGuard = metrics.counter(
      'ato_automation_guard_total',
      'Automatic medium/high-impact ATO responses held for approval, by guard reason',
      ['reason'],
    );
    this.geoipLookups = metrics.counter(
      'ato_geoip_lookups_total',
      'GeoIP lookups by database (city, asn, anonymous) and result (hit, miss, unavailable, skipped, error)',
      ['database', 'result'],
    );
    this.geoipAge = metrics.gauge(
      'ato_geoip_database_age_seconds',
      'Age of the loaded GeoIP database (now minus its build epoch); absent when not loaded',
      ['database'],
    );
    this.geoipLoaded = metrics.gauge(
      'ato_geoip_database_loaded',
      '1 when the GeoIP database is configured and loaded, 0 otherwise',
      ['database'],
    );
    this.reputationLookups = metrics.counter(
      'ato_reputation_lookups_total',
      'IP reputation answers through ReputationService by provider and result (listed, clear, error)',
      ['provider', 'result'],
    );
    this.redisSeconds = metrics.histogram(
      'ato_redis_operation_seconds',
      'Duration of ATO Redis window operations',
      ['operation'],
      [0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1],
    );
    this.redisErrors = metrics.counter(
      'ato_redis_errors_total',
      'Failed ATO Redis operations (the event is retried)',
      ['operation'],
    );
    this.dbSeconds = metrics.histogram(
      'ato_db_query_seconds',
      'Duration of ATO writer transactions and maintenance queries',
      ['query'],
      SECONDS,
    );
    this.ipCampaignsFlagged = metrics.counter(
      'ato_ip_campaigns_flagged_total',
      'IPs newly flagged as credential-attack sources by the platform IP windows',
    );
    this.catchupProcessed = metrics.counter(
      'ato_mail_catchup_processed_total',
      'Outbound/internal messages processed by the ato.mail catch-up (not seen by the live consumer)',
    );
    this.catchupLag = metrics.gauge(
      'ato_mail_catchup_lag_seconds',
      'Largest age of a catch-up cursor of an ATO-enabled organization (now minus its high-water received_at)',
    );
    this.baselineRebuild = metrics.counter(
      'ato_baseline_rebuild_total',
      'Account baseline rebuilds by result (rebuilt, error)',
      ['result'],
    );
    this.providerOperations = metrics.counter(
      'ato_provider_operations_total',
      'Identity-provider adapter operations by provider kind, operation (ingest, execute, confirm, rollback, health) and outcome',
      ['provider', 'operation', 'outcome'],
    );
    this.providerPollSeconds = metrics.histogram(
      'ato_provider_poll_seconds',
      'Duration of one provider ingestion poll of an integration',
      ['provider'],
      SECONDS,
    );
    this.maintenanceRuns = metrics.counter(
      'ato_maintenance_runs_total',
      'Maintenance job passes by job and result (ok, error, not_leader)',
      ['job', 'result'],
    );
    this.leader = metrics.gauge(
      'ato_maintenance_leader',
      '1 while this replica holds the named maintenance leader lock',
      ['job'],
    );
  }
}
