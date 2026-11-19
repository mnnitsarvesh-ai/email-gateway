import type { Counter, Gauge, Histogram, MetricsService } from '@email-gateway/common';

/**
 * The integration-worker series (step 8.2 D18, docs/plan/steps/25-m365-google-connectors.md).
 * Names are a contract of `infrastructure/monitoring/rules/integrations.rules.yml`; labels are
 * bounded enums only — never a tenant, connection id, domain, address or provider error text.
 */
export class IntegrationMetrics {
  /** result = ok | cache_hit | a provider error code. */
  readonly tokenRequests: Counter<'provider' | 'method' | 'result'>;
  /** api = graph | google.admin | m365.token | google.token; result = ok | error code. */
  readonly apiRequests: Counter<'provider' | 'api' | 'result'>;
  readonly apiDuration: Histogram<'provider' | 'api'>;
  /** kind = full | credentials | inbound | outbound; result = passed | warning | failed | expired. */
  readonly validationRuns: Counter<'kind' | 'result'>;
  /** Connections by provider, status and health (maintenance role, leader only). */
  readonly connections: Gauge<'provider' | 'status' | 'health'>;
  /** Active connections with outbound mode `active` (ProviderEgressRangesEmpty). */
  readonly outboundActive: Gauge<'provider'>;
  readonly healthTransitions: Counter<'provider' | 'to'>;
  /** Age of the active egress set's `published_at` (or import time) per provider. */
  readonly egressSetAge: Gauge<'provider'>;
  /** Active source_ip connector networks overlapping an active provider egress range. */
  readonly sharedNetworks: Gauge;
  /** Age of the oldest pending task (grant verification, queued validation run). */
  readonly taskLag: Gauge;
  /** result = active | error | retry | lost. */
  readonly grantVerifications: Counter<'provider' | 'result'>;
  /** result = pass | warn | fail | error | skipped. */
  readonly smtpProbes: Counter<'result'>;
  readonly maintenanceDeleted: Counter<'table'>;
  /** result = reencrypted | failed | skipped. */
  readonly credentialsReencrypted: Counter<'result'>;
  /** 1 while this replica holds the maintenance leader lock. */
  readonly leader: Gauge<'job'>;

  constructor(metrics: MetricsService) {
    this.tokenRequests = metrics.counter(
      'provider_token_requests_total',
      'Provider access-token requests of the integration-worker, by provider, auth method and result (ok, cache_hit or a classified error code)',
      ['provider', 'method', 'result'],
    );
    this.apiRequests = metrics.counter(
      'provider_api_requests_total',
      'Provider HTTP requests (Graph, Admin SDK, token endpoints), by provider, api and result',
      ['provider', 'api', 'result'],
    );
    this.apiDuration = metrics.histogram(
      'provider_api_duration_seconds',
      'Duration of provider HTTP requests, by provider and api',
      ['provider', 'api'],
      [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30],
    );
    this.validationRuns = metrics.counter(
      'provider_validation_runs_total',
      'Completed validation runs, by kind and result (passed, warning, failed, expired)',
      ['kind', 'result'],
    );
    this.connections = metrics.gauge(
      'provider_connections',
      'Provider connections by provider, status and health (maintenance leader; 0 elsewhere)',
      ['provider', 'status', 'health'],
    );
    this.outboundActive = metrics.gauge(
      'provider_connections_outbound_active',
      'Active provider connections with outbound mode active, by provider (maintenance leader)',
      ['provider'],
    );
    this.healthTransitions = metrics.counter(
      'provider_health_transitions_total',
      'Connection health transitions written, by provider and new status',
      ['provider', 'to'],
    );
    this.egressSetAge = metrics.gauge(
      'provider_egress_set_age_seconds',
      'Age of the active provider egress range set (published_at, else import time), by provider (maintenance leader)',
      ['provider'],
    );
    this.sharedNetworks = metrics.gauge(
      'smtp_connector_shared_provider_networks',
      'Active source_ip SMTP connector networks overlapping an active provider egress range (maintenance leader)',
    );
    this.taskLag = metrics.gauge(
      'integration_worker_task_lag_seconds',
      'Age of the oldest pending integration task (grant verification or queued validation run)',
    );
    this.grantVerifications = metrics.counter(
      'provider_grant_verifications_total',
      'Grant verifications, by provider and result (active, error, retry, lost)',
      ['provider', 'result'],
    );
    this.smtpProbes = metrics.counter(
      'provider_smtp_probes_total',
      'SMTP reachability probes of destination hosts (never DATA), by result',
      ['result'],
    );
    this.maintenanceDeleted = metrics.counter(
      'integration_maintenance_deleted_total',
      'Rows removed by the maintenance role (retention and expiry), by table',
      ['table'],
    );
    this.credentialsReencrypted = metrics.counter(
      'provider_credentials_reencrypted_total',
      'Grant credentials processed by the key-rotation re-encryption, by result',
      ['result'],
    );
    this.leader = metrics.gauge(
      'integration_worker_leader',
      '1 while this replica holds the named leader lock',
      ['job'],
    );
  }
}

/** `provider` label of a provider HTTP observation (`api` = graph, m365.token, google.*). */
export const providerOfApi = (api: string): 'microsoft_365' | 'google_workspace' =>
  api.startsWith('google') ? 'google_workspace' : 'microsoft_365';
