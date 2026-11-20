import type { ApiConfig } from '../../config';

/**
 * Constants of the account takeover module (step 8.4 §5.1, D17, D20): permissions, the plan
 * feature, audit actions, Idempotency-Key operation names, v1 cursor resources and bounds.
 */

/** Permission keys (§3.3; seeded by WP1). */
export const ATO_PERMISSIONS = {
  read: 'ato:read',
  manage: 'ato:manage',
  respond: 'ato:respond',
  configure: 'ato:configure',
} as const;

/** The plan feature that enables ATO per organization (PO1, D21; off for every plan). */
export const ATO_FEATURE = 'ato_detection';

/** `audit_logs.action` of the api's own audited ATO reads (mutations are audited by the store). */
export const ATO_AUDIT = {
  authEventsViewed: 'ato.auth_events.viewed',
} as const;

/** Stable Idempotency-Key operation names (one key space per organization). */
export const ATO_OPERATIONS = {
  accountUpdate: 'ato.account_update',
  overrideSet: 'ato.override_set',
  overrideClear: 'ato.override_clear',
  trustedContextAdd: 'ato.trusted_context_add',
  trustedContextRemove: 'ato.trusted_context_remove',
  responseRequest: 'ato.response_request',
  responseApprove: 'ato.response_approve',
  responseReject: 'ato.response_reject',
  responseCancel: 'ato.response_cancel',
  responseRollback: 'ato.response_rollback',
  settingsUpdate: 'ato.settings_update',
  // Step 8.5 (§6): identity-provider integrations and the mailbox state refresh.
  providerCreate: 'ato.provider_create',
  providerUpdate: 'ato.provider_update',
  providerPause: 'ato.provider_pause',
  providerResume: 'ato.provider_resume',
  providerHealthCheck: 'ato.provider_health_check',
  providerBackfill: 'ato.provider_backfill',
  providerRemove: 'ato.provider_remove',
  mailboxRefresh: 'ato.mailbox_refresh',
} as const;

/** `audit_logs.action` of the step 8.5 provider routes (ids, provider and changed paths only). */
export const ATO_PROVIDER_AUDIT = {
  bound: 'ato.provider.bound',
  updated: 'ato.provider.updated',
  paused: 'ato.provider.paused',
  resumed: 'ato.provider.resumed',
  backfillRequested: 'ato.provider.backfill_requested',
  healthCheckRequested: 'ato.provider.health_check_requested',
  unbound: 'ato.provider.unbound',
  mailboxRefreshRequested: 'ato.mailbox_state.refresh_requested',
} as const;

/** `audit_logs.resource_type` of an identity-provider integration. */
export const ATO_PROVIDER_RESOURCE = 'ato_provider_integration';

/** `disabled_reason` of an integration removed through `DELETE /ato/providers/{id}`. */
export const ATO_PROVIDER_USER_DISABLED_REASON = 'user';

/** `result_code` of a pending provider action ended by the removal of its integration (§6 #11). */
export const ATO_PROVIDER_ACTION_DISABLED_CODE = 'integration_disabled';

/** Mailbox items removed within this many days are still shown (§6 #12, D8.3). */
export const ATO_MAILBOX_REMOVED_DAYS = 30;
/** Most mailbox items one response carries. */
export const ATO_MAILBOX_MAX_ITEMS = 500;
/** Disabled integrations listed with `?includeDisabled=true` (newest first). */
export const ATO_PROVIDERS_MAX_DISABLED_LISTED = 50;

/** v1 cursor resources (ADR-0051) of the ATO lists. */
export const ATO_CURSOR_RESOURCES = {
  accounts: 'ato_accounts',
  signals: 'ato_account_signals',
  authEvents: 'ato_account_auth_events',
  scoreHistory: 'ato_account_score_history',
  incidentSignals: 'ato_incident_signals',
  incidentAuthEvents: 'ato_incident_auth_events',
  responses: 'ato_responses',
  restrictions: 'ato_restrictions',
} as const;

/** Writer transaction budget of the ATO mutations (rescoring reads ≤ 5 000 signals). */
export const ATO_TX_TIMEOUT_MS = 30_000;

/** `system_settings` key of the worker capabilities (D17), written every 5 min. */
export const ATO_CAPABILITIES_KEY = 'ato.worker.capabilities';
/** Capabilities older than this are reported as `unknown` (D17). */
export const ATO_CAPABILITIES_MAX_AGE_MS = 15 * 60_000;

/** Range bounds of the account sub-lists (§5.1). */
export const ATO_RANGES = {
  signals: { defaultDays: 30, maxDays: 400 },
  authEvents: { defaultDays: 7, maxDays: 90 },
  activity: { defaultDays: 30, maxDays: 180 },
  scoreHistory: { defaultDays: 30, maxDays: 400 },
  incidentEvidence: { defaultDays: 400, maxDays: 400 },
} as const;

/** `GET /ato/attention` is cached this long per organization (shell badge). */
export const ATO_ATTENTION_CACHE_SECONDS = 30;

/** The api config keys the ATO and incidents modules read. */
export type AtoConfig = Pick<
  ApiConfig,
  | 'API_ATO_OVERVIEW_CACHE_SECONDS'
  | 'API_ATO_REPORT_MAX_ITEMS'
  | 'ATO_APPROVAL_TTL_HOURS'
  | 'ATO_AUTOMATED_RESPONSES_ENABLED'
  | 'ATO_MAX_AUTOMATED_RESPONSES_PER_ORG_PER_HOUR'
  | 'ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG'
  | 'API_LIST_SCAN_BUDGET_ROWS'
  | 'ATO_IDP_MAX_INTEGRATIONS_PER_ORG'
  | 'ATO_IDP_BACKFILL_MAX_DAYS'
  | 'ATO_IDP_HEALTH_INTERVAL_SECONDS'
>;
