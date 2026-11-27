import type { ApiConfig } from '../../config';

/**
 * Constants of the API-mode module (step API-1, docs/plan/steps/35-api-mode-protection.md D2,
 * D10, D12, §5; ADR-0098..0100): permissions, audit actions and resource types, Idempotency-Key
 * operation names, v1 cursor resources, bounds and the config keys the module reads.
 */

/** Permission keys (WP1 §3.3) and the existing ones the protection-mode routes use. */
export const API_MODE_PERMISSIONS = {
  read: 'remediation:read',
  write: 'remediation:write',
  // Step API-3 §3.3 (docs/plan/steps/37-api-mode-clawback-reporting.md).
  purge: 'remediation:purge',
  organizationRead: 'organization:read',
  organizationManage: 'organization:manage',
  domainManage: 'domain:manage',
} as const;

/** `audit_logs.action` of the module (§5). Metadata: enums, ids and counts only (+ `reason`). */
export const API_MODE_AUDIT = {
  organizationModeChanged: 'organization.protection_mode_changed',
  domainModeChanged: 'domain.protection_mode_changed',
  settingsUpdated: 'api_mode.settings_updated',
  inventorySyncRequested: 'api_mode.inventory_sync_requested',
  mailboxResyncRequested: 'api_mode.mailbox_resync_requested',
  // Step API-2 §5 (docs/plan/steps/36-api-mode-remediation.md).
  remediationPolicyUpdated: 'api_mode.remediation_policy_updated',
  remediationRequested: 'api_mode.remediation_requested',
  restoreRequested: 'api_mode.restore_requested',
  remediationRetryRequested: 'api_mode.remediation_retry_requested',
  // Step API-3 §5 (docs/plan/steps/37-api-mode-clawback-reporting.md); content-free metadata.
  clawbackCreated: 'api_mode.clawback_created',
  clawbackSubmitted: 'api_mode.clawback_submitted',
  clawbackApprovalRequested: 'api_mode.clawback_approval_requested',
  clawbackApproved: 'api_mode.clawback_approved',
  clawbackDenied: 'api_mode.clawback_denied',
  clawbackCancelled: 'api_mode.clawback_cancelled',
  clawbackRestoreRequested: 'api_mode.clawback_restore_requested',
  settingsOrgUpdated: 'api_mode.settings_org_updated',
  reportMailboxUpdated: 'api_mode.report_mailbox_updated',
  reportTriaged: 'api_mode.report_triaged',
  reportClawbackRequested: 'api_mode.report_clawback_requested',
} as const;

/** `audit_logs.resource_type` of the module's rows. */
export const API_MODE_RESOURCES = {
  organization: 'organization',
  domain: 'domain',
  connection: 'api_mode_connection',
  mailbox: 'api_mailbox',
  remediationPolicy: 'api_remediation_policy',
  remediation: 'api_remediation_action',
  detection: 'api_message_copy',
  // Step API-3.
  clawback: 'api_clawback',
  report: 'api_user_report',
  orgSettings: 'api_mode_org_settings',
} as const;

/** Stable Idempotency-Key operation names. */
export const API_MODE_OPERATIONS = {
  organizationMode: 'organization.protection_mode_update',
  domainMode: 'domain.protection_mode_update',
  settingsUpdate: 'api_mode.settings_update',
  inventorySync: 'api_mode.inventory_sync',
  mailboxResync: 'api_mode.mailbox_resync',
  // Step API-2 R13.
  policyPut: 'api_mode.remediation_policy_put',
  domainPolicyPut: 'api_mode.remediation_domain_policy_put',
  domainPolicyDelete: 'api_mode.remediation_domain_policy_delete',
  remediationRetry: 'api_mode.remediation_retry',
  remediate: 'api_mode.remediate',
  restore: 'api_mode.restore',
  // Step API-3 C14.
  clawbackCreate: 'api_mode.clawback_create',
  clawbackSubmit: 'api_mode.clawback_submit',
  clawbackSubmitHardDelete: 'api_mode.clawback_submit_hard_delete',
  clawbackApprove: 'api_mode.clawback_approve',
  clawbackDeny: 'api_mode.clawback_deny',
  clawbackCancel: 'api_mode.clawback_cancel',
  clawbackRestore: 'api_mode.clawback_restore',
  reportTriage: 'api_mode.report_triage',
  reportClawback: 'api_mode.report_clawback',
  reportMailboxAdd: 'api_mode.report_mailbox_add',
  reportMailboxSet: 'api_mode.report_mailbox_set',
  orgSettingsPut: 'api_mode.settings_org_put',
} as const;

/** v1 cursor resources (ADR-0051). */
export const API_MODE_CURSOR_RESOURCES = {
  mailboxes: 'api_mailboxes',
  detections: 'api_message_copies',
  remediations: 'api_remediation_actions',
  // Step API-3 C14.
  clawbacks: 'api_clawbacks',
  clawbackTargets: 'api_clawback_targets',
  reports: 'api_user_reports',
} as const;

/** Writer transaction budget of the module's mutations. */
export const API_MODE_TX_TIMEOUT_MS = 30_000;

/** `GET /api-mode/mailboxes/{id}`: its last copies. */
export const MAILBOX_RECENT_COPIES = 20;
/** `GET /api-mode/detections/{id}`: at most this many risk reason codes. */
export const DETECTION_REASON_CODES = 10;
/** `GET /api-mode/detections`: default window and the longest range (D12 #13). */
export const DETECTIONS_DEFAULT_DAYS = 7;
export const DETECTIONS_MAX_DAYS = 31;
/** `GET /api-mode/remediations`: default window and the longest range (R13 #5). */
export const REMEDIATIONS_DEFAULT_DAYS = 7;
export const REMEDIATIONS_MAX_DAYS = 31;
/** The live pending count of the overview's remediation block stops counting here (R13). */
export const REMEDIATION_BACKLOG_COUNT_CAP = 10_000;
/** `quarantine:release`: the extra permission of a restore that delegates to the release (R12). */
export const QUARANTINE_RELEASE_PERMISSION = 'quarantine:release';

/** Step API-3 C14 #2, #11: default window and the longest range of the clawback/report lists. */
export const CLAWBACKS_DEFAULT_DAYS = 30;
export const CLAWBACKS_MAX_DAYS = 93;
export const REPORTS_DEFAULT_DAYS = 30;
export const REPORTS_MAX_DAYS = 93;
/** Step API-3 C14 #12: at most this many group members in a report detail. */
export const REPORT_GROUP_MEMBERS_MAX = 50;
/** Step API-3 C14 #12: at most this many triage history entries (audit rows). */
export const REPORT_HISTORY_MAX = 50;
/** Step API-3: detections list/detail show at most this many clawbacks that targeted the copy. */
export const DETECTION_CLAWBACKS_MAX = 5;
/** Step API-3 C13: live counts of the overview's clawback and reports blocks stop here. */
export const CLAWBACK_COUNT_CAP = 10_000;
/** Step API-3 C2.4: the campaign expansion's sender + subject window (hours). */
export const CAMPAIGN_SENDER_SUBJECT_HOURS = { min: 1, max: 168, default: 72 } as const;
/** Step API-3 C2.4: at most this many attachment / URL hashes a campaign seed contributes. */
export const CAMPAIGN_SEED_HASHES_MAX = 20;
/** Step API-3 C11.4: a resolved report can be reopened once. */
export const REPORT_REOPEN_LIMIT = 1;

/** `GET /api-mode/connections/{id}`: days of counters. */
export const CONNECTION_COUNTER_DAYS = 7;

/** Public callback routes (D12.4). */
export const NOTIFICATION_ROUTES = {
  graph: '/api/v1/provider-notifications/graph',
  lifecycle: '/api/v1/provider-notifications/graph/lifecycle',
} as const;
/** Route-level JSON body limit of the callbacks (D12.4): 256 KiB. */
export const NOTIFICATION_BODY_LIMIT_BYTES = 256 * 1024;
/** Fixed window of the per-client-IP callback limit. */
export const NOTIFICATION_RATE_WINDOW_SECONDS = 60;

/** The api config keys the module reads. */
export type ApiModeConfig = Pick<
  ApiConfig,
  | 'API_MODE_NOTIFICATION_RATE_PER_MINUTE'
  | 'API_MODE_GRAPH_NOTIFICATION_URL'
  | 'PROVIDER_M365_MAILBOX_APP_CLIENT_ID'
  | 'PROVIDER_GOOGLE_MAILBOX_SA_CLIENT_ID'
  | 'API_MODE_HARD_DELETE_ENABLED'
  | 'API_MODE_CLAWBACK_MAX_WINDOW_DAYS'
  | 'API_MODE_PURGE_APPROVAL_TTL_HOURS'
  | 'API_MODE_REPORT_MAILBOXES_MAX'
>;
