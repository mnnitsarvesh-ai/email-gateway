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
} as const;

/** `audit_logs.resource_type` of the module's rows. */
export const API_MODE_RESOURCES = {
  organization: 'organization',
  domain: 'domain',
  connection: 'api_mode_connection',
  mailbox: 'api_mailbox',
} as const;

/** Stable Idempotency-Key operation names. */
export const API_MODE_OPERATIONS = {
  organizationMode: 'organization.protection_mode_update',
  domainMode: 'domain.protection_mode_update',
  settingsUpdate: 'api_mode.settings_update',
  inventorySync: 'api_mode.inventory_sync',
  mailboxResync: 'api_mode.mailbox_resync',
} as const;

/** v1 cursor resources (ADR-0051). */
export const API_MODE_CURSOR_RESOURCES = {
  mailboxes: 'api_mailboxes',
  detections: 'api_message_copies',
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
>;
