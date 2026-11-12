import { QUARANTINE_PERMISSIONS } from '@email-gateway/quarantine';
import type { QuarantineConfigKeys } from '../../config';

/** Permission keys of the quarantine routes (Q25; seeded by WP1). */
export const Q = QUARANTINE_PERMISSIONS;
export const SETTINGS_MANAGE = 'settings:manage';

/** The api config keys the quarantine module reads. */
export type QuarantineConfig = QuarantineConfigKeys & { POLICY_PLATFORM_DEFAULT: string };

/** Deployable name in lifecycle history, `email_events` and outbox correlation ids. */
export const QUARANTINE_SERVICE = 'api';

/** `audit_logs.action` of the quarantine (Q21). Metadata: ids, enums, counts, hashes only. */
export const QUARANTINE_AUDIT = {
  searched: 'quarantine.searched',
  entryViewed: 'quarantine.entry_viewed',
  previewed: 'quarantine.previewed',
  previewFailed: 'quarantine.preview_failed',
  downloadGranted: 'quarantine.download_granted',
  downloaded: 'quarantine.downloaded',
  downloadRefused: 'quarantine.download_refused',
  releaseRequested: 'quarantine.release_requested',
  releaseRefused: 'quarantine.release_refused',
  selfReleased: 'quarantine.self_released',
  rejected: 'quarantine.rejected',
  deleted: 'quarantine.deleted',
  deleteRefused: 'quarantine.delete_refused',
  manualQuarantined: 'quarantine.manual_quarantined',
  approvalRequested: 'quarantine.approval_requested',
  approvalApproved: 'quarantine.approval_approved',
  approvalDenied: 'quarantine.approval_denied',
  approvalCancelled: 'quarantine.approval_cancelled',
  bulk: 'quarantine.bulk',
  settingsUpdated: 'quarantine.settings_updated',
  preferencesUpdated: 'quarantine.preferences_updated',
} as const;
export type QuarantineAuditAction = (typeof QUARANTINE_AUDIT)[keyof typeof QUARANTINE_AUDIT];

export const QUARANTINE_RESOURCE = {
  entry: 'quarantine_entry',
  approval: 'quarantine_approval_request',
  settings: 'quarantine_settings',
  preferences: 'quarantine_user_preferences',
  search: 'quarantine_search',
  message: 'message',
} as const;

/** Idempotency operation names (`api_idempotency_keys.operation`). */
export const QUARANTINE_OPERATIONS = {
  release: 'quarantine.release',
  selfRelease: 'quarantine.self_release',
  requestRelease: 'quarantine.request_release',
  selfRequestRelease: 'quarantine.self_request_release',
  reject: 'quarantine.reject',
  delete: 'quarantine.delete',
  manual: 'quarantine.manual',
  approve: 'quarantine.approve',
  deny: 'quarantine.deny',
  cancel: 'quarantine.cancel',
  bulk: 'quarantine.bulk',
} as const;

/** `Cache-Control` of every quarantine response that carries message-derived text. */
export const NO_STORE = 'no-store';
