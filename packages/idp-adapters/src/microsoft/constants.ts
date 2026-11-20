/**
 * Microsoft adapter constants (design note §3, D2, D7, D9).
 */
import type { ProviderCapabilities } from '../port/ato-port';

export const MICROSOFT_ADAPTER_VERSION = 'msgraph-ato/1';
export const MICROSOFT_PROVIDER = 'microsoft_entra' as const;

/** Sign-in error codes meaning an MFA or Conditional Access interruption (§3.2). */
export const ENTRA_INTERRUPT_CODES: ReadonlySet<number> = new Set([
  50074, 50076, 50079, 50158, 53003, 530032,
]);

/** Token risk detection types → stream `session_events` (§3.2). */
export const TOKEN_RISK_TYPES: ReadonlySet<string> = new Set([
  'anomalousToken',
  'tokenIssuerAnomaly',
  'attackerinTheMiddle',
  'suspiciousAPITraffic',
]);

/** Directory audit activities that are OAuth consents (§3.2). */
export const CONSENT_ACTIVITIES = [
  'Consent to application',
  'Add delegated permission grant',
  'Add app role assignment to service principal',
] as const;

/** Allow-listed Exchange audit operations (§3.2); every other operation is dropped. */
export const EXCHANGE_AUDIT_OPERATIONS = [
  'New-InboxRule',
  'Set-InboxRule',
  'UpdateInboxRules',
  'Set-Mailbox',
  'Add-MailboxPermission',
  'Add-RecipientPermission',
  'MailboxLogin',
  'MailItemsAccessed',
] as const;
export type ExchangeAuditOperation = (typeof EXCHANGE_AUDIT_OPERATIONS)[number];

export const O365_CONTENT_TYPE = 'Audit.Exchange';
/** Office 365 Management error: no subscription for the content type. */
export const O365_NO_SUBSCRIPTION = 'AF20022';

/** Publisher verification cache per integration (§3.2). */
export const PUBLISHER_CACHE_MS = 24 * 60 * 60 * 1000;
/** Graph user lookups of Exchange mailbox owners (§3.2). */
export const OWNER_CACHE_MS = 60 * 60 * 1000;

export const PRIORITY_REFRESH_BATCH = 20;
export const GRAPH_USERS_PAGE = 100;
export const MAX_BLOBS_PER_PAGE = 5;
/**
 * Items handled by one `remove_forwarding_rule` with `scope: 'all_external'`: per-item outcomes
 * live in `provider_state` (≤ 2 KiB), so one action covers at most 12 items; more ⇒ `partial`.
 */
export const MAX_FORWARDING_ITEMS = 12;

/** Provider reference prefix (D9.5). */
export const MICROSOFT_REFERENCE_PREFIX = 'msgraph';

export const MICROSOFT_DECLARED_CAPABILITIES: ProviderCapabilities = {
  streams: {
    sign_ins: { supported: true, latencySeconds: 600 },
    risk_events: { supported: true, latencySeconds: 900 },
    session_events: { supported: true, latencySeconds: 900 },
    oauth_consents: { supported: true, latencySeconds: 900 },
    mailbox_audit: { supported: true, latencySeconds: 3600 },
    forwarding_changes: { supported: true, latencySeconds: 3600 },
    delegation_changes: { supported: true, latencySeconds: 3600 },
  },
  actions: {
    revoke_sessions: { supported: true, rollback: false, confirmation: 'synchronous' },
    require_password_reset: { supported: true, rollback: false, confirmation: 'synchronous' },
    suspend_account: { supported: true, rollback: true, confirmation: 'polling' },
    require_mfa: { supported: true, rollback: true, confirmation: 'polling' },
    remove_forwarding_rule: { supported: true, rollback: true, confirmation: 'polling' },
    revoke_oauth_grant: { supported: true, rollback: false, confirmation: 'synchronous' },
  },
};
