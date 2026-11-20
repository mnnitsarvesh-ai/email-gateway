/**
 * Google Workspace adapter constants (design note §3, D2, D3, D7, D8, D9).
 */
import type { ProviderCapabilities } from '../port/ato-port';

export const GOOGLE_ADAPTER_VERSION = 'gws-ato/1';
export const GOOGLE_PROVIDER = 'google_workspace' as const;

/** Provider reference prefix (D9.5; reference form: deviation WP2-2). */
export const GOOGLE_REFERENCE_PREFIX = 'gws';

/** Reports applications read by the adapter. */
export type ReportsApplication = 'login' | 'token';

/**
 * `login` events that are risk signals → stream `risk_events` with `riskDetail` = event name
 * (§3.2). `account_disabled_spamming*` is matched by prefix.
 */
export const GOOGLE_RISK_EVENTS: Readonly<Record<string, 'low' | 'medium' | 'high'>> = {
  suspicious_login: 'medium',
  suspicious_login_less_secure_app: 'low',
  suspicious_programmatic_login: 'medium',
  gov_attack_warning: 'high',
  account_disabled_password_leak: 'high',
  account_disabled_hijacked: 'high',
};
export const GOOGLE_SPAMMING_PREFIX = 'account_disabled_spamming';

/** `login_challenge_status` value of a failed challenge. */
export const CHALLENGE_FAILED = 'Challenge Failed';

/** Token event that is an OAuth consent (§3.2). */
export const TOKEN_AUTHORIZE_EVENT = 'authorize';

/** Directory `users.list` page size of the settings sweep (D8.3). */
export const DIRECTORY_USERS_PAGE = 100;
/** Directory query listing active users only. */
export const ACTIVE_USERS_QUERY = 'isSuspended=false';
export const PRIORITY_REFRESH_BATCH = 20;

/**
 * Items handled by one `remove_forwarding_rule` with `scope: 'all_external'` (per-item outcomes
 * live in `provider_state`, ≤ 2 KiB; more ⇒ `partial`, as for Microsoft, deviation WP1-9).
 */
export const MAX_FORWARDING_ITEMS = 12;

/** Gmail system labels used in filter classification (§3.2). */
export const GMAIL_LABELS = {
  inbox: 'INBOX',
  unread: 'UNREAD',
  trash: 'TRASH',
  spam: 'SPAM',
} as const;

export const GOOGLE_DECLARED_CAPABILITIES: ProviderCapabilities = {
  streams: {
    sign_ins: { supported: true, latencySeconds: 1800 },
    risk_events: { supported: true, latencySeconds: 1800 },
    session_events: { supported: false },
    oauth_consents: { supported: true, latencySeconds: 1800 },
    mailbox_audit: { supported: true, latencySeconds: 86_400 },
    forwarding_changes: { supported: true, latencySeconds: 86_400 },
    delegation_changes: { supported: true, latencySeconds: 86_400 },
  },
  actions: {
    revoke_sessions: { supported: true, rollback: false, confirmation: 'synchronous' },
    require_password_reset: { supported: true, rollback: false, confirmation: 'polling' },
    suspend_account: { supported: true, rollback: true, confirmation: 'polling' },
    require_mfa: { supported: true, rollback: true, confirmation: 'polling' },
    remove_forwarding_rule: { supported: true, rollback: false, confirmation: 'polling' },
    revoke_oauth_grant: { supported: true, rollback: false, confirmation: 'synchronous' },
  },
};
