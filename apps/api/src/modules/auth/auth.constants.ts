/**
 * Key-value store keys (design §3; all stored under the `eg:` prefix by the store) and fixed
 * parameters of the authentication module.
 */
export const kvKeys = {
  ipFailures: (ip: string) => `auth:fail:ip:${ip}`,
  accountFailures: (userId: bigint) => `auth:fail:acct:${userId}`,
  lockouts: (userId: bigint) => `auth:lockouts:${userId}`,
  mfaChallenge: (hash: string) => `auth:mfa:${hash}`,
  mfaAttempts: (hash: string) => `auth:mfa:attempts:${hash}`,
  revokedSession: (sessionId: string) => `auth:revoked:${sessionId}`,
  /** Keyed by the user's public id, which is what access tokens carry (`sub`). */
  principal: (userPublicId: string) => `auth:principal:${userPublicId}`,
  orgVersion: (organizationId: bigint) => `auth:orgver:${organizationId}`,
  /** Per-user cache version (a random nonce written by `invalidateUser`). */
  userVersion: (userPublicId: string) => `auth:userver:${userPublicId}`,
  apiKey: (prefix: string) => `auth:apikey:${prefix}`,
  /** Per-key cache version (a random nonce written by `invalidateApiKey`). */
  apiKeyVersion: (prefix: string) => `auth:apikeyver:${prefix}`,
  apiKeyUsed: (apiKeyId: bigint) => `apikey:used:${apiKeyId}`,
  override: (overrideId: string) => `auth:override:${overrideId}`,
  emailVerificationResend: (userId: bigint) => `rl:email-verification-user:${userId}`,
  purgeLock: 'jobs:auth-purge',
} as const;

/** Generic login failure message (D6): never reveals which check failed. */
export const INVALID_CREDENTIALS = 'Invalid credentials';
/** Single-use token failure message: never reveals whether it was unknown, used or expired. */
export const INVALID_TOKEN = 'Invalid or expired token';

export const MFA_CHALLENGE_TTL_SECONDS = 300;
export const MFA_CHALLENGE_MAX_ATTEMPTS = 5;
export const PRINCIPAL_CACHE_TTL_SECONDS = 60;
export const API_KEY_CACHE_TTL_SECONDS = 60;
/**
 * Lifetime of a per-user or per-key version nonce. It must outlive every cache entry written
 * before the invalidation (60 s), so an entry stamped with the earlier version (or none) can
 * never become current again when the nonce expires.
 */
export const ENTITY_CACHE_VERSION_TTL_SECONDS = 3600;
export const API_KEY_LAST_USED_THROTTLE_SECONDS = 60;
/** `auth:lockouts:<userId>` lifetime: lockouts within 24 h double the next lockout. */
export const LOCKOUT_HISTORY_TTL_SECONDS = 86_400;
export const EMAIL_VERIFICATION_RESEND_LIMIT = 3;
export const EMAIL_VERIFICATION_RESEND_WINDOW_SECONDS = 3600;

/** Scopes an API key can never hold (D11). */
export const API_KEY_FORBIDDEN_SCOPES: ReadonlySet<string> = new Set([
  'apikey:manage',
  'role:manage',
  'session:manage',
]);

/** `user_sessions.revoked_reason` values. */
export const RevokeReason = {
  rotated: 'rotated',
  reuseDetected: 'reuse_detected',
  logout: 'logout',
  logoutAll: 'logout_all',
  userRevoked: 'user_revoked',
  adminRevoked: 'admin_revoked',
  passwordChanged: 'password_changed',
  passwordReset: 'password_reset',
  mfaEnabled: 'mfa_enabled',
  mfaDisabled: 'mfa_disabled',
  mfaReset: 'mfa_reset',
  userDisabled: 'user_disabled',
  userDeleted: 'user_deleted',
  organizationSuspended: 'organization_suspended',
  organizationDeleted: 'organization_deleted',
} as const;
export type RevokeReason = (typeof RevokeReason)[keyof typeof RevokeReason];

/** `login_audit_logs.failure_reason` values (D6). */
export type LoginFailureReason =
  | 'ip_blocked'
  | 'unknown_account'
  | 'account_locked'
  | 'not_activated'
  | 'invalid_password'
  | 'lockout_started'
  | 'user_disabled'
  | 'org_inactive'
  | 'invalid_challenge'
  | 'invalid_mfa_code'
  | 'mfa_attempts_exceeded';

export const SESSION_PURGE_INTERVAL_MS = 60 * 60 * 1000;
export const SESSION_PURGE_LOCK_SECONDS = 55 * 60;
export const SESSION_PURGE_BATCH = 1000;
/** Expired session rows are kept one more day (reuse detection of just-expired families). */
export const SESSION_PURGE_GRACE_MS = 24 * 60 * 60 * 1000;
export const TOKEN_PURGE_GRACE_MS = 7 * 24 * 60 * 60 * 1000;
