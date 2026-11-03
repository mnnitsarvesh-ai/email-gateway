/** Constants of the domains module (step 2.1, docs/plan/steps/03-domain-onboarding.md). */

/** `audit_logs.resource_type` of every domain audit row (D15). */
export const DOMAIN_RESOURCE_TYPE = 'domain';

/** `message_outbox.aggregate_type` of domain events (D15). */
export const DOMAIN_AGGREGATE_TYPE = 'domain';

/** Audit actions (D15). Metadata never carries keys, tokens or full evidence. */
export const DomainAuditAction = {
  Created: 'domain.created',
  Verified: 'domain.verified',
  VerificationExpired: 'domain.verification_expired',
  VerificationRestarted: 'domain.verification_restarted',
  ClaimSuperseded: 'domain.claim_superseded',
  StatusChanged: 'domain.status_changed',
  Deleted: 'domain.deleted',
  DkimRotationStarted: 'domain.dkim_rotation_started',
  DkimKeyActivated: 'domain.dkim_key_activated',
  DkimKeyRetired: 'domain.dkim_key_retired',
  OwnershipRecordMissing: 'domain.ownership_record_missing',
  // Step 2.2 (D3, §4.1): inbound recipient validation; metadata carries modes and counts only.
  RecipientValidationChanged: 'domain.recipient_validation_changed',
  RecipientsAdded: 'domain.recipients_added',
  RecipientsRemoved: 'domain.recipients_removed',
} as const;
export type DomainAuditAction = (typeof DomainAuditAction)[keyof typeof DomainAuditAction];

/** `domains.status_reason` values written by the system (D3, D4). */
export const DomainStatusReason = {
  ClaimedByAnotherOrganization: 'claimed_by_another_organization',
  VerificationExpired: 'verification_expired',
} as const;

/** Key-value store keys (all under the store's `eg:` prefix, §3). */
export const domainKvKeys = {
  /** Scheduler tick lock: one replica runs each tick (D11). */
  tickLock: 'jobs:domain-checks',
  /** Per-domain check lock, taken by the scheduler and by manual verification. */
  checkLock: (domainId: bigint) => `domains:check:${domainId}`,
  /** Per-domain manual verification counter (§4). */
  verifyCounter: (domainId: bigint) => `domains:verify:${domainId}`,
  /** Per-domain DKIM rotation counter (§4, D9). */
  rotateCounter: (domainId: bigint) => `domains:rotate:${domainId}`,
  /** DKIM signing-key sync tick lock: one replica publishes per tick (step 2.2 D12). */
  dkimSyncLock: 'jobs:dkim-signing-sync',
};

/** Per-domain check lock lifetime (D11). */
export const CHECK_LOCK_SECONDS = 120;
/** Manual verifications allowed per domain per window (§4). */
export const VERIFY_LIMIT_PER_WINDOW = 6;
export const VERIFY_WINDOW_SECONDS = 60;
/**
 * DKIM rotations allowed per domain per window (§4, D9). Bounds key generation and the growth
 * of `domain_dkim_keys` (each replaced pending key stays as a revoked row) and `audit_logs`.
 */
export const ROTATE_LIMIT_PER_WINDOW = 10;
export const ROTATE_WINDOW_SECONDS = 86_400;
/** How long a scheduler claim keeps a domain away from other replicas (D11). */
export const CLAIM_SECONDS = 5 * 60;
/** A new domain is checked for the first time after this delay (D3). */
export const FIRST_CHECK_DELAY_SECONDS = 60;
/** Rotating DKIM keys retired per tick (D11). */
export const RETIREMENT_BATCH_SIZE = 100;
/** Retired DKIM selectors stay listed (detail and `cleanup`) this long (§4, D9). */
export const RETIRED_KEY_LISTING_DAYS = 30;

export const DAY_MS = 86_400_000;
