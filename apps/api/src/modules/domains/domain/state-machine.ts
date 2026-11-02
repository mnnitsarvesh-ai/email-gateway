import { ConflictException } from '@nestjs/common';
import type { DomainStatus } from '@email-gateway/database';

/**
 * Domain lifecycle (D3). `disabled` (step 1.1) is deprecated: never written, treated like
 * `suspended` by the mail path, and can only be deleted.
 */
export type DomainLifecycleEvent =
  | 'ownership_verified'
  | 'claim_superseded'
  | 'verification_expired'
  | 'verification_restarted'
  | 'activate'
  | 'suspend'
  | 'delete';

interface TransitionRule {
  from: readonly DomainStatus[];
  to: DomainStatus;
}

const RULES: Readonly<Record<DomainLifecycleEvent, TransitionRule>> = {
  ownership_verified: { from: ['pending_verification'], to: 'verified' },
  claim_superseded: { from: ['pending_verification'], to: 'failed' },
  verification_expired: { from: ['pending_verification'], to: 'failed' },
  verification_restarted: { from: ['failed'], to: 'pending_verification' },
  activate: { from: ['verified', 'suspended'], to: 'active' },
  suspend: { from: ['active'], to: 'suspended' },
  delete: {
    from: ['pending_verification', 'verified', 'failed', 'suspended', 'disabled'],
    to: 'deleted',
  },
};

/** Statuses that follow ownership verification (globally unique `verified_name`, D3). */
export const OWNED_STATUSES: ReadonlySet<DomainStatus> = new Set([
  'verified',
  'active',
  'suspended',
]);

/** Statuses whose DNS records the background job keeps checking (D11). */
export const CHECKED_STATUSES: ReadonlySet<DomainStatus> = new Set([
  'pending_verification',
  'verified',
  'active',
  'suspended',
]);

export const SUSPEND_BEFORE_DELETE = 'Suspend the domain before deleting it';

export function canTransition(from: DomainStatus, event: DomainLifecycleEvent): boolean {
  return RULES[event].from.includes(from);
}

/** The status `event` leads to from `from`; `409` when the transition is not allowed (D3). */
export function nextStatus(from: DomainStatus, event: DomainLifecycleEvent): DomainStatus {
  if (canTransition(from, event)) return RULES[event].to;
  if (event === 'delete' && from === 'active') throw new ConflictException(SUSPEND_BEFORE_DELETE);
  throw new ConflictException(`Domain is ${from}`);
}

/** The lifecycle event of `PATCH /domains/{id}/status`. */
export function statusChangeEvent(to: 'active' | 'suspended'): DomainLifecycleEvent {
  return to === 'active' ? 'activate' : 'suspend';
}
