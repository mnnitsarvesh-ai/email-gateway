/**
 * Purge approval (step API-3, design note 37 C6, C-I4, ADR-0103 (3)): when a clawback needs a
 * second person, and whether a principal may approve or deny it. The rules mirror 5.3 Q14
 * `checkApprover` of `@email-gateway/quarantine` (user principal, permission, request pending and
 * not expired, not the requester) without the recipient rule: a purge is a tenant-wide operation,
 * so an owner of a target mailbox may approve. Pure; the api calls it for approve and deny.
 */
import type { RemediationAction } from '../remediation/vocabulary';
import {
  REMEDIATION_PURGE_PERMISSION,
  type ClawbackApprovalReason,
  type ClawbackApprovalStatus,
} from './vocabulary';

export interface PurgeApprovalNeedInput {
  /** `api_clawbacks.mailboxes_eligible`. */
  mailboxesEligible: number;
  /** `api_mode_org_settings.purge_approval_mailboxes` (P2, default 50). */
  threshold: number;
  /** The submitted action (explicit) or null (policy mode). */
  action: RemediationAction | null;
  /** The clawback entered `review_required` because of the automatic cap. */
  autoCap: boolean;
}

/**
 * C6 "When": `mailbox_threshold` when the eligible targets span more than `threshold` distinct
 * mailboxes, `hard_delete` for a hard-delete purge, `auto_cap` for an automatic clawback held at
 * its cap. Reasons in that order; `required` when any applies.
 */
export function requiresPurgeApproval(input: PurgeApprovalNeedInput): {
  required: boolean;
  reasons: ClawbackApprovalReason[];
} {
  const reasons: ClawbackApprovalReason[] = [];
  if (input.mailboxesEligible > input.threshold) reasons.push('mailbox_threshold');
  if (input.action === 'hard_delete') reasons.push('hard_delete');
  if (input.autoCap) reasons.push('auto_cap');
  return { required: reasons.length > 0, reasons };
}

export interface PurgeApprovalDecisionInput {
  approver: {
    /** Principal type: API keys never approve. */
    type: 'user' | 'api_key';
    userId: string | null;
    permissions: readonly string[];
  };
  request: {
    status: ClawbackApprovalStatus | null;
    expiresAt: Date | null;
    /** `api_clawbacks.requested_by_user_id` (null for a system clawback). */
    requestedByUserId: string | null;
    /** `api_clawbacks.submitted_by_user_id`. */
    submittedByUserId: string | null;
  };
  now: Date;
}

export type PurgeApprovalForbiddenReason = 'api_key' | 'missing_permission' | 'requester';
export type PurgeApprovalNotPendingReason = 'not_pending' | 'expired';

export type PurgeApprovalDecision =
  | { allowed: true }
  | {
      allowed: false;
      code: 'api_mode_purge_approval_forbidden';
      reason: PurgeApprovalForbiddenReason;
    }
  | {
      allowed: false;
      code: 'api_mode_purge_approval_not_pending';
      reason: PurgeApprovalNotPendingReason;
    };

/**
 * C6 "Rules", in the order of `checkApprover`: not a user principal → `api_key`; without
 * `remediation:purge` → `missing_permission`; the request is not `pending` → `not_pending`; it
 * expired (`expiresAt ≤ now`, or no expiry stored) → `expired`; the approver is the requester or
 * the submitter (by user id) → `requester`. Applies to approve and deny alike.
 */
export function decidePurgeApproval(input: PurgeApprovalDecisionInput): PurgeApprovalDecision {
  const { approver, request } = input;
  const forbidden = (reason: PurgeApprovalForbiddenReason) =>
    ({ allowed: false, code: 'api_mode_purge_approval_forbidden', reason }) as const;
  const notPending = (reason: PurgeApprovalNotPendingReason) =>
    ({ allowed: false, code: 'api_mode_purge_approval_not_pending', reason }) as const;
  if (approver.type !== 'user' || approver.userId === null) return forbidden('api_key');
  if (!approver.permissions.includes(REMEDIATION_PURGE_PERMISSION)) {
    return forbidden('missing_permission');
  }
  if (request.status !== 'pending') return notPending('not_pending');
  if (request.expiresAt === null || request.expiresAt.getTime() <= input.now.getTime()) {
    return notPending('expired');
  }
  if (
    (request.requestedByUserId !== null && request.requestedByUserId === approver.userId) ||
    (request.submittedByUserId !== null && request.submittedByUserId === approver.userId)
  ) {
    return forbidden('requester');
  }
  return { allowed: true };
}
