import type { ApprovalReason } from './release';
import type { QuarantineSettings } from './settings';
import {
  QUARANTINE_PERMISSIONS as P,
  riskLevelRank,
  type QuarantineApprovalKind,
  type QuarantineApprovalStatus,
  type QuarantineEntryKind,
  type QuarantineReason,
  type QuarantineRiskLevel,
  type QuarantineState,
} from './vocabulary';

/**
 * Who may do what (step 5.3 Q10, Q14, Q15; ADR-0047): separation of duties for approvals,
 * end-user self-service, and the `allowedActions` of an entry for a caller (frontend-ready).
 * Plain data in, decisions out; the api and the executor call the same functions.
 */

const lower = (s: string | null | undefined) => (s ?? '').trim().toLowerCase();

// ---------------------------------------------------------------------------------------------
// Q14 checkApprover
// ---------------------------------------------------------------------------------------------

export interface ApproverCheckInput {
  approver: {
    /** Principal type: API keys never approve. */
    type: 'user' | 'api_key';
    userId: string | null;
    /** The approver's own verified address (lower-cased by the check). */
    verifiedEmail: string | null;
    permissions: readonly string[];
  };
  request: {
    status: QuarantineApprovalStatus;
    kind: QuarantineApprovalKind;
    expiresAt: Date;
    requestedByType: 'system' | 'user' | 'api_key';
    requestedByUserId: string | null;
    /**
     * `api_keys.created_by_user_id` of the requesting key (`requestedByType = api_key`): the user
     * accountable for the key's requests. Null for other requesters, and for a key whose creator
     * no longer exists (a deleted user cannot approve).
     */
    requestedByApiKeyCreatorUserId: string | null;
  };
  entry: { userId: string | null; recipientAddress: string };
  now: Date;
}

/** The requester columns of an approval request that separation of duties compares. */
export interface ApprovalRequester {
  requestedByType: 'system' | 'user' | 'api_key';
  requestedByUserId: string | null;
  requestedByApiKeyCreatorUserId: string | null;
}

/**
 * Q14: whether `userId` is accountable for the request: the requesting user, or the creator of
 * the requesting API key (a user who triggers a release with their own key is its requester).
 * The api (`checkApprover`) and the executor's re-check of the stored decision use this rule.
 */
export function isAccountableRequester(request: ApprovalRequester, userId: string): boolean {
  if (request.requestedByType === 'user') return request.requestedByUserId === userId;
  if (request.requestedByType === 'api_key') {
    return request.requestedByApiKeyCreatorUserId === userId;
  }
  return false;
}

export type ApproverCheck =
  | { allowed: true }
  | {
      allowed: false;
      code: 'quarantine_approval_forbidden' | 'quarantine_approval_not_pending';
      reason:
        'api_key' | 'missing_permission' | 'not_pending' | 'expired' | 'requester' | 'recipient';
    };

/**
 * Q14: an approver is a user (never an API key) holding `quarantine:approve`, the request is
 * `pending` and not expired, and the approver is neither the requester (the requesting user, or
 * the creator of the requesting API key: `isAccountableRequester`) nor the entry's recipient
 * (by user id or own verified address). End users hold only `quarantine:self` and therefore
 * fail the permission check.
 */
export function checkApprover(input: ApproverCheckInput): ApproverCheck {
  const { approver, request, entry } = input;
  const forbidden = (reason: 'api_key' | 'missing_permission' | 'requester' | 'recipient') =>
    ({ allowed: false, code: 'quarantine_approval_forbidden', reason }) as const;
  if (approver.type !== 'user' || approver.userId === null) return forbidden('api_key');
  if (!approver.permissions.includes(P.approve)) return forbidden('missing_permission');
  if (request.status !== 'pending') {
    return { allowed: false, code: 'quarantine_approval_not_pending', reason: 'not_pending' };
  }
  if (request.expiresAt.getTime() <= input.now.getTime()) {
    return { allowed: false, code: 'quarantine_approval_not_pending', reason: 'expired' };
  }
  if (isAccountableRequester(request, approver.userId)) return forbidden('requester');
  if (
    (entry.userId !== null && entry.userId === approver.userId) ||
    (approver.verifiedEmail !== null &&
      lower(approver.verifiedEmail) === lower(entry.recipientAddress))
  ) {
    return forbidden('recipient');
  }
  return { allowed: true };
}

// ---------------------------------------------------------------------------------------------
// Q15 checkSelfService
// ---------------------------------------------------------------------------------------------

export const SELF_SERVICE_ACTIONS = [
  'view',
  'preview',
  'release',
  'request_release',
  'preferences',
] as const;
export type SelfServiceAction = (typeof SELF_SERVICE_ACTIONS)[number];

export interface SelfServiceInput {
  action: SelfServiceAction;
  settings: Pick<QuarantineSettings, 'endUser' | 'digest'>;
  caller: {
    type: 'user' | 'api_key';
    verifiedEmail: string | null;
    permissions: readonly string[];
  };
  /** Not needed for `preferences`. */
  entry?: {
    recipientAddress: string;
    state: QuarantineState;
    reason: QuarantineReason;
    riskLevel: QuarantineRiskLevel | null;
    hasHardBlock: boolean;
  };
  /** `release`: the pre-check's approval reasons and staleness (advisory; the executor decides). */
  approvalReasons?: readonly ApprovalReason[];
  stale?: boolean;
  /** `preferences` updates: the request changes `digestOptOut`. */
  changesDigestOptOut?: boolean;
}

export type SelfServiceCause =
  | 'not_user'
  | 'missing_permission'
  | 'no_verified_email'
  | 'end_user_disabled'
  | 'not_own_entry'
  | 'state'
  | 'preview_disabled'
  | 'preview_not_allowed'
  | 'self_release_disabled'
  | 'reason_not_allowed'
  | 'level_unknown'
  | 'level_too_high'
  | 'approval_required'
  | 'stale'
  | 'request_release_disabled'
  | 'opt_out_not_allowed';

export type SelfServiceCheck =
  | { allowed: true }
  | {
      allowed: false;
      code:
        | 'quarantine_entry_not_found'
        | 'quarantine_state_conflict'
        | 'quarantine_preview_not_allowed'
        | 'quarantine_self_release_not_allowed'
        | 'quarantine_settings_invalid'
        | 'forbidden';
      cause: SelfServiceCause;
    };

/**
 * Q15: own verified address only (another address → `404`, never `403`), the tenant's
 * self-service switches, and the self-release bounds (reason ⊆ `selfReleaseReasons`,
 * level ≤ `selfReleaseMaxLevel`, no approval reason, not stale).
 */
export function checkSelfService(input: SelfServiceInput): SelfServiceCheck {
  const { caller, settings, entry } = input;
  const eu = settings.endUser;
  const no = (
    code: Exclude<SelfServiceCheck, { allowed: true }>['code'],
    cause: SelfServiceCause,
  ) => ({ allowed: false, code, cause }) as const;
  if (caller.type !== 'user') return no('forbidden', 'not_user');
  if (!caller.permissions.includes(P.self)) return no('forbidden', 'missing_permission');
  if (caller.verifiedEmail === null || caller.verifiedEmail.trim() === '') {
    return no('forbidden', 'no_verified_email');
  }
  if (!eu.enabled) return no('quarantine_entry_not_found', 'end_user_disabled');
  if (input.action === 'preferences') {
    if (input.changesDigestOptOut === true && !settings.digest.allowOptOut) {
      return no('quarantine_settings_invalid', 'opt_out_not_allowed');
    }
    return { allowed: true };
  }
  if (!entry || lower(entry.recipientAddress) !== lower(caller.verifiedEmail)) {
    return no('quarantine_entry_not_found', 'not_own_entry');
  }
  switch (input.action) {
    case 'view':
      return { allowed: true };
    case 'preview':
      if (!eu.preview) return no('quarantine_preview_not_allowed', 'preview_disabled');
      if (entry.hasHardBlock || entry.reason === 'malware' || entry.reason === 'phishing') {
        return no('quarantine_preview_not_allowed', 'preview_not_allowed');
      }
      return { allowed: true };
    case 'request_release':
      if (!eu.requestRelease) {
        return no('quarantine_self_release_not_allowed', 'request_release_disabled');
      }
      if (entry.state !== 'held') return no('quarantine_state_conflict', 'state');
      return { allowed: true };
    case 'release': {
      if (entry.state !== 'held') return no('quarantine_state_conflict', 'state');
      const refuse = (cause: SelfServiceCause) => no('quarantine_self_release_not_allowed', cause);
      if (!eu.selfRelease) return refuse('self_release_disabled');
      if (!(eu.selfReleaseReasons as readonly string[]).includes(entry.reason)) {
        return refuse('reason_not_allowed');
      }
      if (entry.riskLevel === null) return refuse('level_unknown');
      if (riskLevelRank(entry.riskLevel) > riskLevelRank(eu.selfReleaseMaxLevel)) {
        return refuse('level_too_high');
      }
      if (entry.hasHardBlock || (input.approvalReasons ?? []).length > 0) {
        return refuse('approval_required');
      }
      if (input.stale === true) return refuse('stale');
      return { allowed: true };
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Q10 allowedActionsFor
// ---------------------------------------------------------------------------------------------

export const ENTRY_ACTIONS = [
  'preview',
  'release',
  'request_release',
  'reject',
  'delete',
  'download',
] as const;
export type EntryAction = (typeof ENTRY_ACTIONS)[number];

export interface AllowedActionsInput {
  entry: {
    state: QuarantineState;
    kind: QuarantineEntryKind;
    reason: QuarantineReason;
    riskLevel: QuarantineRiskLevel | null;
    hasHardBlock: boolean;
    /** The message content still exists (`object_purged_at` is null). */
    contentAvailable: boolean;
  };
  permissions: readonly string[];
  settings: Pick<QuarantineSettings, 'endUser' | 'release' | 'download'>;
  /** The caller is the entry's recipient on a self route (`quarantine:self`). */
  isSelf: boolean;
}

const HELD_OR_PENDING: readonly QuarantineState[] = ['held', 'pending_approval'];
const DELETABLE: readonly QuarantineState[] = ['held', 'pending_approval', 'rejected', 'expired'];

/**
 * Q10: the actions the caller may attempt now (advisory for the portal; every route re-checks).
 * Self callers: preview, release (self-release bounds) and request_release only.
 */
export function allowedActionsFor(input: AllowedActionsInput): EntryAction[] {
  const { entry, permissions, settings, isSelf } = input;
  const has = (p: string) => permissions.includes(p);
  const out = new Set<EntryAction>();
  const dangerous = entry.hasHardBlock || entry.reason === 'malware' || entry.reason === 'phishing';
  const held = entry.state === 'held';
  if (isSelf) {
    const eu = settings.endUser;
    if (!has(P.self) || !eu.enabled) return [];
    if (eu.preview && !dangerous && entry.contentAvailable) out.add('preview');
    if (
      held &&
      eu.selfRelease &&
      !entry.hasHardBlock &&
      entry.kind === 'quarantine' &&
      (eu.selfReleaseReasons as readonly string[]).includes(entry.reason) &&
      entry.riskLevel !== null &&
      riskLevelRank(entry.riskLevel) <= riskLevelRank(eu.selfReleaseMaxLevel)
    ) {
      out.add('release');
    }
    if (held && eu.requestRelease) out.add('request_release');
  } else {
    if (has(P.preview) && entry.contentAvailable && entry.state !== 'deleted') out.add('preview');
    if (has(P.release) && held && (!entry.hasHardBlock || settings.release.allowHardBlocks)) {
      out.add('release');
    }
    if (has(P.requestRelease) && held) out.add('request_release');
    if (has(P.reject) && HELD_OR_PENDING.includes(entry.state)) out.add('reject');
    if (has(P.delete) && DELETABLE.includes(entry.state)) out.add('delete');
    if (
      has(P.download) &&
      settings.download.enabled &&
      entry.contentAvailable &&
      entry.state !== 'deleted' &&
      !dangerous
    ) {
      out.add('download');
    }
  }
  return ENTRY_ACTIONS.filter((a) => out.has(a));
}
