import type { ApiError } from '@/lib/api/errors';
import type { ListItem, RequestBody, SuccessBody } from '@/lib/api/types';
import type { Tone } from '@/lib/design/tokens';
import { humanize } from '@/lib/format';

/**
 * Shared model of the account takeover pages (step 8.4 §6, D18; docs/plan/steps/24-account-takeover-core.md):
 * response types of the generated client, the vocabularies the pages offer as filters (typed
 * against the client, so an api change fails the typecheck), tones, routes and the texts of the
 * coded errors of §5. The api stays authoritative for every rule: the portal hides what a caller
 * may not do and explains refusals; it never evaluates detection, scoring or policy logic.
 */

export type AtoOverview = SuccessBody<'AtoOverviewController_overview_v1'>;
export type AtoAttention = SuccessBody<'AtoOverviewController_attention_v1'>;
export type AtoAccount = ListItem<'AtoAccountsController_list_v1'>;
export type AtoAccountDetail = SuccessBody<'AtoAccountsController_get_v1'>;
export type AtoSignal = ListItem<'AtoAccountsController_signals_v1'>;
export type AtoAuthEvent = ListItem<'AtoAccountsController_authEvents_v1'>;
export type AtoScorePoint = ListItem<'AtoAccountsController_scoreHistory_v1'>;
export type AtoActivity = SuccessBody<'AtoAccountsController_activity_v1'>;
export type AtoResponse = ListItem<'AtoResponsesController_list_v1'>;
export type AtoResponseDetail = SuccessBody<'AtoResponsesController_get_v1'>;
export type AtoRestriction = ListItem<'AtoRestrictionsController_list_v1'>;
export type AtoSettings = SuccessBody<'AtoSettingsController_get_v1'>;
export type AtoRules = SuccessBody<'AtoRulesController_list_v1'>;
export type AtoRule = AtoRules['data'][number];
export type AtoCapabilities = AtoAccountDetail['capabilities'];
export type AtoRequestBody = RequestBody<'AtoResponsesController_request_v1'>;
export type AtoTrustedContext = AtoAccountDetail['trustedContexts'][number];

export type AtoAccountKind = AtoAccount['kind'];
export type AtoRiskLevel = AtoAccount['riskLevel'];
export type AtoResponseStatus = AtoResponse['status'];
export type AtoActionType = AtoResponse['actionType'];
export type AtoSignalCategory = AtoSignal['category'];
export type AtoAuthOutcome = AtoAuthEvent['outcome'];
export type AtoAuthSource = AtoAuthEvent['source'];
export type TrustedContextKind = AtoTrustedContext['kind'];

/** Lists typed against the client: `satisfies` fails when the api adds or renames a value. */
export const ATO_ACCOUNT_KINDS = [
  'mailbox',
  'gateway_user',
  'smtp_connector',
] as const satisfies readonly AtoAccountKind[];
export const ATO_RISK_LEVELS = [
  'low',
  'medium',
  'high',
  'critical',
] as const satisfies readonly AtoRiskLevel[];
export const ATO_RESPONSE_STATUSES = [
  'pending_approval',
  'approved',
  'executing',
  'succeeded',
  'failed',
  'rejected',
  'cancelled',
  'expired',
  'unsupported',
  'rollback_requested',
  'rolled_back',
  'rollback_failed',
  'attested',
] as const satisfies readonly AtoResponseStatus[];
export const ATO_ACTION_TYPES = [
  'alert_tenant_admins',
  'notify_soc',
  'escalate_investigation',
  'restrict_smtp_sending',
  'block_smtp_auth',
  'record_manual_action',
  'revoke_sessions',
  'require_mfa',
  'require_password_reset',
  'suspend_account',
  'remove_forwarding_rule',
  'revoke_oauth_grant',
] as const satisfies readonly AtoActionType[];
export const ATO_SIGNAL_CATEGORIES = [
  'authentication',
  'access_context',
  'geography',
  'threat_intel',
  'account_change',
  'outbound_behaviour',
  'outbound_content',
  'mailbox_configuration',
  'oauth_activity',
  'provider_risk',
  'correlation',
] as const satisfies readonly AtoSignalCategory[];
export const ATO_AUTH_OUTCOMES = [
  'success',
  'failure',
  'locked',
  'mfa_required',
  'mfa_failure',
  'rate_limited',
  'throttled',
  'blocked',
] as const satisfies readonly AtoAuthOutcome[];
export const ATO_AUTH_SOURCES = [
  'portal_login',
  'portal_mfa',
  'smtp_auth',
  'idp_sign_in',
] as const satisfies readonly AtoAuthSource[];
export const TRUSTED_CONTEXT_KINDS = [
  'ip_cidr',
  'asn',
  'country',
  'device',
] as const satisfies readonly TrustedContextKind[];
export const OVERVIEW_RANGES = ['24h', '7d', '30d'] as const;
export type OverviewRange = (typeof OVERVIEW_RANGES)[number];

/** Statuses that still need a decision or are in progress (the "pending approvals first" view). */
export const PENDING_STATUSES = [
  'pending_approval',
] as const satisfies readonly AtoResponseStatus[];

/**
 * Gateway response types an analyst may request in 8.4 with their impact (D13 catalogue). Provider
 * actions (revoke sessions, require MFA, …) need an identity-provider adapter (step 8.5): the api
 * records them as `unsupported`, so the portal does not offer them as buttons.
 */
export const REQUESTABLE_ACTIONS: ReadonlyArray<{
  type: AtoActionType;
  impact: 'low' | 'medium' | 'high';
  kinds: readonly AtoAccountKind[];
  needsDuration: boolean;
}> = [
  { type: 'alert_tenant_admins', impact: 'low', kinds: ATO_ACCOUNT_KINDS, needsDuration: false },
  { type: 'notify_soc', impact: 'low', kinds: ATO_ACCOUNT_KINDS, needsDuration: false },
  {
    type: 'escalate_investigation',
    impact: 'low',
    kinds: ATO_ACCOUNT_KINDS,
    needsDuration: false,
  },
  {
    type: 'restrict_smtp_sending',
    impact: 'high',
    kinds: ['mailbox', 'smtp_connector'],
    needsDuration: true,
  },
  { type: 'block_smtp_auth', impact: 'high', kinds: ['smtp_connector'], needsDuration: true },
  {
    type: 'record_manual_action',
    impact: 'low',
    kinds: ATO_ACCOUNT_KINDS,
    needsDuration: false,
  },
];

export const ACTION_LABELS: Record<AtoActionType, string> = {
  alert_tenant_admins: 'Alert tenant administrators',
  notify_soc: 'Notify the SOC',
  escalate_investigation: 'Escalate the investigation',
  restrict_smtp_sending: 'Restrict SMTP sending',
  block_smtp_auth: 'Block SMTP authentication',
  record_manual_action: 'Record a manual action',
  revoke_sessions: 'Revoke sessions',
  require_mfa: 'Require MFA',
  require_password_reset: 'Require a password reset',
  suspend_account: 'Suspend the account',
  remove_forwarding_rule: 'Remove a forwarding rule',
  revoke_oauth_grant: 'Revoke an OAuth grant',
};

export const KIND_LABELS: Record<AtoAccountKind, string> = {
  mailbox: 'Mailbox',
  gateway_user: 'Portal user',
  smtp_connector: 'SMTP connector',
};

export const CATEGORY_LABELS: Record<AtoSignalCategory, string> = {
  authentication: 'Authentication',
  access_context: 'Access context',
  geography: 'Geography',
  threat_intel: 'Threat intelligence',
  account_change: 'Account changes',
  outbound_behaviour: 'Outbound behaviour',
  outbound_content: 'Outbound content',
  mailbox_configuration: 'Mailbox configuration',
  oauth_activity: 'OAuth activity',
  provider_risk: 'Identity-provider risk',
  correlation: 'Correlation',
};

export const LEVEL_TONE: Readonly<Record<string, Tone>> = {
  low: 'info',
  medium: 'warning',
  high: 'orange',
  critical: 'danger',
};

export const RESPONSE_STATUS_TONE: Readonly<Record<string, Tone>> = {
  pending_approval: 'purple',
  approved: 'info',
  executing: 'info',
  succeeded: 'success',
  failed: 'danger',
  rejected: 'neutral',
  cancelled: 'neutral',
  expired: 'neutral',
  unsupported: 'warning',
  rollback_requested: 'info',
  rolled_back: 'neutral',
  rollback_failed: 'danger',
  attested: 'success',
};

export const RESTRICTION_STATUS_TONE: Readonly<Record<string, Tone>> = {
  active: 'danger',
  lifted: 'neutral',
  expired: 'neutral',
};

export const SIGNAL_STRENGTH_TONE: Readonly<Record<string, Tone>> = {
  weak: 'neutral',
  moderate: 'warning',
  strong: 'danger',
};

export const SIGNAL_STATUS_TONE: Readonly<Record<string, Tone>> = {
  active: 'warning',
  dismissed: 'neutral',
  informational: 'info',
};

export const OUTCOME_TONE: Readonly<Record<string, Tone>> = {
  success: 'success',
  failure: 'danger',
  locked: 'danger',
  mfa_required: 'info',
  mfa_failure: 'danger',
  rate_limited: 'warning',
  throttled: 'warning',
  blocked: 'danger',
};

export const CAPABILITY_TONE: Readonly<Record<string, Tone>> = {
  available: 'success',
  unavailable: 'neutral',
  stale: 'warning',
  unknown: 'neutral',
};

export const labelOf = <K extends string>(labels: Record<K, string>, value: string): string =>
  (labels as Record<string, string>)[value] ?? humanize(value);

// ---- routes ----------------------------------------------------------------------------------

export const atoAccountHref = (id: string, tab?: string) =>
  `/ato/accounts/${id}${tab ? `?tab=${tab}` : ''}`;
export const atoResponsesHref = (status?: string) =>
  `/ato/responses${status ? `?status=${status}` : ''}`;
export const atoSettingsHref = (tab?: string) => `/ato/settings${tab ? `?tab=${tab}` : ''}`;
export const incidentHref = (id: string) => `/incidents/${id}`;
export const atoIncidentsHref = (extra: Record<string, string> = {}) =>
  `/incidents?${new URLSearchParams({ category: 'account_takeover', ...extra }).toString()}`;
export const messageHref = (id: string) => `/messages/${id}`;
/** The builder's new-policy page started from the ATO test example (D23). */
export const policyPresetHref = (preset: string) =>
  `/policies/new?${new URLSearchParams({ testPreset: preset }).toString()}`;

/** The account's display text: address, user display name or connector name (never masked: D20). */
export function accountLabel(account: {
  kind: string;
  address: string | null;
  displayName: string | null;
  id: string;
}): string {
  if (account.kind === 'mailbox') return account.address ?? account.id;
  return account.displayName ?? account.address ?? account.id;
}

// ---- errors ----------------------------------------------------------------------------------

/** Human texts of the coded ATO and incident errors (§5, D17); unknown codes keep the api text. */
export function explainAtoError(error: ApiError): string[] {
  const d = error.details;
  switch (error.code) {
    case 'ato_not_enabled':
      return [
        'Account takeover detection is not enabled for this organization. A platform operator enables it per organization.',
      ];
    case 'ato_account_not_found':
    case 'ato_response_not_found':
    case 'incident_not_found':
      return ['It does not exist or is not visible to you.'];
    case 'ato_account_conflict':
    case 'incident_conflict':
      return ['Someone else changed it since you opened it. Reload and try again.'];
    case 'ato_settings_conflict':
      return [
        'The settings were changed by someone else since you opened them. Reload to see the current version, then apply your change again.',
      ];
    case 'ato_settings_invalid': {
      const issues = Array.isArray(d.issues) ? d.issues : [];
      const lines = issues.flatMap((issue) => {
        const i = issue as { path?: unknown; message?: unknown };
        return typeof i.message === 'string'
          ? [`${typeof i.path === 'string' && i.path ? `${i.path}: ` : ''}${i.message}`]
          : [];
      });
      return lines.length > 0 ? lines : ['The settings are not valid.'];
    }
    case 'ato_response_active':
      return [
        'The same response is already pending or in progress for this incident and target. Decide or cancel it first.',
      ];
    case 'ato_response_state':
      return ['The response is no longer in a state that allows this (it was decided or ended).'];
    case 'ato_response_expired':
      return ['The approval window has passed; the response expired. Request it again.'];
    case 'ato_response_invalid':
      return ['This response cannot be requested for this account or target.'];
    case 'ato_approval_self':
      return [
        'Separation of duties: the person who requested a response cannot approve it. Another analyst with ato:respond must decide.',
      ];
    case 'ato_approver_invalid':
      return ['Approvals need a signed-in user with ato:respond (API keys cannot approve).'];
    case 'ato_rollback_unsupported':
      return ['This response cannot be rolled back.'];
    case 'ato_override_invalid':
      return ['The override is not valid for this account.'];
    case 'ato_override_not_found':
      return ['The account has no active override.'];
    case 'ato_trusted_context_invalid':
      return ['The trusted context is not valid (check the CIDR, ASN, country code or device).'];
    case 'ato_trusted_context_not_found':
      return ['The trusted context no longer exists.'];
    case 'incident_transition_invalid':
      return [
        `This status change is not allowed${typeof d.from === 'string' && typeof d.to === 'string' ? ` (${humanize(d.from)} → ${humanize(d.to)})` : ''}.`,
      ];
    case 'incident_active':
      return ['The account already has an active incident.'];
    case 'incident_subject_not_found':
      return ['The account was not found in this organization.'];
    case 'incident_assignee_invalid':
      return ['The assignee must be an active user of this organization.'];
    case 'incident_closed':
      return ['The incident is closed; it cannot be changed.'];
    case 'incident_feedback_invalid':
      return ['The false-positive feedback is not valid (check the trusted contexts).'];
    case 'mfa_required':
      return ['This action needs a session signed in with MFA. Sign in again with MFA.'];
    default:
      return Array.isArray(error.apiMessage) ? error.apiMessage : [error.message];
  }
}

/** Errors worth a manual retry of the same intent (same Idempotency-Key). */
export function isRetryable(error: ApiError | null): boolean {
  return Boolean(
    error &&
    (error.status === 0 || error.status >= 500 || error.code === 'idempotency_request_in_progress'),
  );
}

/** `ato:*` permission holders: helpers for the UI (the api decides). */
export const ATO_PERMISSIONS = {
  read: 'ato:read',
  manage: 'ato:manage',
  respond: 'ato:respond',
  configure: 'ato:configure',
} as const;

/** Duration presets of a restriction request (15 min – 7 days, D13). */
export const DURATION_OPTIONS: ReadonlyArray<{ value: number; label: string }> = [
  { value: 60, label: '1 hour' },
  { value: 240, label: '4 hours' },
  { value: 1440, label: '1 day' },
  { value: 4320, label: '3 days' },
  { value: 10_080, label: '7 days' },
];

export function formatMinutes(minutes: number | null | undefined): string {
  if (minutes === null || minutes === undefined) return '—';
  if (minutes % 1440 === 0) return `${minutes / 1440} day${minutes === 1440 ? '' : 's'}`;
  if (minutes % 60 === 0) return `${minutes / 60} hour${minutes === 60 ? '' : 's'}`;
  return `${minutes} min`;
}

/** Text of a capability state (D17: `unknown` when the worker has not reported for 15 min). */
export function capabilityText(state: string): string {
  switch (state) {
    case 'available':
      return 'Available';
    case 'unavailable':
      return 'Not configured';
    case 'stale':
      return 'Out of date';
    default:
      return 'Unknown (no recent worker report)';
  }
}

/** The country name of an ISO code where the browser knows it, else the code. */
export function countryName(code: string | null | undefined): string {
  if (!code) return '—';
  try {
    const names = new Intl.DisplayNames(['en'], { type: 'region' });
    return names.of(code.toUpperCase()) ?? code;
  } catch {
    return code;
  }
}

/** A JSON scalar as text (`''` for objects, arrays, null and undefined). */
export function str(value: unknown): string {
  return typeof value === 'string'
    ? value
    : typeof value === 'number' || typeof value === 'boolean'
      ? String(value)
      : '';
}
