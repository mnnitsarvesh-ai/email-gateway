import type { ApiError } from '@/lib/api/errors';
import type { RequestBody, SuccessBody } from '@/lib/api/types';
import type { Tone } from '@/lib/design/tokens';
import { humanize } from '@/lib/format';
import { explainAtoError } from '../model';

/**
 * Shared model of the identity-provider pages (step 8.5 §7, docs/plan/steps/26-ato-provider-adapters.md):
 * response types of the generated client, labels, tones and the plain-language texts of the
 * provider codes. The api and the ato-worker decide everything (eligibility, capabilities,
 * health, settings validation): the portal shows their answers as returned and never evaluates
 * provider data itself.
 */

export type ProviderList = SuccessBody<'AtoProvidersController_list_v1'>;
export type ProviderSummary = ProviderList['data'][number];
export type ProviderDetail = SuccessBody<'AtoProvidersController_get_v1'>;
export type ProviderStreamView = ProviderDetail['streamDetails'][number];
export type ProviderActionView = ProviderDetail['actions'][number];
export type ProviderProfileView = ProviderDetail['permissions']['profiles'][number];
export type ProviderRequirements = SuccessBody<'AtoProvidersController_requirements_v1'>;
export type ProviderRequirement = ProviderRequirements['providers'][number];
export type ProviderConnections = SuccessBody<'AtoProvidersController_connections_v1'>;
export type ProviderCandidate = ProviderConnections['data'][number];
export type MailboxState = SuccessBody<'AtoAccountMailboxController_get_v1'>;
export type MailboxItem = MailboxState['items'][number];
export type ProviderKind = ProviderSummary['provider'];
export type ProviderStream = ProviderStreamView['stream'];
export type ProviderActionType = ProviderActionView['action'];
export type CreateProviderBody = RequestBody<'AtoProvidersController_create_v1'>;

/** Every query a provider mutation can make stale. */
export const PROVIDER_QUERIES = [
  'AtoProvidersController_list_v1',
  'AtoProvidersController_get_v1',
  'AtoProvidersController_connections_v1',
  'AtoSettingsController_get_v1',
  'AtoAccountMailboxController_get_v1',
] as const;

export const PROVIDER_LABELS: Record<ProviderKind, string> = {
  microsoft_entra: 'Microsoft Entra ID / Microsoft 365',
  google_workspace: 'Google Workspace',
};

export const CONNECTION_PROVIDER_LABELS: Record<string, string> = {
  microsoft_365: 'Microsoft 365',
  google_workspace: 'Google Workspace',
};

/** Stream order of the design (§3.2); typed against the client. */
export const PROVIDER_STREAMS = [
  'sign_ins',
  'risk_events',
  'session_events',
  'oauth_consents',
  'mailbox_audit',
  'forwarding_changes',
  'delegation_changes',
] as const satisfies readonly ProviderStream[];

export const STREAM_LABELS: Record<ProviderStream, string> = {
  sign_ins: 'Sign-ins',
  risk_events: 'Risk events',
  session_events: 'Session and token events',
  oauth_consents: 'OAuth consents',
  mailbox_audit: 'Mailbox audit',
  forwarding_changes: 'Forwarding changes',
  delegation_changes: 'Delegation changes',
};

export const PROVIDER_ACTIONS = [
  'revoke_sessions',
  'require_mfa',
  'require_password_reset',
  'suspend_account',
  'remove_forwarding_rule',
  'revoke_oauth_grant',
] as const satisfies readonly ProviderActionType[];

export const HEALTH_TONE: Readonly<Record<string, Tone>> = {
  healthy: 'success',
  degraded: 'warning',
  unhealthy: 'danger',
  unknown: 'neutral',
};

export const INTEGRATION_STATUS_TONE: Readonly<Record<string, Tone>> = {
  active: 'success',
  paused: 'warning',
  error: 'danger',
  disabled: 'neutral',
};

export const STREAM_STATUS_TONE: Readonly<Record<string, Tone>> = {
  active: 'success',
  backfilling: 'info',
  paused: 'warning',
  error: 'danger',
  unsupported: 'neutral',
};

export const CAPABILITY_VIEW_TONE: Readonly<Record<string, Tone>> = {
  available: 'success',
  missing_permission: 'danger',
  missing_license: 'warning',
  not_configured: 'warning',
  not_offered: 'neutral',
  error: 'danger',
  unknown: 'neutral',
  disabled: 'neutral',
};

export const ELIGIBILITY_TONE: Readonly<Record<string, Tone>> = {
  eligible: 'success',
  already_bound: 'info',
  wrong_provider: 'neutral',
  inactive: 'warning',
};

const CAPABILITY_TEXT: Record<string, string> = {
  available: 'Available',
  missing_permission: 'Missing permission',
  missing_license: 'Missing licence',
  not_configured: 'Not configured',
  not_offered: 'Not offered by the provider',
  error: 'Error',
  unknown: 'Unknown (no recent probe)',
  disabled: 'Disabled in the settings',
};

export const capabilityViewText = (value: string): string =>
  CAPABILITY_TEXT[value] ?? humanize(value);

const HEALTH_TEXT: Record<string, string> = {
  healthy: 'Healthy',
  degraded: 'Degraded',
  unhealthy: 'Unhealthy',
  unknown: 'Not checked yet',
};

export const healthText = (value: string): string => HEALTH_TEXT[value] ?? humanize(value);

/**
 * Plain-language texts of the codes the worker and the api record (health, availability, pause
 * and disable reasons, stream errors, response result codes). Unknown codes keep a readable form
 * of the code itself, which is always printed next to the text.
 */
const CODE_TEXT: Record<string, string> = {
  user: 'By a user',
  connection_inactive: 'The Microsoft 365 / Google Workspace connection is not active',
  connection_removed: 'The connection was removed in the Integrations pages',
  telemetry_grant_missing: 'The connection has no account takeover telemetry grant',
  telemetry_grant_inactive: 'The account takeover telemetry grant is not active',
  directory_changed: 'The connection now points to another directory (tenant or customer)',
  directory_in_use: 'This directory is already monitored by another organization',
  directory_unverified: 'The directory of the connection is not verified',
  delegated_admin_missing: 'Google: no delegated administrator is configured for the grant',
  missing_permission: 'A required permission is not granted',
  missing_privileged_role: 'The application lacks the administrator role this action needs',
  missing_license: 'The provider licence that this needs is missing',
  not_probed: 'Waiting for the first health check',
  not_configured: 'Not configured (see the Actions and Settings tabs)',
  subscription_pending: 'Office 365 audit subscription is being started',
  throttled: 'The provider is throttling requests',
  rate_budget: 'The gateway’s own request budget is exhausted for now',
  provider_unavailable: 'The provider is not reachable',
  provider_timeout: 'The provider did not answer in time',
  token_unavailable: 'No access token could be obtained for the connection',
  cursor_invalid: 'The stream position was reset',
  mfa_ou_not_configured: 'Google: no 2-step verification organizational unit is configured',
  mfa_ou_not_found: 'Google: the configured organizational unit does not exist',
  mfa_group_not_found: 'Microsoft: the configured MFA group does not exist',
  no_linked_user: 'No active user of a linked domain was found for the probe',
  requires_exchange_admin:
    'Mailbox-level forwarding cannot be changed through Microsoft Graph: remove it in the Exchange admin center',
  already_in_state: 'Already in the requested state',
  restored_previous_state_noop: 'Already back in the previous state',
  rollback_not_available: 'This provider action cannot be rolled back',
  action_disabled: 'The action is disabled in the identity-provider settings',
  capability_unavailable: 'The provider permission or licence for this action is missing',
  confirmation_timeout: 'The provider did not confirm the change in time',
  identity_not_found: 'The user was not found in the provider directory',
  domain_not_linked: 'The user is not in a domain linked to this organization',
  no_integration: 'No identity provider is connected for this account',
  not_a_mailbox_account: 'Only mailbox accounts have identity-provider actions',
  ambiguous_integration: 'Several identity providers match this account',
  integration_disabled: 'The identity provider was removed',
  integration_paused: 'The identity provider is paused',
  partial: 'Only part of the items could be changed',
  item_not_found: 'The mailbox item no longer exists',
  on_premises_managed: 'The user is managed on premises (synced): change it there',
  no_provider_adapter: 'No identity-provider adapter handled this action',
};

export const codeText = (code: string | null | undefined): string | null =>
  code ? (CODE_TEXT[code] ?? humanize(code)) : null;

export const MAILBOX_ITEM_KIND_LABELS: Record<MailboxItem['kind'], string> = {
  forwarding: 'Mailbox forwarding',
  inbox_rule: 'Inbox rule or filter',
  delegate: 'Delegate',
  mailbox_permission: 'Mailbox permission',
  send_as: 'Send as',
};

export const TRAIT_LABELS: Record<string, string> = {
  forwards: 'Forwards',
  redirects: 'Redirects',
  forwards_as_attachment: 'Forwards as attachment',
  forwards_external: 'Forwards outside the organization',
  deletes: 'Deletes messages',
  moves_to_folder: 'Moves to a folder',
  moves_to_rarely_used_folder: 'Moves to a rarely used folder',
  marks_read: 'Marks as read',
  stops_processing: 'Stops other rules',
  matches_finance_keywords: 'Matches finance keywords',
  matches_security_keywords: 'Matches security keywords',
  matches_all_messages: 'Matches every message',
};

/** Items whose removal the providers support (`remove_forwarding_rule`, D9.7). */
export function canRemoveForwarding(item: MailboxItem): boolean {
  return (
    item.state === 'present' &&
    (item.kind === 'forwarding' || item.kind === 'inbox_rule') &&
    (item.kind === 'forwarding' ||
      item.traits.some((t) => t === 'forwards' || t === 'redirects' || t.startsWith('forwards_')))
  );
}

/** Lag in a compact human form (seconds → "4 min", "2 h 5 min", "3 days"). */
export function formatLag(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '—';
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} h${minutes % 60 ? ` ${minutes % 60} min` : ''}`;
  return `${Math.floor(hours / 24)} days`;
}

/**
 * The provider status of a response as returned (8.4 pages, §7): `confirmed`, `pending`
 * confirmation, `unconfirmed` after a timeout, `unsupported` with its reason; gateway responses
 * keep their own wording. A provider response is never shown as done without `confirmed`.
 */
export function providerStatusText(response: {
  provider: string;
  status: string;
  providerStatus: string | null;
  resultCode: string | null;
}): string | null {
  const { providerStatus, resultCode } = response;
  if (!providerStatus) return null;
  const gateway = response.provider === 'gateway' || response.provider === 'manual';
  switch (providerStatus) {
    case 'applied':
      return 'Applied by the gateway';
    case 'confirmed':
      return resultCode === 'already_in_state'
        ? 'Confirmed by the provider (already in that state)'
        : 'Confirmed by the provider';
    case 'pending':
      return 'Pending confirmation by the provider';
    case 'unconfirmed':
      return gateway
        ? 'Queued (delivery not confirmed)'
        : resultCode === 'confirmation_timeout'
          ? 'Unconfirmed after timeout'
          : 'Not confirmed by the provider';
    case 'unsupported':
      return `Unsupported: ${codeText(resultCode) ?? 'no reason given'}`;
    case 'failed':
      return `Failed${resultCode ? `: ${codeText(resultCode)}` : ''}`;
    default:
      return humanize(providerStatus);
  }
}

// ---- routes --------------------------------------------------------------------------------

export const providersHref = '/ato/providers';
export const providerHref = (id: string, tab?: string) =>
  `/ato/providers/${id}${tab ? `?tab=${tab}` : ''}`;
export const connectionHref = (id: string) => `/integrations/providers/${id}`;
export const newConnectionHref = '/integrations/providers/new';

// ---- settings (`ato-idp-binding/1`, D10) ----------------------------------------------------

export type BindingSettings = {
  streams: Record<ProviderStream, { enabled: boolean }>;
  pollIntervalSeconds: number;
  backfillDays: number;
  snapshot: { sweepIntervalHours: number | null };
  actions: Record<ProviderActionType, { enabled: boolean }>;
  mfaEnforcement: { groupId: string | null; orgUnitPath: string | null };
  forwardingRemoval: { mode: 'disable' | 'delete' };
};

/** Bounds of D10 (the api validates again; these only guide the inputs). */
export const SETTINGS_BOUNDS = {
  pollIntervalSeconds: { min: 60, max: 3600 },
  backfillDays: { min: 0, max: 30 },
  sweepIntervalHours: { min: 6, max: 168 },
} as const;

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

const flag = (v: unknown, fallback = true): { enabled: boolean } => ({
  enabled: isObject(v) && typeof v.enabled === 'boolean' ? v.enabled : fallback,
});

/**
 * The api's stored settings as the form's draft: every field present (the api always returns a
 * full document; missing fields fall back to the D10 defaults only so the form renders).
 */
export function bindingSettingsOf(input: unknown): BindingSettings {
  const raw = isObject(input) ? input : {};
  const streams = isObject(raw.streams) ? raw.streams : {};
  const actions = isObject(raw.actions) ? raw.actions : {};
  const snapshot = isObject(raw.snapshot) ? raw.snapshot : {};
  const mfa = isObject(raw.mfaEnforcement) ? raw.mfaEnforcement : {};
  const fwd = isObject(raw.forwardingRemoval) ? raw.forwardingRemoval : {};
  return {
    streams: Object.fromEntries(PROVIDER_STREAMS.map((s) => [s, flag(streams[s])])) as Record<
      ProviderStream,
      { enabled: boolean }
    >,
    pollIntervalSeconds:
      typeof raw.pollIntervalSeconds === 'number' ? raw.pollIntervalSeconds : 300,
    backfillDays: typeof raw.backfillDays === 'number' ? raw.backfillDays : 7,
    snapshot: {
      sweepIntervalHours:
        typeof snapshot.sweepIntervalHours === 'number' ? snapshot.sweepIntervalHours : null,
    },
    actions: Object.fromEntries(PROVIDER_ACTIONS.map((a) => [a, flag(actions[a])])) as Record<
      ProviderActionType,
      { enabled: boolean }
    >,
    mfaEnforcement: {
      groupId: typeof mfa.groupId === 'string' ? mfa.groupId : null,
      orgUnitPath: typeof mfa.orgUnitPath === 'string' ? mfa.orgUnitPath : null,
    },
    forwardingRemoval: { mode: fwd.mode === 'delete' ? 'delete' : 'disable' },
  };
}

/** The defaults of D10 (used by the connect dialog before the binding exists). */
export function defaultBindingSettings(): BindingSettings {
  return bindingSettingsOf({});
}

// ---- errors ----------------------------------------------------------------------------------

/** Human texts of the `ato_provider_*` codes (§6, WP5); other codes use the 8.4 texts. */
export function explainProviderError(error: ApiError): string[] {
  const d = error.details;
  switch (error.code) {
    case 'ato_provider_not_found':
      return ['The identity provider does not exist or is not visible to you.'];
    case 'ato_provider_connection_not_found':
      return ['The Microsoft 365 / Google Workspace connection no longer exists.'];
    case 'ato_provider_connection_ineligible': {
      const reasons = (Array.isArray(d.reasons) ? d.reasons : []).flatMap((r) => {
        const code = (r as { reason?: unknown }).reason;
        return typeof code === 'string' ? [codeText(code) ?? code] : [];
      });
      return [
        'This connection cannot be used for account takeover detection yet: it must be active and have an active account takeover telemetry grant (add it in the connection’s Setup tab).',
        ...reasons,
      ];
    }
    case 'ato_provider_already_bound':
      return ['This connection is already connected for account takeover detection.'];
    case 'ato_provider_directory_in_use':
      return [
        'This directory (tenant or customer) is already monitored by another gateway organization. One directory can be monitored by one organization only; contact your platform operator.',
      ];
    case 'ato_provider_limit_reached':
      return [
        `The organization has reached its limit of identity providers${typeof d.limit === 'number' ? ` (${d.limit})` : ''}. Remove one first.`,
      ];
    case 'ato_provider_settings_invalid': {
      const issues = Array.isArray(d.issues) ? d.issues : [];
      const lines = issues.flatMap((issue) => {
        const i = issue as { path?: unknown; message?: unknown };
        return typeof i.path === 'string'
          ? [`${i.path}: ${typeof i.message === 'string' ? humanize(i.message) : 'not valid'}`]
          : [];
      });
      return lines.length > 0 ? lines : ['The settings are not valid.'];
    }
    case 'ato_provider_conflict':
      return [
        'Someone else changed this identity provider since you opened it. Reload to see the current settings, then apply your change again.',
      ];
    case 'ato_provider_connection_inactive':
      return ['The connection is not active; resume it after the connection is healthy again.'];
    case 'ato_provider_backfill_active':
      return ['A backfill is already running for this identity provider.'];
    case 'ato_provider_backfill_range_invalid':
      return [
        'The backfill start is outside the allowed range (at most 30 days back and within the provider’s retention).',
      ];
    case 'ato_provider_refresh_unavailable':
      return [
        'No connected identity provider can refresh this mailbox now (it needs an active provider with the mailbox stream available).',
      ];
    case 'ato_provider_disabled':
      return ['This identity provider was removed; connect it again to change it.'];
    default:
      return explainAtoError(error);
  }
}
