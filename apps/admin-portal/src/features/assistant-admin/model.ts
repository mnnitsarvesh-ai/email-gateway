import type { OperationId } from '@/lib/api/types';

/**
 * Step AI-6 (design 34 D1, D2, D4): pure helpers of the tenant AI administration page. The page
 * shows metadata only (I24): every view renders an explicit allow-list of fields of the api's
 * documents, never a document as a whole, and no tab requests a content route.
 */

export const ADMIN_TABS = ['usage', 'limits', 'feedback', 'audit', 'executions'] as const;
export type AdminTab = (typeof ADMIN_TABS)[number];

/** The operation each tab needs (tabs are gated one by one, D1). */
export const ADMIN_TAB_GATE: Readonly<Record<AdminTab, OperationId>> = {
  usage: 'AssistantAdminController_usageByUser_v1',
  limits: 'AssistantSettingsController_get_v1',
  feedback: 'AssistantAdminController_feedback_v1',
  audit: 'AssistantAdminAuditController_conversations_v1',
  executions: 'AssistantAdminAuditController_executions_v1',
};

export const ADMIN_TAB_LABEL: Readonly<Record<AdminTab, string>> = {
  usage: 'Usage',
  limits: 'Limits and provider',
  feedback: 'Feedback',
  audit: 'Conversation audit',
  executions: 'Tool calls',
};

/** The api's window bound of the usage, feedback and audit lists (D1, D4). */
export const ADMIN_MAX_DAYS = 92;
export const ADMIN_RANGE_PRESETS = ['7', '30', '90'] as const;
export type AdminRangePreset = (typeof ADMIN_RANGE_PRESETS)[number];

const DAY_MS = 86_400_000;
const DAY = /^\d{4}-\d{2}-\d{2}$/;

/** A window of whole UTC days. */
export interface AdminRange {
  /** First UTC day (`YYYY-MM-DD`). */
  readonly fromDay: string;
  /** Last UTC day, inclusive. */
  readonly toDay: string;
  /** `fromDay` 00:00Z (ISO instant, the `from` of the v1 lists). */
  readonly from: string;
  /** The day after `toDay`, 00:00Z (exclusive `to` of the v1 lists). */
  readonly to: string;
  readonly days: number;
  readonly label: string;
}

function isoDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

function dayMs(day: string): number {
  return Date.parse(`${day}T00:00:00.000Z`);
}

function rangeOf(fromDay: string, toDay: string, label: string): AdminRange {
  const from = dayMs(fromDay);
  const to = dayMs(toDay) + DAY_MS;
  return {
    fromDay,
    toDay,
    from: new Date(from).toISOString(),
    to: new Date(to).toISOString(),
    days: Math.round((to - from) / DAY_MS),
    label,
  };
}

/** The last `preset` UTC days, today included. */
export function presetRange(preset: AdminRangePreset, now = Date.now()): AdminRange {
  const days = Number(preset);
  const today = isoDay(now);
  return rangeOf(isoDay(dayMs(today) - (days - 1) * DAY_MS), today, `Last ${days} days`);
}

export type AdminRangeResult =
  | { readonly ok: true; readonly range: AdminRange }
  | { readonly ok: false; readonly message: string };

/** Validates a custom window of UTC days: both dates, ordered, ≤ 92 days, not in the future. */
export function customRange(fromDay: string, toDay: string, now = Date.now()): AdminRangeResult {
  if (!DAY.test(fromDay) || !DAY.test(toDay)) return { ok: false, message: 'Enter both dates.' };
  const from = dayMs(fromDay);
  const to = dayMs(toDay);
  if (!Number.isFinite(from) || !Number.isFinite(to))
    return { ok: false, message: 'Enter valid dates.' };
  if (to < from) return { ok: false, message: 'The end date must not be before the start date.' };
  if ((to - from) / DAY_MS + 1 > ADMIN_MAX_DAYS)
    return { ok: false, message: `Choose at most ${ADMIN_MAX_DAYS} days.` };
  if (from > dayMs(isoDay(now))) return { ok: false, message: 'The start date is in the future.' };
  return { ok: true, range: rangeOf(fromDay, toDay, `${fromDay} – ${toDay} (UTC)`) };
}

/**
 * Estimated cost from micro-USD (D1: advisory, from the platform's price table): `—` when the
 * api knows no price (`null`), else US dollars with up to four decimals.
 */
export function formatCostMicros(micros: number | null | undefined): string {
  if (micros === null || micros === undefined) return '—';
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
    maximumFractionDigits: 4,
  }).format(micros / 1_000_000);
}

/** A person of an admin document (`displayName`/`email` are null outside the organization). */
export interface AdminUser {
  readonly id: string;
  readonly displayName: string | null;
  readonly email: string | null;
}

export function userLabel(user: AdminUser): string {
  return user.displayName ?? user.email ?? `User ${user.id.slice(0, 8)}`;
}

export const KEY_SOURCE_LABEL: Readonly<Record<'platform' | 'tenant', string>> = {
  platform: 'Platform key',
  tenant: 'Your key',
};

export const FEEDBACK_REASONS = [
  'incorrect',
  'incomplete',
  'not_helpful',
  'wrong_action',
  'unsafe',
  'too_slow',
  'other',
] as const;
export type FeedbackReasonValue = (typeof FEEDBACK_REASONS)[number];

export const FEEDBACK_REASON_LABEL: Readonly<Record<FeedbackReasonValue, string>> = {
  incorrect: 'Incorrect',
  incomplete: 'Incomplete',
  not_helpful: 'Not helpful',
  wrong_action: 'Wrong action',
  unsafe: 'Unsafe',
  too_slow: 'Too slow',
  other: 'Other',
};

export const DATA_SHARING_HELP = {
  metadata:
    'Your questions and the masked record metadata the tools return are sent to the AI provider as they are. Message bodies and attachments are never sent.',
  pseudonymized:
    'Before anything reaches the AI provider, e-mail addresses, IP addresses, domains and person names in name fields are replaced by placeholders such as [EMAIL_1] or [PERSON_2]; the answers, cards and audit records you see keep the real values. Limitation: names written in free text (for example in a subject line) are not detected and are sent as written. A change applies from the next question.',
} as const;

/** Plain text of a tenant-key error code (`last_error_code`, D7). */
export function tenantKeyErrorText(code: string | null): string | null {
  if (!code) return null;
  switch (code) {
    case 'provider_auth':
      return 'the provider rejected the key';
    case 'provider_client_error':
      return 'the provider refused the request (for example an unknown model)';
    case 'provider_connection':
    case 'provider_timeout':
      return 'the provider could not be reached';
    case 'provider_rate_limited':
      return 'the provider rate-limited the check';
    case 'provider_server_error':
      return 'the provider failed';
    case 'tenant_key_undecryptable':
      return 'the stored key can no longer be read; store it again';
    default:
      return 'the key could not be checked';
  }
}

/** Plain text of the coded refusals of the settings and key routes (contracts §35.6). */
export function adminErrorText(code: string): string | null {
  switch (code) {
    case 'assistant_tenant_keys_disabled':
      return 'The platform does not offer your own provider key.';
    case 'assistant_tenant_key_not_found':
      return 'No provider key is stored for your organization.';
    case 'assistant_tenant_key_rejected':
      return 'The provider rejected this key, or the stored key is not valid. Nothing was changed.';
    case 'assistant_tenant_key_unverified':
      return 'The provider could not be reached to check the key. Nothing was stored; try again later.';
    case 'assistant_settings_conflict':
      return 'Someone else changed these settings after you opened them. Reload the current settings, then apply your change again.';
    case 'mfa_required':
      return 'This change needs a session signed in with multi-factor authentication. Verify with your authenticator, then try again.';
    default:
      return null;
  }
}
