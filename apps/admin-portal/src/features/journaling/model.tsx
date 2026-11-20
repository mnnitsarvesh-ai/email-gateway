import { ToneBadge } from '@/components/domain/tone-badge';
import type { ApiError } from '@/lib/api/errors';
import type { ListItem, RequestBody, SuccessBody } from '@/lib/api/types';
import type { Tone } from '@/lib/design/tokens';
import { humanize } from '@/lib/format';

/**
 * Types, labels and badges of Journaling (step 8.6 D1, D8–D11, D14): the capture half of the
 * former archive settings and the journal intake sources. Every state shown is computed by the
 * api (health, wizard steps, guides); the browser renders it and evaluates nothing.
 */

export type JournalingSettings = SuccessBody<'JournalingController_get_v1'>;
export type JournalingStatus = SuccessBody<'JournalingController_status_v1'>;
export type JournalingBody = RequestBody<'JournalingController_update_v1'>;
export type IntakeSourceRow = ListItem<'IntakeSourcesController_list_v1'>;
export type IntakeSource = SuccessBody<'IntakeSourcesController_get_v1'>;
export type IntakeCreateBody = RequestBody<'IntakeSourcesController_create_v1'>;
export type IntakeWizard = SuccessBody<'IntakeSourcesController_wizard_v1'>;
export type IntakeWizardStep = IntakeWizard['steps'][number];
export type IntakeGuide = SuccessBody<'IntakeSourcesController_guide_v1'>;
export type IntakeKind = IntakeSource['kind'];
export type IntakeStatus = IntakeSource['status'];
export type IntakeHealth = IntakeSource['health']['status'];
export type IntakeCounters = IntakeSource['counters'][number];

export const INTAKE_KINDS: readonly IntakeKind[] = [
  'microsoft_365_journal',
  'google_workspace_copy',
  'exchange_onprem_journal',
  'smtp_bcc',
];

export const INTAKE_KIND_LABEL: Record<IntakeKind, string> = {
  microsoft_365_journal: 'Microsoft 365 journaling',
  google_workspace_copy: 'Google Workspace copy',
  exchange_onprem_journal: 'On-premises Exchange journaling',
  smtp_bcc: 'SMTP BCC copy',
};

export const INTAKE_KIND_DESCRIPTION: Record<IntakeKind, string> = {
  microsoft_365_journal:
    'A Microsoft Purview journal rule sends a journal report of every message to the intake address. Needs a Microsoft 365 connection (Integrations) bound to your tenant.',
  google_workspace_copy:
    'A Gmail routing rule adds the intake address ("Also deliver to") and a secret header. Needs a Google Workspace connection (Integrations).',
  exchange_onprem_journal:
    'Exchange Server journaling to a mail contact with the intake address, sent over a TLS Send connector from your registered networks.',
  smtp_bcc:
    'Any SMTP server (for example Postfix always_bcc) sends a copy of every message from your registered networks.',
};

/** The provider an intake kind binds to (8.2 connection), or null for network-based kinds. */
export function providerOfKind(kind: IntakeKind): 'microsoft_365' | 'google_workspace' | null {
  if (kind === 'microsoft_365_journal') return 'microsoft_365';
  if (kind === 'google_workspace_copy') return 'google_workspace';
  return null;
}

const STATUS_TONE: Record<IntakeStatus, Tone> = {
  pending_verification: 'info',
  active: 'success',
  paused: 'warning',
  disabled: 'neutral',
};

const STATUS_LABEL: Record<IntakeStatus, string> = {
  pending_verification: 'Waiting for the first message',
  active: 'Active',
  paused: 'Paused',
  disabled: 'Disabled',
};

export function IntakeStatusBadge({ status }: { status: IntakeStatus }) {
  return <ToneBadge tone={STATUS_TONE[status] ?? 'neutral'}>{STATUS_LABEL[status]}</ToneBadge>;
}

const HEALTH_TONE: Record<IntakeHealth, Tone> = {
  unknown: 'neutral',
  healthy: 'success',
  silent: 'warning',
  failing: 'danger',
  paused: 'neutral',
};

const HEALTH_LABEL: Record<IntakeHealth, string> = {
  unknown: 'Not verified yet',
  healthy: 'Healthy',
  silent: 'Silent',
  failing: 'Failing',
  paused: 'Paused',
};

export function IntakeHealthBadge({ health }: { health: IntakeHealth }) {
  return <ToneBadge tone={HEALTH_TONE[health] ?? 'neutral'}>{HEALTH_LABEL[health]}</ToneBadge>;
}

export const WIZARD_STEP_LABEL: Record<IntakeWizardStep['step'], string> = {
  archiving: 'Archiving enabled',
  domains: 'Verified domain',
  connection: 'Provider connection',
  configure: 'Configure your mail system',
  verify: 'First journal message received',
  monitor: 'Healthy intake',
};

const STEP_TONE: Record<IntakeWizardStep['status'], Tone> = {
  not_started: 'neutral',
  in_progress: 'info',
  done: 'success',
  blocked: 'danger',
  skipped: 'neutral',
};

export function WizardStepBadge({ status }: { status: IntakeWizardStep['status'] }) {
  return <ToneBadge tone={STEP_TONE[status] ?? 'neutral'}>{humanize(status)}</ToneBadge>;
}

/** Plain-language text of a refusal or drop code (`last_refusal_code`, counters). */
export const REFUSAL_TEXT: Record<string, string> = {
  refused_address: 'unknown or retired intake address',
  refused_network: 'sender not in the provider egress ranges or your registered networks',
  refused_tls: 'the sender did not use TLS',
  refused_size: 'message larger than the size limit',
  refused_rate: 'rate limit reached (the sender retries)',
  refused_unavailable: 'intake paused or archiving disabled (the sender retries)',
  proof_tenant_header: 'Microsoft 365 tenant header did not match the bound tenant (dropped)',
  proof_header_token: 'Google Workspace header token missing or wrong (dropped)',
  proof_header_block: 'header block could not be read (dropped)',
};

export function refusalText(code: string | null): string {
  if (!code) return '—';
  return REFUSAL_TEXT[code] ?? humanize(code);
}

/** Paths the client may link to. */
export const journalingHref = '/settings?tab=journaling';
export const newIntakeSourceHref = (kind?: IntakeKind) =>
  kind ? `/settings/journaling/intake/new?kind=${kind}` : '/settings/journaling/intake/new';
export const intakeSourceHref = (id: string, tab?: string) =>
  `/settings/journaling/intake/${encodeURIComponent(id)}${tab ? `?tab=${tab}` : ''}`;

/** Explanation of a journaling / intake refusal, for forms and toasts. */
export function explainJournalingError(error: ApiError): string {
  switch (error.code) {
    case 'archive_default_retention_required':
      return 'Journaling needs a default retention policy first. A compliance officer chooses it in Archive → Retention and lock → Immutability and keys.';
    case 'archiving_not_enabled':
      return 'Archiving is not part of your organization’s plan (feature “archiving”).';
    case 'archive_scope_reference_invalid':
      return 'A chosen domain, department or user no longer exists in your organization.';
    case 'journal_intake_unavailable':
      return 'Journal intake is not configured on this platform (no intake domain). Ask your platform operator.';
    case 'journal_intake_not_enabled':
      return 'Journal intake is not part of your organization’s plan (feature “journal_intake”).';
    case 'journal_intake_networks_invalid':
      return 'The networks are not valid: each must be a CIDR range of at least /16 (IPv4) or /32 (IPv6), never overlapping Microsoft 365 or Google ranges, at most 32.';
    case 'journal_intake_connection_invalid':
      return 'The connection must be yours, of the same provider, not disconnected, and bound to your tenant.';
    case 'journal_intake_source_limit':
      return 'Your organization has the maximum number of intake sources.';
    case 'journal_intake_source_name_taken':
      return 'Another intake source already has this name.';
    case 'journal_intake_domain_required':
      return 'Activation needs a verified domain (and, for Microsoft 365 or Google Workspace, a domain linked to the connection).';
    case 'journal_intake_source_disabled':
      return 'This intake source is disabled; disabling is final.';
    case 'journal_intake_source_conflict':
    case 'archive_settings_conflict':
      return 'Someone else changed this in the meantime. Reload and try again.';
    default:
      return error.message;
  }
}
