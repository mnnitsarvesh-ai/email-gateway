import { ToneBadge } from '@/components/domain/tone-badge';
import type { ApiError } from '@/lib/api/errors';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import type { Tone } from '@/lib/design/tokens';
import { formatDuration, humanize } from '@/lib/format';

/**
 * Types, labels and badges of API-mode protection (step API-1, docs/plan/steps/35-api-mode-
 * protection.md D1, D2, D11, D12, D14). Every state shown here is computed by the api (effective
 * modes, coverage, health checks, wizard steps, lag percentiles): the browser renders it and
 * evaluates nothing.
 */

export type ProtectionMode = 'inline' | 'api' | 'hybrid';
export type DomainModeChoice = ProtectionMode | 'inherit';
export type OrganizationProtectionMode = SuccessBody<'ProtectionModeController_getOrganization_v1'>;
export type DomainProtectionMode = SuccessBody<'DomainsController_get_v1'>['protectionMode'];
export type Overview = SuccessBody<'ApiModeController_overview_v1'>;
export type OverviewConnection = Overview['connections'][number];
export type ApiModeConnection = ListItem<'ApiModeController_listConnections_v1'>;
export type ApiModeConnectionDetail = SuccessBody<'ApiModeController_getConnection_v1'>;
export type ApiModeWizardStep = ApiModeConnectionDetail['wizard']['steps'][number];
export type ApiModeGuide = SuccessBody<'ApiModeController_setupGuide_v1'>;
export type Mailbox = ListItem<'ApiModeController_listMailboxes_v1'>;
export type Detection = ListItem<'ApiModeController_listDetections_v1'>;
export type ApiModeHealth = OverviewConnection['health'];
export type GrantStatus = NonNullable<OverviewConnection['grantStatus']>;
export type FeedMode = ApiModeConnection['feedMode'];

export const PROTECTION_MODES: readonly ProtectionMode[] = ['inline', 'api', 'hybrid'];

export const MODE_LABEL: Record<ProtectionMode, string> = {
  inline: 'Inline (MX)',
  api: 'API (no MX change)',
  hybrid: 'Hybrid',
};

/** Short badge text of each mode. */
export const MODE_SHORT: Record<ProtectionMode, string> = {
  inline: 'Inline',
  api: 'API',
  hybrid: 'Hybrid',
};

/** The three option texts of the wizard and the change dialogs (design D3). */
export const MODE_EXPLANATION: Record<ProtectionMode, string> = {
  inline:
    'Mail is delivered through the gateway; threats are blocked before delivery; needs an MX change.',
  api: 'The gateway receives a copy from Microsoft 365 or Google Workspace and scans it after delivery; threats are removed from the mailbox (from step API-2); mail flow is never changed, delayed or bounced.',
  hybrid:
    'Inline filtering plus API post-delivery protection (retroactive removal, internal mail later).',
};

const MODE_TONE: Record<ProtectionMode, Tone> = {
  inline: 'neutral',
  api: 'info',
  hybrid: 'purple',
};

export function ProtectionModeBadge({
  mode,
  inherited = false,
}: {
  mode: ProtectionMode;
  inherited?: boolean;
}) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <ToneBadge tone={MODE_TONE[mode] ?? 'neutral'}>
        {MODE_SHORT[mode] ?? humanize(mode)}
      </ToneBadge>
      {inherited ? <span className="text-xs text-muted-foreground">inherited</span> : null}
    </span>
  );
}

/** Whether a mode needs the `api_mode_protection` feature (`inline` is always allowed, D1). */
export function needsEntitlement(mode: DomainModeChoice): boolean {
  return mode === 'api' || mode === 'hybrid';
}

export const NOT_ENTITLED_REASON =
  'API and Hybrid need the API-mode protection feature of your plan (enterprise or dedicated). Inline is always available.';

/**
 * Plain-language text of the coded errors of the mode routes (D2, D12.3). The MX conflict names
 * the domains (`details.domains`, at most 20) and suggests Hybrid or moving MX first.
 */
export function protectionModeErrorText(error: ApiError | null): string | null {
  if (!error) return null;
  if (error.code === 'protection_mode_mx_points_to_gateway') {
    const domains = Array.isArray(error.details.domains)
      ? (error.details.domains as unknown[])
          .map((d) =>
            typeof d === 'string'
              ? d
              : d && typeof d === 'object' && 'name' in d
                ? String(d.name)
                : '',
          )
          .filter(Boolean)
      : [];
    return `${domains.length > 0 ? `${domains.join(', ')}: the` : 'The'} MX record still points to the gateway, so API mode would leave mail flowing through the gateway unprotected by the inline path. Choose Hybrid (inline filtering plus API protection), or move the MX record to your provider first and try again.`;
  }
  if (error.code === 'api_mode_not_enabled') {
    return 'API-mode protection is not part of this organization’s plan. Inline is always available; ask your administrator or the platform operator to enable the feature.';
  }
  if (error.code === 'protection_mode_inbound_conflict') {
    return 'A domain in API mode is created with inbound mail through the gateway turned off.';
  }
  return null;
}

// ---- health, coverage and feeds ---------------------------------------------------------------

const HEALTH_TONE: Record<ApiModeHealth, Tone> = {
  unknown: 'neutral',
  healthy: 'success',
  degraded: 'warning',
  failing: 'danger',
};

export const HEALTH_LABEL: Record<ApiModeHealth, string> = {
  unknown: 'Not evaluated yet',
  healthy: 'Healthy',
  degraded: 'Degraded',
  failing: 'Failing',
};

export function ApiModeHealthBadge({ health }: { health: ApiModeHealth }) {
  return <ToneBadge tone={HEALTH_TONE[health] ?? 'neutral'}>{HEALTH_LABEL[health]}</ToneBadge>;
}

/** Titles of the health checks of `api-mode-health/1` (D11.3; step API-2 R14; step API-3 C13). */
export const CHECK_TITLE: Record<string, string> = {
  'connection.active': 'Provider connection active and bound',
  'intake.present': 'Journal copy or mailbox feeds present',
  'intake.journal_health': 'Journal intake source healthy',
  'mailbox_access.grant': 'Mailbox access grant active',
  'coverage.percent': 'Mailbox coverage',
  'lag.p95_1h': 'Detection lag (p95, last hour)',
  'throttling.1h': 'Provider throttling (last hour)',
  'feeds.errors': 'Mailbox feed errors',
  'domains.api_mode_mx': 'API-mode domain whose MX points to the gateway',
  // Step API-2 R14.
  'remediation.failures_1h': 'Remediation failures (last hour)',
  'remediation.backlog': 'Remediation backlog',
  'remediation.access': 'Remediation possible (mailbox access for an enforcing policy)',
  'remediation.paused': 'Remediation paused',
  // Step API-3 C13.
  'clawback.stalled': 'Clawback stalled (queued or running without progress)',
  'reports.backlog': 'Reported messages waiting for triage',
};

export function checkTitle(code: string): string {
  return CHECK_TITLE[code] ?? humanize(code.replace(/\./g, ' '));
}

const GRANT_TONE: Record<GrantStatus, Tone> = {
  pending_consent: 'warning',
  verifying: 'info',
  active: 'success',
  error: 'danger',
  revoked: 'neutral',
};

export function MailboxGrantBadge({ status }: { status: GrantStatus | null }) {
  if (status === null) return <ToneBadge tone="neutral">Not granted</ToneBadge>;
  return <ToneBadge tone={GRANT_TONE[status] ?? 'neutral'}>{humanize(status)}</ToneBadge>;
}

export const COVERAGE_STATES = ['covered', 'gap', 'out_of_scope'] as const;
export const FEED_STATUSES = ['off', 'pending', 'active', 'error', 'throttled', 'revoked'] as const;
export const MAILBOX_STATUSES = ['active', 'discovered', 'disabled', 'deleted'] as const;

const COVERAGE_TONE: Record<Mailbox['coverage'], Tone> = {
  covered: 'success',
  gap: 'warning',
  out_of_scope: 'neutral',
};

export function CoverageBadge({ coverage }: { coverage: Mailbox['coverage'] }) {
  return <ToneBadge tone={COVERAGE_TONE[coverage] ?? 'neutral'}>{humanize(coverage)}</ToneBadge>;
}

const FEED_TONE: Record<Mailbox['feedStatus'], Tone> = {
  off: 'neutral',
  pending: 'info',
  active: 'success',
  error: 'danger',
  throttled: 'orange',
  revoked: 'neutral',
};

export function FeedStatusBadge({ status }: { status: Mailbox['feedStatus'] }) {
  return <ToneBadge tone={FEED_TONE[status] ?? 'neutral'}>{humanize(status)}</ToneBadge>;
}

export const DETECTION_VERDICTS = [
  'clean',
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp_violation',
  'suspicious',
  'unknown',
] as const;
export const DETECTION_STATUSES = [
  'pending',
  'scanned',
  'scan_failed',
  'parse_failed',
  'too_large',
] as const;
export const DETECTION_SOURCES = ['journal', 'graph', 'gmail'] as const;
/**
 * Step API-3 C8: inbound copies and internal (east-west) copies; step API-4 A6: outbound
 * detections recorded on the sender's mailbox (never remediated: the message has left).
 */
export const DETECTION_DIRECTIONS = ['inbound', 'internal', 'outbound'] as const;

export const DIRECTION_LABEL: Record<Detection['direction'], string> = {
  inbound: 'Inbound',
  internal: 'Internal',
  outbound: 'Outbound',
};

/** A late verdict (sandbox or URL inspection after delivery) revised the copy's verdict (C2). */
export function VerdictRevisionBadge({ revision }: { revision: number }) {
  if (revision <= 0) return null;
  return (
    <ToneBadge tone="orange">
      <span title="A late verdict (sandbox or URL inspection after delivery) revised this verdict">
        Revised{revision > 1 ? ` ×${revision}` : ''}
      </span>
    </ToneBadge>
  );
}

export const SOURCE_LABEL: Record<Detection['source'], string> = {
  journal: 'Journal copy',
  graph: 'Microsoft Graph feed',
  gmail: 'Gmail feed',
};

const WIZARD_TONE: Record<ApiModeWizardStep['status'], Tone> = {
  not_started: 'neutral',
  in_progress: 'info',
  done: 'success',
  blocked: 'danger',
  skipped: 'neutral',
};

export function ApiModeWizardBadge({ status }: { status: ApiModeWizardStep['status'] }) {
  return <ToneBadge tone={WIZARD_TONE[status] ?? 'neutral'}>{humanize(status)}</ToneBadge>;
}

export const WIZARD_STEP_LABEL: Record<ApiModeWizardStep['step'], string> = {
  domains: 'Domains in API or Hybrid mode',
  connection: 'Provider connection active and bound',
  journal: 'Journal copy verified',
  mailbox_access: 'Mailbox access granted',
  feeds: 'Mailbox change feeds',
  monitor: 'Healthy protection',
};

/** Plain-language text of the wizard's blocker and next-action codes (D12.2). */
export const WIZARD_CODE_TEXT: Record<string, string> = {
  no_api_mode_domain: 'no domain linked to this connection is in API or Hybrid mode',
  connection_disabled: 'the connection is disconnected',
  connection_not_bound: 'the tenant is not bound yet (a linked domain must be verified in it)',
  connection_not_active: 'the connection is not active yet',
  grant_pending: 'the mailbox access grant waits for consent or verification',
  grant_error: 'the mailbox access grant failed verification',
  grant_missing: 'no mailbox access grant',
  no_in_scope_mailboxes: 'no in-scope mailbox yet (run an inventory sync)',
  feeds_initializing: 'feeds are starting for the in-scope mailboxes',
  journal_source_missing: 'no verified journal intake source on this connection',
  journal_source_paused: 'the journal intake source is paused',
  journal_not_verified: 'the journal intake source has not received its first copy',
  journal_failing: 'the journal intake source is failing',
  intake_missing: 'neither a journal copy nor mailbox feeds deliver copies',
  health_failing: 'health checks fail',
  health_unknown: 'health has not been evaluated yet',
  set_domain_api_mode: 'Set a linked domain to API or Hybrid mode',
  bind_connection: 'Finish the provider connection',
  configure_journal: 'Configure the journal copy (journal intake source)',
  grant_mailbox_access: 'Grant mailbox access for API mode',
  wait_for_feeds: 'Wait for the mailbox feeds to start',
  review_health: 'Review the health checks',
};

export function wizardCodeText(code: string): string {
  return WIZARD_CODE_TEXT[code] ?? humanize(code);
}

/** The mailbox-access permission profile of each provider (D4). */
export const MAILBOX_PROFILE: Record<'microsoft_365' | 'google_workspace', string> = {
  microsoft_365: 'm365.mailbox_remediation',
  google_workspace: 'google.mailbox_remediation',
};

export const MAILBOX_PURPOSE = 'mailbox_remediation';

/** Seconds as a lag (`45 s`, `12 min`, `1.5 h`); `null` = no copy in the window. */
export function formatLagSeconds(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return 'No copies';
  return formatDuration(seconds * 1000);
}

export function formatLagMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return 'Not measured';
  return formatDuration(ms);
}

/** "12 of 40 (30.0 %)" or "12 covered, total unknown" (inventory not available, D11.2). */
export function coverageText(coverage: Overview['coverage']): string {
  if (coverage.total === null) return `${coverage.covered} covered, total unknown`;
  const percent =
    coverage.percent === null ? '' : ` (${(Math.round(coverage.percent * 10) / 10).toFixed(1)} %)`;
  return `${coverage.covered} of ${coverage.total}${percent}`;
}
