import { ToneBadge } from '@/components/domain/tone-badge';
import type { ListItem, RequestBody, SuccessBody } from '@/lib/api/types';
import type { Tone } from '@/lib/design/tokens';
import { humanize } from '@/lib/format';

/**
 * Types, labels and badges of the Microsoft 365 and Google Workspace connections (step 8.2 §6,
 * D13). Every state shown here is computed by the api (wizard steps, change sets, check results,
 * proof outcomes): the browser renders the server's results and evaluates no policy or proof.
 */

export type Catalog = SuccessBody<'ProviderCatalogController_get_v1'>;
export type CatalogProvider = Catalog['providers'][number];
export type CatalogProfile = CatalogProvider['profiles'][number];
export type CatalogAttestation = CatalogProvider['attestations'][number];
export type ConnectionRow = ListItem<'ProviderConnectionsController_list_v1'>;
export type Connection = SuccessBody<'ProviderConnectionsController_get_v1'>;
export type Grant = Connection['grants'][number];
export type Wizard = SuccessBody<'ProviderConnectionsController_wizard_v1'>;
export type WizardStep = Wizard['steps'][number];
export type WizardStepKey = WizardStep['step'];
export type LinkedDomain = ListItem<'ProviderDomainsController_list_v1'>;
export type MailFlow = SuccessBody<'ProviderMailFlowController_get_v1'>;
export type MailFlowChange = RequestBody<'ProviderMailFlowController_preview_v1'>['change'];
export type Preview = SuccessBody<'ProviderMailFlowController_preview_v1'>;
export type ChangeSet = Preview['changeSet'];
export type ValidationRun = SuccessBody<'ProviderValidationsController_get_v1'>;
export type ValidationRow = ListItem<'ProviderValidationsController_list_v1'>;
export type ValidationResult = ValidationRun['results'][number];
export type Health = SuccessBody<'ProviderHealthController_get_v1'>;
export type SetupGuide = SuccessBody<'ProviderGuideController_get_v1'>;

export type Provider = Connection['provider'];
export type AuthMethod = Grant['authMethod'];
export type HealthStatus = Connection['health'];
export type ConnectionStatus = Connection['status'];
export type OutboundMode = Connection['outboundMode'];

export const PROVIDERS: readonly Provider[] = ['microsoft_365', 'google_workspace'];

export const PROVIDER_LABEL: Record<Provider, string> = {
  microsoft_365: 'Microsoft 365',
  google_workspace: 'Google Workspace',
};

/** The mail-flow permission profile of each provider (D1). */
export const MAIL_FLOW_PROFILE: Record<Provider, string> = {
  microsoft_365: 'm365.mail_flow',
  google_workspace: 'google.mail_flow',
};

export const AUTH_METHOD_INFO: Record<
  AuthMethod,
  { title: string; recommended: boolean; summary: string; secret: boolean }
> = {
  platform_app: {
    title: 'Admin consent to the gateway app',
    recommended: true,
    summary:
      'A Global Administrator consents to the gateway’s multi-tenant app in Microsoft Entra. No secret of yours is stored.',
    secret: false,
  },
  customer_app_secret: {
    title: 'Your own app registration',
    recommended: false,
    summary:
      'For tenants that forbid third-party apps: create a single-tenant app with exactly these permissions and upload its client secret (stored encrypted, never shown again).',
    secret: true,
  },
  platform_service_account: {
    title: 'Domain-wide delegation to the gateway service account',
    recommended: true,
    summary:
      'A super administrator authorizes the gateway’s service account for exactly these read-only scopes and names a delegated administrator. No key of yours is stored.',
    secret: false,
  },
  customer_service_account: {
    title: 'Your own service account key',
    recommended: false,
    summary:
      'For organizations that forbid third-party service accounts: upload the JSON key of your own service account with delegation for exactly these scopes (stored encrypted, never shown again).',
    secret: true,
  },
};

const STATUS_TONE: Record<ConnectionStatus, Tone> = {
  draft: 'neutral',
  connecting: 'info',
  configuring: 'warning',
  active: 'success',
  disabled: 'neutral',
};

export function ConnectionStatusBadge({ status }: { status: ConnectionStatus }) {
  return <ToneBadge tone={STATUS_TONE[status] ?? 'neutral'}>{humanize(status)}</ToneBadge>;
}

const HEALTH_TONE: Record<HealthStatus, Tone> = {
  unknown: 'neutral',
  healthy: 'success',
  warning: 'warning',
  critical: 'danger',
};

export function HealthBadge({ status }: { status: HealthStatus }) {
  return (
    <ToneBadge tone={HEALTH_TONE[status] ?? 'neutral'}>
      {status === 'unknown' ? 'Not checked yet' : humanize(status)}
    </ToneBadge>
  );
}

export const OUTBOUND_LABEL: Record<OutboundMode, string> = {
  off: 'Off',
  probe_only: 'Probe only',
  active: 'Active',
  suspended: 'Suspended',
};

const OUTBOUND_TONE: Record<OutboundMode, Tone> = {
  off: 'neutral',
  probe_only: 'info',
  active: 'success',
  suspended: 'warning',
};

export function OutboundBadge({ mode }: { mode: OutboundMode }) {
  return <ToneBadge tone={OUTBOUND_TONE[mode] ?? 'neutral'}>{OUTBOUND_LABEL[mode]}</ToneBadge>;
}

const GRANT_TONE: Record<Grant['status'], Tone> = {
  pending_consent: 'info',
  verifying: 'info',
  active: 'success',
  error: 'danger',
  revoked: 'neutral',
};

export function GrantStatusBadge({ status }: { status: Grant['status'] }) {
  return <ToneBadge tone={GRANT_TONE[status] ?? 'neutral'}>{humanize(status)}</ToneBadge>;
}

const VERIFICATION_TONE: Record<LinkedDomain['providerVerification'], Tone> = {
  unknown: 'neutral',
  verified: 'success',
  unverified: 'warning',
  absent: 'danger',
  alias: 'warning',
};

export function ProviderVerificationBadge({
  value,
}: {
  value: LinkedDomain['providerVerification'];
}) {
  return (
    <ToneBadge tone={VERIFICATION_TONE[value] ?? 'neutral'}>
      {value === 'unknown' ? 'Not checked yet' : humanize(value)}
    </ToneBadge>
  );
}

const CHECK_TONE: Record<ValidationResult['status'], Tone> = {
  pass: 'success',
  warn: 'warning',
  fail: 'danger',
  skipped: 'neutral',
  error: 'orange',
};

export function CheckStatusBadge({ status }: { status: ValidationResult['status'] }) {
  return <ToneBadge tone={CHECK_TONE[status] ?? 'neutral'}>{humanize(status)}</ToneBadge>;
}

const RUN_TONE: Record<ValidationRun['status'], Tone> = {
  queued: 'info',
  running: 'info',
  awaiting_probe: 'info',
  passed: 'success',
  warning: 'warning',
  failed: 'danger',
  expired: 'neutral',
  cancelled: 'neutral',
};

export function RunStatusBadge({ status }: { status: ValidationRun['status'] }) {
  return <ToneBadge tone={RUN_TONE[status] ?? 'neutral'}>{humanize(status)}</ToneBadge>;
}

/** Validation runs the worker has not finished yet (the portal polls them every 5 s). */
export function runInProgress(status: ValidationRun['status']): boolean {
  return status === 'queued' || status === 'running' || status === 'awaiting_probe';
}

export const STEP_LABEL: Record<WizardStepKey, string> = {
  connect: 'Connect',
  domains: 'Domains',
  inbound: 'Inbound',
  outbound: 'Outbound and internal',
  validate: 'Validate',
  activate: 'Activate',
};

const STEP_STATUS_LABEL: Record<WizardStep['status'], string> = {
  not_started: 'Not started',
  in_progress: 'In progress',
  done: 'Done',
  blocked: 'Blocked',
  skipped: 'Skipped',
};

const STEP_STATUS_TONE: Record<WizardStep['status'], Tone> = {
  not_started: 'neutral',
  in_progress: 'info',
  done: 'success',
  blocked: 'neutral',
  skipped: 'neutral',
};

export function StepStatusBadge({ status }: { status: WizardStep['status'] }) {
  return <ToneBadge tone={STEP_STATUS_TONE[status]}>{STEP_STATUS_LABEL[status]}</ToneBadge>;
}

/** Plain-language text of the api's wizard blocker codes (D13; unknown codes are humanized). */
const BLOCKER_TEXT: Record<string, string> = {
  connection_disabled: 'The connection is disconnected.',
  grant_error: 'Verifying the access grant failed. Check the error and verify again.',
  consent_pending: 'Waiting for the administrator’s consent or authorization.',
  verification_pending: 'The gateway is verifying the access grant (usually under a minute).',
  tenant_not_verified: 'The provider tenant is not verified yet.',
  no_domain_linked: 'Link at least one verified domain.',
  domain_not_gateway_active: 'Every linked domain must be active at the gateway.',
  no_domain_provider_verified:
    'At least one linked domain must be verified in the provider tenant.',
  binding_pending: 'The gateway is binding the tenant to this organization.',
  destinations_missing: 'Not every linked domain delivers to the provider yet.',
  attestations_missing: 'Confirm the customer-side inbound steps of the setup guide.',
  relay_connector_disabled: 'The provider relay connector is disabled.',
  run_queued: 'A validation run is queued.',
  run_running: 'A validation run is running.',
  run_awaiting_probe: 'Waiting for the probe message.',
  run_failed: 'The latest validation failed. Fix the failing checks and validate again.',
  run_expired: 'The latest validation expired before the probe arrived.',
  run_cancelled: 'The latest validation was cancelled.',
  internal_routing_attestation_missing: 'Confirm the internal-routing transport rules.',
  outbound_suspended: 'Outbound routing through the gateway is suspended.',
  connect: 'Finish “Connect” first.',
  domains: 'Finish “Domains” first.',
  inbound: 'Finish “Inbound” first.',
  outbound: 'Finish “Outbound and internal” first.',
  validate: 'Finish “Validate” first.',
};

export function blockerText(code: string): string {
  return BLOCKER_TEXT[code] ?? humanize(code);
}

/** Plain-language text of the preview warnings (the api's codes). */
const WARNING_TEXT: Record<string, string> = {
  domain_not_provider_verified:
    'A domain is not verified in the provider tenant yet; mail may be refused there.',
  destination_differs_from_provider_mx:
    'The destination host differs from the MX target the provider reports for the domain.',
  domain_outbound_not_enabled: 'Outbound mail is not enabled for a linked domain at the gateway.',
  internal_routing_attestation_missing:
    'The internal-routing transport rules are not confirmed yet; activation will stay incomplete.',
  tenant_header_off:
    'The tenant header check is off: only the aligned DKIM signature proves the sender’s tenant.',
};

export function warningText(code: string): string {
  return WARNING_TEXT[code] ?? humanize(code);
}

/** The api error codes of this feature with an explanation for the user. */
const ERROR_HINT: Record<string, string> = {
  impact_changed:
    'Something changed since the preview (another administrator, the worker or an expired preview). Review the updated changes and confirm again.',
  connection_not_bound:
    'The tenant is not bound yet: finish Connect and Domains (a verified domain in the tenant).',
  validation_required: 'Run a full validation that passes (and a probe for outbound) first.',
  outbound_active: 'Outbound routing is active: disable outbound before revoking access.',
  auth_method_unavailable: 'This method is not configured by the platform operator.',
  consent_state_invalid:
    'The consent link expired, was already used or belongs to another session. Start the consent again from the connection.',
  domain_linked_elsewhere: 'A domain is already linked to another connection.',
  domain_not_verified: 'Only domains verified at the gateway can be linked.',
  connection_limit: 'Your organization has reached its maximum number of connections.',
  grant_exists: 'Access is already being set up. Start over to change the method.',
  credential_invalid: 'The credentials are incomplete or malformed.',
};

export function errorHint(code: string | undefined): string | null {
  return code ? (ERROR_HINT[code] ?? null) : null;
}
