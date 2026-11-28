import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../http/coded-exception';
import { INCONSISTENT_READ } from '../../http/listing/echo-check';

/**
 * Stable error codes of the provider-connection routes and of the two smtp-connector rules of
 * step 8.2 (§5.2, §5.3; docs/plan/steps/25-m365-google-connectors.md). Unknown ids and ids of
 * another organization answer the same `404`. Error details carry ids, codes and counts only;
 * never a credential, consent state, probe token or provider text.
 */
export const PROVIDER_ERROR_CODES = {
  connectionNotFound: 'connection_not_found',
  connectionLimit: 'connection_limit',
  connectionNameExists: 'connection_name_exists',
  connectionVersionConflict: 'connection_version_conflict',
  connectionDisabled: 'connection_disabled',
  connectionNotBound: 'connection_not_bound',
  grantExists: 'grant_exists',
  grantNotFound: 'grant_not_found',
  authMethodUnavailable: 'auth_method_unavailable',
  authMethodNotAllowed: 'auth_method_not_allowed',
  userPrincipalRequired: 'user_principal_required',
  consentStateInvalid: 'consent_state_invalid',
  credentialInvalid: 'credential_invalid',
  domainNotVerified: 'domain_not_verified',
  domainLinkedElsewhere: 'domain_linked_elsewhere',
  domainNotInOrganization: 'domain_not_in_organization',
  domainNotLinked: 'domain_not_linked',
  impactChanged: 'impact_changed',
  validationRequired: 'validation_required',
  outboundActive: 'outbound_active',
  changeNotApplicable: 'change_not_applicable',
  attestationUnknown: 'attestation_unknown',
  proofPolicyInvalid: 'proof_policy_invalid',
  confirmationRequired: 'confirmation_required',
  validationRunNotFound: 'validation_run_not_found',
  networkSharedProvider: 'network_shared_provider',
  connectorManagedByProviderConnection: 'connector_managed_by_provider_connection',
  domainReserved: 'domain_reserved',
  inconsistentRead: INCONSISTENT_READ,
} as const;

const C = PROVIDER_ERROR_CODES;

export const connectionNotFound = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.NOT_FOUND,
    C.connectionNotFound,
    'Provider connection not found',
  );

export const connectionLimit = (limit: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.connectionLimit,
    'The organization has reached the maximum number of provider connections',
    { limit },
  );

export const connectionNameExists = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.connectionNameExists,
    'Another provider connection of the organization has this name',
  );

export const connectionVersionConflict = (currentRowVersion: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.connectionVersionConflict,
    'rowVersion is not the current version of the connection',
    { currentRowVersion },
  );

export const connectionDisabled = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.connectionDisabled,
    'The provider connection is disconnected',
  );

/** I10: the tenant is not bound (grant active, tenant verified, ≥ 1 provider-verified domain). */
export const connectionNotBound = (status: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.connectionNotBound,
    'The connection is not bound to a verified provider tenant with a verified domain yet',
    { status },
  );

export const grantExists = (status: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.grantExists,
    'The connection already has a grant for this permission profile',
    { status },
  );

export const grantNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, C.grantNotFound, 'Grant not found');

export const authMethodUnavailable = (authMethod: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.authMethodUnavailable,
    'The platform app or service account of this method is not configured on this deployment',
    { authMethod },
  );

export const authMethodNotAllowed = (authMethod: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.authMethodNotAllowed,
    'The authentication method is not allowed for this provider, profile or operation',
    { authMethod },
  );

export const userPrincipalRequired = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.FORBIDDEN,
    C.userPrincipalRequired,
    'Admin consent is bound to a signed-in user; API keys cannot start or complete it',
  );

export const consentStateInvalid = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.NOT_FOUND,
    C.consentStateInvalid,
    'The consent state is unknown, expired, already used or belongs to another user',
  );

/** A credential failed its schema; `field` names the field, never its value. */
export const credentialInvalid = (field: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.credentialInvalid,
    'The credential is invalid',
    { field },
  );

export const domainNotVerified = (domainId: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.domainNotVerified,
    'The domain is not verified at the gateway (verified or active needed)',
    { domainId },
  );

export const domainLinkedElsewhere = (domainId: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.domainLinkedElsewhere,
    'The domain is linked to another provider connection',
    { domainId },
  );

export const domainNotInOrganization = (domainId: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.NOT_FOUND,
    C.domainNotInOrganization,
    'Unknown domain, or a domain of another organization',
    { domainId },
  );

export const domainNotLinked = (domainId: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.domainNotLinked,
    'The domain is not linked to this connection',
    { domainId },
  );

export const impactChanged = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.impactChanged,
    'The impact token is invalid, expired, of another user, or the change set changed since ' +
      'the preview; preview again',
  );

export const validationRequired = (reason: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.validationRequired,
    'Activation needs a passed validation (and a passed outbound probe within 7 days)',
    { reason },
  );

export const outboundActive = (outboundMode: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.outboundActive,
    'Outbound routing through the gateway is on; turn it off first',
    { outboundMode },
  );

export const changeNotApplicable = (reason: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.changeNotApplicable,
    'The change does not apply to the connection in its current state',
    { reason },
  );

export const attestationUnknown = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.attestationUnknown,
    'Unknown attestation code for this provider',
  );

export const proofPolicyInvalid = (issues: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.proofPolicyInvalid,
    'The relay proof policy breaks a provider bound (provider-relay-proof/1)',
    { issues },
  );

export const confirmationRequired = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.BAD_REQUEST,
    C.confirmationRequired,
    'Applying a mail-flow change needs `confirm: true`',
  );

export const validationRunNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, C.validationRunNotFound, 'Validation run not found');

/** D7.6: a `source_ip` network overlaps an active provider egress range. */
export const networkSharedProvider = (index: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.networkSharedProvider,
    'The network overlaps the shared sending ranges of Microsoft 365 or Google Workspace; ' +
      'connect the provider as a Microsoft 365 / Google Workspace connection instead',
    { index },
  );

export const connectorManagedByProviderConnection = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    C.connectorManagedByProviderConnection,
    'This connector is managed by a Microsoft 365 / Google Workspace connection; change it ' +
      'through the connection',
  );

/** §4.4: a tenant domain equal to or under PROVIDER_PROBE_DOMAIN. */
export const domainReserved = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.domainReserved,
    'The domain name is reserved by the platform',
  );
