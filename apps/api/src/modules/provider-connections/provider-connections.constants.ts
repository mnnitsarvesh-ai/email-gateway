/**
 * Constants of the provider-connections module (step 8.2 §5,
 * docs/plan/steps/25-m365-google-connectors.md; ADR-0076–ADR-0081).
 */

/** Permissions (seed catalogue, step 8.2 D16). */
export const INTEGRATION_READ = 'integration:read';
export const INTEGRATION_MANAGE = 'integration:manage';
/** The second permission of a gateway-side mail-flow change (D13). */
export const DOMAIN_ROUTING_MANAGE = 'domain:routing_manage';
export const CONNECTOR_MANAGE = 'connector:manage';

/** `audit_logs.resource_type` of every row of the module (§5.4). */
export const PROVIDER_CONNECTION_RESOURCE_TYPE = 'provider_connection';

/** Audit actions (§5.4). Metadata: ids, codes, counts, domain names; never a secret or token. */
export const PROVIDER_AUDIT = {
  connectionCreated: 'integration.connection_created',
  connectionUpdated: 'integration.connection_updated',
  connectionDisconnected: 'integration.connection_disconnected',
  grantCreated: 'integration.grant_created',
  grantConsented: 'integration.grant_consented',
  grantCredentialsSet: 'integration.grant_credentials_set',
  grantVerificationRequested: 'integration.grant_verification_requested',
  grantRevoked: 'integration.grant_revoked',
  domainsLinked: 'integration.domains_linked',
  mailFlowPreviewed: 'integration.mail_flow_previewed',
  mailFlowApplied: 'integration.mail_flow_applied',
  attestationRecorded: 'integration.attestation_recorded',
  validationRequested: 'integration.validation_requested',
  healthCheckRequested: 'integration.health_check_requested',
} as const;

/** Stable Idempotency-Key operation names (one key space per organization, §5.1). */
export const PROVIDER_OPERATIONS = {
  create: 'provider_connection.create',
  disconnect: 'provider_connection.disconnect',
  grantCreate: 'provider_grant.create',
  consentComplete: 'provider_grant.consent_complete',
  credentialsSet: 'provider_grant.credentials_set',
  grantVerify: 'provider_grant.verify',
  grantRevoke: 'provider_grant.revoke',
  domainsReplace: 'provider_connection.domains_replace',
  mailFlowApply: 'provider_connection.mail_flow_apply',
  attestationRecord: 'provider_connection.attestation_record',
  validationCreate: 'provider_validation.create',
  healthCheck: 'provider_connection.health_check',
} as const;

/** v1 cursor resources (ADR-0051). */
export const PROVIDER_CONNECTIONS_RESOURCE = 'provider_connections';
export const PROVIDER_VALIDATIONS_RESOURCE = 'provider_validation_runs';

/** Writer transaction budget of the module's mutations (applies lock several rows). */
export const PROVIDER_TX_TIMEOUT_MS = 30_000;

/** Health transitions returned by `GET …/health` (§5.2 #22). */
export const HEALTH_TRANSITIONS_SHOWN = 20;
/** An outbound probe pass is valid for activation this long (D13). */
export const PROBE_PASS_MAX_AGE_MS = 7 * 24 * 3_600_000;
/** At most this many attestations are stored per connection (`provider-attestations/1`). */
export const MAX_ATTESTATIONS = 32;
/** Schema tag of `provider_connections.attestations`. */
export const ATTESTATIONS_SCHEMA = 'provider-attestations/1';
