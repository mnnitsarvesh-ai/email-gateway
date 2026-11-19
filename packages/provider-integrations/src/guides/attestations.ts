import type { IntegrationProvider } from '../types';

/**
 * Attestation codes of the setup guides (D13, D14, ADR-0080): statements by the customer's
 * administrator about customer-side changes the gateway cannot observe with read-only access.
 * They are statements, not proofs, and are labelled so everywhere they are shown.
 */
export interface AttestationDefinition {
  code: string;
  provider: IntegrationProvider;
  /** Guide area the step belongs to. */
  phase: 'inbound' | 'outbound' | 'internal' | 'lockdown';
  /** The statement the administrator confirms. */
  statement: string;
  /**
   * Wizard step that requires it (`inbound` requires its inbound attestations; `activate`
   * requires the internal-routing attestation when internal routing is chosen), or null.
   */
  requiredFor: 'inbound' | 'activate' | null;
}

export const ATTESTATIONS: readonly AttestationDefinition[] = Object.freeze([
  {
    code: 'm365.inbound_connector_created',
    provider: 'microsoft_365',
    phase: 'inbound',
    statement:
      'The inbound partner connector "Email security gateway" exists and accepts mail from the gateway only over TLS.',
    requiredFor: 'inbound',
  },
  {
    code: 'm365.enhanced_filtering_enabled',
    provider: 'microsoft_365',
    phase: 'inbound',
    statement: 'Enhanced Filtering for Connectors is enabled on the inbound connector.',
    requiredFor: 'inbound',
  },
  {
    code: 'm365.direct_delivery_locked_down',
    provider: 'microsoft_365',
    phase: 'lockdown',
    statement:
      'Mail that does not arrive through the gateway is rejected or quarantined by Exchange Online.',
    requiredFor: null,
  },
  {
    code: 'm365.outbound_connector_created',
    provider: 'microsoft_365',
    phase: 'outbound',
    statement:
      'The outbound connector "Email security gateway outbound" exists with the gateway relay hosts as smart hosts.',
    requiredFor: null,
  },
  {
    code: 'm365.internal_routing_rules_created',
    provider: 'microsoft_365',
    phase: 'internal',
    statement:
      'The transport rules "Route internal mail through the email security gateway" and "Remove the gateway route token" exist with the current route token.',
    requiredFor: 'activate',
  },
  {
    code: 'm365.internal_routing_rules_updated',
    provider: 'microsoft_365',
    phase: 'internal',
    statement: 'The two internal-routing transport rules were updated for the new route token.',
    requiredFor: null,
  },
  {
    code: 'google.inbound_gateway_configured',
    provider: 'google_workspace',
    phase: 'inbound',
    statement: 'The Gmail inbound gateway lists the gateway addresses and requires TLS from them.',
    requiredFor: 'inbound',
  },
  {
    code: 'google.reject_non_gateway_enabled',
    provider: 'google_workspace',
    phase: 'lockdown',
    statement: 'Gmail rejects all mail that does not come from the gateway addresses.',
    requiredFor: null,
  },
  {
    code: 'google.outbound_route_configured',
    provider: 'google_workspace',
    phase: 'outbound',
    statement:
      'The host "Email security gateway" and the routing rule that sends outbound mail through it exist.',
    requiredFor: null,
  },
  {
    code: 'google.smtp_relay_configured',
    provider: 'google_workspace',
    phase: 'outbound',
    statement:
      'The SMTP relay service requires authentication and TLS, so device and application mail follows the gateway route.',
    requiredFor: null,
  },
  {
    code: 'google.internal_routing_configured',
    provider: 'google_workspace',
    phase: 'internal',
    statement: 'The gateway routing rule also applies to internal sending.',
    requiredFor: 'activate',
  },
] satisfies AttestationDefinition[]);

export const attestationsFor = (provider: IntegrationProvider): AttestationDefinition[] =>
  ATTESTATIONS.filter((a) => a.provider === provider);

export const attestationByCode = (
  provider: IntegrationProvider,
  code: string,
): AttestationDefinition | undefined =>
  ATTESTATIONS.find((a) => a.provider === provider && a.code === code);

/** Codes the wizard's `inbound` step requires. */
export const inboundRequiredAttestations = (provider: IntegrationProvider): string[] =>
  attestationsFor(provider)
    .filter((a) => a.requiredFor === 'inbound')
    .map((a) => a.code);

/** Codes checked by `lockdown.attested`. */
export const lockdownAttestations = (provider: IntegrationProvider): string[] =>
  attestationsFor(provider)
    .filter((a) => a.phase === 'lockdown')
    .map((a) => a.code);

/** The internal-routing attestation the `activate` step requires when internal routing is on. */
export const internalRoutingAttestation = (provider: IntegrationProvider): string =>
  provider === 'microsoft_365'
    ? 'm365.internal_routing_rules_created'
    : 'google.internal_routing_configured';
