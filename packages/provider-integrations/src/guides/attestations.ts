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

// ---------------------------------------------------------------------------------------------
// Step 8.6: journal intake guides (D10, ADR-0087)
// ---------------------------------------------------------------------------------------------

/**
 * Journal intake source kinds (`journal_intake_sources.kind`, restated from
 * `@email-gateway/archive` `INTAKE_SOURCE_KINDS`; this package does not depend on it).
 */
export const JOURNAL_INTAKE_KINDS = [
  'microsoft_365_journal',
  'google_workspace_copy',
  'exchange_onprem_journal',
  'smtp_bcc',
] as const;
export type JournalIntakeKind = (typeof JOURNAL_INTAKE_KINDS)[number];

/**
 * Attestation codes of the journal intake guides: the customer-side steps the gateway cannot
 * observe. The intake wizard's `configure` step requires every code of the source's kind.
 * Statements, not proofs.
 */
export interface IntakeAttestationDefinition {
  code: string;
  kind: JournalIntakeKind;
  statement: string;
  requiredFor: 'configure';
}

export const INTAKE_ATTESTATIONS: readonly IntakeAttestationDefinition[] = Object.freeze([
  {
    code: 'journal.m365.rule_created',
    kind: 'microsoft_365_journal',
    statement:
      'The journal rule "Email security gateway journal" sends journal reports to the intake address.',
    requiredFor: 'configure',
  },
  {
    code: 'journal.m365.ndr_mailbox_set',
    kind: 'microsoft_365_journal',
    statement: 'A mailbox for undeliverable journal reports is set and reviewed.',
    requiredFor: 'configure',
  },
  {
    code: 'journal.google.route_created',
    kind: 'google_workspace_copy',
    statement:
      'The routing setting "Email security gateway journal" also delivers inbound, outbound and internal mail to the intake address.',
    requiredFor: 'configure',
  },
  {
    code: 'journal.google.headers_added',
    kind: 'google_workspace_copy',
    statement:
      'The routing setting adds the X-Gm-Original-To header and the X-EG-Journal-Token header with the current token.',
    requiredFor: 'configure',
  },
  {
    code: 'journal.onprem.journal_recipient_created',
    kind: 'exchange_onprem_journal',
    statement:
      'The journal recipient for the intake address exists and a journal rule or mailbox database journaling uses it.',
    requiredFor: 'configure',
  },
  {
    code: 'journal.onprem.send_connector_tls',
    kind: 'exchange_onprem_journal',
    statement:
      'A Send connector delivers mail for the intake domain to the gateway hosts and requires TLS.',
    requiredFor: 'configure',
  },
  {
    code: 'journal.smtp.bcc_configured',
    kind: 'smtp_bcc',
    statement:
      'The mail server sends a BCC copy of the mail to archive to the intake address over TLS.',
    requiredFor: 'configure',
  },
] satisfies IntakeAttestationDefinition[]);

export const intakeAttestationsFor = (kind: JournalIntakeKind): IntakeAttestationDefinition[] =>
  INTAKE_ATTESTATIONS.filter((a) => a.kind === kind);

export const intakeAttestationByCode = (
  kind: JournalIntakeKind,
  code: string,
): IntakeAttestationDefinition | undefined =>
  INTAKE_ATTESTATIONS.find((a) => a.kind === kind && a.code === code);

/** Codes the intake wizard's `configure` step requires for a kind. */
export const intakeConfigureAttestations = (kind: JournalIntakeKind): string[] =>
  intakeAttestationsFor(kind)
    .filter((a) => a.requiredFor === 'configure')
    .map((a) => a.code);
