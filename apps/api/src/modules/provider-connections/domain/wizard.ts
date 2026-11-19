import {
  inboundRequiredAttestations,
  type IntegrationProvider,
  internalRoutingAttestation,
} from '@email-gateway/provider-integrations';

/**
 * The setup wizard of a connection, computed from rows (step 8.2 D13, ADR-0080 decision 1): never
 * a stored pointer. Pure, so every row combination is table-tested.
 */

export type WizardStep = 'connect' | 'domains' | 'inbound' | 'outbound' | 'validate' | 'activate';
export type WizardStepStatus = 'not_started' | 'in_progress' | 'done' | 'blocked' | 'skipped';

export interface WizardInput {
  provider: IntegrationProvider;
  connectionStatus: 'draft' | 'connecting' | 'configuring' | 'active' | 'disabled';
  outboundMode: 'off' | 'probe_only' | 'active' | 'suspended';
  internalRouting: boolean;
  /** The provider tenant is bound (proven by a linked domain, `active_tenant_key` set). */
  tenantVerified: boolean;
  /** The connection's `*.mail_flow` grant status (null: no grant yet). */
  mailFlowGrant: 'pending_consent' | 'verifying' | 'active' | 'error' | 'revoked' | null;
  domains: readonly {
    gatewayActive: boolean;
    providerVerified: boolean;
    /** The provider of the domain's current inbound destinations (null: none). */
    destinationProvider: string | null;
  }[];
  relayConnector: boolean;
  /** Recorded attestation codes. */
  attestations: readonly string[];
  /** Status of the newest `full` validation run (null: none). */
  latestFullRun:
    | 'queued'
    | 'running'
    | 'awaiting_probe'
    | 'passed'
    | 'warning'
    | 'failed'
    | 'expired'
    | 'cancelled'
    | null;
}

export interface WizardStepState {
  step: WizardStep;
  status: WizardStepStatus;
  blockers: string[];
}

export interface WizardState {
  steps: WizardStepState[];
  nextAction: { step: WizardStep; action: string } | null;
  missingAttestations: string[];
}

const satisfied = (s: WizardStepState): boolean => s.status === 'done' || s.status === 'skipped';

const ACTIONS: Readonly<Record<WizardStep, string>> = {
  connect: 'grant_access',
  domains: 'link_domains',
  inbound: 'apply_inbound',
  outbound: 'enable_outbound_probe',
  validate: 'run_validation',
  activate: 'activate',
};

/** Steps and their states (D13 table); `disabled` connections block everything. */
export function computeWizard(input: WizardInput): WizardState {
  const disabled = input.connectionStatus === 'disabled';
  const blockedBy = (step: WizardStep, ...deps: WizardStepState[]): WizardStepState | null => {
    const missing = deps.filter((d) => !satisfied(d)).map((d) => d.step);
    return missing.length > 0 ? { step, status: 'blocked', blockers: missing } : null;
  };

  // connect: the mail-flow grant is active (the provider accepted it for the CLAIMED tenant). The
  // tenant is bound only on proof of control by a linked domain, which the domains step shows
  // (`binding_pending`, D4/I10).
  let connect: WizardStepState;
  if (disabled) connect = { step: 'connect', status: 'blocked', blockers: ['connection_disabled'] };
  else if (input.mailFlowGrant === 'active') {
    connect = { step: 'connect', status: 'done', blockers: [] };
  } else if (input.mailFlowGrant === null || input.mailFlowGrant === 'revoked') {
    connect = { step: 'connect', status: 'not_started', blockers: [] };
  } else {
    const blockers =
      input.mailFlowGrant === 'error'
        ? ['grant_error']
        : input.mailFlowGrant === 'pending_consent'
          ? ['consent_pending']
          : ['verification_pending'];
    connect = { step: 'connect', status: 'in_progress', blockers };
  }

  // domains: ≥ 1 linked, every linked domain gateway-active, ≥ 1 provider-verified (I10).
  const domains =
    blockedBy('domains', connect) ??
    (() => {
      if (input.domains.length === 0) {
        return { step: 'domains', status: 'not_started', blockers: ['no_domain_linked'] };
      }
      const blockers: string[] = [];
      if (input.domains.some((d) => !d.gatewayActive)) blockers.push('domain_not_gateway_active');
      if (!input.domains.some((d) => d.providerVerified)) {
        blockers.push('no_domain_provider_verified');
      }
      if (blockers.length === 0 && input.connectionStatus !== 'active') {
        blockers.push('binding_pending');
      }
      return blockers.length === 0
        ? { step: 'domains', status: 'done', blockers }
        : { step: 'domains', status: 'in_progress', blockers };
    })();

  // inbound: every linked domain delivers to the provider preset, inbound attestations recorded.
  const required = inboundRequiredAttestations(input.provider);
  const missingInbound = required.filter((code) => !input.attestations.includes(code));
  const inbound =
    blockedBy('inbound', domains) ??
    (() => {
      const blockers: string[] = [];
      const applied = input.domains.filter((d) => d.destinationProvider === input.provider);
      if (applied.length < input.domains.length) blockers.push('destinations_missing');
      if (missingInbound.length > 0) blockers.push('attestations_missing');
      if (blockers.length === 0) return { step: 'inbound', status: 'done', blockers };
      const started = applied.length > 0 || missingInbound.length < required.length;
      return { step: 'inbound', status: started ? 'in_progress' : 'not_started', blockers };
    })();

  // outbound: `off` is a valid choice (skipped); otherwise the relay connector exists.
  const outbound =
    blockedBy('outbound', domains) ??
    ((): WizardStepState => {
      if (input.outboundMode === 'off' && !input.relayConnector) {
        return { step: 'outbound', status: 'skipped', blockers: [] };
      }
      if (input.relayConnector && input.outboundMode !== 'off') {
        return { step: 'outbound', status: 'done', blockers: [] };
      }
      return { step: 'outbound', status: 'in_progress', blockers: ['relay_connector_disabled'] };
    })();

  // validate: the newest full run passed (or passed with warnings).
  const validate =
    blockedBy('validate', inbound, outbound) ??
    ((): WizardStepState => {
      const run = input.latestFullRun;
      if (run === 'passed' || run === 'warning') {
        return { step: 'validate', status: 'done', blockers: [] };
      }
      if (run === null) return { step: 'validate', status: 'not_started', blockers: [] };
      if (run === 'queued' || run === 'running' || run === 'awaiting_probe') {
        return { step: 'validate', status: 'in_progress', blockers: [`run_${run}`] };
      }
      return { step: 'validate', status: 'in_progress', blockers: [`run_${run}`] };
    })();

  // activate: outbound active (or off for an inbound-only setup), internal routing chosen.
  const internalCode = internalRoutingAttestation(input.provider);
  const activate =
    blockedBy('activate', validate) ??
    ((): WizardStepState => {
      if (input.outboundMode === 'active') {
        const blockers =
          input.internalRouting && !input.attestations.includes(internalCode)
            ? ['internal_routing_attestation_missing']
            : [];
        return { step: 'activate', status: blockers.length ? 'in_progress' : 'done', blockers };
      }
      if (input.outboundMode === 'off' && outbound.status === 'skipped') {
        return { step: 'activate', status: 'done', blockers: [] };
      }
      if (input.outboundMode === 'suspended') {
        return { step: 'activate', status: 'in_progress', blockers: ['outbound_suspended'] };
      }
      return { step: 'activate', status: 'not_started', blockers: [] };
    })();

  const steps = [connect, domains, inbound, outbound, validate, activate] as WizardStepState[];
  const next = disabled ? undefined : steps.find((s) => !satisfied(s) && s.status !== 'blocked');
  const missing = [...missingInbound];
  if (input.internalRouting && !input.attestations.includes(internalCode)) {
    missing.push(internalCode);
  }
  return {
    steps,
    nextAction:
      next === undefined
        ? null
        : {
            step: next.step,
            action:
              next.step === 'inbound' && next.blockers.length === 1 && missingInbound.length > 0
                ? 'record_attestations'
                : ACTIONS[next.step],
          },
    missingAttestations: missing,
  };
}

/** Whether the `validate` step is done (activation precondition, D13). */
export const validateDone = (state: WizardState): boolean =>
  state.steps.find((s) => s.step === 'validate')?.status === 'done';
