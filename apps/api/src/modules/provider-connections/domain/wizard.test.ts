import {
  inboundRequiredAttestations,
  internalRoutingAttestation,
} from '@email-gateway/provider-integrations';
import { describe, expect, it } from 'vitest';
import { computeWizard, validateDone, type WizardInput, type WizardStep } from './wizard';

const M365_INBOUND = [...inboundRequiredAttestations('microsoft_365')];

/** A Microsoft 365 connection that has completed every step (outbound active). */
const complete = (over: Partial<WizardInput> = {}): WizardInput => ({
  provider: 'microsoft_365',
  connectionStatus: 'active',
  outboundMode: 'active',
  internalRouting: false,
  tenantVerified: true,
  mailFlowGrant: 'active',
  domains: [{ gatewayActive: true, providerVerified: true, destinationProvider: 'microsoft_365' }],
  relayConnector: true,
  attestations: M365_INBOUND,
  latestFullRun: 'passed',
  ...over,
});

const statusOf = (input: WizardInput) =>
  Object.fromEntries(computeWizard(input).steps.map((s) => [s.step, s.status])) as Record<
    WizardStep,
    string
  >;
const step = (input: WizardInput, name: WizardStep) =>
  computeWizard(input).steps.find((s) => s.step === name)!;

describe('computeWizard (step 8.2 D13 table)', () => {
  it('a fresh draft: connect not started, everything else blocked by its predecessors', () => {
    const state = computeWizard(
      complete({
        connectionStatus: 'draft',
        mailFlowGrant: null,
        tenantVerified: false,
        domains: [],
        relayConnector: false,
        outboundMode: 'off',
        attestations: [],
        latestFullRun: null,
      }),
    );
    expect(state.steps.map((s) => [s.step, s.status, s.blockers])).toEqual([
      ['connect', 'not_started', []],
      ['domains', 'blocked', ['connect']],
      ['inbound', 'blocked', ['domains']],
      ['outbound', 'blocked', ['domains']],
      ['validate', 'blocked', ['inbound', 'outbound']],
      ['activate', 'blocked', ['validate']],
    ]);
    expect(state.nextAction).toEqual({ step: 'connect', action: 'grant_access' });
  });

  it.each([
    ['pending_consent', true, 'consent_pending'],
    ['verifying', false, 'verification_pending'],
    ['error', false, 'grant_error'],
  ] as const)('connect in progress for a %s grant (tenant verified: %s)', (grant, tenant, code) => {
    const s = step(complete({ mailFlowGrant: grant, tenantVerified: tenant }), 'connect');
    expect(s).toEqual({ step: 'connect', status: 'in_progress', blockers: [code] });
  });

  it('an active grant completes connect; the unbound tenant keeps domains pending (D4)', () => {
    const input = complete({ tenantVerified: false, connectionStatus: 'configuring' });
    expect(step(input, 'connect')).toEqual({ step: 'connect', status: 'done', blockers: [] });
    expect(step(input, 'domains')).toEqual({
      step: 'domains',
      status: 'in_progress',
      blockers: ['binding_pending'],
    });
  });

  it('a revoked grant restarts the connect step', () => {
    expect(step(complete({ mailFlowGrant: 'revoked' }), 'connect').status).toBe('not_started');
  });

  it('domains: none linked, not gateway-active, none provider-verified, binding pending (I10)', () => {
    expect(step(complete({ domains: [] }), 'domains').blockers).toEqual(['no_domain_linked']);
    expect(
      step(
        complete({
          domains: [{ gatewayActive: false, providerVerified: false, destinationProvider: null }],
        }),
        'domains',
      ).blockers,
    ).toEqual(['domain_not_gateway_active', 'no_domain_provider_verified']);
    expect(step(complete({ connectionStatus: 'configuring' }), 'domains')).toEqual({
      step: 'domains',
      status: 'in_progress',
      blockers: ['binding_pending'],
    });
    // One provider-verified domain is enough (≥ 1, I10).
    expect(
      step(
        complete({
          domains: [
            { gatewayActive: true, providerVerified: true, destinationProvider: 'microsoft_365' },
            { gatewayActive: true, providerVerified: false, destinationProvider: 'microsoft_365' },
          ],
        }),
        'domains',
      ).status,
    ).toBe('done');
  });

  it('inbound: destinations with the provider preset AND the inbound attestations', () => {
    expect(
      step(
        complete({
          domains: [{ gatewayActive: true, providerVerified: true, destinationProvider: 'custom' }],
          attestations: [],
        }),
        'inbound',
      ),
    ).toEqual({
      step: 'inbound',
      status: 'not_started',
      blockers: ['destinations_missing', 'attestations_missing'],
    });
    const onlyAttestationsMissing = complete({ attestations: [] });
    expect(step(onlyAttestationsMissing, 'inbound')).toEqual({
      step: 'inbound',
      status: 'in_progress',
      blockers: ['attestations_missing'],
    });
    const state = computeWizard({ ...onlyAttestationsMissing, outboundMode: 'off' });
    expect(state.missingAttestations).toEqual(M365_INBOUND);
    expect(state.nextAction).toEqual({ step: 'inbound', action: 'record_attestations' });
  });

  it('outbound: off without a connector is skipped; probe_only with the connector is done', () => {
    expect(step(complete({ outboundMode: 'off', relayConnector: false }), 'outbound').status).toBe(
      'skipped',
    );
    expect(step(complete({ outboundMode: 'probe_only' }), 'outbound').status).toBe('done');
    expect(step(complete({ outboundMode: 'off', relayConnector: true }), 'outbound')).toEqual({
      step: 'outbound',
      status: 'in_progress',
      blockers: ['relay_connector_disabled'],
    });
  });

  it.each([
    ['passed', 'done', []],
    ['warning', 'done', []],
    [null, 'not_started', []],
    ['awaiting_probe', 'in_progress', ['run_awaiting_probe']],
    ['failed', 'in_progress', ['run_failed']],
    ['expired', 'in_progress', ['run_expired']],
  ] as const)('validate with the newest full run %s → %s', (run, status, blockers) => {
    const s = step(complete({ latestFullRun: run, outboundMode: 'probe_only' }), 'validate');
    expect(s).toEqual({ step: 'validate', status, blockers });
    expect(validateDone(computeWizard(complete({ latestFullRun: run })))).toBe(status === 'done');
  });

  it('activate: active outbound (or an inbound-only setup); internal routing needs its attestation', () => {
    expect(statusOf(complete())).toEqual({
      connect: 'done',
      domains: 'done',
      inbound: 'done',
      outbound: 'done',
      validate: 'done',
      activate: 'done',
    });
    expect(computeWizard(complete()).nextAction).toBeNull();
    expect(step(complete({ outboundMode: 'off', relayConnector: false }), 'activate').status).toBe(
      'done',
    );
    expect(step(complete({ outboundMode: 'probe_only' }), 'activate').status).toBe('not_started');
    expect(step(complete({ outboundMode: 'suspended' }), 'activate').blockers).toEqual([
      'outbound_suspended',
    ]);
    const internal = complete({ internalRouting: true });
    expect(step(internal, 'activate').blockers).toEqual(['internal_routing_attestation_missing']);
    expect(computeWizard(internal).missingAttestations).toEqual([
      internalRoutingAttestation('microsoft_365'),
    ]);
    const attested = complete({
      internalRouting: true,
      attestations: [...M365_INBOUND, internalRoutingAttestation('microsoft_365')],
    });
    expect(step(attested, 'activate').status).toBe('done');
  });

  it('Google Workspace uses its own attestation codes', () => {
    const google = complete({
      provider: 'google_workspace',
      domains: [
        { gatewayActive: true, providerVerified: true, destinationProvider: 'google_workspace' },
      ],
      attestations: M365_INBOUND,
    });
    expect(step(google, 'inbound').blockers).toEqual(['attestations_missing']);
    expect(computeWizard(google).missingAttestations).toEqual([
      ...inboundRequiredAttestations('google_workspace'),
    ]);
    expect(
      step(
        { ...google, attestations: [...inboundRequiredAttestations('google_workspace')] },
        'inbound',
      ).status,
    ).toBe('done');
  });

  it('a disabled connection blocks everything and offers no next action', () => {
    const state = computeWizard(complete({ connectionStatus: 'disabled' }));
    expect(state.steps[0]).toEqual({
      step: 'connect',
      status: 'blocked',
      blockers: ['connection_disabled'],
    });
    expect(state.steps.every((s) => s.status === 'blocked')).toBe(true);
    expect(state.nextAction).toBeNull();
  });
});
