import { describe, expect, it } from 'vitest';
import {
  computeIntakeWizard,
  type IntakeWizardInput,
  type IntakeWizardStep,
  type IntakeWizardStepStatus,
} from './intake-wizard';

const M365: IntakeWizardInput = {
  kind: 'microsoft_365_journal',
  sourceStatus: 'active',
  archiving: { entitled: true, intakeEntitled: true, enabled: true, defaultRetention: true },
  verifiedDomains: 2,
  linkedVerifiedDomains: 1,
  connection: { status: 'active', bound: true },
  attestations: ['journal.m365.rule_created', 'journal.m365.ndr_mailbox_set'],
  verified: true,
  health: 'healthy',
};

const SMTP: IntakeWizardInput = {
  ...M365,
  kind: 'smtp_bcc',
  linkedVerifiedDomains: 0,
  connection: null,
  attestations: ['journal.smtp.bcc_configured'],
};

const statuses = (input: IntakeWizardInput) =>
  Object.fromEntries(computeIntakeWizard(input).steps.map((s) => [s.step, s.status])) as Record<
    IntakeWizardStep,
    IntakeWizardStepStatus
  >;

const blockersOf = (input: IntakeWizardInput, step: IntakeWizardStep) =>
  computeIntakeWizard(input).steps.find((s) => s.step === step)!.blockers;

describe('computeIntakeWizard (step 8.6 D10)', () => {
  it('a fully configured, verified, healthy Microsoft 365 source is done everywhere', () => {
    const state = computeIntakeWizard(M365);
    expect(state.steps.map((s) => s.status)).toEqual([
      'done',
      'done',
      'done',
      'done',
      'done',
      'done',
    ]);
    expect(state.nextAction).toBeNull();
    expect(state.missingAttestations).toEqual([]);
  });

  it('network kinds skip the connection step', () => {
    expect(statuses(SMTP)).toEqual({
      archiving: 'done',
      domains: 'done',
      connection: 'skipped',
      configure: 'done',
      verify: 'done',
      monitor: 'done',
    });
    expect(blockersOf({ ...SMTP, linkedVerifiedDomains: 0 }, 'domains')).toEqual([]);
  });

  it.each<[string, Partial<IntakeWizardInput>, IntakeWizardStep, IntakeWizardStepStatus, string[]]>(
    [
      [
        'not entitled to archiving',
        { archiving: { ...M365.archiving, entitled: false } },
        'archiving',
        'blocked',
        ['archiving_not_entitled'],
      ],
      [
        'not entitled to journal intake',
        { archiving: { ...M365.archiving, intakeEntitled: false } },
        'archiving',
        'blocked',
        ['journal_intake_not_entitled'],
      ],
      [
        'archiving disabled without default retention',
        { archiving: { ...M365.archiving, enabled: false, defaultRetention: false } },
        'archiving',
        'not_started',
        ['archiving_disabled', 'default_retention_missing'],
      ],
      [
        'archiving enabled without default retention',
        { archiving: { ...M365.archiving, defaultRetention: false } },
        'archiving',
        'in_progress',
        ['default_retention_missing'],
      ],
      [
        'no verified domain',
        { verifiedDomains: 0 },
        'domains',
        'not_started',
        ['no_verified_domain'],
      ],
      [
        'no domain linked to the connection',
        { linkedVerifiedDomains: 0 },
        'domains',
        'in_progress',
        ['no_linked_domain'],
      ],
      [
        'connection disabled',
        { connection: { status: 'disabled', bound: true } },
        'connection',
        'blocked',
        ['connection_disabled'],
      ],
      [
        'connection not bound',
        { connection: { status: 'configuring', bound: false } },
        'connection',
        'in_progress',
        ['connection_not_bound'],
      ],
      ['connection missing', { connection: null }, 'connection', 'blocked', ['connection_missing']],
      [
        'one attestation missing',
        { attestations: ['journal.m365.rule_created'] },
        'configure',
        'in_progress',
        ['attestations_missing'],
      ],
      [
        'no attestation',
        { attestations: [] },
        'configure',
        'not_started',
        ['attestations_missing'],
      ],
      [
        'configure blocked by the connection',
        { connection: { status: 'configuring', bound: false } },
        'configure',
        'blocked',
        ['connection'],
      ],
      [
        'configured but not verified',
        { verified: false },
        'verify',
        'in_progress',
        ['awaiting_first_message'],
      ],
      [
        'neither configured nor verified',
        { verified: false, attestations: [] },
        'verify',
        'not_started',
        ['awaiting_first_message'],
      ],
      ['not verified blocks monitoring', { verified: false }, 'monitor', 'blocked', ['verify']],
      ['failing', { health: 'failing' }, 'monitor', 'in_progress', ['health_failing']],
      ['silent', { health: 'silent' }, 'monitor', 'in_progress', ['health_silent']],
      [
        'paused',
        { sourceStatus: 'paused', health: 'paused' },
        'monitor',
        'in_progress',
        ['source_paused'],
      ],
      ['unknown health after verification', { health: 'unknown' }, 'monitor', 'done', []],
    ],
  )('%s', (_name, patch, step, status, blockers) => {
    const input = { ...M365, ...patch };
    expect(statuses(input)[step]).toBe(status);
    expect(blockersOf(input, step)).toEqual(blockers);
  });

  it('a verified source stays verified even when the statements are missing', () => {
    expect(statuses({ ...M365, attestations: [] }).verify).toBe('done');
  });

  it('a disabled source blocks every step and has no next action', () => {
    const state = computeIntakeWizard({ ...M365, sourceStatus: 'disabled' });
    expect(state.steps.every((s) => s.status === 'blocked')).toBe(true);
    expect(state.steps.every((s) => s.blockers[0] === 'source_disabled')).toBe(true);
    expect(state.nextAction).toBeNull();
  });

  it.each<[IntakeWizardInput, { step: IntakeWizardStep; action: string }]>([
    [
      { ...M365, archiving: { ...M365.archiving, enabled: false } },
      { step: 'archiving', action: 'enable_archiving' },
    ],
    [
      { ...M365, linkedVerifiedDomains: 0 },
      { step: 'domains', action: 'link_domain' },
    ],
    [
      { ...SMTP, verifiedDomains: 0 },
      { step: 'domains', action: 'verify_domain' },
    ],
    [
      { ...M365, connection: { status: 'configuring', bound: false } },
      { step: 'connection', action: 'bind_connection' },
    ],
    [
      { ...M365, attestations: [] },
      { step: 'configure', action: 'configure_journal_rule' },
    ],
    [
      {
        ...M365,
        kind: 'google_workspace_copy',
        attestations: [],
      },
      { step: 'configure', action: 'configure_routing_rule' },
    ],
    [
      { ...SMTP, attestations: [] },
      { step: 'configure', action: 'configure_bcc' },
    ],
    [
      { ...M365, verified: false },
      { step: 'verify', action: 'send_first_message' },
    ],
    [
      { ...M365, health: 'failing' },
      { step: 'monitor', action: 'review_health' },
    ],
  ])('next action %#', (input, action) => {
    expect(computeIntakeWizard(input).nextAction).toEqual(action);
  });

  it('lists the missing attestations of the kind', () => {
    expect(
      computeIntakeWizard({ ...M365, kind: 'google_workspace_copy', attestations: [] })
        .missingAttestations,
    ).toEqual(['journal.google.route_created', 'journal.google.headers_added']);
    expect(
      computeIntakeWizard({ ...SMTP, kind: 'exchange_onprem_journal', attestations: [] })
        .missingAttestations,
    ).toEqual(['journal.onprem.journal_recipient_created', 'journal.onprem.send_connector_tls']);
  });

  it('step API-1 D6: active API mode entitles the source without archiving (archiving skipped)', () => {
    const noArchiving = {
      ...M365,
      archiving: {
        entitled: false,
        intakeEntitled: true,
        enabled: false,
        defaultRetention: false,
        apiModeActive: true,
      },
    };
    const state = computeIntakeWizard(noArchiving);
    expect(state.steps[0]).toEqual({
      step: 'archiving',
      status: 'skipped',
      blockers: [],
      reason: 'api_mode',
    });
    expect(state.steps.every((s) => s.status === 'done' || s.status === 'skipped')).toBe(true);
    expect(state.nextAction).toBeNull();
    // Archiving entitled but disabled: API mode still entitles.
    expect(
      statuses({
        ...noArchiving,
        archiving: { ...noArchiving.archiving, entitled: true, enabled: false },
      }).archiving,
    ).toBe('skipped');
    // Ready archiving stays `done` (no reason) even with API mode.
    expect(
      computeIntakeWizard({ ...M365, archiving: { ...M365.archiving, apiModeActive: true } })
        .steps[0],
    ).toEqual({ step: 'archiving', status: 'done', blockers: [] });
    // Without journal_intake, API mode does not help.
    expect(
      blockersOf(
        { ...noArchiving, archiving: { ...noArchiving.archiving, intakeEntitled: false } },
        'archiving',
      ),
    ).toEqual(['archiving_not_entitled', 'journal_intake_not_entitled']);
    // Without API mode the 8.6 rules are unchanged.
    expect(
      statuses({ ...noArchiving, archiving: { ...noArchiving.archiving, apiModeActive: false } })
        .archiving,
    ).toBe('blocked');
  });
});
