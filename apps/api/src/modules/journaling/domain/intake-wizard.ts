import { intakeConfigureAttestations } from '@email-gateway/provider-integrations';

/**
 * The setup wizard of a journal intake source, computed from rows (step 8.6 D10; the 8.2
 * `computeWizard` pattern, ADR-0080 decision 1): never a stored pointer. Pure, so every row
 * combination is table-tested.
 */

export type IntakeKind =
  'microsoft_365_journal' | 'google_workspace_copy' | 'exchange_onprem_journal' | 'smtp_bcc';

export type IntakeWizardStep =
  'archiving' | 'domains' | 'connection' | 'configure' | 'verify' | 'monitor';
export type IntakeWizardStepStatus = 'not_started' | 'in_progress' | 'done' | 'blocked' | 'skipped';

export interface IntakeWizardInput {
  kind: IntakeKind;
  sourceStatus: 'pending_verification' | 'active' | 'paused' | 'disabled';
  archiving: {
    /** Plan feature `archiving`. */
    entitled: boolean;
    /** Plan feature `journal_intake`. */
    intakeEntitled: boolean;
    /** Archiving (capture) is enabled. */
    enabled: boolean;
    /** A live default retention policy is set. */
    defaultRetention: boolean;
    /**
     * Step API-1 D6: API mode is active (`api_mode_protection` and a domain effective
     * `api`/`hybrid`): it entitles the source without archiving. Default false.
     */
    apiModeActive?: boolean;
  };
  /** TXT-verified (`verified`/`active`) domains of the organization. */
  verifiedDomains: number;
  /** Provider kinds: verified domains linked to the bound connection. */
  linkedVerifiedDomains: number;
  /** Provider kinds: the 8.2 connection (null for network kinds). */
  connection: {
    status: 'draft' | 'connecting' | 'configuring' | 'active' | 'disabled';
    /** `active_tenant_key` and `external_tenant_id` set (8.2 D4). */
    bound: boolean;
  } | null;
  /** Recorded attestation codes. */
  attestations: readonly string[];
  /** The first accepted intake message (`verified_at`). */
  verified: boolean;
  health: 'unknown' | 'healthy' | 'silent' | 'failing' | 'paused';
}

export interface IntakeWizardStepState {
  step: IntakeWizardStep;
  status: IntakeWizardStepStatus;
  blockers: string[];
  /** Why a step is `skipped` when the kind alone does not explain it (step API-1: `api_mode`). */
  reason?: string;
}

export interface IntakeWizardState {
  steps: IntakeWizardStepState[];
  nextAction: { step: IntakeWizardStep; action: string } | null;
  missingAttestations: string[];
}

const PROVIDER_KINDS: ReadonlySet<IntakeKind> = new Set([
  'microsoft_365_journal',
  'google_workspace_copy',
]);

export const isProviderKind = (kind: IntakeKind): boolean => PROVIDER_KINDS.has(kind);

const satisfied = (s: IntakeWizardStepState): boolean =>
  s.status === 'done' || s.status === 'skipped';

const CONFIGURE_ACTION: Readonly<Record<IntakeKind, string>> = {
  microsoft_365_journal: 'configure_journal_rule',
  google_workspace_copy: 'configure_routing_rule',
  exchange_onprem_journal: 'configure_journal_rule',
  smtp_bcc: 'configure_bcc',
};

function actionOf(step: IntakeWizardStep, kind: IntakeKind): string {
  switch (step) {
    case 'archiving':
      return 'enable_archiving';
    case 'domains':
      return isProviderKind(kind) ? 'link_domain' : 'verify_domain';
    case 'connection':
      return 'bind_connection';
    case 'configure':
      return CONFIGURE_ACTION[kind];
    case 'verify':
      return 'send_first_message';
    case 'monitor':
      return 'review_health';
  }
}

/** Steps and their states (D10); a `disabled` source blocks everything. */
export function computeIntakeWizard(input: IntakeWizardInput): IntakeWizardState {
  const required = intakeConfigureAttestations(input.kind);
  const missingAttestations = required.filter((c) => !input.attestations.includes(c));
  const order: IntakeWizardStep[] = [
    'archiving',
    'domains',
    'connection',
    'configure',
    'verify',
    'monitor',
  ];
  if (input.sourceStatus === 'disabled') {
    return {
      steps: order.map((step) => ({ step, status: 'blocked', blockers: ['source_disabled'] })),
      nextAction: null,
      missingAttestations,
    };
  }
  const blockedBy = (
    step: IntakeWizardStep,
    ...deps: IntakeWizardStepState[]
  ): IntakeWizardStepState | null => {
    const missing = deps.filter((d) => !satisfied(d)).map((d) => d.step);
    return missing.length > 0 ? { step, status: 'blocked', blockers: missing } : null;
  };

  // archiving: entitled (archiving + journal_intake), enabled, with a default retention policy.
  const a = input.archiving;
  const archiving: IntakeWizardStepState = (() => {
    const notEntitled = [
      ...(a.entitled ? [] : ['archiving_not_entitled']),
      ...(a.intakeEntitled ? [] : ['journal_intake_not_entitled']),
    ];
    // Step API-1 D6: with journal intake entitled, active API mode entitles the source when
    // archiving does not (archiving not entitled, disabled or without a default policy).
    const archivingReady = a.entitled && a.enabled && a.defaultRetention;
    if (a.intakeEntitled && !archivingReady && a.apiModeActive === true) {
      return { step: 'archiving', status: 'skipped', blockers: [], reason: 'api_mode' };
    }
    if (notEntitled.length > 0)
      return { step: 'archiving', status: 'blocked', blockers: notEntitled };
    const blockers = [
      ...(a.enabled ? [] : ['archiving_disabled']),
      ...(a.defaultRetention ? [] : ['default_retention_missing']),
    ];
    if (blockers.length === 0) return { step: 'archiving', status: 'done', blockers };
    return {
      step: 'archiving',
      status: blockers.length === 2 ? 'not_started' : 'in_progress',
      blockers,
    };
  })();

  // domains: a TXT-verified domain; provider kinds: one linked to the connection.
  const domains: IntakeWizardStepState = (() => {
    if (input.verifiedDomains === 0) {
      return { step: 'domains', status: 'not_started', blockers: ['no_verified_domain'] };
    }
    if (isProviderKind(input.kind) && input.linkedVerifiedDomains === 0) {
      return { step: 'domains', status: 'in_progress', blockers: ['no_linked_domain'] };
    }
    return { step: 'domains', status: 'done', blockers: [] };
  })();

  // connection: provider kinds only; bound and not disabled (8.2 D4).
  const connection: IntakeWizardStepState = (() => {
    if (!isProviderKind(input.kind)) return { step: 'connection', status: 'skipped', blockers: [] };
    const c = input.connection;
    if (c === null)
      return { step: 'connection', status: 'blocked', blockers: ['connection_missing'] };
    if (c.status === 'disabled') {
      return { step: 'connection', status: 'blocked', blockers: ['connection_disabled'] };
    }
    if (!c.bound) {
      return { step: 'connection', status: 'in_progress', blockers: ['connection_not_bound'] };
    }
    return { step: 'connection', status: 'done', blockers: [] };
  })();

  // configure: the customer-side attestations of the kind's guide.
  const configure =
    blockedBy('configure', archiving, domains, connection) ??
    ((): IntakeWizardStepState => {
      if (missingAttestations.length === 0) {
        return { step: 'configure', status: 'done', blockers: [] };
      }
      return {
        step: 'configure',
        status: missingAttestations.length < required.length ? 'in_progress' : 'not_started',
        blockers: ['attestations_missing'],
      };
    })();

  // verify: the first accepted message (a source can verify before every statement is made).
  const verify: IntakeWizardStepState = input.verified
    ? { step: 'verify', status: 'done', blockers: [] }
    : (blockedBy('verify', archiving, domains, connection) ?? {
        step: 'verify',
        status: satisfied(configure) ? 'in_progress' : 'not_started',
        blockers: ['awaiting_first_message'],
      });

  // monitor: verified and not failing, silent or paused.
  const monitor =
    blockedBy('monitor', verify) ??
    ((): IntakeWizardStepState => {
      if (input.sourceStatus === 'paused' || input.health === 'paused') {
        return { step: 'monitor', status: 'in_progress', blockers: ['source_paused'] };
      }
      if (input.health === 'failing') {
        return { step: 'monitor', status: 'in_progress', blockers: ['health_failing'] };
      }
      if (input.health === 'silent') {
        return { step: 'monitor', status: 'in_progress', blockers: ['health_silent'] };
      }
      return { step: 'monitor', status: 'done', blockers: [] };
    })();

  const steps = [archiving, domains, connection, configure, verify, monitor];
  const next = steps.find((s) => !satisfied(s) && s.status !== 'blocked') ?? null;
  return {
    steps,
    nextAction: next === null ? null : { step: next.step, action: actionOf(next.step, input.kind) },
    missingAttestations,
  };
}
