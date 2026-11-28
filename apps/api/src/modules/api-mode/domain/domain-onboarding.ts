import type { ProtectionModeValue } from '../../../tenancy/api-mode-status.service';

/**
 * The API-mode onboarding state of one domain (step API-4 B8, ADR-0107;
 * docs/plan/steps/38-api-mode-parity-onboarding.md): the wizard's steps (ownership, connect,
 * intake, mailboxes, action, review) computed from server state only (never from clicks), the
 * live first-copy check and the troubleshooting hints. Pure and table-tested.
 */

export const ONBOARDING_STEP_KEYS = [
  'ownership',
  'connect',
  'intake',
  'mailboxes',
  'action',
  'review',
] as const;
export type OnboardingStepKey = (typeof ONBOARDING_STEP_KEYS)[number];

export const ONBOARDING_STEP_STATUSES = [
  'not_started',
  'in_progress',
  'done',
  'blocked',
  'skipped',
] as const;
export type OnboardingStepStatus = (typeof ONBOARDING_STEP_STATUSES)[number];

/** Blocker codes of the steps (documented). */
export const ONBOARDING_BLOCKERS = [
  'ownership_failed',
  'ownership_pending',
  'connection_missing',
  'connection_disabled',
  'connection_not_bound',
  'mailbox_access_missing',
  'intake_missing',
  'no_mailboxes_in_scope',
  'domain_not_active',
] as const;
export type OnboardingBlocker = (typeof ONBOARDING_BLOCKERS)[number];

/** Next-action codes of the steps (documented). */
export const ONBOARDING_NEXT_ACTIONS = [
  'verify_ownership',
  'verify_through_provider',
  'restart_verification',
  'link_connection',
  'complete_binding',
  'grant_mailbox_access',
  'enable_connection',
  'set_up_journal',
  'verify_journal_source',
  'enable_feeds',
  'wait_for_feeds',
  'sync_inventory',
  'choose_mailboxes',
  'choose_action',
  'activate_domain',
  'send_test_message',
] as const;
export type OnboardingNextAction = (typeof ONBOARDING_NEXT_ACTIONS)[number];

/** First-copy hint codes (B8; documented with text and links). */
export const FIRST_COPY_HINT_CODES = [
  'domain_not_active',
  'mode_not_api',
  'connection_missing',
  'connection_not_bound',
  'mailbox_access_missing',
  'journal_source_missing',
  'journal_source_unverified',
  'journal_source_silent',
  'journal_seen_no_domain_recipient',
  'feeds_disabled',
  'feeds_initializing',
  'no_mailboxes_in_scope',
  'connection_throttled',
  'copies_failing',
  'send_test_message',
] as const;
export type FirstCopyHintCode = (typeof FIRST_COPY_HINT_CODES)[number];

/** B1 intake rule: feeds count as done on ≥ 90 % of the in-scope mailboxes. */
export const FEEDS_DONE_RATIO = 0.9;

export interface OnboardingInput {
  now: Date;
  /** `API_MODE_FIRST_COPY_HINT_AFTER_MINUTES`. */
  hintAfterMinutes: number;
  domain: {
    id: string;
    status: 'pending_verification' | 'verified' | 'active' | 'failed' | 'suspended' | 'disabled';
    effectiveMode: ProtectionModeValue;
    createdAt: Date;
    activatedAt: Date | null;
  };
  ownership: {
    method: 'dns_txt' | 'provider_tenant' | null;
    providerCheck: {
      id: string;
      status: 'pending' | 'verified' | 'failed' | 'expired';
      result: string | null;
      connectionId: string | null;
      requestedAt: string;
      checkedAt: string | null;
      expiresAt: string;
    } | null;
    providerCheckAvailable: boolean;
  };
  connection: {
    id: string;
    provider: 'microsoft_365' | 'google_workspace';
    bound: boolean;
    status: 'draft' | 'connecting' | 'configuring' | 'active' | 'disabled';
    mailFlowGrant: string | null;
    mailboxAccessGrant: string | null;
    throttledUntil: Date | null;
  } | null;
  journalSources: ReadonlyArray<{
    id: string;
    status: 'pending_verification' | 'active' | 'paused' | 'disabled';
    health: 'unknown' | 'healthy' | 'silent' | 'failing' | 'paused';
    verified: boolean;
    lastAcceptedAt: Date | null;
  }>;
  feeds: {
    enabled: boolean;
    mode: 'poll' | 'notify';
    activeMailboxes: number;
    inScopeMailboxes: number;
  };
  scope: { kind: 'all' | 'departments' | 'mailboxes'; inScope: number; excluded: number };
  /** Non-deleted mailboxes of the domain known to API mode (inventory or journal). */
  mailboxesKnown: number;
  action: {
    source: 'platform_default' | 'organization' | 'domain';
    mode: 'enforce' | 'detect_only';
    presetKey: 'p1' | 'detectOnlyStart' | 'strict' | null;
    detectOnly: { until: string; then: 'remind' | 'enforce'; ended: boolean } | null;
  };
  firstCopy: {
    detectionId: string;
    receivedAt: Date;
    verdict: string | null;
    lagMs: number | null;
    source: 'journal' | 'graph' | 'gmail';
    policyState: string;
    remediationState: string;
  } | null;
  /** Copies of the connection that failed (scan/parse) recently. */
  recentFailedCopies: number;
}

export interface OnboardingStep {
  key: OnboardingStepKey;
  status: OnboardingStepStatus;
  blockers: OnboardingBlocker[];
  nextAction: OnboardingNextAction | null;
}

export interface FirstCopyHint {
  code: FirstCopyHintCode;
  severity: 'info' | 'warn';
  link: string | null;
}

const OWNED = new Set(['verified', 'active', 'suspended', 'disabled']);
const MINUTE_MS = 60_000;

const step = (
  key: OnboardingStepKey,
  status: OnboardingStepStatus,
  blockers: OnboardingBlocker[] = [],
  nextAction: OnboardingNextAction | null = null,
): OnboardingStep => ({ key, status, blockers, nextAction });

function ownershipStep(input: OnboardingInput): OnboardingStep {
  const { domain, ownership } = input;
  if (OWNED.has(domain.status)) return step('ownership', 'done');
  if (domain.status === 'failed') {
    return step('ownership', 'blocked', ['ownership_failed'], 'restart_verification');
  }
  return step(
    'ownership',
    'in_progress',
    [],
    ownership.providerCheck?.status === 'pending'
      ? null
      : ownership.providerCheckAvailable
        ? 'verify_through_provider'
        : 'verify_ownership',
  );
}

function connectionDone(c: OnboardingInput['connection']): boolean {
  return c !== null && c.bound && c.status !== 'disabled' && c.mailboxAccessGrant === 'active';
}

function connectStep(input: OnboardingInput): OnboardingStep {
  const c = input.connection;
  if (c === null) return step('connect', 'not_started', [], 'link_connection');
  if (c.status === 'disabled') {
    return step('connect', 'blocked', ['connection_disabled'], 'enable_connection');
  }
  if (connectionDone(c)) return step('connect', 'done');
  const blockers: OnboardingBlocker[] = [];
  if (!c.bound) blockers.push('connection_not_bound');
  if (c.mailboxAccessGrant !== 'active') blockers.push('mailbox_access_missing');
  return step(
    'connect',
    'in_progress',
    blockers,
    !c.bound ? 'complete_binding' : 'grant_mailbox_access',
  );
}

const verifiedJournal = (input: OnboardingInput) =>
  input.journalSources.some((s) => s.verified && s.status !== 'disabled');

const feedsDone = (f: OnboardingInput['feeds']) =>
  f.enabled &&
  f.inScopeMailboxes > 0 &&
  f.activeMailboxes >= Math.ceil(f.inScopeMailboxes * FEEDS_DONE_RATIO);

function intakeStep(input: OnboardingInput): OnboardingStep {
  if (input.connection === null) {
    return step('intake', 'blocked', ['connection_missing'], 'link_connection');
  }
  if (verifiedJournal(input) || feedsDone(input.feeds)) return step('intake', 'done');
  if (input.journalSources.some((s) => s.status === 'pending_verification')) {
    return step('intake', 'in_progress', [], 'verify_journal_source');
  }
  if (input.feeds.enabled) return step('intake', 'in_progress', [], 'wait_for_feeds');
  return step('intake', 'not_started', [], 'set_up_journal');
}

function mailboxesStep(input: OnboardingInput): OnboardingStep {
  if (input.connection === null) {
    return step('mailboxes', 'blocked', ['connection_missing'], 'link_connection');
  }
  if (input.scope.inScope > 0) return step('mailboxes', 'done');
  if (input.mailboxesKnown === 0) return step('mailboxes', 'not_started', [], 'sync_inventory');
  return step('mailboxes', 'in_progress', ['no_mailboxes_in_scope'], 'choose_mailboxes');
}

function actionStep(input: OnboardingInput): OnboardingStep {
  if (input.action.source === 'platform_default') {
    return step('action', 'not_started', [], 'choose_action');
  }
  return step('action', 'done');
}

function reviewStep(input: OnboardingInput, steps: readonly OnboardingStep[]): OnboardingStep {
  const ownership = steps.find((s) => s.key === 'ownership')!;
  const blockers: OnboardingBlocker[] = [];
  if (ownership.status !== 'done') {
    blockers.push(input.domain.status === 'failed' ? 'ownership_failed' : 'ownership_pending');
  }
  if (input.connection === null) blockers.push('connection_missing');
  else if (input.connection.status === 'disabled') blockers.push('connection_disabled');
  else if (!input.connection.bound) blockers.push('connection_not_bound');
  if (input.connection !== null && input.connection.mailboxAccessGrant !== 'active') {
    blockers.push('mailbox_access_missing');
  }
  if (blockers.length > 0) return step('review', 'blocked', blockers, null);
  if (input.domain.status !== 'active') {
    return step('review', 'not_started', [], 'activate_domain');
  }
  if (input.firstCopy !== null) return step('review', 'done');
  return step('review', 'in_progress', [], 'send_test_message');
}

/** B8 hints, in documented order; `send_test_message` always closes the list. */
export function firstCopyHints(input: OnboardingInput): FirstCopyHint[] {
  const hints: FirstCopyHint[] = [];
  const add = (code: FirstCopyHintCode, severity: 'info' | 'warn', link: string | null = null) =>
    hints.push({ code, severity, link });
  const c = input.connection;
  const connectionLink = c === null ? '/integrations/providers' : `/integrations/providers/${c.id}`;
  if (input.domain.status !== 'active')
    add('domain_not_active', 'warn', `/domains/${input.domain.id}`);
  if (input.domain.effectiveMode === 'inline') {
    add('mode_not_api', 'warn', `/domains/${input.domain.id}`);
  }
  if (c === null) add('connection_missing', 'warn', connectionLink);
  else {
    if (!c.bound) add('connection_not_bound', 'warn', connectionLink);
    if (c.mailboxAccessGrant !== 'active') add('mailbox_access_missing', 'warn', connectionLink);
  }
  const sources = input.journalSources.filter((s) => s.status !== 'disabled');
  if (sources.length === 0) {
    add('journal_source_missing', input.feeds.enabled ? 'info' : 'warn', '/journaling');
  }
  if (sources.some((s) => s.status === 'pending_verification')) {
    add('journal_source_unverified', 'warn', '/journaling');
  }
  if (sources.some((s) => s.health === 'silent' || s.health === 'failing')) {
    add('journal_source_silent', 'warn', '/journaling');
  }
  const since = input.domain.activatedAt ?? input.domain.createdAt;
  if (
    input.firstCopy === null &&
    sources.some((s) => s.lastAcceptedAt !== null && s.lastAcceptedAt.getTime() > since.getTime())
  ) {
    add('journal_seen_no_domain_recipient', 'warn', '/journaling');
  }
  if (!input.feeds.enabled && !verifiedJournal(input)) {
    add('feeds_disabled', 'info', '/api-mode?tab=connections');
  }
  if (input.feeds.enabled && !feedsDone(input.feeds)) {
    add('feeds_initializing', 'info', '/api-mode?tab=connections');
  }
  if (input.scope.inScope === 0) {
    add('no_mailboxes_in_scope', 'warn', `/domains/${input.domain.id}`);
  }
  if (c !== null && c.throttledUntil !== null && c.throttledUntil.getTime() > input.now.getTime()) {
    add('connection_throttled', 'warn', '/api-mode?tab=connections');
  }
  if (input.recentFailedCopies > 0) {
    add('copies_failing', 'warn', '/api-mode?tab=detections&status=scan_failed');
  }
  add('send_test_message', 'info', null);
  return hints;
}

/** `GET /api-mode/domains/{domainId}/onboarding` (B8). */
export function computeDomainOnboarding(input: OnboardingInput) {
  const apiSide = input.domain.effectiveMode === 'api' || input.domain.effectiveMode === 'hybrid';
  let steps: OnboardingStep[];
  if (!apiSide) {
    steps = ONBOARDING_STEP_KEYS.map((key) => step(key, 'skipped'));
  } else {
    const first = [
      ownershipStep(input),
      connectStep(input),
      intakeStep(input),
      mailboxesStep(input),
      actionStep(input),
    ];
    steps = [...first, reviewStep(input, first)];
  }
  const waitingSince = input.domain.activatedAt ?? input.domain.createdAt;
  const waitedMinutes = Math.max(
    0,
    Math.floor((input.now.getTime() - waitingSince.getTime()) / MINUTE_MS),
  );
  const received = input.firstCopy !== null;
  const showHints = !received && waitedMinutes >= input.hintAfterMinutes;
  const c = input.connection;
  const copy = input.firstCopy;
  return {
    domainId: input.domain.id,
    effectiveMode: input.domain.effectiveMode,
    steps,
    ownership: {
      status: OWNED.has(input.domain.status)
        ? ('verified' as const)
        : input.domain.status === 'failed'
          ? ('failed' as const)
          : ('pending' as const),
      method: input.ownership.method,
      providerCheck: input.ownership.providerCheck,
      providerCheckAvailable: input.ownership.providerCheckAvailable,
    },
    connection:
      c === null
        ? null
        : {
            id: c.id,
            provider: c.provider,
            bound: c.bound,
            status: c.status,
            mailFlowGrant: c.mailFlowGrant,
            mailboxAccessGrant: c.mailboxAccessGrant,
          },
    intake: {
      journalSources: input.journalSources.map((s) => ({
        id: s.id,
        status: s.status,
        health: s.health,
      })),
      feeds: { ...input.feeds },
    },
    scope: { ...input.scope },
    action: {
      source: input.action.source,
      mode: input.action.mode,
      presetKey: input.action.presetKey,
      detectOnly: input.action.detectOnly,
    },
    firstCopy: {
      status: received ? ('received' as const) : ('waiting' as const),
      copy:
        copy === null
          ? null
          : {
              detectionId: copy.detectionId,
              receivedAt: copy.receivedAt.toISOString(),
              verdict: copy.verdict,
              lagMs: copy.lagMs,
              source: copy.source,
              policyState: copy.policyState,
              remediationState: copy.remediationState,
            },
      waitingSinceMinutes: received ? null : waitedMinutes,
      hints: showHints ? firstCopyHints(input) : [],
    },
  };
}
export type DomainOnboardingView = ReturnType<typeof computeDomainOnboarding>;
