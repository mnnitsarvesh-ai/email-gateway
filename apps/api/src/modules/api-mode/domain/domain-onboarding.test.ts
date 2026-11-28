import { describe, expect, it } from 'vitest';
import {
  computeDomainOnboarding,
  FIRST_COPY_HINT_CODES,
  firstCopyHints,
  type OnboardingInput,
} from './domain-onboarding';

const NOW = new Date('2026-11-27T12:00:00.000Z');
const minutesAgo = (m: number) => new Date(NOW.getTime() - m * 60_000);

/** A fully onboarded api domain waiting for its first copy for 30 minutes. */
function base(patch: Partial<OnboardingInput> = {}): OnboardingInput {
  return {
    now: NOW,
    hintAfterMinutes: 10,
    domain: {
      id: '0192f3a0-2222-7000-8000-000000000002',
      status: 'active',
      effectiveMode: 'api',
      createdAt: minutesAgo(120),
      activatedAt: minutesAgo(30),
    },
    ownership: { method: 'dns_txt', providerCheck: null, providerCheckAvailable: false },
    connection: {
      id: '0192f3a0-3333-7000-8000-000000000003',
      provider: 'microsoft_365',
      bound: true,
      status: 'active',
      mailFlowGrant: 'active',
      mailboxAccessGrant: 'active',
      throttledUntil: null,
    },
    journalSources: [
      {
        id: '0192f3a0-4444-7000-8000-000000000004',
        status: 'active',
        health: 'healthy',
        verified: true,
        lastAcceptedAt: null,
      },
    ],
    feeds: { enabled: false, mode: 'poll', activeMailboxes: 0, inScopeMailboxes: 10 },
    scope: { kind: 'all', inScope: 10, excluded: 0 },
    mailboxesKnown: 10,
    action: {
      source: 'domain',
      mode: 'detect_only',
      presetKey: 'detectOnlyStart',
      detectOnly: null,
    },
    firstCopy: null,
    recentFailedCopies: 0,
    ...patch,
  };
}

type StepView = { status: string; blockers: string[]; nextAction: string | null };
type StepKey = 'ownership' | 'connect' | 'intake' | 'mailboxes' | 'action' | 'review';
const stepsOf = (input: OnboardingInput): Record<StepKey, StepView> => {
  const out = {} as Record<StepKey, StepView>;
  for (const s of computeDomainOnboarding(input).steps) {
    out[s.key] = { status: s.status, blockers: s.blockers, nextAction: s.nextAction };
  }
  return out;
};

describe('computeDomainOnboarding (step API-4 B8)', () => {
  it('an inline domain skips every API step and still answers the first-copy block', () => {
    const view = computeDomainOnboarding(
      base({ domain: { ...base().domain, effectiveMode: 'inline' } }),
    );
    expect(view.steps.map((s) => s.status)).toEqual(Array(6).fill('skipped'));
    expect(view.firstCopy.hints.map((h) => h.code)).toContain('mode_not_api');
  });

  it.each([
    [
      'pending, no provider',
      { status: 'pending_verification' as const },
      { providerCheckAvailable: false, providerCheck: null },
      { status: 'in_progress', blockers: [], nextAction: 'verify_ownership' },
    ],
    [
      'pending, provider available',
      { status: 'pending_verification' as const },
      { providerCheckAvailable: true, providerCheck: null },
      { status: 'in_progress', blockers: [], nextAction: 'verify_through_provider' },
    ],
    [
      'pending, provider check running',
      { status: 'pending_verification' as const },
      {
        providerCheckAvailable: true,
        providerCheck: {
          id: '1',
          status: 'pending' as const,
          result: null,
          connectionId: null,
          requestedAt: NOW.toISOString(),
          checkedAt: null,
          expiresAt: NOW.toISOString(),
        },
      },
      { status: 'in_progress', blockers: [], nextAction: null },
    ],
    [
      'failed',
      { status: 'failed' as const },
      { providerCheckAvailable: true, providerCheck: null },
      { status: 'blocked', blockers: ['ownership_failed'], nextAction: 'restart_verification' },
    ],
    [
      'verified',
      { status: 'verified' as const },
      { providerCheckAvailable: false, providerCheck: null },
      { status: 'done', blockers: [], nextAction: null },
    ],
  ])('ownership step: %s', (_name, domain, ownership, expected) => {
    const input = base({
      domain: { ...base().domain, ...domain },
      ownership: { method: null, ...ownership },
    });
    expect(stepsOf(input).ownership).toEqual(expected);
  });

  it.each([
    ['no connection', null, { status: 'not_started', blockers: [], nextAction: 'link_connection' }],
    [
      'disabled',
      { status: 'disabled' as const },
      { status: 'blocked', blockers: ['connection_disabled'], nextAction: 'enable_connection' },
    ],
    [
      'not bound, no mailbox access',
      { bound: false, mailboxAccessGrant: null },
      {
        status: 'in_progress',
        blockers: ['connection_not_bound', 'mailbox_access_missing'],
        nextAction: 'complete_binding',
      },
    ],
    [
      'bound, mailbox access pending consent',
      { mailboxAccessGrant: 'pending_consent' },
      {
        status: 'in_progress',
        blockers: ['mailbox_access_missing'],
        nextAction: 'grant_mailbox_access',
      },
    ],
    ['bound with mailbox access', {}, { status: 'done', blockers: [], nextAction: null }],
  ])('connect step: %s', (_name, patch, expected) => {
    const connection = patch === null ? null : { ...base().connection!, ...patch };
    expect(stepsOf(base({ connection })).connect).toEqual(expected);
  });

  it.each([
    ['verified journal source', {}, 'done', null],
    [
      'pending journal source',
      {
        journalSources: [
          {
            ...base().journalSources[0]!,
            status: 'pending_verification' as const,
            verified: false,
          },
        ],
      },
      'in_progress',
      'verify_journal_source',
    ],
    [
      'feeds active on 9 of 10 (90 %)',
      {
        journalSources: [],
        feeds: { enabled: true, mode: 'poll' as const, activeMailboxes: 9, inScopeMailboxes: 10 },
      },
      'done',
      null,
    ],
    [
      'feeds active on 8 of 10',
      {
        journalSources: [],
        feeds: { enabled: true, mode: 'poll' as const, activeMailboxes: 8, inScopeMailboxes: 10 },
      },
      'in_progress',
      'wait_for_feeds',
    ],
    ['nothing', { journalSources: [] }, 'not_started', 'set_up_journal'],
  ])('intake step: %s', (_name, patch, status, nextAction) => {
    expect(stepsOf(base(patch)).intake).toMatchObject({ status, nextAction });
  });

  it('intake and mailboxes are blocked without a connection', () => {
    const steps = stepsOf(base({ connection: null }));
    expect(steps.intake).toEqual({
      status: 'blocked',
      blockers: ['connection_missing'],
      nextAction: 'link_connection',
    });
    expect(steps.mailboxes.status).toBe('blocked');
  });

  it.each([
    ['mailboxes in scope', {}, 'done', [], null],
    [
      'none known',
      { scope: { kind: 'all' as const, inScope: 0, excluded: 0 }, mailboxesKnown: 0 },
      'not_started',
      [],
      'sync_inventory',
    ],
    [
      'all excluded',
      { scope: { kind: 'mailboxes' as const, inScope: 0, excluded: 10 } },
      'in_progress',
      ['no_mailboxes_in_scope'],
      'choose_mailboxes',
    ],
  ])('mailboxes step: %s', (_name, patch, status, blockers, nextAction) => {
    expect(stepsOf(base(patch)).mailboxes).toEqual({ status, blockers, nextAction });
  });

  it('action step: the platform default asks for a choice; organization or domain is done', () => {
    const platform = base({
      action: { source: 'platform_default', mode: 'enforce', presetKey: 'p1', detectOnly: null },
    });
    expect(stepsOf(platform).action).toEqual({
      status: 'not_started',
      blockers: [],
      nextAction: 'choose_action',
    });
    expect(
      stepsOf(base({ action: { ...base().action, source: 'organization' } })).action.status,
    ).toBe('done');
  });

  it('review step: blocked by ownership and connection; activate; waiting; done', () => {
    const pending = base({ domain: { ...base().domain, status: 'pending_verification' } });
    expect(stepsOf(pending).review).toEqual({
      status: 'blocked',
      blockers: ['ownership_pending'],
      nextAction: null,
    });
    expect(stepsOf(base({ connection: null })).review.blockers).toEqual(['connection_missing']);
    const verified = base({ domain: { ...base().domain, status: 'verified', activatedAt: null } });
    expect(stepsOf(verified).review).toEqual({
      status: 'not_started',
      blockers: [],
      nextAction: 'activate_domain',
    });
    expect(stepsOf(base()).review).toEqual({
      status: 'in_progress',
      blockers: [],
      nextAction: 'send_test_message',
    });
    const received = base({
      firstCopy: {
        detectionId: '0192f3a0-6666-7000-8000-000000000006',
        receivedAt: minutesAgo(5),
        verdict: 'clean',
        lagMs: 1500,
        source: 'journal',
        policyState: 'evaluated',
        remediationState: 'none',
      },
    });
    expect(stepsOf(received).review.status).toBe('done');
    const view = computeDomainOnboarding(received);
    expect(view.firstCopy).toMatchObject({
      status: 'received',
      waitingSinceMinutes: null,
      hints: [],
      copy: { verdict: 'clean', source: 'journal', policyState: 'evaluated' },
    });
  });

  it('first copy: no hints before API_MODE_FIRST_COPY_HINT_AFTER_MINUTES, then the list', () => {
    const early = computeDomainOnboarding(
      base({ domain: { ...base().domain, activatedAt: minutesAgo(5) } }),
    );
    expect(early.firstCopy).toMatchObject({ status: 'waiting', waitingSinceMinutes: 5, hints: [] });
    const late = computeDomainOnboarding(base());
    expect(late.firstCopy.waitingSinceMinutes).toBe(30);
    expect(late.firstCopy.hints).toEqual([
      { code: 'send_test_message', severity: 'info', link: null },
    ]);
  });

  it('hints: every code, in the documented order', () => {
    const input = base({
      domain: { ...base().domain, status: 'verified', effectiveMode: 'inline', activatedAt: null },
      connection: {
        ...base().connection!,
        bound: false,
        mailboxAccessGrant: 'revoked',
        throttledUntil: new Date(NOW.getTime() + 60_000),
      },
      journalSources: [
        {
          id: '0192f3a0-4444-7000-8000-000000000004',
          status: 'pending_verification',
          health: 'silent',
          verified: false,
          lastAcceptedAt: minutesAgo(1),
        },
      ],
      feeds: { enabled: true, mode: 'notify', activeMailboxes: 0, inScopeMailboxes: 0 },
      scope: { kind: 'departments', inScope: 0, excluded: 4 },
      recentFailedCopies: 3,
    });
    expect(firstCopyHints(input).map((h) => h.code)).toEqual([
      'domain_not_active',
      'mode_not_api',
      'connection_not_bound',
      'mailbox_access_missing',
      'journal_source_unverified',
      'journal_source_silent',
      'journal_seen_no_domain_recipient',
      'feeds_initializing',
      'no_mailboxes_in_scope',
      'connection_throttled',
      'copies_failing',
      'send_test_message',
    ]);
    const missing = firstCopyHints(base({ connection: null, journalSources: [] }));
    expect(missing.map((h) => h.code)).toEqual([
      'connection_missing',
      'journal_source_missing',
      'feeds_disabled',
      'send_test_message',
    ]);
    expect(missing.find((h) => h.code === 'journal_source_missing')?.severity).toBe('warn');
    // Every documented code is produced by some input above.
    const seen = new Set([...firstCopyHints(input), ...missing].map((h) => h.code));
    expect(FIRST_COPY_HINT_CODES.filter((c) => !seen.has(c))).toEqual([]);
  });

  it('carries ownership, connection, intake, scope and action facts without addresses', () => {
    const view = computeDomainOnboarding(base());
    expect(view.ownership).toEqual({
      status: 'verified',
      method: 'dns_txt',
      providerCheck: null,
      providerCheckAvailable: false,
    });
    expect(view.connection).toMatchObject({ bound: true, mailFlowGrant: 'active' });
    expect(view.intake.journalSources).toEqual([
      { id: '0192f3a0-4444-7000-8000-000000000004', status: 'active', health: 'healthy' },
    ]);
    expect(JSON.stringify(view)).not.toContain('@');
  });
});
