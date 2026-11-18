import { describe, expect, it } from 'vitest';
import { resolveArchiveSettings } from '../documents/settings';
import type { MessageStatus, RecipientStatus } from '../vocabulary';
import {
  type CaptureDecisionInput,
  type CaptureMessageFacts,
  categoryOf,
  decideCapture,
  QUARANTINE_WAIT_MAX_DAYS,
  waitMaxAgeDays,
} from './decide';
import {
  createScopeMatcher,
  directionEligible,
  domainOf,
  journalEligibility,
  normalizeAddress,
  orgSideParties,
  type JournalMessageFacts,
} from './eligibility';
import { nextOutcomeCheckAt, nextWaitCheckAt } from './schedule';

const NOW = new Date('2026-11-16T12:00:00.000Z');
const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;

function message(
  status: MessageStatus,
  statusReason: string | null = null,
  recipients: RecipientStatus[] = ['pending'],
): CaptureMessageFacts {
  return {
    status,
    statusReason,
    direction: 'inbound',
    recipients: recipients.map((s) => ({ status: s, direction: 'inbound' as const })),
  };
}

function input(
  m: CaptureMessageFacts | null,
  overrides: Omit<Partial<CaptureDecisionInput>, 'settings'> & { settings?: unknown } = {},
): CaptureDecisionInput {
  const { settings, ...rest } = overrides;
  return {
    now: NOW,
    entitled: true,
    enabled: true,
    settings: resolveArchiveSettings(settings ?? null),
    sources: { journal: true, policy: false },
    message: m,
    intentCreatedAt: new Date(NOW.getTime() - HOUR),
    waitsSoFar: 0,
    maxAgeDays: 25,
    outcomeWindowDays: 7,
    ...rest,
  };
}

const allIncluded = { include: { rejected: true, quarantined: true, failed: true } };
const POLICY = { sources: { journal: false, policy: true } };

describe('decideCapture: the A3 table', () => {
  const PRE_DECISION: MessageStatus[] = [
    'received',
    'persisted',
    'scanning',
    'scanned',
    'scan_failed',
    'policy_evaluated',
    'approved',
    'delivery_pending',
    'delivery_retry',
    'archived',
  ];

  it.each(PRE_DECISION)('%s without a delivered recipient waits', (status) => {
    const d = decideCapture(input(message(status), { settings: allIncluded }));
    expect(d).toEqual({
      action: 'wait',
      reason: 'not_final',
      recheckAt: new Date(NOW.getTime() + MIN),
    });
    // Even a policy-sourced intent waits for a decision.
    expect(decideCapture(input(message(status), POLICY)).action).toBe('wait');
  });

  it.each([
    ['delivered', 'delivery_complete', ['delivered']],
    ['delivered', 'delivery_partial', ['delivered', 'failed']],
    ['delivery_retry', 'delivery_deferred', ['delivered', 'deferred']],
    ['delivery_pending', 'delivery_planned', ['delivered', 'pending']],
    ['quarantined', 'policy_partial', ['delivered', 'quarantined']],
  ] as const)(
    '%s (%s) with a delivered recipient is captured as delivered',
    (status, reason, recipients) => {
      const d = decideCapture(input(message(status, reason, [...recipients])));
      expect(d).toMatchObject({
        action: 'capture',
        category: 'delivered',
        final: status === 'delivered',
        sources: { journal: true, policy: false },
      });
    },
  );

  it.each(['quarantined', 'held_for_review'] as const)(
    '%s: captured with include.quarantined, else waits',
    (status) => {
      const reason = status === 'quarantined' ? 'policy_quarantine' : 'policy_hold';
      expect(decideCapture(input(message(status, reason, ['quarantined'])))).toEqual({
        action: 'wait',
        reason: 'quarantine_excluded',
        recheckAt: new Date(NOW.getTime() + MIN),
      });
      const included = decideCapture(
        input(message(status, reason, ['quarantined']), { settings: allIncluded }),
      );
      expect(included).toMatchObject({ action: 'capture', category: 'quarantined', final: false });
      // Non-final capture re-checks hourly.
      expect(included.action === 'capture' && included.recheckAt).toEqual(
        new Date(NOW.getTime() + HOUR),
      );
      expect(decideCapture(input(message(status, reason, ['quarantined']), POLICY))).toMatchObject({
        action: 'capture',
        category: 'quarantined',
        sources: { journal: false, policy: true },
      });
    },
  );

  it.each(['policy_discard', 'policy_reject', 'quarantine_deleted', 'review_rejected'])(
    'rejected (%s) is category rejected: included, policy, else skipped',
    (reason) => {
      const m = message('rejected', reason, ['discarded']);
      expect(decideCapture(input(m))).toEqual({ action: 'skip', reason: 'category_excluded' });
      expect(decideCapture(input(m, { settings: { include: { rejected: true } } }))).toMatchObject({
        action: 'capture',
        category: 'rejected',
        final: true,
      });
      expect(
        decideCapture(input(m, { settings: { include: { failed: true, quarantined: true } } })),
      ).toEqual({
        action: 'skip',
        reason: 'category_excluded',
      });
      expect(decideCapture(input(m, POLICY))).toMatchObject({
        action: 'capture',
        category: 'rejected',
      });
    },
  );

  it.each([
    ['rejected', 'delivery_failed', ['failed']],
    ['expired', 'deadline_exceeded', ['pending']],
    ['expired', 'quarantine_expired', ['quarantined']],
  ] as const)(
    '%s (%s) is category failed: included, policy, else skipped',
    (status, reason, recipients) => {
      const m = message(status, reason, [...recipients]);
      expect(decideCapture(input(m))).toEqual({ action: 'skip', reason: 'category_excluded' });
      expect(decideCapture(input(m, { settings: { include: { failed: true } } }))).toMatchObject({
        action: 'capture',
        category: 'failed',
        final: true,
      });
      expect(decideCapture(input(m, { settings: { include: { rejected: true } } }))).toMatchObject({
        action: 'skip',
      });
      expect(decideCapture(input(m, POLICY))).toMatchObject({
        action: 'capture',
        category: 'failed',
      });
    },
  );

  it('organization not entitled, disabled, policy archive disabled', () => {
    const m = message('delivered', 'delivery_complete', ['delivered']);
    expect(decideCapture(input(m, { entitled: false }))).toEqual({
      action: 'skip',
      reason: 'not_entitled',
    });
    expect(decideCapture(input(m, { enabled: false }))).toEqual({
      action: 'skip',
      reason: 'archiving_disabled',
    });
    expect(
      decideCapture(input(m, { ...POLICY, settings: { policyArchive: { enabled: false } } })),
    ).toEqual({
      action: 'skip',
      reason: 'policy_archive_disabled',
    });
    // A journal + policy intent keeps the journal source when policy archiving is off.
    expect(
      decideCapture(
        input(m, {
          sources: { journal: true, policy: true },
          settings: { policyArchive: { enabled: false } },
        }),
      ),
    ).toMatchObject({ action: 'capture', sources: { journal: true, policy: false } });
    // Policy archiving off also removes the policy override of the categories.
    expect(
      decideCapture(
        input(message('rejected', 'policy_reject', ['discarded']), {
          sources: { journal: true, policy: true },
          settings: { policyArchive: { enabled: false } },
        }),
      ),
    ).toEqual({ action: 'skip', reason: 'category_excluded' });
  });

  it('message row gone or original missing → lost', () => {
    expect(decideCapture(input(null))).toEqual({ action: 'lost', reason: 'message_missing' });
    const m = {
      ...message('delivered', 'delivery_complete', ['delivered']),
      originalAvailable: false,
    };
    expect(decideCapture(input(m))).toEqual({ action: 'lost', reason: 'original_missing' });
    // Lost wins over a skip (the record is never silently dropped).
    expect(decideCapture(input(null, { entitled: false }))).toMatchObject({ action: 'lost' });
  });

  it('a waiting intent older than the max age is skipped (max_age)', () => {
    const old = new Date(NOW.getTime() - 26 * DAY);
    expect(decideCapture(input(message('scanning'), { intentCreatedAt: old }))).toEqual({
      action: 'skip',
      reason: 'max_age',
    });
    // A message waiting in quarantine keeps waiting past the intent max age (a later release
    // must still be journaled), up to QUARANTINE_WAIT_MAX_DAYS.
    expect(
      decideCapture(input(message('quarantined', 'policy_quarantine'), { intentCreatedAt: old })),
    ).toMatchObject({ action: 'wait', reason: 'quarantine_excluded' });
    const ancient = new Date(NOW.getTime() - (QUARANTINE_WAIT_MAX_DAYS + 1) * DAY);
    expect(
      decideCapture(
        input(message('quarantined', 'policy_quarantine'), { intentCreatedAt: ancient }),
      ),
    ).toEqual({ action: 'skip', reason: 'max_age' });
    expect(waitMaxAgeDays('not_final', 25)).toBe(25);
    expect(waitMaxAgeDays('quarantine_excluded', 25)).toBe(QUARANTINE_WAIT_MAX_DAYS);
    // Released after 60 days in quarantine: captured as delivered.
    const released = new Date(NOW.getTime() - 60 * DAY);
    expect(
      decideCapture(
        input(message('delivered', 'delivery_complete', ['delivered']), {
          intentCreatedAt: released,
        }),
      ),
    ).toMatchObject({ action: 'capture', category: 'delivered' });
    // Captures are not affected by the age.
    expect(
      decideCapture(
        input(message('delivered', 'delivery_complete', ['delivered']), { intentCreatedAt: old }),
      ).action,
    ).toBe('capture');
  });

  it('wait schedule: 1, 2, 5, 15, 30 minutes, then hourly', () => {
    const at = (n: number) => {
      const d = decideCapture(input(message('scanning'), { waitsSoFar: n }));
      return d.action === 'wait' ? (d.recheckAt.getTime() - NOW.getTime()) / MIN : -1;
    };
    expect([0, 1, 2, 3, 4, 5, 6, 40].map(at)).toEqual([1, 2, 5, 15, 30, 60, 60, 60]);
    expect(nextWaitCheckAt(NOW, -3).getTime() - NOW.getTime()).toBe(MIN);
  });

  it('final captures re-check at +1 h from the later of capture and final state', () => {
    const m = { ...message('delivered', 'delivery_complete', ['delivered']), statusChangedAt: NOW };
    const d = decideCapture(input(m));
    expect(d.action === 'capture' && d.recheckAt).toEqual(new Date(NOW.getTime() + HOUR));
  });

  it('categoryOf', () => {
    expect(categoryOf(message('scanning'))).toBeNull();
    expect(categoryOf(message('held_for_review'))).toBe('quarantined');
    expect(categoryOf(message('rejected', null, ['discarded']))).toBe('rejected');
  });
});

describe('outcome refresh schedule (A7)', () => {
  const capturedAt = NOW;
  it('final: +1 h, +24 h, then close', () => {
    const f = (now: number, finalSince?: Date) =>
      nextOutcomeCheckAt({
        now: new Date(now),
        capturedAt,
        final: true,
        finalSince,
        outcomeWindowDays: 7,
      });
    expect(f(NOW.getTime())).toEqual(new Date(NOW.getTime() + HOUR));
    expect(f(NOW.getTime() + HOUR)).toEqual(new Date(NOW.getTime() + 24 * HOUR));
    expect(f(NOW.getTime() + 24 * HOUR)).toBeNull();
    // Became final later (released then delivered): measured from the final state.
    const later = new Date(NOW.getTime() + 2 * DAY);
    expect(f(later.getTime(), later)).toEqual(new Date(later.getTime() + HOUR));
  });

  it('non-final: hourly until the window ends; the window also bounds final checks', () => {
    const f = (now: number, final = false) =>
      nextOutcomeCheckAt({
        now: new Date(now),
        capturedAt,
        final,
        finalSince: new Date(now),
        outcomeWindowDays: 7,
      });
    expect(f(NOW.getTime())).toEqual(new Date(NOW.getTime() + HOUR));
    expect(f(NOW.getTime() + 7 * DAY - 10 * MIN)).toEqual(new Date(NOW.getTime() + 7 * DAY));
    expect(f(NOW.getTime() + 7 * DAY)).toBeNull();
    expect(f(NOW.getTime() + 7 * DAY - 10 * MIN, true)).toEqual(new Date(NOW.getTime() + 7 * DAY));
    expect(f(NOW.getTime() + 8 * DAY, true)).toBeNull();
  });
});

describe('journal eligibility and scope (A4)', () => {
  const enabledAt = new Date('2026-11-01T00:00:00Z');
  const msg = (overrides: Partial<JournalMessageFacts> = {}): JournalMessageFacts => ({
    receivedAt: NOW,
    direction: 'inbound',
    envelopeFrom: 'outside@example.org',
    headerFrom: 'Outside <outside@example.org>',
    recipients: [{ address: 'Alice@Example.com', direction: 'inbound' }],
    ...overrides,
  });
  const elig = (m: JournalMessageFacts, settings: unknown, scope = {}) =>
    journalEligibility({
      settings: resolveArchiveSettings(settings),
      journalEnabledAt: enabledAt,
      message: m,
      scope: { addresses: [], userEmails: [], departmentAddresses: [], domains: [], ...scope },
    });

  it('addresses and domains are normalized', () => {
    expect(normalizeAddress(' Name <A@B.example> ')).toBe('a@b.example');
    expect(normalizeAddress('<>')).toBeNull();
    expect(normalizeAddress('')).toBeNull();
    expect(domainOf('x@Sub.Example.COM')).toBe('sub.example.com');
    expect(domainOf('nodomain')).toBeNull();
  });

  it('only messages received at or after journal_enabled_at', () => {
    expect(elig(msg({ receivedAt: new Date(enabledAt.getTime() - 1) }), null)).toEqual({
      eligible: false,
      reason: 'before_enablement',
    });
    expect(elig(msg({ receivedAt: enabledAt }), null)).toEqual({ eligible: true });
    expect(
      journalEligibility({
        settings: resolveArchiveSettings(null),
        journalEnabledAt: null,
        message: msg(),
      }),
    ).toEqual({ eligible: false, reason: 'before_enablement' });
  });

  it('direction: the message direction or any recipient direction', () => {
    const mixed = msg({
      direction: 'outbound',
      envelopeFrom: 'alice@example.com',
      headerFrom: null,
      recipients: [
        { address: 'bob@example.com', direction: 'internal' },
        { address: 'partner@example.net', direction: 'outbound' },
      ],
    });
    const internalOnly = { directions: { inbound: false, outbound: false, internal: true } };
    expect(elig(mixed, internalOnly)).toEqual({ eligible: true });
    expect(
      elig(mixed, { directions: { inbound: true, outbound: false, internal: false } }),
    ).toEqual({
      eligible: false,
      reason: 'direction_disabled',
    });
    expect(directionEligible(resolveArchiveSettings(null), mixed)).toBe(true);
  });

  it('org-side parties: inbound/internal recipients, plus the senders for outbound/internal', () => {
    expect(orgSideParties(msg())).toEqual(['alice@example.com']);
    const out = msg({
      direction: 'outbound',
      envelopeFrom: 'alice@example.com',
      headerFrom: 'Alice <ALICE@example.com>',
      recipients: [{ address: 'partner@example.net', direction: 'outbound' }],
    });
    expect(orgSideParties(out)).toEqual(['alice@example.com']);
    const internal = msg({
      direction: 'internal',
      envelopeFrom: 'alice@example.com',
      headerFrom: 'boss@example.com',
      recipients: [{ address: 'bob@example.com', direction: 'internal' }],
    });
    expect(orgSideParties(internal).sort()).toEqual([
      'alice@example.com',
      'bob@example.com',
      'boss@example.com',
    ]);
  });

  it('scope include: some org-side party matches an address, user, department member or domain', () => {
    const include = (scope: object, m = msg()) =>
      elig(m, { scope: { mode: 'include' } }, scope).eligible;
    expect(include({})).toBe(false);
    expect(include({ addresses: ['alice@example.com'] })).toBe(true);
    expect(include({ userEmails: ['ALICE@example.com'] })).toBe(true);
    expect(include({ departmentAddresses: ['alice@example.com'] })).toBe(true);
    expect(include({ domains: ['Example.com.'] })).toBe(true);
    expect(include({ domains: ['example.org'] })).toBe(false); // the external sender never counts
    expect(include({ addresses: ['outside@example.org'] })).toBe(false);
    // Settings addresses are part of the resolved scope the caller passes in.
    expect(
      elig(msg(), { scope: { mode: 'include', addresses: ['alice@example.com'] } }).eligible,
    ).toBe(false);
  });

  it('scope exclude: some org-side party does not match', () => {
    const two = msg({
      recipients: [
        { address: 'alice@example.com', direction: 'inbound' },
        { address: 'bob@example.com', direction: 'inbound' },
      ],
    });
    const exclude = (scope: object, m = two) => elig(m, { scope: { mode: 'exclude' } }, scope);
    expect(exclude({ addresses: ['alice@example.com'] })).toEqual({ eligible: true });
    expect(exclude({ addresses: ['alice@example.com', 'bob@example.com'] })).toEqual({
      eligible: false,
      reason: 'out_of_scope',
    });
    expect(exclude({ domains: ['example.com'] }).eligible).toBe(false);
    expect(exclude({}).eligible).toBe(true);
  });

  it('a prebuilt matcher gives the same answers', () => {
    const matcher = createScopeMatcher({
      addresses: ['alice@example.com'],
      userEmails: [],
      departmentAddresses: [],
      domains: [],
    });
    expect(matcher('<Alice@Example.com>')).toBe(true);
    expect(matcher('')).toBe(false);
    expect(
      journalEligibility({
        settings: resolveArchiveSettings({ scope: { mode: 'include' } }),
        journalEnabledAt: enabledAt,
        message: msg(),
        matcher,
      }),
    ).toEqual({ eligible: true });
  });
});
