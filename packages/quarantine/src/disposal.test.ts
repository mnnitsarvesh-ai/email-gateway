import { describe, expect, it } from 'vitest';
import {
  ARCHIVE_PENDING_RECHECK_MS,
  archivePendingOf,
  type ArchivePendingFacts,
  decideObjectDisposal,
  legalHoldMatches,
  type ObjectDisposalInput,
} from './disposal';
import { isQuarantineErrorCode } from './errors';

const NOW = new Date('2026-11-12T12:00:00.000Z');
const RECEIVED = new Date('2026-11-01T08:00:00.000Z');

const base: ObjectDisposalInput = {
  now: NOW,
  message: {
    receivedAt: RECEIVED,
    direction: 'inbound',
    recipientDirections: ['inbound', 'inbound'],
    senderAddresses: ['sender@ext.example'],
    recipientAddresses: ['a@corp.example', 'b@corp.example'],
  },
  legalHolds: [],
  archived: false,
  archivePending: false,
  entries: [{ state: 'deleted' }, { state: 'rejected' }],
  recipientStatuses: ['discarded', 'discarded'],
};
const d = (patch: Partial<ObjectDisposalInput>) => decideObjectDisposal({ ...base, ...patch });

describe('legal hold criteria (Q17.1 with the 8.1 matcher, A23 rule 1)', () => {
  const m = base.message;
  it.each([
    [null, true],
    [{}, true],
    [{ custodians: ['A@corp.example'] }, true],
    [{ custodians: ['sender@ext.example'] }, true],
    [{ custodians: ['other@corp.example'] }, false],
    [{ custodians: [] }, true],
    [{ from: '2026-11-01', to: '2026-11-01' }, true],
    [{ from: '2026-11-02' }, false],
    [{ to: '2026-10-31' }, false],
    [{ from: '2026-11-01T08:00:00Z', to: '2026-11-01T08:00:00.000Z' }, true],
    [{ from: '2026-11-01T08:00:01Z' }, false],
    [{ custodians: ['a@corp.example'], from: '2026-12-01' }, false],
    // Unparseable (not the strict legacy subset) → match everything (fail-safe).
    [{ query: 'subject:invoice' }, true],
    [{ custodians: 'a@corp.example' }, true],
    [{ from: 'last tuesday' }, true],
    // `directions` is not part of the legacy subset: a legacy row carrying it holds everything.
    [{ directions: ['outbound'] }, true],
    ['everything', true],
    [42, true],
  ])('legacy row %j → %s', (criteria, expected) => {
    expect(legalHoldMatches(criteria, m)).toBe(expected);
  });

  it.each([
    [{ directions: ['outbound'] }, false],
    [{ directions: ['inbound', 'outbound'] }, true],
    [{ custodians: ['b@corp.example'], directions: ['inbound'] }, true],
    [{ custodians: ['b@corp.example'], to: '2026-10-01' }, false],
    [{ bogus: true }, true],
  ])('archive-hold/1 row %j → %s', (criteria, expected) => {
    expect(legalHoldMatches(criteria, m, 'archive-hold/1')).toBe(expected);
  });

  it('a recipient direction is enough for an archive-hold/1 direction (A12, the fail-safe side)', () => {
    const mixed = {
      ...m,
      direction: 'outbound' as const,
      recipientDirections: ['outbound' as const, 'internal' as const],
    };
    expect(legalHoldMatches({ directions: ['internal'] }, mixed, 'archive-hold/1')).toBe(true);
  });

  it('an unknown criteria version matches everything', () => {
    expect(legalHoldMatches({ custodians: ['nobody@x.example'] }, m, 'archive-hold/9')).toBe(true);
  });
});

describe('decideObjectDisposal (Q17 under 8.1, A23)', () => {
  it('no hold, no pending capture, every entry terminal → delete and purge now', () => {
    expect(d({})).toEqual({
      deleteAllowed: true,
      refusal: null,
      purge: 'now',
      retainedReason: null,
      purgeAfter: null,
    });
  });

  it('1. an active legal hold refuses the delete and keeps the object', () => {
    expect(
      d({
        legalHolds: [
          { id: 'h1', criteria: { custodians: ['other@x.example'] } },
          { id: 'h2', criteria: { bogus: true } },
        ],
      }),
    ).toEqual({
      deleteAllowed: false,
      refusal: { code: 'quarantine_legal_hold', retainUntil: null, legalHoldId: 'h2' },
      purge: 'retained',
      retainedReason: 'legal_hold',
      purgeAfter: null,
    });
    expect(
      d({ legalHolds: [{ id: 'h1', criteria: { custodians: ['other@x.example'] } }] })
        .deleteAllowed,
    ).toBe(true);
    // Case-scoped holds (archive-hold/1) are matched with their version.
    expect(
      d({
        legalHolds: [
          { id: 'h3', criteria: { directions: ['outbound'] }, criteriaVersion: 'archive-hold/1' },
        ],
      }).deleteAllowed,
    ).toBe(true);
    expect(
      d({
        legalHolds: [
          { id: 'h4', criteria: { directions: ['inbound'] }, criteriaVersion: 'archive-hold/1' },
        ],
      }).refusal,
    ).toEqual({ code: 'quarantine_legal_hold', retainUntil: null, legalHoldId: 'h4' });
  });

  it('2. archive retention never retains the mail-bucket object any more (no retention refusal)', () => {
    const r = d({ archived: true });
    expect(r).toEqual({
      deleteAllowed: true,
      refusal: null,
      purge: 'now',
      retainedReason: null,
      purgeAfter: null,
    });
    // The code is still in the catalogue (deprecated), but never produced.
    expect(isQuarantineErrorCode('quarantine_retention_active')).toBe(true);
    expect(JSON.stringify(r)).not.toContain('retention');
  });

  it('3. a pending capture without a record → delete allowed, purge deferred one hour', () => {
    expect(d({ archivePending: true })).toEqual({
      deleteAllowed: true,
      refusal: null,
      purge: 'retained',
      retainedReason: 'archive_pending',
      purgeAfter: new Date(NOW.getTime() + ARCHIVE_PENDING_RECHECK_MS),
    });
    expect(ARCHIVE_PENDING_RECHECK_MS).toBe(3_600_000);
    expect(d({ archivePending: true, archived: true }).purge).toBe('now');
  });

  it('4. shared object: another live entry, a released entry or a live recipient keeps it', () => {
    for (const patch of [
      { entries: [{ state: 'deleted' as const }, { state: 'held' as const }] },
      { entries: [{ state: 'deleted' as const }, { state: 'pending_approval' as const }] },
      { entries: [{ state: 'deleted' as const }, { state: 'releasing' as const }] },
      { entries: [{ state: 'deleted' as const }, { state: 'released' as const }] },
      { recipientStatuses: ['discarded' as const, 'delivered' as const] },
      { recipientStatuses: ['pending' as const] },
      { recipientStatuses: ['deferred' as const] },
    ]) {
      expect(d(patch), JSON.stringify(patch)).toMatchObject({
        deleteAllowed: true,
        purge: 'retained',
        retainedReason: 'shared',
      });
    }
    expect(
      d({
        entries: [{ state: 'expired' }, { state: 'superseded' }],
        recipientStatuses: ['failed', 'bounced', 'quarantined'],
      }).purge,
    ).toBe('now');
  });
});

describe('archivePendingOf (A23 rule 3)', () => {
  const journal = (patch: Partial<NonNullable<ArchivePendingFacts['journal']>> = {}) => ({
    entitled: true,
    enabled: true,
    settings: null,
    journalEnabledAt: new Date('2026-10-01T00:00:00.000Z'),
    scope: { addresses: [], userEmails: [], departmentAddresses: [], domains: [] },
    message: {
      receivedAt: RECEIVED,
      direction: 'inbound' as const,
      envelopeFrom: 'sender@ext.example',
      headerFrom: null,
      recipients: [{ address: 'a@corp.example', direction: 'inbound' as const }],
    },
    ...patch,
  });
  const facts = (patch: Partial<ArchivePendingFacts>): ArchivePendingFacts => ({
    intentStatus: null,
    archiveRequested: false,
    journal: null,
    ...patch,
  });

  it('an unresolved intent is pending; a resolved one is not', () => {
    expect(archivePendingOf(facts({ intentStatus: 'pending' }))).toBe(true);
    expect(archivePendingOf(facts({ intentStatus: 'failed' }))).toBe(true);
    for (const s of ['captured_open', 'closed', 'skipped', 'lost'] as const) {
      expect(archivePendingOf(facts({ intentStatus: s, archiveRequested: true })), s).toBe(false);
    }
  });

  it('ARCHIVE requested without an intent yet is pending', () => {
    expect(archivePendingOf(facts({ archiveRequested: true }))).toBe(true);
  });

  it('journal-eligible under the current settings without an intent is pending', () => {
    expect(archivePendingOf(facts({ journal: journal() }))).toBe(true);
    expect(archivePendingOf(facts({ journal: journal({ enabled: false }) }))).toBe(false);
    expect(archivePendingOf(facts({ journal: journal({ entitled: false }) }))).toBe(false);
    expect(archivePendingOf(facts({ journal: journal({ journalEnabledAt: null }) }))).toBe(false);
    expect(
      archivePendingOf(
        facts({ journal: journal({ journalEnabledAt: new Date('2026-11-02T00:00:00Z') }) }),
      ),
    ).toBe(false);
    expect(
      archivePendingOf(
        facts({ journal: journal({ settings: { directions: { inbound: false } } }) }),
      ),
    ).toBe(false);
    // Scope `include` with the recipient in scope / out of scope.
    expect(
      archivePendingOf(
        facts({
          journal: journal({
            settings: { scope: { mode: 'include' } },
            scope: {
              addresses: ['a@corp.example'],
              userEmails: [],
              departmentAddresses: [],
              domains: [],
            },
          }),
        }),
      ),
    ).toBe(true);
    expect(
      archivePendingOf(
        facts({
          journal: journal({
            settings: { scope: { mode: 'include' } },
            scope: {
              addresses: [],
              userEmails: [],
              departmentAddresses: [],
              domains: ['x.example'],
            },
          }),
        }),
      ),
    ).toBe(false);
  });

  it('settings that cannot be parsed count as eligible (fail-safe)', () => {
    expect(archivePendingOf(facts({ journal: journal({ settings: { bogus: 1 } }) }))).toBe(true);
  });

  it('nothing at all is not pending', () => {
    expect(archivePendingOf(facts({}))).toBe(false);
  });
});
