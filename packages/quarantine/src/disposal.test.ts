import { describe, expect, it } from 'vitest';
import { decideObjectDisposal, legalHoldMatches, type ObjectDisposalInput } from './disposal';

const NOW = new Date('2026-11-12T12:00:00.000Z');
const RECEIVED = new Date('2026-11-01T08:00:00.000Z');
const DAY = 86_400_000;

const base: ObjectDisposalInput = {
  now: NOW,
  message: {
    receivedAt: RECEIVED,
    direction: 'inbound',
    senderAddresses: ['sender@ext.example'],
    recipientAddresses: ['a@corp.example', 'b@corp.example'],
  },
  legalHolds: [],
  archive: null,
  retentionPolicyDays: [],
  emailArchives: [],
  archiveRequested: false,
  entries: [{ state: 'deleted' }, { state: 'rejected' }],
  recipientStatuses: ['discarded', 'discarded'],
};
const d = (patch: Partial<ObjectDisposalInput>) => decideObjectDisposal({ ...base, ...patch });

describe('legal hold criteria (Q17.1)', () => {
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
    // Unparseable (not the strict subset) → match everything (fail-safe).
    [{ query: 'subject:invoice' }, true],
    [{ custodians: 'a@corp.example' }, true],
    [{ from: 'last tuesday' }, true],
    ['everything', true],
    [42, true],
  ])('%j → %s', (criteria, expected) => {
    expect(legalHoldMatches(criteria, m)).toBe(expected);
  });
});

describe('decideObjectDisposal (Q17)', () => {
  it('no hold, no retention, every entry terminal → delete and purge now', () => {
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
  });
  it('2. archive retention covering the direction refuses with retainUntil', () => {
    const r = d({ archive: { enabled: true, scope: 'inbound' }, retentionPolicyDays: [7, 30] });
    expect(r).toEqual({
      deleteAllowed: false,
      refusal: {
        code: 'quarantine_retention_active',
        retainUntil: new Date(RECEIVED.getTime() + 30 * DAY),
        legalHoldId: null,
      },
      purge: 'retained',
      retainedReason: 'retention',
      purgeAfter: new Date(RECEIVED.getTime() + 30 * DAY),
    });
    expect(
      d({ archive: { enabled: true, scope: 'all' }, retentionPolicyDays: [30] }).deleteAllowed,
    ).toBe(false);
  });
  it('2. retention does not apply: disabled, other scope, no policies, already passed', () => {
    expect(
      d({ archive: { enabled: false, scope: 'all' }, retentionPolicyDays: [30] }).deleteAllowed,
    ).toBe(true);
    expect(
      d({ archive: { enabled: true, scope: 'outbound' }, retentionPolicyDays: [30] }).deleteAllowed,
    ).toBe(true);
    expect(
      d({ archive: { enabled: true, scope: 'all' }, retentionPolicyDays: [] }).deleteAllowed,
    ).toBe(true);
    expect(
      d({ archive: { enabled: true, scope: 'all' }, retentionPolicyDays: [5] }).deleteAllowed,
    ).toBe(true);
  });
  it('2. an email_archives row with retain_until in the future or a legal hold refuses', () => {
    const until = new Date(NOW.getTime() + DAY);
    expect(d({ emailArchives: [{ retainUntil: until, legalHold: false }] }).refusal).toEqual({
      code: 'quarantine_retention_active',
      retainUntil: until,
      legalHoldId: null,
    });
    expect(d({ emailArchives: [{ retainUntil: null, legalHold: true }] })).toMatchObject({
      deleteAllowed: false,
      refusal: { code: 'quarantine_retention_active', retainUntil: null },
      purgeAfter: null,
    });
    expect(
      d({ emailArchives: [{ retainUntil: new Date(NOW.getTime() - DAY), legalHold: false }] }),
    ).toMatchObject({
      deleteAllowed: true,
      purge: 'now',
    });
  });
  it('3. ARCHIVE requested and not archived yet → delete allowed, purge deferred', () => {
    expect(d({ archiveRequested: true })).toEqual({
      deleteAllowed: true,
      refusal: null,
      purge: 'retained',
      retainedReason: 'archive_pending',
      purgeAfter: null,
    });
    expect(
      d({ archiveRequested: true, emailArchives: [{ retainUntil: null, legalHold: false }] }).purge,
    ).toBe('now');
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
