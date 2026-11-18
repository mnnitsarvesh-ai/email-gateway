import { describe, expect, it } from 'vitest';
import {
  computeRetainUntil,
  decideExpiry,
  effectiveRetainUntil,
  type ExpiryDecisionInput,
  type RetentionPolicyCandidate,
  type RetentionRecordFacts,
  retentionCriteriaMatch,
  selectRetentionPolicy,
} from './retention';

const RECEIVED = new Date('2025-01-10T08:00:00.000Z');
const DAY = 86_400_000;
const D1 = '0190a5d0-0000-7000-8000-000000000101';
const DEP = '0190a5d0-0000-7000-8000-000000000201';

const facts: RetentionRecordFacts = {
  directions: ['outbound', 'internal'],
  category: 'delivered',
  sources: { journal: true, policy: false },
  policyRuleRef: null,
  partyDomainIds: [D1],
  departmentIds: [],
};

const policy = (
  id: number,
  priority: number,
  criteria: unknown,
  extra: Partial<RetentionPolicyCandidate> = {},
): RetentionPolicyCandidate => ({
  id,
  priority,
  criteria,
  retentionDays: 365,
  onExpiry: 'delete',
  ...extra,
});

describe('retention criteria (archive-retention/1)', () => {
  it.each([
    [{}, true],
    [{ directions: ['internal'] }, true],
    [{ directions: ['inbound'] }, false],
    [{ categories: ['delivered', 'failed'] }, true],
    [{ categories: ['rejected'] }, false],
    [{ sources: ['journal'] }, true],
    [{ sources: ['policy'] }, false],
    [{ policyRuleRefs: ['r1'] }, false],
    [{ domainIds: [D1] }, true],
    [{ departmentIds: [DEP] }, false],
    [{ directions: ['outbound'], domainIds: [D1], categories: ['delivered'] }, true],
    [{ directions: ['outbound'], categories: ['rejected'] }, false],
    [{ unknown: true }, false],
    ['garbage', false],
  ])('%j → %s', (criteria, expected) => {
    expect(retentionCriteriaMatch(criteria, facts)).toBe(expected);
  });

  it('matches the policy source and rule reference', () => {
    const f = { ...facts, sources: { journal: false, policy: true }, policyRuleRef: 'rule-7' };
    expect(retentionCriteriaMatch({ sources: ['policy'], policyRuleRefs: ['rule-7'] }, f)).toBe(
      true,
    );
    expect(retentionCriteriaMatch({ policyRuleRefs: ['rule-8'] }, f)).toBe(false);
  });
});

describe('selectRetentionPolicy', () => {
  it('orders live policies by priority then id; the first match wins', () => {
    const policies = [
      policy(5, 20, {}),
      policy(9, 10, { directions: ['inbound'] }),
      policy(7, 10, { categories: ['delivered'] }),
      policy(3, 10, { categories: ['delivered'] }, { deletedAt: new Date() }),
      policy(4, 10, { categories: ['delivered'] }),
    ];
    expect(selectRetentionPolicy(policies, facts, null)).toMatchObject({
      policy: { id: 4 },
      matchedBy: 'criteria',
    });
    expect(
      selectRetentionPolicy([policy(2n as never, 1, {}), policy(10, 1, {})], facts, null)?.policy
        .id,
    ).toBe(2n);
  });

  it('falls back to the live default policy, else null', () => {
    const policies = [
      policy(1, 1, { directions: ['inbound'] }),
      policy(2, 2, { categories: ['failed'] }),
    ];
    expect(selectRetentionPolicy(policies, facts, '2')).toMatchObject({
      policy: { id: 2 },
      matchedBy: 'default',
    });
    expect(selectRetentionPolicy(policies, facts, null)).toBeNull();
    expect(
      selectRetentionPolicy(
        [policy(2, 1, { directions: ['inbound'] }, { deletedAt: new Date() })],
        facts,
        2,
      ),
    ).toBeNull();
  });
});

describe('computeRetainUntil and effectiveRetainUntil', () => {
  it('adds UTC days, or test days of ARCHIVE_TEST_DAY_SECONDS', () => {
    expect(computeRetainUntil(RECEIVED, 365)).toEqual(new Date(RECEIVED.getTime() + 365 * DAY));
    expect(computeRetainUntil(RECEIVED, 3, 10)).toEqual(new Date(RECEIVED.getTime() + 30_000));
    expect(() => computeRetainUntil(RECEIVED, 1.5)).toThrow(RangeError);
    expect(() => computeRetainUntil(RECEIVED, 1, 0)).toThrow(RangeError);
    expect(() => computeRetainUntil(RECEIVED, 1, 86_401)).toThrow(RangeError);
  });

  it('extends only: max(stored, received + current days) while the policy is live', () => {
    const stored = new Date(RECEIVED.getTime() + 365 * DAY);
    const longer = { retentionDays: 730, onExpiry: 'delete' as const, live: true };
    const shorter = { retentionDays: 30, onExpiry: 'delete' as const, live: true };
    expect(
      effectiveRetainUntil({ storedRetainUntil: stored, receivedAt: RECEIVED, policy: longer }),
    ).toEqual(new Date(RECEIVED.getTime() + 730 * DAY));
    expect(
      effectiveRetainUntil({ storedRetainUntil: stored, receivedAt: RECEIVED, policy: shorter }),
    ).toEqual(stored);
    expect(
      effectiveRetainUntil({
        storedRetainUntil: stored,
        receivedAt: RECEIVED,
        policy: { ...longer, live: false },
      }),
    ).toEqual(stored);
    expect(
      effectiveRetainUntil({ storedRetainUntil: stored, receivedAt: RECEIVED, policy: null }),
    ).toEqual(stored);
  });
});

describe('decideExpiry (A13 order: policy_extended, held, review, disposed)', () => {
  const now = new Date(RECEIVED.getTime() + 400 * DAY);
  const base = (overrides: Partial<ExpiryDecisionInput> = {}): ExpiryDecisionInput => ({
    now,
    mode: 'expiry',
    record: {
      receivedAt: RECEIVED,
      retainUntil: new Date(RECEIVED.getTime() + 365 * DAY),
      expiryAction: 'delete',
      lockMode: 'none',
      lockUntil: null,
      status: 'active',
    },
    policy: { retentionDays: 365, onExpiry: 'delete', live: true },
    holds: [],
    holdFacts: {
      receivedAt: RECEIVED,
      direction: 'inbound',
      senderAddresses: ['sender@example.org'],
      recipientAddresses: ['alice@example.com'],
    },
    holdExtensionDays: 30,
    reviewExtensionDays: 30,
    ...overrides,
  });
  const hold = {
    id: 'h1',
    criteria: { custodians: ['alice@example.com'] },
    criteriaVersion: 'archive-hold/1',
  };

  it('1. a lengthened live policy extends (and extends the lock first when locked)', () => {
    const d = decideExpiry(
      base({ policy: { retentionDays: 730, onExpiry: 'delete', live: true } }),
    );
    expect(d).toMatchObject({ outcome: 'policy_extended', lockUntil: null, status: 'active' });
    expect(d.retainUntil).toEqual(new Date(RECEIVED.getTime() + 730 * DAY));
    const locked = decideExpiry(
      base({
        policy: { retentionDays: 730, onExpiry: 'delete', live: true },
        holds: [hold],
        record: { ...base().record, lockMode: 'compliance', lockUntil: base().record.retainUntil },
      }),
    );
    expect(locked).toMatchObject({ outcome: 'policy_extended' });
    expect(locked.lockUntil).toEqual(new Date(RECEIVED.getTime() + 730 * DAY));
  });

  it('a running object lock keeps the record', () => {
    const lockUntil = new Date(now.getTime() + DAY);
    const d = decideExpiry(
      base({ record: { ...base().record, lockMode: 'governance', lockUntil } }),
    );
    expect(d).toMatchObject({ outcome: 'policy_extended', lockUntil: null });
    expect(d.retainUntil).toEqual(lockUntil);
  });

  it('2. a matching active hold extends by the hold extension and flags legal_hold', () => {
    const d = decideExpiry(
      base({
        holds: [
          { id: 'h0', criteria: { custodians: ['x@y.z'] }, criteriaVersion: 'archive-hold/1' },
          hold,
        ],
      }),
    );
    expect(d).toMatchObject({ outcome: 'held', legalHold: true, holdId: 'h1', lockUntil: null });
    expect(d.retainUntil).toEqual(new Date(now.getTime() + 30 * DAY));
    const locked = decideExpiry(
      base({
        holds: [hold],
        record: { ...base().record, lockMode: 'governance', lockUntil: base().record.retainUntil },
      }),
    );
    expect(locked.lockUntil).toEqual(new Date(now.getTime() + 30 * DAY));
    // Unparsable criteria hold everything (fail-safe).
    expect(decideExpiry(base({ holds: [{ id: 'h9', criteria: 'broken' }] })).outcome).toBe('held');
    // A hold beats review and is re-checked by manual disposal.
    expect(decideExpiry(base({ holds: [hold], mode: 'manual_dispose' })).outcome).toBe('held');
  });

  it('3. review: the live policy decides, else the stored action; locked records are extended', () => {
    expect(
      decideExpiry(base({ policy: { retentionDays: 365, onExpiry: 'review', live: true } })),
    ).toMatchObject({
      outcome: 'review',
      status: 'expiry_review',
      lockUntil: null,
    });
    // Live policy says delete even though the record stored review.
    expect(
      decideExpiry(base({ record: { ...base().record, expiryAction: 'review' } })).outcome,
    ).toBe('disposed');
    // Deleted policy: the stored action applies.
    const stored = decideExpiry(
      base({ policy: null, record: { ...base().record, expiryAction: 'review' } }),
    );
    expect(stored).toMatchObject({ outcome: 'review' });
    expect(stored.retainUntil).toEqual(base().record.retainUntil);
    const locked = decideExpiry(
      base({
        policy: null,
        record: {
          ...base().record,
          expiryAction: 'review',
          lockMode: 'compliance',
          lockUntil: base().record.retainUntil,
        },
      }),
    );
    expect(locked.retainUntil).toEqual(new Date(now.getTime() + 30 * DAY));
    expect(locked.lockUntil).toEqual(new Date(now.getTime() + 30 * DAY));
  });

  it('4. otherwise disposed; manual disposal of a reviewed record skips rule 3', () => {
    expect(decideExpiry(base())).toMatchObject({ outcome: 'disposed', status: 'disposing' });
    expect(
      decideExpiry(
        base({
          mode: 'manual_dispose',
          policy: { retentionDays: 365, onExpiry: 'review', live: true },
          record: { ...base().record, status: 'expiry_review' },
        }),
      ),
    ).toMatchObject({ outcome: 'disposed' });
  });

  it('never shortens retention', () => {
    const d = decideExpiry(base({ holdExtensionDays: 0, holds: [hold] }));
    expect(d.retainUntil.getTime()).toBeGreaterThanOrEqual(base().record.retainUntil.getTime());
  });

  it('honours the test day length', () => {
    const t0 = new Date('2026-11-16T00:00:00Z');
    const d = decideExpiry(
      base({
        now: new Date(t0.getTime() + 25_000),
        daySeconds: 10,
        record: { ...base().record, receivedAt: t0, retainUntil: new Date(t0.getTime() + 20_000) },
        policy: { retentionDays: 3, onExpiry: 'delete', live: true },
      }),
    );
    expect(d.outcome).toBe('policy_extended');
    expect(d.retainUntil).toEqual(new Date(t0.getTime() + 30_000));
  });
});
