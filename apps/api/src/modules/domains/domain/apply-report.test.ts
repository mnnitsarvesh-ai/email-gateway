import type { DnsCheckOutcome, DnsRecordPurpose, DnsRecordStatus } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import type { DomainCheckReport, RecordCheckResult } from '../engine/types';
import {
  indeterminateError,
  ownershipIntent,
  planReportApplication,
  reportApplies,
  type StoredDomainState,
} from './apply-report';
import { noJitter, type ScheduleConfig } from './schedule';

const schedule: ScheduleConfig = {
  retryBaseSeconds: 60,
  retryMaxSeconds: 3600,
  recheckIncompleteSeconds: 1800,
  recheckIntervalSeconds: 86_400,
};
const now = new Date('2026-11-02T10:00:00.000Z');
const later = (seconds: number) => new Date(now.getTime() + seconds * 1000);
const DAY = 86_400_000;

const KEYS: Array<[string, DnsRecordPurpose]> = [
  ['verification', 'verification'],
  ['mx:mx1.gw.test', 'mx'],
  ['spf', 'spf'],
  ['dkim:sel1', 'dkim'],
  ['dmarc', 'dmarc'],
];

function state(patch: {
  status?: StoredDomainState['domain']['status'];
  checkFailures?: number;
  recordStatus?: Partial<Record<string, DnsRecordStatus>>;
  attempts?: number;
  expiresAt?: Date;
  keys?: StoredDomainState['dkimKeys'];
}): StoredDomainState {
  return {
    domain: {
      id: 1n,
      status: patch.status ?? 'pending_verification',
      checkFailures: patch.checkFailures ?? 0,
    },
    verification: {
      id: 2n,
      status: 'pending',
      attempts: patch.attempts ?? 0,
      expiresAt: patch.expiresAt ?? new Date(now.getTime() + 7 * DAY),
    },
    records: KEYS.map(([recordKey, purpose], i) => ({
      id: BigInt(10 + i),
      recordKey,
      purpose,
      status: patch.recordStatus?.[recordKey] ?? 'pending',
      evidence: { warnings: ['previous_warning'] },
    })),
    dkimKeys: patch.keys ?? [
      { id: 30n, selector: 'sel1', algorithm: 'rsa_2048', status: 'pending' },
    ],
  };
}

function result(
  recordKey: string,
  outcome: DnsCheckOutcome,
  warnings: string[] = [],
): RecordCheckResult {
  return {
    recordKey,
    outcome,
    observedValue: outcome === 'valid' || outcome === 'invalid' ? `observed ${recordKey}` : null,
    expectedValue: `recommended ${recordKey}`,
    warnings,
    evidence:
      outcome === 'indeterminate'
        ? { query: { upstream: 'system:127.0.0.1:53', reason: 'servfail', detail: 'SERVFAIL' } }
        : { query: { upstream: 'system:127.0.0.1:53', outcome: 'answer' } },
  };
}

function report(
  outcomes: Partial<Record<string, DnsCheckOutcome>>,
  extra: Partial<DomainCheckReport> = {},
): DomainCheckReport {
  const records = KEYS.map(([key]) => result(key, outcomes[key] ?? 'missing'));
  return {
    checkedAt: now,
    records,
    mx: { observed: [{ priority: 10, exchange: 'mx1.gw.test' }], propagation: [] },
    spf: { lookupCount: 1, lookupCountExact: true, recommendedValue: 'v=spf1 ~all' },
    dmarc: {
      stage: 'none',
      partial: false,
      recommendedValue: 'v=DMARC1; p=quarantine',
      nextStep: 'tighten',
    },
    indeterminate: records.some((r) => r.outcome === 'indeterminate'),
    ...extra,
  };
}

const plan = (
  s: StoredDomainState,
  r: DomainCheckReport,
  ownership?: 'won' | 'lost',
  at: Date = now,
) =>
  planReportApplication(s, r, { now: at, ownership, schedule, overlapDays: 7, jitter: noJitter });

describe('ownershipIntent (D3, D4)', () => {
  it('claims the name when the ownership TXT is found on a pending domain', () => {
    expect(ownershipIntent(state({}), report({ verification: 'valid' }), now)).toBe('claim');
  });

  it('expires a pending domain without definitive success at the expiry', () => {
    const expired = state({ expiresAt: now });
    expect(ownershipIntent(expired, report({ verification: 'missing' }), now)).toBe('expire');
    expect(ownershipIntent(expired, report({ verification: 'indeterminate' }), now)).toBe('expire');
    // A last-moment success still wins.
    expect(ownershipIntent(expired, report({ verification: 'valid' }), now)).toBe('claim');
  });

  it('does nothing before the expiry or for owned domains', () => {
    expect(ownershipIntent(state({}), report({ verification: 'invalid' }), now)).toBeNull();
    for (const status of ['verified', 'active', 'suspended'] as const) {
      expect(ownershipIntent(state({ status, expiresAt: now }), report({}), now)).toBeNull();
    }
  });

  it('only applies reports to checked statuses', () => {
    expect(reportApplies('pending_verification')).toBe(true);
    expect(reportApplies('active')).toBe(true);
    expect(reportApplies('failed')).toBe(false);
    expect(reportApplies('deleted')).toBe(false);
    expect(reportApplies('disabled')).toBe(false);
  });

  it('refuses to plan a claim before the ownership step ran', () => {
    expect(() => plan(state({}), report({ verification: 'valid' }))).toThrow(/ownership step/);
  });
});

describe('planReportApplication: record persistence (D10)', () => {
  it('writes definitive outcomes: status, observed value, recommendation, warnings', () => {
    const r = report({ verification: 'invalid', spf: 'valid' });
    r.records.find((x) => x.recordKey === 'spf')!.warnings = ['spf_ptr_mechanism'];
    const p = plan(state({ recordStatus: { spf: 'missing' } }), r);
    const spf = p.records.find((u) => u.recordKey === 'spf')!;
    expect(spf.data).toMatchObject({
      status: 'valid',
      statusChangedAt: now,
      observedValue: 'observed spf',
      expectedValue: 'recommended spf',
      lastOutcome: 'valid',
      lastCheckedAt: now,
      lastError: null,
    });
    expect(spf.data.evidence.warnings).toEqual(['spf_ptr_mechanism']);
    const ownership = p.records.find((u) => u.recordKey === 'verification')!;
    expect(ownership.data.status).toBe('invalid');
  });

  it('does not touch status_changed_at when the status stays the same', () => {
    const p = plan(state({ recordStatus: { dmarc: 'missing' } }), report({ dmarc: 'missing' }));
    const dmarc = p.records.find((u) => u.recordKey === 'dmarc')!;
    expect(dmarc.data.status).toBe('missing');
    expect(dmarc.data).not.toHaveProperty('statusChangedAt');
    expect(dmarc.data.evidence).toMatchObject({ stage: 'none', nextStep: 'tighten' });
  });

  it('records an indeterminate outcome without changing status, value or recommendation', () => {
    const s = state({ status: 'active', recordStatus: { spf: 'valid' } });
    const p = plan(s, report({ spf: 'indeterminate' }));
    const spf = p.records.find((u) => u.recordKey === 'spf')!;
    expect(spf.data).toEqual({
      lastOutcome: 'indeterminate',
      lastCheckedAt: now,
      lastError: 'servfail: SERVFAIL',
      evidence: expect.objectContaining({ warnings: ['previous_warning'] }),
    });
    expect(p.transition).toBeNull();
    expect(p.domain).not.toHaveProperty('status');
    expect(p.outcome).toBe('indeterminate');
  });

  it('keeps per-upstream MX outcomes in the MX evidence', () => {
    const p = plan(
      state({}),
      report(
        { 'mx:mx1.gw.test': 'invalid' },
        {
          mx: {
            observed: [{ priority: 10, exchange: 'mx1.gw.test' }],
            propagation: [{ upstream: 'system:10.0.0.1:53', outcome: 'missing' }],
          },
        },
      ),
    );
    const mx = p.records.find((u) => u.recordKey === 'mx:mx1.gw.test')!;
    expect(mx.data.evidence.propagationOutcomes).toEqual([
      { upstream: 'system:10.0.0.1:53', outcome: 'missing' },
    ]);
    expect(p.mxObservations).toEqual([{ priority: 10, exchange: 'mx1.gw.test' }]);
  });

  it('does not store MX observations when the primary MX result was indeterminate', () => {
    const p = plan(
      state({}),
      report({ 'mx:mx1.gw.test': 'indeterminate' }, { mx: { observed: null, propagation: [] } }),
    );
    expect(p.mxObservations).toBeNull();
  });

  it('ignores results for records that no longer exist', () => {
    const r = report({});
    r.records.push(result('dkim:gone', 'valid'));
    expect(plan(state({}), r).records.map((u) => u.recordKey)).not.toContain('dkim:gone');
  });

  it('formats indeterminate errors from evidence', () => {
    expect(
      indeterminateError({ query: { reason: 'timeout', detail: 'x'.repeat(600) } }),
    ).toHaveLength(512);
    expect(indeterminateError({})).toBe('other: no definitive DNS answer');
  });
});

describe('planReportApplication: lifecycle', () => {
  it('verifies the domain when the claim wins', () => {
    const p = plan(state({ attempts: 2 }), report({ verification: 'valid' }), 'won');
    expect(p.transition).toMatchObject({
      from: 'pending_verification',
      to: 'verified',
      reason: null,
      auditAction: 'domain.verified',
    });
    expect(p.domain).toMatchObject({ status: 'verified', verifiedAt: now, statusChangedAt: now });
    expect(p.verification!.data).toMatchObject({
      status: 'verified',
      verifiedAt: now,
      attempts: 3,
      lastOutcome: 'valid',
    });
    expect(p.outcome).toBe('verified');
    // Owned with incomplete configuration → recheck in 30 minutes.
    expect(p.domain.nextCheckAt).toEqual(later(1800));
  });

  it('fails the claim when another organization owns the name', () => {
    const p = plan(state({}), report({ verification: 'valid' }), 'lost');
    expect(p.transition).toMatchObject({
      to: 'failed',
      reason: 'claimed_by_another_organization',
      auditAction: 'domain.claim_superseded',
    });
    expect(p.domain).toMatchObject({ status: 'failed', nextCheckAt: null });
    expect(p.verification!.data).toMatchObject({ status: 'failed', nextCheckAt: null });
    expect(p.keyChanges).toEqual([]);
    expect(p.outcome).toBe('failed');
  });

  it('expires the verification at the expiry', () => {
    const p = plan(state({ expiresAt: now }), report({ verification: 'missing' }));
    expect(p.transition).toMatchObject({
      to: 'failed',
      reason: 'verification_expired',
      auditAction: 'domain.verification_expired',
    });
    expect(p.verification!.data.status).toBe('expired');
    expect(p.domain.nextCheckAt).toBeNull();
  });

  it('schedules pending retries with the attempt backoff, capped at the expiry', () => {
    const p = plan(state({ attempts: 2 }), report({ verification: 'missing' }));
    expect(p.transition).toBeNull();
    expect(p.verification!.data.attempts).toBe(3);
    expect(p.domain.nextCheckAt).toEqual(later(480));
    const capped = plan(state({ attempts: 9, expiresAt: later(100) }), report({}));
    expect(capped.domain.nextCheckAt).toEqual(later(100));
  });

  it('counts consecutive indeterminate checks and resets on a definitive one', () => {
    const indeterminate = plan(
      state({ status: 'active', checkFailures: 2 }),
      report({ verification: 'indeterminate' }),
    );
    expect(indeterminate.domain.checkFailures).toBe(3);
    expect(indeterminate.domain.nextCheckAt).toEqual(later(240));
    expect(indeterminate.verification!.data.lastError).toBe('servfail: SERVFAIL');
    const definitive = plan(state({ status: 'active', checkFailures: 2 }), report({}));
    expect(definitive.domain.checkFailures).toBe(0);
  });

  it('never changes the status of an owned domain because of DNS', () => {
    for (const status of ['verified', 'active', 'suspended'] as const) {
      const p = plan(
        state({ status, expiresAt: later(-DAY), recordStatus: { verification: 'valid' } }),
        report({ verification: 'missing', 'mx:mx1.gw.test': 'invalid' }),
      );
      expect(p.transition).toBeNull();
      expect(p.domain).not.toHaveProperty('status');
      expect(p.ownershipRecordMissing).toEqual({ outcome: 'missing' });
    }
  });

  it('flags the ownership record only on its valid → missing/invalid transition', () => {
    const s = state({ status: 'active', recordStatus: { verification: 'missing' } });
    expect(plan(s, report({ verification: 'missing' })).ownershipRecordMissing).toBeNull();
    const pending = state({ recordStatus: { verification: 'valid' } });
    expect(plan(pending, report({ verification: 'missing' })).ownershipRecordMissing).toBeNull();
  });

  it('rechecks healthy owned domains on the long interval', () => {
    const allValid = Object.fromEntries(KEYS.map(([k]) => [k, 'valid' as const]));
    const p = plan(
      state({
        status: 'active',
        keys: [{ id: 30n, selector: 'sel1', algorithm: 'rsa_2048', status: 'active' }],
      }),
      report(allValid),
    );
    expect(p.domain.nextCheckAt).toEqual(later(86_400));
    expect(p.outcome).toBe('checked');
  });
});

describe('planReportApplication: DKIM activation (D9)', () => {
  const owned = { status: 'active' as const };

  it('activates a pending key with a valid record once the domain is owned', () => {
    const p = plan(state(owned), report({ 'dkim:sel1': 'valid' }));
    expect(p.keyChanges).toEqual([
      { keyId: 30n, selector: 'sel1', algorithm: 'rsa_2048', to: 'active' },
    ]);
    expect(p.keyActivations).toEqual([
      { selector: 'sel1', algorithm: 'rsa_2048', previousSelector: null },
    ]);
  });

  it('activates in the same check that verifies ownership', () => {
    const p = plan(state({}), report({ verification: 'valid', 'dkim:sel1': 'valid' }), 'won');
    expect(p.keyChanges.map((c) => c.to)).toEqual(['active']);
  });

  it('does not activate keys of a pending or failed claim', () => {
    expect(plan(state({}), report({ 'dkim:sel1': 'valid' })).keyChanges).toEqual([]);
    expect(
      plan(state({}), report({ verification: 'valid', 'dkim:sel1': 'valid' }), 'lost').keyChanges,
    ).toEqual([]);
  });

  it('uses the stored record status when the DKIM lookup was indeterminate', () => {
    const p = plan(
      state({ ...owned, recordStatus: { 'dkim:sel1': 'valid' } }),
      report({ 'dkim:sel1': 'indeterminate' }),
    );
    expect(p.keyChanges.map((c) => c.to)).toEqual(['active']);
  });

  it('moves the previous active key of the algorithm to rotating for the overlap', () => {
    const s = state({
      ...owned,
      keys: [
        { id: 29n, selector: 'old', algorithm: 'rsa_2048', status: 'active' },
        { id: 30n, selector: 'sel1', algorithm: 'rsa_2048', status: 'pending' },
        { id: 31n, selector: 'ed', algorithm: 'ed25519', status: 'active' },
      ],
    });
    const p = plan(s, report({ 'dkim:sel1': 'valid' }));
    expect(p.keyChanges).toEqual([
      {
        keyId: 29n,
        selector: 'old',
        algorithm: 'rsa_2048',
        to: 'rotating',
        retireAfter: new Date(now.getTime() + 7 * DAY),
      },
      { keyId: 30n, selector: 'sel1', algorithm: 'rsa_2048', to: 'active' },
    ]);
    expect(p.keyActivations).toEqual([
      { selector: 'sel1', algorithm: 'rsa_2048', previousSelector: 'old' },
    ]);
  });

  it('leaves pending keys whose record is not valid', () => {
    expect(plan(state(owned), report({ 'dkim:sel1': 'invalid' })).keyChanges).toEqual([]);
  });

  it('is idempotent: re-applying the same report to the resulting state changes nothing', () => {
    const allValid = Object.fromEntries(KEYS.map(([k]) => [k, 'valid' as const]));
    const after = state({
      ...owned,
      recordStatus: allValid,
      keys: [{ id: 30n, selector: 'sel1', algorithm: 'rsa_2048', status: 'active' }],
    });
    const p = plan(after, report(allValid));
    expect(p.transition).toBeNull();
    expect(p.keyChanges).toEqual([]);
    expect(p.ownershipRecordMissing).toBeNull();
    expect(p.records.every((u) => !('statusChangedAt' in u.data))).toBe(true);
  });
});
