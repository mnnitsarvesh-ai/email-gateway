import { describe, expect, it } from 'vitest';
import { selectWithinCaps } from './claims';
import { locateBackoffMs, retryBackoffMs } from './executor';
import { ruleIdOf } from './outcomes';

describe('selectWithinCaps (R5.1 per-connection concurrency)', () => {
  const c = (id: number, connection: number) => ({
    id: BigInt(id),
    apiConnectionId: BigInt(connection),
  });

  it('caps every connection, counting rows other replicas hold, and keeps the due order', () => {
    const candidates = [c(1, 10), c(2, 10), c(3, 10), c(4, 20), c(5, 30), c(6, 20)];
    const inFlight = new Map([[20n, 1]]);
    expect(selectWithinCaps(candidates, inFlight, 2, 50).map((x) => x.id)).toEqual([
      1n,
      2n,
      4n,
      5n,
    ]);
  });

  it('stops at the batch size and skips saturated connections', () => {
    const candidates = [c(1, 10), c(2, 20), c(3, 30)];
    expect(selectWithinCaps(candidates, new Map(), 2, 2).map((x) => x.id)).toEqual([1n, 2n]);
    expect(selectWithinCaps(candidates, new Map([[10n, 2]]), 2, 5).map((x) => x.id)).toEqual([
      2n,
      3n,
    ]);
  });
});

describe('back-off (R5.3, R5.6)', () => {
  it('locates again after 60 s doubling', () => {
    expect([1, 2, 3, 4, 5].map(locateBackoffMs)).toEqual([
      60_000, 120_000, 240_000, 480_000, 960_000,
    ]);
  });

  it('retries after 30 s doubling, capped by API_MODE_REMEDIATION_BACKOFF_MAX_SECONDS', () => {
    expect([0, 1, 2, 6, 7, 10].map((a) => retryBackoffMs(a, 3600))).toEqual([
      30_000, 60_000, 120_000, 1_920_000, 3_600_000, 3_600_000,
    ]);
    expect(retryBackoffMs(3, 60)).toBe(60_000);
  });
});

describe('ruleIdOf', () => {
  it('reads the rule id of a decision record only when it is a rule id', () => {
    expect(ruleIdOf({ v: 1, ruleId: 'p1-suspicious' })).toBe('p1-suspicious');
    expect(ruleIdOf({ ruleId: 'Not a rule <id>' })).toBeNull();
    expect(ruleIdOf({ requestedAction: 'tag', reason: 'x' })).toBeNull();
    expect(ruleIdOf(null)).toBeNull();
  });
});
