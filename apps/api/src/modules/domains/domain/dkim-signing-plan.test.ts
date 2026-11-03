import { describe, expect, it } from 'vitest';
import { dkimKeyField, isEmptyPlan, planSigningSync } from './dkim-signing-plan';

const PEM_A = '-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n';
const PEM_B = '-----BEGIN PRIVATE KEY-----\nBBB\n-----END PRIVATE KEY-----\n';

describe('planSigningSync (D12)', () => {
  it('publishes new domains: key first, then selector', () => {
    const plan = planSigningSync([{ domain: 'a.test', selector: 's1', pem: PEM_A }], {
      selectors: {},
      keyFields: [],
    });
    expect(plan.keysToWrite).toEqual([['s1.a.test', PEM_A]]);
    expect(plan.selectorsToWrite).toEqual([['a.test', 's1']]);
    expect(plan.selectorsToDelete).toEqual([]);
    expect(plan.keysToDelete).toEqual([]);
    expect(plan.counts).toEqual({ published: 1, removed: 0, unchanged: 0, skipped: 0, pruned: 0 });
  });

  it('leaves published domains alone (empty plan)', () => {
    const plan = planSigningSync([{ domain: 'a.test', selector: 's1', pem: PEM_A }], {
      selectors: { 'a.test': 's1' },
      keyFields: ['s1.a.test'],
    });
    expect(isEmptyPlan(plan)).toBe(true);
    expect(plan.counts).toMatchObject({ published: 0, unchanged: 1 });
  });

  it('switches the selector on rotation and prunes the old key', () => {
    const plan = planSigningSync([{ domain: 'a.test', selector: 's2', pem: PEM_B }], {
      selectors: { 'a.test': 's1' },
      keyFields: ['s1.a.test'],
    });
    expect(plan.keysToWrite).toEqual([['s2.a.test', PEM_B]]);
    expect(plan.selectorsToWrite).toEqual([['a.test', 's2']]);
    expect(plan.keysToDelete).toEqual(['s1.a.test']);
    expect(plan.counts).toEqual({ published: 1, removed: 0, unchanged: 0, skipped: 0, pruned: 1 });
  });

  it('rewrites a missing key without touching the selector', () => {
    const plan = planSigningSync([{ domain: 'a.test', selector: 's1', pem: PEM_A }], {
      selectors: { 'a.test': 's1' },
      keyFields: [],
    });
    expect(plan.keysToWrite).toEqual([['s1.a.test', PEM_A]]);
    expect(plan.selectorsToWrite).toEqual([]);
    expect(plan.counts.published).toBe(1);
  });

  it('removes domains that are no longer signable, selector before key', () => {
    const plan = planSigningSync([], {
      selectors: { 'gone.test': 's9' },
      keyFields: ['s9.gone.test', 'orphan.other.test'],
    });
    expect(plan.selectorsToDelete).toEqual(['gone.test']);
    expect(plan.keysToDelete).toEqual(['s9.gone.test', 'orphan.other.test']);
    expect(plan.counts).toEqual({ published: 0, removed: 1, unchanged: 0, skipped: 0, pruned: 2 });
  });

  it('keeps a domain whose key could not be decrypted exactly as published', () => {
    const plan = planSigningSync(
      [{ domain: 'b.test', selector: 'b1', pem: PEM_B }],
      { selectors: { 'a.test': 's1', 'b.test': 'b1' }, keyFields: ['s1.a.test', 'b1.b.test'] },
      new Set(['a.test']),
    );
    expect(isEmptyPlan(plan)).toBe(true);
    expect(plan.counts).toEqual({ published: 0, removed: 0, unchanged: 1, skipped: 1, pruned: 0 });
    // Not yet published and undecryptable: nothing to write, still counted as skipped.
    expect(
      planSigningSync([], { selectors: {}, keyFields: [] }, new Set(['c.test'])).counts.skipped,
    ).toBe(1);
  });

  it('builds key fields as <selector>.<domain>', () => {
    expect(dkimKeyField('eg20261102abcd', 'xn--bcher-kva.test')).toBe(
      'eg20261102abcd.xn--bcher-kva.test',
    );
  });
});
