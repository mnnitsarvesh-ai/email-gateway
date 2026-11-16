import { describe, expect, it } from 'vitest';
import type { PolicySampleItem } from '../dto/policies.schemas';
import type { SampleRoundRow } from '../repositories/policy-executions.repository';
import {
  sampleItem,
  sampleSummary,
  sampleTarget,
  sampleWindow,
  selectSampleRounds,
  windowTooWide,
} from './policy-sample';

const POLICY = '0190f0f0-0000-7000-8000-00000000a001';

function sampleRow(over: Partial<SampleRoundRow> = {}): SampleRoundRow {
  return {
    id: 1n,
    receivedAt: new Date('2026-11-15T10:00:00.000Z'),
    messageId: 100n,
    evaluationSeq: 0,
    scanId: 900n,
    trigger: 'scanned',
    direction: 'inbound',
    disposition: 'allow',
    decisionSource: 'platform_default',
    decisivePolicyPublicId: null,
    decisiveRuleId: null,
    policyVersions: [],
    evaluatedAt: new Date('2026-11-15T10:00:05.000Z'),
    ...over,
  };
}

describe('sampleWindow / windowTooWide (step 7.3 §4.3)', () => {
  const now = new Date('2026-11-16T12:00:00.000Z');

  it('defaults to the 7 days before the request time', () => {
    expect(sampleWindow({}, now, 7, 31)).toEqual({
      from: new Date('2026-11-09T12:00:00.000Z'),
      to: now,
    });
    const to = '2026-11-10T00:00:00.000Z';
    expect(sampleWindow({ to }, now, 7, 31)).toEqual({
      from: new Date('2026-11-03T00:00:00.000Z'),
      to: new Date(to),
    });
    const from = '2026-11-15T00:00:00.000Z';
    expect(sampleWindow({ from }, now, 7, 31)).toEqual({ from: new Date(from), to: now });
  });

  it('clamps the default window to the widest allowed range', () => {
    const w = sampleWindow({}, now, 7, 2);
    expect(w.to.getTime() - w.from.getTime()).toBe(2 * 86_400_000);
    expect(windowTooWide(w, 2)).toBe(false);
  });

  it('flags a range longer than the bound', () => {
    const from = new Date('2026-11-01T00:00:00.000Z');
    expect(windowTooWide({ from, to: new Date('2026-11-08T00:00:00.000Z') }, 7)).toBe(false);
    expect(windowTooWide({ from, to: new Date('2026-11-08T00:00:00.001Z') }, 7)).toBe(true);
  });
});

describe('selectSampleRounds', () => {
  it('keeps the newest evaluated round per message, newest message first, at most limit', () => {
    const rows = [
      sampleRow({ id: 9n, messageId: 3n, receivedAt: new Date('2026-11-15T12:00:00Z') }),
      // Message 2: round 1 (newer) and round 0.
      sampleRow({
        id: 8n,
        messageId: 2n,
        evaluationSeq: 1,
        receivedAt: new Date('2026-11-15T11:00:00Z'),
      }),
      sampleRow({
        id: 7n,
        messageId: 2n,
        evaluationSeq: 0,
        receivedAt: new Date('2026-11-15T11:00:00Z'),
      }),
      sampleRow({ id: 6n, messageId: 1n, receivedAt: new Date('2026-11-15T10:00:00Z') }),
    ];
    expect(selectSampleRounds(rows, 10).map((r) => [r.messageId, r.evaluationSeq])).toEqual([
      [3n, 0],
      [2n, 1],
      [1n, 0],
    ]);
    expect(selectSampleRounds(rows, 2).map((r) => r.id)).toEqual([9n, 8n]);
  });

  it('prefers the higher round even when it was read later, and skips rounds without a scan', () => {
    const at = new Date('2026-11-15T11:00:00Z');
    const rows = [
      sampleRow({ id: 5n, messageId: 2n, evaluationSeq: 0, receivedAt: at }),
      sampleRow({ id: 4n, messageId: 2n, evaluationSeq: 2, receivedAt: at }),
      sampleRow({ id: 3n, messageId: 4n, scanId: null, trigger: 'parse_failed' }),
    ];
    expect(selectSampleRounds(rows, 5).map((r) => [r.id, r.evaluationSeq])).toEqual([[4n, 2]]);
  });
});

describe('sampleTarget', () => {
  it('reports the kind and, for versions and inline definitions, the snapshot id', () => {
    expect(sampleTarget('active')).toEqual({ kind: 'active', policyId: null, versionNo: null });
    expect(sampleTarget('platform')).toEqual({ kind: 'platform', policyId: null, versionNo: null });
    expect(sampleTarget({ policyId: POLICY, versionNo: 3 })).toEqual({
      kind: 'version',
      policyId: POLICY,
      versionNo: 3,
    });
    expect(sampleTarget({ definition: {} })).toEqual({
      kind: 'inline',
      policyId: '00000000-0000-7000-8000-000000000000',
      versionNo: 1,
    });
  });
});

describe('sampleItem and sampleSummary', () => {
  const evaluation = (
    disposition: 'allow' | 'quarantine' | 'reject',
    decisive: { source: string; policyPublicId: string | null; ruleId: string | null },
  ) =>
    ({
      split: false,
      lifecycleDisposition: disposition,
      message: {
        disposition,
        decisive: { ...decisive, versionNo: decisive.policyPublicId ? 2 : null, reason: 'x.y' },
        matchedRules: decisive.ruleId ? [{}] : [],
        actions: [{ type: disposition === 'allow' ? 'ALLOW' : 'QUARANTINE' }],
        override: null,
      },
    }) as never;

  it('maps the stored row (version from the snapshot JSON) and the recomputed decision', () => {
    const row = sampleRow({
      disposition: 'quarantine',
      decisionSource: 'tenant_rule',
      decisivePolicyPublicId: POLICY,
      decisiveRuleId: 'r1',
      policyVersions: [{ policyPublicId: POLICY, versionNo: 2, definitionSha256: 'x' }],
    });
    const same = sampleItem(
      row,
      'm-1',
      'evaluated',
      evaluation('quarantine', { source: 'tenant_rule', policyPublicId: POLICY, ruleId: 'r1' }),
    );
    expect(same).toMatchObject({
      messageId: 'm-1',
      lifecycleRound: 0,
      scanId: '900',
      trigger: 'scanned',
      outcome: 'evaluated',
      stored: { disposition: 'quarantine', source: 'tenant_rule', policyId: POLICY, versionNo: 2 },
      dryRun: { disposition: 'quarantine', versionNo: 2, matchedRuleCount: 1 },
      dispositionChanged: false,
      decisiveChanged: false,
    });
    const other = sampleItem(
      row,
      'm-1',
      'evaluated',
      evaluation('quarantine', { source: 'tenant_rule', policyPublicId: POLICY, ruleId: 'r2' }),
    );
    expect([other.dispositionChanged, other.decisiveChanged]).toEqual([false, true]);
    const skipped = sampleItem(row, null, 'not_found', null);
    expect(skipped).toMatchObject({
      messageId: null,
      dryRun: null,
      dispositionChanged: false,
      decisiveChanged: false,
    });
  });

  it('counts evaluated items only and sorts the transitions by count', () => {
    const item = (from: string, to: string | null): PolicySampleItem =>
      ({
        stored: { disposition: from },
        dryRun: to === null ? null : { disposition: to },
        dispositionChanged: to !== null && to !== from,
        outcome: to === null ? 'not_complete' : 'evaluated',
      }) as never;
    const summary = sampleSummary([
      item('allow', 'quarantine'),
      item('allow', 'allow'),
      item('quarantine', 'reject'),
      item('allow', 'quarantine'),
      item('reject', null),
    ]);
    expect(summary).toEqual({
      changed: 3,
      unchanged: 1,
      stored: { allow: 3, require_approval: 0, quarantine: 1, reject: 0 },
      dryRun: { allow: 1, require_approval: 0, quarantine: 2, reject: 1 },
      transitions: [
        { from: 'allow', to: 'quarantine', count: 2 },
        { from: 'quarantine', to: 'reject', count: 1 },
      ],
    });
    expect(sampleSummary([])).toMatchObject({ changed: 0, unchanged: 0, transitions: [] });
  });
});
