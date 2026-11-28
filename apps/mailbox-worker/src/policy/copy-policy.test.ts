/* eslint-disable @typescript-eslint/require-await -- the fakes implement async ports */
import { describe, expect, it, vi } from 'vitest';
import type { Prisma } from '@email-gateway/database';
import type { PolicyEvaluationView } from '@email-gateway/policy-dsl';
import { InconsistentPolicyReadError } from '@email-gateway/policy-runtime';
import { CopyPolicyEvaluator, dlpCategoryCodes, storedOutcomeOf } from './copy-policy';

const POLICY = '0193a000-0000-7000-8000-0000000000aa';

const view = (over: Partial<PolicyEvaluationView> = {}): PolicyEvaluationView =>
  ({
    disposition: 'quarantine',
    decisive: {
      source: 'tenant_rule',
      policyPublicId: POLICY,
      versionNo: 2,
      ruleId: 'q',
      reason: 'x',
    },
    actions: [
      { type: 'QUARANTINE', applicability: 'applies', params: {}, ruleRefs: [] },
      { type: 'TAG', applicability: 'not_applicable', params: {}, ruleRefs: [] },
      { type: 'ALERT', applicability: 'applies', params: {}, ruleRefs: [] },
    ],
    override: null,
    floor: { disposition: null, tag: false, reasons: ['policy.floor.dlp_alert'] },
    recipientSplit: false,
    recipientDecisions: null,
    ...over,
  }) as unknown as PolicyEvaluationView;

describe('storedOutcomeOf (A1 duplicate: reuse of the stored detect row)', () => {
  it('message level: disposition, rule ref, applying action types, floor reasons, DLP action', () => {
    expect(storedOutcomeOf(view(), null, 'alert')).toEqual({
      disposition: 'quarantine',
      tagged: false,
      overrideApplied: false,
      decisionSource: 'tenant_rule',
      decisiveRuleRef: `${POLICY}#2/q`,
      floorReasons: ['policy.floor.dlp_alert'],
      dlpAction: 'alert',
      actionTypes: ['QUARANTINE', 'ALERT'],
      recommendationOnly: false,
    });
  });

  it('marks a platform-default disposition that restates the risk recommendation (review fix)', () => {
    const platform = view({
      decisive: {
        source: 'platform_default',
        policyPublicId: null,
        versionNo: null,
        ruleId: null,
        reason: 'policy.default.risk_quarantine',
      },
      floor: { disposition: null, tag: false, reasons: [] },
    } as unknown as Partial<PolicyEvaluationView>);
    expect(storedOutcomeOf(platform, null, null)).toMatchObject({
      decisionSource: 'platform_default',
      recommendationOnly: true,
    });
    const dlpFloor = view({
      decisive: platform.decisive,
      floor: { disposition: 'quarantine', tag: false, reasons: ['policy.floor.dlp_quarantine'] },
    } as unknown as Partial<PolicyEvaluationView>);
    expect(storedOutcomeOf(dlpFloor, null, 'quarantine').recommendationOnly).toBe(false);
    const riskTag = view({
      disposition: 'allow',
      decisive: { ...platform.decisive, reason: 'policy.default.risk_tag' },
      actions: [
        {
          type: 'TAG',
          applicability: 'applies',
          origin: 'platform_default',
          params: {},
          ruleRefs: [],
        },
      ],
      floor: { disposition: null, tag: false, reasons: [] },
    } as unknown as Partial<PolicyEvaluationView>);
    expect(storedOutcomeOf(riskTag, null, null)).toMatchObject({
      tagged: true,
      recommendationOnly: true,
    });
  });

  it('a split evaluation uses the recipient decision; tagged only with allow', () => {
    const split = view({
      disposition: 'allow',
      actions: [{ type: 'TAG', applicability: 'applies', params: {}, ruleRefs: [] }],
      recipientSplit: true,
      recipientDecisions: [
        {
          rcptSeq: 0,
          disposition: 'allow',
          source: 'platform_default',
          decisiveRuleRef: null,
          reasonCodes: [],
        },
        {
          rcptSeq: 1,
          disposition: 'reject',
          source: 'tenant_rule',
          decisiveRuleRef: `${POLICY}#2/r`,
          reasonCodes: [],
        },
      ],
    } as unknown as Partial<PolicyEvaluationView>);
    expect(storedOutcomeOf(split, 0, null)).toMatchObject({ disposition: 'allow', tagged: true });
    expect(storedOutcomeOf(split, 1, null)).toMatchObject({
      disposition: 'reject',
      tagged: false,
      decisionSource: 'tenant_rule',
      decisiveRuleRef: `${POLICY}#2/r`,
    });
  });
});

describe('dlpCategoryCodes', () => {
  it('unique, sorted, bounded category codes of stored rows (JSON text or value)', () => {
    expect(
      dlpCategoryCodes(
        JSON.stringify([
          { category: 'payment_card', maxSeverity: 'high' },
          { category: 'credential' },
          { category: 'payment_card' },
          { category: 'Not A Code' },
          null,
        ]),
      ),
    ).toEqual(['credential', 'payment_card']);
    expect(dlpCategoryCodes('not json')).toEqual([]);
  });
});

describe('CopyPolicyEvaluator (A1)', () => {
  const ref = {
    messageId: 7n,
    receivedAt: new Date('2026-11-27T10:00:00.000Z'),
    organizationId: 41n,
    round: 0,
    trigger: 'scanned' as const,
    scanId: 99n,
  };
  const tx = (stored: unknown) =>
    ({
      policyExecutionLog: { findUnique: vi.fn(async () => stored), create: vi.fn() },
    }) as unknown as Prisma.TransactionClient;
  const deps = (read: () => Promise<never>) => ({
    enabled: true,
    facts: { read: vi.fn(read) },
    snapshots: { get: vi.fn() },
    directory: { resolve: vi.fn() },
  });

  it('a PolicyInputError of the fact reads → failed (never thrown, never a row)', async () => {
    const { PolicyInputError } = await import('@email-gateway/policy-dsl');
    const d = deps(async () => {
      throw new PolicyInputError('malformed row');
    });
    const t = tx(null);
    const result = await new CopyPolicyEvaluator(d).evaluate(t, ref, new Date());
    expect(result).toMatchObject({
      state: 'failed',
      failureCode: 'policy_input_invalid',
      fresh: true,
    });
    expect(result.outcomeFor(0)).toBeNull();
    expect(
      (t as unknown as { policyExecutionLog: { create: ReturnType<typeof vi.fn> } })
        .policyExecutionLog.create,
    ).not.toHaveBeenCalled();
  });

  it('an inconsistent read throws (the ledger transaction is retried)', async () => {
    const d = deps(async () => {
      throw new InconsistentPolicyReadError('scan', 'row missing');
    });
    await expect(
      new CopyPolicyEvaluator(d as never).evaluate(tx(null), ref, new Date()),
    ).rejects.toBeInstanceOf(InconsistentPolicyReadError);
  });

  it('a stored row of another organization is an inconsistent read', async () => {
    const d = deps(async () => {
      throw new Error('not reached');
    });
    await expect(
      new CopyPolicyEvaluator(d as never).evaluate(tx({ organizationId: 42n }), ref, new Date()),
    ).rejects.toThrow('inconsistent read');
    expect(d.facts.read).not.toHaveBeenCalled();
  });
});
