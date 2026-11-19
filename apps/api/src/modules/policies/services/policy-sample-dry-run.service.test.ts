import type { AtoPolicyFactsRepository } from '../repositories/ato-policy-facts.repository';
import { BadRequestException } from '@nestjs/common';
import {
  buildPolicyInput,
  compileSnapshot,
  evaluatePolicyPerRecipient,
} from '@email-gateway/policy-dsl';
import { describe, expect, it, vi } from 'vitest';
import { InMemoryPolicies } from '../../../../test/support/in-memory-policies';
import { cleanRound, quarantineDomainDefinition } from '../../../../test/support/policy-fixtures';
import type { Principal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../../database/transaction-runner';
import { CodedHttpException } from '../../../http/coded-exception';
import { policyRoundRowsOf, snapshotSource } from '../domain/policy-round';
import { PolicySampleDryRunSchema } from '../dto/policies.schemas';
import type {
  PolicyExecutionsRepository,
  SampleRoundRow,
} from '../repositories/policy-executions.repository';
import type { PolicyFactsRepository } from '../repositories/policy-facts.repository';
import { PoliciesService } from './policies.service';
import { PolicyEvaluationService } from './policy-evaluation.service';
import { PolicySampleDryRunService } from './policy-sample-dry-run.service';
import { type PolicyAuditor, type PolicyMetrics, PolicyWriter } from './policy-writer';

const SCOPE = systemScope(1n);
const principal = { kind: 'user', userId: 10n } as unknown as Principal;
const client = { ip: '203.0.113.9', userAgent: null } as never;
const NOW = new Date('2026-11-16T00:00:00.000Z');
const bounds = {
  POLICY_PLATFORM_DEFAULT: 'pol-default/1',
  POLICY_MAX_POLICIES: 10,
  POLICY_MAX_VERSIONS_PER_POLICY: 10,
  POLICY_MAX_ACTIVE_RULES: 100,
  POLICY_HISTORY_MAX_RANGE_DAYS: 31,
  POLICY_DRY_RUN_SAMPLE_MAX: 50,
  POLICY_SAMPLE_DRY_RUNS_PER_MINUTE: 6,
  POLICY_DRY_RUN_DEADLINE_MS: 10_000,
  DEPARTMENT_MAX_PER_ORG: 10,
  DEPARTMENT_MAX_MEMBERS: 100,
};

const publicIdOf = (n: number) => `0190f0f0-0000-7000-8000-0000000000${(0xa0 + n).toString(16)}`;

interface Fixture {
  id: bigint;
  publicId: string | null;
  receivedAt: Date;
  sender: string;
  scans: Array<{ id: bigint; round: number; status?: string; malformed?: boolean }>;
}

/**
 * Five messages of organization 1 (newest first): m1 from bad.example with two rounds, m2 clean,
 * m3 still running, m4 whose registry row is gone, m5 whose stored rows are malformed.
 */
const FIXTURES: Fixture[] = [
  {
    id: 101n,
    publicId: publicIdOf(1),
    receivedAt: new Date('2026-11-15T10:00:00.000Z'),
    sender: 'ceo@bad.example',
    scans: [
      { id: 902n, round: 1 },
      { id: 901n, round: 0 },
    ],
  },
  {
    id: 102n,
    publicId: publicIdOf(2),
    receivedAt: new Date('2026-11-15T09:00:00.000Z'),
    sender: 'someone@partner.example',
    scans: [{ id: 903n, round: 0 }],
  },
  {
    id: 103n,
    publicId: publicIdOf(3),
    receivedAt: new Date('2026-11-15T08:00:00.000Z'),
    sender: 'someone@partner.example',
    scans: [{ id: 904n, round: 0, status: 'running' }],
  },
  {
    id: 104n,
    publicId: null,
    receivedAt: new Date('2026-11-15T07:00:00.000Z'),
    sender: 'someone@partner.example',
    scans: [{ id: 905n, round: 0 }],
  },
  {
    id: 105n,
    publicId: publicIdOf(5),
    receivedAt: new Date('2026-11-15T06:00:00.000Z'),
    sender: 'someone@partner.example',
    scans: [{ id: 906n, round: 0, malformed: true }],
  },
];

function setup(settings: Partial<typeof bounds> = {}) {
  const store = new InMemoryPolicies();
  store.addUser(10n, { organizationId: 1n });
  store.activeDomains.add('1:acme.example');
  const metrics = {
    changes: { inc: vi.fn() },
    dryRuns: { inc: vi.fn() },
    sampleRounds: { inc: vi.fn() },
  };
  const writer = new PolicyWriter(store.transactions as unknown as TransactionRunner);
  const policies = new PoliciesService(
    bounds,
    store.repository,
    writer,
    { record: vi.fn(() => Promise.resolve()) } as unknown as PolicyAuditor,
    metrics as unknown as PolicyMetrics,
  );
  const rounds = new Map<bigint, { fixture: Fixture; round: ReturnType<typeof cleanRound> }>();
  for (const fixture of FIXTURES) {
    for (const scan of fixture.scans) {
      const round = cleanRound({
        messageId: fixture.id,
        receivedAt: fixture.receivedAt,
        organizationId: 1n,
        scanId: scan.id,
        envelopeFrom: fixture.sender,
      });
      round.scan.lifecycleRound = scan.round;
      if (scan.status) (round.scan as { status: string }).status = scan.status;
      if (scan.malformed) round.rows.risk.push({ ...round.rows.risk[0]!, revision: 7 });
      rounds.set(scan.id, { fixture, round });
    }
  }
  const byPublicId = new Map(FIXTURES.map((f) => [f.publicId, f]));
  let clock = 0;
  let tick = 0;
  const facts = {
    ...store.facts,
    message: vi.fn((scope: { organizationId: bigint }, id: string) => {
      clock += tick;
      const fixture = byPublicId.get(id);
      if (scope.organizationId !== 1n || !fixture) return Promise.resolve(null);
      const round = rounds.get(fixture.scans[0]!.id)!.round;
      return Promise.resolve({ ...round.message, publicId: id });
    }),
    scan: vi.fn((_s: unknown, message: { id: bigint }, id: bigint) => {
      const entry = rounds.get(id);
      return Promise.resolve(entry && entry.fixture.id === message.id ? entry.round.scan : null);
    }),
    roundRows: vi.fn((_s: unknown, _m: unknown, id: bigint) =>
      Promise.resolve(rounds.get(id)!.round.rows),
    ),
    storedEvaluation: vi.fn(() => Promise.reject(new Error('the sample never reads it'))),
  } as unknown as PolicyFactsRepository & Record<string, ReturnType<typeof vi.fn>>;
  const evaluation = new PolicyEvaluationService(
    bounds,
    facts,
    metrics as unknown as PolicyMetrics,
    { current: vi.fn(() => Promise.resolve(null)) } as unknown as AtoPolicyFactsRepository,
  );
  // The stored evaluations: what the platform default decided for every round (no tenant policy).
  const platform = compileSnapshot(
    snapshotSource({ generation: 0n, settings: null, policies: [] }, 'pol-default/1', {
      kind: 'active',
    }),
  );
  let nextId = 1000n;
  const rows: SampleRoundRow[] = [];
  for (const fixture of FIXTURES) {
    for (const scan of fixture.scans) {
      const { round } = rounds.get(scan.id)!;
      // A running or malformed round has no stored decision to compute here (the row says allow).
      const decided =
        scan.malformed || scan.status !== undefined
          ? null
          : evaluatePolicyPerRecipient(
              buildPolicyInput(
                policyRoundRowsOf(
                  { ...round.message, publicId: '' },
                  round.scan as never,
                  round.rows,
                  { departmentsByAddress: {}, usersByAddress: {} },
                ),
              ),
              platform,
            ).message;
      nextId -= 1n;
      rows.push({
        id: nextId,
        receivedAt: fixture.receivedAt,
        messageId: fixture.id,
        evaluationSeq: scan.round,
        scanId: scan.id,
        trigger: 'scanned',
        direction: 'inbound',
        disposition: decided?.disposition ?? 'allow',
        decisionSource: decided?.decisive.source ?? 'platform_default',
        decisivePolicyPublicId: null,
        decisiveRuleId: null,
        atoFacts: null,
        policyVersions: [],
        evaluatedAt: new Date(fixture.receivedAt.getTime() + 5_000),
      });
    }
  }
  const executions = {
    sampleRounds: vi.fn((_s: unknown, f: { take: number }) =>
      Promise.resolve(rows.slice(0, f.take)),
    ),
    messagePublicIds: vi.fn((_s: unknown, ids: readonly bigint[]) =>
      Promise.resolve(
        new Map(
          ids.flatMap((id) => {
            const f = FIXTURES.find((x) => x.id === id);
            return f?.publicId ? [[id, f.publicId] as const] : [];
          }),
        ),
      ),
    ),
  };
  const service = new PolicySampleDryRunService(
    { ...bounds, ...settings },
    evaluation,
    executions as unknown as PolicyExecutionsRepository,
    facts,
    metrics as unknown as PolicyMetrics,
  );
  return {
    store,
    policies,
    evaluation,
    service,
    executions,
    facts,
    metrics,
    rows,
    setTick: (ms: number) => (tick = ms),
    clock: () => clock,
    writes: () => store.calls.filter((c) => /create|update|publish|delete|bump/i.test(c)),
  };
}

const parse = (body: unknown = {}) => PolicySampleDryRunSchema.parse(body);
const codeOf = (p: Promise<unknown>) =>
  p.then(
    () => 'ok',
    (e: unknown) =>
      e instanceof CodedHttpException
        ? e.code
        : e instanceof BadRequestException
          ? 'validation_failed'
          : String(e),
  );

describe('PolicySampleDryRunService (step 7.3 §4.3)', () => {
  it('re-evaluates the newest round per message against the active snapshot; unchanged decisions', async () => {
    const ctx = setup();
    const res = await ctx.service.sampleDryRun(SCOPE, parse(), { now: NOW });
    expect(ctx.executions.sampleRounds).toHaveBeenCalledWith(SCOPE, {
      from: new Date('2026-11-09T00:00:00.000Z'),
      to: NOW,
      take: 100,
    });
    expect(res.target).toEqual({ kind: 'active', policyId: null, versionNo: null });
    expect(res.window).toEqual({ from: '2026-11-09T00:00:00.000Z', to: NOW.toISOString() });
    expect(res.items.map((i) => [i.messageId, i.lifecycleRound, i.scanId, i.outcome])).toEqual([
      [publicIdOf(1), 1, '902', 'evaluated'],
      [publicIdOf(2), 0, '903', 'evaluated'],
      [publicIdOf(3), 0, '904', 'not_complete'],
      [null, 0, '905', 'not_found'],
      [publicIdOf(5), 0, '906', 'input_invalid'],
    ]);
    expect(res).toMatchObject({ limit: 25, evaluated: 2, skipped: 3, truncated: false });
    // Six stored rows in the window, fewer than 25 × 4: the whole window was read.
    expect(res.exhausted).toBe(true);
    for (const item of res.items.filter((i) => i.outcome === 'evaluated')) {
      expect(item.dryRun).toMatchObject({ disposition: 'allow', source: 'platform_default' });
      expect([item.dispositionChanged, item.decisiveChanged]).toEqual([false, false]);
    }
    expect(res.summary).toEqual({
      changed: 0,
      unchanged: 2,
      stored: { allow: 2, require_approval: 0, quarantine: 0, reject: 0 },
      dryRun: { allow: 2, require_approval: 0, quarantine: 0, reject: 0 },
      transitions: [],
    });
    expect(JSON.stringify(res)).not.toContain('@');
    expect(ctx.metrics.dryRuns.inc).toHaveBeenCalledWith({ kind: 'sample', result: 'ok' });
    for (const outcome of ['evaluated', 'not_complete', 'not_found', 'input_invalid']) {
      expect(ctx.metrics.sampleRounds.inc).toHaveBeenCalledWith({ outcome });
    }
    expect(ctx.metrics.sampleRounds.inc).toHaveBeenCalledTimes(5);
  });

  it('shows the decisions a draft version would change, compiling the snapshot once and writing nothing', async () => {
    const ctx = setup();
    const { policy } = await ctx.policies.create(
      principal,
      SCOPE,
      { name: 'q', definition: quarantineDomainDefinition('bad.example') },
      client,
    );
    const writes = ctx.writes().length;
    const snapshots = ctx.store.calls.filter((c) => c === 'snapshot').length;
    const compile = vi.spyOn(ctx.evaluation, 'compile');
    const res = await ctx.service.sampleDryRun(
      SCOPE,
      parse({ target: { policyId: policy.id, versionNo: 1 }, sample: { direction: 'inbound' } }),
      { now: NOW },
    );
    expect(compile).toHaveBeenCalledTimes(1);
    expect(ctx.store.calls.filter((c) => c === 'snapshot').length).toBe(snapshots + 1);
    expect(ctx.executions.sampleRounds).toHaveBeenCalledWith(
      SCOPE,
      expect.objectContaining({ direction: 'inbound' }),
    );
    expect(res.target).toEqual({ kind: 'version', policyId: policy.id, versionNo: 1 });
    const [m1, m2] = res.items;
    expect(m1).toMatchObject({
      outcome: 'evaluated',
      stored: { disposition: 'allow', source: 'platform_default', policyId: null },
      dryRun: {
        disposition: 'quarantine',
        source: 'tenant_rule',
        policyId: policy.id,
        versionNo: 1,
        ruleId: 'quarantine-domain',
        actionTypes: ['QUARANTINE', 'TAG'],
      },
      dispositionChanged: true,
      decisiveChanged: true,
    });
    expect(m2).toMatchObject({ dispositionChanged: false, decisiveChanged: false });
    expect(res.summary).toMatchObject({
      changed: 1,
      unchanged: 1,
      dryRun: { allow: 1, quarantine: 1 },
      transitions: [{ from: 'allow', to: 'quarantine', count: 1 }],
    });
    expect(ctx.writes().length).toBe(writes);
    // The inline target reports the synthetic snapshot id.
    const inline = await ctx.service.sampleDryRun(
      SCOPE,
      parse({ target: { definition: quarantineDomainDefinition('bad.example') } }),
      { now: NOW },
    );
    expect(inline.target.kind).toBe('inline');
    expect(inline.items[0]!.dryRun!.policyId).toBe('00000000-0000-7000-8000-000000000000');
  });

  it('bounds the selection by limit × 4 and keeps at most limit messages', async () => {
    const ctx = setup();
    const res = await ctx.service.sampleDryRun(SCOPE, parse({ sample: { limit: 1 } }), {
      now: NOW,
    });
    expect(ctx.executions.sampleRounds).toHaveBeenCalledWith(
      SCOPE,
      expect.objectContaining({ take: 4 }),
    );
    expect(res.items.map((i) => i.messageId)).toEqual([publicIdOf(1)]);
    // Four rows were read (the bound): the window may hold more, so it is not exhausted.
    expect(res.exhausted).toBe(false);
    const two = await ctx.service.sampleDryRun(SCOPE, parse({ sample: { limit: 2 } }), {
      now: NOW,
    });
    expect(two.items).toHaveLength(2);
    expect(two.exhausted).toBe(false);
  });

  it('returns the evaluated prefix with truncated: true when the deadline passes', async () => {
    const ctx = setup({ POLICY_DRY_RUN_DEADLINE_MS: 1_000 });
    ctx.setTick(600);
    const res = await ctx.service.sampleDryRun(SCOPE, parse(), {
      now: NOW,
      clock: () => ctx.clock(),
    });
    expect(res.truncated).toBe(true);
    expect(res.items.map((i) => i.messageId)).toEqual([publicIdOf(1), publicIdOf(2)]);
    expect(res.evaluated).toBe(2);
    expect(ctx.metrics.sampleRounds.inc).toHaveBeenCalledWith({ outcome: 'deadline' }, 3);
  });

  it('refuses limits, ranges and targets with 400/404 before reading any round', async () => {
    const ctx = setup({ POLICY_DRY_RUN_SAMPLE_MAX: 10, POLICY_HISTORY_MAX_RANGE_DAYS: 7 });
    const run = (body: unknown) =>
      codeOf(ctx.service.sampleDryRun(SCOPE, parse(body), { now: NOW }));
    expect(await run({ sample: { limit: 11 } })).toBe('validation_failed');
    expect(
      await run({ sample: { from: '2026-11-10T00:00:00.000Z', to: '2026-11-10T00:00:00.000Z' } }),
    ).toBe('validation_failed');
    expect(await run({ sample: { from: '2026-11-17T00:00:00.000Z' } })).toBe('validation_failed');
    expect(
      await run({ sample: { from: '2026-11-01T00:00:00.000Z', to: '2026-11-08T00:00:00.001Z' } }),
    ).toBe('validation_failed');
    expect(await run({ target: { definition: { dslVersion: 'x' } } })).toBe(
      'policy_definition_invalid',
    );
    expect(
      await run({ target: { policyId: '0190f0f0-0000-7000-8000-00000000beef', versionNo: 1 } }),
    ).toBe('policy_version_not_found');
    expect(ctx.executions.sampleRounds).not.toHaveBeenCalled();
    expect(ctx.metrics.dryRuns.inc).toHaveBeenCalledWith({ kind: 'sample', result: 'invalid' });
    expect(ctx.metrics.dryRuns.inc).toHaveBeenCalledWith({ kind: 'sample', result: 'not_found' });
    expect(ctx.metrics.dryRuns.inc).toHaveBeenCalledTimes(2);
    // A window of exactly the bound is accepted; the default window and limit are clamped.
    expect(
      await run({ sample: { from: '2026-11-01T00:00:00.000Z', to: '2026-11-08T00:00:00.000Z' } }),
    ).toBe('ok');
    const defaults = await ctx.service.sampleDryRun(SCOPE, parse(), { now: NOW });
    expect(defaults.limit).toBe(10);
    expect(ctx.executions.sampleRounds).toHaveBeenLastCalledWith(
      SCOPE,
      expect.objectContaining({ take: 40, from: new Date('2026-11-09T00:00:00.000Z') }),
    );
  });

  it('never reads another organization’s rounds (the scope goes to every read)', async () => {
    const ctx = setup();
    const other = systemScope(2n);
    const res = await ctx.service.sampleDryRun(other, parse(), { now: NOW });
    for (const call of ctx.executions.sampleRounds.mock.calls) expect(call[0]).toBe(other);
    for (const call of ctx.executions.messagePublicIds.mock.calls) expect(call[0]).toBe(other);
    // The fake answers no message for organization 2: every selected round is not_found.
    expect(res.items.every((i) => i.outcome === 'not_found')).toBe(true);
  });
});
