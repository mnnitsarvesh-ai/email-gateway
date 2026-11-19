import type { AtoPolicyFactsRepository } from '../repositories/ato-policy-facts.repository';
import {
  buildPolicyInput,
  compileSnapshot,
  evaluatePolicyPerRecipient,
  evaluationResultToRow,
} from '@email-gateway/policy-dsl';
import { describe, expect, it, vi } from 'vitest';
import { InMemoryPolicies } from '../../../../test/support/in-memory-policies';
import {
  cleanRound,
  departmentExceptionDefinition,
  quarantineDomainDefinition,
  tagAllDefinition,
} from '../../../../test/support/policy-fixtures';
import type { Principal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../../database/transaction-runner';
import { CodedHttpException } from '../../../http/coded-exception';
import { DepartmentsService } from '../../directory/services/departments.service';
import {
  directoryMaps,
  policyRoundRowsOf,
  roundAddresses,
  snapshotSource,
} from '../domain/policy-round';
import { PolicyTestSchema, PolicyDryRunSchema } from '../dto/policies.schemas';
import type { PolicyFactsRepository } from '../repositories/policy-facts.repository';
import { PoliciesService } from './policies.service';
import { PolicyEvaluationService } from './policy-evaluation.service';
import { type PolicyAuditor, type PolicyMetrics, PolicyWriter } from './policy-writer';

const SCOPE = systemScope(1n);
const principal = { kind: 'user', userId: 10n } as unknown as Principal;
const client = { ip: '203.0.113.9', userAgent: null } as never;
const MESSAGE = '0190f0f0-0000-7000-8000-0000000000aa';
const bounds = {
  POLICY_PLATFORM_DEFAULT: 'pol-default/1',
  POLICY_MAX_POLICIES: 10,
  POLICY_MAX_VERSIONS_PER_POLICY: 10,
  POLICY_MAX_ACTIVE_RULES: 100,
  POLICY_HISTORY_MAX_RANGE_DAYS: 31,
  // Step 7.3 §3: the sample dry-run bounds the catalog reports.
  POLICY_DRY_RUN_SAMPLE_MAX: 50,
  POLICY_SAMPLE_DRY_RUNS_PER_MINUTE: 6,
  DEPARTMENT_MAX_PER_ORG: 10,
  DEPARTMENT_MAX_MEMBERS: 100,
};

function setup() {
  const store = new InMemoryPolicies();
  store.addUser(10n, { organizationId: 1n });
  store.activeDomains.add('1:acme.example');
  const audit = { record: vi.fn(() => Promise.resolve()) };
  const metrics = { changes: { inc: vi.fn() }, dryRuns: { inc: vi.fn() } };
  const writer = new PolicyWriter(store.transactions as unknown as TransactionRunner);
  const policies = new PoliciesService(
    bounds,
    store.repository,
    writer,
    audit as unknown as PolicyAuditor,
    metrics as unknown as PolicyMetrics,
  );
  const departments = new DepartmentsService(
    bounds,
    store.departments,
    store.repository,
    writer,
    audit as unknown as PolicyAuditor,
    metrics as unknown as PolicyMetrics,
  );
  const round = cleanRound({
    messageId: 77n,
    receivedAt: new Date('2026-11-11T08:00:00.000Z'),
    organizationId: 1n,
    scanId: 900n,
    recipients: ['alice@acme.example', 'Bob@ACME.example'],
  });
  const message = { ...round.message, publicId: MESSAGE };
  let stored: unknown = null;
  let scanStatus = 'completed';
  const facts = {
    ...store.facts,
    message: vi.fn((scope: { organizationId: bigint }, id: string) =>
      Promise.resolve(scope.organizationId === 1n && id === MESSAGE ? message : null),
    ),
    scan: vi.fn((_s: unknown, _m: unknown, id: bigint) =>
      Promise.resolve(id === 900n ? { ...round.scan, status: scanStatus } : null),
    ),
    roundRows: vi.fn(() => Promise.resolve(round.rows)),
    storedEvaluation: vi.fn(() => Promise.resolve(stored)),
  } as unknown as PolicyFactsRepository;
  const atoFacts = {
    current: vi.fn((_scope: unknown, _sender: string) =>
      Promise.resolve<Record<string, unknown> | null>(null),
    ),
  };
  const service = new PolicyEvaluationService(
    bounds,
    facts,
    metrics as unknown as PolicyMetrics,
    atoFacts as unknown as AtoPolicyFactsRepository,
  );
  return {
    store,
    policies,
    departments,
    service,
    atoFacts,
    metrics,
    round,
    message,
    setStored: (row: unknown) => (stored = row),
    setScanStatus: (s: string) => (scanStatus = s),
    writes: () => store.calls.filter((c) => /create|update|publish|delete|bump/i.test(c)),
  };
}

const codeOf = (p: Promise<unknown>) =>
  p.then(
    () => 'ok',
    (e: unknown) => (e instanceof CodedHttpException ? e.code : String(e)),
  );

describe('PolicyEvaluationService.test (P23)', () => {
  it('evaluates synthetic facts against the active, platform, version and inline targets', async () => {
    const ctx = setup();
    const { policy } = await ctx.policies.create(
      principal,
      SCOPE,
      { name: 'q', definition: quarantineDomainDefinition('bad.example') },
      client,
    );
    await ctx.policies.publish(
      principal,
      SCOPE,
      policy.id,
      1,
      { expectedRowVersion: 1, activate: true },
      client,
    );
    const writesBefore = ctx.writes().length;
    const facts = { sender: { envelope: 'x@bad.example' } };
    const active = await ctx.service.test(SCOPE, PolicyTestSchema.parse({ facts }));
    expect(active.result).toMatchObject({
      disposition: 'quarantine',
      decisive: { source: 'tenant_rule', policyPublicId: policy.id, ruleId: 'quarantine-domain' },
    });
    expect(active.result.versions.generation).toBe('1');
    const platform = await ctx.service.test(
      SCOPE,
      PolicyTestSchema.parse({ target: 'platform', facts }),
    );
    expect(platform.result).toMatchObject({
      disposition: 'allow',
      decisive: { source: 'platform_default' },
    });
    const inline = await ctx.service.test(
      SCOPE,
      PolicyTestSchema.parse({ target: { definition: tagAllDefinition('ext') }, facts: {} }),
    );
    expect(inline.result.actions.map((a) => a.type)).toContain('TAG');
    expect(ctx.writes().length).toBe(writesBefore);
    const draft = await ctx.policies.createDraft(
      principal,
      SCOPE,
      policy.id,
      { definition: quarantineDomainDefinition('other.example') },
      client,
    );
    const writesAfterDraft = ctx.writes().length;
    const version = await ctx.service.test(
      SCOPE,
      PolicyTestSchema.parse({
        target: { policyId: policy.id, versionNo: draft.versionNo },
        facts,
      }),
    );
    expect(version.result.disposition).toBe('allow');
    expect(
      await codeOf(
        ctx.service.test(
          SCOPE,
          PolicyTestSchema.parse({ target: { definition: { dslVersion: 'x' } }, facts: {} }),
        ),
      ),
    ).toBe('policy_definition_invalid');
    expect(
      await codeOf(
        ctx.service.test(
          systemScope(2n),
          PolicyTestSchema.parse({ target: { policyId: policy.id, versionNo: 1 }, facts: {} }),
        ),
      ),
    ).toBe('policy_version_not_found');
    // Defaults the evaluation time to the request time; writes nothing.
    const at = new Date('2026-11-11T12:34:56.789Z');
    const timed = await ctx.service.test(SCOPE, PolicyTestSchema.parse({}), at);
    expect(timed.result.round.trigger).toBe('scanned');
    expect(ctx.writes().length).toBe(writesAfterDraft);
    expect(ctx.metrics.dryRuns.inc).toHaveBeenCalledWith({ kind: 'test', result: 'ok' });
    expect(ctx.metrics.dryRuns.inc).toHaveBeenCalledWith({ kind: 'test', result: 'invalid' });
    expect(ctx.metrics.dryRuns.inc).toHaveBeenCalledWith({ kind: 'test', result: 'not_found' });
  });

  it('resolves department memberships from the directory with resolveDirectory', async () => {
    const ctx = setup();
    const dept = await ctx.departments.create(principal, SCOPE, { name: 'Finance' }, client);
    await ctx.departments.addMember(
      principal,
      SCOPE,
      dept.id,
      { address: 'alice@acme.example' },
      client,
    );
    const { policy } = await ctx.policies.create(
      principal,
      SCOPE,
      { name: 'd', definition: departmentExceptionDefinition(dept.id) },
      client,
    );
    await ctx.policies.publish(
      principal,
      SCOPE,
      policy.id,
      1,
      { expectedRowVersion: 1, activate: true },
      client,
    );
    const finance = await ctx.service.test(
      SCOPE,
      PolicyTestSchema.parse({
        facts: { recipients: [{ address: 'Alice@ACME.example' }], resolveDirectory: true },
      }),
    );
    expect(finance.result.disposition).toBe('allow');
    const mixed = await ctx.service.test(
      SCOPE,
      PolicyTestSchema.parse({
        facts: {
          recipients: [{ address: 'alice@acme.example' }, { address: 'bob@acme.example' }],
          resolveDirectory: true,
        },
      }),
    );
    expect(mixed.result.disposition).toBe('quarantine');
    const unresolved = await ctx.service.test(
      SCOPE,
      PolicyTestSchema.parse({ facts: { recipients: [{ address: 'alice@acme.example' }] } }),
    );
    expect(unresolved.result.disposition).toBe('quarantine');
  });
});

describe('dry-runs with ATO facts (step 8.4 D23, §5.3)', () => {
  const HIGH = {
    accountKnown: true,
    riskScore: 70,
    riskLevel: 'high',
    incidentSeverity: 'high',
    incidentStatus: 'open',
  };
  const holdHighRisk = {
    dslVersion: 'policy-dsl/1',
    direction: 'outbound',
    priority: 100,
    rules: [
      {
        id: 'ato-hold',
        priority: 10,
        when: { field: 'ato.risk_level', op: 'gte', value: 'high' },
        actions: [{ type: 'QUARANTINE' }],
      },
    ],
  };

  async function outboundWithPolicy() {
    const ctx = setup();
    // The round as outbound mail of the tenant (authenticated sender = the envelope sender).
    (ctx.message as { direction: string }).direction = 'outbound';
    const { policy } = await ctx.policies.create(
      principal,
      SCOPE,
      { name: 'ato', definition: holdHighRisk },
      client,
    );
    await ctx.policies.publish(
      principal,
      SCOPE,
      policy.id,
      1,
      { expectedRowVersion: 1, activate: true },
      client,
    );
    return ctx;
  }

  it('without a stored evaluation the current account state is read (atoFactsSource current)', async () => {
    const ctx = await outboundWithPolicy();
    ctx.atoFacts.current.mockResolvedValueOnce(HIGH);
    const res = await ctx.service.dryRun(SCOPE, MESSAGE, 900n, PolicyDryRunSchema.parse({}));
    expect(ctx.atoFacts.current).toHaveBeenCalledWith(SCOPE, 'sender@partner.example');
    expect(res.atoFactsSource).toBe('current');
    expect(res.result.disposition).toBe('quarantine');
    expect(res.stored).toBeNull();
    expect(res.reproducible).toBe(false);
  });

  it('with a stored evaluation its ato_facts block is reused (stored, reproducible), never the current state', async () => {
    const ctx = await outboundWithPolicy();
    const snapshot = compileSnapshot(
      snapshotSource(await ctx.store.facts.snapshot(SCOPE), 'pol-default/1', { kind: 'active' }),
    );
    const rows = policyRoundRowsOf(ctx.message, ctx.round.scan as never, ctx.round.rows, {
      departmentsByAddress: {},
      usersByAddress: {},
    });
    const input = buildPolicyInput({ ...rows, ato: HIGH });
    const result = evaluatePolicyPerRecipient(input, snapshot).message;
    const json = evaluationResultToRow(result);
    ctx.setStored({
      ...json,
      id: 1n,
      receivedAt: ctx.message.receivedAt,
      messageId: 77n,
      scanId: 900n,
      policyGeneration: BigInt(json.policyGeneration),
      durationUs: 300,
      evaluatedAt: new Date('2026-11-11T08:00:06.000Z'),
      atoFacts: input.ato,
    });
    // The account state changed since: the stored facts still decide.
    ctx.atoFacts.current.mockResolvedValue({ ...HIGH, riskScore: 5, riskLevel: 'low' });
    const res = await ctx.service.dryRun(SCOPE, MESSAGE, 900n, PolicyDryRunSchema.parse({}));
    expect(ctx.atoFacts.current).not.toHaveBeenCalled();
    expect(res.atoFactsSource).toBe('stored');
    expect(res.result.disposition).toBe('quarantine');
    expect(res.reproducible).toBe(true);
    expect(res.stored?.atoFacts).toEqual({ version: 'ato-policy-facts/1', ...HIGH });

    // A stored evaluation without facts: absent (none), reproducible, allowed.
    const plainInput = buildPolicyInput(rows);
    const plain = evaluatePolicyPerRecipient(plainInput, snapshot).message;
    const plainJson = evaluationResultToRow(plain);
    ctx.setStored({
      ...plainJson,
      id: 2n,
      receivedAt: ctx.message.receivedAt,
      messageId: 77n,
      scanId: 900n,
      policyGeneration: BigInt(plainJson.policyGeneration),
      durationUs: 300,
      evaluatedAt: new Date('2026-11-11T08:00:06.000Z'),
      atoFacts: null,
    });
    const none = await ctx.service.dryRun(SCOPE, MESSAGE, 900n, PolicyDryRunSchema.parse({}));
    expect(none.atoFactsSource).toBe('none');
    expect(none.result.disposition).toBe('allow');
    expect(none.reproducible).toBe(true);
    expect(none.stored?.atoFacts).toBeNull();
  });

  it('inbound rounds never read ATO facts (none)', async () => {
    const ctx = setup();
    ctx.atoFacts.current.mockResolvedValue(HIGH);
    const res = await ctx.service.dryRun(SCOPE, MESSAGE, 900n, PolicyDryRunSchema.parse({}));
    expect(ctx.atoFacts.current).not.toHaveBeenCalled();
    expect(res.atoFactsSource).toBe('none');
  });

  it('a malformed stored block is policy_input_invalid', async () => {
    const ctx = await outboundWithPolicy();
    ctx.setStored({ id: 3n, atoFacts: { version: 'ato-policy-facts/1', riskScore: 900 } });
    expect(
      await codeOf(ctx.service.dryRun(SCOPE, MESSAGE, 900n, PolicyDryRunSchema.parse({}))),
    ).toBe('policy_input_invalid');
  });

  it('POST /policies/test accepts synthetic ATO facts', async () => {
    const ctx = await outboundWithPolicy();
    const res = await ctx.service.test(
      SCOPE,
      PolicyTestSchema.parse({
        facts: {
          direction: 'outbound',
          sender: { envelope: 'ceo@acme.example' },
          ato: { riskScore: 80, riskLevel: 'critical' },
        },
      }),
    );
    expect(res.result.disposition).toBe('quarantine');
    const low = await ctx.service.test(
      SCOPE,
      PolicyTestSchema.parse({
        facts: {
          direction: 'outbound',
          sender: { envelope: 'ceo@acme.example' },
          ato: { riskScore: 10, riskLevel: 'low' },
        },
      }),
    );
    expect(low.result.disposition).toBe('allow');
  });
});

describe('PolicyEvaluationService.dryRun (P8, P22)', () => {
  it('reproduces a stored evaluation built from the same rows (target active) and writes nothing', async () => {
    const ctx = setup();
    const dept = await ctx.departments.create(principal, SCOPE, { name: 'Finance' }, client);
    await ctx.departments.addMember(
      principal,
      SCOPE,
      dept.id,
      { address: 'alice@acme.example' },
      client,
    );
    const { policy } = await ctx.policies.create(
      principal,
      SCOPE,
      { name: 'd', definition: departmentExceptionDefinition(dept.id) },
      client,
    );
    await ctx.policies.publish(
      principal,
      SCOPE,
      policy.id,
      1,
      { expectedRowVersion: 1, activate: true },
      client,
    );
    // The stored row as the engine writes it: the same rows, the same snapshot, the directory.
    const snapshot = compileSnapshot(
      snapshotSource(await ctx.store.facts.snapshot(SCOPE), 'pol-default/1', { kind: 'active' }),
    );
    const directory = directoryMaps(
      await ctx.store.facts.directory(SCOPE, roundAddresses(ctx.message, ctx.round.rows), {
        departmentIds: [dept.id],
        userIds: [],
      }),
    );
    // Step 5.3 (Q4): the engine evaluates per recipient; the row keeps the message-level record.
    const perRecipient = evaluatePolicyPerRecipient(
      buildPolicyInput(
        policyRoundRowsOf(ctx.message, ctx.round.scan as never, ctx.round.rows, directory),
      ),
      snapshot,
    );
    const result = perRecipient.message;
    // Bob is not in Finance: the exception (quantifier all) does not apply.
    expect(result.disposition).toBe('quarantine');
    const json = evaluationResultToRow(result);
    ctx.setStored({
      ...json,
      id: 1n,
      receivedAt: ctx.message.receivedAt,
      messageId: 77n,
      scanId: 900n,
      policyGeneration: BigInt(json.policyGeneration),
      durationUs: 300,
      evaluatedAt: new Date('2026-11-11T08:00:06.000Z'),
    });
    const before = ctx.store.calls.length;
    const res = await ctx.service.dryRun(SCOPE, MESSAGE, 900n, PolicyDryRunSchema.parse({}));
    expect(res.reproducible).toBe(true);
    expect(res.result).toEqual(result);
    expect(res.recipientSplit).toBe(perRecipient.split);
    expect(res.recipientDecisions).toEqual(perRecipient.recipientDecisions);
    expect(res.lifecycleDisposition).toBe(perRecipient.lifecycleDisposition);
    expect(res.stored).toMatchObject({
      disposition: 'quarantine',
      lifecycleRound: 0,
      durationUs: 300,
    });
    expect(ctx.store.calls.slice(before).every((c) => c === 'snapshot')).toBe(true);
    // Platform target: same input, another snapshot → not reproducible.
    const platform = await ctx.service.dryRun(
      SCOPE,
      MESSAGE,
      900n,
      PolicyDryRunSchema.parse({ target: 'platform' }),
    );
    expect(platform.reproducible).toBe(false);
    // A membership change makes the active dry-run differ (input hash).
    await ctx.departments.addMember(
      principal,
      SCOPE,
      dept.id,
      { address: 'bob@acme.example' },
      client,
    );
    const after = await ctx.service.dryRun(SCOPE, MESSAGE, 900n, PolicyDryRunSchema.parse({}));
    expect(after.reproducible).toBe(false);
    expect(after.result.disposition).toBe('allow');
  });

  it('answers 404 and 409 with the dry-run metric labels', async () => {
    const ctx = setup();
    expect(
      await codeOf(
        ctx.service.dryRun(systemScope(2n), MESSAGE, 900n, PolicyDryRunSchema.parse({})),
      ),
    ).toBe('message_not_found');
    expect(
      await codeOf(ctx.service.dryRun(SCOPE, MESSAGE, 901n, PolicyDryRunSchema.parse({}))),
    ).toBe('scan_not_found');
    ctx.setScanStatus('running');
    expect(
      await codeOf(ctx.service.dryRun(SCOPE, MESSAGE, 900n, PolicyDryRunSchema.parse({}))),
    ).toBe('scan_round_not_complete');
    expect(ctx.metrics.dryRuns.inc).toHaveBeenCalledWith({ kind: 'message', result: 'not_found' });
    expect(ctx.metrics.dryRuns.inc).toHaveBeenCalledWith({
      kind: 'message',
      result: 'not_complete',
    });
    ctx.setScanStatus('completed');
    const ok = await ctx.service.dryRun(SCOPE, MESSAGE, 900n, PolicyDryRunSchema.parse({}));
    expect(ok.stored).toBeNull();
    expect(ok.reproducible).toBe(false);
    expect(ok.result.decisive.source).toBe('platform_default');
  });
});
