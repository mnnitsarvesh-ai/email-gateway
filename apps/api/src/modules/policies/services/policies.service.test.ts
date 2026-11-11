import { describe, expect, it, vi } from 'vitest';
import {
  departmentExceptionDefinition,
  overrideDefinition,
  quarantineDomainDefinition,
  tagAllDefinition,
} from '../../../../test/support/policy-fixtures';
import { InMemoryPolicies } from '../../../../test/support/in-memory-policies';
import type { Principal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../../database/transaction-runner';
import { CodedHttpException } from '../../../http/coded-exception';
import { DepartmentsService } from '../../directory/services/departments.service';
import { PoliciesService } from './policies.service';
import { POLICY_TX, type PolicyAuditor, type PolicyMetrics, PolicyWriter } from './policy-writer';

const SCOPE = systemScope(1n);
const OTHER = systemScope(2n);
const principal = { kind: 'user', userId: 10n } as unknown as Principal;
const client = { ip: '203.0.113.9', userAgent: null } as never;
const bounds = {
  POLICY_PLATFORM_DEFAULT: 'pol-default/1',
  POLICY_MAX_POLICIES: 10,
  POLICY_MAX_VERSIONS_PER_POLICY: 10,
  POLICY_MAX_ACTIVE_RULES: 100,
  POLICY_HISTORY_MAX_RANGE_DAYS: 31,
  DEPARTMENT_MAX_PER_ORG: 10,
  DEPARTMENT_MAX_MEMBERS: 100,
};

function setup(overrides: Partial<typeof bounds> = {}) {
  const store = new InMemoryPolicies();
  store.addUser(10n, { organizationId: 1n });
  const audit = {
    record: vi.fn((_tx: unknown, _entry: Record<string, unknown>) => Promise.resolve()),
  };
  const metrics = { changes: { inc: vi.fn() }, dryRuns: { inc: vi.fn() } };
  const writer = new PolicyWriter(store.transactions as unknown as TransactionRunner);
  const settings = { ...bounds, ...overrides };
  const service = new PoliciesService(
    settings,
    store.repository,
    writer,
    audit as unknown as PolicyAuditor,
    metrics as unknown as PolicyMetrics,
  );
  const departments = new DepartmentsService(
    settings,
    store.departments,
    store.repository,
    writer,
    audit as unknown as PolicyAuditor,
    metrics as unknown as PolicyMetrics,
  );
  const actions = () => audit.record.mock.calls.map(([, e]) => e.action as string);
  const metadataOf = (action: string) =>
    audit.record.mock.calls.map(([, e]) => e).filter((e) => e.action === action);
  return { store, service, departments, audit, metrics, actions, metadataOf };
}

const codeOf = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
  } catch (error) {
    if (error instanceof CodedHttpException) return error.code;
    throw error;
  }
  throw new Error('expected a coded error');
};

async function createPolicy(
  ctx: ReturnType<typeof setup>,
  name = 'Block bad domain',
  definition: object = quarantineDomainDefinition(),
) {
  return ctx.service.create(principal, SCOPE, { name, definition } as never, client);
}

describe('PoliciesService: lifecycle (P17)', () => {
  it('creates a draft policy with version 1 and never changes the generation for drafts', async () => {
    const ctx = setup();
    const created = await createPolicy(ctx);
    expect(created.policy).toMatchObject({
      status: 'draft',
      direction: 'inbound',
      priority: 100,
      activeVersionNo: null,
      latestVersionNo: 1,
      counts: { drafts: 1, published: 0 },
    });
    expect(created.version).toMatchObject({ versionNo: 1, status: 'draft', rowVersion: 1 });
    expect(ctx.store.generationOf(1n)).toBe(0n);
    expect(ctx.actions()).toEqual(['policy.created']);
    expect(ctx.store.txOptions[0]).toEqual(POLICY_TX);
    const meta = ctx.metadataOf('policy.created')[0]!.metadata as Record<string, unknown>;
    expect(Object.keys(meta).sort()).toEqual(
      [
        'definitionSha256',
        'hasOverrideRules',
        'policyId',
        'ruleCount',
        'rowVersion',
        'versionNo',
      ].sort(),
    );
    expect(JSON.stringify(meta)).not.toContain('bad.example');
  });

  it('publishes and activates once, numbers versions MAX+1 and rolls back by activation', async () => {
    const ctx = setup();
    const { policy } = await createPolicy(ctx);
    const published = await ctx.service.publish(
      principal,
      SCOPE,
      policy.id,
      1,
      { expectedRowVersion: 1, activate: true },
      client,
    );
    expect(published.generation).toBe('1');
    expect(published.policy).toMatchObject({ status: 'active', activeVersionNo: 1 });
    expect(published.version).toMatchObject({ status: 'published', active: true });
    expect(ctx.actions()).toEqual([
      'policy.created',
      'policy.version_published',
      'policy.version_activated',
    ]);

    const v2 = await ctx.service.createDraft(
      principal,
      SCOPE,
      policy.id,
      { basedOnVersionNo: 1 },
      client,
    );
    expect(v2.versionNo).toBe(2);
    await ctx.service.updateDraft(
      principal,
      SCOPE,
      policy.id,
      2,
      { definition: quarantineDomainDefinition('worse.example'), expectedRowVersion: 1 },
      client,
    );
    const p2 = await ctx.service.publish(
      principal,
      SCOPE,
      policy.id,
      2,
      { expectedRowVersion: 2, activate: true },
      client,
    );
    expect(p2.generation).toBe('2');
    // Rollback to v1: one generation change; activating it again changes nothing.
    const back = await ctx.service.activate(principal, SCOPE, policy.id, 1, {}, client);
    expect(back.generation).toBe('3');
    expect(back.policy.activeVersionNo).toBe(1);
    const again = await ctx.service.activate(principal, SCOPE, policy.id, 1, {}, client);
    expect(again.generation).toBe('3');
    expect(ctx.metadataOf('policy.version_activated').at(-1)!.metadata).toMatchObject({
      versionNo: 1,
      previousVersionNo: 2,
    });
    expect(ctx.metadataOf('policy.version_activated')).toHaveLength(3);
  });

  it('keeps published versions immutable and drafts compare-and-set', async () => {
    const ctx = setup();
    const { policy } = await createPolicy(ctx);
    expect(
      await codeOf(
        ctx.service.updateDraft(
          principal,
          SCOPE,
          policy.id,
          1,
          { definition: tagAllDefinition(), expectedRowVersion: 7 },
          client,
        ),
      ),
    ).toBe('policy_conflict');
    await ctx.service.publish(
      principal,
      SCOPE,
      policy.id,
      1,
      { expectedRowVersion: 1, activate: false },
      client,
    );
    expect(ctx.store.generationOf(1n)).toBe(0n);
    expect(
      await codeOf(
        ctx.service.updateDraft(
          principal,
          SCOPE,
          policy.id,
          1,
          { definition: tagAllDefinition(), expectedRowVersion: 2 },
          client,
        ),
      ),
    ).toBe('policy_version_immutable');
    expect(
      await codeOf(ctx.service.deleteDraft(principal, SCOPE, policy.id, 1, undefined, client)),
    ).toBe('policy_version_immutable');
    expect(
      await codeOf(
        ctx.service.publish(
          principal,
          SCOPE,
          policy.id,
          1,
          { expectedRowVersion: 2, activate: true },
          client,
        ),
      ),
    ).toBe('policy_version_immutable');
    // The repository's own guard matches no published row.
    const v = ctx.store.versions[0]!;
    expect(
      await ctx.store.repository.updateDraft(
        {} as never,
        SCOPE,
        v.id,
        v.rowVersion,
        { ...(v as unknown as object), changeNote: null } as never,
        null,
      ),
    ).toBe(false);
    expect(await ctx.store.repository.deleteDraft({} as never, SCOPE, v.id, undefined)).toBe(false);
  });

  it('enables, disables and deletes with exactly one generation change each', async () => {
    const ctx = setup();
    const { policy } = await createPolicy(ctx);
    expect(await codeOf(ctx.service.enable(principal, SCOPE, policy.id, {}, client))).toBe(
      'policy_no_active_version',
    );
    // Disabling a never-activated policy changes nothing.
    await ctx.service.disable(principal, SCOPE, policy.id, {}, client);
    expect(ctx.store.generationOf(1n)).toBe(0n);
    await ctx.service.publish(
      principal,
      SCOPE,
      policy.id,
      1,
      { expectedRowVersion: 1, activate: true },
      client,
    );
    const disabled = await ctx.service.disable(principal, SCOPE, policy.id, {}, client);
    expect(disabled.status).toBe('disabled');
    expect(ctx.store.generationOf(1n)).toBe(2n);
    await ctx.service.disable(principal, SCOPE, policy.id, {}, client);
    expect(ctx.store.generationOf(1n)).toBe(2n);
    const enabled = await ctx.service.enable(principal, SCOPE, policy.id, {}, client);
    expect(enabled.status).toBe('active');
    expect(ctx.store.generationOf(1n)).toBe(3n);
    expect(await codeOf(ctx.service.remove(principal, SCOPE, policy.id, 1, client))).toBe(
      'policy_conflict',
    );
    await ctx.service.remove(principal, SCOPE, policy.id, undefined, client);
    expect(ctx.store.generationOf(1n)).toBe(4n);
    expect(ctx.store.policies[0]).toMatchObject({ status: 'archived' });
    expect(await codeOf(ctx.service.get(SCOPE, policy.id))).toBe('policy_not_found');
    expect(ctx.actions().filter((a) => a.startsWith('policy.'))).toEqual([
      'policy.created',
      'policy.version_published',
      'policy.version_activated',
      'policy.disabled',
      'policy.enabled',
      'policy.deleted',
    ]);
    // The name stays taken by the archived policy.
    expect(await codeOf(createPolicy(ctx))).toBe('policy_name_taken');
  });

  it('enforces the policy, version and active-rule bounds', async () => {
    const ctx = setup({ POLICY_MAX_POLICIES: 10, POLICY_MAX_VERSIONS_PER_POLICY: 10 });
    for (let i = 0; i < 10; i += 1) await createPolicy(ctx, `p${i}`);
    expect(await codeOf(createPolicy(ctx, 'one too many'))).toBe('policy_limit_reached');
    const first = ctx.store.policies[0]!.publicId;
    for (let i = 2; i <= 10; i += 1) {
      await ctx.service.createDraft(principal, SCOPE, first, { basedOnVersionNo: 1 }, client);
    }
    expect(
      await codeOf(
        ctx.service.createDraft(principal, SCOPE, first, { basedOnVersionNo: 1 }, client),
      ),
    ).toBe('policy_version_limit_reached');

    const small = setup({ POLICY_MAX_ACTIVE_RULES: 100 });
    const many = {
      ...tagAllDefinition(),
      rules: Array.from({ length: 60 }, (_, i) => ({
        id: `r${i}`,
        priority: i,
        when: { field: 'direction', op: 'equals', value: 'inbound' },
        actions: [{ type: 'TAG', label: 'x' }],
      })),
    };
    const a = await createPolicy(small, 'a', many);
    const b = await createPolicy(small, 'b', many);
    await small.service.publish(
      principal,
      SCOPE,
      a.policy.id,
      1,
      { expectedRowVersion: 1, activate: true },
      client,
    );
    expect(
      await codeOf(
        small.service.publish(
          principal,
          SCOPE,
          b.policy.id,
          1,
          { expectedRowVersion: 1, activate: true },
          client,
        ),
      ),
    ).toBe('policy_rule_limit_reached');
    // Publish and activation are one transaction: the draft stays a draft.
    expect(
      small.store.versions.find((v) => v.policyId === small.store.policies[1]!.id)!.status,
    ).toBe('draft');
  });

  it('refuses invalid definitions with violations and unknown departments at publish', async () => {
    const ctx = setup();
    const error = await ctx.service
      .create(principal, SCOPE, { name: 'x', definition: { dslVersion: 'nope' } }, client)
      .catch((e: unknown) => e as CodedHttpException);
    expect(error).toBeInstanceOf(CodedHttpException);
    expect((error as CodedHttpException).code).toBe('policy_definition_invalid');
    expect((error as CodedHttpException).details.violations).not.toHaveLength(0);
    const dept = '0190f0f0-0000-7000-8000-00000000d0d0';
    const { policy } = await createPolicy(ctx, 'dept', departmentExceptionDefinition(dept));
    expect(
      await codeOf(
        ctx.service.publish(
          principal,
          SCOPE,
          policy.id,
          1,
          { expectedRowVersion: 1, activate: true },
          client,
        ),
      ),
    ).toBe('policy_definition_invalid');
    const created = await ctx.departments.create(principal, SCOPE, { name: 'Finance' }, client);
    const { policy: p2 } = await createPolicy(
      ctx,
      'dept2',
      departmentExceptionDefinition(created.id),
    );
    await ctx.service.publish(
      principal,
      SCOPE,
      p2.id,
      1,
      { expectedRowVersion: 1, activate: true },
      client,
    );
    expect(
      await codeOf(ctx.departments.remove(principal, SCOPE, created.id, undefined, client)),
    ).toBe('department_in_use');
    await ctx.service.disable(principal, SCOPE, p2.id, {}, client);
    await ctx.departments.remove(principal, SCOPE, created.id, undefined, client);
    // Re-enabling re-checks the references.
    expect(await codeOf(ctx.service.enable(principal, SCOPE, p2.id, {}, client))).toBe(
      'policy_definition_invalid',
    );
  });

  it('audits override rules and turning overrides on; identical settings change nothing', async () => {
    const ctx = setup();
    const { policy } = await createPolicy(ctx, 'override', overrideDefinition());
    await ctx.service.publish(
      principal,
      SCOPE,
      policy.id,
      1,
      { expectedRowVersion: 1, activate: true },
      client,
    );
    expect(ctx.metadataOf('policy.override_rules_published')[0]!.metadata).toMatchObject({
      overrideRuleIds: ['trusted-partner'],
    });
    const before = ctx.store.generationOf(1n);
    expect(
      await codeOf(
        ctx.service.putSettings(principal, SCOPE, { settings: {}, expectedRowVersion: 5 }, client),
      ),
    ).toBe('policy_conflict');
    expect(
      await codeOf(
        ctx.service.putSettings(
          principal,
          SCOPE,
          { settings: { bad: true }, expectedRowVersion: 0 },
          client,
        ),
      ),
    ).toBe('policy_settings_invalid');
    const same = await ctx.service.putSettings(
      principal,
      SCOPE,
      { settings: {}, expectedRowVersion: 0 },
      client,
    );
    expect(same.generation).toBe(before.toString());
    const on = await ctx.service.putSettings(
      principal,
      SCOPE,
      { settings: { allowRecommendationOverrides: true }, expectedRowVersion: 1 },
      client,
    );
    expect(on).toMatchObject({ rowVersion: 2, effective: { allowRecommendationOverrides: true } });
    expect(BigInt(on.generation)).toBe(before + 1n);
    expect(ctx.actions().slice(-2)).toEqual([
      'policy.settings_updated',
      'policy.settings_overrides_enabled',
    ]);
    expect(ctx.metadataOf('policy.settings_updated')[0]!.metadata).toMatchObject({
      changedPaths: ['allowRecommendationOverrides'],
    });
  });

  it('isolates organizations and retries an inconsistent writer read once', async () => {
    const ctx = setup();
    const { policy } = await createPolicy(ctx);
    expect(await codeOf(ctx.service.get(OTHER, policy.id))).toBe('policy_not_found');
    expect(
      await codeOf(
        ctx.service.publish(
          principal,
          OTHER,
          policy.id,
          1,
          { expectedRowVersion: 1, activate: true },
          client,
        ),
      ),
    ).toBe('policy_not_found');
    ctx.store.injectWrongRead = 'email_policy';
    const ok = await ctx.service.publish(
      principal,
      SCOPE,
      policy.id,
      1,
      { expectedRowVersion: 1, activate: true },
      client,
    );
    expect(ok.generation).toBe('1');
    expect(ctx.store.txOptions.length).toBeGreaterThanOrEqual(3);
  });

  it('follows the newest draft for direction and priority until the first activation', async () => {
    const ctx = setup();
    const { policy } = await createPolicy(ctx);
    await ctx.service.createDraft(
      principal,
      SCOPE,
      policy.id,
      { definition: tagAllDefinition('x', 300) },
      client,
    );
    expect((await ctx.service.get(SCOPE, policy.id)).priority).toBe(300);
    await ctx.service.publish(
      principal,
      SCOPE,
      policy.id,
      1,
      { expectedRowVersion: 1, activate: true },
      client,
    );
    expect((await ctx.service.get(SCOPE, policy.id)).priority).toBe(100);
  });
});

describe('DepartmentsService (P5)', () => {
  it('manages departments and members with tenant checks and audit ids only', async () => {
    const ctx = setup();
    ctx.store.activeDomains.add('1:acme.example');
    ctx.store.addUser(11n, { organizationId: 1n, email: 'cfo@acme.example' });
    const foreignUser = ctx.store.addUser(21n, { organizationId: 2n });
    const d = await ctx.departments.create(principal, SCOPE, { name: 'Finance' }, client);
    expect(
      await codeOf(ctx.departments.create(principal, SCOPE, { name: 'Finance' }, client)),
    ).toBe('department_name_taken');
    const m = await ctx.departments.addMember(
      principal,
      SCOPE,
      d.id,
      { address: '  Alice@ACME.example ' },
      client,
    );
    expect(m).toMatchObject({ kind: 'address', address: 'alice@acme.example', userId: null });
    expect(
      await codeOf(
        ctx.departments.addMember(
          principal,
          SCOPE,
          d.id,
          { address: 'alice@acme.example' },
          client,
        ),
      ),
    ).toBe('department_member_exists');
    expect(
      await codeOf(
        ctx.departments.addMember(principal, SCOPE, d.id, { address: 'x@other.example' }, client),
      ),
    ).toBe('member_address_not_tenant');
    expect(
      await codeOf(
        ctx.departments.addMember(principal, SCOPE, d.id, { userId: foreignUser.publicId }, client),
      ),
    ).toBe('member_user_not_tenant');
    const u = await ctx.departments.addMember(
      principal,
      SCOPE,
      d.id,
      { userId: ctx.store.users.get(11n)!.publicId },
      client,
    );
    expect(u.kind).toBe('user');
    expect((await ctx.departments.get(SCOPE, d.id)).memberCount).toBe(2);
    expect(await codeOf(ctx.departments.get(OTHER, d.id))).toBe('department_not_found');
    await ctx.departments.removeMember(principal, SCOPE, d.id, m.id, client);
    expect(await codeOf(ctx.departments.removeMember(principal, SCOPE, d.id, m.id, client))).toBe(
      'department_member_not_found',
    );
    const updated = await ctx.departments.update(
      principal,
      SCOPE,
      d.id,
      { name: 'Finance EU', expectedRowVersion: 1 },
      client,
    );
    expect(updated.rowVersion).toBe(2);
    expect(
      await codeOf(
        ctx.departments.update(
          principal,
          SCOPE,
          d.id,
          { name: 'x', expectedRowVersion: 1 },
          client,
        ),
      ),
    ).toBe('department_conflict');
    await ctx.departments.remove(principal, SCOPE, d.id, undefined, client);
    expect(ctx.store.memberRows).toHaveLength(0);
    expect(ctx.actions()).toEqual([
      'department.created',
      'department.member_added',
      'department.member_added',
      'department.member_removed',
      'department.updated',
      'department.deleted',
    ]);
    expect(JSON.stringify(ctx.audit.record.mock.calls.map(([, e]) => e.metadata))).not.toContain(
      'alice@',
    );
    // Membership changes never change the generation (live data).
    expect(ctx.store.generationOf(1n)).toBe(0n);
  });

  it('caps departments and members', async () => {
    const ctx = setup({ DEPARTMENT_MAX_PER_ORG: 10, DEPARTMENT_MAX_MEMBERS: 100 });
    for (let i = 0; i < 10; i += 1) {
      await ctx.departments.create(principal, SCOPE, { name: `d${i}` }, client);
    }
    expect(await codeOf(ctx.departments.create(principal, SCOPE, { name: 'd10' }, client))).toBe(
      'department_limit_reached',
    );
    ctx.store.activeDomains.add('1:acme.example');
    const d = ctx.store.departmentRows[0]!.publicId;
    for (let i = 0; i < 100; i += 1) {
      await ctx.departments.addMember(
        principal,
        SCOPE,
        d,
        { address: `m${i}@acme.example` },
        client,
      );
    }
    expect(
      await codeOf(
        ctx.departments.addMember(principal, SCOPE, d, { address: 'x@acme.example' }, client),
      ),
    ).toBe('department_member_limit_reached');
  });
});
