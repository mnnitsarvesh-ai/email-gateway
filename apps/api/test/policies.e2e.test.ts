/**
 * Step 5.2 policy routes (P11, P16, P17, P22, P23) over HTTP with MySQL, Redis and S3 stubbed:
 * the real controllers, validation, guards, services and writer run against an in-memory store
 * with the repository semantics (tenant filter, settings lock, draft-only updates with row-version
 * compare-and-set, the policy CAS, generation increments, transaction rollback). Covered:
 * authorization per route (read-only, manage-only, publish), the draft → publish → activate →
 * rollback → disable → enable → delete lifecycle with its audit rows and generation, validation
 * errors by path, immutability, CAS conflicts, limits, isolation between two organizations, the
 * catalog, the test endpoint, the message dry-run (reproducible, writes nothing), the history
 * query validation and the message evaluations. The same routes run against the real MySQL
 * writer and replica in integration/policies.test.ts.
 */
import { randomUUID } from 'node:crypto';
import {
  buildPolicyInput,
  compileSnapshot,
  evaluatePolicy,
  evaluationResultToRow,
} from '@email-gateway/policy-dsl';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { policyRoundRowsOf, snapshotSource } from '../src/modules/policies/domain/policy-round';
import { createPolicyApp, MESSAGE_ID, type PolicyApp, roleOf, SCAN } from './support/policy-app';
import { quarantineDomainDefinition, tagAllDefinition } from './support/policy-fixtures';

const READ_ONLY = roleOf('read_only_user');
const ANALYST = roleOf('security_analyst');
const ADMIN = roleOf('organization_admin');
const P = '/api/v1/policies';
const dryRunUrl = `/api/v1/messages/${MESSAGE_ID}/scans/${SCAN}/policy/dry-run`;

describe('step 5.2 policy routes (e2e, dependencies stubbed)', () => {
  let ctx: PolicyApp;
  const http = () => ctx.http();

  beforeAll(async () => {
    ctx = await createPolicyApp({
      POLICY_MAX_POLICIES: '10',
      POLICY_MAX_VERSIONS_PER_POLICY: '10',
    });
  });
  afterAll(async () => {
    await ctx?.close();
  });
  beforeEach(() => ctx.reset());

  const create = (
    auth: Record<string, string>,
    name = 'Block bad domain',
    definition: object = quarantineDomainDefinition(),
  ) => http().post(P).set(auth).send({ name, definition, changeNote: 'first' });

  it('answers 401 without credentials on every route', async () => {
    const id = randomUUID();
    const routes: Array<[string, string]> = [
      ['get', `${P}/catalog`],
      ['get', P],
      ['post', P],
      ['get', `${P}/${id}`],
      ['patch', `${P}/${id}`],
      ['post', `${P}/${id}/disable`],
      ['post', `${P}/${id}/enable`],
      ['delete', `${P}/${id}`],
      ['get', `${P}/${id}/versions`],
      ['post', `${P}/${id}/versions`],
      ['get', `${P}/${id}/versions/1`],
      ['put', `${P}/${id}/versions/1`],
      ['delete', `${P}/${id}/versions/1`],
      ['post', `${P}/${id}/versions/1/publish`],
      ['post', `${P}/${id}/versions/1/activate`],
      ['get', '/api/v1/policy-settings'],
      ['put', '/api/v1/policy-settings'],
      ['post', `${P}/test`],
      ['get', `${P}/executions`],
      ['post', dryRunUrl],
      ['get', `/api/v1/messages/${MESSAGE_ID}/policy-evaluations`],
    ];
    for (const [method, url] of routes) {
      await (
        http() as unknown as Record<
          string,
          (u: string) => { expect: (s: number) => Promise<unknown> }
        >
      )[method]!(url).expect(401);
    }
  });

  it('serves the catalog to policy:read and refuses it without', async () => {
    const res = await http()
      .get(`${P}/catalog`)
      .set(await ctx.as(READ_ONLY))
      .expect(200);
    expect(res.body.versions.dsl).toBe('policy-dsl/1');
    expect(res.body.limits.policiesPerOrganization).toBe(10);
    expect(res.body.fields.length).toBeGreaterThan(50);
    expect(res.body.enforcement).toContain('step 8.1');
    await http()
      .get(`${P}/catalog`)
      .set(await ctx.as(['message:read']))
      .expect(403);
  });

  it('runs the lifecycle with RBAC, audit rows and one generation change per effective change', async () => {
    await create(await ctx.as(READ_ONLY)).expect(403);
    const created = await create(await ctx.as(ANALYST)).expect(201);
    expect(created.body.policy).toMatchObject({
      status: 'draft',
      latestVersionNo: 1,
      rowVersion: 1,
    });
    expect(created.body.version).toMatchObject({
      versionNo: 1,
      status: 'draft',
      changeNote: 'first',
    });
    const id = created.body.policy.id as string;
    // policy:manage cannot publish, activate, enable, disable, delete or change settings.
    await http()
      .post(`${P}/${id}/versions/1/publish`)
      .set(await ctx.as(ANALYST))
      .send({ expectedRowVersion: 1 })
      .expect(403);
    await http()
      .post(`${P}/${id}/versions/1/activate`)
      .set(await ctx.as(ANALYST))
      .send({})
      .expect(403);
    await http()
      .post(`${P}/${id}/disable`)
      .set(await ctx.as(ANALYST))
      .send({})
      .expect(403);
    await http()
      .delete(`${P}/${id}`)
      .set(await ctx.as(ANALYST))
      .expect(403);
    await http()
      .put('/api/v1/policy-settings')
      .set(await ctx.as(ANALYST))
      .send({ settings: {}, expectedRowVersion: 0 })
      .expect(403);
    const published = await http()
      .post(`${P}/${id}/versions/1/publish`)
      .set(await ctx.as(ADMIN))
      .send({ expectedRowVersion: 1 })
      .expect(200);
    expect(published.body).toMatchObject({
      generation: '1',
      policy: { status: 'active', activeVersionNo: 1 },
      version: { status: 'published', active: true },
    });
    expect(published.body.version.definitionSha256).toMatch(/^[0-9a-f]{64}$/);
    // Immutable afterwards.
    const put = await http()
      .put(`${P}/${id}/versions/1`)
      .set(await ctx.as(ADMIN))
      .send({ definition: tagAllDefinition(), expectedRowVersion: 2 })
      .expect(409);
    expect(put.body.code).toBe('policy_version_immutable');
    await http()
      .delete(`${P}/${id}/versions/1`)
      .set(await ctx.as(ADMIN))
      .expect(409);

    // A second version, rollback, no-op activation.
    const v2 = await http()
      .post(`${P}/${id}/versions`)
      .set(await ctx.as(ANALYST))
      .send({ definition: quarantineDomainDefinition('worse.example') })
      .expect(201);
    expect(v2.body.versionNo).toBe(2);
    const stale = await http()
      .put(`${P}/${id}/versions/2`)
      .set(await ctx.as(ANALYST))
      .send({ definition: tagAllDefinition(), expectedRowVersion: 9 })
      .expect(409);
    expect(stale.body).toMatchObject({ code: 'policy_conflict', currentRowVersion: 1 });
    await http()
      .post(`${P}/${id}/versions/2/activate`)
      .set(await ctx.as(ADMIN))
      .send({})
      .expect(409)
      .expect((res) => expect(res.body.code).toBe('policy_version_not_published'));
    await http()
      .post(`${P}/${id}/versions/2/publish`)
      .set(await ctx.as(ADMIN))
      .send({ expectedRowVersion: 1 })
      .expect(200);
    const back = await http()
      .post(`${P}/${id}/versions/1/activate`)
      .set(await ctx.as(ADMIN))
      .send({})
      .expect(200);
    expect(back.body.generation).toBe('3');
    const same = await http()
      .post(`${P}/${id}/versions/1/activate`)
      .set(await ctx.as(ADMIN))
      .send({})
      .expect(200);
    expect(same.body.generation).toBe('3');

    const disabled = await http()
      .post(`${P}/${id}/disable`)
      .set(await ctx.as(ADMIN))
      .send({})
      .expect(200);
    expect(disabled.body.status).toBe('disabled');
    await http()
      .post(`${P}/${id}/enable`)
      .set(await ctx.as(ADMIN))
      .send({})
      .expect(200);
    const list = await http()
      .get(P)
      .set(await ctx.as(READ_ONLY))
      .expect(200);
    expect(list.body).toMatchObject({ generation: '5', nextCursor: null });
    expect(list.body.data).toHaveLength(1);
    const versions = await http()
      .get(`${P}/${id}/versions`)
      .set(await ctx.as(READ_ONLY))
      .expect(200);
    expect(versions.body.data.map((v: { versionNo: number }) => v.versionNo)).toEqual([2, 1]);
    const detail = await http()
      .get(`${P}/${id}/versions/1`)
      .set(await ctx.as(READ_ONLY))
      .expect(200);
    expect(detail.body).toMatchObject({
      validation: { valid: true },
      definition: { dslVersion: 'policy-dsl/1' },
    });
    await http()
      .patch(`${P}/${id}`)
      .set(await ctx.as(ADMIN))
      .send({ name: 'Renamed', expectedRowVersion: 1 })
      .expect(409);
    const current = (
      await http()
        .get(`${P}/${id}`)
        .set(await ctx.as(READ_ONLY))
    ).body.rowVersion;
    const renamed = await http()
      .patch(`${P}/${id}`)
      .set(await ctx.as(ANALYST))
      .send({ name: 'Renamed', expectedRowVersion: current })
      .expect(200);
    expect(renamed.body.name).toBe('Renamed');
    await http()
      .delete(`${P}/${id}`)
      .set(await ctx.as(ADMIN))
      .expect(204);
    await http()
      .get(`${P}/${id}`)
      .set(await ctx.as(READ_ONLY))
      .expect(404);
    expect(ctx.store().generationOf(1n)).toBe(6n);
    expect(ctx.actions()).toEqual([
      'policy.created',
      'policy.version_published',
      'policy.version_activated',
      'policy.version_draft_created',
      'policy.version_published',
      'policy.version_activated',
      'policy.version_activated',
      'policy.disabled',
      'policy.enabled',
      'policy.updated',
      'policy.deleted',
    ]);
    const metadata = JSON.stringify(
      ctx.audit.record.mock.calls.map(([e]) => (e as { metadata: unknown }).metadata),
      (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v),
    );
    expect(metadata).not.toContain('bad.example');
    expect(metadata).not.toContain('first');
  });

  it('answers validation errors by path, limits and isolation', async () => {
    const bad = await create(await ctx.as(ADMIN), 'bad', {
      dslVersion: 'policy-dsl/1',
      direction: 'inbound',
      priority: 1,
      rules: [
        { id: 'r', priority: 1, when: { field: 'nope', op: 'equals', value: 1 }, actions: [] },
      ],
    }).expect(400);
    expect(bad.body.code).toBe('policy_definition_invalid');
    expect(bad.body.violations.map((v: { path: string }) => v.path)).toContain(
      'rules[0].when.field',
    );
    await http()
      .post(P)
      .set(await ctx.as(ADMIN))
      .send({ name: '', definition: {} })
      .expect(400);
    for (let i = 0; i < 10; i += 1) await create(await ctx.as(ADMIN), `p${i}`).expect(201);
    const limit = await create(await ctx.as(ADMIN), 'p10').expect(409);
    expect(limit.body).toMatchObject({ code: 'policy_limit_reached', limit: 10 });
    const dup = await create(await ctx.as(ADMIN), 'p0');
    expect(dup.body.code).toBe('policy_limit_reached');

    const id = ctx.store().policies[0]!.publicId;
    await http()
      .get(`${P}/${id}`)
      .set(await ctx.as(ADMIN, 'B'))
      .expect(404);
    await http()
      .get(`${P}/${id}/versions/1`)
      .set(await ctx.as(ADMIN, 'B'))
      .expect(404);
    await http()
      .post(`${P}/${id}/versions/1/publish`)
      .set(await ctx.as(ADMIN, 'B'))
      .send({ expectedRowVersion: 1 })
      .expect(404);
    await http()
      .delete(`${P}/${id}`)
      .set(await ctx.as(ADMIN, 'B'))
      .expect(404);
    expect(
      (
        await http()
          .get(P)
          .set(await ctx.as(ADMIN, 'B'))
          .expect(200)
      ).body.data,
    ).toEqual([]);
    await http()
      .get(`${P}/not-a-uuid`)
      .set(await ctx.as(ADMIN))
      .expect(400);
    await http()
      .get(`${P}/${id}/versions/0`)
      .set(await ctx.as(ADMIN))
      .expect(400);
  });

  it('reads and replaces the settings with CAS; identical settings change nothing', async () => {
    const empty = await http()
      .get('/api/v1/policy-settings')
      .set(await ctx.as(READ_ONLY))
      .expect(200);
    expect(empty.body).toMatchObject({ generation: '0', rowVersion: 0, settings: {} });
    const invalid = await http()
      .put('/api/v1/policy-settings')
      .set(await ctx.as(ADMIN))
      .send({ settings: { alerts: { enabled: 'no' } }, expectedRowVersion: 0 })
      .expect(400);
    expect(invalid.body.code).toBe('policy_settings_invalid');
    const on = await http()
      .put('/api/v1/policy-settings')
      .set(await ctx.as(ADMIN))
      .send({ settings: { allowRecommendationOverrides: true }, expectedRowVersion: 0 })
      .expect(200);
    expect(on.body).toMatchObject({ generation: '1', rowVersion: 2 });
    expect(ctx.actions()).toEqual(['policy.settings_updated', 'policy.settings_overrides_enabled']);
    const conflict = await http()
      .put('/api/v1/policy-settings')
      .set(await ctx.as(ADMIN))
      .send({ settings: {}, expectedRowVersion: 1 })
      .expect(409);
    expect(conflict.body).toMatchObject({ code: 'policy_conflict', currentRowVersion: 2 });
    await http()
      .put('/api/v1/policy-settings')
      .set(await ctx.as(ADMIN))
      .send({ settings: { allowRecommendationOverrides: true }, expectedRowVersion: 2 })
      .expect(200)
      .expect((res) => expect(res.body.generation).toBe('1'));
  });

  it('tests synthetic facts (policy:manage) and writes nothing', async () => {
    const id = (await create(await ctx.as(ADMIN)).expect(201)).body.policy.id as string;
    await http()
      .post(`${P}/${id}/versions/1/publish`)
      .set(await ctx.as(ADMIN))
      .send({ expectedRowVersion: 1 })
      .expect(200);
    const calls = ctx.store().calls.length;
    const auditRows = ctx.audit.record.mock.calls.length;
    const res = await http()
      .post(`${P}/test`)
      .set(await ctx.as(ANALYST))
      .send({ facts: { sender: { envelope: 'ceo@bad.example' } } })
      .expect(200);
    expect(res.body.result).toMatchObject({
      disposition: 'quarantine',
      decisive: { source: 'tenant_rule', policyPublicId: id },
      versions: { generation: '1' },
    });
    expect(res.body.result.explanation.text).not.toContain('bad.example');
    const inline = await http()
      .post(`${P}/test`)
      .set(await ctx.as(ANALYST))
      .send({ target: { definition: tagAllDefinition() }, facts: {} })
      .expect(200);
    expect(inline.body.result.actions.map((a: { type: string }) => a.type)).toContain('TAG');
    await http()
      .post(`${P}/test`)
      .set(await ctx.as(ANALYST))
      .send({ facts: { unknown: true } })
      .expect(400);
    await http()
      .post(`${P}/test`)
      .set(await ctx.as(READ_ONLY))
      .send({})
      .expect(403);
    expect(
      ctx
        .store()
        .calls.slice(calls)
        .every((c) => c === 'snapshot'),
    ).toBe(true);
    expect(ctx.audit.record.mock.calls.length).toBe(auditRows);
  });

  it('dry-runs a stored round (policy:manage + message:read), reproducible with target active', async () => {
    const id = (
      await create(await ctx.as(ADMIN), 'p', quarantineDomainDefinition('partner.example')).expect(
        201,
      )
    ).body.policy.id as string;
    await http()
      .post(`${P}/${id}/versions/1/publish`)
      .set(await ctx.as(ADMIN))
      .send({ expectedRowVersion: 1 })
      .expect(200);
    // The stored row as the engine writes it, from the same rows and snapshot.
    const store = ctx.store();
    const result = evaluatePolicy(
      buildPolicyInput(
        policyRoundRowsOf(
          { ...ctx.round.message, publicId: MESSAGE_ID },
          ctx.round.scan as never,
          ctx.round.rows,
          { departmentsByAddress: {}, usersByAddress: {} },
        ),
      ),
      compileSnapshot(
        snapshotSource(
          await store.facts.snapshot({ organizationId: 1n } as never),
          'pol-default/1',
          { kind: 'active' },
        ),
      ),
    );
    const json = evaluationResultToRow(result);
    ctx.stored.row = {
      ...json,
      id: 1n,
      messageId: 77n,
      receivedAt: ctx.round.message.receivedAt,
      scanId: 900n,
      policyGeneration: BigInt(json.policyGeneration),
      durationUs: 250,
      evaluatedAt: new Date('2026-11-10T10:00:06.000Z'),
    };
    const auditRows = ctx.audit.record.mock.calls.length;
    const res = await http()
      .post(dryRunUrl)
      .set(await ctx.as(ANALYST))
      .send({})
      .expect(200);
    expect(res.body.reproducible).toBe(true);
    expect(res.body.result.disposition).toBe('quarantine');
    expect(res.body.stored).toMatchObject({ disposition: 'quarantine', durationUs: 250 });
    const platform = await http()
      .post(dryRunUrl)
      .set(await ctx.as(ANALYST))
      .send({ target: 'platform' })
      .expect(200);
    expect(platform.body.reproducible).toBe(false);
    expect(ctx.audit.record.mock.calls.length).toBe(auditRows);
    // Permissions: message:read alone and policy:manage alone are both refused.
    await http()
      .post(dryRunUrl)
      .set(await ctx.as(['message:read']))
      .send({})
      .expect(403);
    await http()
      .post(dryRunUrl)
      .set(await ctx.as(['policy:manage']))
      .send({})
      .expect(403);
    const foreign = await http()
      .post(dryRunUrl)
      .set(await ctx.as(ADMIN, 'B'))
      .send({})
      .expect(404);
    expect(foreign.body.code).toBe('message_not_found');
    const noScan = await http()
      .post(`/api/v1/messages/${MESSAGE_ID}/scans/901/policy/dry-run`)
      .set(await ctx.as(ANALYST))
      .send({})
      .expect(404);
    expect(noScan.body.code).toBe('scan_not_found');
  });

  it('validates the history range and lists the evaluations of a message', async () => {
    await http()
      .get(`${P}/executions`)
      .set(await ctx.as(READ_ONLY))
      .expect(400);
    await http()
      .get(`${P}/executions?from=2026-10-01T00:00:00Z&to=2026-12-01T00:00:00Z`)
      .set(await ctx.as(READ_ONLY))
      .expect(400);
    const ok = await http()
      .get(
        `${P}/executions?from=2026-11-01T00:00:00Z&to=2026-11-15T00:00:00Z&disposition=reject&overrideApplied=true`,
      )
      .set(await ctx.as(READ_ONLY))
      .expect(200);
    expect(ok.body).toEqual({ data: [], nextCursor: null });
    expect(ctx.executions.history).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ disposition: 'reject', overrideApplied: true, take: 26 }),
    );
    await http()
      .get(`${P}/executions?from=2026-11-01T00:00:00Z&to=2026-11-02T00:00:00Z`)
      .set(await ctx.as(['message:read']))
      .expect(403);
    const evaluations = await http()
      .get(`/api/v1/messages/${MESSAGE_ID}/policy-evaluations`)
      .set(await ctx.as(READ_ONLY))
      .expect(200);
    expect(evaluations.body).toEqual({ messageId: MESSAGE_ID, data: [] });
    await http()
      .get(`/api/v1/messages/${MESSAGE_ID}/policy-evaluations`)
      .set(await ctx.as(READ_ONLY, 'B'))
      .expect(404);
  });
});
