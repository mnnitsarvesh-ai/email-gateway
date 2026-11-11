/**
 * Step 5.2 policy and department api against the real MySQL writer and replica
 * (docs/plan/steps/16-policy-engine.md P5, P11, P12, P16, P17, P22, §9.2): the lifecycle with the
 * seeded roles (`read_only_user`, `security_analyst` = policy:manage, `organization_admin` =
 * policy:publish + user:manage), the generation incremented exactly once per effective change,
 * audit rows and their metadata (no values), immutability through the repository, the test
 * endpoint and the message dry-run writing nothing (checksums of the policy tables,
 * `policy_execution_logs`, `audit_logs` and `message_outbox`), a stored evaluation (written as
 * `evaluationResultToRow` maps it, from the same rows the dry-run reads) reproduced with
 * `reproducible: true`, the history filters/pagination/range bound, the scans `policy` section,
 * departments with `department_in_use`, and the organization purge.
 */
import { createHash } from 'node:crypto';
import {
  buildPolicyInput,
  canonicalJson,
  compileSnapshot,
  evaluatePolicy,
  evaluationResultToRow,
  type PolicyRoundRows,
  sha256Hex,
} from '@email-gateway/policy-dsl';
import {
  buildScoringInput,
  platformProfile,
  riskResultToRowJson,
  scoreRisk,
} from '@email-gateway/risk-scoring';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { PoliciesManagementRepository } from '../src/modules/policies/repositories/policies-management.repository';
import {
  POLICY_PURGE_ORDER,
  PolicyTenantDataRepository,
} from '../src/modules/tenant-data/policy-tenant-data.repository';
import {
  departmentExceptionDefinition,
  quarantineDomainDefinition,
  tagAllDefinition,
} from '../test/support/policy-fixtures';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
} from './support/fixtures';
import { bearer, loginWithMfa, uniqueIp } from './support/http';
import {
  deleteLifecycleFixtures,
  insertLifecycleMessage,
  type LifecycleMessage,
} from './support/lifecycle';

const POLL = { timeout: 15_000, interval: 200 };
const P = '/api/v1/policies';

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: Record<string, string>;
let analystA: Record<string, string>;
let readOnlyA: Record<string, string>;
let adminB: Record<string, string>;

const headers = (auth: Record<string, string>) => ({ ...auth, 'X-Forwarded-For': uniqueIp() });
const tokenOf = async (user: FixtureUser) =>
  bearer((await loginWithMfa(ctx, fx, user)).accessToken);
const generationOf = async (org: FixtureOrganization) =>
  (await ctx.prisma.policySettings.findFirst({ where: { organizationId: org.id } }))?.generation ??
  0n;
const auditOf = (org: FixtureOrganization, action: string) =>
  ctx.prisma.auditLog.findMany({
    where: { organizationId: org.id, action },
    orderBy: { id: 'asc' },
  });

const sha = (rows: unknown) =>
  createHash('sha256')
    .update(JSON.stringify(rows, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v)))
    .digest('hex');

/** Checksums of every table a test or dry-run could write, for one organization. */
async function checksums(org: FixtureOrganization) {
  const where = { organizationId: org.id };
  const orderBy = { id: 'asc' as const };
  return {
    policies: sha(await ctx.prisma.emailPolicy.findMany({ where, orderBy })),
    versions: sha(await ctx.prisma.policyVersion.findMany({ where, orderBy })),
    settings: sha(await ctx.prisma.policySettings.findMany({ where, orderBy })),
    departments: sha(await ctx.prisma.tenantDepartment.findMany({ where, orderBy })),
    members: sha(await ctx.prisma.tenantDepartmentMember.findMany({ where, orderBy })),
    evaluations: sha(await ctx.prisma.policyExecutionLog.findMany({ where, orderBy })),
    audit: sha(await ctx.prisma.auditLog.findMany({ where, orderBy })),
    outbox: await ctx.prisma.messageOutbox.count({ where }),
  };
}

async function purgePolicies(orgIds: bigint[]): Promise<void> {
  const repo = ctx.get(PolicyTenantDataRepository);
  for (const id of orgIds) await repo.purgeOrganization(systemScope(id));
  const where = { organizationId: { in: orgIds } };
  await ctx.prisma.messageRiskScore.deleteMany({ where });
  await ctx.prisma.emailAuthResult.deleteMany({ where });
  await ctx.prisma.scanEngineResult.deleteMany({ where });
  await ctx.prisma.emailScan.deleteMany({ where });
}

/**
 * A completed round (rspamd clean final, authentication row, the revision-0 risk row as the
 * email-worker writes it). Returns the scan id and the `PolicyRoundRows` built from the writer
 * rows (the engine's view of the same rows).
 */
async function insertRound(message: LifecycleMessage, round = 0) {
  const startedAt = new Date(message.receivedAt.getTime() + 1_000);
  const completedAt = new Date(startedAt.getTime() + 2_000);
  const base = {
    receivedAt: message.receivedAt,
    messageId: message.id,
    organizationId: message.organizationId,
  };
  const scan = await ctx.prisma.emailScan.create({
    data: {
      ...base,
      scanKind: round === 0 ? 'initial' : 'rescan',
      status: 'completed',
      lifecycleRound: round,
      scanVerdict: 'clean',
      requiredEngines: ['rspamd'],
      reasonCodes: [],
      startedAt,
      completedAt,
      deadlineAt: new Date(startedAt.getTime() + 1_800_000),
    },
    select: { id: true },
  });
  await ctx.prisma.scanEngineResult.create({
    data: {
      ...base,
      scanId: scan.id,
      engine: 'rspamd',
      engineVersion: '3.13.2',
      outcome: 'clean',
      score: 1.5,
      requiredScore: 15,
      durationMs: 120,
      attempt: 1,
      isFinal: true,
      reasonCodes: [],
      settingsVersion: 'rspamd-map/2;p=000000000000;t=none',
      evidence: { signals: [] },
      completedAt,
    },
  });
  const auth = {
    spf: 'pass',
    dkim: 'pass',
    dmarc: 'pass',
    dmarcPolicy: 'reject',
    arc: 'none',
  } as const;
  await ctx.prisma.emailAuthResult.create({
    data: { ...base, scanId: scan.id, engine: 'rspamd', ...auth },
  });
  const final = await ctx.prisma.scanEngineResult.findFirstOrThrow({
    where: { scanId: scan.id, isFinal: true },
  });
  const msg = await ctx.prisma.emailMessage.findFirstOrThrow({
    where: { id: message.id, receivedAt: message.receivedAt },
  });
  const risk = scoreRisk(
    buildScoringInput(
      {
        scan: {
          requiredEngines: ['rspamd'],
          scanKind: round === 0 ? 'initial' : 'rescan',
          lifecycleRound: round,
          status: 'completed',
        },
        message: {
          direction: msg.direction,
          attachmentCount: 0,
          recipientCount: msg.recipientCount,
        },
        finals: [
          {
            engine: final.engine,
            outcome: final.outcome,
            errorCode: final.errorCode,
            reasonCodes: final.reasonCodes,
            score: final.score === null ? null : final.score.toString(),
            engineVersion: final.engineVersion,
            settingsVersion: final.settingsVersion,
            attempt: final.attempt,
            completedAt: final.completedAt,
          },
        ],
        auth,
        bec: null,
        dlp: null,
      },
      0,
    ),
    platformProfile('rsk-default/1'),
  );
  const riskJson = riskResultToRowJson(risk);
  await ctx.prisma.messageRiskScore.create({
    data: {
      ...base,
      scanId: scan.id,
      lifecycleRound: round,
      revision: 0,
      direction: msg.direction,
      ...riskJson,
      explanation: risk.explanation.lines,
      profileVersionId: null,
      durationUs: 250,
    },
  });
  const recipients = await ctx.prisma.emailRecipient.findMany({
    where: { messageId: message.id, receivedAt: message.receivedAt },
    orderBy: { rcptSeq: 'asc' },
  });
  const rows = (directory: PolicyRoundRows['directory']): PolicyRoundRows => ({
    trigger: 'scanned',
    message: {
      direction: msg.direction,
      envelopeFrom: msg.envelopeFrom,
      headerFrom: msg.headerFrom,
      clientIp: msg.clientIp,
      clientName: msg.clientName,
      sizeBytes: msg.sizeBytes,
      recipientCount: msg.recipientCount,
      attachmentCount: msg.attachmentCount,
      lifecycleRound: round,
    },
    recipients: recipients.map((r) => ({ rcptSeq: r.rcptSeq, address: r.address })),
    scan: {
      scanId: scan.id,
      lifecycleRound: round,
      scanKind: round === 0 ? 'initial' : 'rescan',
      status: 'completed',
      scanVerdict: 'clean',
      reasonCodes: [],
      requiredEngines: ['rspamd'],
      completedAt,
    },
    parseFailedAt: null,
    finals: [{ engine: 'rspamd', outcome: 'clean', reasonCodes: [] }],
    auth,
    bec: null,
    dlp: null,
    risk: [{ revision: 0, ...riskJson }],
    attachments: [],
    attachmentResults: [],
    urls: [],
    urlResults: [],
    urlRewrite: null,
    directory,
  });
  return { scanId: scan.id, rows, completedAt };
}

/** The active snapshot source of the organization read on the writer (the engine's view). */
async function writerSnapshot(org: FixtureOrganization) {
  const settings = await ctx.prisma.policySettings.findFirst({ where: { organizationId: org.id } });
  const policies = await ctx.prisma.emailPolicy.findMany({
    where: {
      organizationId: org.id,
      status: 'active',
      deletedAt: null,
      activeVersionId: { not: null },
    },
  });
  const versions = await ctx.prisma.policyVersion.findMany({
    where: { id: { in: policies.map((p) => p.activeVersionId!) }, status: 'published' },
  });
  return {
    generation: (settings?.generation ?? 0n).toString(),
    settings: settings?.settings ?? null,
    platformDefaultId: 'pol-default/1',
    policies: policies.flatMap((p) => {
      const v = versions.find((x) => x.id === p.activeVersionId);
      return v
        ? [
            {
              publicId: p.publicId,
              versionNo: v.version,
              definition: v.definition,
              definitionSha256: v.definitionSha256,
            },
          ]
        : [];
    }),
    ids: Object.fromEntries(
      policies.flatMap((p) => {
        const v = versions.find((x) => x.id === p.activeVersionId);
        return v ? [[`${p.publicId}#${v.version}`, v.id.toString()]] : [];
      }),
    ),
  };
}

beforeAll(async () => {
  ctx = await createIntegrationApp({
    POLICY_MAX_POLICIES: '10',
    POLICY_MAX_ACTIVE_RULES: '100',
    POLICY_HISTORY_MAX_RANGE_DAYS: '7',
  });
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgA.id, orgB.id]));
  fx.registerCleanup(() => purgePolicies([orgA.id, orgB.id]));
  adminA = await tokenOf(await fx.createUser(orgA, { roles: ['organization_admin'], mfa: true }));
  analystA = await tokenOf(await fx.createUser(orgA, { roles: ['security_analyst'], mfa: true }));
  readOnlyA = await tokenOf(await fx.createUser(orgA, { roles: ['read_only_user'], mfa: true }));
  adminB = await tokenOf(await fx.createUser(orgB, { roles: ['organization_admin'], mfa: true }));
  await ctx.prisma.domain.create({
    data: { organizationId: orgA.id, name: 'acme.example', status: 'active' },
  });
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('policy lifecycle on the writer (P17, P12)', () => {
  let policyId: string;

  it('creates, publishes and rolls back with one generation change per effective change', async () => {
    await ctx.http
      .post(P)
      .set(headers(readOnlyA))
      .send({ name: 'x', definition: tagAllDefinition() })
      .expect(403);
    const created = await ctx.http
      .post(P)
      .set(headers(analystA))
      .send({
        name: 'Block bad',
        definition: quarantineDomainDefinition(),
        changeNote: 'secret note',
      })
      .expect(201);
    policyId = created.body.policy.id as string;
    expect(await generationOf(orgA)).toBe(0n);
    const settingsRow = await ctx.prisma.policySettings.findFirstOrThrow({
      where: { organizationId: orgA.id },
    });
    expect(settingsRow.settingsSha256).toBe(sha256Hex(canonicalJson({})));

    await ctx.http
      .post(`${P}/${policyId}/versions/1/publish`)
      .set(headers(analystA))
      .send({ expectedRowVersion: 1 })
      .expect(403);
    const published = await ctx.http
      .post(`${P}/${policyId}/versions/1/publish`)
      .set(headers(adminA))
      .send({ expectedRowVersion: 1 })
      .expect(200);
    expect(published.body.generation).toBe('1');
    expect(await generationOf(orgA)).toBe(1n);
    const v1 = await ctx.prisma.policyVersion.findFirstOrThrow({
      where: { organizationId: orgA.id, version: 1 },
    });
    expect(v1).toMatchObject({
      status: 'published',
      dslVersion: 'policy-dsl/1',
      ruleCount: 1,
      hasOverrideRules: false,
      definitionSha256: sha256Hex(canonicalJson(v1.definition)),
    });
    const policy = await ctx.prisma.emailPolicy.findFirstOrThrow({ where: { publicId: policyId } });
    expect(policy).toMatchObject({
      status: 'active',
      activeVersionId: v1.id,
      direction: 'inbound',
    });

    await ctx.http
      .post(`${P}/${policyId}/versions`)
      .set(headers(analystA))
      .send({ definition: quarantineDomainDefinition('worse.example') })
      .expect(201);
    await ctx.http
      .post(`${P}/${policyId}/versions/2/publish`)
      .set(headers(adminA))
      .send({ expectedRowVersion: 1 })
      .expect(200);
    expect(await generationOf(orgA)).toBe(2n);
    await ctx.http.post(`${P}/${policyId}/versions/1/activate`).set(headers(adminA)).expect(200);
    await ctx.http.post(`${P}/${policyId}/versions/1/activate`).set(headers(adminA)).expect(200);
    expect(await generationOf(orgA)).toBe(3n);
    await ctx.http.post(`${P}/${policyId}/disable`).set(headers(adminA)).expect(200);
    await ctx.http.post(`${P}/${policyId}/disable`).set(headers(adminA)).expect(200);
    await ctx.http.post(`${P}/${policyId}/enable`).set(headers(adminA)).expect(200);
    expect(await generationOf(orgA)).toBe(5n);

    // Audit rows and metadata: ids, numbers and hashes; never definition values or notes.
    const activated = await auditOf(orgA, 'policy.version_activated');
    expect(activated).toHaveLength(3);
    expect(activated.at(-1)!.metadata).toMatchObject({
      policyId,
      versionNo: 1,
      previousVersionNo: 2,
    });
    for (const action of [
      'policy.created',
      'policy.version_published',
      'policy.version_draft_created',
      'policy.disabled',
      'policy.enabled',
    ]) {
      expect((await auditOf(orgA, action)).length, action).toBeGreaterThan(0);
    }
    const all = JSON.stringify(
      (await ctx.prisma.auditLog.findMany({ where: { organizationId: orgA.id } })).map(
        (a) => a.metadata,
      ),
    );
    expect(all).not.toContain('bad.example');
    expect(all).not.toContain('secret note');
  });

  it('keeps published versions immutable (route and repository) and isolates organizations', async () => {
    const put = await ctx.http
      .put(`${P}/${policyId}/versions/1`)
      .set(headers(adminA))
      .send({ definition: tagAllDefinition(), expectedRowVersion: 2 })
      .expect(409);
    expect(put.body.code).toBe('policy_version_immutable');
    const row = await ctx.prisma.policyVersion.findFirstOrThrow({
      where: { organizationId: orgA.id, version: 1 },
    });
    const repo = ctx.get(PoliciesManagementRepository);
    const changed = await ctx.prisma.$transaction((tx) =>
      repo.updateDraft(
        tx,
        systemScope(orgA.id),
        row.id,
        row.rowVersion,
        {
          definition: {},
          definitionSha256: 'f'.repeat(64),
          dslVersion: 'policy-dsl/1',
          references: {},
          hasOverrideRules: false,
          ruleCount: 0,
          changeNote: null,
        },
        null,
      ),
    );
    expect(changed).toBe(false);
    expect(await ctx.prisma.policyVersion.findFirstOrThrow({ where: { id: row.id } })).toEqual(row);

    await ctx.http.get(`${P}/${policyId}`).set(headers(adminB)).expect(404);
    await ctx.http.post(`${P}/${policyId}/disable`).set(headers(adminB)).expect(404);
    await expect
      .poll(async () => {
        const res = await ctx.http.get(P).set(headers(readOnlyA));
        return (res.body.data as Array<{ id: string }> | undefined)?.map((p) => p.id);
      }, POLL)
      .toEqual([policyId]);
    expect((await ctx.http.get(P).set(headers(adminB)).expect(200)).body.data).toEqual([]);
  });
});

describe('test, dry-run, scans policy section and history (P16, P22, P23)', () => {
  let message: LifecycleMessage;
  let scanId: bigint;
  let departmentId: string;

  beforeAll(async () => {
    // A Finance department with alice; a policy quarantining unless every recipient is Finance.
    const dept = await ctx.http
      .post('/api/v1/departments')
      .set(headers(adminA))
      .send({ name: 'Finance' })
      .expect(201);
    departmentId = dept.body.id as string;
    await ctx.http
      .post(`/api/v1/departments/${departmentId}/members`)
      .set(headers(adminA))
      .send({ address: 'Alice@ACME.example' })
      .expect(201);
    const created = await ctx.http
      .post(P)
      .set(headers(adminA))
      .send({ name: 'Finance only', definition: departmentExceptionDefinition(departmentId) })
      .expect(201);
    await ctx.http
      .post(`${P}/${created.body.policy.id as string}/versions/1/publish`)
      .set(headers(adminA))
      .send({ expectedRowVersion: 1 })
      .expect(200);
    message = await insertLifecycleMessage(ctx, orgA, {
      state: 'quarantined',
      recipients: [{ address: 'alice@acme.example' }, { address: 'bob@acme.example' }],
    });
    const round = await insertRound(message);
    scanId = round.scanId;
    // The stored evaluation as the engine writes it: writer rows, writer snapshot, directory.
    const snap = await writerSnapshot(orgA);
    const result = evaluatePolicy(
      buildPolicyInput(
        round.rows({
          departmentsByAddress: { 'alice@acme.example': [departmentId] },
          usersByAddress: {},
        }),
      ),
      compileSnapshot(snap),
    );
    expect(result.disposition).toBe('quarantine');
    const json = evaluationResultToRow(result, { policyVersionIds: snap.ids });
    await ctx.prisma.policyExecutionLog.create({
      data: {
        ...json,
        receivedAt: message.receivedAt,
        messageId: message.id,
        organizationId: orgA.id,
        scanId: BigInt(json.scanId!),
        decisivePolicyVersionId:
          json.decisivePolicyVersionId === null ? null : BigInt(json.decisivePolicyVersionId),
        policyGeneration: BigInt(json.policyGeneration),
        delivery: json.delivery ?? undefined,
        overrideDetail: json.overrideDetail ?? undefined,
        durationUs: 310,
        evaluatedAt: round.completedAt,
      } as never,
    });
  });

  const dryRunUrl = () =>
    `/api/v1/messages/${message.publicId}/scans/${scanId.toString()}/policy/dry-run`;

  it('dry-run reproduces the stored evaluation and the test endpoint writes nothing', async () => {
    const before = await checksums(orgA);
    let body: Record<string, unknown> = {};
    await expect
      .poll(async () => {
        const res = await ctx.http.post(dryRunUrl()).set(headers(analystA)).send({});
        body = res.body as Record<string, unknown>;
        return body.reproducible;
      }, POLL)
      .toBe(true);
    expect(body.stored).toMatchObject({
      disposition: 'quarantine',
      durationUs: 310,
      lifecycleRound: 0,
    });
    expect((body.result as { disposition: string }).disposition).toBe('quarantine');
    const platform = await ctx.http
      .post(dryRunUrl())
      .set(headers(analystA))
      .send({ target: 'platform' })
      .expect(200);
    expect(platform.body.reproducible).toBe(false);
    // The platform snapshot references no department: memberships are not resolved (P5).
    expect(platform.body.result.inputSha256).not.toBe(
      (body.result as { inputSha256: string }).inputSha256,
    );
    const test = await ctx.http
      .post(`${P}/test`)
      .set(headers(analystA))
      .send({ facts: { recipients: [{ address: 'alice@acme.example' }], resolveDirectory: true } })
      .expect(200);
    expect(test.body.result.disposition).toBe('allow');
    await ctx.http
      .post(`${P}/test`)
      .set(headers(analystA))
      .send({ target: { definition: tagAllDefinition() } })
      .expect(200);
    expect(await checksums(orgA)).toEqual(before);

    await ctx.http.post(dryRunUrl()).set(headers(readOnlyA)).send({}).expect(403);
    const foreign = await ctx.http.post(dryRunUrl()).set(headers(adminB)).send({}).expect(404);
    expect(foreign.body.code).toBe('message_not_found');
  });

  it('shows the evaluation in the scans read API and the message evaluations (no internal ids)', async () => {
    let policy: Record<string, unknown> | null = null;
    await expect
      .poll(async () => {
        const res = await ctx.http
          .get(`/api/v1/messages/${message.publicId}/scans`)
          .set(headers(readOnlyA));
        policy = (res.body.data?.[0]?.policy ?? null) as Record<string, unknown> | null;
        return policy !== null;
      }, POLL)
      .toBe(true);
    expect(policy).toMatchObject({
      disposition: 'quarantine',
      decisive: { source: 'tenant_rule' },
      durationUs: 310,
    });
    const text = JSON.stringify(policy);
    expect(text).not.toContain('decisivePolicyVersionId');
    expect(text).not.toContain('alice@');
    const list = await ctx.http
      .get(`/api/v1/messages/${message.publicId}/policy-evaluations`)
      .set(headers(readOnlyA))
      .expect(200);
    expect(list.body.data).toHaveLength(1);
    await ctx.http
      .get(`/api/v1/messages/${message.publicId}/policy-evaluations`)
      .set(headers(adminB))
      .expect(404);
  });

  it('filters and pages the history within the range bound', async () => {
    const from = new Date(message.receivedAt.getTime() - 3_600_000).toISOString();
    const to = new Date(message.receivedAt.getTime() + 3_600_000).toISOString();
    const url = (q: string) => `${P}/executions?from=${from}&to=${to}${q}`;
    let data: Array<Record<string, unknown>> = [];
    await expect
      .poll(async () => {
        const res = await ctx.http.get(url('&disposition=quarantine')).set(headers(readOnlyA));
        data = (res.body.data ?? []) as Array<Record<string, unknown>>;
        return data.length;
      }, POLL)
      .toBe(1);
    expect(data[0]).toMatchObject({
      messageId: message.publicId,
      disposition: 'quarantine',
      finalAction: 'quarantine',
      decisive: { source: 'tenant_rule', ruleId: 'quarantine-except-finance' },
      matchedRuleCount: 1,
      durationUs: 310,
    });
    expect(
      (await ctx.http.get(url('&disposition=allow')).set(headers(readOnlyA)).expect(200)).body.data,
    ).toEqual([]);
    expect(
      (await ctx.http.get(url('&source=floor')).set(headers(readOnlyA)).expect(200)).body.data,
    ).toEqual([]);
    expect(
      (await ctx.http.get(url('&limit=1')).set(headers(readOnlyA)).expect(200)).body.nextCursor,
    ).toBeNull();
    expect((await ctx.http.get(url('')).set(headers(adminB)).expect(200)).body.data).toEqual([]);
    await ctx.http
      .get(`${P}/executions?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z`)
      .set(headers(readOnlyA))
      .expect(400);
  });

  it('refuses to delete a department an active version references', async () => {
    const res = await ctx.http
      .delete(`/api/v1/departments/${departmentId}`)
      .set(headers(adminA))
      .expect(409);
    expect(res.body.code).toBe('department_in_use');
    const member = await ctx.prisma.tenantDepartmentMember.findFirstOrThrow({
      where: { organizationId: orgA.id },
    });
    expect(member).toMatchObject({ address: 'alice@acme.example', userId: null });
    expect((await auditOf(orgA, 'department.member_added'))[0]!.metadata).not.toHaveProperty(
      'address',
    );
  });
});

describe('organization purge (step 5.2)', () => {
  it('deletes the policy and directory rows of one organization only, resumably', async () => {
    const orgC = await fx.createOrganization();
    fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgC.id]));
    fx.registerCleanup(() => purgePolicies([orgC.id]));
    const adminC = await tokenOf(
      await fx.createUser(orgC, { roles: ['organization_admin'], mfa: true }),
    );
    await ctx.prisma.domain.create({
      data: { organizationId: orgC.id, name: 'c.example', status: 'active' },
    });
    const created = await ctx.http
      .post(P)
      .set(headers(adminC))
      .send({ name: 'c', definition: tagAllDefinition() })
      .expect(201);
    await ctx.http
      .post(`${P}/${created.body.policy.id as string}/versions/1/publish`)
      .set(headers(adminC))
      .send({ expectedRowVersion: 1 })
      .expect(200);
    const dept = await ctx.http
      .post('/api/v1/departments')
      .set(headers(adminC))
      .send({ name: 'D' })
      .expect(201);
    await ctx.http
      .post(`/api/v1/departments/${dept.body.id as string}/members`)
      .set(headers(adminC))
      .send({ address: 'x@c.example' })
      .expect(201);
    const message = await insertLifecycleMessage(ctx, orgC, { state: 'scanned' });
    const round = await insertRound(message);
    const snap = await writerSnapshot(orgC);
    const json = evaluationResultToRow(
      evaluatePolicy(
        buildPolicyInput(round.rows({ departmentsByAddress: {}, usersByAddress: {} })),
        compileSnapshot(snap),
      ),
    );
    await ctx.prisma.policyExecutionLog.create({
      data: {
        ...json,
        receivedAt: message.receivedAt,
        messageId: message.id,
        organizationId: orgC.id,
        scanId: round.scanId,
        decisivePolicyVersionId: null,
        policyGeneration: BigInt(json.policyGeneration),
        delivery: json.delivery ?? undefined,
        overrideDetail: json.overrideDetail ?? undefined,
        durationUs: 1,
        evaluatedAt: round.completedAt,
      } as never,
    });
    const othersBefore = await ctx.prisma.policyVersion.count({
      where: { organizationId: orgA.id },
    });

    const repo = ctx.get(PolicyTenantDataRepository);
    const counts = await repo.purgeOrganization(systemScope(orgC.id), 1);
    expect(Object.keys(counts)).toEqual([...POLICY_PURGE_ORDER]);
    expect(counts).toMatchObject({
      policy_execution_logs: 1,
      policy_versions: 1,
      email_policies: 1,
      policy_settings: 1,
      tenant_department_members: 1,
      tenant_departments: 1,
    });
    const where = { organizationId: orgC.id };
    expect(
      await Promise.all([
        ctx.prisma.policyExecutionLog.count({ where }),
        ctx.prisma.policyVersion.count({ where }),
        ctx.prisma.emailPolicy.count({ where }),
        ctx.prisma.policySettings.count({ where }),
        ctx.prisma.tenantDepartmentMember.count({ where }),
        ctx.prisma.tenantDepartment.count({ where }),
      ]),
    ).toEqual([0, 0, 0, 0, 0, 0]);
    expect(await ctx.prisma.policyVersion.count({ where: { organizationId: orgA.id } })).toBe(
      othersBefore,
    );
    expect(
      Object.values(await repo.purgeOrganization(systemScope(orgC.id))).every((n) => n === 0),
    ).toBe(true);
  });
});
