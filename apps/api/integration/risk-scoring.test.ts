/**
 * Step 5.1 risk scoring api against the real MySQL writer and replica (docs/plan/steps/
 * 15-risk-scoring.md R10, R12, R15, §3, §9.4): the profile lifecycle with the seeded roles
 * (`read_only_user`, `security_analyst` = policy:manage, `organization_admin` = policy:publish),
 * audit rows in `audit_logs`, the row-version and pointer compare-and-set, immutability of
 * published rows (the repository's `WHERE status = 'draft'`), the version cap, isolation of two
 * organizations, the dry-run of a stored round (reproduces the stored `input_sha256` with
 * `profile: active` and changes no row), the `risk` section of the scans read API, and the
 * organization purge of the three risk tables. Score rows are inserted as the email-worker
 * writes them (the library's `riskResultToRowJson`).
 */
// ---- Route coverage (step 6.1 §3.8, test/route-coverage/legacy.ts) ----
// @covers delete /api/v1/risk-scoring/profile/versions/:versionId
// @covers get /api/v1/risk-scoring/profile
// @covers get /api/v1/risk-scoring/profile/versions
// @covers get /api/v1/risk-scoring/profile/versions/:versionId
// @covers post /api/v1/messages/:messageId/scans/:scanId/risk/dry-run
// @covers post /api/v1/risk-scoring/profile/reset
// @covers post /api/v1/risk-scoring/profile/versions
// @covers post /api/v1/risk-scoring/profile/versions/:versionId/activate
// @covers post /api/v1/risk-scoring/profile/versions/:versionId/publish
// @covers put /api/v1/risk-scoring/profile/versions/:versionId
// ---- end of route coverage ----
import {
  buildScoringInput,
  resolveProfile,
  riskResultToRowJson,
  type RoundRows,
  scoreRisk,
} from '@email-gateway/risk-scoring';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { RiskProfilesRepository } from '../src/modules/risk-scoring/repositories/risk-profiles.repository';
import {
  RISK_PURGE_ORDER,
  RiskTenantDataRepository,
} from '../src/modules/tenant-data/risk-tenant-data.repository';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
} from './support/fixtures';
import { bearer, idem, loginWithMfa, uniqueIp } from './support/http';
import {
  deleteLifecycleFixtures,
  insertLifecycleMessage,
  type LifecycleMessage,
} from './support/lifecycle';

const POLL = { timeout: 15_000, interval: 200 };
const VERSIONS = '/api/v1/risk-scoring/profile/versions';

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

async function purgeRisk(orgIds: bigint[]): Promise<void> {
  const repo = ctx.get(RiskTenantDataRepository);
  for (const id of orgIds) await repo.purgeOrganization(systemScope(id));
  const where = { organizationId: { in: orgIds } };
  await ctx.prisma.emailAuthResult.deleteMany({ where });
  await ctx.prisma.scanEngineResult.deleteMany({ where });
  await ctx.prisma.emailScan.deleteMany({ where });
}

const auditOf = (org: FixtureOrganization, action: string, resourceId: string) =>
  ctx.prisma.auditLog.findFirst({
    where: { organizationId: org.id, action, resourceId },
    orderBy: { id: 'desc' },
  });

/**
 * A completed round with an rspamd final (suspicious score) and its authentication row, the
 * round's snapshot `riskProfileVersionId`, and its stored revision-0 score as the email-worker
 * writes it with `resolved` (R11 mapping). Returns the scan id and the stored result.
 */
async function insertScoredRound(
  message: LifecycleMessage,
  snapshot: { id: bigint; publicId: string; versionNo: number; overrides: unknown } | null,
) {
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
      scanKind: 'initial',
      status: 'completed',
      lifecycleRound: 0,
      scanVerdict: 'spam',
      requiredEngines: ['rspamd'],
      reasonCodes: ['spam.suspicious_score'],
      startedAt,
      completedAt,
      deadlineAt: new Date(startedAt.getTime() + 1_800_000),
      riskProfileVersionId: snapshot?.id ?? null,
    },
    select: { id: true },
  });
  await ctx.prisma.scanEngineResult.create({
    data: {
      ...base,
      scanId: scan.id,
      engine: 'rspamd',
      engineVersion: '3.13.2',
      outcome: 'spam',
      score: 7.25,
      requiredScore: 15,
      durationMs: 120,
      attempt: 1,
      isFinal: true,
      reasonCodes: ['spam.suspicious_score'],
      settingsVersion: 'rspamd-map/2;p=000000000000;t=none',
      evidence: { signals: [] },
      completedAt,
    },
  });
  await ctx.prisma.emailAuthResult.create({
    data: {
      ...base,
      scanId: scan.id,
      engine: 'rspamd',
      spf: 'pass',
      dkim: 'pass',
      dmarc: 'pass',
      dmarcPolicy: 'reject',
      arc: 'none',
    },
  });
  // The worker's view of the same rows (Decimal score as toString()).
  const final = await ctx.prisma.scanEngineResult.findFirstOrThrow({
    where: { scanId: scan.id, isFinal: true },
  });
  const rows: RoundRows = {
    scan: {
      requiredEngines: ['rspamd'],
      scanKind: 'initial',
      lifecycleRound: 0,
      status: 'completed',
    },
    message: { direction: 'inbound', attachmentCount: 0, recipientCount: 2 },
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
    auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarcPolicy: 'reject', arc: 'none' },
    bec: null,
    dlp: null,
  };
  const resolved = resolveProfile(
    'rsk-default/1',
    snapshot === null
      ? null
      : {
          publicId: snapshot.publicId,
          versionNo: snapshot.versionNo,
          baseProfile: 'rsk-default/1',
          overrides: snapshot.overrides,
        },
  );
  const result = scoreRisk(buildScoringInput(rows, 0), resolved);
  await ctx.prisma.messageRiskScore.create({
    data: {
      ...base,
      scanId: scan.id,
      lifecycleRound: 0,
      revision: 0,
      direction: 'inbound',
      ...riskResultToRowJson(result),
      explanation: result.explanation.lines,
      profileVersionId: snapshot?.id ?? null,
      durationUs: 250,
    },
  });
  return { scanId: scan.id, result };
}

beforeAll(async () => {
  ctx = await createIntegrationApp({ RISK_PROFILE_MAX_VERSIONS: '10' });
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgA.id, orgB.id]));
  fx.registerCleanup(() => purgeRisk([orgA.id, orgB.id]));
  adminA = await tokenOf(await fx.createUser(orgA, { roles: ['organization_admin'], mfa: true }));
  analystA = await tokenOf(await fx.createUser(orgA, { roles: ['security_analyst'], mfa: true }));
  readOnlyA = await tokenOf(await fx.createUser(orgA, { roles: ['read_only_user'], mfa: true }));
  adminB = await tokenOf(await fx.createUser(orgB, { roles: ['organization_admin'], mfa: true }));
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('risk scoring profile lifecycle (R10, R15)', () => {
  let v1: string;
  let v2: string;

  it('drafts with policy:manage, publishes with policy:publish; read-only users never write', async () => {
    await ctx.http.post(VERSIONS).set(headers(readOnlyA)).send({ overrides: {} }).expect(403);
    const created = await ctx.http
      .post(VERSIONS)
      .set(headers(analystA))
      .send({ overrides: { actions: { medium: 'quarantine' } }, changeNote: 'hold medium' })
      .expect(201);
    expect(created.body).toMatchObject({ versionNo: 1, status: 'draft', rowVersion: 1 });
    v1 = created.body.id as string;
    expect((await auditOf(orgA, 'risk_profile.draft_created', v1))?.metadata).toMatchObject({
      versionId: v1,
      versionNo: 1,
      changedPaths: ['actions.medium'],
    });
    const row = await ctx.prisma.riskScoringProfileVersion.findFirstOrThrow({
      where: { publicId: v1 },
    });
    expect(row).toMatchObject({ organizationId: orgA.id, baseProfile: 'rsk-default/1' });
    expect(row.publicId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7/);

    const stale = await ctx.http
      .put(`${VERSIONS}/${v1}`)
      .set(headers(analystA))
      .send({ overrides: { actions: { medium: 'require_approval' } }, expectedRowVersion: 9 })
      .expect(409);
    expect(stale.body).toMatchObject({
      code: 'risk_profile_version_conflict',
      currentRowVersion: 1,
    });
    await ctx.http
      .put(`${VERSIONS}/${v1}`)
      .set(headers(analystA))
      .send({ overrides: { actions: { medium: 'require_approval' } }, expectedRowVersion: 1 })
      .expect(200);
    await ctx.http
      .post(`${VERSIONS}/${v1}/publish`)
      .set(idem())
      .set(headers(analystA))
      .send({ expectedRowVersion: 2 })
      .expect(403);
    const published = await ctx.http
      .post(`${VERSIONS}/${v1}/publish`)
      .set(idem())
      .set(headers(adminA))
      .send({ expectedRowVersion: 2 })
      .expect(200);
    expect(published.body.profile.active).toMatchObject({ source: 'tenant', versionId: v1 });
    expect(await auditOf(orgA, 'risk_profile.published', v1)).toBeTruthy();
    expect((await auditOf(orgA, 'risk_profile.activated', v1))?.metadata).toMatchObject({
      versionId: v1,
      previousVersionId: null,
    });
    const profile = await ctx.prisma.riskScoringProfile.findFirstOrThrow({
      where: { organizationId: orgA.id },
    });
    expect(profile).toMatchObject({ activeVersionId: row.id, version: 2 });
  });

  it('keeps published versions immutable (route and repository)', async () => {
    const put = await ctx.http
      .put(`${VERSIONS}/${v1}`)
      .set(headers(adminA))
      .send({ overrides: {}, expectedRowVersion: 3 })
      .expect(409);
    expect(put.body.code).toBe('risk_profile_version_immutable');
    await ctx.http.delete(`${VERSIONS}/${v1}`).set(headers(adminA)).expect(409);
    const row = await ctx.prisma.riskScoringProfileVersion.findFirstOrThrow({
      where: { publicId: v1 },
    });
    // The repository's own guard: a draft-only update matches no published row.
    const repo = ctx.get(RiskProfilesRepository);
    const changed = await ctx.prisma.$transaction((tx) =>
      repo.updateDraft(
        tx,
        systemScope(orgA.id),
        row.id,
        row.rowVersion,
        { overrides: {}, overridesSha256: 'f'.repeat(64), changeNote: null },
        null,
      ),
    );
    expect(changed).toBe(false);
    const after = await ctx.prisma.riskScoringProfileVersion.findFirstOrThrow({
      where: { publicId: v1 },
    });
    expect(after).toEqual(row);
  });

  it('activates (rollback) and resets with the pointer CAS, audited', async () => {
    v2 = (await ctx.http.post(VERSIONS).set(headers(adminA)).send({}).expect(201)).body
      .id as string;
    await ctx.http
      .post(`${VERSIONS}/${v2}/activate`)
      .set(idem())
      .set(headers(adminA))
      .expect(409)
      .expect((res) => expect(res.body.code).toBe('risk_profile_version_not_published'));
    await ctx.http
      .post(`${VERSIONS}/${v2}/publish`)
      .set(idem())
      .set(headers(adminA))
      .send({ expectedRowVersion: 1 })
      .expect(200);
    const rollback = await ctx.http
      .post(`${VERSIONS}/${v1}/activate`)
      .set(idem())
      .set(headers(adminA))
      .send({ expectedProfileVersion: 3 })
      .expect(200);
    expect(rollback.body.active.versionId).toBe(v1);
    expect((await auditOf(orgA, 'risk_profile.activated', v1))?.metadata).toMatchObject({
      previousVersionId: v2,
      previousVersionNo: 2,
    });
    const stale = await ctx.http
      .post('/api/v1/risk-scoring/profile/reset')
      .set(idem())
      .set(headers(adminA))
      .send({ expectedProfileVersion: 1 })
      .expect(409);
    expect(stale.body).toMatchObject({ currentProfileVersion: 4 });
    // Re-activate v1 for the dry-run below after checking reset.
    const reset = await ctx.http
      .post('/api/v1/risk-scoring/profile/reset')
      .set(idem())
      .set(headers(adminA))
      .expect(200);
    expect(reset.body.active.source).toBe('platform');
    const profile = await ctx.prisma.riskScoringProfile.findFirstOrThrow({
      where: { organizationId: orgA.id },
    });
    expect(profile.activeVersionId).toBeNull();
    expect(
      await ctx.prisma.auditLog.findFirst({
        where: { organizationId: orgA.id, action: 'risk_profile.reset' },
      }),
    ).toBeTruthy();
    await ctx.http.post(`${VERSIONS}/${v1}/activate`).set(idem()).set(headers(adminA)).expect(200);

    // Replica reads.
    await expect
      .poll(async () => {
        const res = await ctx.http.get('/api/v1/risk-scoring/profile').set(headers(readOnlyA));
        return res.body.active?.versionId as string | undefined;
      }, POLL)
      .toBe(v1);
  });

  it('caps versions per organization and isolates organizations', async () => {
    const existing = await ctx.prisma.riskScoringProfileVersion.count({
      where: { organizationId: orgA.id },
    });
    for (let i = existing; i < 10; i += 1) {
      await ctx.http.post(VERSIONS).set(headers(adminA)).send({}).expect(201);
    }
    const capped = await ctx.http.post(VERSIONS).set(headers(adminA)).send({}).expect(409);
    expect(capped.body).toMatchObject({ code: 'risk_profile_limit_reached', limit: 10 });

    await ctx.http.get(`${VERSIONS}/${v1}`).set(headers(adminB)).expect(404);
    await ctx.http.post(`${VERSIONS}/${v1}/activate`).set(idem()).set(headers(adminB)).expect(404);
    await ctx.http.delete(`${VERSIONS}/${v2}`).set(headers(adminB)).expect(404);
    const b = await ctx.http.post(VERSIONS).set(headers(adminB)).send({}).expect(201);
    expect(b.body.versionNo).toBe(1);
    await expect
      .poll(async () => {
        const res = await ctx.http.get(VERSIONS).set(headers(adminB));
        return (res.body.data as { id: string }[] | undefined)?.map((v) => v.id);
      }, POLL)
      .toEqual([b.body.id]);
  });
});

describe('dry-run and the scans read API risk section (R12, R15)', () => {
  let message: LifecycleMessage;
  let scanId: bigint;
  let stored: Awaited<ReturnType<typeof insertScoredRound>>['result'];

  beforeAll(async () => {
    message = await insertLifecycleMessage(ctx, orgA, { state: 'scanned' });
    const v1 = await ctx.prisma.riskScoringProfileVersion.findFirstOrThrow({
      where: { organizationId: orgA.id, versionNo: 1 },
    });
    const round = await insertScoredRound(message, {
      id: v1.id,
      publicId: v1.publicId,
      versionNo: 1,
      overrides: v1.overrides,
    });
    scanId = round.scanId;
    stored = round.result;
  });

  const url = () => `/api/v1/messages/${message.publicId}/scans/${scanId.toString()}/risk/dry-run`;

  it('reproduces the stored score with profile active and writes nothing', async () => {
    const count = async () => ({
      scores: await ctx.prisma.messageRiskScore.count({ where: { organizationId: orgA.id } }),
      audits: await ctx.prisma.auditLog.count({ where: { organizationId: orgA.id } }),
      outbox: await ctx.prisma.messageOutbox.count({ where: { organizationId: orgA.id } }),
      versions: await ctx.prisma.riskScoringProfileVersion.findMany({
        where: { organizationId: orgA.id },
        orderBy: { id: 'asc' },
      }),
      profile: await ctx.prisma.riskScoringProfile.findFirst({
        where: { organizationId: orgA.id },
      }),
      scan: await ctx.prisma.emailScan.findFirst({ where: { id: scanId } }),
    });
    const before = await count();
    let body: Record<string, unknown> = {};
    await expect
      .poll(async () => {
        const res = await ctx.http.post(url()).set(headers(analystA)).send({ profile: 'active' });
        body = res.body as Record<string, unknown>;
        return res.status;
      }, POLL)
      .toBe(200);
    expect(body.reproducible).toBe(true);
    expect(body.stored).toMatchObject({
      revision: 0,
      score: stored.score,
      level: stored.level,
      inputSha256: stored.inputSha256,
      profileSha256: stored.versions.profile.sha256,
    });
    expect(body.result).toEqual(JSON.parse(JSON.stringify({ ...stored, revision: 0 })));
    const platform = await ctx.http
      .post(url())
      .set(headers(analystA))
      .send({ profile: 'platform' })
      .expect(200);
    expect(platform.body.result.inputSha256).toBe(stored.inputSha256);
    expect(platform.body.result.versions.profile.source).toBe('platform');
    expect(await count()).toEqual(before);

    await ctx.http.post(url()).set(headers(readOnlyA)).send({ profile: 'active' }).expect(403);
    const foreign = await ctx.http
      .post(url())
      .set(headers(adminB))
      .send({ profile: 'active' })
      .expect(404);
    expect(foreign.body.code).toBe('message_not_found');
    const revision1 = await ctx.http
      .post(url())
      .set(headers(analystA))
      .send({ profile: 'active', revision: 1 })
      .expect(409);
    expect(revision1.body.code).toBe('risk_revision_unavailable');
  });

  it('shows the stored score in GET /messages/{messageId}/scans (public ids only)', async () => {
    let risk: Array<Record<string, unknown>> = [];
    await expect
      .poll(async () => {
        const res = await ctx.http
          .get(`/api/v1/messages/${message.publicId}/scans`)
          .set(headers(readOnlyA));
        risk = (res.body.data?.[0]?.risk ?? []) as Array<Record<string, unknown>>;
        return risk.length;
      }, POLL)
      .toBe(1);
    expect(risk[0]).toMatchObject({
      revision: 0,
      score: stored.score,
      level: stored.level,
      recommendedAction: stored.recommendedAction,
      inputSha256: stored.inputSha256,
      versions: { profile: { source: 'tenant', id: stored.versions.profile.id, versionNo: 1 } },
    });
    expect(JSON.stringify(risk)).not.toContain('profileVersionId');
    const res = await ctx.http
      .get(`/api/v1/messages/${message.publicId}/scans`)
      .set(headers(adminB))
      .expect(404);
    expect(res.body.code).toBe('message_not_found');
  });
});

describe('organization purge (step 5.1 §3)', () => {
  it('deletes the scores, versions and profile of one organization only, resumably', async () => {
    const orgC = await fx.createOrganization();
    fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgC.id]));
    fx.registerCleanup(() => purgeRisk([orgC.id]));
    const adminC = await tokenOf(
      await fx.createUser(orgC, { roles: ['organization_admin'], mfa: true }),
    );
    const v = (await ctx.http.post(VERSIONS).set(headers(adminC)).send({}).expect(201)).body
      .id as string;
    await ctx.http
      .post(`${VERSIONS}/${v}/publish`)
      .set(idem())
      .set(headers(adminC))
      .send({ expectedRowVersion: 1 })
      .expect(200);
    await ctx.http.post(VERSIONS).set(headers(adminC)).send({}).expect(201);
    const message = await insertLifecycleMessage(ctx, orgC, { state: 'scanned' });
    await insertScoredRound(message, null);
    const othersBefore = await ctx.prisma.riskScoringProfileVersion.count({
      where: { organizationId: orgA.id },
    });

    const repo = ctx.get(RiskTenantDataRepository);
    const counts = await repo.purgeOrganization(systemScope(orgC.id), 1);
    expect(Object.keys(counts)).toEqual([...RISK_PURGE_ORDER]);
    expect(counts.risk_scoring_profile_versions).toBe(2);
    expect(counts.risk_scoring_profiles).toBe(1);
    expect(counts.message_risk_scores).toBe(1);
    const where = { organizationId: orgC.id };
    expect(
      await Promise.all([
        ctx.prisma.messageRiskScore.count({ where }),
        ctx.prisma.riskScoringProfileVersion.count({ where }),
        ctx.prisma.riskScoringProfile.count({ where }),
      ]),
    ).toEqual([0, 0, 0]);
    expect(
      await ctx.prisma.riskScoringProfileVersion.count({ where: { organizationId: orgA.id } }),
    ).toBe(othersBefore);
    expect(Object.values(await repo.purgeOrganization(systemScope(orgC.id)))).toEqual([0, 0, 0]);
  });
});
