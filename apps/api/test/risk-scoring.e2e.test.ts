/**
 * Step 5.1 risk scoring routes (R10, R15, §9.4) over HTTP with MySQL, Redis and S3 stubbed: the
 * real controllers, validation, guards, services and writer run against an in-memory profile
 * store with the repository's semantics (tenant filter, draft-only updates with row-version
 * compare-and-set, the pointer CAS, transaction rollback). Covered: authorization per route
 * (`policy:read` / `policy:manage` / `policy:publish`, the dry-run needing `policy:manage` and
 * `message:read`, the seeded read-only user refused every write), the draft → publish →
 * activate → rollback → reset lifecycle with its audit rows, bounds errors with violations by
 * path, immutability, the version limit, isolation between two organizations, the dry-run
 * response shape and that it writes nothing, and the `risk` section of the scans read API
 * from a stored `message_risk_scores` row. The same routes run against the real MySQL writer
 * and replica in integration/risk-scoring.test.ts.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import {
  configureHttpApp,
  PrismaReadService,
  PrismaService,
  RedisService,
  S3Service,
} from '@email-gateway/common';
import { Prisma, SYSTEM_ROLES } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import {
  buildScoringInput,
  platformProfile,
  riskResultToRowJson,
  scoreRisk,
} from '@email-gateway/risk-scoring';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { AppModule } from '../src/app.module';
import { AuditService } from '../src/audit/audit.service';
import type { ApiKeyPrincipal } from '../src/auth-contracts/principal';
import type { TenantScope } from '../src/auth-contracts/tenant-scope';
import { loadApiConfig } from '../src/config';
import { TransactionRunner } from '../src/database/transaction-runner';
import { EmailSender } from '../src/email/email-sender';
import { configureApiApp } from '../src/http/configure-api-app';
import { KeyValueStore } from '../src/kv/key-value-store';
import { ApiKeyAuthenticatorService } from '../src/modules/auth/services/api-key-authenticator.service';
import type { PrincipalSnapshot } from '../src/modules/auth/services/principal-cache.service';
import { PrincipalLoaderService } from '../src/modules/auth/services/principal-loader.service';
import { SessionService } from '../src/modules/auth/services/session.service';
import { TokenService } from '../src/modules/auth/services/token.service';
import { MessageLifecycleReadRepository } from '../src/modules/messages/repositories/message-lifecycle-read.repository';
import { MessageScansReadRepository } from '../src/modules/messages/repositories/message-scans-read.repository';
import { roundRowsOf } from '../src/modules/risk-scoring/domain/risk-dry-run';
import {
  type DryRunRows,
  RiskDryRunRepository,
} from '../src/modules/risk-scoring/repositories/risk-dry-run.repository';
import { RiskProfilesRepository } from '../src/modules/risk-scoring/repositories/risk-profiles.repository';
import { InMemoryKeyValueStore } from './support/in-memory-key-value-store';
import { InMemoryRiskProfiles } from './support/in-memory-risk-profiles';
import { RecordingEmailSender } from './support/recording-email-sender';
import { TEST_DOMAIN_ENV } from './support/test-env';

const env = {
  ...TEST_DOMAIN_ENV,
  NODE_ENV: 'test',
  HTTP_PORT: '3000',
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'us-east-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  AUTH_JWT_SECRET: randomBytes(32).toString('hex'),
  AUTH_TOKEN_PEPPER: randomBytes(32).toString('hex'),
  DATA_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
  AUTH_BACKGROUND_JOBS_ENABLED: 'false',
  RISK_PROFILE_MAX_VERSIONS: '10',
};

const roleOf = (key: string): string[] => [
  ...SYSTEM_ROLES.find((role) => role.key === key)!.permissions,
];
const READ_ONLY = roleOf('read_only_user');
const ANALYST = roleOf('security_analyst');
const ADMIN = roleOf('organization_admin');

const ORGS = {
  A: { id: '1', publicId: randomUUID() },
  B: { id: '2', publicId: randomUUID() },
} as const;
type OrgKey = keyof typeof ORGS;
const USER = { id: '10', publicId: randomUUID() };
const SESSION = randomUUID();
const MESSAGE_ID = '0190f0f0-0000-7000-8000-0000000000f1';
const RECEIVED = new Date('2026-11-10T10:00:00.000Z');
const COMPLETED = new Date('2026-11-10T10:00:05.000Z');
const SCAN = '900';

let snapshot: PrincipalSnapshot;
let currentOrg: OrgKey = 'A';
function principalWith(permissions: string[], org: OrgKey = 'A'): void {
  currentOrg = org;
  snapshot = {
    orgVersion: 0,
    userVersion: '',
    user: {
      id: USER.id,
      publicId: USER.publicId,
      status: 'active',
      deleted: false,
      mfaEnabled: true,
    },
    org: {
      id: ORGS[org].id,
      publicId: ORGS[org].publicId,
      kind: 'customer',
      status: 'active',
      deleted: false,
      mfaRequired: false,
    },
    permissions,
  };
}

let apiKeyPermissions = new Set<string>(['policy:read']);
const apiKeyPrincipal = (): ApiKeyPrincipal => ({
  kind: 'api_key',
  apiKeyId: 5n,
  apiKeyPublicId: randomUUID(),
  organizationId: 1n,
  organizationPublicId: ORGS.A.publicId,
  permissions: apiKeyPermissions,
});

// The round of the dry-run and the scans read API: rspamd suspicious score, a DLP alert.
const message = {
  id: 77n,
  publicId: MESSAGE_ID,
  receivedAt: RECEIVED,
  organizationId: 1n,
  direction: 'inbound' as const,
  attachmentCount: 0,
  recipientCount: 1,
};
const scanRow = {
  id: 900n,
  messageId: 77n,
  receivedAt: RECEIVED,
  organizationId: 1n,
  lifecycleRound: 0,
  scanKind: 'initial' as const,
  status: 'completed' as const,
  requiredEngines: ['rspamd', 'dlp'],
  riskProfileVersionId: null as bigint | null,
};
const finalRow = (
  engine: string,
  outcome: string,
  reasonCodes: string[],
  score: string | null,
) => ({
  engine,
  outcome: outcome as DryRunRows['finals'][number]['outcome'],
  errorCode: null,
  reasonCodes,
  score: score === null ? null : new Prisma.Decimal(score),
  engineVersion: `${engine}/1`,
  settingsVersion: `${engine}-map/1;p=000000000000;t=none`,
  attempt: 1,
  completedAt: COMPLETED,
});
const rows: DryRunRows = {
  finals: [
    finalRow('dlp', 'suspicious', ['dlp.action.alert', 'dlp.payment_card.number'], null),
    finalRow('rspamd', 'spam', ['spam.suspicious_score'], '7.25'),
  ],
  auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarcPolicy: 'reject', arc: 'none' },
  bec: null,
  dlp: {
    action: 'alert',
    verdict: 'suspicious',
    coverage: 'complete',
    categories: [{ category: 'payment_card', count: 1, maxSeverity: 'high', maxConfidence: 0.9 }],
  },
};
// The stored revision-0 score as the email-worker writes it (platform default, R11 mapping).
const storedResult = scoreRisk(
  buildScoringInput(roundRowsOf(message, scanRow, rows), 0),
  platformProfile('rsk-default/1'),
);
const storedRow = {
  scanId: 900n,
  revision: 0,
  ...riskResultToRowJson(storedResult),
  createdAt: COMPLETED,
};

describe('step 5.1 risk scoring routes (e2e, dependencies stubbed)', () => {
  let app: INestApplication;
  const kv = new InMemoryKeyValueStore();
  const tokens = new TokenService(loadApiConfig(env));
  const http = () => request(app.getHttpServer());
  let store = new InMemoryRiskProfiles();
  const audit = {
    actorFrom: () => ({ type: 'user', id: USER.publicId }),
    record: vi.fn((_entry: Record<string, unknown>, _tx?: unknown) => Promise.resolve()),
  };
  const dryRunReads = {
    message: vi.fn((scope: TenantScope, id: string) =>
      Promise.resolve(scope.organizationId === 1n && id === MESSAGE_ID ? message : null),
    ),
    scan: vi.fn((_s: TenantScope, _m: unknown, id: bigint) =>
      Promise.resolve(id === 900n ? scanRow : null),
    ),
    roundRows: vi.fn(() => Promise.resolve(rows)),
    storedScore: vi.fn((_s: unknown, _m: unknown, _id: bigint, revision: number) =>
      Promise.resolve(
        revision === 0
          ? {
              revision: 0,
              score: storedRow.score,
              level: storedRow.level,
              recommendedAction: storedRow.recommendedAction,
              inputSha256: storedRow.inputSha256,
              profileSha256: storedRow.profileSha256,
            }
          : null,
      ),
    ),
  };
  const scanReads = {
    rounds: vi.fn(() =>
      Promise.resolve([
        {
          id: 900n,
          lifecycleRound: 0,
          scanKind: 'initial',
          status: 'completed',
          scanVerdict: 'spam',
          reasonCodes: [],
          requiredEngines: ['rspamd', 'dlp'],
          startedAt: null,
          completedAt: COMPLETED,
          deadlineAt: null,
        },
      ]),
    ),
    engineResults: vi.fn(() => Promise.resolve([] as unknown[])),
    authResults: () => Promise.resolve([]),
    attachmentResults: () => Promise.resolve([]),
    attachmentParts: () => Promise.resolve([]),
    sandboxSubmissions: () => Promise.resolve([]),
    riskScores: vi.fn(() => Promise.resolve([storedRow] as unknown[])),
  };

  const bearer = async () => {
    const { token } = await tokens.issue({
      userPublicId: USER.publicId,
      organizationPublicId: ORGS[currentOrg].publicId,
      sessionId: SESSION,
      amr: ['pwd', 'otp'],
    });
    return { Authorization: `Bearer ${token}` };
  };
  const apiKey = { 'X-API-Key': `egk_${'a'.repeat(12)}_${'b'.repeat(43)}` };
  const actions = () => audit.record.mock.calls.map(([entry]) => entry.action);
  const as = async (permissions: string[], org: OrgKey = 'A') => {
    principalWith(permissions, org);
    kv.entries.clear();
    return bearer();
  };
  const dryRunUrl = `/api/v1/messages/${MESSAGE_ID}/scans/${SCAN}/risk/dry-run`;
  const versions = '/api/v1/risk-scoring/profile/versions';

  beforeAll(async () => {
    const cfg = loadApiConfig(env);
    const stub = (healthName: string) => ({ healthName, checkHealth: () => Promise.resolve() });
    // The store instance is swapped per test; the providers delegate to the current one.
    const repository = new Proxy(
      {},
      { get: (_t, key: string) => (store.repository as unknown as Record<string, unknown>)[key] },
    );
    const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(cfg)] })
      .overrideProvider(PrismaService)
      .useValue(stub('mysql'))
      .overrideProvider(PrismaReadService)
      .useValue(stub('mysql-reader'))
      .overrideProvider(RedisService)
      .useValue(stub('redis'))
      .overrideProvider(S3Service)
      .useValue(stub('s3'))
      .overrideProvider(KeyValueStore)
      .useValue(kv)
      .overrideProvider(EmailSender)
      .useValue(new RecordingEmailSender())
      .overrideProvider(SessionService)
      .useValue({ isRevoked: () => Promise.resolve(false), isLive: () => Promise.resolve(true) })
      .overrideProvider(PrincipalLoaderService)
      .useValue({ load: () => Promise.resolve(snapshot) })
      .overrideProvider(ApiKeyAuthenticatorService)
      .useValue({ authenticate: () => Promise.resolve(apiKeyPrincipal()) })
      .overrideProvider(TransactionRunner)
      .useValue({
        run: (fn: (tx: unknown) => Promise<unknown>, options: unknown) =>
          store.transactions.run(fn as never, options),
      })
      .overrideProvider(AuditService)
      .useValue(audit)
      .overrideProvider(RiskProfilesRepository)
      .useValue(repository)
      .overrideProvider(RiskDryRunRepository)
      .useValue(dryRunReads)
      .overrideProvider(MessageLifecycleReadRepository)
      .useValue({
        findMessage: (scope: TenantScope, publicId: string) =>
          Promise.resolve(
            scope.organizationId === 1n && publicId === MESSAGE_ID
              ? {
                  id: 77n,
                  publicId,
                  receivedAt: RECEIVED,
                  direction: 'inbound',
                  status: 'scanned',
                  statusReason: null,
                  version: 3,
                  lifecycleRound: 0,
                  statusChangedAt: COMPLETED,
                }
              : null,
          ),
      })
      .overrideProvider(MessageScansReadRepository)
      .useValue(scanReads)
      .compile();
    app = moduleRef.createNestApplication({ logger: false });
    configureHttpApp(app, createLogger({ service: 'api-test', level: 'silent' }));
    configureApiApp(app, cfg);
    await app.init();
  });

  afterAll(async () => {
    await app?.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    kv.entries.clear();
    store = new InMemoryRiskProfiles();
    store.users.set(10n, USER.publicId);
    apiKeyPermissions = new Set(['policy:read']);
    principalWith(ADMIN);
  });

  it('answers 401 without credentials on every route', async () => {
    const id = randomUUID();
    await http().get('/api/v1/risk-scoring/platform-profile').expect(401);
    await http().get('/api/v1/risk-scoring/profile').expect(401);
    await http().get(versions).expect(401);
    await http().get(`${versions}/${id}`).expect(401);
    await http().post(versions).send({}).expect(401);
    await http().put(`${versions}/${id}`).send({}).expect(401);
    await http().delete(`${versions}/${id}`).expect(401);
    await http().post(`${versions}/${id}/publish`).send({}).expect(401);
    await http().post(`${versions}/${id}/activate`).send({}).expect(401);
    await http().post('/api/v1/risk-scoring/profile/reset').send({}).expect(401);
    await http().post(dryRunUrl).send({ profile: 'active' }).expect(401);
  });

  it('serves the platform profile, bounds, signal map and hard blocks to policy:read', async () => {
    const res = await http()
      .get('/api/v1/risk-scoring/platform-profile')
      .set(await as(READ_ONLY))
      .expect(200);
    expect(res.body).toMatchObject({
      id: 'rsk-default/1',
      versions: { scorer: 'risk-score/1', signalMap: 'risk-signals/1', input: 'risk-input/1' },
      bounds: { thresholds: { low: { min: 50, max: 250 } }, thresholdMinGap: 50 },
      profile: { thresholds: { low: 100, medium: 300, high: 550, critical: 800 } },
    });
    expect(res.body.signals.length).toBeGreaterThan(50);
    expect(res.body.hardBlocks).toHaveLength(9);
    expect(res.body.notice).toContain('not validated detection accuracy');
    // API keys with policy:read too; without it 403.
    await http().get('/api/v1/risk-scoring/profile').set(apiKey).expect(200);
    await http()
      .get('/api/v1/risk-scoring/platform-profile')
      .set(await as(['message:read']))
      .expect(403);
  });

  it('runs the draft → publish → activate → rollback → reset lifecycle with RBAC and audit rows', async () => {
    // The seeded read-only user (policy:read, message:read) reads but never writes.
    const readOnly = await as(READ_ONLY);
    const empty = await http().get('/api/v1/risk-scoring/profile').set(readOnly).expect(200);
    expect(empty.body).toMatchObject({
      id: null,
      profileVersion: 0,
      active: { source: 'platform', versionId: null, profileId: 'rsk-default/1' },
      counts: { drafts: 0, published: 0, limit: 10 },
    });
    await http().post(versions).set(readOnly).send({ overrides: {} }).expect(403);
    await http().post(dryRunUrl).set(readOnly).send({ profile: 'active' }).expect(403);

    // policy:manage (security analyst) creates and edits drafts but cannot publish.
    const analyst = await as(ANALYST);
    const created = await http()
      .post(versions)
      .set(analyst)
      .send({ overrides: { actions: { medium: 'quarantine' } }, changeNote: 'hold medium' })
      .expect(201);
    expect(created.body).toMatchObject({
      versionNo: 1,
      status: 'draft',
      rowVersion: 1,
      active: false,
      createdByUserId: USER.publicId,
      resolved: { valid: true },
    });
    const v1 = created.body.id as string;
    const updated = await http()
      .put(`${versions}/${v1}`)
      .set(analyst)
      .send({ overrides: { actions: { medium: 'require_approval' } }, expectedRowVersion: 1 })
      .expect(200);
    expect(updated.body).toMatchObject({ rowVersion: 2, changeNote: 'hold medium' });
    await http()
      .post(`${versions}/${v1}/publish`)
      .set(analyst)
      .send({ expectedRowVersion: 2 })
      .expect(403);
    await http().post(`${versions}/${v1}/activate`).set(analyst).send({}).expect(403);
    await http().post('/api/v1/risk-scoring/profile/reset').set(analyst).send({}).expect(403);

    // policy:publish (organization admin) publishes and activates (activate defaults to true).
    const admin = await as(ADMIN);
    const published = await http()
      .post(`${versions}/${v1}/publish`)
      .set(admin)
      .send({ expectedRowVersion: 2 })
      .expect(200);
    expect(published.body.version).toMatchObject({
      status: 'published',
      active: true,
      publishedByUserId: USER.publicId,
    });
    expect(published.body.version.profileSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(published.body.profile.active).toMatchObject({
      source: 'tenant',
      versionId: v1,
      versionNo: 1,
      profileId: `rsk-default/1+t:${v1}#1`,
    });

    // Immutable afterwards.
    for (const res of [
      await http()
        .put(`${versions}/${v1}`)
        .set(admin)
        .send({ overrides: {}, expectedRowVersion: 3 })
        .expect(409),
      await http().delete(`${versions}/${v1}`).set(admin).expect(409),
      await http()
        .post(`${versions}/${v1}/publish`)
        .set(admin)
        .send({ expectedRowVersion: 3 })
        .expect(409),
    ]) {
      expect(res.body.code).toBe('risk_profile_version_immutable');
    }

    // A second version, published without activation; a draft cannot be activated.
    const v2 = (await http().post(versions).set(admin).send({ basedOnVersionId: v1 }).expect(201))
      .body.id as string;
    const draftActivate = await http().post(`${versions}/${v2}/activate`).set(admin).expect(409);
    expect(draftActivate.body.code).toBe('risk_profile_version_not_published');
    await http()
      .post(`${versions}/${v2}/publish`)
      .set(admin)
      .send({ activate: false, expectedRowVersion: 1 })
      .expect(200);
    const switched = await http()
      .post(`${versions}/${v2}/activate`)
      .set(admin)
      .send({ expectedProfileVersion: 2 })
      .expect(200);
    expect(switched.body.active).toMatchObject({ versionId: v2, versionNo: 2 });
    const stale = await http()
      .post(`${versions}/${v1}/activate`)
      .set(admin)
      .send({ expectedProfileVersion: 2 })
      .expect(409);
    expect(stale.body).toMatchObject({
      code: 'risk_profile_version_conflict',
      currentProfileVersion: 3,
    });
    // Rollback to v1, then reset to the platform default.
    await http().post(`${versions}/${v1}/activate`).set(admin).expect(200);
    const reset = await http().post('/api/v1/risk-scoring/profile/reset').set(admin).expect(200);
    expect(reset.body).toMatchObject({
      active: { source: 'platform', versionId: null },
      counts: { drafts: 0, published: 2 },
    });

    const list = await http().get(`${versions}?status=published`).set(readOnly).expect(200);
    expect(list.body.data.map((v: { id: string }) => v.id)).toEqual([v2, v1]);

    expect(actions()).toEqual([
      'risk_profile.draft_created',
      'risk_profile.draft_updated',
      'risk_profile.published',
      'risk_profile.activated',
      'risk_profile.draft_created',
      'risk_profile.published',
      'risk_profile.activated',
      'risk_profile.activated',
      'risk_profile.reset',
    ]);
    const entries = audit.record.mock.calls.map(([entry]) => entry);
    expect(entries[0]).toMatchObject({
      organizationId: 1n,
      resourceType: 'risk_scoring_profile_version',
      resourceId: v1,
      metadata: { versionId: v1, versionNo: 1, changedPaths: ['actions.medium'] },
    });
    expect(entries[7]).toMatchObject({
      metadata: { versionId: v1, previousVersionId: v2, previousVersionNo: 2 },
    });
    // Audit metadata never carries the note or override values.
    const metadata = JSON.stringify(entries.map((e) => e.metadata));
    expect(metadata).not.toContain('hold medium');
    expect(metadata).not.toContain('require_approval');
  });

  it('refuses invalid overrides with violations by path, and malformed bodies with 400', async () => {
    const admin = await as(ADMIN);
    const res = await http()
      .post(versions)
      .set(admin)
      .send({
        overrides: {
          thresholds: { low: 20, high: 380 },
          hardBlocks: { 'hb.malware_attachment': { enabled: false } },
          unknownSection: {},
        },
      })
      .expect(400);
    expect(res.body.code).toBe('risk_profile_invalid');
    const paths = (res.body.violations as Array<{ path: string }>).map((v) => v.path);
    expect(paths).toEqual(expect.arrayContaining(['unknownSection']));
    const valid = await http()
      .post(versions)
      .set(admin)
      .send({ overrides: { thresholds: { low: 20, high: 380 } } })
      .expect(400);
    expect((valid.body.violations as Array<{ path: string }>).map((v) => v.path)).toEqual(
      expect.arrayContaining(['thresholds.low', 'thresholds.high']),
    );
    const locked = await http()
      .post(versions)
      .set(admin)
      .send({ overrides: { hardBlocks: { 'hb.malware_attachment': { enabled: false } } } })
      .expect(400);
    expect(locked.body.violations).toEqual([
      { path: 'hardBlocks.hb.malware_attachment.enabled', message: 'locked on' },
    ]);
    // Standard validation (before any database access).
    await http().post(versions).set(admin).send({ overrides: [] }).expect(400);
    await http()
      .post(versions)
      .set(admin)
      .send({ overrides: {}, changeNote: 'x'.repeat(513) })
      .expect(400);
    await http().post(versions).set(admin).send({ overrides: {}, extra: 1 }).expect(400);
    await http().get(`${versions}/not-a-uuid`).set(admin).expect(400);
    await http().post(dryRunUrl).set(admin).send({ profile: 'tenant' }).expect(400);
    expect(store.versions).toEqual([]);
    expect(audit.record).not.toHaveBeenCalled();
  });

  it('caps versions at RISK_PROFILE_MAX_VERSIONS (409 risk_profile_limit_reached)', async () => {
    const admin = await as(ADMIN);
    for (let i = 0; i < 10; i += 1) await http().post(versions).set(admin).send({}).expect(201);
    const res = await http().post(versions).set(admin).send({}).expect(409);
    expect(res.body).toMatchObject({ code: 'risk_profile_limit_reached', limit: 10 });
    const last = store.versions.at(-1)!;
    await http().delete(`${versions}/${last.publicId}`).set(admin).expect(204);
    await http().post(versions).set(admin).send({}).expect(201);
  });

  it('isolates two organizations (404, empty lists, own active profile)', async () => {
    const adminA = await as(ADMIN, 'A');
    const v1 = (await http().post(versions).set(adminA).send({}).expect(201)).body.id as string;
    await http()
      .post(`${versions}/${v1}/publish`)
      .set(adminA)
      .send({ expectedRowVersion: 1 })
      .expect(200);

    const adminB = await as(ADMIN, 'B');
    await http().get(`${versions}/${v1}`).set(adminB).expect(404);
    for (const res of [
      await http()
        .put(`${versions}/${v1}`)
        .set(adminB)
        .send({ overrides: {}, expectedRowVersion: 2 })
        .expect(404),
      await http().delete(`${versions}/${v1}`).set(adminB).expect(404),
      await http().post(`${versions}/${v1}/activate`).set(adminB).expect(404),
      await http()
        .post(`${versions}/${v1}/publish`)
        .set(adminB)
        .send({ expectedRowVersion: 2 })
        .expect(404),
      await http().post(versions).set(adminB).send({ basedOnVersionId: v1 }).expect(404),
    ]) {
      expect(res.body.code).toBe('risk_profile_version_not_found');
    }
    expect((await http().get(versions).set(adminB).expect(200)).body.data).toEqual([]);
    const profileB = await http().get('/api/v1/risk-scoring/profile').set(adminB).expect(200);
    expect(profileB.body.active.source).toBe('platform');
    // Organization B's dry-run of organization A's message: 404, and B cannot use A's version.
    const dry = await http().post(dryRunUrl).set(adminB).send({ profile: 'active' }).expect(404);
    expect(dry.body.code).toBe('message_not_found');
    const adminA2 = await as(ADMIN, 'A');
    const profileA = await http().get('/api/v1/risk-scoring/profile').set(adminA2).expect(200);
    expect(profileA.body.active).toMatchObject({ source: 'tenant', versionId: v1 });
  });

  it('dry-runs a stored round: response shape, reproducible with profile active, writes nothing', async () => {
    const analyst = await as(ANALYST);
    const draft = (
      await http()
        .post(versions)
        .set(analyst)
        .send({ overrides: { thresholds: { low: 50, medium: 200 } } })
        .expect(201)
    ).body.id as string;
    vi.clearAllMocks();
    const calls = store.calls.length;
    const transactions = store.txOptions.length;

    const active = await http()
      .post(dryRunUrl)
      .set(analyst)
      .send({ profile: 'active' })
      .expect(200);
    expect(active.body).toEqual({
      result: JSON.parse(JSON.stringify({ ...storedResult, revision: 0 })),
      stored: {
        revision: 0,
        score: storedRow.score,
        level: storedRow.level,
        recommendedAction: storedRow.recommendedAction,
        inputSha256: storedRow.inputSha256,
        profileSha256: storedRow.profileSha256,
      },
      reproducible: true,
    });
    const byDraft = await http()
      .post(dryRunUrl)
      .set(analyst)
      .send({ profile: { versionId: draft } })
      .expect(200);
    expect(byDraft.body.result.versions.profile).toMatchObject({ source: 'tenant', versionNo: 1 });
    expect(byDraft.body.reproducible).toBe(true);
    const inline = await http()
      .post(dryRunUrl)
      .set(analyst)
      .send({ profile: { overrides: { thresholds: { medium: 250 } } }, revision: 0 })
      .expect(200);
    expect(inline.body.result.versions.profile.id).toBe('rsk-default/1+t:inline');
    const platform = await http()
      .post(dryRunUrl)
      .set(analyst)
      .send({ profile: 'platform' })
      .expect(200);
    expect(platform.body.result.score).toBe(storedRow.score);

    const revision1 = await http()
      .post(dryRunUrl)
      .set(analyst)
      .send({ profile: 'active', revision: 1 })
      .expect(409);
    expect(revision1.body.code).toBe('risk_revision_unavailable');
    const otherScan = await http()
      .post(`/api/v1/messages/${MESSAGE_ID}/scans/901/risk/dry-run`)
      .set(analyst)
      .send({ profile: 'active' })
      .expect(404);
    expect(otherScan.body.code).toBe('scan_not_found');

    // Nothing written: no transaction, no write repository call, no audit row.
    expect(store.txOptions).toHaveLength(transactions);
    expect(store.calls.slice(calls).every((c) => ['findVersion', 'versionById'].includes(c))).toBe(
      true,
    );
    expect(audit.record).not.toHaveBeenCalled();
  });

  it('shows the stored risk scores in the scans read API (message:read; public ids only)', async () => {
    const res = await http()
      .get(`/api/v1/messages/${MESSAGE_ID}/scans`)
      .set(await as(['message:read']))
      .expect(200);
    const [round] = res.body.data;
    expect(round.risk).toHaveLength(1);
    expect(round.risk[0]).toMatchObject({
      revision: 0,
      status: 'scored',
      score: storedResult.score,
      level: storedResult.level,
      verdict: storedResult.verdict,
      recommendedAction: storedResult.recommendedAction,
      inputSha256: storedResult.inputSha256,
      versions: { profile: { source: 'platform', id: 'rsk-default/1', versionNo: null } },
      createdAt: COMPLETED.toISOString(),
    });
    expect(round.risk[0].explanation.text).toContain('Risk ');
    expect(JSON.stringify(round.risk)).not.toContain('profileVersionId');
    expect(scanReads.riskScores).toHaveBeenCalledWith(
      expect.objectContaining({ organizationId: 1n }),
      expect.objectContaining({ id: 77n }),
      [900n],
    );
  });
});
