/**
 * Quarantine routes (step 5.3 Q26) over HTTP with the repositories, the object store, the
 * lifecycle door, the idempotency store and the audit trail replaced by an in-memory world
 * (test/support/in-memory-quarantine.ts): authentication and RBAC per permission (mailbox users
 * reach only the /me routes), users-only and MFA routes, tenant isolation (another
 * organization's entry is 404), end-user scoping (another address is 404), validation before
 * any work, Idempotency-Key replay and reuse, the config-driven rate limits (preview, grants,
 * bulk), the bulk limits and the audit row of every action. The SQL behaviour runs in
 * integration/quarantine.test.ts.
 */
// ---- Route coverage (step 6.1 §3.8, test/route-coverage/legacy.ts) ----
// @covers get /api/v1/quarantine/approvals
// @covers get /api/v1/quarantine/catalog
// @covers get /api/v1/quarantine/downloads/:token
// @covers get /api/v1/quarantine/entries
// @covers get /api/v1/quarantine/entries/:entryId
// @covers get /api/v1/quarantine/entries/:entryId/history
// @covers get /api/v1/quarantine/entries/:entryId/preview
// @covers get /api/v1/quarantine/me/entries
// @covers get /api/v1/quarantine/me/entries/:entryId
// @covers get /api/v1/quarantine/me/entries/:entryId/preview
// @covers get /api/v1/quarantine/settings
// @covers get /api/v1/quarantine/summary
// @covers post /api/v1/quarantine/approvals/:approvalId/approve
// @covers post /api/v1/quarantine/approvals/:approvalId/deny
// @covers post /api/v1/quarantine/bulk
// @covers post /api/v1/quarantine/entries
// @covers post /api/v1/quarantine/entries/:entryId/delete
// @covers post /api/v1/quarantine/entries/:entryId/download-grants
// @covers post /api/v1/quarantine/entries/:entryId/reject
// @covers post /api/v1/quarantine/entries/:entryId/release
// @covers post /api/v1/quarantine/entries/:entryId/request-release
// @covers post /api/v1/quarantine/me/entries/:entryId/release
// @covers post /api/v1/quarantine/me/entries/:entryId/request-release
// @covers put /api/v1/quarantine/settings
// ---- end of route coverage ----
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
import { createLogger } from '@email-gateway/logger';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AppModule } from '../src/app.module';
import { AuditService } from '../src/audit/audit.service';
import type { ApiKeyPrincipal } from '../src/auth-contracts/principal';
import { loadApiConfig } from '../src/config';
import { TransactionRunner } from '../src/database/transaction-runner';
import { EmailSender } from '../src/email/email-sender';
import { configureApiApp } from '../src/http/configure-api-app';
import { IdempotencyRepository } from '../src/http/idempotency/idempotency.repository';
import { KeyValueStore } from '../src/kv/key-value-store';
import { ApiKeyAuthenticatorService } from '../src/modules/auth/services/api-key-authenticator.service';
import type { PrincipalSnapshot } from '../src/modules/auth/services/principal-cache.service';
import { PrincipalLoaderService } from '../src/modules/auth/services/principal-loader.service';
import { ReauthenticationService } from '../src/modules/auth/services/reauthentication.service';
import { SessionService } from '../src/modules/auth/services/session.service';
import { TokenService } from '../src/modules/auth/services/token.service';
import { MessageLifecycleRepository } from '../src/modules/messages/repositories/message-lifecycle.repository';
import { LifecycleGateway } from '../src/modules/messages/services/lifecycle-gateway';
import { QuarantineFactsRepository } from '../src/modules/quarantine/repositories/quarantine-facts.repository';
import { QuarantineReadRepository } from '../src/modules/quarantine/repositories/quarantine-read.repository';
import { QuarantineWriteRepository } from '../src/modules/quarantine/repositories/quarantine-write.repository';
import { QuarantineObjectStore } from '../src/modules/quarantine/services/quarantine-object-store';
import { InMemoryKeyValueStore } from './support/in-memory-key-value-store';
import { OTHER_ORG, QuarantineWorld } from './support/in-memory-quarantine';
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
  QUARANTINE_PREVIEW_RATE_PER_MINUTE: '3',
  QUARANTINE_DOWNLOAD_GRANTS_PER_HOUR: '2',
  QUARANTINE_BULK_REQUESTS_PER_MINUTE: '2',
  QUARANTINE_BULK_MAX_ITEMS: '3',
};

const P = {
  read: 'quarantine:read',
  preview: 'quarantine:preview',
  release: 'quarantine:release',
  approve: 'quarantine:approve',
  reject: 'quarantine:reject',
  delete: 'quarantine:delete',
  manage: 'quarantine:manage',
  download: 'quarantine:download',
  request: 'quarantine:request_release',
  self: 'quarantine:self',
  settings: 'settings:manage',
};
const OPERATOR = Object.values(P).filter((p) => p !== P.self);
const ids = { user: randomUUID(), org: randomUUID(), session: randomUUID() };
const USER_ID = 10n;
const reason = 'checked by the operator';

let snapshot: PrincipalSnapshot;
function principalWith(permissions: string[]): void {
  snapshot = {
    orgVersion: 0,
    userVersion: '',
    user: {
      id: USER_ID.toString(),
      publicId: ids.user,
      status: 'active',
      deleted: false,
      mfaEnabled: true,
    },
    org: {
      id: '1',
      publicId: ids.org,
      kind: 'customer',
      status: 'active',
      deleted: false,
      mfaRequired: false,
    },
    permissions,
  };
}

let apiKeyPermissions: string[] = [P.read];
const apiKeyPrincipal = (): ApiKeyPrincipal => ({
  kind: 'api_key',
  apiKeyId: 5n,
  apiKeyPublicId: '0190a5b2-7c3d-7e4f-8a1b-00000000aaaa',
  organizationId: 1n,
  organizationPublicId: ids.org,
  permissions: new Set(apiKeyPermissions),
});

describe('quarantine routes (e2e, in-memory world)', () => {
  let app: INestApplication;
  const world = new QuarantineWorld();
  const kv = new InMemoryKeyValueStore();
  let reauthOk = true;
  const tokens = new TokenService(loadApiConfig(env));
  const http = () => request(app.getHttpServer());
  const auth = async (mfa = true) => {
    const { token } = await tokens.issue({
      userPublicId: ids.user,
      organizationPublicId: ids.org,
      sessionId: ids.session,
      amr: mfa ? ['pwd', 'otp'] : ['pwd'],
    });
    return { Authorization: `Bearer ${token}` };
  };
  const apiKey = { 'X-API-Key': `egk_${'a'.repeat(12)}_${'b'.repeat(43)}` };
  const window = () => ({
    from: new Date(Date.now() - 86_400_000).toISOString(),
    to: new Date(Date.now() + 86_400_000).toISOString(),
  });
  const post = async (
    path: string,
    body: unknown,
    key: string | null = randomUUID(),
    mfa = true,
  ) => {
    const req = http()
      .post(`/api/v1/quarantine${path}`)
      .set(await auth(mfa));
    if (key !== null) req.set('Idempotency-Key', key);
    return req.send(body as object);
  };
  const get = async (path: string, query: Record<string, string> = {}) =>
    http()
      .get(`/api/v1/quarantine${path}`)
      .query(query)
      .set(await auth());

  beforeAll(async () => {
    const config = loadApiConfig(env);
    const stub = (healthName: string) => ({ healthName, checkHealth: () => Promise.resolve() });
    const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
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
      .useValue({ run: (fn: (tx: unknown) => Promise<unknown>) => fn({}) })
      .overrideProvider(QuarantineReadRepository)
      .useValue(world.reader())
      .overrideProvider(QuarantineWriteRepository)
      .useValue(world.writer())
      .overrideProvider(QuarantineFactsRepository)
      .useValue(world.facts())
      .overrideProvider(QuarantineObjectStore)
      .useValue(world.objects())
      .overrideProvider(LifecycleGateway)
      .useValue(world.lifecycle())
      .overrideProvider(IdempotencyRepository)
      .useValue(world.idempotencyRepository())
      .overrideProvider(AuditService)
      .useValue(world.auditService())
      .overrideProvider(MessageLifecycleRepository)
      .useValue({ insertEmailEvent: () => Promise.resolve() })
      .overrideProvider(ReauthenticationService)
      .useValue({
        verify: () => Promise.resolve(reauthOk ? { ok: true } : { ok: false, reason: 'password' }),
      })
      .compile();
    app = moduleRef.createNestApplication({ logger: false });
    configureHttpApp(app, createLogger({ service: 'api-test', level: 'silent' }));
    configureApiApp(app, config);
    await app.init();
  });

  afterAll(async () => {
    await app?.close();
  });

  beforeEach(() => {
    world.reset();
    kv.entries.clear();
    reauthOk = true;
    apiKeyPermissions = [P.read];
    world.identities.set(USER_ID, { email: 'operator@acme.example', verified: true });
    principalWith(OPERATOR);
  });

  it('answers 401 without credentials on every quarantine route family', async () => {
    const id = randomUUID();
    await http().get('/api/v1/quarantine/entries').expect(401);
    await http().get(`/api/v1/quarantine/entries/${id}`).expect(401);
    await http().post(`/api/v1/quarantine/entries/${id}/release`).send({ reason }).expect(401);
    await http().get('/api/v1/quarantine/me/entries').expect(401);
    await http().post('/api/v1/quarantine/bulk').send({}).expect(401);
    await http().get(`/api/v1/quarantine/downloads/qdl1.a.b`).expect(401);
  });

  describe('RBAC per permission', () => {
    it.each([
      ['GET', '/entries', P.read],
      ['GET', '/entries/{e}', P.read],
      ['GET', '/entries/{e}/history', P.read],
      ['GET', '/entries/{e}/preview', P.preview],
      ['POST', '/entries/{e}/release', P.release],
      ['POST', '/entries/{e}/request-release', P.request],
      ['POST', '/entries/{e}/reject', P.reject],
      ['POST', '/entries/{e}/delete', P.delete],
      ['POST', '/entries/{e}/download-grants', P.download],
      ['POST', '/entries', P.manage],
      ['GET', '/approvals', P.read],
      ['POST', '/approvals/{e}/approve', P.approve],
      ['POST', '/approvals/{e}/deny', P.approve],
      ['GET', '/summary', P.read],
      ['GET', '/settings', P.read],
      ['PUT', '/settings', P.settings],
    ])('%s %s needs %s (403 without it)', async (method, path, permission) => {
      const entry = world.addEntry();
      principalWith(OPERATOR.filter((p) => p !== permission));
      const url = `/api/v1/quarantine${path.replace('{e}', entry.publicId)}`;
      const req =
        method === 'GET'
          ? http().get(url).query(window())
          : method === 'PUT'
            ? http().put(url)
            : http().post(url).set('Idempotency-Key', 'k1');
      await req
        .set(await auth())
        .send({ reason })
        .expect(403);
    });

    it('a mailbox user (quarantine:self) reaches only the /me routes and the catalog', async () => {
      principalWith([P.self]);
      world.identities.set(USER_ID, { email: 'alice@acme.example', verified: true });
      const own = world.addEntry({ address: 'alice@acme.example' });
      expect((await get('/me/entries', window())).status).toBe(200);
      expect((await get('/catalog')).status).toBe(200);
      expect((await get('/entries', window())).status).toBe(403);
      expect((await get(`/entries/${own.publicId}`)).status).toBe(403);
      expect((await post(`/entries/${own.publicId}/reject`, { reason })).status).toBe(403);
      expect((await post('/bulk', { action: 'reject', ids: [own.publicId], reason })).status).toBe(
        403,
      );
      expect((await post(`/approvals/${randomUUID()}/approve`, { reason })).status).toBe(403);
      expect(
        (
          await post(
            `/entries/${own.publicId}/download-grants`,
            { object: 'eml', password: 'x' },
            null,
          )
        ).status,
      ).toBe(403);
    });

    it('operators are not end users: /me answers 403 without quarantine:self, and for API keys', async () => {
      expect((await get('/me/entries', window())).status).toBe(403);
      apiKeyPermissions = [P.self];
      await http().get('/api/v1/quarantine/me/entries').query(window()).set(apiKey).expect(403);
    });

    it('approve/deny and download grants need a user with MFA; API keys are refused', async () => {
      const entry = world.addEntry();
      expect(
        (await post(`/approvals/${randomUUID()}/approve`, { reason }, 'k', false)).status,
      ).toBe(403);
      expect(
        (
          await post(
            `/entries/${entry.publicId}/download-grants`,
            { object: 'eml', password: 'pw' },
            null,
            false,
          )
        ).status,
      ).toBe(403);
      apiKeyPermissions = [P.approve, P.download];
      await http()
        .post(`/api/v1/quarantine/approvals/${randomUUID()}/approve`)
        .set(apiKey)
        .set('Idempotency-Key', 'k')
        .send({ reason })
        .expect(403);
    });
  });

  describe('tenant isolation and end-user scoping', () => {
    it("another organization's entry is 404 on every entry route", async () => {
      const foreign = world.addEntry({ organizationId: OTHER_ORG });
      for (const res of [
        await get(`/entries/${foreign.publicId}`),
        await get(`/entries/${foreign.publicId}/history`),
        await get(`/entries/${foreign.publicId}/preview`),
        await post(`/entries/${foreign.publicId}/release`, { reason }),
        await post(`/entries/${foreign.publicId}/reject`, { reason }),
        await post(`/entries/${foreign.publicId}/delete`, { reason }),
      ]) {
        expect(res.status).toBe(404);
        expect(res.body.code).toBe('quarantine_entry_not_found');
      }
      const page = await get('/entries', window());
      expect(page.body.items).toEqual([]);
    });

    it("an end user sees only the own address; another address's entry is 404", async () => {
      principalWith([P.self]);
      world.identities.set(USER_ID, { email: 'alice@acme.example', verified: true });
      const own = world.addEntry({ address: 'alice@acme.example' });
      const other = world.addEntry({ address: 'bob@acme.example' });
      const page = await get('/me/entries', window());
      expect(page.body.items.map((i: { id: string }) => i.id)).toEqual([own.publicId]);
      expect(page.body.items[0].subject).toBeNull();
      for (const res of [
        await get(`/me/entries/${other.publicId}`),
        await get(`/me/entries/${other.publicId}/preview`),
        await post(`/me/entries/${other.publicId}/release`, { reason }),
        await post(`/me/entries/${other.publicId}/request-release`, { reason }),
      ]) {
        expect(res.status).toBe(404);
      }
      // An unverified address sees nothing at all.
      world.identities.set(USER_ID, { email: 'alice@acme.example', verified: false });
      expect((await get('/me/entries', window())).status).toBe(403);
    });
  });

  describe('validation (before any work)', () => {
    it('ids, ranges, bodies and the Idempotency-Key header', async () => {
      const entry = world.addEntry();
      expect((await get('/entries/not-a-uuid')).status).toBe(400);
      expect((await get('/entries')).status).toBe(400);
      expect((await get('/entries', { ...window(), state: 'bogus' })).status).toBe(400);
      expect(
        (await get('/entries', { ...window(), riskLevel: 'low', minRiskLevel: 'high' })).status,
      ).toBe(400);
      const wide = await get('/entries', {
        from: new Date(Date.now() - 100 * 86_400_000).toISOString(),
        to: new Date().toISOString(),
      });
      expect(wide.body.code).toBe('quarantine_search_range_invalid');
      const badCursor = await get('/entries', { ...window(), cursor: 'Zm9v' });
      expect(badCursor.body.code).toBe('quarantine_cursor_invalid');
      const noKey = await post(`/entries/${entry.publicId}/release`, { reason }, null);
      expect(noKey.status).toBe(400);
      expect(noKey.body.code).toBe('idempotency_key_required');
      expect(
        (await post(`/entries/${entry.publicId}/release`, { reason }, 'bad key!')).body.code,
      ).toBe('idempotency_key_invalid');
      expect((await post(`/entries/${entry.publicId}/release`, { reason: '' })).status).toBe(400);
      expect((await post(`/entries/${entry.publicId}/release`, { reason, extra: 1 })).status).toBe(
        400,
      );
      expect(
        (
          await post(
            `/entries/${entry.publicId}/download-grants`,
            { object: 'attachment', password: 'x' },
            null,
          )
        ).status,
      ).toBe(400);
      expect(world.audits).toHaveLength(0);
    });
  });

  describe('mutations, idempotency and audit rows', () => {
    it('release without a scan round → 202 approval_requested; replay; reuse → 422', async () => {
      const entry = world.addEntry();
      const first = await post(`/entries/${entry.publicId}/release`, { reason }, 'key-1');
      expect(first.status).toBe(202);
      expect(first.body).toMatchObject({
        outcome: 'approval_requested',
        approvalReasons: ['no_scan_round'],
      });
      const again = await post(`/entries/${entry.publicId}/release`, { reason }, 'key-1');
      expect(again.status).toBe(202);
      expect(again.headers['idempotency-replayed']).toBe('true');
      expect(again.body).toEqual(first.body);
      expect(
        (await post(`/entries/${entry.publicId}/release`, { reason: 'other' }, 'key-1')).status,
      ).toBe(422);
      expect(world.auditActions()).toEqual(['quarantine.release_requested']);
      expect(world.actions.map((a) => a.action)).toEqual(['release_blocked']);
      expect(world.actions[0]!.reason).toBe(reason);
      expect(JSON.stringify(world.audits[0]!.metadata)).not.toContain(reason);
      expect(world.outbox.map((o) => o.eventType)).toEqual([
        'mail.quarantine.notification_requested.v1',
      ]);
    });

    it('reject, delete, request-release and detail/preview write their audit rows', async () => {
      const a = world.addEntry();
      const b = world.addEntry();
      const c = world.addEntry();
      expect((await post(`/entries/${a.publicId}/reject`, { reason })).status).toBe(200);
      expect((await post(`/entries/${b.publicId}/delete`, { reason })).status).toBe(200);
      expect((await post(`/entries/${c.publicId}/request-release`, { reason })).status).toBe(202);
      expect((await get(`/entries/${c.publicId}`)).status).toBe(200);
      const preview = await get(`/entries/${c.publicId}/preview`);
      expect(preview.status).toBe(200);
      expect(preview.headers['cache-control']).toBe('no-store');
      expect(JSON.stringify(preview.body)).not.toContain('<script');
      expect((await get('/entries', window())).status).toBe(200);
      expect(world.auditActions()).toEqual([
        'quarantine.rejected',
        'quarantine.deleted',
        'quarantine.approval_requested',
        'quarantine.entry_viewed',
        'quarantine.previewed',
        'quarantine.searched',
      ]);
      expect(world.transitions.map((t) => t.reason)).toEqual([
        'quarantine_deleted',
        'quarantine_deleted',
      ]);
    });

    it('approve: SoD (the requester is refused), then a second user approves and the release is queued', async () => {
      const entry = world.addEntry();
      expect((await post(`/entries/${entry.publicId}/request-release`, { reason })).status).toBe(
        202,
      );
      const approval = world.approvals[0]!;
      const self = await post(`/approvals/${approval.publicId}/approve`, { reason });
      expect(self.status).toBe(403);
      expect(self.body).toMatchObject({
        code: 'quarantine_approval_forbidden',
        reason: 'requester',
      });
      approval.requestedByUserId = 77n;
      const ok = await post(`/approvals/${approval.publicId}/approve`, { reason });
      expect(ok.status).toBe(202);
      expect(ok.body).toMatchObject({ status: 'approved', entryState: 'releasing' });
      expect(world.outbox.map((o) => o.eventType)).toContain(
        'mail.quarantine.release_requested.v1',
      );
      expect(world.auditActions()).toContain('quarantine.approval_approved');
    });

    it('settings PUT validates with violations by path and compares rowVersion', async () => {
      const bad = await http()
        .put('/api/v1/quarantine/settings')
        .set(await auth())
        .send({
          settings: { endUser: { selfReleaseMaxLevel: 'critical' } },
          expectedRowVersion: 0,
        });
      expect(bad.status).toBe(400);
      expect(bad.body.violations[0].path).toBe('endUser.selfReleaseMaxLevel');
      const ok = await http()
        .put('/api/v1/quarantine/settings')
        .set(await auth())
        .send({ settings: { download: { enabled: true } }, expectedRowVersion: 0 });
      expect(ok.status).toBe(200);
      expect(ok.body).toMatchObject({ rowVersion: 1, effective: { download: { enabled: true } } });
      const stale = await http()
        .put('/api/v1/quarantine/settings')
        .set(await auth())
        .send({ settings: {}, expectedRowVersion: 0 });
      expect(stale.body.code).toBe('quarantine_settings_conflict');
      expect(world.auditActions()).toEqual(['quarantine.settings_updated']);
    });
  });

  describe('download door', () => {
    it('disabled → 403; enabled: wrong password 401; grant → download once → 410; another user 404', async () => {
      const entry = world.addEntry();
      const body = { object: 'eml', password: 'pw', totpCode: '123456' };
      expect((await post(`/entries/${entry.publicId}/download-grants`, body, null)).body.code).toBe(
        'quarantine_download_disabled',
      );
      world.settings.set(1n, { settings: { download: { enabled: true } }, rowVersion: 1 });
      reauthOk = false;
      const wrong = await post(`/entries/${entry.publicId}/download-grants`, body, null);
      expect(wrong.status).toBe(401);
      expect(wrong.body.code).toBe('quarantine_reauth_failed');
      kv.entries.clear();
      reauthOk = true;
      const grant = await post(`/entries/${entry.publicId}/download-grants`, body, null);
      expect(grant.status).toBe(201);
      const file = await http()
        .get(`/api/v1/quarantine/downloads/${grant.body.token}`)
        .set(await auth());
      expect(file.status).toBe(200);
      expect(file.headers).toMatchObject({
        'content-type': 'application/octet-stream',
        'x-content-type-options': 'nosniff',
        'cache-control': 'no-store',
        'content-security-policy': "sandbox; default-src 'none'",
      });
      expect(file.headers['content-disposition']).toMatch(/^attachment; filename=".+\.eml\.bin"$/);
      const reused = await http()
        .get(`/api/v1/quarantine/downloads/${grant.body.token}`)
        .set(await auth());
      expect(reused.status).toBe(410);
      expect(reused.body.code).toBe('quarantine_download_token_used');
      kv.entries.clear();
      await http()
        .get('/api/v1/quarantine/downloads/qdl1.AAAA.BBBB')
        .set(await auth())
        .expect(404);
      expect(world.auditActions()).toEqual([
        'quarantine.download_refused',
        'quarantine.download_granted',
        'quarantine.downloaded',
      ]);
    });
  });

  describe('rate limits (env-configured)', () => {
    it('preview: QUARANTINE_PREVIEW_RATE_PER_MINUTE per caller, then 429 with Retry-After', async () => {
      const entry = world.addEntry();
      for (let i = 0; i < 3; i += 1)
        expect((await get(`/entries/${entry.publicId}/preview`)).status).toBe(200);
      const limited = await get(`/entries/${entry.publicId}/preview`);
      expect(limited.status).toBe(429);
      expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
    });

    it('download grants: QUARANTINE_DOWNLOAD_GRANTS_PER_HOUR per user', async () => {
      const entry = world.addEntry();
      world.settings.set(1n, { settings: { download: { enabled: true } }, rowVersion: 1 });
      const body = { object: 'eml', password: 'pw', totpCode: '123456' };
      expect((await post(`/entries/${entry.publicId}/download-grants`, body, null)).status).toBe(
        201,
      );
      expect((await post(`/entries/${entry.publicId}/download-grants`, body, null)).status).toBe(
        201,
      );
      expect((await post(`/entries/${entry.publicId}/download-grants`, body, null)).status).toBe(
        429,
      );
    });

    it('bulk: request limit, per-item results, request rate per caller', async () => {
      const a = world.addEntry();
      const tooMany = await post('/bulk', {
        action: 'reject',
        ids: [randomUUID(), randomUUID(), randomUUID(), randomUUID()],
        reason,
      });
      expect(tooMany.status).toBe(400);
      expect(tooMany.body).toMatchObject({
        code: 'quarantine_bulk_limit',
        cause: 'too_many',
        maxItems: 3,
      });
      const unknown = randomUUID();
      const mixed = await post('/bulk', { action: 'reject', ids: [a.publicId, unknown], reason });
      expect(mixed.status).toBe(200);
      expect(mixed.body.results).toEqual([
        { id: a.publicId, status: 'done' },
        { id: unknown, status: 'not_found', code: 'quarantine_entry_not_found' },
      ]);
      expect(world.auditActions()).toEqual(['quarantine.rejected', 'quarantine.bulk']);
      expect((await post('/bulk', { action: 'reject', ids: [unknown], reason })).status).toBe(429);
    });

    it('bulk approve/deny need the approve permission and MFA', async () => {
      principalWith(OPERATOR.filter((p) => p !== P.approve));
      expect((await post('/bulk', { action: 'approve', ids: [randomUUID()], reason })).status).toBe(
        403,
      );
      principalWith(OPERATOR);
      expect(
        (await post('/bulk', { action: 'deny', ids: [randomUUID()], reason }, randomUUID(), false))
          .status,
      ).toBe(403);
    });
  });

  it('catalog lists the vocabularies, error codes and self-service switches', async () => {
    const res = await get('/catalog');
    expect(res.status).toBe(200);
    expect(res.body.errorCodes.quarantine_download_token_used).toBe(410);
    expect(res.body.limits.bulkMaxItems).toBe(3);
    expect(res.body.selfService).toMatchObject({ enabled: true, selfRelease: false });
  });
});
