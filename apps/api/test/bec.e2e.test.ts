/**
 * Step 4.4 BEC routes (B13, B18) over HTTP with MySQL, Redis and S3 stubbed: authorization (401,
 * 403 per permission, MFA on the export and the history purge, users only on feedback, API keys
 * where allowed), validation before any database access (400, 422), the coded errors, the NDJSON
 * export with its cursor header and rate limit, the 202 purge and the `bec` scan settings. The
 * same routes against the real MySQL run in integration/bec.test.ts.
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
import { createLogger } from '@email-gateway/logger';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { AppModule } from '../src/app.module';
import { AuditService } from '../src/audit/audit.service';
import type { ApiKeyPrincipal } from '../src/auth-contracts/principal';
import { loadApiConfig } from '../src/config';
import { TransactionRunner } from '../src/database/transaction-runner';
import { EmailSender } from '../src/email/email-sender';
import { configureApiApp } from '../src/http/configure-api-app';
import { KeyValueStore } from '../src/kv/key-value-store';
import { ApiKeyAuthenticatorService } from '../src/modules/auth/services/api-key-authenticator.service';
import type { PrincipalSnapshot } from '../src/modules/auth/services/principal-cache.service';
import { PrincipalLoaderService } from '../src/modules/auth/services/principal-loader.service';
import { SessionService } from '../src/modules/auth/services/session.service';
import { type AuthMethod, TokenService } from '../src/modules/auth/services/token.service';
import { BecFeedbackRepository } from '../src/modules/bec/repositories/bec-feedback.repository';
import { BecProfilesRepository } from '../src/modules/bec/repositories/bec-profiles.repository';
import { ScanSettingsRepository } from '../src/modules/scans/repositories/scan-settings.repository';
import { OrganizationFeaturesService } from '../src/tenancy/organization-features.service';
import { InMemoryKeyValueStore } from './support/in-memory-key-value-store';
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
};

const READ = 'bec:read';
const MANAGE = 'bec:manage';
const FEEDBACK = 'bec:feedback';
const EXPORT = 'bec:feedback_export';
const ids = { user: randomUUID(), org: randomUUID(), session: randomUUID() };
const NOW = new Date('2026-11-06T12:00:00.000Z');
const EXEC_ID = '0190f0f0-0000-7000-8000-0000000000e1';
const MESSAGE_ID = '0190f0f0-0000-7000-8000-0000000000a1';

let snapshot: PrincipalSnapshot;
function principalWith(permissions: string[]): void {
  snapshot = {
    orgVersion: 0,
    userVersion: '',
    user: { id: '10', publicId: ids.user, status: 'active', deleted: false, mfaEnabled: true },
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

let apiKeyPermissions = new Set<string>([READ]);
const apiKeyPrincipal = (): ApiKeyPrincipal => ({
  kind: 'api_key',
  apiKeyId: 5n,
  apiKeyPublicId: randomUUID(),
  organizationId: 1n,
  organizationPublicId: ids.org,
  permissions: apiKeyPermissions,
});

const executiveRow = {
  id: 11n,
  publicId: EXEC_ID,
  organizationId: 1n,
  displayName: 'Anita Sharma',
  normalizedName: 'anita sharma',
  aliases: [],
  knownAddresses: ['anita@acme.example'],
  title: null,
  enabled: true,
  version: 1,
  createdAt: NOW,
  updatedAt: NOW,
  createdBy: { publicId: ids.user },
  updatedBy: null,
};

describe('step 4.4 BEC routes (e2e, dependencies stubbed)', () => {
  let app: INestApplication;
  const kv = new InMemoryKeyValueStore();
  const tokens = new TokenService(loadApiConfig(env));
  const http = () => request(app.getHttpServer());
  const profiles = {
    lockOrganization: vi.fn(() => Promise.resolve()),
    listExecutives: vi.fn(() => Promise.resolve([executiveRow])),
    findExecutive: vi.fn((_s: unknown, id: string) =>
      Promise.resolve(id === EXEC_ID ? executiveRow : null),
    ),
    findExecutiveByName: vi.fn(() => Promise.resolve(null)),
    countExecutives: vi.fn(() => Promise.resolve(0)),
    createExecutive: vi.fn(() => Promise.resolve(executiveRow)),
  };
  const feedback = {
    lockOrganization: vi.fn(() => Promise.resolve()),
    findMessage: vi.fn(() => Promise.resolve(null)),
    exportIds: vi.fn(() => Promise.resolve([1n, 2n])),
    exportFeedback: vi.fn(() =>
      Promise.resolve([
        {
          id: 1n,
          publicId: randomUUID(),
          kind: 'false_positive',
          createdAt: NOW,
          becResultId: 55n,
          messageReceivedAt: NOW,
        },
      ]),
    ),
    exportResults: vi.fn(() =>
      Promise.resolve([
        {
          id: 55n,
          receivedAt: NOW,
          rulesVersion: 'bec-map/1',
          engineVersion: 'bec/1',
          deterministicScore: 45,
          score: 45,
          verdict: 'suspicious',
          deterministicVerdict: 'suspicious',
          rules: [],
          features: { rule_r2: 1 },
          ai: null,
          aiShadow: null,
        },
      ]),
    ),
    purgeHistoryBatch: vi.fn(() => Promise.resolve(3)),
  };
  const settingsRows = {
    list: vi.fn(() => Promise.resolve([] as unknown[])),
    find: vi.fn(() => Promise.resolve(null as unknown)),
    create: vi.fn(() => Promise.resolve({})),
    replaceIfVersion: vi.fn(() => Promise.resolve(true)),
  };
  const audit = {
    actorFrom: () => ({ type: 'user', id: ids.user }),
    record: vi.fn((_entry: Record<string, unknown>, _tx?: unknown) => Promise.resolve()),
  };
  const transactions = { run: vi.fn((fn: (tx: unknown) => Promise<unknown>) => fn({})) };

  const bearer = async (amr: AuthMethod[] = ['pwd', 'otp']) => {
    const { token } = await tokens.issue({
      userPublicId: ids.user,
      organizationPublicId: ids.org,
      sessionId: ids.session,
      amr,
    });
    return { Authorization: `Bearer ${token}` };
  };
  const apiKey = { 'X-API-Key': `egk_${'a'.repeat(12)}_${'b'.repeat(43)}` };
  const feedbackUrl = (message = MESSAGE_ID, scan = '900') =>
    `/api/v1/messages/${message}/scans/${scan}/bec-feedback`;

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
      .useValue(transactions)
      .overrideProvider(AuditService)
      .useValue(audit)
      .overrideProvider(BecProfilesRepository)
      .useValue(profiles)
      .overrideProvider(BecFeedbackRepository)
      .useValue(feedback)
      .overrideProvider(ScanSettingsRepository)
      .useValue(settingsRows)
      // Plan features (step 4.6 X17: the scan-settings views state attachment_sandbox).
      .overrideProvider(OrganizationFeaturesService)
      .useValue({ isEnabled: () => Promise.resolve(false) })
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
    vi.clearAllMocks();
    kv.entries.clear();
    apiKeyPermissions = new Set([READ]);
    principalWith([READ, MANAGE, FEEDBACK, EXPORT]);
  });

  it('answers 401 without credentials', async () => {
    await http().get('/api/v1/bec/executives').expect(401);
    await http().post(feedbackUrl()).send({ kind: 'false_negative' }).expect(401);
    await http().delete('/api/v1/bec/history').expect(401);
  });

  it('lists and gets executives with bec:read (users and API keys); 403 without', async () => {
    const res = await http().get('/api/v1/bec/executives').set(apiKey).expect(200);
    expect(res.body).toEqual({
      data: [expect.objectContaining({ id: EXEC_ID, displayName: 'Anita Sharma', version: 1 })],
      nextCursor: null,
    });
    await http()
      .get(`/api/v1/bec/executives/${EXEC_ID}`)
      .set(await bearer())
      .expect(200);
    const missing = await http()
      .get(`/api/v1/bec/executives/${randomUUID()}`)
      .set(await bearer())
      .expect(404);
    expect(missing.body.code).toBe('bec_executive_not_found');
    await http()
      .get('/api/v1/bec/executives/not-a-uuid')
      .set(await bearer())
      .expect(400);
    principalWith([MANAGE]);
    await http()
      .get('/api/v1/bec/executives')
      .set(await bearer())
      .expect(403);
  });

  it('creates with bec:manage (201, audited); refuses invalid bodies and API keys without it', async () => {
    const res = await http()
      .post('/api/v1/bec/executives')
      .set(await bearer())
      .send({ displayName: 'Anita Sharma', knownAddresses: ['anita@acme.example'] })
      .expect(201);
    expect(res.body.id).toBe(EXEC_ID);
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'bec_executive.created' }),
      {},
    );
    for (const body of [
      {},
      { displayName: 'A' },
      { displayName: 'Anita Sharma', aliases: Array(11).fill('Alias Name') },
      { displayName: 'Anita Sharma', knownAddresses: ['nope'] },
      { displayName: 'Anita Sharma', extra: true },
    ]) {
      await http()
        .post('/api/v1/bec/executives')
        .set(await bearer())
        .send(body)
        .expect(400);
    }
    await http()
      .post('/api/v1/bec/executives')
      .set(apiKey)
      .send({ displayName: 'X Y' })
      .expect(403);
  });

  it('refuses free-mail vendor and trusted domains (422) before any database access', async () => {
    const vendor = await http()
      .post('/api/v1/bec/vendors')
      .set(await bearer())
      .send({ name: 'Globex', domains: ['gmail.com'] })
      .expect(422);
    expect(vendor.body).toMatchObject({ code: 'vendor_domain_freemail', index: 0 });
    const trusted = await http()
      .post('/api/v1/bec/trusted-senders')
      .set(await bearer())
      .send({ kind: 'domain', value: 'outlook.com', reason: 'partner' })
      .expect(422);
    expect(trusted.body.code).toBe('trusted_domain_freemail');
    await http()
      .post('/api/v1/bec/trusted-senders')
      .set(await bearer())
      .send({ kind: 'domain', value: 'co.uk', reason: 'partner' })
      .expect(400);
    expect(transactions.run).not.toHaveBeenCalled();
  });

  it('feedback: users only with bec:feedback; validates the body and ids; 404 for unknown messages', async () => {
    apiKeyPermissions = new Set([FEEDBACK]);
    await http().post(feedbackUrl()).set(apiKey).send({ kind: 'false_negative' }).expect(403);
    principalWith([READ]);
    await http()
      .post(feedbackUrl())
      .set(await bearer())
      .send({ kind: 'false_negative' })
      .expect(403);
    principalWith([FEEDBACK]);
    await http()
      .post(feedbackUrl(MESSAGE_ID, 'abc'))
      .set(await bearer())
      .send({ kind: 'false_negative' })
      .expect(400);
    for (const body of [
      { kind: 'maybe' },
      {
        kind: 'false_positive',
        suppress: { codes: ['bec.auth.dmarc_fail'], scope: 'domain', days: 10 },
      },
      {
        kind: 'false_positive',
        suppress: { codes: ['bec.content.urgency'], scope: 'domain', days: 91 },
      },
      { kind: 'false_positive', note: 'x'.repeat(501) },
    ]) {
      await http()
        .post(feedbackUrl())
        .set(await bearer())
        .send(body)
        .expect(400);
    }
    const res = await http()
      .post(feedbackUrl())
      .set(await bearer())
      .send({ kind: 'false_negative' })
      .expect(404);
    expect(res.body.code).toBe('message_not_found');
  });

  it('export: MFA users with bec:feedback_export, NDJSON with the next cursor, 10 per minute', async () => {
    apiKeyPermissions = new Set([EXPORT]);
    await http().get('/api/v1/bec/feedback/export').set(apiKey).expect(403);
    await http()
      .get('/api/v1/bec/feedback/export')
      .set(await bearer(['pwd']))
      .expect(403);
    principalWith([READ]);
    await http()
      .get('/api/v1/bec/feedback/export')
      .set(await bearer())
      .expect(403);
    principalWith([EXPORT]);
    const auth = await bearer();
    const res = await http().get('/api/v1/bec/feedback/export?limit=1').set(auth).expect(200);
    expect(res.headers['content-type']).toContain('application/x-ndjson');
    expect(res.headers['x-next-cursor']).toBeTruthy();
    const lines = res.text.trim().split('\n');
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]!)).toMatchObject({
      kind: 'false_positive',
      features: { rule_r2: 1 },
    });
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'bec_feedback.exported' }),
    );
    await http()
      .get('/api/v1/bec/feedback/export?from=2026-11-06T00:00:00Z&to=2026-11-05T00:00:00Z')
      .set(auth)
      .expect(400);
    for (let i = 0; i < 8; i += 1) {
      await http().get('/api/v1/bec/feedback/export').set(auth).expect(200);
    }
    await http().get('/api/v1/bec/feedback/export').set(auth).expect(429);
  });

  it('history purge: MFA users with bec:manage, 202 with the count, audited', async () => {
    await http()
      .delete('/api/v1/bec/history')
      .set(await bearer(['pwd']))
      .expect(403);
    apiKeyPermissions = new Set([MANAGE]);
    await http().delete('/api/v1/bec/history').set(apiKey).expect(403);
    const res = await http()
      .delete('/api/v1/bec/history')
      .set(await bearer())
      .expect(202);
    expect(res.body).toEqual({ deleted: 3 });
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'bec_history.purged',
        metadata: { deleted: 3, batches: 1 },
      }),
      {},
    );
  });

  it('bec scan settings: normalized free-mail domains stored, public suffixes refused (422)', async () => {
    principalWith(['policy:read', 'scan:settings_manage']);
    const bad = await http()
      .put('/api/v1/scan-settings/bec')
      .set(await bearer())
      .send({
        expectedVersion: 0,
        settings: { freemailExtraDomains: ['co.uk'], ai: { llm: 'active' } },
      })
      .expect(422);
    expect(bad.body).toMatchObject({ code: 'scan_settings_invalid' });
    settingsRows.find.mockResolvedValueOnce(null).mockResolvedValueOnce({
      engine: 'bec',
      settings: { freemailExtraDomains: ['mail.example'] },
      version: 1,
      updatedAt: NOW,
    });
    const ok = await http()
      .put('/api/v1/scan-settings/bec')
      .set(await bearer())
      .send({ expectedVersion: 0, settings: { freemailExtraDomains: ['Mail.Example'] } })
      .expect(200);
    expect(settingsRows.create).toHaveBeenCalledWith(
      {},
      expect.anything(),
      expect.objectContaining({
        engine: 'bec',
        settings: { freemailExtraDomains: ['mail.example'] },
      }),
    );
    expect(ok.body).toMatchObject({
      engine: 'bec',
      overrideApplied: true,
      effective: { freemailExtraDomains: ['mail.example'] },
    });
  });
});
