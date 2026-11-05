/**
 * Step 4.1 scan routes (S13, S16) over HTTP with MySQL, Redis, S3 and Rspamd stubbed:
 * authorization (401, 403 per permission, API keys refused and MFA required on the platform
 * training route), validation before any database access (400, 404 unknown engine, 422 invalid
 * settings with violations), the version compare-and-set (409), the scan read mapping and its
 * coded 404, the training route's 503 without a configured controller and its rate limit. The
 * same routes against the real MySQL, MinIO and Rspamd run in integration/scans.test.ts.
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
import { Prisma } from '@email-gateway/database';
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
import {
  type LifecycleMessageRow,
  MessageLifecycleReadRepository,
} from '../src/modules/messages/repositories/message-lifecycle-read.repository';
import { MessageScansReadRepository } from '../src/modules/messages/repositories/message-scans-read.repository';
import { ScanSettingsRepository } from '../src/modules/scans/repositories/scan-settings.repository';
import { ScanTrainingRepository } from '../src/modules/scans/repositories/scan-training.repository';
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
  // No RSPAMD_CONTROLLER_URL: the training route answers 503 once authorized and found.
};

const READ = 'message:read';
const POLICY_READ = 'policy:read';
const MANAGE = 'scan:settings_manage';
const TRAIN = 'platform:scan_training';
const ids = { user: randomUUID(), org: randomUUID(), session: randomUUID() };

let snapshot: PrincipalSnapshot;
function principalWith(permissions: string[], kind: 'customer' | 'platform' = 'customer'): void {
  snapshot = {
    orgVersion: 0,
    userVersion: '',
    user: { id: '10', publicId: ids.user, status: 'active', deleted: false, mfaEnabled: true },
    org: {
      id: '1',
      publicId: ids.org,
      kind,
      status: 'active',
      deleted: false,
      mfaRequired: false,
    },
    permissions,
  };
}

let apiKeyPermissions = new Set<string>([READ, POLICY_READ]);
const apiKeyPrincipal = (): ApiKeyPrincipal => ({
  kind: 'api_key',
  apiKeyId: 5n,
  apiKeyPublicId: randomUUID(),
  organizationId: 1n,
  organizationPublicId: ids.org,
  permissions: apiKeyPermissions,
});

const knownMessage: LifecycleMessageRow = {
  id: 77n,
  publicId: randomUUID(),
  receivedAt: new Date('2026-11-05T08:00:00.000Z'),
  direction: 'inbound',
  status: 'scanned',
  statusReason: 'scan_complete',
  version: 4,
  lifecycleRound: 0,
  statusChangedAt: new Date('2026-11-05T08:01:00.000Z'),
};

const scanRow = {
  id: 900n,
  lifecycleRound: 0,
  scanKind: 'initial' as const,
  status: 'completed' as const,
  scanVerdict: 'spam' as const,
  reasonCodes: ['spam.score', 'reputation.ip_listed'],
  requiredEngines: ['rspamd'],
  startedAt: new Date('2026-11-05T08:00:01.000Z'),
  completedAt: new Date('2026-11-05T08:00:05.000Z'),
  deadlineAt: new Date('2026-11-05T08:30:01.000Z'),
};
const engineRow = (attempt: number, isFinal: boolean) => ({
  scanId: 900n,
  engine: 'rspamd',
  engineVersion: '3.12.1',
  outcome: isFinal ? ('spam' as const) : ('timeout' as const),
  score: isFinal ? new Prisma.Decimal('8.5') : null,
  requiredScore: isFinal ? new Prisma.Decimal('15') : null,
  action: isFinal ? 'no action' : null,
  reasonCodes: isFinal ? ['spam.score'] : ['engine.timeout'],
  errorCode: isFinal ? null : 'timeout',
  settingsVersion: isFinal ? 'rspamd-map/1;p=abc;t=none' : null,
  durationMs: 1200,
  evidence: isFinal
    ? { signals: [{ name: 'EG_TEST_RBL', score: 5, options: ['66.2.0.192'] }, { bad: true }] }
    : null,
  attempt,
  isFinal,
  completedAt: new Date(`2026-11-05T08:00:0${attempt + 1}.000Z`),
});

describe('step 4.1 scan routes (e2e, dependencies stubbed)', () => {
  let app: INestApplication;
  const kv = new InMemoryKeyValueStore();
  const tokens = new TokenService(loadApiConfig(env));
  const http = () => request(app.getHttpServer());
  const settingsRows = {
    list: vi.fn(() => Promise.resolve([] as unknown[])),
    find: vi.fn(() => Promise.resolve(null as unknown)),
    create: vi.fn(() => Promise.resolve({})),
    replaceIfVersion: vi.fn(() => Promise.resolve(true)),
  };
  const training = {
    findOrganization: vi.fn((publicId: string) =>
      Promise.resolve(publicId === ids.org ? { id: 1n, publicId } : null),
    ),
    findMessage: vi.fn(() =>
      Promise.resolve({
        id: 77n,
        publicId: knownMessage.publicId,
        receivedAt: knownMessage.receivedAt,
        organizationId: 1n,
        emlObjectKey: 'org/1/eml/x.eml',
      }),
    ),
    insertTrainingEvent: vi.fn(() => Promise.resolve()),
  };
  const audit = {
    actorFrom: () => ({ type: 'user', id: ids.user }),
    record: vi.fn((_entry: Record<string, unknown>) => Promise.resolve()),
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
  const trainUrl = (org: string = ids.org, message: string = knownMessage.publicId) =>
    `/api/v1/platform/organizations/${org}/messages/${message}/scan-training`;
  const learn = { operation: 'learn_spam', reason: 'confirmed spam campaign' };

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
      .overrideProvider(MessageLifecycleReadRepository)
      .useValue({
        findMessage: (_scope: unknown, publicId: string) =>
          Promise.resolve(publicId === knownMessage.publicId ? knownMessage : null),
      })
      .overrideProvider(MessageScansReadRepository)
      .useValue({
        rounds: () => Promise.resolve([scanRow]),
        engineResults: () => Promise.resolve([engineRow(2, true), engineRow(1, false)]),
        authResults: () =>
          Promise.resolve([
            {
              scanId: 900n,
              engine: 'rspamd',
              spf: 'fail',
              spfDomain: 'spoof.scan.test',
              dkim: 'none',
              dkimSignatures: [],
              dmarc: 'fail',
              dmarcPolicy: 'reject',
              dmarcDomain: 'spoof.scan.test',
              arc: null,
            },
          ]),
      })
      .overrideProvider(ScanSettingsRepository)
      .useValue(settingsRows)
      .overrideProvider(ScanTrainingRepository)
      .useValue(training)
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
    apiKeyPermissions = new Set([READ, POLICY_READ]);
    principalWith([READ, POLICY_READ, MANAGE]);
  });

  it('answers 401 without credentials', async () => {
    await http().get(`/api/v1/messages/${knownMessage.publicId}/scans`).expect(401);
    await http().get('/api/v1/scan-settings').expect(401);
    await http().put('/api/v1/scan-settings/rspamd').send({}).expect(401);
    await http().delete('/api/v1/scan-settings/rspamd?expectedVersion=1').expect(401);
    await http().post(trainUrl()).send(learn).expect(401);
  });

  describe('GET /messages/{messageId}/scans', () => {
    it('requires message:read', async () => {
      principalWith([POLICY_READ]);
      await http()
        .get(`/api/v1/messages/${knownMessage.publicId}/scans`)
        .set(await bearer())
        .expect(403);
    });

    it('maps rounds, engines (final + attempts), symbols and auth (API key)', async () => {
      const res = await http()
        .get(`/api/v1/messages/${knownMessage.publicId}/scans`)
        .set(apiKey)
        .expect(200);
      expect(res.body).toEqual({
        messageId: knownMessage.publicId,
        nextCursor: null,
        data: [
          {
            round: 0,
            scanKind: 'initial',
            status: 'completed',
            verdict: 'spam',
            reasonCodes: ['spam.score', 'reputation.ip_listed'],
            requiredEngines: ['rspamd'],
            startedAt: '2026-11-05T08:00:01.000Z',
            completedAt: '2026-11-05T08:00:05.000Z',
            deadlineAt: '2026-11-05T08:30:01.000Z',
            auth: {
              spf: 'fail',
              spfDomain: 'spoof.scan.test',
              dkim: 'none',
              dkimSignatures: [],
              dmarc: 'fail',
              dmarcPolicy: 'reject',
              dmarcDomain: 'spoof.scan.test',
              arc: null,
            },
            engines: [
              {
                engine: 'rspamd',
                final: true,
                engineVersion: '3.12.1',
                outcome: 'spam',
                score: 8.5,
                requiredScore: 15,
                action: 'no action',
                reasonCodes: ['spam.score'],
                symbols: [{ name: 'EG_TEST_RBL', score: 5, options: ['66.2.0.192'] }],
                attempts: [
                  {
                    attempt: 1,
                    outcome: 'timeout',
                    errorCode: 'timeout',
                    durationMs: 1200,
                    at: '2026-11-05T08:00:02.000Z',
                  },
                  {
                    attempt: 2,
                    outcome: 'spam',
                    errorCode: null,
                    durationMs: 1200,
                    at: '2026-11-05T08:00:03.000Z',
                  },
                ],
                durationMs: 1200,
                settingsVersion: 'rspamd-map/1;p=abc;t=none',
                completedAt: '2026-11-05T08:00:03.000Z',
              },
            ],
          },
        ],
      });
    });

    it('answers the coded 404 for an unknown (or another organization’s) message', async () => {
      const res = await http()
        .get(`/api/v1/messages/${randomUUID()}/scans`)
        .set(apiKey)
        .expect(404);
      expect(res.body).toMatchObject({ statusCode: 404, code: 'message_not_found' });
    });

    it.each([
      ['not a uuid', '/api/v1/messages/not-a-uuid/scans'],
      ['limit above 20', `/api/v1/messages/${randomUUID()}/scans?limit=21`],
      ['bad cursor', `/api/v1/messages/${randomUUID()}/scans?cursor=bogus`],
      ['unknown query', `/api/v1/messages/${randomUUID()}/scans?x=1`],
    ])('400 for %s', async (_label, path) => {
      await http().get(path).set(apiKey).expect(400);
    });
  });

  describe('scan settings', () => {
    it('GET requires policy:read and lists the catalog engines with the platform settings', async () => {
      principalWith([MANAGE]);
      await http()
        .get('/api/v1/scan-settings')
        .set(await bearer())
        .expect(403);
      const res = await http().get('/api/v1/scan-settings').set(apiKey).expect(200);
      expect(res.body.data).toEqual([
        expect.objectContaining({
          engine: 'rspamd',
          required: true,
          tenantMayDisable: false,
          override: null,
          overrideApplied: false,
          version: 0,
          platform: expect.objectContaining({ spamScore: 6, suspiciousScore: 4 }),
          effective: expect.objectContaining({ spamScore: 6, phishingVerdict: 'suspicious' }),
        }),
      ]);
      expect(res.body.note).toContain('SCAN_SETTINGS_CACHE_TTL_MS');
    });

    it('PUT and DELETE require scan:settings_manage (users and API keys)', async () => {
      principalWith([READ, POLICY_READ]);
      const body = { expectedVersion: 0, settings: { spamScore: 7 } };
      await http()
        .put('/api/v1/scan-settings/rspamd')
        .set(await bearer())
        .send(body)
        .expect(403);
      await http()
        .delete('/api/v1/scan-settings/rspamd?expectedVersion=1')
        .set(await bearer())
        .expect(403);
      await http().put('/api/v1/scan-settings/rspamd').set(apiKey).send(body).expect(403);
      apiKeyPermissions = new Set([MANAGE]);
      await http().put('/api/v1/scan-settings/rspamd').set(apiKey).send(body).expect(200);
      expect(settingsRows.create).toHaveBeenCalledTimes(1);
    });

    it('404 for an engine that is not registered, before any database access', async () => {
      const res = await http()
        .put('/api/v1/scan-settings/clamav')
        .set(await bearer())
        .send({ expectedVersion: 0, settings: {} })
        .expect(404);
      expect(res.body.code).toBe('scan_engine_not_found');
      await http()
        .delete('/api/v1/scan-settings/nope?expectedVersion=0')
        .set(await bearer())
        .expect(404);
      expect(transactions.run).not.toHaveBeenCalled();
    });

    it('422 scan_settings_invalid with every violation, before any database access', async () => {
      const res = await http()
        .put('/api/v1/scan-settings/rspamd')
        .set(await bearer())
        .send({
          expectedVersion: 0,
          settings: { spamScore: 50, authFailureVerdict: 'reason_only', disabled: true },
        })
        .expect(422);
      expect(res.body).toMatchObject({ statusCode: 422, code: 'scan_settings_invalid' });
      expect(res.body.violations).toEqual([
        expect.objectContaining({ path: 'disabled', code: 'unknown_key' }),
      ]);
      const lowered = await http()
        .put('/api/v1/scan-settings/rspamd')
        .set(await bearer())
        .send({ expectedVersion: 0, settings: { spamScore: 50, suspiciousScore: 3 } })
        .expect(422);
      expect(lowered.body.violations).toEqual([
        expect.objectContaining({ path: 'spamScore', code: 'out_of_bounds' }),
      ]);
      expect(transactions.run).not.toHaveBeenCalled();
    });

    it.each([
      [{ settings: {} }, 'expectedVersion'],
      [{ expectedVersion: -1, settings: {} }, 'expectedVersion'],
      [{ expectedVersion: 0, settings: 'x' }, 'settings'],
      [{ expectedVersion: 0, settings: {}, extra: 1 }, 'Unrecognized key'],
    ])('400 for body %j', async (body, text) => {
      const res = await http()
        .put('/api/v1/scan-settings/rspamd')
        .set(await bearer())
        .send(body)
        .expect(400);
      expect(JSON.stringify(res.body.message)).toContain(text);
    });

    it('409 version_conflict when expectedVersion is not the current version', async () => {
      settingsRows.find.mockResolvedValueOnce({
        engine: 'rspamd',
        settings: { spamScore: 7 },
        version: 3,
        updatedAt: new Date(),
      });
      const res = await http()
        .put('/api/v1/scan-settings/rspamd')
        .set(await bearer())
        .send({ expectedVersion: 2, settings: { spamScore: 8 } })
        .expect(409);
      expect(res.body).toMatchObject({ code: 'version_conflict', currentVersion: 3 });
      await http()
        .delete('/api/v1/scan-settings/rspamd')
        .set(await bearer())
        .expect(400);
      expect(audit.record).not.toHaveBeenCalled();
    });
  });

  describe('POST /platform/organizations/{organizationId}/messages/{messageId}/scan-training', () => {
    beforeEach(() => principalWith([TRAIN], 'platform'));

    it('refuses API keys, sessions without MFA and users without the permission', async () => {
      apiKeyPermissions = new Set([TRAIN]);
      await http().post(trainUrl()).set(apiKey).send(learn).expect(403);
      await http()
        .post(trainUrl())
        .set(await bearer(['pwd']))
        .send(learn)
        .expect(403);
      principalWith([READ, POLICY_READ, MANAGE], 'platform');
      await http()
        .post(trainUrl())
        .set(await bearer())
        .send(learn)
        .expect(403);
      // A tenant administrator never holds the platform permission.
      principalWith([READ, POLICY_READ, MANAGE, 'message:rescan']);
      await http()
        .post(trainUrl())
        .set(await bearer())
        .send(learn)
        .expect(403);
      expect(training.findOrganization).not.toHaveBeenCalled();
    });

    it.each([
      [{ operation: 'fuzzy_add', reason: 'x' }, 'fuzzyFlag'],
      [{ ...learn, fuzzyFlag: 'spam' }, 'fuzzyFlag'],
      [{ operation: 'learn', reason: 'x' }, 'operation'],
      [{ operation: 'learn_ham' }, 'reason'],
      [{ ...learn, reason: 'x'.repeat(513) }, 'reason'],
    ])('400 for body %j', async (body, text) => {
      const res = await http()
        .post(trainUrl())
        .set(await bearer())
        .send(body)
        .expect(400);
      expect(JSON.stringify(res.body.message)).toContain(text);
    });

    it('404 for an unknown organization; 503 rspamd_unavailable without a controller', async () => {
      const missing = await http()
        .post(trainUrl(randomUUID()))
        .set(await bearer())
        .send(learn)
        .expect(404);
      expect(missing.body.code).toBe('organization_not_found');
      await http()
        .post(trainUrl('not-a-uuid'))
        .set(await bearer())
        .send(learn)
        .expect(400);
      const unavailable = await http()
        .post(trainUrl())
        .set(await bearer())
        .send(learn)
        .expect(503);
      expect(unavailable.body.code).toBe('rspamd_unavailable');
      // The refused call is audited with its outcome; no timeline event.
      expect(audit.record).toHaveBeenCalledTimes(1);
      expect(audit.record.mock.calls[0]![0]).toMatchObject({
        action: 'scan_training.learn_spam',
        resourceType: 'message',
        resourceId: knownMessage.publicId,
        metadata: { operation: 'learn_spam', outcome: 'rspamd_unavailable' },
      });
      expect(training.insertTrainingEvent).not.toHaveBeenCalled();
    });

    it('allows 60 calls per caller per minute (429 after)', async () => {
      const auth = await bearer();
      for (let i = 0; i < 60; i += 1) {
        await http().post(trainUrl(randomUUID())).set(auth).send(learn).expect(404);
      }
      await http().post(trainUrl(randomUUID())).set(auth).send(learn).expect(429);
    });
  });
});
