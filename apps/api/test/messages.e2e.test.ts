/**
 * Message lifecycle routes (step 3.3 L10, L12) over HTTP with MySQL, Redis and S3 stubbed:
 * authorization (401, 403 per permission, users and API keys), request validation before any
 * database access (400 with the coded Idempotency-Key errors, invalid ids and bodies), the 202
 * with the `Idempotency-Replayed` header, and the coded 404 body of the read routes. The writes
 * against the real writer and replica run in integration/messages-lifecycle.test.ts.
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
import type { ApiKeyPrincipal } from '../src/auth-contracts/principal';
import { loadApiConfig } from '../src/config';
import { EmailSender } from '../src/email/email-sender';
import { configureApiApp } from '../src/http/configure-api-app';
import { TransactionRunner } from '../src/database/transaction-runner';
import { KeyValueStore } from '../src/kv/key-value-store';
import { ApiKeyAuthenticatorService } from '../src/modules/auth/services/api-key-authenticator.service';
import type { PrincipalSnapshot } from '../src/modules/auth/services/principal-cache.service';
import { PrincipalLoaderService } from '../src/modules/auth/services/principal-loader.service';
import { SessionService } from '../src/modules/auth/services/session.service';
import { TokenService } from '../src/modules/auth/services/token.service';
import { RESCAN_NOTE } from '../src/modules/messages/domain/lifecycle-operations';
import { quarantineWorkflowRequired } from '../src/modules/messages/messages.errors';
import {
  type LifecycleMessageRow,
  MessageLifecycleReadRepository,
} from '../src/modules/messages/repositories/message-lifecycle-read.repository';
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

const READ = 'message:read';
const RESCAN = 'message:rescan';
const RELEASE = 'quarantine:release';
const ids = { user: randomUUID(), org: randomUUID(), session: randomUUID() };

let snapshot: PrincipalSnapshot;
function principalWith(permissions: string[]): void {
  snapshot = {
    orgVersion: 0,
    userVersion: '',
    user: { id: '10', publicId: ids.user, status: 'active', deleted: false, mfaEnabled: false },
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

const apiKeyPrincipal: ApiKeyPrincipal = {
  kind: 'api_key',
  apiKeyId: 5n,
  apiKeyPublicId: randomUUID(),
  organizationId: 1n,
  organizationPublicId: ids.org,
  permissions: new Set([READ]),
};

const knownMessage: LifecycleMessageRow = {
  id: 77n,
  publicId: randomUUID(),
  receivedAt: new Date('2026-11-04T08:00:00.000Z'),
  direction: 'inbound',
  status: 'held_for_review',
  statusReason: 'policy_hold',
  version: 6,
  lifecycleRound: 0,
  statusChangedAt: new Date('2026-11-04T08:01:00.000Z'),
};

const valid = { expectedVersion: 3, reason: 'operator reviewed the headers' };

describe('message lifecycle routes (e2e, dependencies stubbed)', () => {
  let app: INestApplication;
  const transactions = { run: vi.fn(() => Promise.reject(new Error('no database in e2e'))) };
  const tokens = new TokenService(loadApiConfig(env));
  const http = () => request(app.getHttpServer());
  const bearer = async () => {
    const { token } = await tokens.issue({
      userPublicId: ids.user,
      organizationPublicId: ids.org,
      sessionId: ids.session,
      amr: ['pwd'],
    });
    return { Authorization: `Bearer ${token}` };
  };
  const apiKey = { 'X-API-Key': `egk_${'a'.repeat(12)}_${'b'.repeat(43)}` };
  const id = randomUUID();

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
      .useValue(new InMemoryKeyValueStore())
      .overrideProvider(EmailSender)
      .useValue(new RecordingEmailSender())
      .overrideProvider(SessionService)
      .useValue({ isRevoked: () => Promise.resolve(false), isLive: () => Promise.resolve(true) })
      .overrideProvider(PrincipalLoaderService)
      .useValue({ load: () => Promise.resolve(snapshot) })
      .overrideProvider(ApiKeyAuthenticatorService)
      .useValue({ authenticate: () => Promise.resolve(apiKeyPrincipal) })
      .overrideProvider(TransactionRunner)
      .useValue(transactions)
      .overrideProvider(MessageLifecycleReadRepository)
      .useValue({
        findMessage: (_scope: unknown, publicId: string) =>
          Promise.resolve(publicId === knownMessage.publicId ? knownMessage : null),
        parseOf: () => Promise.resolve(null),
        recipientCounts: () => Promise.resolve(new Map([['quarantined', 2]])),
        maxDeliverySeq: () => Promise.resolve(null),
        history: () => Promise.resolve([]),
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
    vi.clearAllMocks();
    principalWith([READ, RESCAN, RELEASE]);
  });

  it('answers 401 without credentials', async () => {
    await http().get(`/api/v1/messages/${id}/lifecycle`).expect(401);
    await http().get(`/api/v1/messages/${id}/lifecycle/history`).expect(401);
    await http().post(`/api/v1/messages/${id}/rescan`).send(valid).expect(401);
    await http().post(`/api/v1/messages/${id}/release`).send(valid).expect(401);
  });

  it('requires message:read, message:rescan and quarantine:release (403)', async () => {
    principalWith([RESCAN, RELEASE]);
    await http()
      .get(`/api/v1/messages/${id}/lifecycle`)
      .set(await bearer())
      .expect(403);
    await http()
      .get(`/api/v1/messages/${id}/lifecycle/history`)
      .set(await bearer())
      .expect(403);
    principalWith([READ, RELEASE]);
    await http()
      .post(`/api/v1/messages/${id}/rescan`)
      .set(await bearer())
      .set('Idempotency-Key', 'k1')
      .send(valid)
      .expect(403);
    principalWith([READ, RESCAN, 'quarantine:read']);
    await http()
      .post(`/api/v1/messages/${id}/release`)
      .set(await bearer())
      .set('Idempotency-Key', 'k1')
      .send(valid)
      .expect(403);
    // An API key with message:read only.
    await http().post(`/api/v1/messages/${id}/rescan`).set(apiKey).send(valid).expect(403);
    await http().post(`/api/v1/messages/${id}/release`).set(apiKey).send(valid).expect(403);
    expect(transactions.run).not.toHaveBeenCalled();
  });

  it('reads the lifecycle (200) and answers the coded 404 for an unknown message', async () => {
    const res = await http()
      .get(`/api/v1/messages/${knownMessage.publicId}/lifecycle`)
      .set(apiKey)
      .expect(200);
    expect(res.body).toEqual({
      messageId: knownMessage.publicId,
      receivedAt: '2026-11-04T08:00:00.000Z',
      direction: 'inbound',
      state: 'held_for_review',
      statusReason: 'policy_hold',
      version: 6,
      lifecycleRound: 0,
      statusChangedAt: '2026-11-04T08:01:00.000Z',
      parse: null,
      recipients: { total: 2, byStatus: { quarantined: 2 } },
      deliverySeq: null,
      actions: { rescan: true, release: true },
    });
    const missing = await http().get(`/api/v1/messages/${id}/lifecycle`).set(apiKey).expect(404);
    expect(missing.body).toMatchObject({
      statusCode: 404,
      code: 'message_not_found',
      message: 'Message not found',
    });
    const history = await http()
      .get(`/api/v1/messages/${knownMessage.publicId}/lifecycle/history?limit=5`)
      .set(apiKey)
      .expect(200);
    expect(history.body).toEqual({ data: [], nextCursor: null });
  });

  it.each([
    ['lifecycle', '/api/v1/messages/not-a-uuid/lifecycle'],
    ['history', '/api/v1/messages/not-a-uuid/lifecycle/history'],
    ['history cursor', `/api/v1/messages/${randomUUID()}/lifecycle/history?cursor=bogus`],
    ['history limit', `/api/v1/messages/${randomUUID()}/lifecycle/history?limit=0`],
    ['history unknown query', `/api/v1/messages/${randomUUID()}/lifecycle/history?x=1`],
  ])('GET %s with invalid input → 400', async (_label, path) => {
    await http().get(path).set(apiKey).expect(400);
  });

  describe.each(['rescan', 'release'])('POST %s validation (before any database access)', (op) => {
    const url = (messageId: string) => `/api/v1/messages/${messageId}/${op}`;

    it('400 idempotency_key_required without the header', async () => {
      const res = await http()
        .post(url(id))
        .set(await bearer())
        .send(valid)
        .expect(400);
      expect(res.body).toMatchObject({
        statusCode: 400,
        code: 'idempotency_key_required',
        correlationId: expect.any(String),
      });
    });

    it.each(['has space', 'x'.repeat(129), 'a/b', 'a;b'])(
      '400 idempotency_key_invalid for %j',
      async (key) => {
        const res = await http()
          .post(url(id))
          .set(await bearer())
          .set('Idempotency-Key', key)
          .send(valid);
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('idempotency_key_invalid');
        expect(JSON.stringify(res.body)).not.toContain('has space');
      },
    );

    it.each([
      [
        { reason: valid.reason },
        'expectedVersion: Invalid input: expected number, received undefined',
      ],
      [{ ...valid, expectedVersion: -1 }, 'expectedVersion: Too small: expected number to be >=0'],
      [
        { ...valid, expectedVersion: 1.5 },
        'expectedVersion: Invalid input: expected int, received number',
      ],
      [{ ...valid, reason: 'short' }, 'reason: Too small: expected string to have >=10 characters'],
      [
        { ...valid, reason: 'x'.repeat(501) },
        'reason: Too big: expected string to have <=500 characters',
      ],
      [{ ...valid, extra: true }, '(root): Unrecognized key: "extra"'],
    ])('400 for body %j', async (body, message) => {
      const res = await http()
        .post(url(id))
        .set(await bearer())
        .set('Idempotency-Key', 'key-1')
        .send(body)
        .expect(400);
      expect(res.body.message).toContain(message);
    });

    it('400 for a message id that is not a UUID', async () => {
      const res = await http()
        .post(url('not-a-uuid'))
        .set(await bearer())
        .set('Idempotency-Key', 'key-1')
        .send(valid)
        .expect(400);
      expect(res.body.message).toEqual(['messageId: Invalid UUID']);
    });

    afterAll(() => {
      expect(transactions.run).not.toHaveBeenCalled();
    });
  });

  it('answers 202 and marks a replayed response with Idempotency-Replayed: true', async () => {
    const stored = {
      messageId: id,
      state: 'scanning',
      version: 4,
      lifecycleRound: 1,
      rescanEventId: randomUUID(),
      note: RESCAN_NOTE,
    };
    transactions.run.mockImplementationOnce(() =>
      Promise.resolve({ replayed: true, statusCode: 202, body: stored } as never),
    );
    const res = await http()
      .post(`/api/v1/messages/${id}/rescan`)
      .set(await bearer())
      .set('Idempotency-Key', 'key-1')
      .send(valid)
      .expect(202);
    expect(res.headers['idempotency-replayed']).toBe('true');
    expect(res.body).toEqual(stored);
  });

  it('a first (not replayed) 202 has no replay header', async () => {
    transactions.run.mockImplementationOnce(() =>
      Promise.resolve({ replayed: false, statusCode: 202, body: { ok: true } } as never),
    );
    const res = await http()
      .post(`/api/v1/messages/${id}/rescan`)
      .set(await bearer())
      .set('Idempotency-Key', 'key-2')
      .send(valid)
      .expect(202);
    expect(res.headers['idempotency-replayed']).toBeUndefined();
  });

  it('release (step 5.3 Q30): the coded 409 quarantine_workflow_required body', async () => {
    transactions.run.mockImplementationOnce(() =>
      Promise.reject(quarantineWorkflowRequired({ state: 'quarantined', version: 4 }, 2)),
    );
    const res = await http()
      .post(`/api/v1/messages/${id}/release`)
      .set(await bearer())
      .set('Idempotency-Key', 'key-3')
      .send(valid)
      .expect(409);
    expect(res.body).toMatchObject({
      code: 'quarantine_workflow_required',
      currentState: 'quarantined',
      currentVersion: 4,
      entries: 2,
      route: 'POST /api/v1/quarantine/entries/{entryId}/release',
    });
  });
});
