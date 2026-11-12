/**
 * Dead-letter routes (step 3.2 Q9) over HTTP with MySQL, Redis and the broker stubbed: request
 * validation (400, nothing reaches the broker), authorization (401, 403 per permission, MFA
 * step-up, API keys refused), 503 without RABBITMQ_OPS_URL and 409 while another replay holds the
 * lock. The full replay against a real broker runs in integration/dead-letters.test.ts.
 */
// ---- Route coverage (step 6.1 §3.8, test/route-coverage/legacy.ts) ----
// @covers get /api/v1/platform/dead-letters
// @covers post /api/v1/platform/dead-letters/replay
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
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { AppModule } from '../src/app.module';
import { AuditService } from '../src/audit/audit.service';
import type { ApiKeyPrincipal } from '../src/auth-contracts/principal';
import { loadApiConfig } from '../src/config';
import { EmailSender } from '../src/email/email-sender';
import { configureApiApp } from '../src/http/configure-api-app';
import { KeyValueStore } from '../src/kv/key-value-store';
import { ApiKeyAuthenticatorService } from '../src/modules/auth/services/api-key-authenticator.service';
import type { PrincipalSnapshot } from '../src/modules/auth/services/principal-cache.service';
import { PrincipalLoaderService } from '../src/modules/auth/services/principal-loader.service';
import { SessionService } from '../src/modules/auth/services/session.service';
import { type AuthMethod, TokenService } from '../src/modules/auth/services/token.service';
import {
  DeadLetterBroker,
  type DeadLetterSession,
} from '../src/modules/dead-letters/broker/dead-letter-broker';
import { REPLAY_LOCK_KEY } from '../src/modules/dead-letters/domain/dead-letter-replay';
import { idem, withIdempotencyStore } from './legacy-idempotency-support';
import { InMemoryIdempotencyStore } from './support/api-test-app';
import { InMemoryKeyValueStore } from './support/in-memory-key-value-store';
import { RecordingEmailSender } from './support/recording-email-sender';
import { TEST_DOMAIN_ENV } from './support/test-env';

const baseEnv = {
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

const ids = { user: randomUUID(), org: randomUUID(), session: randomUUID() };
const REPLAY = 'platform:dead_letter_replay';
const OPERATIONS = 'platform:operations';

let snapshot: PrincipalSnapshot;
function principalWith(permissions: string[]): void {
  snapshot = {
    orgVersion: 0,
    userVersion: '',
    user: { id: '10', publicId: ids.user, status: 'active', deleted: false, mfaEnabled: true },
    org: {
      id: '1',
      publicId: ids.org,
      kind: 'platform',
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
  permissions: new Set([REPLAY, OPERATIONS]),
};

/** An empty dead-letter queue; `open` is a spy so tests can assert the broker was not reached. */
function emptySession(): DeadLetterSession {
  return {
    get: () => Promise.resolve(null),
    ack: () => undefined,
    requeue: () => undefined,
    republish: () => Promise.resolve(),
    stats: () => Promise.resolve({ messages: 3, consumers: 0 }),
    close: () => Promise.resolve(),
  };
}

const valid = {
  sourceQueue: 'email.received',
  limit: 10,
  reason: 'replay after the parser fix',
};

async function buildApp(
  env: Record<string, string>,
  overrides: { broker?: DeadLetterBroker; kv: InMemoryKeyValueStore },
): Promise<INestApplication> {
  const config = loadApiConfig({ ...baseEnv, ...env });
  const stub = (healthName: string) => ({ healthName, checkHealth: () => Promise.resolve() });
  let builder = Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
    .overrideProvider(PrismaService)
    .useValue(stub('mysql'))
    .overrideProvider(PrismaReadService)
    .useValue(stub('mysql-reader'))
    .overrideProvider(RedisService)
    .useValue(stub('redis'))
    .overrideProvider(S3Service)
    .useValue(stub('s3'))
    .overrideProvider(KeyValueStore)
    .useValue(overrides.kv)
    .overrideProvider(EmailSender)
    .useValue(new RecordingEmailSender())
    .overrideProvider(SessionService)
    .useValue({ isRevoked: () => Promise.resolve(false), isLive: () => Promise.resolve(true) })
    .overrideProvider(PrincipalLoaderService)
    .useValue({ load: () => Promise.resolve(snapshot) })
    .overrideProvider(ApiKeyAuthenticatorService)
    .useValue({ authenticate: () => Promise.resolve(apiKeyPrincipal) })
    .overrideProvider(AuditService)
    .useValue({
      actorFrom: () => ({ type: 'user', id: ids.user }),
      record: () => Promise.resolve(),
    });
  if (overrides.broker) {
    builder = builder.overrideProvider(DeadLetterBroker).useValue(overrides.broker);
  }
  // Step 6.1 §3.5: the replay is a legacy sensitive mutation (Idempotency-Key, in memory here).
  builder = withIdempotencyStore(builder, new InMemoryIdempotencyStore());
  const moduleRef = await builder.compile();
  const app = moduleRef.createNestApplication({ logger: false });
  configureHttpApp(app, createLogger({ service: 'api-test', level: 'silent' }));
  configureApiApp(app, config);
  await app.init();
  return app;
}

describe('dead-letter routes (e2e, broker stubbed)', () => {
  let app: INestApplication;
  let unconfigured: INestApplication;
  const kv = new InMemoryKeyValueStore();
  const broker = { configured: true, open: vi.fn(() => Promise.resolve(emptySession())) };
  const tokens = new TokenService(loadApiConfig(baseEnv));
  const http = () => request(app.getHttpServer());

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

  beforeAll(async () => {
    app = await buildApp(
      { RABBITMQ_OPS_URL: 'amqp://eg-ops:unused@127.0.0.1:1/email-gateway' },
      { broker: broker, kv },
    );
    // No RABBITMQ_OPS_URL and the real broker class.
    unconfigured = await buildApp({}, { kv: new InMemoryKeyValueStore() });
  });

  afterAll(async () => {
    await app?.close();
    await unconfigured?.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    kv.entries.clear();
    principalWith([REPLAY, OPERATIONS]);
  });

  it('answers 401 without credentials', async () => {
    await http().get('/api/v1/platform/dead-letters').expect(401);
    await http().post('/api/v1/platform/dead-letters/replay').send(valid).expect(401);
    expect(broker.open).not.toHaveBeenCalled();
  });

  it.each([
    [{ ...valid, sourceQueue: 'scan.auth' }, 'sourceQueue: source_queue_not_replayable'],
    [{ ...valid, sourceQueue: 'email.delivery.retry' }, 'sourceQueue: source_queue_not_replayable'],
    [{ ...valid, sourceQueue: 'email.dead-letter' }, 'sourceQueue: source_queue_not_replayable'],
    [{ ...valid, limit: 0 }, 'limit: Too small: expected number to be >=1'],
    [{ ...valid, limit: 1001 }, 'limit: Too big: expected number to be <=1000'],
    [{ ...valid, reason: 'short' }, 'reason: Too small: expected string to have >=10 characters'],
    [{ ...valid, organizationId: 'not-a-uuid' }, 'organizationId: Invalid UUID'],
    [
      { ...valid, eventType: 'received' },
      'eventType: must be a versioned event type such as mail.message.received.v1',
    ],
    [
      { ...valid, failureReason: 'Max Attempts' },
      'failureReason: must be a failure reason code such as max_attempts_exceeded',
    ],
    [{ ...valid, dryRun: 'yes' }, 'dryRun: Invalid input: expected boolean, received string'],
    [{ ...valid, extra: 1 }, '(root): Unrecognized key: "extra"'],
  ])('POST replay %j → 400', async (body, message) => {
    const res = await http()
      .post('/api/v1/platform/dead-letters/replay')
      .set(await bearer())
      .set(idem())
      .send(body)
      .expect(400);
    expect(res.body.message).toContain(message);
    expect(broker.open).not.toHaveBeenCalled();
  });

  it('requires platform:dead_letter_replay for the replay and platform:operations for the view', async () => {
    principalWith([OPERATIONS]);
    await http()
      .post('/api/v1/platform/dead-letters/replay')
      .set(await bearer())
      .set(idem())
      .send(valid)
      .expect(403);
    principalWith([REPLAY]);
    await http()
      .get('/api/v1/platform/dead-letters')
      .set(await bearer())
      .expect(403);
    expect(broker.open).not.toHaveBeenCalled();
  });

  it('requires an MFA session for the replay', async () => {
    const res = await http()
      .post('/api/v1/platform/dead-letters/replay')
      .set(await bearer(['pwd']))
      .set(idem())
      .send(valid)
      .expect(403);
    expect(JSON.stringify(res.body.message)).toMatch(/MFA/i);
    expect(broker.open).not.toHaveBeenCalled();
  });

  it('refuses API keys, even with both permissions', async () => {
    await http().post('/api/v1/platform/dead-letters/replay').set(apiKey).send(valid).expect(403);
    await http().get('/api/v1/platform/dead-letters').set(apiKey).expect(403);
    expect(broker.open).not.toHaveBeenCalled();
  });

  it('answers 409 replay_in_progress while another replay holds the lock', async () => {
    await kv.setIfAbsent(REPLAY_LOCK_KEY, randomUUID(), 300);
    const res = await http()
      .post('/api/v1/platform/dead-letters/replay')
      .set(await bearer())
      .set(idem())
      .send(valid)
      .expect(409);
    expect(res.body.message).toBe('replay_in_progress');
    expect(broker.open).not.toHaveBeenCalled();
  });

  it('replays (nothing to do) and shows the queue depth with a configured broker', async () => {
    const res = await http()
      .post('/api/v1/platform/dead-letters/replay')
      .set(await bearer())
      .set(idem())
      .send({ ...valid, dryRun: true })
      .expect(200);
    expect(res.body).toMatchObject({
      dryRun: true,
      scanned: 0,
      matched: 0,
      replayed: 0,
      skipped: { invalid: 0, notMatching: 0 },
      items: [],
    });
    expect(await kv.get(REPLAY_LOCK_KEY)).toBeNull();
    const stats = await http()
      .get('/api/v1/platform/dead-letters')
      .set(await bearer(['pwd']))
      .expect(200);
    expect(stats.body).toEqual({ queue: 'email.dead-letter', messages: 3, consumers: 0 });
  });

  it('answers 503 dead_letter_replay_unavailable without RABBITMQ_OPS_URL', async () => {
    const server = () => request(unconfigured.getHttpServer());
    const replay = await server()
      .post('/api/v1/platform/dead-letters/replay')
      .set(await bearer())
      .set(idem())
      .send(valid)
      .expect(503);
    expect(replay.body.message).toBe('dead_letter_replay_unavailable');
    const view = await server()
      .get('/api/v1/platform/dead-letters')
      .set(await bearer())
      .expect(503);
    expect(view.body.message).toBe('dead_letter_replay_unavailable');
  });
});
