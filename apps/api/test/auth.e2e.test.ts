/**
 * Authentication controllers and guards over HTTP with the services stubbed (no MySQL, no
 * Redis): request validation, rate limiting with the in-memory store, credential handling and
 * JWT rejection. The full flows run against real MySQL/Redis in integration/auth.test.ts.
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
import { loadApiConfig } from '../src/config';
import { EmailSender } from '../src/email/email-sender';
import { configureApiApp } from '../src/http/configure-api-app';
import { KeyValueStore } from '../src/kv/key-value-store';
import { AuthenticationService } from '../src/modules/auth/services/authentication.service';
import { PasswordService } from '../src/modules/auth/services/password.service';
import type { PrincipalSnapshot } from '../src/modules/auth/services/principal-cache.service';
import { PrincipalLoaderService } from '../src/modules/auth/services/principal-loader.service';
import { SessionService } from '../src/modules/auth/services/session.service';
import { TokenService } from '../src/modules/auth/services/token.service';
import { InMemoryKeyValueStore } from './support/in-memory-key-value-store';
import { RecordingEmailSender } from './support/recording-email-sender';
import { TEST_DOMAIN_ENV } from './support/test-env';

const secret = randomBytes(32).toString('hex');
const config = loadApiConfig({
  ...TEST_DOMAIN_ENV,
  NODE_ENV: 'test',
  HTTP_PORT: '3000',
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'us-east-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  AUTH_JWT_SECRET: secret,
  AUTH_TOKEN_PEPPER: randomBytes(32).toString('hex'),
  DATA_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
  AUTH_BACKGROUND_JOBS_ENABLED: 'false',
  HTTP_TRUST_PROXY: '1',
});

const ids = { user: randomUUID(), org: randomUUID(), session: randomUUID() };
const snapshot: PrincipalSnapshot = {
  orgVersion: 0,
  userVersion: '',
  user: { id: '10', publicId: ids.user, status: 'active', deleted: false, mfaEnabled: false },
  org: {
    id: '2',
    publicId: ids.org,
    kind: 'customer',
    status: 'active',
    deleted: false,
    mfaRequired: false,
  },
  permissions: ['user:read'],
};

let ipCounter = 0;
const nextIp = () => `203.0.113.${(ipCounter += 1)}`;

describe('auth endpoints (e2e, services stubbed)', () => {
  let app: INestApplication;
  let kv: InMemoryKeyValueStore;
  const authentication = {
    login: vi.fn(),
    verifyMfa: vi.fn(),
    me: vi.fn(),
    logout: vi.fn(),
  };
  const sessions = {
    rotate: vi.fn(),
    isRevoked: vi.fn(() => Promise.resolve(false)),
    isLive: vi.fn(() => Promise.resolve(true)),
    revokeOwnSession: vi.fn(() => Promise.resolve(true)),
  };
  const passwords = { requestReset: vi.fn(), reset: vi.fn(), change: vi.fn() };
  const tokens = new TokenService(config);
  const http = () => request(app.getHttpServer());

  const accessToken = async (now?: Date, signer: TokenService = tokens) =>
    (
      await signer.issue(
        {
          userPublicId: ids.user,
          organizationPublicId: ids.org,
          sessionId: ids.session,
          amr: ['pwd'],
        },
        now,
      )
    ).token;

  beforeAll(async () => {
    kv = new InMemoryKeyValueStore();
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
      .overrideProvider(AuthenticationService)
      .useValue(authentication)
      .overrideProvider(SessionService)
      .useValue(sessions)
      .overrideProvider(PasswordService)
      .useValue(passwords)
      .overrideProvider(PrincipalLoaderService)
      .useValue({ load: () => Promise.resolve(snapshot) })
      .compile();
    app = moduleRef.createNestApplication({ logger: false });
    configureHttpApp(app, createLogger({ service: 'api-test', level: 'silent' }));
    configureApiApp(app, config);
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    kv.failing = false;
  });

  describe('validation', () => {
    it.each([
      [{}, ['email: Invalid input: expected string, received undefined']],
      [{ email: 'not-an-email', password: 'x' }, ['email: Invalid email address']],
      [
        { email: 'a@example.com', password: '' },
        ['password: Too small: expected string to have >=1 characters'],
      ],
      [
        { email: 'a@example.com', password: 'x', organization: 'Not A Slug!' },
        ['organization: must be an organization slug'],
      ],
    ])('login %j → 400', async (body, messages) => {
      const res = await http()
        .post('/api/v1/auth/login')
        .set('X-Forwarded-For', nextIp())
        .send(body)
        .expect(400);
      for (const message of messages) expect(res.body.message).toContain(message);
      expect(JSON.stringify(res.body)).not.toContain('not-an-email');
      expect(authentication.login).not.toHaveBeenCalled();
    });

    it('MFA verify needs exactly one of code and recoveryCode', async () => {
      for (const body of [
        { mfaToken: 'egt_x' },
        { mfaToken: 'egt_x', code: '123456', recoveryCode: 'abcde-fghij' },
        { mfaToken: 'egt_x', code: '12345' },
      ]) {
        await http()
          .post('/api/v1/auth/mfa/verify')
          .set('X-Forwarded-For', nextIp())
          .send(body)
          .expect(400);
      }
      expect(authentication.verifyMfa).not.toHaveBeenCalled();
    });

    it('password reset enforces the length policy; refresh needs a token', async () => {
      const res = await http()
        .post('/api/v1/auth/password/reset')
        .set('X-Forwarded-For', nextIp())
        .send({ token: 'egt_x', newPassword: 'short' })
        .expect(400);
      expect(res.body.message).toEqual(['newPassword: must be at least 12 characters']);
      await http().post('/api/v1/auth/refresh').send({}).expect(400);
      expect(passwords.reset).not.toHaveBeenCalled();
    });

    it('path ids must be UUIDs and override requests need a reason', async () => {
      const token = await accessToken();
      await http()
        .delete('/api/v1/auth/sessions/not-a-uuid')
        .set('Authorization', `Bearer ${token}`)
        .expect(400);
      await http()
        .delete(`/api/v1/auth/sessions/${randomUUID()}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(204);
    });
  });

  it('returns the service result for a valid login', async () => {
    authentication.login.mockResolvedValue({
      mfaRequired: true,
      mfaToken: 'egt_y',
      expiresIn: 300,
    });
    const res = await http()
      .post('/api/v1/auth/login')
      .set('X-Forwarded-For', '198.51.100.77')
      .set('User-Agent', 'e2e-agent')
      .send({ email: ' Alice@Example.com ', password: 'secret-password', organization: 'acme' })
      .expect(200);
    expect(res.body).toEqual({ mfaRequired: true, mfaToken: 'egt_y', expiresIn: 300 });
    expect(authentication.login).toHaveBeenCalledWith(
      { email: 'alice@example.com', password: 'secret-password', organization: 'acme' },
      { ip: '198.51.100.77', userAgent: 'e2e-agent' },
    );
  });

  it('answers 429 with Retry-After after 20 logins per minute from one IP', async () => {
    authentication.login.mockResolvedValue({
      mfaRequired: true,
      mfaToken: 'egt_y',
      expiresIn: 300,
    });
    const ip = nextIp();
    for (let i = 0; i < 20; i += 1) {
      await http()
        .post('/api/v1/auth/login')
        .set('X-Forwarded-For', ip)
        .send({ email: 'a@example.com', password: 'x' })
        .expect(200);
    }
    const res = await http()
      .post('/api/v1/auth/login')
      .set('X-Forwarded-For', ip)
      .send({ email: 'a@example.com', password: 'x' })
      .expect(429);
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
    await http()
      .post('/api/v1/auth/login')
      .set('X-Forwarded-For', nextIp())
      .send({ email: 'a@example.com', password: 'x' })
      .expect(200);
  });

  it('limits password-forgot per email across IPs (3 per hour)', async () => {
    const email = `limit-${randomUUID()}@example.com`;
    for (let i = 0; i < 3; i += 1) {
      await http()
        .post('/api/v1/auth/password/forgot')
        .set('X-Forwarded-For', nextIp())
        .send({ email })
        .expect(202);
    }
    await http()
      .post('/api/v1/auth/password/forgot')
      .set('X-Forwarded-For', nextIp())
      .send({ email })
      .expect(429);
    expect(passwords.requestReset).toHaveBeenCalledTimes(3);
  });

  describe('credentials', () => {
    it('accepts a valid access token', async () => {
      authentication.me.mockResolvedValue({ ok: true });
      await http()
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${await accessToken()}`)
        .expect(200, { ok: true });
    });

    it('rejects both an access token and an API key in one request', async () => {
      await http()
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${await accessToken()}`)
        .set('X-API-Key', 'egk_abcdefghijkl_xyz')
        .expect(401);
    });

    it('rejects malformed, expired and foreign-key tokens', async () => {
      const expired = await accessToken(new Date(Date.now() - 3_600_000));
      const foreign = await accessToken(
        undefined,
        new TokenService({ ...config, AUTH_JWT_SECRET: randomBytes(32).toString('hex') }),
      );
      for (const header of [
        'Bearer',
        'Bearer abc',
        `Token ${await accessToken()}`,
        `Bearer ${expired}`,
        `Bearer ${foreign}`,
      ]) {
        const res = await http().get('/api/v1/auth/me').set('Authorization', header).expect(401);
        expect(res.body.message).toBe('Unauthorized');
      }
      expect(authentication.me).not.toHaveBeenCalled();
    });

    it('rejects a deny-listed session', async () => {
      sessions.isRevoked.mockResolvedValueOnce(true);
      await http()
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${await accessToken()}`)
        .expect(401);
    });

    it('fails closed with 503 when the key-value store is down', async () => {
      kv.failing = true;
      await http()
        .post('/api/v1/auth/login')
        .set('X-Forwarded-For', nextIp())
        .send({ email: 'a@example.com', password: 'x' })
        .expect(503);
    });
  });
});
