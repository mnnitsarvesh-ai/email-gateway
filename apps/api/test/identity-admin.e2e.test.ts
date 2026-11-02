/**
 * Identity administration routes over HTTP with the services stubbed (no MySQL, no Redis):
 * request validation (400), authentication (401), authorization (403: permission, user-only,
 * MFA step-up) and that the tenant scope comes from the principal, never from a header. The full
 * flows run against MySQL/Redis in integration/identity-admin.test.ts.
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
import { TENANT_PERMISSIONS } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { AppModule } from '../src/app.module';
import type { ApiKeyPrincipal } from '../src/auth-contracts/principal';
import type { TenantScope } from '../src/auth-contracts/tenant-scope';
import { loadApiConfig } from '../src/config';
import { EmailSender } from '../src/email/email-sender';
import { configureApiApp } from '../src/http/configure-api-app';
import { KeyValueStore } from '../src/kv/key-value-store';
import { ApiKeysService } from '../src/modules/api-keys/api-keys.service';
import { ApiKeyAuthenticatorService } from '../src/modules/auth/services/api-key-authenticator.service';
import type { PrincipalSnapshot } from '../src/modules/auth/services/principal-cache.service';
import { PrincipalLoaderService } from '../src/modules/auth/services/principal-loader.service';
import { SessionService } from '../src/modules/auth/services/session.service';
import { type AuthMethod, TokenService } from '../src/modules/auth/services/token.service';
import { LoginEventsService } from '../src/modules/login-audit/login-events.service';
import { RolesService } from '../src/modules/roles/roles.service';
import { UsersService } from '../src/modules/users/users.service';
import { InMemoryKeyValueStore } from './support/in-memory-key-value-store';
import { RecordingEmailSender } from './support/recording-email-sender';
import { TEST_DOMAIN_ENV } from './support/test-env';

const config = loadApiConfig({
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
  HTTP_TRUST_PROXY: '1',
});

const ids = { user: randomUUID(), org: randomUUID(), session: randomUUID() };
const API_KEY = `egk_ABCDEFGHIJKL_${randomBytes(32).toString('base64url')}`;
let permissions: string[] = [...TENANT_PERMISSIONS];

const snapshot = (): PrincipalSnapshot => ({
  orgVersion: 0,
  userVersion: '',
  user: { id: '10', publicId: ids.user, status: 'active', deleted: false, mfaEnabled: true },
  org: {
    id: '2',
    publicId: ids.org,
    kind: 'customer',
    status: 'active',
    deleted: false,
    mfaRequired: false,
  },
  permissions,
});

const apiKeyPrincipal = (): ApiKeyPrincipal => ({
  kind: 'api_key',
  apiKeyId: 5n,
  apiKeyPublicId: randomUUID(),
  organizationId: 2n,
  organizationPublicId: ids.org,
  permissions: new Set(permissions),
});

describe('identity administration (e2e, services stubbed)', () => {
  let app: INestApplication;
  const tokens = new TokenService(config);
  const users = {
    list: vi.fn(() => Promise.resolve({ data: [], nextCursor: null })),
    get: vi.fn(),
    invite: vi.fn(() => Promise.resolve({ id: randomUUID() })),
    resendInvitation: vi.fn(() => Promise.resolve({ expiresAt: new Date().toISOString() })),
    updateProfile: vi.fn(() => Promise.resolve({})),
    changeStatus: vi.fn(() => Promise.resolve({})),
    replaceRoles: vi.fn(() => Promise.resolve({})),
    remove: vi.fn(() => Promise.resolve()),
    resetMfa: vi.fn(() => Promise.resolve()),
    listSessions: vi.fn(() => Promise.resolve([])),
    revokeAllSessions: vi.fn(() => Promise.resolve()),
    revokeSession: vi.fn(() => Promise.resolve()),
  };
  const roles = {
    listPermissions: vi.fn(() => Promise.resolve([])),
    list: vi.fn(() => Promise.resolve([])),
    get: vi.fn(() => Promise.resolve({})),
    create: vi.fn(() => Promise.resolve({})),
    update: vi.fn(() => Promise.resolve({})),
    remove: vi.fn(() => Promise.resolve()),
  };
  const apiKeys = {
    list: vi.fn(() => Promise.resolve({ data: [], nextCursor: null })),
    create: vi.fn(() => Promise.resolve({})),
    revoke: vi.fn(() => Promise.resolve()),
  };
  const loginEvents = { list: vi.fn(() => Promise.resolve({ data: [], nextCursor: null })) };
  const http = () => request(app.getHttpServer());

  const bearer = async (amr: AuthMethod[] = ['pwd']) => {
    const { token } = await tokens.issue({
      userPublicId: ids.user,
      organizationPublicId: ids.org,
      sessionId: ids.session,
      amr,
    });
    return { Authorization: `Bearer ${token}` };
  };

  beforeAll(async () => {
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
      .useValue({ load: () => Promise.resolve(snapshot()) })
      .overrideProvider(ApiKeyAuthenticatorService)
      .useValue({
        authenticate: (key: string) => Promise.resolve(key === API_KEY ? apiKeyPrincipal() : null),
      })
      .overrideProvider(UsersService)
      .useValue(users)
      .overrideProvider(RolesService)
      .useValue(roles)
      .overrideProvider(ApiKeysService)
      .useValue(apiKeys)
      .overrideProvider(LoginEventsService)
      .useValue(loginEvents)
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
    permissions = [...TENANT_PERMISSIONS];
  });

  const ID = randomUUID();

  describe('authentication', () => {
    it.each([
      ['get', '/api/v1/users'],
      ['post', '/api/v1/users/invitations'],
      ['patch', `/api/v1/users/${ID}/status`],
      ['get', '/api/v1/roles'],
      ['get', '/api/v1/permissions'],
      ['post', '/api/v1/api-keys'],
      ['get', '/api/v1/audit/login-events'],
    ] as const)('%s %s without credentials → 401', async (method, path) => {
      await http()[method](path).expect(401);
    });

    it('rejects an unknown API key and a malformed bearer token', async () => {
      await http().get('/api/v1/users').set('X-API-Key', 'egk_nope').expect(401);
      await http().get('/api/v1/users').set('Authorization', 'Bearer nope').expect(401);
    });
  });

  describe('validation (400, services not called)', () => {
    it.each([
      ['post', '/api/v1/users/invitations', {}],
      ['post', '/api/v1/users/invitations', { email: 'x', displayName: 'X', roleKeys: ['a_b'] }],
      [
        'post',
        '/api/v1/users/invitations',
        { email: 'a@example.test', displayName: 'X', roleKeys: [] },
      ],
      ['patch', `/api/v1/users/${ID}`, {}],
      ['patch', `/api/v1/users/${ID}/status`, { status: 'disabled' }],
      ['patch', `/api/v1/users/${ID}/status`, { status: 'locked', reason: 'x' }],
      ['put', `/api/v1/users/${ID}/roles`, { roleKeys: ['Bad Key'] }],
      ['post', '/api/v1/roles', { key: 'ab', name: 'x', permissions: ['user:read'] }],
      ['post', '/api/v1/roles', { key: 'mail_ops', name: 'x', permissions: [] }],
      ['put', '/api/v1/roles/mail_ops', { name: '', permissions: ['user:read'] }],
      ['post', '/api/v1/api-keys', { name: 'ci', scopes: [] }],
      ['post', '/api/v1/api-keys', { name: 'ci', scopes: ['user:read'], expiresAt: 'tomorrow' }],
    ] as const)('%s %s %j → 400', async (method, path, body) => {
      const res = await http()
        [method](path)
        .set(await bearer(['pwd', 'otp']))
        .send(body)
        .expect(400);
      expect(Array.isArray(res.body.message)).toBe(true);
      for (const stub of [users, roles, apiKeys]) {
        for (const fn of Object.values(stub)) expect(fn).not.toHaveBeenCalled();
      }
    });

    it.each([
      '/api/v1/users/not-a-uuid',
      '/api/v1/users?limit=0',
      '/api/v1/users?status=deleted',
      '/api/v1/roles/Not-A-Key',
      '/api/v1/api-keys?limit=101',
      '/api/v1/audit/login-events?outcome=maybe',
      '/api/v1/audit/login-events?from=yesterday',
      '/api/v1/audit/login-events?userId=42',
    ])('GET %s → 400', async (path) => {
      await http()
        .get(path)
        .set(await bearer())
        .expect(400);
    });

    it('session and API key ids must be UUIDs', async () => {
      const headers = await bearer();
      await http().delete(`/api/v1/users/${ID}/sessions/not-a-uuid`).set(headers).expect(400);
      await http().delete('/api/v1/api-keys/not-a-uuid').set(headers).expect(400);
      expect(users.revokeSession).not.toHaveBeenCalled();
      expect(apiKeys.revoke).not.toHaveBeenCalled();
    });

    it('does not echo invalid input', async () => {
      const res = await http()
        .post('/api/v1/users/invitations')
        .set(await bearer())
        .send({ email: 'secret-looking-value', displayName: 'X', roleKeys: ['read_only_user'] })
        .expect(400);
      expect(JSON.stringify(res.body)).not.toContain('secret-looking-value');
    });
  });

  describe('authorization (403)', () => {
    it('requires the route permission', async () => {
      permissions = ['user:read', 'role:read'];
      const headers = await bearer(['pwd', 'otp']);
      await http()
        .post('/api/v1/users/invitations')
        .set(headers)
        .send({ email: 'a@example.test', displayName: 'A', roleKeys: ['read_only_user'] })
        .expect(403);
      await http().delete(`/api/v1/users/${ID}`).set(headers).expect(403);
      await http().get(`/api/v1/users/${ID}/sessions`).set(headers).expect(403);
      await http().get('/api/v1/api-keys').set(headers).expect(403);
      await http().get('/api/v1/audit/login-events').set(headers).expect(403);
      await http()
        .post('/api/v1/roles')
        .set(headers)
        .send({ key: 'mail_ops', name: 'M', permissions: ['user:read'] })
        .expect(403);
      await http().get('/api/v1/users').set(headers).expect(200);
      expect(users.invite).not.toHaveBeenCalled();
      expect(users.remove).not.toHaveBeenCalled();
    });

    it('MFA reset needs an MFA-authenticated session', async () => {
      const res = await http()
        .post(`/api/v1/users/${ID}/mfa/reset`)
        .set(await bearer(['pwd']))
        .expect(403);
      expect(res.body.message).toBe('MFA required');
      await http()
        .post(`/api/v1/users/${ID}/mfa/reset`)
        .set(await bearer(['pwd', 'otp']))
        .expect(204);
      expect(users.resetMfa).toHaveBeenCalledTimes(1);
    });

    it('API keys reach K routes but not user-only routes', async () => {
      const key = { 'X-API-Key': API_KEY };
      await http().get('/api/v1/users').set(key).expect(200);
      await http().get('/api/v1/roles').set(key).expect(200);
      await http().get('/api/v1/audit/login-events').set(key).expect(200);
      await http()
        .post('/api/v1/users/invitations')
        .set(key)
        .send({ email: 'a@example.test', displayName: 'A', roleKeys: ['read_only_user'] })
        .expect(201);
      await http()
        .post('/api/v1/api-keys')
        .set(key)
        .send({ name: 'ci', scopes: ['user:read'] })
        .expect(403);
      await http()
        .post('/api/v1/roles')
        .set(key)
        .send({ key: 'mail_ops', name: 'M', permissions: ['user:read'] })
        .expect(403);
      await http().delete(`/api/v1/api-keys/${ID}`).set(key).expect(403);
      await http().post(`/api/v1/users/${ID}/mfa/reset`).set(key).expect(403);
      expect(apiKeys.create).not.toHaveBeenCalled();
      expect(roles.create).not.toHaveBeenCalled();
    });
  });

  describe('tenant scope', () => {
    it('comes from the principal, never from client headers', async () => {
      await http()
        .get('/api/v1/users?status=active&q=al&role=read_only_user&limit=5')
        .set(await bearer())
        .set('X-Organization-Id', '999')
        .set('X-Tenant-Id', '999')
        .expect(200);
      const [scope, query] = users.list.mock.calls[0] as unknown as [TenantScope, object];
      expect(scope).toMatchObject({ organizationId: 2n, via: 'member' });
      expect(query).toEqual({ limit: 5, status: 'active', q: 'al', role: 'read_only_user' });
    });

    it('passes validated, normalized bodies and the client IP to the services', async () => {
      await http()
        .post('/api/v1/users/invitations')
        .set(await bearer())
        .set('X-Forwarded-For', '198.51.100.20')
        .send({
          email: ' New.User@Example.TEST ',
          displayName: ' New ',
          roleKeys: ['read_only_user', 'read_only_user'],
        })
        .expect(201);
      const call = users.invite.mock.calls[0] as unknown as [unknown, TenantScope, object, object];
      expect(call[2]).toEqual({
        email: 'new.user@example.test',
        displayName: 'New',
        roleKeys: ['read_only_user'],
      });
      expect(call[3]).toMatchObject({ ip: '198.51.100.20' });
    });

    it('answers 204 for deletes and revocations and 202 for invitation resends', async () => {
      const headers = await bearer();
      await http().delete(`/api/v1/users/${ID}`).set(headers).expect(204);
      await http().delete(`/api/v1/users/${ID}/sessions`).set(headers).expect(204);
      await http().delete(`/api/v1/users/${ID}/sessions/${randomUUID()}`).set(headers).expect(204);
      await http().delete('/api/v1/roles/mail_ops').set(headers).expect(204);
      await http().delete(`/api/v1/api-keys/${ID}`).set(headers).expect(204);
      await http().post(`/api/v1/users/${ID}/invitation`).set(headers).expect(202);
    });
  });
});
