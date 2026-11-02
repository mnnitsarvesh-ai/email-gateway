/**
 * Organization endpoints over HTTP with the services stubbed (no MySQL, no Redis): request
 * validation (400 with path messages, nothing reaches a service), authorization (401/403 per the
 * §4.3 access column, MFA step-up, user-only routes) and the access passed to the services. The
 * full flows run against real MySQL/Redis in integration/organizations.test.ts.
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
import { KeyValueStore } from '../src/kv/key-value-store';
import { ApiKeyAuthenticatorService } from '../src/modules/auth/services/api-key-authenticator.service';
import type { PrincipalSnapshot } from '../src/modules/auth/services/principal-cache.service';
import { PrincipalLoaderService } from '../src/modules/auth/services/principal-loader.service';
import { SessionService } from '../src/modules/auth/services/session.service';
import { type AuthMethod, TokenService } from '../src/modules/auth/services/token.service';
import { OrganizationDeletionService } from '../src/modules/organizations/services/organization-deletion.service';
import { OrganizationEntitlementsService } from '../src/modules/organizations/services/organization-entitlements.service';
import { OrganizationSettingsService } from '../src/modules/organizations/services/organization-settings.service';
import { OrganizationUsageService } from '../src/modules/organizations/services/organization-usage.service';
import { OrganizationsService } from '../src/modules/organizations/services/organizations.service';
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
});

const ids = { user: randomUUID(), org: randomUUID(), session: randomUUID() };
const orgId = randomUUID();

const MEMBER = ['organization:read', 'organization:manage'];
const PLATFORM = ['platform:organizations', 'organization:read'];

let snapshot: PrincipalSnapshot;
function principalWith(permissions: string[], kind: 'customer' | 'platform'): void {
  snapshot = {
    orgVersion: 0,
    userVersion: '',
    user: { id: '10', publicId: ids.user, status: 'active', deleted: false, mfaEnabled: true },
    org: {
      id: '2',
      publicId: ids.org,
      kind,
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
  organizationId: 2n,
  organizationPublicId: ids.org,
  permissions: new Set(['organization:read', 'organization:manage']),
};

describe('organization endpoints (e2e, services stubbed)', () => {
  let app: INestApplication;
  const tokens = new TokenService(config);
  const organizations = {
    create: vi.fn(() => Promise.resolve({ id: orgId })),
    list: vi.fn(() => Promise.resolve({ data: [], nextCursor: null })),
    get: vi.fn(() => Promise.resolve({ id: orgId })),
    update: vi.fn(() => Promise.resolve({ id: orgId })),
    changeStatus: vi.fn(() => Promise.resolve({ id: orgId })),
  };
  const usage = { get: vi.fn(() => Promise.resolve({ organizationId: orgId })) };
  const settings = {
    get: vi.fn(() => Promise.resolve({ organizationId: orgId })),
    update: vi.fn(() => Promise.resolve({ organizationId: orgId })),
  };
  const entitlements = {
    listFeatures: vi.fn(() => Promise.resolve({ organizationId: orgId, data: [] })),
    listLimits: vi.fn(() => Promise.resolve({ organizationId: orgId, data: [] })),
    overrideFeature: vi.fn(() => Promise.resolve({ key: 'sso' })),
    resetFeature: vi.fn(() => Promise.resolve()),
    overrideLimit: vi.fn(() => Promise.resolve({ key: 'max_users' })),
    resetLimit: vi.fn(() => Promise.resolve()),
  };
  const deletion = {
    get: vi.fn(() => Promise.resolve({ state: 'none' })),
    request: vi.fn(() => Promise.resolve({ state: 'pending_deletion' })),
    confirm: vi.fn(() => Promise.resolve({ state: 'deleted' })),
    cancel: vi.fn(() => Promise.resolve({ state: 'none' })),
  };
  const apiKeys = { authenticate: vi.fn(() => Promise.resolve(apiKeyPrincipal)) };
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
      .useValue(apiKeys)
      .overrideProvider(OrganizationsService)
      .useValue(organizations)
      .overrideProvider(OrganizationUsageService)
      .useValue(usage)
      .overrideProvider(OrganizationSettingsService)
      .useValue(settings)
      .overrideProvider(OrganizationEntitlementsService)
      .useValue(entitlements)
      .overrideProvider(OrganizationDeletionService)
      .useValue(deletion)
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
    principalWith(PLATFORM, 'platform');
  });

  const allServices = () => [
    ...Object.values(organizations),
    ...Object.values(usage),
    ...Object.values(settings),
    ...Object.values(entitlements),
    ...Object.values(deletion),
  ];
  const expectNoServiceCall = () => {
    for (const fn of allServices()) expect(fn).not.toHaveBeenCalled();
  };

  describe('authentication', () => {
    it('answers 401 without credentials', async () => {
      await http().get('/api/v1/organizations').expect(401);
      await http().get(`/api/v1/organizations/${orgId}/usage`).expect(401);
      expectNoServiceCall();
    });
  });

  describe('validation (400, nothing reaches a service)', () => {
    const valid = {
      name: 'Acme',
      slug: 'acme',
      planCode: 'standard',
      deploymentMode: 'saas',
      dataRegion: 'ap-south-1',
    };

    it.each([
      [{ ...valid, slug: 'platform' }, 'slug: is reserved'],
      [{ ...valid, slug: 'Bad Slug' }, 'slug: must be 3–63 lower-case letters, digits or hyphens'],
      [{ ...valid, dataRegion: 'mars' }, 'dataRegion: must be a region such as ap-south-1'],
      [
        { ...valid, deploymentMode: 'dedicated' },
        'deployment: is required for a dedicated deployment',
      ],
      [
        { ...valid, settings: { timezone: 'Nowhere/City' } },
        'settings.timezone: must be an IANA time zone',
      ],
      [
        { ...valid, initialAdmin: { email: 'nope', displayName: 'A' } },
        'initialAdmin.email: Invalid email address',
      ],
    ])('POST /organizations %j → 400', async (body, message) => {
      const res = await http()
        .post('/api/v1/organizations')
        .set(await bearer())
        .send(body)
        .expect(400);
      expect(res.body.message).toContain(message);
      expectNoServiceCall();
    });

    it('rejects malformed ids and keys', async () => {
      const auth = await bearer();
      await http().get('/api/v1/organizations/not-a-uuid').set(auth).expect(400);
      await http()
        .put(`/api/v1/organizations/${orgId}/features/teleport`)
        .set(auth)
        .send({ enabled: true })
        .expect(400);
      await http()
        .put(`/api/v1/organizations/${orgId}/limits/max_planets`)
        .set(auth)
        .send({ value: 1 })
        .expect(400);
      await http()
        .delete(`/api/v1/organizations/${orgId}/limits/max_planets`)
        .set(auth)
        .expect(400);
      expectNoServiceCall();
    });

    it('rejects immutable fields on update', async () => {
      const res = await http()
        .put(`/api/v1/organizations/${orgId}`)
        .set(await bearer())
        .send({ name: 'New', slug: 'other', dataRegion: 'eu-west-1' })
        .expect(400);
      expect(res.body.message).toEqual(['slug: is immutable', 'dataRegion: is immutable']);
      expectNoServiceCall();
    });

    it('validates settings, overrides, status, usage and list queries', async () => {
      const auth = await bearer();
      const cases: Array<[() => request.Test, string]> = [
        [
          () => http().put(`/api/v1/organizations/${orgId}/settings`).set(auth).send({}),
          '(root): provide at least one setting',
        ],
        [
          () =>
            http()
              .put(`/api/v1/organizations/${orgId}/settings`)
              .set(auth)
              .send({ digestSchedule: '61 * * * *' }),
          'digestSchedule: must be a 5-field cron expression',
        ],
        [
          () =>
            http()
              .put(`/api/v1/organizations/${orgId}/settings`)
              .set(auth)
              .send({ preferences: { blob: 'x'.repeat(17_000) } }),
          'preferences: must be at most 16384 bytes as JSON',
        ],
        [
          () =>
            http()
              .put(`/api/v1/organizations/${orgId}/limits/max_users`)
              .set(auth)
              .send({ value: -1 }),
          'value: Too small: expected number to be >=0',
        ],
        [
          () => http().put(`/api/v1/organizations/${orgId}/features/sso`).set(auth).send({}),
          'enabled: Invalid input: expected boolean, received undefined',
        ],
        [
          () =>
            http()
              .patch(`/api/v1/organizations/${orgId}/status`)
              .set(auth)
              .send({ status: 'suspended' }),
          'reason: is required when suspending',
        ],
        [
          () =>
            http()
              .patch(`/api/v1/organizations/${orgId}/status`)
              .set(auth)
              .send({ status: 'deleted', reason: 'abc' }),
          'status: Invalid option: expected one of "active"|"suspended"',
        ],
        [
          () => http().get(`/api/v1/organizations/${orgId}/usage?from=yesterday`).set(auth),
          'from: Invalid ISO datetime',
        ],
        [
          () => http().get('/api/v1/organizations?limit=1000').set(auth),
          'limit: Too big: expected number to be <=100',
        ],
        [
          () => http().get('/api/v1/organizations?status=gone').set(auth),
          'status: Invalid option: expected one of "active"|"suspended"|"pending_deletion"|"deleted"',
        ],
        [
          () =>
            http()
              .post(`/api/v1/organizations/${orgId}/deletion`)
              .set(auth)
              .send({ reason: 'short', confirmSlug: 'acme' }),
          'reason: Too small: expected string to have >=10 characters',
        ],
      ];
      for (const [req, message] of cases) {
        const res = await req().expect(400);
        expect(res.body.message).toContain(message);
      }
      expectNoServiceCall();
    });
  });

  describe('authorization', () => {
    it('lets a member read and manage only through the scoped access', async () => {
      principalWith(MEMBER, 'customer');
      const auth = await bearer(['pwd']);
      await http().get('/api/v1/organizations').set(auth).expect(200);
      expect(organizations.list).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: 'scoped',
          scope: expect.objectContaining({ organizationId: 2n, via: 'member' }),
        }),
        expect.objectContaining({ limit: 25 }),
      );
      await http()
        .put(`/api/v1/organizations/${orgId}`)
        .set(auth)
        .send({ name: 'Renamed' })
        .expect(200);
      await http()
        .put(`/api/v1/organizations/${orgId}/settings`)
        .set(auth)
        .send({ locale: 'en-IN' })
        .expect(200);
      await http().get(`/api/v1/organizations/${orgId}/usage`).set(auth).expect(200);
    });

    it('refuses catalog functions to members (403)', async () => {
      principalWith(MEMBER, 'customer');
      const auth = await bearer();
      const forbidden = [
        () => http().post('/api/v1/organizations').set(auth).send({}),
        () =>
          http()
            .patch(`/api/v1/organizations/${orgId}/status`)
            .set(auth)
            .send({ status: 'active' }),
        () =>
          http()
            .put(`/api/v1/organizations/${orgId}/features/sso`)
            .set(auth)
            .send({ enabled: true }),
        () => http().delete(`/api/v1/organizations/${orgId}/features/sso`).set(auth),
        () =>
          http()
            .put(`/api/v1/organizations/${orgId}/limits/max_users`)
            .set(auth)
            .send({ value: 5 }),
        () => http().delete(`/api/v1/organizations/${orgId}/limits/max_users`).set(auth),
        () => http().get(`/api/v1/organizations/${orgId}/deletion`).set(auth),
        () => http().post(`/api/v1/organizations/${orgId}/deletion`).set(auth).send({}),
        () => http().post(`/api/v1/organizations/${orgId}/deletion/confirm`).set(auth).send({}),
        () => http().post(`/api/v1/organizations/${orgId}/deletion/cancel`).set(auth).send({}),
      ];
      for (const req of forbidden) await req().expect(403);
      expectNoServiceCall();
    });

    it('refuses reads without organization:read and writes without organization:manage', async () => {
      principalWith(['user:read'], 'customer');
      const auth = await bearer();
      await http().get('/api/v1/organizations').set(auth).expect(403);
      await http().get(`/api/v1/organizations/${orgId}/settings`).set(auth).expect(403);
      principalWith(['organization:read'], 'customer');
      await http().put(`/api/v1/organizations/${orgId}`).set(auth).send({ name: 'x' }).expect(403);
      await http()
        .put(`/api/v1/organizations/${orgId}/settings`)
        .set(auth)
        .send({ locale: 'en' })
        .expect(403);
      expectNoServiceCall();
    });

    it('accepts API keys on K routes only', async () => {
      await http().get('/api/v1/organizations').set(apiKey).expect(200);
      expect(organizations.list).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: 'scoped',
          scope: expect.objectContaining({ via: 'api_key' }),
        }),
        expect.anything(),
      );
      await http().get(`/api/v1/organizations/${orgId}/limits`).set(apiKey).expect(200);
      vi.clearAllMocks();
      apiKeys.authenticate.mockResolvedValue({
        ...apiKeyPrincipal,
        // Even a (forged) platform scope on a key never unlocks a user-only route.
        permissions: new Set(['platform:organizations']),
      });
      await http().post('/api/v1/organizations').set(apiKey).send({}).expect(403);
      await http()
        .patch(`/api/v1/organizations/${orgId}/status`)
        .set(apiKey)
        .send({ status: 'active' })
        .expect(403);
      await http().get(`/api/v1/organizations/${orgId}/deletion`).set(apiKey).expect(403);
      expectNoServiceCall();
      apiKeys.authenticate.mockResolvedValue(apiKeyPrincipal);
    });

    it('requires an MFA session for the deletion steps, not for reading the state', async () => {
      const noMfa = await bearer(['pwd']);
      const body = { reason: 'Customer offboarded per contract', confirmSlug: 'acme' };
      for (const path of ['deletion', 'deletion/confirm', 'deletion/cancel']) {
        const res = await http()
          .post(`/api/v1/organizations/${orgId}/${path}`)
          .set(noMfa)
          .send(body)
          .expect(403);
        expect(res.body.message).toBe('MFA required');
      }
      await http().get(`/api/v1/organizations/${orgId}/deletion`).set(noMfa).expect(200);
      await http()
        .post(`/api/v1/organizations/${orgId}/deletion`)
        .set(await bearer())
        .send(body)
        .expect(200);
      expect(deletion.request).toHaveBeenCalledWith(
        expect.objectContaining({ kind: 'user', mfaAuthenticated: true }),
        expect.objectContaining({ kind: 'platform' }),
        orgId,
        body,
        expect.anything(),
      );
    });

    it('passes platform access to catalog functions', async () => {
      const auth = await bearer();
      const body = {
        name: 'Acme',
        slug: 'acme',
        planCode: 'standard',
        deploymentMode: 'saas',
        dataRegion: 'ap-south-1',
      };
      await http().post('/api/v1/organizations').set(auth).send(body).expect(201);
      expect(organizations.create).toHaveBeenCalledWith(
        expect.objectContaining({ kind: 'user' }),
        expect.objectContaining({ kind: 'platform' }),
        body,
        expect.objectContaining({ ip: expect.any(String) }),
      );
      await http().delete(`/api/v1/organizations/${orgId}/features/sso`).set(auth).expect(204);
      await http().delete(`/api/v1/organizations/${orgId}/limits/max_users`).set(auth).expect(204);
    });
  });
});
