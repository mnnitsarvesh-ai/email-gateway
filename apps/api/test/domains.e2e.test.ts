/**
 * Domain endpoints (§4 of docs/plan/steps/03-domain-onboarding.md) over HTTP with the services
 * stubbed (no MySQL, no Redis, no DNS): request validation (400 with path messages, nothing
 * reaches a service), authentication (401), permissions per route (403, D14) and the tenant
 * scope passed to the services (always from the credential, never from headers or the body).
 * The full flows run against real MySQL/Redis and a test DNS server in the integration suites.
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
import { TokenService } from '../src/modules/auth/services/token.service';
import {
  TooManyRotationsException,
  TooManyVerificationsException,
} from '../src/modules/domains/domains.errors';
import { DkimRotationService } from '../src/modules/domains/services/dkim-rotation.service';
import { DomainCheckScheduler } from '../src/modules/domains/services/domain-check-scheduler.service';
import { DomainVerificationService } from '../src/modules/domains/services/domain-verification.service';
import { DomainsService } from '../src/modules/domains/services/domains.service';
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
const domainId = randomUUID();
const ALL = ['domain:read', 'domain:manage', 'domain:dkim_rotate'];

let snapshot: PrincipalSnapshot;
function principalWith(permissions: string[]): void {
  snapshot = {
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
  };
}

let apiKeyPrincipal: ApiKeyPrincipal;

describe('domain endpoints (e2e, services stubbed)', () => {
  let app: INestApplication;
  const tokens = new TokenService(config);
  const domains = {
    create: vi.fn(() => Promise.resolve({ id: domainId })),
    list: vi.fn(() => Promise.resolve({ data: [], nextCursor: null })),
    get: vi.fn(() => Promise.resolve({ id: domainId })),
    dnsRecords: vi.fn(() => Promise.resolve({ domainId, records: [], cleanup: [] })),
    changeStatus: vi.fn(() => Promise.resolve({ id: domainId })),
    remove: vi.fn(() => Promise.resolve()),
  };
  const verification = {
    verifyNow: vi.fn(() => Promise.resolve({ domainId })),
    statusView: vi.fn(() => Promise.resolve({ domainId })),
  };
  const rotation = { rotate: vi.fn(() => Promise.resolve({ domainId })) };
  const apiKeys = { authenticate: vi.fn(() => Promise.resolve(apiKeyPrincipal)) };
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
      .overrideProvider(DomainsService)
      .useValue(domains)
      .overrideProvider(DomainVerificationService)
      .useValue(verification)
      .overrideProvider(DkimRotationService)
      .useValue(rotation)
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
    principalWith(ALL);
    apiKeyPrincipal = {
      kind: 'api_key',
      apiKeyId: 5n,
      apiKeyPublicId: randomUUID(),
      organizationId: 2n,
      organizationPublicId: ids.org,
      permissions: new Set(ALL),
    };
  });

  const allServices = () => [
    ...Object.values(domains),
    ...Object.values(verification),
    ...Object.values(rotation),
  ];
  const expectNoServiceCall = () => {
    for (const fn of allServices()) expect(fn).not.toHaveBeenCalled();
  };

  /** Every route of §4 with a valid request. */
  const routes = (id: string = domainId) =>
    [
      ['POST /domains', () => http().post('/api/v1/domains').send({ name: 'acme.test' })],
      ['GET /domains', () => http().get('/api/v1/domains')],
      ['GET /domains/{id}', () => http().get(`/api/v1/domains/${id}`)],
      ['POST /domains/{id}/verify', () => http().post(`/api/v1/domains/${id}/verify`)],
      ['GET /domains/{id}/dns-records', () => http().get(`/api/v1/domains/${id}/dns-records`)],
      ['GET /domains/{id}/status', () => http().get(`/api/v1/domains/${id}/status`)],
      ['POST /domains/{id}/dkim/rotate', () => http().post(`/api/v1/domains/${id}/dkim/rotate`)],
      [
        'PATCH /domains/{id}/status',
        () => http().patch(`/api/v1/domains/${id}/status`).send({ status: 'active' }),
      ],
      ['DELETE /domains/{id}', () => http().delete(`/api/v1/domains/${id}`)],
    ] as const;

  /** Required permission per route (D14). */
  const PERMISSION: Record<string, string> = {
    'POST /domains': 'domain:manage',
    'GET /domains': 'domain:read',
    'GET /domains/{id}': 'domain:read',
    'POST /domains/{id}/verify': 'domain:manage',
    'GET /domains/{id}/dns-records': 'domain:read',
    'GET /domains/{id}/status': 'domain:read',
    'POST /domains/{id}/dkim/rotate': 'domain:dkim_rotate',
    'PATCH /domains/{id}/status': 'domain:manage',
    'DELETE /domains/{id}': 'domain:manage',
  };

  describe('authentication', () => {
    it('answers 401 without credentials on every route', async () => {
      for (const [name, req] of routes()) {
        const res = await req();
        expect(res.status, name).toBe(401);
      }
      expectNoServiceCall();
    });
  });

  describe('authorization (D14)', () => {
    it.each(Object.entries(PERMISSION))(
      '%s needs %s (403 otherwise)',
      async (route, permission) => {
        principalWith(ALL.filter((p) => p !== permission));
        const auth = await bearer();
        const [, req] = routes().find(([name]) => name === route)!;
        const res = await req().set(auth);
        expect(res.status).toBe(403);
        expectNoServiceCall();
      },
    );

    it('lets each route through with exactly its permission', async () => {
      for (const [name, req] of routes()) {
        principalWith([PERMISSION[name]!]);
        const res = await req().set(await bearer());
        expect(res.status, name).toBeLessThan(300);
      }
    });

    it('refuses an API key without the permission in its scopes', async () => {
      apiKeyPrincipal = { ...apiKeyPrincipal, permissions: new Set(['domain:read']) };
      await http().post('/api/v1/domains').set(apiKey).send({ name: 'acme.test' }).expect(403);
      await http().post(`/api/v1/domains/${domainId}/dkim/rotate`).set(apiKey).expect(403);
      expectNoServiceCall();
      await http().get('/api/v1/domains').set(apiKey).expect(200);
      expect(domains.list).toHaveBeenCalledWith(
        expect.objectContaining({ organizationId: 2n, via: 'api_key' }),
        expect.objectContaining({ limit: 25 }),
      );
    });
  });

  describe('tenant scope', () => {
    it('comes from the credential, never from headers or the body', async () => {
      const auth = await bearer();
      await http()
        .get(`/api/v1/domains/${domainId}`)
        .set(auth)
        .set('X-Organization-Id', '99')
        .set('X-Tenant-Id', randomUUID())
        .expect(200);
      expect(domains.get).toHaveBeenCalledWith(
        expect.objectContaining({ organizationId: 2n, via: 'member' }),
        domainId,
      );
      await http()
        .post('/api/v1/domains')
        .set(auth)
        .send({ name: 'acme.test', organizationId: '99' })
        .expect(400);
      expect(domains.create).not.toHaveBeenCalled();
    });
  });

  describe('validation (400, nothing reaches a service)', () => {
    it.each([
      [{}, 'name: Invalid input: expected string, received undefined'],
      [{ name: '' }, 'name: Too small: expected string to have >=1 characters'],
      [
        { name: `${'a'.repeat(250)}.com` },
        'name: Too big: expected string to have <=253 characters',
      ],
      [
        { name: 'not a domain' },
        'name: Domain name contains a character that is not allowed (invalid)',
      ],
      [
        { name: '*.acme.com' },
        'name: Domain name contains a character that is not allowed (invalid)',
      ],
      [
        { name: '192.168.1.1' },
        'name: Domain name must end with an alphabetic top-level label (invalid)',
      ],
      [{ name: 'acme' }, 'name: Domain name must have at least two labels (invalid)'],
      [{ name: 'mail.localhost' }, 'name: Domain name is reserved (localhost) (reserved)'],
      [
        { name: 'acme.test', inboundEnabled: 'yes' },
        'inboundEnabled: Invalid input: expected boolean, received string',
      ],
      [
        { name: 'acme.test', dkim: { ed25519: 1 } },
        'dkim.ed25519: Invalid input: expected boolean, received number',
      ],
      [{ name: 'acme.test', dkim: { rsa4096: true } }, 'dkim: Unrecognized key: "rsa4096"'],
      [{ name: 'acme.test', status: 'active' }, '(root): Unrecognized key: "status"'],
    ])('POST /domains %j → 400', async (body, message) => {
      const res = await http()
        .post('/api/v1/domains')
        .set(await bearer())
        .send(body)
        .expect(400);
      expect(res.body.message).toContain(message);
      expectNoServiceCall();
    });

    it.each([
      [{}, 'status: Invalid option: expected one of "active"|"suspended"'],
      [{ status: 'deleted' }, 'status: Invalid option: expected one of "active"|"suspended"'],
      [{ status: 'verified' }, 'status: Invalid option: expected one of "active"|"suspended"'],
      [{ status: 'suspended' }, 'reason: is required when suspending'],
      [
        { status: 'suspended', reason: '   ' },
        'reason: Too small: expected string to have >=1 characters',
      ],
      [
        { status: 'suspended', reason: 'x'.repeat(513) },
        'reason: Too big: expected string to have <=512 characters',
      ],
      [{ status: 'active', note: 'x' }, '(root): Unrecognized key: "note"'],
    ])('PATCH /domains/{id}/status %j → 400', async (body, message) => {
      const res = await http()
        .patch(`/api/v1/domains/${domainId}/status`)
        .set(await bearer())
        .send(body)
        .expect(400);
      expect(res.body.message).toContain(message);
      expectNoServiceCall();
    });

    it.each([
      [
        { algorithm: 'rsa_4096' },
        'algorithm: Invalid option: expected one of "rsa_2048"|"ed25519"',
      ],
      [
        { algorithm: 'RSA_2048' },
        'algorithm: Invalid option: expected one of "rsa_2048"|"ed25519"',
      ],
      [{ algorithm: 'ed25519', selector: 'mine' }, '(root): Unrecognized key: "selector"'],
    ])('POST /domains/{id}/dkim/rotate %j → 400', async (body, message) => {
      const res = await http()
        .post(`/api/v1/domains/${domainId}/dkim/rotate`)
        .set(await bearer())
        .send(body)
        .expect(400);
      expect(res.body.message).toContain(message);
      expectNoServiceCall();
    });

    it.each([
      ['?status=deleted', 'status: Invalid option'],
      ['?status=gone', 'status: Invalid option'],
      ['?limit=0', 'limit: Too small: expected number to be >=1'],
      ['?limit=1000', 'limit: Too big: expected number to be <=100'],
      ['?q=acme%25', 'q: must be a prefix of an ASCII (punycode) domain name'],
      [`?q=${'a'.repeat(254)}`, 'q: Too big: expected string to have <=253 characters'],
    ])('GET /domains%s → 400', async (query, message) => {
      const res = await http()
        .get(`/api/v1/domains${query}`)
        .set(await bearer())
        .expect(400);
      expect(res.body.message.join('\n')).toContain(message);
      expectNoServiceCall();
    });

    it('rejects malformed domain ids on every {id} route', async () => {
      const auth = await bearer();
      for (const [name, req] of routes('not-a-uuid').filter(([n]) => n.includes('{id}'))) {
        const res = await req().set(auth);
        expect(res.status, name).toBe(400);
        expect(res.body.message, name).toEqual(['(root): Invalid UUID']);
      }
      expectNoServiceCall();
    });
  });

  describe('success codes and service arguments', () => {
    it('creates with 201 and defaults applied', async () => {
      await http()
        .post('/api/v1/domains')
        .set(await bearer())
        .send({ name: 'Acme.test.' })
        .expect(201);
      expect(domains.create).toHaveBeenCalledWith(
        expect.objectContaining({ kind: 'user', userPublicId: ids.user }),
        expect.objectContaining({ organizationId: 2n }),
        { name: 'Acme.test.', inboundEnabled: true },
        expect.objectContaining({ ip: expect.any(String) }),
      );
    });

    it('verifies with 200 and rotates with 201 (default algorithm)', async () => {
      const auth = await bearer();
      await http().post(`/api/v1/domains/${domainId}/verify`).set(auth).expect(200);
      expect(verification.verifyNow).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ organizationId: 2n }),
        domainId,
        expect.anything(),
      );
      await http().post(`/api/v1/domains/${domainId}/dkim/rotate`).set(auth).expect(201);
      expect(rotation.rotate).toHaveBeenLastCalledWith(
        expect.anything(),
        expect.anything(),
        domainId,
        { algorithm: 'rsa_2048' },
        expect.anything(),
      );
      await http()
        .post(`/api/v1/domains/${domainId}/dkim/rotate`)
        .set(auth)
        .send({ algorithm: 'ed25519' })
        .expect(201);
      expect(rotation.rotate).toHaveBeenLastCalledWith(
        expect.anything(),
        expect.anything(),
        domainId,
        { algorithm: 'ed25519' },
        expect.anything(),
      );
    });

    it('deletes with 204 and no body', async () => {
      const res = await http()
        .delete(`/api/v1/domains/${domainId}`)
        .set(await bearer())
        .expect(204);
      expect(res.text).toBe('');
    });

    it('passes list filters through, lower-casing the name prefix', async () => {
      await http()
        .get('/api/v1/domains?status=active&q=ACME&limit=10')
        .set(await bearer())
        .expect(200);
      expect(domains.list).toHaveBeenCalledWith(expect.anything(), {
        status: 'active',
        q: 'acme',
        limit: 10,
      });
    });

    it('sets Retry-After on the per-domain verification limit', async () => {
      verification.verifyNow.mockRejectedValueOnce(new TooManyVerificationsException(17));
      const res = await http()
        .post(`/api/v1/domains/${domainId}/verify`)
        .set(await bearer())
        .expect(429);
      expect(res.headers['retry-after']).toBe('17');
      expect(res.body.message).toBe('Too many verification requests for this domain');
    });

    it('sets Retry-After on the per-domain DKIM rotation limit', async () => {
      rotation.rotate.mockRejectedValueOnce(new TooManyRotationsException(3600));
      const res = await http()
        .post(`/api/v1/domains/${domainId}/dkim/rotate`)
        .set(await bearer())
        .expect(429);
      expect(res.headers['retry-after']).toBe('3600');
      expect(res.body.message).toBe('Too many DKIM rotations for this domain');
    });

    // Each test gets a fresh API key (beforeEach), so these buckets are this test's own.
    it.each([
      ['POST /domains', 60, () => http().post('/api/v1/domains').send({ name: 'acme.test' })],
      [
        'POST /domains/{id}/dkim/rotate',
        30,
        () => http().post(`/api/v1/domains/${domainId}/dkim/rotate`),
      ],
    ] as const)(
      'limits %s per caller (%i per minute, 429 with Retry-After)',
      async (_, limit, send) => {
        const statuses: number[] = [];
        let retryAfter: string | undefined;
        for (let i = 0; i <= limit; i++) {
          // From different IPs: the limit follows the credential, not the address.
          const res = await send()
            .set(apiKey)
            .set('X-Forwarded-For', `198.51.100.${i % 250}`);
          statuses.push(res.status);
          if (res.status === 429) retryAfter = res.headers['retry-after'];
        }
        expect(statuses.slice(0, limit).every((s) => s === 201)).toBe(true);
        expect(statuses[limit]).toBe(429);
        expect(Number(retryAfter)).toBeGreaterThan(0);
        // Another caller is not affected.
        apiKeyPrincipal = { ...apiKeyPrincipal, apiKeyPublicId: randomUUID() };
        expect((await send().set(apiKey)).status).toBe(201);
      },
    );

    // Runs last among the verify tests: it exhausts the per-IP bucket of this test client.
    it('limits verify requests per IP (30 per minute, 429 with Retry-After)', async () => {
      const auth = await bearer();
      const statuses: number[] = [];
      let retryAfter: string | undefined;
      for (let i = 0; i < 31; i++) {
        const res = await http().post(`/api/v1/domains/${domainId}/verify`).set(auth);
        statuses.push(res.status);
        if (res.status === 429) retryAfter = res.headers['retry-after'];
      }
      expect(statuses).toContain(429);
      expect(Number(retryAfter)).toBeGreaterThan(0);
      expect(verification.verifyNow.mock.calls.length).toBeLessThanOrEqual(30);
    });
  });

  it('does not run the background scheduler in tests', () => {
    expect(app.get(DomainCheckScheduler).scheduled).toBe(false);
  });
});
