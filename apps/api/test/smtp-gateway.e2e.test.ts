/**
 * Step 2.2 control-plane endpoints over HTTP with the services stubbed (no MySQL, no Redis):
 * SMTP connectors (`/smtp-connectors`) and inbound recipient validation
 * (`/domains/{id}/recipient-validation`, `/domains/{id}/recipients`). Covers authentication
 * (401), the permission of every route (403 otherwise, nothing reaches a service), request
 * validation (400), the tenant scope (always from the credential) and the per-caller limits on
 * connector creation and secret rotation. The full flows run against MySQL and Redis in the
 * integration suites.
 */
// ---- Route coverage (step 6.1 §3.8, test/route-coverage/legacy.ts) ----
// @covers delete /api/v1/smtp-connectors/:id
// @covers get /api/v1/domains/:id/recipient-validation
// @covers get /api/v1/domains/:id/recipients
// @covers get /api/v1/smtp-connectors
// @covers get /api/v1/smtp-connectors/:id
// @covers patch /api/v1/smtp-connectors/:id
// @covers post /api/v1/domains/:id/recipients
// @covers post /api/v1/domains/:id/recipients/remove
// @covers post /api/v1/smtp-connectors
// @covers post /api/v1/smtp-connectors/:id/rotate-secret
// @covers put /api/v1/domains/:id/recipient-validation
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
import { RecipientValidationService } from '../src/modules/domains/services/recipient-validation.service';
import { SmtpConnectorsService } from '../src/modules/smtp-connectors/services/smtp-connectors.service';
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
const connectorId = randomUUID();
const domainId = randomUUID();
const ALL = ['connector:read', 'connector:manage', 'domain:read', 'domain:manage'];

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

describe('SMTP connectors and recipient validation (e2e, services stubbed)', () => {
  let app: INestApplication;
  const tokens = new TokenService(config);
  const connectors = {
    create: vi.fn(() => Promise.resolve({ id: connectorId })),
    list: vi.fn(() => Promise.resolve({ data: [], nextCursor: null })),
    get: vi.fn(() => Promise.resolve({ id: connectorId })),
    update: vi.fn(() => Promise.resolve({ id: connectorId })),
    rotateSecret: vi.fn(() => Promise.resolve({ id: connectorId })),
    remove: vi.fn(() => Promise.resolve()),
  };
  const recipients = {
    get: vi.fn(() => Promise.resolve({ domainId })),
    set: vi.fn(() => Promise.resolve({ domainId })),
    list: vi.fn(() => Promise.resolve({ data: [], nextCursor: null })),
    add: vi.fn(() => Promise.resolve({ added: 1, existing: 0 })),
    remove: vi.fn(() => Promise.resolve({ removed: 1 })),
  };
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
  const apiKey = { 'X-API-Key': `egk_${'c'.repeat(12)}_${'d'.repeat(43)}` };

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
      .overrideProvider(SmtpConnectorsService)
      .useValue(connectors)
      .overrideProvider(RecipientValidationService)
      .useValue(recipients)
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

  const allServices = () => [...Object.values(connectors), ...Object.values(recipients)];
  const expectNoServiceCall = () => {
    for (const fn of allServices()) expect(fn).not.toHaveBeenCalled();
  };

  const C = '/api/v1/smtp-connectors';
  const D = (id: string) => `/api/v1/domains/${id}`;

  /** Every new route with a valid request. */
  const routes = (cid: string = connectorId, did: string = domainId) =>
    [
      ['POST /smtp-connectors', () => http().post(C).send({ name: 'relay', authType: 'sasl' })],
      ['GET /smtp-connectors', () => http().get(C)],
      ['GET /smtp-connectors/{id}', () => http().get(`${C}/${cid}`)],
      [
        'PATCH /smtp-connectors/{id}',
        () => http().patch(`${C}/${cid}`).send({ status: 'disabled' }),
      ],
      ['POST /smtp-connectors/{id}/rotate-secret', () => http().post(`${C}/${cid}/rotate-secret`)],
      ['DELETE /smtp-connectors/{id}', () => http().delete(`${C}/${cid}`)],
      [
        'GET /domains/{id}/recipient-validation',
        () => http().get(`${D(did)}/recipient-validation`),
      ],
      [
        'PUT /domains/{id}/recipient-validation',
        () =>
          http()
            .put(`${D(did)}/recipient-validation`)
            .send({ mode: 'accept_all' }),
      ],
      ['GET /domains/{id}/recipients', () => http().get(`${D(did)}/recipients`)],
      [
        'POST /domains/{id}/recipients',
        () =>
          http()
            .post(`${D(did)}/recipients`)
            .send({ localParts: ['alice'] }),
      ],
      [
        'POST /domains/{id}/recipients/remove',
        () =>
          http()
            .post(`${D(did)}/recipients/remove`)
            .send({ localParts: ['alice'] }),
      ],
    ] as const;

  /** Required permission per route (§4.1). */
  const PERMISSION: Record<string, string> = {
    'POST /smtp-connectors': 'connector:manage',
    'GET /smtp-connectors': 'connector:read',
    'GET /smtp-connectors/{id}': 'connector:read',
    'PATCH /smtp-connectors/{id}': 'connector:manage',
    'POST /smtp-connectors/{id}/rotate-secret': 'connector:manage',
    'DELETE /smtp-connectors/{id}': 'connector:manage',
    'GET /domains/{id}/recipient-validation': 'domain:read',
    'PUT /domains/{id}/recipient-validation': 'domain:manage',
    'GET /domains/{id}/recipients': 'domain:read',
    'POST /domains/{id}/recipients': 'domain:manage',
    'POST /domains/{id}/recipients/remove': 'domain:manage',
  };

  it('answers 401 without credentials on every route', async () => {
    for (const [name, req] of routes()) {
      const res = await req();
      expect(res.status, name).toBe(401);
    }
    expectNoServiceCall();
  });

  it.each(Object.entries(PERMISSION))('%s needs %s (403 otherwise)', async (route, permission) => {
    principalWith(ALL.filter((p) => p !== permission));
    const auth = await bearer();
    const [, req] = routes().find(([name]) => name === route)!;
    const res = await req().set(auth);
    expect(res.status).toBe(403);
    expectNoServiceCall();
  });

  it('lets each route through with exactly its permission', async () => {
    for (const [name, req] of routes()) {
      principalWith([PERMISSION[name]!]);
      const res = await req().set(await bearer());
      expect(res.status, name).toBeLessThan(300);
    }
  });

  it('refuses an API key without the permission in its scopes', async () => {
    apiKeyPrincipal = { ...apiKeyPrincipal, permissions: new Set(['connector:read']) };
    await http().post(C).set(apiKey).send({ name: 'x', authType: 'sasl' }).expect(403);
    await http().post(`${C}/${connectorId}/rotate-secret`).set(apiKey).expect(403);
    expectNoServiceCall();
    await http().get(C).set(apiKey).expect(200);
    expect(connectors.list).toHaveBeenCalledWith(
      expect.objectContaining({ organizationId: 2n, via: 'api_key' }),
      expect.objectContaining({ limit: 25 }),
    );
  });

  it('takes the tenant from the credential, never from headers or the body', async () => {
    const auth = await bearer();
    await http()
      .get(`${C}/${connectorId}`)
      .set(auth)
      .set('X-Organization-Id', '99')
      .set('X-Tenant-Id', randomUUID())
      .expect(200);
    expect(connectors.get).toHaveBeenCalledWith(
      expect.objectContaining({ organizationId: 2n, via: 'member' }),
      connectorId,
    );
    await http()
      .post(C)
      .set(auth)
      .send({ name: 'x', authType: 'sasl', organizationId: '99' })
      .expect(400);
    await http()
      .post(`${D(domainId)}/recipients`)
      .set(auth)
      .send({ localParts: ['a'], organizationId: '99' })
      .expect(400);
    expect(connectors.create).not.toHaveBeenCalled();
    expect(recipients.add).not.toHaveBeenCalled();
  });

  it.each([
    [{ name: 'x', authType: 'source_ip' }, 'networks: is required for source_ip'],
    [
      { name: 'x', authType: 'source_ip', networks: ['10.0.0.0/8'] },
      'networks.0: must not be larger than /16 for IPv4 networks',
    ],
    [
      { name: 'x', authType: 'source_ip', networks: ['2001:db8::/32'] },
      'networks.0: must not be larger than /48 for IPv6 networks',
    ],
    [
      { name: 'x', authType: 'client_certificate', certificateFingerprintSha256: 'nope' },
      'certificateFingerprintSha256: must be a SHA-256 fingerprint',
    ],
    [{ name: 'x', authType: 'sasl', requireTls: false }, 'requireTls: cannot be false'],
  ])('POST /smtp-connectors %j → 400', async (body, message) => {
    const res = await http()
      .post(C)
      .set(await bearer())
      .send(body)
      .expect(400);
    expect(res.body.message.join('\n')).toContain(message);
    expectNoServiceCall();
  });

  it.each([
    [{ mode: 'allow_list' }, 'enforcement: is required for allow_list'],
    [{ mode: 'accept_all', enforcement: 'reject' }, 'enforcement: is only allowed for allow_list'],
    [{ mode: 'everyone' }, 'mode: Invalid option'],
  ])('PUT /recipient-validation %j → 400', async (body, message) => {
    const res = await http()
      .put(`${D(domainId)}/recipient-validation`)
      .set(await bearer())
      .send(body)
      .expect(400);
    expect(res.body.message.join('\n')).toContain(message);
    expectNoServiceCall();
  });

  it('passes smtp_callout / ldap through to the service (which answers 422)', async () => {
    await http()
      .put(`${D(domainId)}/recipient-validation`)
      .set(await bearer())
      .send({ mode: 'ldap', enforcement: 'reject' })
      .expect(200);
    expect(recipients.set).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ organizationId: 2n }),
      domainId,
      { mode: 'ldap', enforcement: 'reject' },
      expect.anything(),
    );
  });

  it.each([
    [{ localParts: [] }, 'localParts: Too small'],
    [{ localParts: Array.from({ length: 1001 }, (_, i) => `u${i}`) }, 'localParts: Too big'],
    [{ localParts: ['a@b.test'] }, 'localParts.0: must be a local part without "@" or domain'],
    [{ localParts: ['ok', 'two words'] }, 'localParts.1: must not contain whitespace'],
    [{ localParts: ['x'.repeat(65)] }, 'localParts.0: must be at most 64 bytes (UTF-8)'],
  ])('POST /recipients %j → 400', async (body, message) => {
    const res = await http()
      .post(`${D(domainId)}/recipients`)
      .set(await bearer())
      .send(body)
      .expect(400);
    expect(res.body.message.join('\n')).toContain(message);
    expectNoServiceCall();
  });

  it('normalizes local parts before the service sees them', async () => {
    await http()
      .post(`${D(domainId)}/recipients`)
      .set(await bearer())
      .send({ localParts: ['Alice', 'José'] })
      .expect(200);
    expect(recipients.add).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      domainId,
      { localParts: ['alice', 'josé'] },
      expect.anything(),
    );
  });

  it('rejects malformed ids on every {id} route', async () => {
    const auth = await bearer();
    for (const [name, req] of routes('not-a-uuid', 'not-a-uuid').filter(([n]) =>
      n.includes('{id}'),
    )) {
      const res = await req().set(auth);
      expect(res.status, name).toBe(400);
      expect(res.body.message, name).toEqual(['(root): Invalid UUID']);
    }
    expectNoServiceCall();
  });

  it('answers 201 on create, 200 on rotate and 204 on delete', async () => {
    const auth = await bearer();
    await http().post(C).set(auth).send({ name: 'relay', authType: 'sasl' }).expect(201);
    await http().post(`${C}/${connectorId}/rotate-secret`).set(auth).expect(200);
    const res = await http().delete(`${C}/${connectorId}`).set(auth).expect(204);
    expect(res.text).toBe('');
  });

  // Each test gets a fresh API key (beforeEach), so these buckets are this test's own.
  it.each([
    ['POST /smtp-connectors', 20, () => http().post(C).send({ name: 'r', authType: 'sasl' }), 201],
    [
      'POST /smtp-connectors/{id}/rotate-secret',
      10,
      () => http().post(`${C}/${connectorId}/rotate-secret`),
      200,
    ],
  ] as const)('limits %s per caller (%i per minute)', async (_, limit, send, ok) => {
    const statuses: number[] = [];
    for (let i = 0; i <= limit; i++) {
      const res = await send()
        .set(apiKey)
        .set('X-Forwarded-For', `198.51.100.${i % 250}`);
      statuses.push(res.status);
    }
    expect(statuses.slice(0, limit).every((s) => s === ok)).toBe(true);
    expect(statuses[limit]).toBe(429);
    apiKeyPrincipal = { ...apiKeyPrincipal, apiKeyPublicId: randomUUID() };
    expect((await send().set(apiKey)).status).toBe(ok);
  });
});
