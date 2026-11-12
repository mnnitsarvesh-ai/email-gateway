/**
 * Step 2.3 control-plane endpoints over HTTP with the services stubbed (no MySQL, no Redis):
 * destination providers and servers (`/destination-providers`, `/domains/{id}/destinations`)
 * and per-recipient delivery status (`/messages/{messageId}/deliveries[/events]`,
 * `/deliveries`). Covers authentication (401), the permission of every route (403 otherwise,
 * nothing reaches a service), request validation (400), the tenant scope (always from the
 * credential), the 422 refusal body with its `reason` and the per-caller write limit. The full
 * flows run against MySQL in the integration suites.
 */
// ---- Route coverage (step 6.1 §3.8, test/route-coverage/legacy.ts) ----
// @covers delete /api/v1/domains/:id/destinations
// @covers get /api/v1/deliveries
// @covers get /api/v1/destination-providers
// @covers get /api/v1/domains/:id/destinations
// @covers get /api/v1/messages/:messageId/deliveries
// @covers get /api/v1/messages/:messageId/deliveries/events
// @covers put /api/v1/domains/:id/destinations
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
import { DeliveriesService } from '../src/modules/deliveries/services/deliveries.service';
import { DestinationRefusedException } from '../src/modules/domain-destinations/domain-destinations.errors';
import { DomainDestinationsService } from '../src/modules/domain-destinations/services/domain-destinations.service';
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
const messageId = randomUUID();
const ALL = ['domain:read', 'domain:routing_manage', 'domain:manage', 'delivery:read'];

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

describe('destinations and delivery status (e2e, services stubbed)', () => {
  let app: INestApplication;
  const tokens = new TokenService(config);
  const destinations = {
    providers: vi.fn(() => Promise.resolve({ data: [] })),
    get: vi.fn(() => Promise.resolve({ provider: null, servers: [] })),
    replace: vi.fn(() => Promise.resolve({ provider: 'google_workspace', servers: [] })),
    remove: vi.fn(() => Promise.resolve()),
  };
  const deliveries = {
    forMessage: vi.fn(() => Promise.resolve({ message: {}, deliveries: [] })),
    events: vi.fn(() => Promise.resolve({ data: [], nextCursor: null })),
    list: vi.fn(() => Promise.resolve({ data: [], nextCursor: null })),
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
  const apiKey = { 'X-API-Key': `egk_${'e'.repeat(12)}_${'f'.repeat(43)}` };

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
      .overrideProvider(DomainDestinationsService)
      .useValue(destinations)
      .overrideProvider(DeliveriesService)
      .useValue(deliveries)
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

  const allServices = () => [...Object.values(destinations), ...Object.values(deliveries)];
  const expectNoServiceCall = () => {
    for (const fn of allServices()) expect(fn).not.toHaveBeenCalled();
  };

  const D = (id: string) => `/api/v1/domains/${id}/destinations`;
  const M = (id: string) => `/api/v1/messages/${id}/deliveries`;

  const routes = (did: string = domainId, mid: string = messageId) =>
    [
      ['GET /destination-providers', () => http().get('/api/v1/destination-providers')],
      ['GET /domains/{id}/destinations', () => http().get(D(did))],
      [
        'PUT /domains/{id}/destinations',
        () => http().put(D(did)).send({ provider: 'google_workspace' }),
      ],
      ['DELETE /domains/{id}/destinations', () => http().delete(D(did))],
      ['GET /messages/{messageId}/deliveries', () => http().get(M(mid))],
      ['GET /messages/{messageId}/deliveries/events', () => http().get(`${M(mid)}/events`)],
      ['GET /deliveries', () => http().get('/api/v1/deliveries')],
    ] as const;

  /** Required permission per route (R13). */
  const PERMISSION: Record<string, string> = {
    'GET /destination-providers': 'domain:read',
    'GET /domains/{id}/destinations': 'domain:read',
    'PUT /domains/{id}/destinations': 'domain:routing_manage',
    'DELETE /domains/{id}/destinations': 'domain:routing_manage',
    'GET /messages/{messageId}/deliveries': 'delivery:read',
    'GET /messages/{messageId}/deliveries/events': 'delivery:read',
    'GET /deliveries': 'delivery:read',
  };

  it('answers 401 without credentials on every route', async () => {
    for (const [name, req] of routes()) {
      expect((await req()).status, name).toBe(401);
    }
    expectNoServiceCall();
  });

  it.each(Object.entries(PERMISSION))('%s needs %s (403 otherwise)', async (route, permission) => {
    principalWith(ALL.filter((p) => p !== permission));
    const auth = await bearer();
    const [, req] = routes().find(([name]) => name === route)!;
    expect((await req().set(auth)).status).toBe(403);
    expectNoServiceCall();
  });

  it('domain:manage alone cannot change destinations (domain:routing_manage is separate)', async () => {
    principalWith(['domain:read', 'domain:manage']);
    const auth = await bearer();
    await http().put(D(domainId)).set(auth).send({ provider: 'google_workspace' }).expect(403);
    await http().delete(D(domainId)).set(auth).expect(403);
    expectNoServiceCall();
  });

  it('lets each route through with exactly its permission', async () => {
    for (const [name, req] of routes()) {
      principalWith([PERMISSION[name]!]);
      const res = await req().set(await bearer());
      expect(res.status, name).toBeLessThan(300);
    }
    expect(destinations.remove).toHaveBeenCalledTimes(1);
  });

  it('takes the tenant from the credential, never from headers, the body or the query', async () => {
    const auth = await bearer();
    await http()
      .get(D(domainId))
      .set(auth)
      .set('X-Organization-Id', '99')
      .set('X-Tenant-Id', randomUUID())
      .expect(200);
    expect(destinations.get).toHaveBeenCalledWith(
      expect.objectContaining({ organizationId: 2n, via: 'member' }),
      domainId,
    );
    await http()
      .put(D(domainId))
      .set(auth)
      .send({ provider: 'google_workspace', organizationId: '99' })
      .expect(400);
    await http().get('/api/v1/deliveries?organizationId=99').set(auth).expect(400);
    await http().get(M(messageId)).set(apiKey).expect(200);
    expect(deliveries.forMessage).toHaveBeenCalledWith(
      expect.objectContaining({ organizationId: 2n, via: 'api_key' }),
      messageId,
    );
    expect(destinations.replace).not.toHaveBeenCalled();
    expect(deliveries.list).not.toHaveBeenCalled();
  });

  it.each([
    [{ provider: 'exchange' }, 'provider'],
    [{ provider: 'microsoft_365' }, 'host'],
    [{ provider: 'custom', servers: [] }, 'servers: Too small'],
    [{ provider: 'custom', servers: [{ host: 'a.example', port: 0 }] }, 'servers.0.port'],
    [
      { provider: 'custom', servers: [{ host: 'a.example', tlsVerifyNames: 'nexthop' }] },
      'servers.0.tlsVerifyNames: is only allowed with tlsMode verify',
    ],
    [
      {
        provider: 'custom',
        servers: [{ host: 'a.example', tlsMode: 'verify', tlsVerifyNames: 'x protocols=SSLv3' }],
      },
      'servers.0.tlsVerifyNames',
    ],
  ])('PUT /destinations %j → 400', async (body, message) => {
    const res = await http()
      .put(D(domainId))
      .set(await bearer())
      .send(body)
      .expect(400);
    expect(res.body.message.join('\n')).toContain(message);
    expectNoServiceCall();
  });

  it('passes the parsed body to the service', async () => {
    await http()
      .put(D(domainId))
      .set(await bearer())
      .send({ provider: 'custom', servers: [{ host: 'mx.example', tlsMode: 'required' }] })
      .expect(200);
    expect(destinations.replace).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ organizationId: 2n }),
      domainId,
      { provider: 'custom', servers: [{ host: 'mx.example', tlsMode: 'required' }] },
      expect.anything(),
    );
  });

  it('renders a destination refusal as 422 with a stable reason and field', async () => {
    destinations.replace.mockRejectedValueOnce(
      new DestinationRefusedException('metadata_address', 'servers.0.host'),
    );
    const res = await http()
      .put(D(domainId))
      .set(await bearer())
      .send({ provider: 'custom', servers: [{ host: '169.254.169.254' }] })
      .expect(422);
    expect(res.body).toMatchObject({
      statusCode: 422,
      error: 'UNPROCESSABLE_ENTITY',
      reason: 'metadata_address',
      field: 'servers.0.host',
    });
    expect(JSON.stringify(res.body)).not.toContain('169.254.169.254');
  });

  it.each([
    ['?from=yesterday', 'from'],
    ['?status=lost', 'status'],
    ['?direction=sideways', 'direction'],
    ['?limit=0', 'limit'],
    ['?limit=101', 'limit'],
  ])('GET /deliveries%s → 400', async (query, field) => {
    const res = await http()
      .get(`/api/v1/deliveries${query}`)
      .set(await bearer())
      .expect(400);
    expect(res.body.message.join('\n')).toContain(field);
    expectNoServiceCall();
  });

  it('GET /deliveries/events validates rcptSeq and passes the query', async () => {
    const auth = await bearer();
    await http()
      .get(`${M(messageId)}/events?rcptSeq=-1`)
      .set(auth)
      .expect(400);
    await http()
      .get(`${M(messageId)}/events?rcptSeq=3&limit=10`)
      .set(auth)
      .expect(200);
    expect(deliveries.events).toHaveBeenCalledWith(
      expect.objectContaining({ organizationId: 2n }),
      messageId,
      { rcptSeq: 3, limit: 10 },
    );
  });

  it('rejects malformed ids on every {id} route', async () => {
    const auth = await bearer();
    for (const [name, req] of routes('not-a-uuid', 'not-a-uuid').filter(([n]) => n.includes('{'))) {
      const res = await req().set(auth);
      expect(res.status, name).toBe(400);
      expect(res.body.message, name).toEqual(['(root): Invalid UUID']);
    }
    expectNoServiceCall();
  });

  it('answers 204 on delete', async () => {
    const res = await http()
      .delete(D(domainId))
      .set(await bearer())
      .expect(204);
    expect(res.text).toBe('');
  });

  it('limits destination changes to 30 per caller per minute (PUT and DELETE share it)', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 30; i++) {
      const res = await (
        i % 2 === 0
          ? http().put(D(domainId)).send({ provider: 'google_workspace' })
          : http().delete(D(domainId))
      ).set(apiKey);
      statuses.push(res.status);
    }
    expect(statuses.every((s) => s < 300)).toBe(true);
    await http().put(D(domainId)).set(apiKey).send({ provider: 'google_workspace' }).expect(429);
    apiKeyPrincipal = { ...apiKeyPrincipal, apiKeyPublicId: randomUUID() };
    await http().put(D(domainId)).set(apiKey).send({ provider: 'google_workspace' }).expect(200);
  });
});
