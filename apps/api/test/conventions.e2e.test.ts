/**
 * Step 6.1 HTTP conventions (docs/plan/steps/18-rest-api.md D1, D2, D8, D9, §3.2, §3.4, §9) over
 * HTTP with MySQL, Redis and S3 stubbed: the error envelope (code + requestId + correlationId on
 * every error, the global ApiExceptionFilter taking precedence over the shared
 * AllExceptionsFilter, the same body as the controller-scoped CodedExceptionFilter), X-Request-Id
 * on every response (unknown routes and probes included), Cache-Control on /api, coded 401/403,
 * the global rate limiter's headers and 429, and the idempotency interceptor on a test-only
 * controller registered only inside this test module.
 */
import {
  Body,
  Controller,
  Get,
  Global,
  Header,
  HttpCode,
  HttpStatus,
  Module,
  NotFoundException,
  Param,
  Post,
  UseFilters,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import {
  configureHttpApp,
  CorrelationModule,
  METRICS_OPTIONS,
  MetricsService,
} from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  AllowDuringMfaEnrollment,
  AuthenticatedOnly,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../src/auth-contracts/decorators';
import { ApiConventionMetrics } from '../src/http/api-metrics';
import { CodedExceptionFilter, CodedHttpException } from '../src/http/coded-exception';
import { configureApiApp } from '../src/http/configure-api-app';
import { HttpConventionsModule } from '../src/http/http-conventions.module';
import { Idempotent } from '../src/http/idempotency/idempotency.interceptor';
import { RateClass } from '../src/rate-limit/rate-class.decorator';
import { ZodValidationPipe } from '../src/validation/zod-validation.pipe';
import {
  createStubbedApiApp,
  InMemoryIdempotencyStore,
  type StubbedApiApp,
} from './support/api-test-app';
import { discoverRoutes } from './support/route-discovery';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ACT = 'conventions:act';
let actCalls = 0;

const ValidateBody = z.strictObject({ name: z.string().min(1) });

/** Test-only routes: registered in this test module, never in production code. */
@Controller('conventions-test')
class ConventionsTestController {
  @Get('boom')
  @AuthenticatedOnly()
  boom(): never {
    throw new Error('SELECT secret_column FROM internal_table failed');
  }

  @Get('not-found')
  @AuthenticatedOnly()
  notFound(): never {
    throw new NotFoundException('Thing not found');
  }

  @Get('coded')
  @AuthenticatedOnly()
  coded(): never {
    throw new CodedHttpException(HttpStatus.CONFLICT, 'thing_conflict', 'No', {
      currentVersion: 3,
    });
  }

  @Get('coded-scoped')
  @AuthenticatedOnly()
  @UseFilters(CodedExceptionFilter)
  codedScoped(): never {
    throw new CodedHttpException(HttpStatus.CONFLICT, 'thing_conflict', 'No', {
      currentVersion: 3,
    });
  }

  @Post('validate')
  @AuthenticatedOnly()
  validate(@Body(new ZodValidationPipe(ValidateBody)) body: z.infer<typeof ValidateBody>) {
    return body;
  }

  @Get('cache')
  @AuthenticatedOnly()
  @Header('Cache-Control', 'private, max-age=60')
  cache() {
    return { ok: true };
  }

  @Get('mfa')
  @AuthenticatedOnly()
  @RequireMfa()
  mfa() {
    return { ok: true };
  }

  @Get('user-only')
  @AuthenticatedOnly()
  @UserOnly()
  userOnly() {
    return { ok: true };
  }

  @Get('enrollment')
  @AuthenticatedOnly()
  @AllowDuringMfaEnrollment()
  enrollment() {
    return { ok: true };
  }

  @Get('expensive')
  @AuthenticatedOnly()
  @RateClass('expensive')
  expensive() {
    return { ok: true };
  }

  @Post('things/:thingId/act')
  @RequirePermissions(ACT)
  @HttpCode(202)
  @Idempotent({ operation: 'conventions.act' })
  act(@Param('thingId') thingId: string, @Body() body: unknown) {
    actCalls += 1;
    return { thingId, body, call: actCalls };
  }

  @Post('things/:thingId/fail')
  @RequirePermissions(ACT)
  @Idempotent({ operation: 'conventions.fail' })
  fail(): never {
    actCalls += 1;
    throw new CodedHttpException(HttpStatus.CONFLICT, 'thing_state_conflict', 'Not now');
  }

  @Post('legacy/:thingId')
  @RequirePermissions(ACT)
  @Idempotent({ operation: 'conventions.legacy', legacy: true })
  legacy(@Param('thingId') thingId: string) {
    actCalls += 1;
    return { thingId };
  }
}

@Module({ controllers: [ConventionsTestController] })
class ConventionsTestModule {}

function expectEnvelope(res: request.Response, status: number, code: string): void {
  expect(res.status).toBe(status);
  expect(res.body).toMatchObject({ statusCode: status, code });
  expect(typeof res.body.error).toBe('string');
  expect(res.body.message).toBeDefined();
  expect(res.body.requestId).toMatch(UUID);
  expect(res.body.requestId).toBe(res.headers['x-request-id']);
  expect(res.body.correlationId).toBe(res.headers['x-correlation-id']);
}

describe('REST API conventions (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const store = new InMemoryIdempotencyStore();

  beforeAll(async () => {
    api = await createStubbedApiApp(
      {},
      { imports: [ConventionsTestModule], override: (b) => store.override(b), discovery: true },
    );
  });

  afterAll(async () => {
    await api?.close();
  });

  afterEach(() => {
    api.principals.user([]);
    api.principals.apiKeyWith([]);
  });

  describe('error envelope and request ids (D1, D2, §3.2)', () => {
    it('answers an unknown route 404 route_not_found with X-Request-Id', async () => {
      const res = await api.http().get('/api/v1/no-such-route');
      expectEnvelope(res, 404, 'route_not_found');
      // Internal paths are not served under /api (D13).
      for (const path of ['/api/metrics', '/api/health/live', '/api/docs']) {
        expectEnvelope(await api.http().get(path), 404, 'route_not_found');
      }
    });

    it('never takes the request id from the client and mints one per response', async () => {
      const a = await api.http().get('/api/v1/meta').set('X-Request-Id', 'client-chosen-id');
      const b = await api.http().get('/api/v1/meta');
      expect(a.status).toBe(200);
      expect(a.headers['x-request-id']).toMatch(UUID);
      expect(a.headers['x-request-id']).not.toBe('client-chosen-id');
      expect(b.headers['x-request-id']).not.toBe(a.headers['x-request-id']);
      // The client's correlation id keeps working.
      const c = await api.http().get('/api/v1/meta').set('x-correlation-id', 'client-corr-0001');
      expect(c.headers['x-correlation-id']).toBe('client-corr-0001');
    });

    it('puts X-Request-Id on the probes and the metrics scrape (no /api Cache-Control there)', async () => {
      for (const path of ['/health/live', '/health/ready', '/metrics']) {
        const res = await api.http().get(path);
        expect(res.status, path).toBe(200);
        expect(res.headers['x-request-id'], path).toMatch(UUID);
      }
      expect((await api.http().get('/health/live')).headers['cache-control']).toBeUndefined();
    });

    it('sets Cache-Control: no-store on /api responses unless the route sets its own', async () => {
      expect((await api.http().get('/api/v1/meta')).headers['cache-control']).toBe('no-store');
      expect((await api.http().get('/api/v1/nope')).headers['cache-control']).toBe('no-store');
      api.principals.user([]);
      const own = await api
        .http()
        .get('/api/v1/conventions-test/cache')
        .set(await api.principals.bearer());
      expect(own.status).toBe(200);
      expect(own.headers['cache-control']).toBe('private, max-age=60');
    });

    it('answers 401 coded unauthorized', async () => {
      expectEnvelope(await api.http().get('/api/v1/auth/me'), 401, 'unauthorized');
      expectEnvelope(
        await api.http().get('/api/v1/auth/me').set('Authorization', 'Bearer a.b.c'),
        401,
        'unauthorized',
      );
    });

    it('answers coded 403s with the existing messages', async () => {
      api.principals.user([]);
      const bearer = await api.principals.bearer();
      const mfa = await api.http().get('/api/v1/conventions-test/mfa').set(bearer);
      expectEnvelope(mfa, 403, 'mfa_required');
      expect(mfa.body.message).toBe('MFA required');
      const userOnly = await api
        .http()
        .get('/api/v1/conventions-test/user-only')
        .set(api.principals.apiKeyHeaders);
      expectEnvelope(userOnly, 403, 'user_required');
      expect(userOnly.body.message).toBe('This operation requires a user');
      const denied = await api
        .http()
        .post('/api/v1/conventions-test/things/t-1/act')
        .set(bearer)
        .set('Idempotency-Key', 'k-denied')
        .send({});
      expectEnvelope(denied, 403, 'forbidden');
      expect(denied.body.message).toBe('Forbidden');
      api.principals.user([], { mfaEnrollmentRequired: true });
      const enrolling = await api.principals.bearer();
      const enroll = await api.http().get('/api/v1/conventions-test/mfa').set(enrolling);
      expectEnvelope(enroll, 403, 'mfa_enrollment_required');
      expect(enroll.body.message).toBe('MFA enrollment required');
      expect(
        (await api.http().get('/api/v1/conventions-test/enrollment').set(enrolling)).status,
      ).toBe(200);
    });

    it('renders 400 validation_failed with the issue list (strict body)', async () => {
      const res = await api
        .http()
        .post('/api/v1/conventions-test/validate')
        .set(await api.principals.bearer())
        .send({ name: 'x', extra: 1 });
      expectEnvelope(res, 400, 'validation_failed');
      expect(res.body.message).toEqual([expect.stringContaining('Unrecognized key')]);
    });

    it('renders an unexpected error as a generic 500 internal_error (ApiExceptionFilter wins)', async () => {
      // AllExceptionsFilter (registered by configureHttpApp) would render no `code`/`requestId`:
      // configureApiApp registers ApiExceptionFilter after it, so Nest consults it first.
      const res = await api
        .http()
        .get('/api/v1/conventions-test/boom')
        .set(await api.principals.bearer());
      expectEnvelope(res, 500, 'internal_error');
      expect(res.body.message).toBe('Internal server error');
      expect(JSON.stringify(res.body)).not.toContain('secret_column');
      const notFound = await api
        .http()
        .get('/api/v1/conventions-test/not-found')
        .set(await api.principals.bearer());
      expectEnvelope(notFound, 404, 'not_found');
      expect(notFound.body.message).toBe('Thing not found');
    });

    it('renders coded errors identically with and without the scoped CodedExceptionFilter', async () => {
      const bearer = await api.principals.bearer();
      const global = await api.http().get('/api/v1/conventions-test/coded').set(bearer);
      const scoped = await api.http().get('/api/v1/conventions-test/coded-scoped').set(bearer);
      expectEnvelope(global, 409, 'thing_conflict');
      expectEnvelope(scoped, 409, 'thing_conflict');
      const strip = (body: Record<string, unknown>) => {
        const { requestId: _r, correlationId: _c, ...rest } = body;
        return rest;
      };
      expect(strip(global.body)).toEqual(strip(scoped.body));
      expect(Object.keys(global.body)).toEqual(Object.keys(scoped.body));
      expect(global.body.currentVersion).toBe(3);
    });

    it('carries the envelope on a malformed JSON body (rejected before the middleware)', async () => {
      const res = await api
        .http()
        .post('/api/v1/conventions-test/validate')
        .set(await api.principals.bearer())
        .set('Content-Type', 'application/json')
        .send('{"name":');
      expectEnvelope(res, 400, 'validation_failed');
      expect(res.headers['x-request-id']).toMatch(UUID);
    });
  });

  describe('global rate limiter headers (D8)', () => {
    it('sets RateLimit-* on authenticated responses, not on public ones', async () => {
      const res = await api
        .http()
        .get('/api/v1/conventions-test/expensive')
        .set(await api.principals.bearer());
      expect(res.status).toBe(200);
      expect(Number(res.headers['ratelimit-limit'])).toBeGreaterThan(0);
      expect(Number(res.headers['ratelimit-remaining'])).toBeGreaterThanOrEqual(0);
      expect(Number(res.headers['ratelimit-reset'])).toBeGreaterThan(0);
      expect(res.headers['ratelimit-limit']).toBe(
        api.config.API_RATE_EXPENSIVE_PER_MINUTE.toString(),
      );
      const pub = await api.http().get('/api/v1/meta');
      expect(pub.headers['ratelimit-limit']).toBeUndefined();
    });
  });

  describe('idempotency interceptor (D9) on a test-only route', () => {
    it('stores the first response and replays it with the stored status', async () => {
      api.principals.user([ACT]);
      const bearer = await api.principals.bearer();
      const send = () =>
        api
          .http()
          .post('/api/v1/conventions-test/things/t-1/act')
          .set(bearer)
          .set('Idempotency-Key', 'e2e-key-1')
          .send({ reason: 'because' });
      const first = await send();
      expect(first.status).toBe(202);
      expect(first.headers['idempotency-replayed']).toBeUndefined();
      const second = await send();
      expect(second.status).toBe(202);
      expect(second.headers['idempotency-replayed']).toBe('true');
      expect(second.body).toEqual(first.body);
      expect(first.body).toMatchObject({ thingId: 't-1', body: { reason: 'because' } });
      const row = store.rows.get(`${api.principals.organizationId}:e2e-key-1`)!;
      expect(row).toMatchObject({
        state: 'completed',
        statusCode: 202,
        operation: 'conventions.act',
        resourceId: 't-1',
        principal: `user:${api.principals.ids.user}`,
      });
    });

    it('replays the stored status even when it differs from the route status', async () => {
      api.principals.user([ACT]);
      const bearer = await api.principals.bearer();
      const first = await api
        .http()
        .post('/api/v1/conventions-test/things/t-9/act')
        .set(bearer)
        .set('Idempotency-Key', 'e2e-key-9')
        .send({});
      expect(first.status).toBe(202);
      // A record stored with 201 (e.g. before the route changed its status) replays as 201.
      store.rows.get(`${api.principals.organizationId}:e2e-key-9`)!.statusCode = 201;
      const replay = await api
        .http()
        .post('/api/v1/conventions-test/things/t-9/act')
        .set(bearer)
        .set('Idempotency-Key', 'e2e-key-9')
        .send({});
      expect(replay.status).toBe(201);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body).toEqual(first.body);
      expect(replay.headers['x-request-id']).toMatch(UUID);
    });

    it('refuses a reused key (422), a missing key (400) and an invalid key (400)', async () => {
      api.principals.user([ACT]);
      const bearer = await api.principals.bearer();
      const reuse = await api
        .http()
        .post('/api/v1/conventions-test/things/t-2/act')
        .set(bearer)
        .set('Idempotency-Key', 'e2e-key-1')
        .send({ reason: 'because' });
      expectEnvelope(reuse, 422, 'idempotency_key_reused');
      expectEnvelope(
        await api.http().post('/api/v1/conventions-test/things/t-2/act').set(bearer).send({}),
        400,
        'idempotency_key_required',
      );
      expectEnvelope(
        await api
          .http()
          .post('/api/v1/conventions-test/things/t-2/act')
          .set(bearer)
          .set('Idempotency-Key', 'bad key')
          .send({}),
        400,
        'idempotency_key_invalid',
      );
    });

    it('answers a live pending reservation with 409 and Retry-After', async () => {
      api.principals.user([ACT]);
      const bearer = await api.principals.bearer();
      const body = { reason: 'pending' };
      // Simulate a request still running under the key (its pending reservation).
      const first = await api
        .http()
        .post('/api/v1/conventions-test/things/t-3/act')
        .set(bearer)
        .set('Idempotency-Key', 'e2e-key-3')
        .send(body);
      expect(first.status).toBe(202);
      const row = store.rows.get(`${api.principals.organizationId}:e2e-key-3`)!;
      Object.assign(row, { state: 'pending', statusCode: 0, response: null });
      const res = await api
        .http()
        .post('/api/v1/conventions-test/things/t-3/act')
        .set(bearer)
        .set('Idempotency-Key', 'e2e-key-3')
        .send(body);
      expectEnvelope(res, 409, 'idempotency_request_in_progress');
      expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
    });

    it('releases the reservation when the handler fails (the key can be retried)', async () => {
      api.principals.user([ACT]);
      const bearer = await api.principals.bearer();
      const before = actCalls;
      for (let i = 0; i < 2; i += 1) {
        const res = await api
          .http()
          .post('/api/v1/conventions-test/things/t-4/fail')
          .set(bearer)
          .set('Idempotency-Key', 'e2e-key-4')
          .send({});
        expectEnvelope(res, 409, 'thing_state_conflict');
      }
      expect(actCalls - before).toBe(2);
      expect(store.rows.has(`${api.principals.organizationId}:e2e-key-4`)).toBe(false);
    });

    it('enforce mode refuses a keyless legacy request', async () => {
      api.principals.user([ACT]);
      expectEnvelope(
        await api
          .http()
          .post('/api/v1/conventions-test/legacy/t-5')
          .set(await api.principals.bearer())
          .send({}),
        400,
        'idempotency_key_required',
      );
    });

    it('no test-only route is both idempotent and secret-bearing (route discovery)', () => {
      const routes = discoverRoutes(api.app);
      const act = routes.find((r) => r.path === '/api/v1/conventions-test/things/:thingId/act')!;
      expect(act).toMatchObject({
        rateClass: 'sensitive',
        idempotency: { operation: 'conventions.act', legacy: false },
        returnsSecret: false,
      });
      expect(routes.filter((r) => r.idempotency && r.returnsSecret)).toEqual([]);
    });
  });
});

describe('REST API conventions: warn mode and the 429 (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const store = new InMemoryIdempotencyStore();

  beforeAll(async () => {
    api = await createStubbedApiApp(
      { API_IDEMPOTENCY_LEGACY_MODE: 'warn', API_RATE_PRINCIPAL_PER_MINUTE: '10' },
      { imports: [ConventionsTestModule], override: (b) => store.override(b) },
    );
  });

  afterAll(async () => {
    await api?.close();
  });

  it('processes a keyless legacy request with Deprecation and Link headers', async () => {
    api.principals.user([ACT]);
    const res = await api
      .http()
      .post('/api/v1/conventions-test/legacy/t-6')
      .set(await api.principals.bearer())
      .send({});
    expect(res.status).toBe(201);
    expect(res.body).toEqual({ thingId: 't-6' });
    expect(res.headers.deprecation).toBe('true');
    expect(res.headers.link).toBe('</docs/api/README.md#idempotency>; rel="deprecation"');
    expect(store.rows.size).toBe(0);
  });

  it('answers 429 rate_limited with scope and Retry-After once the principal limit is used', async () => {
    api.principals.user([]);
    const bearer = await api.principals.bearer();
    // The previous test used one request of this window.
    api.kv.entries.clear();
    for (let i = 0; i < 10; i += 1) {
      const ok = await api.http().get('/api/v1/conventions-test/cache').set(bearer);
      expect(ok.status).toBe(200);
      expect(ok.headers['ratelimit-limit']).toBe('10');
      expect(ok.headers['ratelimit-remaining']).toBe(String(9 - i));
    }
    const res = await api.http().get('/api/v1/conventions-test/cache').set(bearer);
    expectEnvelope(res, 429, 'rate_limited');
    expect(res.body.scope).toBe('principal');
    expect(res.body.message).toBe('Too many requests');
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
    expect(res.headers['ratelimit-remaining']).toBe('0');
    // Denied requests count too: the guard runs before authorization.
    const denied = await api
      .http()
      .post('/api/v1/conventions-test/things/t-7/act')
      .set(bearer)
      .set('Idempotency-Key', 'k')
      .send({});
    expect(denied.status).toBe(429);
  });
});

@Controller('filter-order')
class FilterOrderController {
  @Get('boom')
  boom(): never {
    throw new Error('boom');
  }
}

/** What ApiCommonModule / MetricsModule provide globally in the app. */
@Global()
@Module({
  providers: [
    ApiConventionMetrics,
    { provide: METRICS_OPTIONS, useValue: { service: 'filter-order-test' } },
    MetricsService,
  ],
  exports: [ApiConventionMetrics],
})
class FilterOrderGlobals {}

@Module({
  imports: [FilterOrderGlobals, CorrelationModule, HttpConventionsModule],
  controllers: [FilterOrderController],
})
class FilterOrderModule {}

describe('filter precedence (step 6.1: proved, not assumed)', () => {
  const build = async (withApiApp: boolean) => {
    const moduleRef = await Test.createTestingModule({ imports: [FilterOrderModule] }).compile();
    const app = moduleRef.createNestApplication({ logger: false });
    configureHttpApp(app, createLogger({ service: 'api-test', level: 'silent' }));
    if (withApiApp) configureApiApp(app, { HTTP_TRUST_PROXY: 0 });
    await app.init();
    return app;
  };

  it('an APP_FILTER alone loses to the AllExceptionsFilter of configureHttpApp', async () => {
    const app = await build(false);
    try {
      const res = await request(app.getHttpServer()).get('/v1/filter-order/boom');
      expect(res.status).toBe(500);
      expect(res.body).not.toHaveProperty('code');
      expect(res.body).not.toHaveProperty('requestId');
    } finally {
      await app.close();
    }
  });

  it('configureApiApp registers ApiExceptionFilter so that it wins', async () => {
    const app = await build(true);
    try {
      const res = await request(app.getHttpServer()).get('/api/v1/filter-order/boom');
      expect(res.status).toBe(500);
      expect(res.body).toMatchObject({ code: 'internal_error', message: 'Internal server error' });
      expect(res.body.requestId).toBe(res.headers['x-request-id']);
    } finally {
      await app.close();
    }
  });
});
