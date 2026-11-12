/**
 * Step 6.1 conventions against the real stack (docs/plan/steps/18-rest-api.md D8, D9, §9):
 * the global API rate limiter with Redis counters and the tenant limit read from
 * `organization_limits.api_requests_per_minute` on the replica (clamp, cache, 429), and the
 * idempotency reservation interceptor's `api_idempotency_keys` rows on the writer (pending →
 * completed, replay, reuse, in progress, pending expiry). The idempotent routes are a test-only
 * controller registered only in this suite's app (production routes get `@Idempotent` in WP4).
 */
import { Body, Controller, HttpCode, HttpStatus, Module, Param, Post } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RequirePermissions } from '../src/auth-contracts/decorators';
import { CodedHttpException } from '../src/http/coded-exception';
import { Idempotent } from '../src/http/idempotency/idempotency.interceptor';
import {
  API_REQUESTS_PER_MINUTE_LIMIT,
  TenantRateLimitResolver,
} from '../src/rate-limit/tenant-rate-limit.resolver';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { Fixtures, type FixtureOrganization } from './support/fixtures';
import { apiKeyHeader } from './support/http';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Lets a test hold a handler open (to observe the pending reservation). */
const gate: { wait?: Promise<void>; release?: () => void; calls: number } = { calls: 0 };

@Controller('conventions-it')
class ConventionsItController {
  @Post('things/:thingId/act')
  @RequirePermissions('domain:read')
  @HttpCode(202)
  @Idempotent({ operation: 'conventions_it.act' })
  async act(@Param('thingId') thingId: string, @Body() body: unknown) {
    gate.calls += 1;
    if (gate.wait) await gate.wait;
    return { thingId, body, call: gate.calls };
  }

  @Post('things/:thingId/fail')
  @RequirePermissions('domain:read')
  @Idempotent({ operation: 'conventions_it.fail' })
  fail(): never {
    gate.calls += 1;
    throw new CodedHttpException(HttpStatus.CONFLICT, 'thing_state_conflict', 'Not now');
  }
}

@Module({ controllers: [ConventionsItController] })
class ConventionsItModule {}

let ctx: IntegrationApp;
let fx: Fixtures;

beforeAll(async () => {
  ctx = await createIntegrationApp(
    {
      API_RATE_TENANT_MIN_PER_MINUTE: '10',
      API_RATE_TENANT_DEFAULT_PER_MINUTE: '300',
      API_RATE_TENANT_MAX_PER_MINUTE: '1000',
      API_RATE_LIMIT_CACHE_SECONDS: '5',
      API_IDEMPOTENCY_PENDING_TTL_SECONDS: '60',
    },
    { imports: [ConventionsItModule] },
  );
  fx = new Fixtures(ctx);
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

/** Sets the organization's API limit and waits until the replica serves it. */
async function setTenantLimit(org: FixtureOrganization, value: number): Promise<void> {
  await ctx.prisma.organizationLimit.update({
    where: {
      organizationId_limitKey: { organizationId: org.id, limitKey: API_REQUESTS_PER_MINUTE_LIMIT },
    },
    data: { limitValue: BigInt(value) },
  });
  const read = ctx.get(PrismaReadService);
  for (let i = 0; i < 100; i += 1) {
    const row = await read.client.organizationLimit.findUnique({
      where: {
        organizationId_limitKey: {
          organizationId: org.id,
          limitKey: API_REQUESTS_PER_MINUTE_LIMIT,
        },
      },
      select: { limitValue: true },
    });
    if (row?.limitValue === BigInt(value)) return;
    await sleep(50);
  }
  throw new Error('the replica never served the new limit');
}

async function tenantFixture(limit: number) {
  const org = await fx.createOrganization();
  const key = await fx.createApiKey(org, ['domain:read']);
  await setTenantLimit(org, limit);
  ctx.get(TenantRateLimitResolver).invalidate(org.id);
  fx.registerCleanup(() => ctx.kv.del(`rl:api:t:${org.id}`));
  return { org, headers: apiKeyHeader(key) };
}

describe('global API rate limiter on Redis with organization_limits (D8)', () => {
  it('enforces the tenant limit from organization_limits and answers 429 scope tenant', async () => {
    const { headers } = await tenantFixture(12);
    for (let i = 1; i <= 12; i += 1) {
      const res = await ctx.http.get('/api/v1/domains').set(headers);
      expect(res.status, `request ${i}`).toBe(200);
      expect(res.headers['ratelimit-limit']).toBe('12');
      expect(res.headers['ratelimit-remaining']).toBe(String(12 - i));
      expect(Number(res.headers['ratelimit-reset'])).toBeGreaterThan(0);
    }
    const res = await ctx.http.get('/api/v1/domains').set(headers);
    expect(res.status).toBe(429);
    expect(res.body).toMatchObject({ code: 'rate_limited', scope: 'tenant' });
    expect(res.body.requestId).toBe(res.headers['x-request-id']);
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('clamps the tenant value to the configured minimum and maximum', async () => {
    const low = await tenantFixture(3);
    const lowRes = await ctx.http.get('/api/v1/domains').set(low.headers);
    expect(lowRes.status).toBe(200);
    expect(lowRes.headers['ratelimit-limit']).toBe('10');
    const high = await tenantFixture(50_000);
    const highRes = await ctx.http.get('/api/v1/domains').set(high.headers);
    expect(highRes.status).toBe(200);
    // The most restrictive counter is the principal one (10000) or the clamped tenant (1000).
    expect(highRes.headers['ratelimit-limit']).toBe('1000');
  });

  it('caches the tenant value and reads the new one after the cache expires', async () => {
    const { org, headers } = await tenantFixture(40);
    expect((await ctx.http.get('/api/v1/domains').set(headers)).headers['ratelimit-limit']).toBe(
      '40',
    );
    await setTenantLimit(org, 45);
    expect((await ctx.http.get('/api/v1/domains').set(headers)).headers['ratelimit-limit']).toBe(
      '40',
    );
    await sleep(5_200);
    expect((await ctx.http.get('/api/v1/domains').set(headers)).headers['ratelimit-limit']).toBe(
      '45',
    );
  }, 20_000);

  it('counts in Redis with a 60 s window per tenant', async () => {
    const { org, headers } = await tenantFixture(100);
    await ctx.http.get('/api/v1/domains').set(headers).expect(200);
    await ctx.http.get('/api/v1/domains').set(headers).expect(200);
    expect(await ctx.kv.get(`rl:api:t:${org.id}`)).toBe('2');
    const ttl = await ctx.kv.ttl(`rl:api:t:${org.id}`);
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(60);
  });
});

describe('idempotency reservation interceptor on the writer (D9)', () => {
  let org: FixtureOrganization;
  let headers: Record<string, string>;

  beforeAll(async () => {
    org = await fx.createOrganization();
    headers = apiKeyHeader(await fx.createApiKey(org, ['domain:read']));
    fx.registerCleanup(() =>
      ctx.prisma.apiIdempotencyKey.deleteMany({ where: { organizationId: org.id } }),
    );
  });

  const row = (key: string) =>
    ctx.prisma.apiIdempotencyKey.findUnique({
      where: { organizationId_idempotencyKey: { organizationId: org.id, idempotencyKey: key } },
    });

  it('reserves (pending), completes with the 2xx response and replays it', async () => {
    let release!: () => void;
    gate.wait = new Promise<void>((resolve) => (release = resolve));
    const first = ctx.http
      .post('/api/v1/conventions-it/things/t-1/act')
      .set(headers)
      .set('Idempotency-Key', 'it-key-1')
      .send({ reason: 'first' })
      .then((r) => r);
    // While the handler runs the key is a pending reservation, and the same request is 409.
    let pending = await row('it-key-1');
    for (let i = 0; i < 100 && pending?.state !== 'pending'; i += 1) {
      await sleep(20);
      pending = await row('it-key-1');
    }
    expect(pending).toMatchObject({
      state: 'pending',
      statusCode: 0,
      operation: 'conventions_it.act',
      resourceId: 't-1',
    });
    expect(pending!.response).toBeNull();
    expect(pending!.expiresAt.getTime() - Date.now()).toBeLessThanOrEqual(60_000);
    const busy = await ctx.http
      .post('/api/v1/conventions-it/things/t-1/act')
      .set(headers)
      .set('Idempotency-Key', 'it-key-1')
      .send({ reason: 'first' });
    expect(busy.status).toBe(409);
    expect(busy.body.code).toBe('idempotency_request_in_progress');
    expect(Number(busy.headers['retry-after'])).toBeGreaterThan(0);
    gate.wait = undefined;
    release();

    const done = await first;
    expect(done.status).toBe(202);
    const completed = await row('it-key-1');
    expect(completed).toMatchObject({ state: 'completed', statusCode: 202 });
    expect(completed!.response).toEqual(done.body);
    expect(completed!.expiresAt.getTime() - Date.now()).toBeGreaterThan(23 * 3600 * 1000);

    const calls = gate.calls;
    const replay = await ctx.http
      .post('/api/v1/conventions-it/things/t-1/act')
      .set(headers)
      .set('Idempotency-Key', 'it-key-1')
      .send({ reason: 'first' });
    expect(replay.status).toBe(202);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual(done.body);
    expect(gate.calls).toBe(calls);

    const reused = await ctx.http
      .post('/api/v1/conventions-it/things/t-1/act')
      .set(headers)
      .set('Idempotency-Key', 'it-key-1')
      .send({ reason: 'other' });
    expect(reused.status).toBe(422);
    expect(reused.body.code).toBe('idempotency_key_reused');
  });

  it('deletes the reservation when the handler fails', async () => {
    const res = await ctx.http
      .post('/api/v1/conventions-it/things/t-2/fail')
      .set(headers)
      .set('Idempotency-Key', 'it-key-2')
      .send({});
    expect(res.status).toBe(409);
    expect(res.body.code).toBe('thing_state_conflict');
    expect(await row('it-key-2')).toBeNull();
  });

  it('replaces an expired pending reservation (the documented crash window)', async () => {
    await ctx.prisma.apiIdempotencyKey.create({
      data: {
        organizationId: org.id,
        idempotencyKey: 'it-key-3',
        operation: 'conventions_it.act',
        principal: 'api_key:crashed',
        requestSha256: '0'.repeat(64),
        resourceId: 't-3',
        statusCode: 0,
        response: {},
        state: 'pending',
        expiresAt: new Date(Date.now() - 1000),
      },
    });
    const res = await ctx.http
      .post('/api/v1/conventions-it/things/t-3/act')
      .set(headers)
      .set('Idempotency-Key', 'it-key-3')
      .send({});
    expect(res.status).toBe(202);
    expect(await row('it-key-3')).toMatchObject({ state: 'completed', statusCode: 202 });
  });

  it('never replays another organization’s key', async () => {
    const other = await fx.createOrganization();
    const otherHeaders = apiKeyHeader(await fx.createApiKey(other, ['domain:read']));
    fx.registerCleanup(() =>
      ctx.prisma.apiIdempotencyKey.deleteMany({ where: { organizationId: other.id } }),
    );
    const res = await ctx.http
      .post('/api/v1/conventions-it/things/t-1/act')
      .set(otherHeaders)
      .set('Idempotency-Key', 'it-key-1')
      .send({ reason: 'first' });
    expect(res.status).toBe(202);
    expect(res.headers['idempotency-replayed']).toBeUndefined();
  });
});
