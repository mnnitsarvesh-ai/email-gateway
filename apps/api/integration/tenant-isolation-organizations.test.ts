/**
 * Tenant isolation of the organization endpoints (design §9, gate of step 1.2/1.3): a member of
 * tenant A, and an API key of A, never see or change tenant B (404, never 403, so existence is not
 * disclosed) and cannot use catalog functions (403); a platform administrator sees the catalog;
 * a platform user under an override into B sees only B, every request is audited, mutations
 * carry `metadata.override`, and the override cannot reach C, create organizations or be
 * refreshed, and stops on DELETE. Organization endpoints only (identity endpoints: WP4's suite).
 */
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateApiKey, TokenHasher } from '../src/crypto/tokens';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
} from './support/fixtures';
import { apiKeyHeader, bearer, login, loginWithMfa, uniqueIp } from './support/http';

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let orgC: FixtureOrganization;
let adminOfA: FixtureUser;
let tokenOfA: string;
let keyOfA: string;
let platformAdmin: FixtureUser;
let platformToken: string;

const POLL = { timeout: 10_000, interval: 200 };
const path = (org: FixtureOrganization, suffix = '') =>
  `/api/v1/organizations/${org.publicId}${suffix}`;

async function createApiKey(org: FixtureOrganization, scopes: string[]): Promise<string> {
  const { key, prefix } = generateApiKey();
  await ctx.prisma.apiKey.create({
    data: {
      organizationId: org.id,
      name: `it-${prefix}`,
      keyPrefix: prefix,
      keyHash: ctx.get(TokenHasher).hmacHex(key),
      scopes,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    },
  });
  return key;
}

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  [orgA, orgB, orgC] = [
    await fx.createOrganization(),
    await fx.createOrganization(),
    await fx.createOrganization(),
  ];
  // organization_admin holds every tenant permission.
  adminOfA = await fx.createUser(orgA, { roles: ['organization_admin'] });
  const res = await login(ctx, {
    email: adminOfA.email,
    password: adminOfA.password,
    organization: orgA.slug,
  }).expect(200);
  tokenOfA = res.body.accessToken as string;
  keyOfA = await createApiKey(orgA, ['organization:read', 'organization:manage']);
  platformAdmin = await fx.createPlatformUser(['platform_admin']);
  platformToken = (await loginWithMfa(ctx, fx, platformAdmin)).accessToken;
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

/** Every read of another tenant's organization data is 404. */
async function expectNoReadAccess(
  headers: Record<string, string>,
  target: FixtureOrganization,
): Promise<void> {
  for (const suffix of ['', '/settings', '/features', '/limits', '/usage']) {
    await ctx.http.get(path(target, suffix)).set(headers).expect(404);
  }
}

/** Every write to another tenant's organization is 404 and changes nothing. */
async function expectNoWriteAccess(
  headers: Record<string, string>,
  target: FixtureOrganization,
): Promise<void> {
  const before = await ctx.prisma.organization.findUniqueOrThrow({
    where: { id: target.id },
    include: { settings: true },
  });
  await ctx.http.put(path(target)).set(headers).send({ name: 'Hijacked' }).expect(404);
  await ctx.http
    .put(path(target, '/settings'))
    .set(headers)
    .send({ timezone: 'Europe/Berlin', notificationEmail: 'attacker@example.test' })
    .expect(404);
  const after = await ctx.prisma.organization.findUniqueOrThrow({
    where: { id: target.id },
    include: { settings: true },
  });
  expect(after.name).toBe(before.name);
  expect(after.settings).toEqual(before.settings);
}

const listedIds = async (headers: Record<string, string>, query = ''): Promise<string[]> => {
  const res = await ctx.http.get(`/api/v1/organizations${query}`).set(headers);
  expect(res.status).toBe(200);
  return (res.body.data as Array<{ id: string }>).map((o) => o.id);
};

describe('tenant A member', () => {
  it('lists only its own organization', async () => {
    await expect.poll(() => listedIds(bearer(tokenOfA)), POLL).toEqual([orgA.publicId]);
    // Filters cannot widen the scope.
    expect(await listedIds(bearer(tokenOfA), `?q=${orgB.slug}`)).toEqual([]);
    expect(await listedIds(bearer(tokenOfA), '?kind=platform')).toEqual([]);
  });

  it('reads its own organization', async () => {
    for (const suffix of ['', '/settings', '/features', '/limits']) {
      await ctx.http.get(path(orgA, suffix)).set(bearer(tokenOfA)).expect(200);
    }
    await expect
      .poll(
        async () => (await ctx.http.get(path(orgA, '/usage')).set(bearer(tokenOfA))).status,
        POLL,
      )
      .toBe(200);
  });

  it('cannot read or change tenant B (404)', async () => {
    await expectNoReadAccess(bearer(tokenOfA), orgB);
    await expectNoWriteAccess(bearer(tokenOfA), orgB);
    await ctx.http
      .get(path(await fx.platformOrg()))
      .set(bearer(tokenOfA))
      .expect(404);
  });

  it('cannot use catalog functions, not even on its own organization (403)', async () => {
    const auth = bearer(tokenOfA);
    await ctx.http
      .post('/api/v1/organizations')
      .set(auth)
      .send({
        name: 'Rogue',
        slug: `rogue-${randomBytes(4).toString('hex')}`,
        planCode: 'enterprise',
        deploymentMode: 'saas',
        dataRegion: 'ap-south-1',
      })
      .expect(403);
    for (const target of [orgA, orgB]) {
      await ctx.http
        .patch(path(target, '/status'))
        .set(auth)
        .send({ status: 'suspended', reason: 'Takeover' })
        .expect(403);
      await ctx.http
        .put(path(target, '/features/sso'))
        .set(auth)
        .send({ enabled: true })
        .expect(403);
      await ctx.http
        .put(path(target, '/limits/max_users'))
        .set(auth)
        .send({ value: 100_000 })
        .expect(403);
      await ctx.http.get(path(target, '/deletion')).set(auth).expect(403);
    }
    await ctx.http
      .put(path(orgA))
      .set(auth)
      .send({ name: 'x', planCode: 'enterprise' })
      .expect(403);
    const b = await ctx.prisma.organization.findUniqueOrThrow({ where: { id: orgB.id } });
    expect(b.status).toBe('active');
  });
});

describe('tenant A API key', () => {
  it('sees only tenant A and cannot change tenant B', async () => {
    await expect.poll(() => listedIds(apiKeyHeader(keyOfA)), POLL).toEqual([orgA.publicId]);
    await ctx.http.get(path(orgA)).set(apiKeyHeader(keyOfA)).expect(200);
    await expectNoReadAccess(apiKeyHeader(keyOfA), orgB);
    await expectNoWriteAccess(apiKeyHeader(keyOfA), orgB);
    await ctx.http
      .patch(path(orgA, '/status'))
      .set(apiKeyHeader(keyOfA))
      .send({ status: 'suspended', reason: 'x' })
      .expect(403);
  });
});

describe('platform administrator (catalog, no override)', () => {
  it('lists and reads every organization', async () => {
    await expect
      .poll(async () => {
        const ids = await listedIds(bearer(platformToken), '?q=it-&limit=100');
        return [orgA, orgB, orgC].every((o) => ids.includes(o.publicId));
      }, POLL)
      .toBe(true);
    for (const org of [orgA, orgB, orgC]) {
      await ctx.http.get(path(org)).set(bearer(platformToken)).expect(200);
    }
  });
});

describe('platform override into B (organization endpoints)', () => {
  it('sees only B, is audited, cannot reach C or the catalog, cannot be refreshed and ends on DELETE', async () => {
    // super_admin: its tenant permissions (organization:manage included) survive the override.
    const operator = await fx.createPlatformUser(['super_admin']);
    const session = await loginWithMfa(ctx, fx, operator);
    const started = await ctx.http
      .post('/api/v1/platform/overrides')
      .set(bearer(session.accessToken))
      .send({ organizationId: orgB.publicId, reason: 'Customer ticket 9001', durationMinutes: 15 })
      .expect(201);
    const { overrideId, accessToken } = started.body as {
      overrideId: string;
      accessToken: string;
    };
    expect(started.body).not.toHaveProperty('refreshToken');
    const asOverride = bearer(accessToken);

    // Only B, like a member of B.
    await expect.poll(() => listedIds(asOverride), POLL).toEqual([orgB.publicId]);
    expect(await listedIds(asOverride, '?q=it-&limit=100')).toEqual([orgB.publicId]);
    await ctx.http.get(path(orgB, '/settings')).set(asOverride).expect(200);
    await expect
      .poll(async () => (await ctx.http.get(path(orgB, '/usage')).set(asOverride)).status, POLL)
      .toBe(200);

    // A mutation on B is audited with the override.
    await ctx.http
      .put(path(orgB))
      .set(asOverride)
      .send({ name: 'Renamed under override' })
      .expect(200);
    const updated = await ctx.prisma.auditLog.findMany({
      where: { action: 'organization.updated', resourceId: orgB.publicId },
    });
    expect(updated).toHaveLength(1);
    expect(updated[0]).toMatchObject({ organizationId: orgB.id, actorId: operator.publicId });
    expect(updated[0]!.metadata).toMatchObject({
      override: { id: overrideId, reason: 'Customer ticket 9001' },
    });

    // Not C, not the platform organization, not the catalog.
    await expectNoReadAccess(asOverride, orgC);
    await expectNoWriteAccess(asOverride, orgC);
    await ctx.http
      .get(path(await fx.platformOrg()))
      .set(asOverride)
      .expect(404);
    await ctx.http
      .post('/api/v1/organizations')
      .set(asOverride)
      .send({
        name: 'Via override',
        slug: `via-override-${randomBytes(4).toString('hex')}`,
        planCode: 'standard',
        deploymentMode: 'saas',
        dataRegion: 'ap-south-1',
      })
      .expect(403);
    await ctx.http
      .patch(path(orgB, '/status'))
      .set(asOverride)
      .send({ status: 'suspended', reason: 'Not allowed' })
      .expect(403);
    await ctx.http
      .put(path(orgB, '/limits/max_users'))
      .set(asOverride)
      .send({ value: 1 })
      .expect(403);

    // The override token is not a refresh token, and refreshing the session yields a token
    // without the override.
    const asRefresh = await ctx.http
      .post('/api/v1/auth/refresh')
      .set('X-Forwarded-For', uniqueIp())
      .send({ refreshToken: accessToken });
    expect([400, 401]).toContain(asRefresh.status);
    const refreshed = await ctx.http
      .post('/api/v1/auth/refresh')
      .set('X-Forwarded-For', uniqueIp())
      .send({ refreshToken: session.refreshToken })
      .expect(200);
    await ctx.http
      .get(path(orgB))
      .set(bearer(refreshed.body.accessToken as string))
      .expect(200);
    const me = await ctx.http
      .get('/api/v1/auth/me')
      .set(bearer(refreshed.body.accessToken as string))
      .expect(200);
    expect(me.body.override).toBeNull();

    // Every request under the override is audited (route template, never the raw URL).
    await expect
      .poll(async () => {
        const rows = await ctx.prisma.auditLog.findMany({
          where: { action: 'platform.override_request', organizationId: orgB.id },
        });
        return rows
          .map(
            (r) =>
              r.metadata as {
                overrideId: string;
                method: string;
                route: string;
                statusCode: number;
              },
          )
          .filter((m) => m.overrideId === overrideId)
          .map((m) => `${m.method} ${m.route} ${m.statusCode}`);
      }, POLL)
      .toEqual(
        expect.arrayContaining([
          'GET /api/v1/organizations 200',
          'GET /api/v1/organizations/:id/settings 200',
          'GET /api/v1/organizations/:id/usage 200',
          'PUT /api/v1/organizations/:id 200',
          'GET /api/v1/organizations/:id 404',
          'POST /api/v1/organizations 403',
          'PATCH /api/v1/organizations/:id/status 403',
        ]),
      );

    // Ending the override stops the token.
    await ctx.http.delete(`/api/v1/platform/overrides/${overrideId}`).set(asOverride).expect(204);
    await ctx.http.get(path(orgB)).set(asOverride).expect(401);
    await ctx.http.get('/api/v1/organizations').set(asOverride).expect(401);
  });
});
