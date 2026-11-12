/**
 * Tenant isolation of the domain endpoints (step 2.1 gate, design §9 isolation row): a member
 * of tenant A and an API key of A with every domain scope get `404` (never `403`, so existence
 * is not disclosed) for every route of a tenant B domain and list only A's domains; the domain
 * permissions are enforced per route (read-only, domain admin, a custom role without
 * `domain:dkim_rotate`); platform users see no tenant domain without an override; `super_admin`
 * under an override into B manages B only, `platform_admin` under an override can only read, and
 * every override request is audited with domain audit rows carrying `metadata.override`.
 */
// ---- Route coverage (step 6.1 §3.8, test/route-coverage/legacy.ts) ----
// @covers delete /api/v1/domains/:id
// @covers get /api/v1/domains
// @covers get /api/v1/domains/:id
// @covers get /api/v1/domains/:id/dns-records
// @covers get /api/v1/domains/:id/status
// @covers patch /api/v1/domains/:id/status
// @covers post /api/v1/domains
// @covers post /api/v1/domains/:id/dkim/rotate
// @covers post /api/v1/domains/:id/verify
// ---- end of route coverage ----
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { TestDnsServer } from '../test/support/dns/test-dns-server';
import type { IntegrationApp } from './support/app';
import {
  createDomainApp,
  DomainApi,
  type DomainBody,
  domainAudit,
  domainRow,
  publishFromApi,
  publishGatewaySpf,
  resetVerifyLimit,
  uniqueDomainName,
} from './support/domains';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
} from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa, uniqueIp } from './support/http';

const ALL_DOMAIN_SCOPES = ['domain:read', 'domain:manage', 'domain:dkim_rotate'];
const POLL = { timeout: 10_000, interval: 200 };

let dns: TestDnsServer;
let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: DomainApi;
let keyA: DomainApi;
let adminB: DomainApi;
/** A's domain, verified. */
let domainA: DomainBody;
/** B's domains: one pending, one verified (both would accept changes from B). */
let pendingB: DomainBody;
let verifiedB: DomainBody;

async function apiFor(user: FixtureUser): Promise<DomainApi> {
  return new DomainApi(ctx, bearer((await loginWithMfa(ctx, fx, user)).accessToken));
}

async function verified(api: DomainApi, label: string): Promise<DomainBody> {
  const domain = await api.okCreate(uniqueDomainName(label));
  await publishFromApi(api, dns, domain.id, ['verification', 'dkim']);
  expect((await api.okVerify(domain.id)).status).toBe('verified');
  return api.okGet(domain.id);
}

const listedIds = async (api: DomainApi, query = ''): Promise<string[]> => {
  const res = await api.list(query).expect(200);
  return (res.body.data as Array<{ id: string }>).map((d) => d.id).sort();
};

/** A snapshot of everything a foreign request could have changed. */
async function snapshot(id: string): Promise<unknown> {
  const row = await domainRow(ctx, id);
  return {
    status: row.status,
    statusReason: row.statusReason,
    lastCheckedAt: row.lastCheckedAt,
    nextCheckAt: row.nextCheckAt,
    attempts: row.verifications.map((v) => v.attempts),
    keys: row.dkimKeys.map((k) => `${k.selector}:${k.status}`),
    records: row.dnsRecords.map((r) => `${r.recordKey}:${r.status}:${r.lastCheckedAt?.getTime()}`),
  };
}

/** Every domain route on `target` answers `status` for `api` and changes nothing. */
async function expectEveryRoute(api: DomainApi, target: DomainBody, status: number): Promise<void> {
  const before = await snapshot(target.id);
  await resetVerifyLimit(ctx, target.id);
  const calls: Array<[string, () => ReturnType<DomainApi['get']>]> = [
    ['GET', () => api.get(target.id)],
    ['GET dns-records', () => api.dnsRecords(target.id)],
    ['GET status', () => api.status(target.id)],
    ['POST verify', () => api.verify(target.id)],
    ['POST rotate', () => api.rotate(target.id, { algorithm: 'rsa_2048' })],
    ['PATCH status active', () => api.setStatus(target.id, { status: 'active' })],
    [
      'PATCH status suspended',
      () => api.setStatus(target.id, { status: 'suspended', reason: 'Hijack' }),
    ],
    ['DELETE', () => api.remove(target.id)],
  ];
  for (const [label, call] of calls) {
    const res = await call();
    expect({ label, status: res.status }).toEqual({ label, status });
  }
  expect(await snapshot(target.id)).toEqual(before);
}

beforeAll(async () => {
  dns = await TestDnsServer.start({ defaultTtl: 60 });
  publishGatewaySpf(dns);
  ctx = await createDomainApp(dns);
  fx = createFixtures(ctx);
  [orgA, orgB] = [await fx.createOrganization(), await fx.createOrganization()];
  adminA = await apiFor(await fx.createUser(orgA, { roles: ['organization_admin'] }));
  adminB = await apiFor(await fx.createUser(orgB, { roles: ['organization_admin'] }));
  keyA = new DomainApi(ctx, apiKeyHeader(await fx.createApiKey(orgA, ALL_DOMAIN_SCOPES)));
  domainA = await verified(adminA, 'tenant-a');
  pendingB = await adminB.okCreate(uniqueDomainName('tenant-b-pending'));
  verifiedB = await verified(adminB, 'tenant-b');
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
  await dns?.close();
});

describe('tenant A (organization admin and API key)', () => {
  it('lists only its own domains, whatever the filters', async () => {
    for (const api of [adminA, keyA]) {
      await expect.poll(() => listedIds(api), POLL).toEqual([domainA.id]);
      expect(await listedIds(api, `?q=${verifiedB.name}`)).toEqual([]);
      expect(await listedIds(api, '?status=pending_verification')).toEqual([]);
    }
  });

  it('gets 404 on every route of a tenant B domain and changes nothing', async () => {
    for (const api of [adminA, keyA]) {
      await expectEveryRoute(api, pendingB, 404);
      await expectEveryRoute(api, verifiedB, 404);
    }
  });

  it('cannot take over a name B owns, but may claim a name B only claims', async () => {
    const owned = await adminA.create({ name: verifiedB.name }).expect(409);
    expect(owned.body.message).toBe('Domain is already registered with another organization');
    expect(JSON.stringify(owned.body)).not.toContain(orgB.publicId);
    // A pending claim of B does not block A; whoever proves ownership first wins (D4).
    const claim = await keyA.create({ name: pendingB.name }).expect(201);
    expect(claim.body.id).not.toBe(pendingB.id);
    expect((await domainRow(ctx, pendingB.id)).status).toBe('pending_verification');
  });

  it('manages its own domains with the API key', async () => {
    await keyA.get(domainA.id).expect(200);
    await keyA.dnsRecords(domainA.id).expect(200);
    await resetVerifyLimit(ctx, domainA.id);
    await keyA.verify(domainA.id).expect(200);
    await keyA.rotate(domainA.id).expect(201);
    const key = await fx.createApiKey(orgA, ['domain:read']);
    const readOnly = new DomainApi(ctx, apiKeyHeader(key));
    await readOnly.get(domainA.id).expect(200);
    await readOnly.create({ name: uniqueDomainName('key-ro') }).expect(403);
    await readOnly.rotate(domainA.id).expect(403);
  });
});

describe('domain permissions per role', () => {
  it('a read-only user reads but gets 403 on every mutation', async () => {
    const api = await apiFor(await fx.createUser(orgA, { roles: ['read_only_user'] }));
    await expect.poll(() => listedIds(api), POLL).toContain(domainA.id);
    await api.get(domainA.id).expect(200);
    await api.dnsRecords(domainA.id).expect(200);
    await api.status(domainA.id).expect(200);
    await api.create({ name: uniqueDomainName('ro') }).expect(403);
    await api.verify(domainA.id).expect(403);
    await api.rotate(domainA.id).expect(403);
    await api.setStatus(domainA.id, { status: 'active' }).expect(403);
    await api.remove(domainA.id).expect(403);
    // Tenant B stays invisible: 404 for reads (403 for mutations comes first by permission).
    await api.get(verifiedB.id).expect(404);
  });

  it('a domain admin manages domains and rotates DKIM keys', async () => {
    const api = await apiFor(await fx.createUser(orgA, { roles: ['domain_admin'] }));
    const domain = await verified(api, 'domain-admin');
    await api.rotate(domain.id).expect(201);
    await api.setStatus(domain.id, { status: 'active' }).expect(200);
    await api.setStatus(domain.id, { status: 'suspended', reason: 'Test' }).expect(200);
    await api.remove(domain.id).expect(204);
    await expectEveryRoute(api, verifiedB, 404);
  });

  it('a custom role with domain:manage but without domain:dkim_rotate cannot rotate', async () => {
    const role = await fx.createCustomRole(orgA, ['domain:read', 'domain:manage']);
    const api = await apiFor(await fx.createUser(orgA, { roles: [role] }));
    const domain = await api.okCreate(uniqueDomainName('custom'));
    await resetVerifyLimit(ctx, domain.id);
    await api.verify(domain.id).expect(200);
    const res = await api.rotate(domain.id).expect(403);
    expect(res.body.message).toBeDefined();
    expect(await domainAudit(ctx, domain.id, 'domain.dkim_rotation_started')).toHaveLength(0);
  });
});

describe('platform users', () => {
  it('see no tenant domain without an override', async () => {
    for (const roles of [['platform_admin'], ['super_admin']]) {
      const api = await apiFor(await fx.createPlatformUser(roles));
      const ids = await listedIds(api, '?limit=100');
      for (const id of [domainA.id, pendingB.id, verifiedB.id]) expect(ids).not.toContain(id);
      expect(await listedIds(api, `?q=${verifiedB.name}`)).toEqual([]);
      await api.get(verifiedB.id).expect(404);
      await api.status(verifiedB.id).expect(404);
    }
  });

  async function startOverride(
    operator: FixtureUser,
    reason: string,
  ): Promise<{ overrideId: string; api: DomainApi }> {
    const session = await loginWithMfa(ctx, fx, operator);
    const started = await ctx.http
      .post('/api/v1/platform/overrides')
      .set(bearer(session.accessToken))
      .set('X-Forwarded-For', uniqueIp())
      .send({ organizationId: orgB.publicId, reason, durationMinutes: 15 })
      .expect(201);
    return {
      overrideId: started.body.overrideId as string,
      api: new DomainApi(ctx, bearer(started.body.accessToken as string)),
    };
  }

  const overrideRequests = async (overrideId: string): Promise<string[]> => {
    const rows = await ctx.prisma.auditLog.findMany({
      where: { action: 'platform.override_request', organizationId: orgB.id },
    });
    return rows
      .map(
        (r) =>
          r.metadata as { overrideId: string; method: string; route: string; statusCode: number },
      )
      .filter((m) => m.overrideId === overrideId)
      .map((m) => `${m.method} ${m.route} ${m.statusCode}`);
  };

  it('super_admin under an override into B manages B only, audited with metadata.override', async () => {
    const operator = await fx.createPlatformUser(['super_admin']);
    const reason = 'Customer ticket 2101';
    const { overrideId, api } = await startOverride(operator, reason);

    await expect.poll(() => listedIds(api), POLL).toEqual([pendingB.id, verifiedB.id].sort());
    await api.get(verifiedB.id).expect(200);
    await resetVerifyLimit(ctx, verifiedB.id);
    await api.verify(verifiedB.id).expect(200);
    await api.rotate(verifiedB.id).expect(201);
    await api.setStatus(verifiedB.id, { status: 'active' }).expect(200);
    const created = await api.create({ name: uniqueDomainName('override') }).expect(201);
    await api.remove(created.body.id as string).expect(204);

    // Not A.
    await expectEveryRoute(api, domainA, 404);
    expect(await listedIds(api, `?q=${domainA.name}`)).toEqual([]);

    // Domain audit rows written under the override carry it.
    const audit = [
      ...(await domainAudit(ctx, verifiedB.id)),
      ...(await domainAudit(ctx, created.body.id as string)),
    ].filter((a) => a.actorId === operator.publicId);
    expect(audit.map((a) => a.action).sort()).toEqual(
      [
        'domain.created',
        'domain.deleted',
        'domain.dkim_rotation_started',
        'domain.status_changed',
      ].sort(),
    );
    for (const row of audit) {
      expect(row.organizationId).toBe(orgB.id);
      expect(row.metadata).toMatchObject({ override: { id: overrideId, reason } });
    }

    await expect
      .poll(() => overrideRequests(overrideId), POLL)
      .toEqual(
        expect.arrayContaining([
          'GET /api/v1/domains 200',
          'GET /api/v1/domains/:id 200',
          'POST /api/v1/domains/:id/verify 200',
          'POST /api/v1/domains/:id/dkim/rotate 201',
          'PATCH /api/v1/domains/:id/status 200',
          'POST /api/v1/domains 201',
          'DELETE /api/v1/domains/:id 204',
          'GET /api/v1/domains/:id 404',
          'DELETE /api/v1/domains/:id 404',
        ]),
      );
  });

  it('platform_admin under an override into B can only read', async () => {
    const operator = await fx.createPlatformUser(['platform_admin']);
    const { overrideId, api } = await startOverride(operator, 'Read-only investigation 2102');
    await expect.poll(() => listedIds(api), POLL).toEqual([pendingB.id, verifiedB.id].sort());
    await api.get(verifiedB.id).expect(200);
    await api.dnsRecords(verifiedB.id).expect(200);
    await api.status(verifiedB.id).expect(200);

    const before = await snapshot(verifiedB.id);
    await api.create({ name: uniqueDomainName('pa') }).expect(403);
    await api.verify(verifiedB.id).expect(403);
    await api.rotate(verifiedB.id).expect(403);
    await api.setStatus(verifiedB.id, { status: 'suspended', reason: 'x' }).expect(403);
    await api.remove(pendingB.id).expect(403);
    expect(await snapshot(verifiedB.id)).toEqual(before);
    await api.get(domainA.id).expect(404);

    await expect
      .poll(() => overrideRequests(overrideId), POLL)
      .toEqual(
        expect.arrayContaining([
          'GET /api/v1/domains/:id 200',
          'POST /api/v1/domains 403',
          'PATCH /api/v1/domains/:id/status 403',
          'GET /api/v1/domains/:id 404',
        ]),
      );
  });
});
