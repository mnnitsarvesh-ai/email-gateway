/**
 * Tenant isolation of the step 2.3 routes (R13, ADR-0016): a member of tenant A and an API key
 * of A with every routing and delivery scope get `404` (never `403`) for every destination
 * route of a tenant B domain and every delivery route of a tenant B message, see only A's
 * deliveries in the list and change nothing of B. Platform users see nothing without an
 * override; `super_admin` under an override into B replaces B's destinations (audited with
 * `metadata.override`); `platform_admin` under an override can only read.
 */
// ---- Route coverage (step 6.1 §3.8, test/route-coverage/legacy.ts) ----
// @covers delete /api/v1/domains/:id/destinations
// @covers get /api/v1/deliveries
// @covers get /api/v1/domains/:id/destinations
// @covers get /api/v1/messages/:messageId/deliveries
// @covers get /api/v1/messages/:messageId/deliveries/events
// @covers put /api/v1/domains/:id/destinations
// ---- end of route coverage ----
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
} from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa, uniqueIp } from './support/http';
import {
  type DeliveredMessage,
  DeliveryApi,
  DestinationApi,
  deleteDeliveryFixtures,
  insertDeliveredMessage,
} from './support/routing';
import { insertDomain, type InsertedDomain } from './support/smtp';

const ALL_SCOPES = ['domain:read', 'domain:routing_manage', 'delivery:read'];
const POLL = { timeout: 10_000, interval: 200 };

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: Record<string, string>;
let keyA: Record<string, string>;
let domainB: InsertedDomain;
let messageA: DeliveredMessage;
let messageB: DeliveredMessage;

const headersFor = async (user: FixtureUser) =>
  bearer((await loginWithMfa(ctx, fx, user)).accessToken);

/** Everything a foreign request could have changed on B's side. */
async function snapshotB(): Promise<unknown> {
  return {
    servers: await ctx.prisma.domainMailServer.findMany({
      where: { domainId: domainB.id },
      orderBy: { id: 'asc' },
    }),
    events: await ctx.prisma.messageOutbox.count({
      where: { eventType: 'domain.routing.changed.v1', aggregateId: domainB.id.toString() },
    }),
  };
}

/** Every step 2.3 route on B's resources answers `status` and changes nothing. */
async function expectEveryRoute(
  headers: Record<string, string>,
  status: number,
  /** Per-route exceptions (e.g. 403 for a write route the caller has no permission for). */
  except: Record<string, number> = {},
): Promise<void> {
  const destinations = new DestinationApi(ctx, headers);
  const deliveries = new DeliveryApi(ctx, headers);
  const before = await snapshotB();
  const calls: Array<[string, () => ReturnType<DestinationApi['get']>]> = [
    ['GET destinations', () => destinations.get(domainB.publicId)],
    [
      'PUT destinations',
      () => destinations.put(domainB.publicId, { provider: 'google_workspace' }),
    ],
    ['DELETE destinations', () => destinations.remove(domainB.publicId)],
    ['GET deliveries of message', () => deliveries.forMessage(messageB.publicId)],
    ['GET delivery events', () => deliveries.events(messageB.publicId)],
    ['GET delivery events (rcptSeq)', () => deliveries.events(messageB.publicId, '?rcptSeq=0')],
  ];
  for (const [label, call] of calls) {
    const res = await call().set('X-Forwarded-For', uniqueIp());
    const expected = except[label] ?? status;
    expect({ label, status: res.status }).toEqual({ label, status: expected });
    if (expected === 404) {
      const text = JSON.stringify(res.body);
      expect(text).not.toContain(orgB.publicId);
      expect(text).not.toContain('mx.tenant-b.example');
    }
  }
  expect(await snapshotB()).toEqual(before);
}

const listedMessages = async (headers: Record<string, string>): Promise<string[]> => {
  const res = await new DeliveryApi(ctx, headers).list('?limit=100').expect(200);
  return [...new Set((res.body.data as Array<{ messageId: string }>).map((d) => d.messageId))];
};

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  [orgA, orgB] = [await fx.createOrganization(), await fx.createOrganization()];
  fx.registerCleanup(() => deleteDeliveryFixtures(ctx, [orgA.id, orgB.id]));
  adminA = await headersFor(await fx.createUser(orgA, { roles: ['organization_admin'] }));
  keyA = apiKeyHeader(await fx.createApiKey(orgA, ALL_SCOPES));
  domainB = await insertDomain(ctx, orgB, { label: 'iso-route-b' });
  const adminB = new DestinationApi(
    ctx,
    await headersFor(await fx.createUser(orgB, { roles: ['organization_admin'] })),
  );
  await adminB
    .put(domainB.publicId, { provider: 'custom', servers: [{ host: 'mx.tenant-b.example' }] })
    .expect(200);
  messageA = await insertDeliveredMessage(ctx, orgA, {
    recipients: [{ address: 'a@tenant-a.example', status: 'delivered' }],
  });
  messageB = await insertDeliveredMessage(ctx, orgB, {
    recipients: [
      {
        address: 'b@tenant-b.example',
        status: 'bounced',
        events: [{ source: 'postfix_log', fromStatus: 'queued', toStatus: 'bounced' }],
      },
    ],
  });
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('tenant A (organization admin and API key)', () => {
  it('lists only its own deliveries', async () => {
    for (const headers of [adminA, keyA]) {
      await expect.poll(() => listedMessages(headers), POLL).toEqual([messageA.publicId]);
    }
  });

  it('gets 404 on every destination and delivery route of B, and changes nothing', async () => {
    await expectEveryRoute(adminA, 404);
    await expectEveryRoute(keyA, 404);
  });

  it('a domain admin of A also gets 404 for B', async () => {
    const headers = await headersFor(await fx.createUser(orgA, { roles: ['domain_admin'] }));
    await expectEveryRoute(headers, 404);
  });

  it("cannot change the TLS policy of B's destination server through a shared host", async () => {
    // Postfix's tls_policy answer for [mx.tenant-b.example]:25 is shared by every tenant using
    // that next hop: A may use B's server only with B's policy (review fix of step 2.3).
    const domainA = await insertDomain(ctx, orgA, { label: 'iso-route-a' });
    const destinations = new DestinationApi(ctx, keyA);
    const before = await snapshotB();
    for (const server of [
      { host: 'mx.tenant-b.example', tlsMode: 'verify', tlsVerifyNames: 'bogus.invalid' },
      { host: 'MX.Tenant-B.Example.', tlsMode: 'verify' },
      { host: 'mx.tenant-b.example', tlsMode: 'required' },
    ]) {
      const res = await destinations
        .put(domainA.publicId, { provider: 'custom', servers: [{ host: 'mx.a.example' }, server] })
        .expect(422);
      expect(res.body).toMatchObject({
        reason: 'destination_tls_conflict',
        field: 'servers.1.tlsMode',
      });
      // Nothing of B is disclosed: no host, organization or domain id in the refusal.
      const text = JSON.stringify(res.body);
      expect(text).not.toContain('tenant-b');
      expect(text).not.toContain(orgB.publicId);
    }
    expect(
      await ctx.prisma.domainMailServer.count({
        where: { domainId: domainA.id, role: 'inbound_destination' },
      }),
    ).toBe(0);
    // A preset host can never be a custom server (its TLS policy is the preset's).
    await destinations
      .put(domainA.publicId, {
        provider: 'custom',
        servers: [{ host: 'aspmx.l.google.com', tlsMode: 'verify', tlsVerifyNames: 'x.invalid' }],
      })
      .expect(422)
      .expect((res) => expect(res.body.reason).toBe('host_reserved_for_provider'));
    // An internal listener port is refused whatever the host.
    await destinations
      .put(domainA.publicId, {
        provider: 'custom',
        servers: [{ host: 'mx.a.example', port: 10052 }],
      })
      .expect(422)
      .expect((res) => expect(res.body.reason).toBe('port_not_allowed'));
    // B's own policy is accepted: the shared answer does not change.
    await destinations
      .put(domainA.publicId, { provider: 'custom', servers: [{ host: 'mx.tenant-b.example' }] })
      .expect(200);
    expect(await snapshotB()).toEqual(before);
  });
});

describe('platform users', () => {
  it('see nothing of a tenant without an override', async () => {
    // platform_admin holds no write permission at all: its writes are 403 before any lookup.
    const cases: Array<[string[], Record<string, number>]> = [
      [['platform_admin'], { 'PUT destinations': 403, 'DELETE destinations': 403 }],
      [['super_admin'], {}],
    ];
    for (const [roles, except] of cases) {
      const headers = await headersFor(await fx.createPlatformUser(roles));
      await expectEveryRoute(headers, 404, except);
      const listed = await listedMessages(headers);
      expect(listed).not.toContain(messageA.publicId);
      expect(listed).not.toContain(messageB.publicId);
    }
  });

  async function startOverride(operator: FixtureUser, reason: string) {
    const session = await loginWithMfa(ctx, fx, operator);
    const started = await ctx.http
      .post('/api/v1/platform/overrides')
      .set(bearer(session.accessToken))
      .set('X-Forwarded-For', uniqueIp())
      .send({ organizationId: orgB.publicId, reason, durationMinutes: 15 })
      .expect(201);
    return {
      overrideId: started.body.overrideId as string,
      headers: bearer(started.body.accessToken as string),
    };
  }

  it('super_admin under an override into B replaces B’s destinations, audited', async () => {
    const operator = await fx.createPlatformUser(['super_admin']);
    const reason = 'Customer ticket 2301';
    const { overrideId, headers } = await startOverride(operator, reason);
    const destinations = new DestinationApi(ctx, headers);
    await destinations.get(domainB.publicId).expect(200);
    const res = await destinations
      .put(domainB.publicId, {
        provider: 'custom',
        servers: [{ host: 'mx.tenant-b.example' }, { host: 'backup.tenant-b.example' }],
      })
      .expect(200);
    expect(res.body.servers).toHaveLength(2);
    await new DeliveryApi(ctx, headers).forMessage(messageB.publicId).expect(200);
    await new DeliveryApi(ctx, headers).forMessage(messageA.publicId).expect(404);

    const rows = await ctx.prisma.auditLog.findMany({
      where: { action: 'domain.destinations_replaced', actorId: operator.publicId },
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.organizationId).toBe(orgB.id);
    expect(rows[0]!.resourceId).toBe(domainB.publicId);
    expect(rows[0]!.metadata).toMatchObject({ override: { id: overrideId, reason } });
  });

  it('platform_admin under an override into B can only read', async () => {
    const operator = await fx.createPlatformUser(['platform_admin']);
    const { headers } = await startOverride(operator, 'Read-only investigation 2302');
    const destinations = new DestinationApi(ctx, headers);
    await destinations.get(domainB.publicId).expect(200);
    await new DeliveryApi(ctx, headers).forMessage(messageB.publicId).expect(200);
    await new DeliveryApi(ctx, headers).events(messageB.publicId).expect(200);
    const before = await snapshotB();
    await destinations.put(domainB.publicId, { provider: 'google_workspace' }).expect(403);
    await destinations.remove(domainB.publicId).expect(403);
    expect(await snapshotB()).toEqual(before);
  });
});
