/**
 * Destination servers of a domain (step 2.3 R2, R3, R13) against the real MySQL writer and
 * replica: provider presets, atomic replacement for every provider, every `422` reason, `409`
 * for a deleted domain, the audit row and the `domain.routing.changed.v1` outbox event in the
 * same transaction, deprecated `outbound_source` rows never shown or touched, and the
 * permission split (`domain:read` cannot change destinations).
 */
// ---- Route coverage (step 6.1 §3.8, test/route-coverage/legacy.ts) ----
// @covers delete /api/v1/domains/:id/destinations
// @covers get /api/v1/destination-providers
// @covers get /api/v1/domains/:id/destinations
// @covers put /api/v1/domains/:id/destinations
// ---- end of route coverage ----
import { domainRoutingChangedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  unknownId,
} from './support/fixtures';
import { apiKeyHeader } from './support/http';
import { type DestinationsBody, DestinationApi } from './support/routing';
import { insertDomain, type InsertedDomain } from './support/smtp';

const POLL = { timeout: 10_000, interval: 200 };
const M365_HOST = 'contoso-test.mail.protection.outlook.com';

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let api: DestinationApi;
let reader: DestinationApi;

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  api = new DestinationApi(
    ctx,
    apiKeyHeader(await fx.createApiKey(org, ['domain:read', 'domain:routing_manage'])),
  );
  reader = new DestinationApi(ctx, apiKeyHeader(await fx.createApiKey(org, ['domain:read'])));
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

const events = (domain: InsertedDomain) =>
  ctx.prisma.messageOutbox.findMany({
    where: { eventType: 'domain.routing.changed.v1', aggregateId: domain.id.toString() },
    orderBy: { id: 'asc' },
  });
const audits = (domain: InsertedDomain) =>
  ctx.prisma.auditLog.findMany({
    where: { organizationId: org.id, resourceType: 'domain', resourceId: domain.publicId },
    orderBy: { id: 'asc' },
  });

describe('GET /destination-providers', () => {
  it('lists the seeded presets', async () => {
    const res = await reader.providers().expect(200);
    const byProvider = new Map(
      (res.body.data as Array<{ provider: string }>).map((p) => [p.provider, p]),
    );
    expect(byProvider.get('microsoft_365')).toMatchObject({
      port: 25,
      tlsMode: 'verify',
      tlsVerifyNames: 'nexthop:mail.protection.outlook.com:.mail.protection.outlook.com',
      maxServers: 1,
      defaultServers: null,
    });
    expect(byProvider.get('google_workspace')).toMatchObject({
      tlsMode: 'verify',
      maxServers: 5,
      defaultServers: expect.arrayContaining([{ host: 'aspmx.l.google.com', priority: 1 }]),
    });
  });
});

describe('PUT/GET/DELETE /domains/{id}/destinations', () => {
  it('replaces with Microsoft 365, audited and announced in the same transaction', async () => {
    const domain = await insertDomain(ctx, org, { label: 'dest-m365' });
    const res = await api.put(domain.publicId, { provider: 'microsoft_365', host: M365_HOST });
    expect(res.status).toBe(200);
    const body = res.body as DestinationsBody;
    expect(body.provider).toBe('microsoft_365');
    expect(body.servers).toHaveLength(1);
    expect(body.servers[0]).toMatchObject({
      host: M365_HOST,
      port: 25,
      priority: 10,
      tlsMode: 'verify',
      tlsVerifyNames: 'nexthop:mail.protection.outlook.com:.mail.protection.outlook.com',
      enabled: true,
    });
    expect(body.servers[0]!.id).toMatch(/^[0-9a-f-]{36}$/);

    const rows = await ctx.prisma.domainMailServer.findMany({ where: { domainId: domain.id } });
    expect(rows.map((r) => [r.role, r.host, r.provider, r.organizationId])).toEqual([
      ['inbound_destination', M365_HOST, 'microsoft_365', org.id],
    ]);
    const [audit] = await audits(domain);
    expect(audit).toMatchObject({ action: 'domain.destinations_replaced' });
    expect(audit!.metadata).toMatchObject({
      name: domain.name,
      provider: 'microsoft_365',
      hosts: [M365_HOST],
      count: 1,
      previous: { provider: null, hosts: [] },
    });
    const [event] = await events(domain);
    expect(event).toMatchObject({ aggregateType: 'domain', organizationId: org.id });
    expect(domainRoutingChangedV1.parse(event!.payload)).toMatchObject({
      domainId: domain.id.toString(),
      domainPublicId: domain.publicId,
      name: domain.name,
      hosts: [M365_HOST],
    });

    // Reads come from the replica.
    await expect
      .poll(
        async () => ((await reader.get(domain.publicId)).body as DestinationsBody).servers,
        POLL,
      )
      .toEqual(body.servers);
  });

  it('replaces Microsoft 365 with Google Workspace; the event names the old and new hosts', async () => {
    const domain = await insertDomain(ctx, org, { label: 'dest-google' });
    await api.put(domain.publicId, { provider: 'microsoft_365', host: M365_HOST }).expect(200);
    const res = await api.put(domain.publicId, { provider: 'google_workspace' }).expect(200);
    const body = res.body as DestinationsBody;
    expect(body.provider).toBe('google_workspace');
    expect(body.servers.map((s) => [s.host, s.priority, s.tlsMode])).toEqual([
      ['aspmx.l.google.com', 1, 'verify'],
      ['alt1.aspmx.l.google.com', 5, 'verify'],
      ['alt2.aspmx.l.google.com', 5, 'verify'],
      ['alt3.aspmx.l.google.com', 10, 'verify'],
      ['alt4.aspmx.l.google.com', 10, 'verify'],
    ]);
    const all = await events(domain);
    expect(all).toHaveLength(2);
    const hosts = domainRoutingChangedV1.parse(all[1]!.payload).hosts;
    expect(hosts).toContain(M365_HOST);
    expect(hosts).toContain('aspmx.l.google.com');
    // Same body again: no write, no audit, no event.
    await api.put(domain.publicId, { provider: 'google_workspace' }).expect(200);
    expect(await events(domain)).toHaveLength(2);
    expect(await audits(domain)).toHaveLength(2);
  });

  it('custom servers: defaults, normalization, delivery order; outbound_source rows are untouched', async () => {
    const domain = await insertDomain(ctx, org, { label: 'dest-custom' });
    const legacy = await ctx.prisma.domainMailServer.create({
      data: {
        organizationId: org.id,
        domainId: domain.id,
        role: 'outbound_source',
        ipCidr: '45.1.2.0/24',
      },
    });
    const res = await api
      .put(domain.publicId, {
        provider: 'custom',
        servers: [
          { host: 'Backup.Tenant-Mail.example.', priority: 20, port: 2525 },
          { host: 'primary.tenant-mail.example', tlsMode: 'verify', tlsVerifyNames: 'nexthop' },
          { host: '45.33.32.156', tlsMode: 'required' },
        ],
      })
      .expect(200);
    expect(
      (res.body as DestinationsBody).servers.map((s) => [s.host, s.port, s.priority, s.tlsMode]),
    ).toEqual([
      ['primary.tenant-mail.example', 25, 10, 'verify'],
      ['45.33.32.156', 25, 10, 'required'],
      ['backup.tenant-mail.example', 2525, 20, 'opportunistic'],
    ]);
    await expect
      .poll(
        async () => ((await reader.get(domain.publicId)).body as DestinationsBody).servers.length,
        POLL,
      )
      .toBe(3);

    await api.remove(domain.publicId).expect(204);
    expect(
      await ctx.prisma.domainMailServer.count({
        where: { domainId: domain.id, role: 'inbound_destination' },
      }),
    ).toBe(0);
    expect(
      await ctx.prisma.domainMailServer.findUnique({ where: { id: legacy.id } }),
    ).not.toBeNull();
    const actions = (await audits(domain)).map((a) => a.action);
    expect(actions).toEqual(['domain.destinations_replaced', 'domain.destinations_removed']);
    const last = (await events(domain)).at(-1)!;
    expect(domainRoutingChangedV1.parse(last.payload).hosts.sort()).toEqual(
      ['45.33.32.156', 'backup.tenant-mail.example', 'primary.tenant-mail.example'].sort(),
    );
    await expect
      .poll(async () => (await reader.get(domain.publicId)).body as DestinationsBody, POLL)
      .toEqual({ provider: null, servers: [] });
    // Deleting again is idempotent: no audit row, no event.
    await api.remove(domain.publicId).expect(204);
    expect(await audits(domain)).toHaveLength(2);
  });

  it.each([
    [
      'a private IP literal',
      { provider: 'custom', servers: [{ host: '10.1.2.3' }] },
      'ip_not_public',
    ],
    [
      'an IPv6 unique-local literal',
      { provider: 'custom', servers: [{ host: '[fd12::1]' }] },
      'ip_not_public',
    ],
    [
      'a metadata address',
      { provider: 'custom', servers: [{ host: '169.254.169.254' }] },
      'metadata_address',
    ],
    ['a single-label name', { provider: 'custom', servers: [{ host: 'mysql' }] }, 'single_label'],
    [
      'a .internal name',
      { provider: 'custom', servers: [{ host: 'smtp.corp.internal' }] },
      'internal_suffix',
    ],
    [
      'a gateway MX host',
      { provider: 'custom', servers: [{ host: 'MX1.mail-gateway.test' }] },
      'gateway_host',
    ],
    [
      'the gateway Postfix host',
      { provider: 'custom', servers: [{ host: 'mx.gateway.local' }] },
      'gateway_host',
    ],
    [
      'the bounce domain',
      { provider: 'custom', servers: [{ host: 'bounces.gateway.internal' }] },
      'gateway_host',
    ],
    [
      'an invalid name',
      { provider: 'custom', servers: [{ host: 'bad_host.example' }] },
      'invalid_host',
    ],
    [
      'a duplicate host:port',
      { provider: 'custom', servers: [{ host: 'a.example' }, { host: 'A.example.' }] },
      'duplicate_server',
    ],
    [
      'a wrong Microsoft 365 host',
      { provider: 'microsoft_365', host: 'mail.contoso.com' },
      'host_not_allowed_for_provider',
    ],
  ])('422 for %s (reason %s), nothing written', async (_, body, reason) => {
    const domain = await insertDomain(ctx, org, { label: 'dest-422' });
    const res = await api.put(domain.publicId, body).expect(422);
    expect(res.body).toMatchObject({ statusCode: 422, reason });
    expect(typeof res.body.field).toBe('string');
    expect(await ctx.prisma.domainMailServer.count({ where: { domainId: domain.id } })).toBe(0);
    expect(await events(domain)).toHaveLength(0);
    expect(await audits(domain)).toHaveLength(0);
  });

  it('409 for a deleted domain (PUT and DELETE), 404 on GET; 404 for an unknown id', async () => {
    const domain = await insertDomain(ctx, org, { label: 'dest-del', status: 'deleted' });
    const put = await api.put(domain.publicId, { provider: 'google_workspace' }).expect(409);
    expect(put.body.message).toBe('Domain is deleted');
    await api.remove(domain.publicId).expect(409);
    await reader.get(domain.publicId).expect(404);
    await api.put(unknownId(), { provider: 'google_workspace' }).expect(404);
  });

  it('domain:read alone gets 403 on PUT and DELETE and changes nothing', async () => {
    const domain = await insertDomain(ctx, org, { label: 'dest-ro' });
    await reader.put(domain.publicId, { provider: 'google_workspace' }).expect(403);
    await reader.remove(domain.publicId).expect(403);
    await reader.get(domain.publicId).expect(200);
    expect(await ctx.prisma.domainMailServer.count({ where: { domainId: domain.id } })).toBe(0);
  });

  it('a domain_admin user may change destinations; a read_only_user may not', async () => {
    const domain = await insertDomain(ctx, org, { label: 'dest-roles' });
    const { loginWithMfa, bearer } = await import('./support/http');
    const admin = await fx.createUser(org, { roles: ['domain_admin'] });
    const readOnly = await fx.createUser(org, { roles: ['read_only_user'] });
    const adminApi = new DestinationApi(
      ctx,
      bearer((await loginWithMfa(ctx, fx, admin)).accessToken),
    );
    const roApi = new DestinationApi(
      ctx,
      bearer((await loginWithMfa(ctx, fx, readOnly)).accessToken),
    );
    await adminApi.put(domain.publicId, { provider: 'google_workspace' }).expect(200);
    await roApi
      .put(domain.publicId, { provider: 'custom', servers: [{ host: 'x.example' }] })
      .expect(403);
    await roApi.get(domain.publicId).expect(200);
    const [audit] = await audits(domain);
    expect(audit).toMatchObject({ actorType: 'user', actorId: admin.publicId });
  });
});
