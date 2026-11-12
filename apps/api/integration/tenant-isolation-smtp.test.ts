/**
 * Tenant isolation of the step 2.2 control-plane routes (design §4.1, ADR-0016): a member of
 * tenant A and an API key of A with every connector and domain scope get `404` (never `403`)
 * for every SMTP connector route of a tenant B connector and every recipient route of a tenant
 * B domain, list only A's connectors, and change nothing of B. Permissions per role
 * (read-only, domain admin); platform users see nothing without an override; `super_admin`
 * under an override into B manages B's connectors (audited with `metadata.override`) and
 * `platform_admin` under an override can only read.
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
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { IntegrationApp } from './support/app';
import { createIntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
} from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa, uniqueIp } from './support/http';
import {
  ConnectorApi,
  type ConnectorBody,
  insertDomain,
  type InsertedDomain,
  RecipientApi,
  randomV4Network,
} from './support/smtp';

const ALL_SCOPES = ['connector:read', 'connector:manage', 'domain:read', 'domain:manage'];
const POLL = { timeout: 10_000, interval: 200 };

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: Record<string, string>;
let keyA: Record<string, string>;
let adminB: ConnectorApi;
let connectorA: ConnectorBody;
let connectorB: ConnectorBody;
let saslB: ConnectorBody;
let domainB: InsertedDomain;

const headersFor = async (user: FixtureUser) =>
  bearer((await loginWithMfa(ctx, fx, user)).accessToken);

const listedConnectors = async (api: ConnectorApi): Promise<string[]> => {
  const res = await api.list('?limit=100').expect(200);
  return (res.body.data as ConnectorBody[]).map((c) => c.id).sort();
};

/** Everything a foreign request could have changed on B's side. */
async function snapshotB(): Promise<unknown> {
  const connectors = await ctx.prisma.smtpConnector.findMany({
    where: { organizationId: orgB.id },
    include: { networks: { select: { cidr: true } } },
    orderBy: { id: 'asc' },
  });
  const recipients = await ctx.prisma.domainRecipientAddress.findMany({
    where: { domainId: domainB.id },
    select: { localPart: true },
    orderBy: { id: 'asc' },
  });
  const settings = await ctx.prisma.domainSetting.findUnique({ where: { domainId: domainB.id } });
  return {
    connectors: connectors.map((c) => ({
      ...c,
      networks: c.networks.map((n) => n.cidr),
    })),
    recipients,
    settings: settings && {
      recipientValidation: settings.recipientValidation,
      reject: settings.rejectUnknownRecipients,
    },
  };
}

/** Every connector and recipient route on B's resources answers `status` and changes nothing. */
async function expectEveryRoute(headers: Record<string, string>, status: number): Promise<void> {
  const connectors = new ConnectorApi(ctx, headers);
  const recipients = new RecipientApi(ctx, headers);
  const before = await snapshotB();
  const calls: Array<[string, () => ReturnType<ConnectorApi['get']>]> = [
    ['GET connector', () => connectors.get(connectorB.id)],
    ['PATCH connector', () => connectors.update(connectorB.id, { status: 'disabled' })],
    ['PATCH networks', () => connectors.update(connectorB.id, { networks: [randomV4Network()] })],
    ['POST rotate', () => connectors.rotate(saslB.id)],
    ['DELETE connector', () => connectors.remove(connectorB.id)],
    ['GET recipient-validation', () => recipients.getValidation(domainB.publicId)],
    [
      'PUT recipient-validation',
      () => recipients.setValidation(domainB.publicId, { mode: 'accept_all' }),
    ],
    ['GET recipients', () => recipients.list(domainB.publicId)],
    ['POST recipients', () => recipients.add(domainB.publicId, ['intruder'])],
    ['POST recipients/remove', () => recipients.remove(domainB.publicId, ['bob'])],
  ];
  for (const [label, call] of calls) {
    const res = await call().set('X-Forwarded-For', uniqueIp());
    expect({ label, status: res.status }).toEqual({ label, status });
    if (status === 404) expect(JSON.stringify(res.body)).not.toContain(orgB.publicId);
  }
  expect(await snapshotB()).toEqual(before);
}

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  [orgA, orgB] = [await fx.createOrganization(), await fx.createOrganization()];
  adminA = await headersFor(await fx.createUser(orgA, { roles: ['organization_admin'] }));
  keyA = apiKeyHeader(await fx.createApiKey(orgA, ALL_SCOPES));
  const adminBHeaders = await headersFor(
    await fx.createUser(orgB, { roles: ['organization_admin'] }),
  );
  adminB = new ConnectorApi(ctx, adminBHeaders);
  connectorA = await new ConnectorApi(ctx, adminA).okCreate({ authType: 'sasl' });
  connectorB = await adminB.okCreate({ authType: 'source_ip', networks: [randomV4Network()] });
  saslB = await adminB.okCreate({ authType: 'sasl' });
  domainB = await insertDomain(ctx, orgB, { label: 'iso-b' });
  const recipientsB = new RecipientApi(ctx, adminBHeaders);
  await recipientsB.add(domainB.publicId, ['alice', 'bob']).expect(200);
  await recipientsB
    .setValidation(domainB.publicId, { mode: 'allow_list', enforcement: 'reject' })
    .expect(200);
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('tenant A (organization admin and API key)', () => {
  it('lists only its own connectors', async () => {
    for (const headers of [adminA, keyA]) {
      await expect
        .poll(() => listedConnectors(new ConnectorApi(ctx, headers)), POLL)
        .toEqual([connectorA.id]);
    }
  });

  it('gets 404 on every route of B’s connectors and domain, and changes nothing', async () => {
    await expectEveryRoute(adminA, 404);
    await expectEveryRoute(keyA, 404);
  });
});

describe('permissions per role', () => {
  it('a read-only user reads connectors and recipients but cannot change them', async () => {
    const headers = await headersFor(await fx.createUser(orgA, { roles: ['read_only_user'] }));
    const api = new ConnectorApi(ctx, headers);
    await api.get(connectorA.id).expect(200);
    await api.create({ name: 'ro', authType: 'sasl' }).expect(403);
    await api.update(connectorA.id, { status: 'disabled' }).expect(403);
    await api.rotate(connectorA.id).expect(403);
    await api.remove(connectorA.id).expect(403);
    const domainA = await insertDomain(ctx, orgA, { label: 'iso-a' });
    const recipients = new RecipientApi(ctx, headers);
    await recipients.getValidation(domainA.publicId).expect(200);
    await recipients.list(domainA.publicId).expect(200);
    await recipients.setValidation(domainA.publicId, { mode: 'accept_all' }).expect(403);
    await recipients.add(domainA.publicId, ['x']).expect(403);
    // B stays invisible for reads.
    await api.get(connectorB.id).expect(404);
    await recipients.getValidation(domainB.publicId).expect(404);
  });

  it('a domain admin manages connectors of its own organization only', async () => {
    const headers = await headersFor(await fx.createUser(orgA, { roles: ['domain_admin'] }));
    const api = new ConnectorApi(ctx, headers);
    const mine = await api.okCreate({ authType: 'sasl' });
    await api.rotate(mine.id).expect(200);
    await api.remove(mine.id).expect(204);
    await expectEveryRoute(headers, 404);
  });
});

describe('platform users', () => {
  it('see no tenant connector without an override', async () => {
    for (const roles of [['platform_admin'], ['super_admin']]) {
      const headers = await headersFor(await fx.createPlatformUser(roles));
      const api = new ConnectorApi(ctx, headers);
      const ids = await listedConnectors(api);
      for (const id of [connectorA.id, connectorB.id, saslB.id]) expect(ids).not.toContain(id);
      await api.get(connectorB.id).expect(404);
      await new RecipientApi(ctx, headers).getValidation(domainB.publicId).expect(404);
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

  it('super_admin under an override into B manages B’s connectors, audited', async () => {
    const operator = await fx.createPlatformUser(['super_admin']);
    const reason = 'Customer ticket 2201';
    const { overrideId, headers } = await startOverride(operator, reason);
    const api = new ConnectorApi(ctx, headers);
    await expect.poll(() => listedConnectors(api), POLL).toEqual([connectorB.id, saslB.id].sort());
    const created = await api.okCreate({ authType: 'sasl' });
    expect(created.credentials).toBeDefined();
    await api.rotate(saslB.id).expect(200);
    await api.remove(created.id).expect(204);
    await api.get(connectorA.id).expect(404);
    await new RecipientApi(ctx, headers).add(domainB.publicId, ['carol']).expect(200);

    const rows = await ctx.prisma.auditLog.findMany({
      where: { resourceType: 'smtp_connector', actorId: operator.publicId },
    });
    expect(rows.map((r) => r.action).sort()).toEqual(
      ['smtp_connector.created', 'smtp_connector.deleted', 'smtp_connector.secret_rotated'].sort(),
    );
    for (const row of rows) {
      expect(row.organizationId).toBe(orgB.id);
      expect(row.metadata).toMatchObject({ override: { id: overrideId, reason } });
    }
    // The connector was created in B (then deleted), never in the operator's home organization.
    const createdRow = rows.find((r) => r.action === 'smtp_connector.created')!;
    expect(createdRow.resourceId).toBe(created.id);
    expect(
      await ctx.prisma.smtpConnector.findUnique({ where: { publicId: created.id } }),
    ).toBeNull();
  });

  it('platform_admin under an override into B can only read', async () => {
    const operator = await fx.createPlatformUser(['platform_admin']);
    const { headers } = await startOverride(operator, 'Read-only investigation 2202');
    const api = new ConnectorApi(ctx, headers);
    await api.get(connectorB.id).expect(200);
    const before = await snapshotB();
    await api.create({ name: 'pa', authType: 'sasl' }).expect(403);
    await api.update(connectorB.id, { status: 'disabled' }).expect(403);
    await api.rotate(saslB.id).expect(403);
    await api.remove(connectorB.id).expect(403);
    const recipients = new RecipientApi(ctx, headers);
    await recipients.getValidation(domainB.publicId).expect(200);
    await recipients.add(domainB.publicId, ['x']).expect(403);
    expect(await snapshotB()).toEqual(before);
  });
});
