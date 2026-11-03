/**
 * SMTP connectors (step 2.2 D10, §4.1) against real MySQL and Redis: each connector type, the
 * one-time SASL password and its Argon2id hash, global network non-overlap across
 * organizations (also under concurrent requests, which the MySQL named lock serializes),
 * fingerprint uniqueness, disable, rotate, delete, the per-organization limit and the audit
 * rows (never carrying secrets).
 */
import * as argon2 from 'argon2';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa } from './support/http';
import {
  ConnectorApi,
  type ConnectorBody,
  randomFingerprint,
  randomV4Network,
  randomV6Network,
} from './support/smtp';

const MAX_CONNECTORS = 12;
const POLL = { timeout: 10_000, interval: 200 };

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: ConnectorApi;
let adminB: ConnectorApi;
let keyA: ConnectorApi;

const row = (publicId: string) =>
  ctx.prisma.smtpConnector.findUnique({ where: { publicId }, include: { networks: true } });
const audit = (publicId: string, action?: string) =>
  ctx.prisma.auditLog.findMany({
    where: { resourceType: 'smtp_connector', resourceId: publicId, ...(action && { action }) },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
  });

beforeAll(async () => {
  ctx = await createIntegrationApp({
    SMTP_CONNECTORS_MAX_PER_ORGANIZATION: String(MAX_CONNECTORS),
  });
  fx = createFixtures(ctx);
  [orgA, orgB] = [await fx.createOrganization(), await fx.createOrganization()];
  const login = async (org: FixtureOrganization) =>
    bearer(
      (await loginWithMfa(ctx, fx, await fx.createUser(org, { roles: ['organization_admin'] })))
        .accessToken,
    );
  adminA = new ConnectorApi(ctx, await login(orgA));
  adminB = new ConnectorApi(ctx, await login(orgB));
  keyA = new ConnectorApi(
    ctx,
    apiKeyHeader(await fx.createApiKey(orgA, ['connector:read', 'connector:manage'])),
  );
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('sasl connectors', () => {
  let created: ConnectorBody;

  it('returns generated credentials once and stores only an Argon2id hash', async () => {
    created = await adminA.okCreate({ name: 'Exchange Online relay', authType: 'sasl' });
    expect(created.saslUsername).toMatch(/^egc-[a-z2-7]{20}$/);
    expect(created.credentials).toEqual({
      username: created.saslUsername,
      password: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
    });
    expect(created.requireTls).toBe(true);
    expect(created.secretSetAt).not.toBeNull();
    expect(JSON.stringify(created)).not.toMatch(/argon2|secretHash/);

    const stored = await row(created.id);
    expect(stored!.secretHash).toMatch(/^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$/);
    expect(await argon2.verify(stored!.secretHash!, created.credentials!.password)).toBe(true);
    expect(stored!.organizationId).toBe(orgA.id);

    // Never shown again: neither on read nor in the list.
    const fetched = await adminA.get(created.id).expect(200);
    expect(fetched.body).not.toHaveProperty('credentials');
    expect(JSON.stringify(fetched.body)).not.toContain(created.credentials!.password);
    await expect
      .poll(async () => {
        const res = await adminA.list().expect(200);
        return (res.body.data as ConnectorBody[]).map((c) => c.id);
      }, POLL)
      .toContain(created.id);

    // Audited without the password or its hash; the logs never contain it either.
    const [entry] = await audit(created.id, 'smtp_connector.created');
    expect(entry!.organizationId).toBe(orgA.id);
    expect(entry!.metadata).toMatchObject({ authType: 'sasl', saslUsername: created.saslUsername });
    const serialized = JSON.stringify(entry!.metadata);
    expect(serialized).not.toContain(created.credentials!.password);
    expect(serialized).not.toContain('argon2');
    expect(ctx.logs.join('\n')).not.toContain(created.credentials!.password);
  });

  it('rotates the secret: the new password verifies, the old one does not', async () => {
    const before = await row(created.id);
    const res = await adminA.rotate(created.id).expect(200);
    expect(res.body.credentials.username).toBe(created.saslUsername);
    const password = res.body.credentials.password as string;
    expect(password).not.toBe(created.credentials!.password);
    const after = await row(created.id);
    expect(await argon2.verify(after!.secretHash!, password)).toBe(true);
    expect(await argon2.verify(after!.secretHash!, created.credentials!.password)).toBe(false);
    expect(after!.updatedAt.getTime()).toBeGreaterThanOrEqual(before!.updatedAt.getTime());
    const [entry] = await audit(created.id, 'smtp_connector.secret_rotated');
    expect(JSON.stringify(entry!.metadata)).not.toContain(password);
  });

  it('disables the connector and audits the change', async () => {
    const res = await keyA.update(created.id, { status: 'disabled' }).expect(200);
    expect(res.body.status).toBe('disabled');
    expect((await row(created.id))!.status).toBe('disabled');
    const [entry] = await audit(created.id, 'smtp_connector.updated');
    expect(entry!.actorType).toBe('api_key');
    expect(entry!.metadata).toMatchObject({
      changes: { status: { from: 'active', to: 'disabled' } },
    });
  });

  it('refuses networks and requireTls=false for sasl', async () => {
    await adminA.update(created.id, { networks: [randomV4Network()] }).expect(400);
    await adminA.update(created.id, { requireTls: false }).expect(400);
    await adminA.create({ name: 'x', authType: 'sasl', networks: [randomV4Network()] }).expect(400);
  });

  it('deletes it with 204 and audits the deletion', async () => {
    await adminA.remove(created.id).expect(204);
    expect(await row(created.id)).toBeNull();
    await adminA.get(created.id).expect(404);
    expect(await audit(created.id, 'smtp_connector.deleted')).toHaveLength(1);
  });
});

describe('source_ip connectors and global non-overlap', () => {
  it('stores canonical CIDRs with 4/16-byte big-endian ranges', async () => {
    const v4 = randomV4Network();
    const [a, b, c] = v4.split('.');
    const v6 = randomV6Network();
    const created = await adminB.okCreate({
      authType: 'source_ip',
      networks: [`${a}.${b}.${c}.77/24`, v6.toUpperCase()],
      requireTls: false,
    });
    expect(created.networks).toEqual([
      { cidr: v4, ipVersion: 4 },
      { cidr: v6, ipVersion: 6 },
    ]);
    expect(created.requireTls).toBe(false);
    const stored = await row(created.id);
    const net4 = stored!.networks.find((n) => n.ipVersion === 4)!;
    expect(Buffer.from(net4.rangeStart).toString('hex')).toBe(
      Buffer.from([+a!, +b!, +c!, 0]).toString('hex'),
    );
    expect(Buffer.from(net4.rangeEnd).toString('hex')).toBe(
      Buffer.from([+a!, +b!, +c!, 255]).toString('hex'),
    );
    const net6 = stored!.networks.find((n) => n.ipVersion === 6)!;
    expect(Buffer.from(net6.rangeStart)).toHaveLength(16);
    expect(Buffer.from(net6.rangeEnd).subarray(8).toString('hex')).toBe('ff'.repeat(8));
    expect(net4.organizationId).toBe(orgB.id);
  });

  it('refuses a network overlapping another organization’s connector (409, no details)', async () => {
    const owned = randomV4Network(24);
    const theirs = await adminB.okCreate({ authType: 'source_ip', networks: [owned] });
    const host = owned.replace('.0/24', '.42');
    const [a, b] = owned.split('.');
    const covering = `${a}.${b}.0.0/16`;
    for (const network of [owned, host, covering]) {
      const res = await adminA.create({
        name: `o-${network}`,
        authType: 'source_ip',
        networks: [network],
      });
      expect({ network, status: res.status }).toEqual({ network, status: 409 });
      expect(res.body.message).toBe('Network overlaps an existing connector network');
      expect(JSON.stringify(res.body)).not.toContain(orgB.publicId);
      expect(JSON.stringify(res.body)).not.toContain(theirs.id);
    }
    // IPv6 too.
    const v6 = randomV6Network();
    await adminB.okCreate({ authType: 'source_ip', networks: [v6] });
    const inner = v6.replace('::/64', '::1');
    const res6 = await adminA.create({ name: 'v6', authType: 'source_ip', networks: [inner] });
    expect(res6.status).toBe(409);
    // Nothing of A was written.
    expect(
      await ctx.prisma.smtpConnectorNetwork.count({
        where: { organizationId: orgA.id, cidr: { in: [owned, `${host}/32`, `${inner}/128`] } },
      }),
    ).toBe(0);
  });

  it('replaces networks atomically on PATCH and keeps them on overlap', async () => {
    const mine = await adminA.okCreate({ authType: 'source_ip', networks: [randomV4Network()] });
    const blocked = randomV4Network();
    await adminB.okCreate({ authType: 'source_ip', networks: [blocked] });
    const res = await adminA.update(mine.id, { networks: [randomV4Network(), blocked] });
    expect(res.status).toBe(409);
    expect((await adminA.get(mine.id).expect(200)).body.networks).toEqual(mine.networks);

    const next = [randomV4Network(), randomV6Network()];
    const updated = await adminA.update(mine.id, { networks: next, name: 'renamed' }).expect(200);
    expect((updated.body as ConnectorBody).networks.map((n) => n.cidr).sort()).toEqual(
      [...next].sort(),
    );
    // The old network is free again for anyone.
    await adminB.okCreate({ authType: 'source_ip', networks: [mine.networks[0]!.cidr] });
    await adminA.update(mine.id, { networks: [] }).expect(400);
  });

  it('serializes concurrent claims of the same range: exactly one wins', async () => {
    const network = randomV4Network(24);
    const results = await Promise.all([
      adminA.create({ name: 'race-a', authType: 'source_ip', networks: [network] }),
      adminB.create({ name: 'race-b', authType: 'source_ip', networks: [network] }),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual([201, 409]);
    expect(await ctx.prisma.smtpConnectorNetwork.count({ where: { cidr: network } })).toBe(1);
  });

  it('refuses ranges larger than /16 (IPv4) or /48 (IPv6)', async () => {
    const res = await adminA.create({
      name: 'big',
      authType: 'source_ip',
      networks: ['100.64.0.0/10', '2001:db8::/32'],
    });
    expect(res.status).toBe(400);
    expect(res.body.message).toEqual([
      'networks.0: must not be larger than /16 for IPv4 networks',
      'networks.1: must not be larger than /48 for IPv6 networks',
    ]);
  });
});

describe('non-public connector networks (SMTP_CONNECTOR_ALLOW_NON_PUBLIC_NETWORKS=false)', () => {
  it('refuses private, shared, loopback and documentation ranges with 400 and writes nothing', async () => {
    const res = await adminA.create({
      name: 'internal',
      authType: 'source_ip',
      networks: [randomV4Network(), '10.0.0.0/16', '100.64.1.0/24', '127.0.0.1', 'fd00:1::/48'],
    });
    expect(res.status).toBe(400);
    const message =
      'must be a publicly routable network (private, loopback, link-local, shared, documentation, multicast and reserved ranges are refused)';
    expect(res.body.message).toEqual([1, 2, 3, 4].map((i) => `networks.${i}: ${message}`));
    expect(
      await ctx.prisma.smtpConnector.count({
        where: { organizationId: orgA.id, name: 'internal' },
      }),
    ).toBe(0);
    const mine = await adminA.okCreate({ authType: 'source_ip', networks: [randomV4Network()] });
    await adminA.update(mine.id, { networks: ['192.168.10.0/24'] }).expect(400);
  });
});

describe('client_certificate connectors', () => {
  it('stores the fingerprint lower-case without colons; it is globally unique', async () => {
    const fp = randomFingerprint();
    const created = await adminA.okCreate({
      authType: 'client_certificate',
      certificateFingerprintSha256: fp.colon,
    });
    expect(created.certificateFingerprintSha256).toBe(fp.hex);
    expect(created.credentials).toBeUndefined();
    expect((await row(created.id))!.certFingerprintSha256).toBe(fp.hex);

    for (const [api, value] of [
      [adminB, fp.hex],
      [adminA, fp.hex.toUpperCase()],
    ] as const) {
      const res = await api.create({
        name: `dup-${value.slice(0, 6)}`,
        authType: 'client_certificate',
        certificateFingerprintSha256: value,
      });
      expect(res.status).toBe(409);
      expect(res.body.message).toBe('Certificate fingerprint is already registered');
    }
    await adminA.rotate(created.id).expect(409);
  });

  it('accepts optional networks, under the same non-overlap rule', async () => {
    const network = randomV4Network();
    const created = await adminA.okCreate({
      authType: 'client_certificate',
      certificateFingerprintSha256: randomFingerprint().hex,
      networks: [network],
    });
    expect(created.networks).toEqual([{ cidr: network, ipVersion: 4 }]);
    await adminB
      .create({ name: 'over', authType: 'source_ip', networks: [network.replace('/24', '/25')] })
      .expect(409);
    await adminA.update(created.id, { networks: [] }).expect(200);
    await adminB
      .create({ name: 'free', authType: 'source_ip', networks: [network.replace('/24', '/25')] })
      .expect(201);
  });
});

describe('per-organization rules', () => {
  it('names are unique per organization only', async () => {
    const name = `shared-${Date.now()}`;
    await adminA.okCreate({ name, authType: 'sasl' });
    await adminB.okCreate({ name, authType: 'sasl' });
    const res = await adminA.create({ name, authType: 'sasl' }).expect(409);
    expect(res.body.message).toBe('SMTP connector name already exists');
  });

  it(`enforces SMTP_CONNECTORS_MAX_PER_ORGANIZATION (${MAX_CONNECTORS} in this suite)`, async () => {
    const orgC = await fx.createOrganization();
    const user = await fx.createUser(orgC, { roles: ['domain_admin'] });
    const api = new ConnectorApi(ctx, bearer((await loginWithMfa(ctx, fx, user)).accessToken));
    for (let i = 0; i < MAX_CONNECTORS; i++) await api.okCreate({ authType: 'sasl' });
    const res = await api.create({ name: 'one-too-many', authType: 'sasl' }).expect(409);
    expect(res.body.message).toBe(
      `SMTP connector limit reached: at most ${MAX_CONNECTORS} per organization`,
    );
    expect(await ctx.prisma.smtpConnector.count({ where: { organizationId: orgC.id } })).toBe(
      MAX_CONNECTORS,
    );
  });
});
