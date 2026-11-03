/**
 * DKIM signing publisher (step 2.2 D12, ADR-0020) against real MySQL and the real redis-dkim
 * (ACL users from the local `.env`): the active RSA key of an active, outbound-enabled domain
 * of an active organization appears in `dkim_selectors` / `dkim_keys`; it disappears when the
 * domain is suspended, its outbound mail is disabled or its organization is suspended; the
 * selector switches on rotation and the old key is pruned; a key that cannot be decrypted is
 * skipped without logging key material; and the `dkim-probe` user (smtp-adapter) can check
 * selectors but never read keys. Every fixture is removed and a final reconciliation removes
 * this suite's entries from redis-dkim.
 */
import { Redis } from 'ioredis';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DkimSigningPublisher } from '../src/modules/domains/services/dkim-signing-publisher.service';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { bearer, loginWithMfa } from './support/http';
import { insertDkimKey, insertDomain, type InsertedDomain } from './support/smtp';

const SELECTORS = 'dkim_selectors';
const KEYS = 'dkim_keys';

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let publisher: DkimSigningPublisher;
let writer: Redis;
let probe: Redis;
let admin: Record<string, string>;
const created: InsertedDomain[] = [];

function requireEnv(key: string): string {
  const value = process.env[key];
  if (!value) throw new Error(`${key} must be set (redis-dkim, step 2.2) for this suite`);
  return value;
}

async function domain(
  options: Parameters<typeof insertDomain>[2] = {},
  owner: FixtureOrganization = org,
): Promise<InsertedDomain> {
  const d = await insertDomain(ctx, owner, { label: 'dkim', ...options });
  created.push(d);
  return d;
}

const selectorOf = (d: InsertedDomain) => writer.hget(SELECTORS, d.name);
const keyOf = (d: InsertedDomain, selector: string) => writer.hget(KEYS, `${selector}.${d.name}`);

beforeAll(async () => {
  writer = new Redis(requireEnv('REDIS_DKIM_URL'), { lazyConnect: true, enableReadyCheck: false });
  probe = new Redis(requireEnv('REDIS_DKIM_PROBE_URL'), {
    lazyConnect: true,
    enableReadyCheck: false,
  });
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  publisher = ctx.get(DkimSigningPublisher);
  const user = await fx.createUser(org, { roles: ['domain_admin'] });
  admin = bearer((await loginWithMfa(ctx, fx, user)).accessToken);
});

afterAll(async () => {
  await fx?.cleanup();
  // The fixtures are gone: one more reconciliation removes their entries from redis-dkim.
  if (publisher) await publisher.reconcile();
  if (writer && created.length > 0) {
    // dkim-writer has no HMGET (ACL of D12): one HEXISTS per domain.
    for (const d of created) expect(await writer.hexists(SELECTORS, d.name)).toBe(0);
  }
  writer?.disconnect();
  probe?.disconnect();
  await ctx?.close();
});

describe('DkimSigningPublisher against redis-dkim', () => {
  it('publishes the active RSA key of active, outbound-enabled domains only', async () => {
    const signable = await domain();
    const key = await insertDkimKey(ctx, org, signable);
    await insertDkimKey(ctx, org, signable, { status: 'pending' });
    const inboundOnly = await domain({ outboundEnabled: false });
    await insertDkimKey(ctx, org, inboundOnly);
    const pending = await domain({ status: 'verified' });
    await insertDkimKey(ctx, org, pending);
    const suspendedOrg = await fx.createOrganization({ status: 'suspended' });
    const otherTenant = await domain({}, suspendedOrg);
    await insertDkimKey(ctx, suspendedOrg, otherTenant);

    const counts = await publisher.reconcile();
    expect(counts.published).toBeGreaterThanOrEqual(1);
    expect(await selectorOf(signable)).toBe(key.selector);
    expect(await keyOf(signable, key.selector)).toBe(key.pem);
    for (const d of [inboundOnly, pending, otherTenant]) expect(await selectorOf(d)).toBeNull();

    // A second run changes nothing for it.
    const again = await publisher.reconcile();
    expect(again.unchanged).toBeGreaterThanOrEqual(1);
    expect(await keyOf(signable, key.selector)).toBe(key.pem);

    // Never a PEM in the logs.
    expect(ctx.logs.join('\n')).not.toContain('PRIVATE KEY');
  });

  it('lets the probe user check selectors but never read keys', async () => {
    const d = await domain();
    const key = await insertDkimKey(ctx, org, d);
    await publisher.reconcile();
    expect(await probe.hexists(SELECTORS, d.name)).toBe(1);
    expect(await probe.hget(SELECTORS, d.name)).toBe(key.selector);
    await expect(probe.hget(KEYS, `${key.selector}.${d.name}`)).rejects.toThrow(/NOPERM/);
    await expect(probe.hgetall(SELECTORS)).rejects.toThrow(/NOPERM/);
    await expect(probe.hset(SELECTORS, d.name, 'forged')).rejects.toThrow(/NOPERM/);
  });

  it('switches the selector on rotation and prunes the old key', async () => {
    const d = await domain();
    const old = await insertDkimKey(ctx, org, d);
    await publisher.reconcile();
    expect(await selectorOf(d)).toBe(old.selector);

    // Rotation completed (D9): the old key is rotating, the new one active.
    await ctx.prisma.domainDkimKey.update({
      where: { id: old.id },
      data: { status: 'rotating', retireAfter: new Date(Date.now() + 86_400_000) },
    });
    const next = await insertDkimKey(ctx, org, d);
    await publisher.reconcile();
    expect(await selectorOf(d)).toBe(next.selector);
    expect(await keyOf(d, next.selector)).toBe(next.pem);
    expect(await keyOf(d, old.selector)).toBeNull();
  });

  it('removes keys on suspension and outbound disable, and restores them on resume', async () => {
    const d = await domain();
    const key = await insertDkimKey(ctx, org, d);
    await publisher.reconcile();
    expect(await selectorOf(d)).toBe(key.selector);

    await ctx.http
      .patch(`/api/v1/domains/${d.publicId}/status`)
      .set(admin)
      .send({ status: 'suspended', reason: 'Integration test' })
      .expect(200);
    expect((await publisher.reconcile()).removed).toBeGreaterThanOrEqual(1);
    expect(await selectorOf(d)).toBeNull();
    expect(await keyOf(d, key.selector)).toBeNull();

    await ctx.http
      .patch(`/api/v1/domains/${d.publicId}/status`)
      .set(admin)
      .send({ status: 'active' })
      .expect(200);
    await publisher.reconcile();
    expect(await keyOf(d, key.selector)).toBe(key.pem);

    await ctx.prisma.domain.update({ where: { id: d.id }, data: { outboundEnabled: false } });
    await publisher.reconcile();
    expect(await selectorOf(d)).toBeNull();
  });

  it('removes the keys of an organization that is suspended', async () => {
    const tenant = await fx.createOrganization();
    const d = await domain({}, tenant);
    await insertDkimKey(ctx, tenant, d);
    await publisher.reconcile();
    expect(await selectorOf(d)).not.toBeNull();
    await ctx.prisma.organization.update({
      where: { id: tenant.id },
      data: { status: 'suspended' },
    });
    await publisher.reconcile();
    expect(await selectorOf(d)).toBeNull();
  });

  it('skips a key that cannot be decrypted and logs only the domain public id', async () => {
    const d = await domain();
    const key = await insertDkimKey(ctx, org, d);
    await publisher.reconcile();
    // Bound to another row (AAD mismatch): tampering or a wrong DATA_ENCRYPTION_KEY.
    const { privateKeyCiphertext } = await ctx.prisma.domainDkimKey.findFirstOrThrow({
      where: { domainId: { not: d.id }, privateKeyCiphertext: { not: null } },
      select: { privateKeyCiphertext: true },
    });
    await ctx.prisma.domainDkimKey.update({
      where: { id: key.id },
      data: { privateKeyCiphertext },
    });
    const before = ctx.logs.length;
    const counts = await publisher.reconcile();
    expect(counts.skipped).toBeGreaterThanOrEqual(1);
    // Left as it was published (never removed because of a decryption problem).
    expect(await keyOf(d, key.selector)).toBe(key.pem);
    const logged = ctx.logs.slice(before).join('\n');
    expect(logged).toContain(d.publicId);
    expect(logged).not.toContain(d.name);
    expect(logged).not.toContain('PRIVATE KEY');
    // Revoking the broken key removes the domain.
    await ctx.prisma.domainDkimKey.update({
      where: { id: key.id },
      data: { status: 'revoked', privateKeyCiphertext: null },
    });
    await publisher.reconcile();
    expect(await selectorOf(d)).toBeNull();
  });

  it('runs one scheduled reconciliation per tick across replicas', async () => {
    await ctx.kv.del('jobs:dkim-signing-sync');
    expect(await publisher.runOnce()).not.toBeNull();
    expect(await publisher.runOnce()).toBeNull();
    await ctx.kv.del('jobs:dkim-signing-sync');
  });
});
