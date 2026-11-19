import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Harness, signal } from './support/harness';

/**
 * Provider domain checks of newly linked domains (§10.3, D4, I10; tasks role): a domain linked
 * after the tenant was bound (`PUT …/domains` leaves `provider_verification = 'unknown'`) is
 * checked at the provider and the connection is promoted by I10; a pass handles at most `limit`
 * connections and leaves the links of the others eligible for the next pass.
 */
const h = new Harness();
let org: bigint;

beforeAll(async () => {
  await h.start();
  org = await h.organization('domain-checks');
});

afterAll(async () => {
  await h.cleanup();
});

/** A bound (`configuring`) Microsoft 365 connection with an active grant and one new link. */
async function boundConnectionWithNewLink(label: string, isVerified = true) {
  const domainName = h.name(label);
  const tenant = h.m365Tenant({ domains: [{ name: domainName, isVerified }] });
  const domain = await h.domain(org, domainName);
  const connection = await h.connection(org, 'microsoft_365', {
    status: 'configuring',
    externalTenantId: tenant.tenantId,
    externalTenantName: 'Tenant',
    tenantVerifiedAt: h.clock.now(),
    activeTenantKey: `microsoft_365:${tenant.tenantId}`,
  });
  await h.grant(connection, {
    authMethod: 'customer_app_secret',
    status: 'active',
    clientId: tenant.clientId,
    claimedTenantId: tenant.tenantId,
    credential: { method: 'customer_app_secret', clientSecret: tenant.secret },
  });
  const link = await h.link(connection, domain.id);
  return { connection, link, domainName };
}

describe('provider domain checks (tasks role)', () => {
  it('checks a newly linked domain at the provider and promotes the connection (I10)', async () => {
    const { connection, link, domainName } = await boundConnectionWithNewLink('late-link');
    const { components } = h.worker();
    expect(await components.domainChecks.runOnce(10, signal())).toBeGreaterThanOrEqual(1);

    const after = await h.prisma.providerConnectionDomain.findUniqueOrThrow({
      where: { id: link.id },
    });
    expect(after.providerVerification).toBe('verified');
    expect(after.providerMxHost).toBe(
      `${domainName.replace(/\./g, '-')}.mail.protection.outlook.com`,
    );
    expect(after.providerCheckedAt).not.toBeNull();
    const conn = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    expect(conn.status).toBe('active');
    expect(conn.rowVersion).toBeGreaterThan(connection.rowVersion);
    const audit = await h.prisma.auditLog.findMany({
      where: { organizationId: org, resourceId: connection.publicId },
    });
    expect(audit.map((a) => a.action)).toContain('integration.connection_bound');

    // Checked links are not picked again.
    const again = await h.worker().components.domainChecks.runOnce(10, signal());
    const recheck = await h.prisma.providerConnectionDomain.findUniqueOrThrow({
      where: { id: link.id },
    });
    expect(recheck.providerCheckedAt?.getTime()).toBe(after.providerCheckedAt?.getTime());
    expect(again).toBe(0);
  });

  it('an unverified domain keeps the connection configuring', async () => {
    const { connection, link } = await boundConnectionWithNewLink('late-unverified', false);
    await h.worker().components.domainChecks.runOnce(10, signal());
    const after = await h.prisma.providerConnectionDomain.findUniqueOrThrow({
      where: { id: link.id },
    });
    expect(after.providerVerification).toBe('unverified');
    const conn = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    expect(conn.status).toBe('configuring');
  });

  it('a pass handles at most `limit` connections; the other links stay eligible', async () => {
    const first = await boundConnectionWithNewLink('limit-a');
    const second = await boundConnectionWithNewLink('limit-b');
    const { components } = h.worker();

    expect(await components.domainChecks.runOnce(1, signal())).toBe(1);
    const links = await h.prisma.providerConnectionDomain.findMany({
      where: { id: { in: [first.link.id, second.link.id] } },
    });
    const checked = links.filter((l) => l.providerVerification === 'verified');
    const waiting = links.filter((l) => l.providerVerification === 'unknown');
    expect(checked).toHaveLength(1);
    expect(waiting).toHaveLength(1);
    // Not stamped: the next pass picks it at once instead of after the retry delay.
    expect(waiting[0]!.providerCheckedAt).toBeNull();

    expect(await components.domainChecks.runOnce(1, signal())).toBe(1);
    const rest = await h.prisma.providerConnectionDomain.findUniqueOrThrow({
      where: { id: waiting[0]!.id },
    });
    expect(rest.providerVerification).toBe('verified');
  });
});
