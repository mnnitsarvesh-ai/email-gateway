import {
  GOOGLE_MAIL_FLOW_PROFILE,
  M365_ATO_RESPONSE_PROFILE,
  M365_ATO_TELEMETRY_PROFILE,
  M365_MAIL_FLOW_PROFILE,
  testing,
} from '@email-gateway/provider-integrations';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Harness, signal } from './support/harness';

/**
 * Grant verification (§10.3, D3.4, D4, I10) for each auth method against the in-process fake and
 * the MySQL writer: success with tenant binding and I10, consent missing, wrong tenant, tenant
 * bound elsewhere, missing and excess permissions, provider unavailability, SKIP LOCKED claims.
 */
const h = new Harness();
let org: bigint;
let otherOrg: bigint;

beforeAll(async () => {
  await h.start();
  org = await h.organization('grants');
  otherOrg = await h.organization('grants-other');
});

afterAll(async () => {
  await h.cleanup();
});

async function auditActions(
  connectionPublicId: string,
  forbidden: readonly string[] = [],
): Promise<string[]> {
  const rows = await h.prisma.auditLog.findMany({
    where: { organizationId: { in: h.organizationIds }, resourceId: connectionPublicId },
    orderBy: { id: 'asc' },
  });
  for (const row of rows) {
    // D12: never a secret, token or credential in audit details.
    const text = JSON.stringify(row.metadata);
    expect(text).not.toMatch(/private_key|access_token|clientSecret|-----BEGIN/);
    for (const value of forbidden) expect(text).not.toContain(value);
    expect(row.actorType).toBe('system');
  }
  return rows.map((r) => r.action);
}

describe('grant verification', () => {
  it('customer_app_secret: binds the tenant, checks linked domains and activates the connection (I10)', async () => {
    const domainName = h.name('m365-a');
    const tenant = h.m365Tenant({ domains: [{ name: domainName }] });
    const domain = await h.domain(org, domainName);
    const connection = await h.connection(org, 'microsoft_365');
    await h.link(connection, domain.id);
    const grant = await h.grant(connection, {
      authMethod: 'customer_app_secret',
      clientId: tenant.clientId,
      claimedTenantId: tenant.tenantId,
      credential: { method: 'customer_app_secret', clientSecret: tenant.secret },
    });
    const { components, metrics } = h.worker();
    expect(await components.verifier.runOnce(10, signal())).toBeGreaterThanOrEqual(1);

    const after = await h.prisma.providerConnectionGrant.findUniqueOrThrow({
      where: { id: grant.id },
    });
    expect(after).toMatchObject({
      status: 'active',
      lastErrorCode: null,
      verifyClaimedUntil: null,
    });
    expect(after.observedPermissions).toEqual([...M365_MAIL_FLOW_PROFILE.permissions].sort());
    expect(after.verifiedAt).not.toBeNull();
    const conn = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    expect(conn).toMatchObject({
      status: 'active',
      externalTenantId: tenant.tenantId,
      activeTenantKey: `microsoft_365:${tenant.tenantId}`,
    });
    expect(conn.tenantVerifiedAt).not.toBeNull();
    expect(conn.nextHealthCheckAt).not.toBeNull();
    const link = await h.prisma.providerConnectionDomain.findFirstOrThrow({
      where: { connectionId: connection.id },
    });
    expect(link.providerVerification).toBe('verified');
    expect(link.providerMxHost).toBe(
      `${domainName.replace(/\./g, '-')}.mail.protection.outlook.com`,
    );
    expect(await auditActions(connection.publicId, [tenant.secret])).toEqual([
      'integration.grant_verified',
      'integration.tenant_bound',
      'integration.connection_bound',
    ]);
    const verifications = await metrics.grantVerifications.get();
    expect(verifications.values.some((v) => v.labels.result === 'active' && v.value >= 1)).toBe(
      true,
    );
  });

  it('stays configuring while no linked domain is verified at the provider (I10)', async () => {
    const domainName = h.name('m365-unverified');
    const tenant = h.m365Tenant({ domains: [{ name: domainName, isVerified: false }] });
    const domain = await h.domain(org, domainName);
    const connection = await h.connection(org, 'microsoft_365');
    await h.link(connection, domain.id);
    await h.grant(connection, {
      authMethod: 'customer_app_secret',
      clientId: tenant.clientId,
      claimedTenantId: tenant.tenantId,
      credential: { method: 'customer_app_secret', clientSecret: tenant.secret },
    });
    await h.worker().components.verifier.runOnce(10, signal());
    const conn = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    // No linked domain proves control of the tenant: it stays a claim (D4).
    expect(conn).toMatchObject({
      status: 'configuring',
      externalTenantId: null,
      externalTenantName: null,
      activeTenantKey: null,
    });
    const link = await h.prisma.providerConnectionDomain.findFirstOrThrow({
      where: { connectionId: connection.id },
    });
    expect(link.providerVerification).toBe('unverified');
  });

  it('consent missing: the grant errs with consent_missing and an audit row', async () => {
    const tenant = h.m365Tenant({ domains: [{ name: h.name('m365-noconsent') }] });
    h.fake.revokeConsent(tenant.tenantId, tenant.clientId);
    const connection = await h.connection(org, 'microsoft_365');
    const grant = await h.grant(connection, {
      authMethod: 'customer_app_secret',
      clientId: tenant.clientId,
      claimedTenantId: tenant.tenantId,
      credential: { method: 'customer_app_secret', clientSecret: tenant.secret },
    });
    await h.worker().components.verifier.runOnce(10, signal());
    const after = await h.prisma.providerConnectionGrant.findUniqueOrThrow({
      where: { id: grant.id },
    });
    expect(after).toMatchObject({ status: 'error', lastErrorCode: 'consent_missing' });
    const conn = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    expect(conn.externalTenantId).toBeNull();
    expect(await auditActions(connection.publicId)).toEqual([
      'integration.grant_verification_failed',
    ]);
  });

  it('wrong tenant: a tenant other than the one bound earlier is refused (tenant_mismatch)', async () => {
    const tenant = h.m365Tenant({ domains: [{ name: h.name('m365-wrong') }] });
    const connection = await h.connection(org, 'microsoft_365', {
      externalTenantId: testing.testGuid(),
    });
    const grant = await h.grant(connection, {
      authMethod: 'customer_app_secret',
      clientId: tenant.clientId,
      claimedTenantId: tenant.tenantId,
      credential: { method: 'customer_app_secret', clientSecret: tenant.secret },
    });
    await h.worker().components.verifier.runOnce(10, signal());
    const after = await h.prisma.providerConnectionGrant.findUniqueOrThrow({
      where: { id: grant.id },
    });
    expect(after).toMatchObject({ status: 'error', lastErrorCode: 'tenant_mismatch' });
  });

  it('tenant bound elsewhere: one provider tenant binds to at most one connection (I10)', async () => {
    const domainName = h.name('m365-dup');
    const tenant = h.m365Tenant({ domains: [{ name: domainName }] });
    await h.connection(otherOrg, 'microsoft_365', {
      status: 'active',
      externalTenantId: tenant.tenantId,
      activeTenantKey: `microsoft_365:${tenant.tenantId}`,
    });
    const connection = await h.connection(org, 'microsoft_365');
    await h.link(connection, (await h.domain(org, domainName)).id);
    const grant = await h.grant(connection, {
      authMethod: 'customer_app_secret',
      clientId: tenant.clientId,
      claimedTenantId: tenant.tenantId,
      credential: { method: 'customer_app_secret', clientSecret: tenant.secret },
    });
    await h.worker().components.verifier.runOnce(10, signal());
    const after = await h.prisma.providerConnectionGrant.findUniqueOrThrow({
      where: { id: grant.id },
    });
    expect(after).toMatchObject({ status: 'error', lastErrorCode: 'tenant_bound_elsewhere' });
    const conn = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    expect(conn).toMatchObject({
      externalTenantId: null,
      externalTenantName: null,
      activeTenantKey: null,
      status: 'configuring',
    });
  });

  it('missing permissions err; excess permissions are recorded on an active grant', async () => {
    const missing = h.m365Tenant({
      domains: [{ name: h.name('m365-miss') }],
      roles: ['Organization.Read.All'],
    });
    const excess = h.m365Tenant({
      domains: [{ name: h.name('m365-excess') }],
      roles: [...M365_MAIL_FLOW_PROFILE.permissions, 'User.Read.All'],
    });
    const c1 = await h.connection(org, 'microsoft_365');
    const g1 = await h.grant(c1, {
      authMethod: 'customer_app_secret',
      clientId: missing.clientId,
      claimedTenantId: missing.tenantId,
      credential: { method: 'customer_app_secret', clientSecret: missing.secret },
    });
    const c2 = await h.connection(org, 'microsoft_365');
    const g2 = await h.grant(c2, {
      authMethod: 'customer_app_secret',
      clientId: excess.clientId,
      claimedTenantId: excess.tenantId,
      credential: { method: 'customer_app_secret', clientSecret: excess.secret },
    });
    await h.worker().components.verifier.runOnce(10, signal());
    const a1 = await h.prisma.providerConnectionGrant.findUniqueOrThrow({ where: { id: g1.id } });
    expect(a1).toMatchObject({ status: 'error', lastErrorCode: 'permissions_missing' });
    expect(a1.missingPermissions).toEqual(['Domain.Read.All']);
    const a2 = await h.prisma.providerConnectionGrant.findUniqueOrThrow({ where: { id: g2.id } });
    expect(a2.status).toBe('active');
    expect(a2.excessPermissions).toEqual(['User.Read.All']);
  });

  it('platform_app: admin consent + the platform app credentials (worker-held)', async () => {
    const tenantId = testing.testGuid();
    const clientId = testing.testGuid();
    const secret = testing.testClientSecret();
    h.fake.addMicrosoftTenant({ tenantId, displayName: 'Consenting tenant', domains: [] });
    h.fake.addMicrosoftApp({ clientId, secret });
    h.fake.consent(tenantId, clientId, [...M365_MAIL_FLOW_PROFILE.permissions]);
    const connection = await h.connection(org, 'microsoft_365');
    const grant = await h.grant(connection, {
      authMethod: 'platform_app',
      claimedTenantId: tenantId,
    });
    const { components } = h.worker({
      platform: {
        microsoft: new Map([[M365_MAIL_FLOW_PROFILE.key, { clientId, secret }]]),
        google: new Map(),
      },
    });
    await components.verifier.runOnce(10, signal());
    const after = await h.prisma.providerConnectionGrant.findUniqueOrThrow({
      where: { id: grant.id },
    });
    expect(after.status).toBe('active');
    const conn = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    // Consent alone binds nothing: no linked domain proves control of the tenant yet (D4).
    expect(conn).toMatchObject({
      status: 'configuring',
      externalTenantId: null,
      externalTenantName: null,
      activeTenantKey: null,
    });
  });

  it('platform_app: another organization claiming a consented tenant never binds it (D4)', async () => {
    // Organization A's tenant consented to the shared platform app (as for its own connection).
    const victimDomain = h.name('victim');
    const tenantId = testing.testGuid();
    const clientId = testing.testGuid();
    const secret = testing.testClientSecret();
    h.fake.addMicrosoftTenant({
      tenantId,
      displayName: 'Victim tenant',
      domains: [{ name: victimDomain, isVerified: true }],
    });
    h.fake.addMicrosoftApp({ clientId, secret });
    h.fake.consent(tenantId, clientId, [...M365_MAIL_FLOW_PROFILE.permissions]);
    const platform = {
      microsoft: new Map([[M365_MAIL_FLOW_PROFILE.key, { clientId, secret }]]),
      google: new Map(),
    };
    // Organization B claims that tenant (a forged consent/complete) with its own verified domain.
    const attacker = await h.connection(otherOrg, 'microsoft_365');
    const attackerLink = await h.link(attacker, (await h.domain(otherOrg, h.name('attacker'))).id);
    const attackerGrant = await h.grant(attacker, {
      authMethod: 'platform_app',
      claimedTenantId: tenantId,
    });
    await h.worker({ platform }).components.verifier.runOnce(10, signal());
    const claimed = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: attacker.id },
    });
    expect(claimed).toMatchObject({
      status: 'configuring',
      externalTenantId: null,
      externalTenantName: null,
      tenantVerifiedAt: null,
      activeTenantKey: null,
    });
    expect(
      (
        await h.prisma.providerConnectionDomain.findUniqueOrThrow({
          where: { id: attackerLink.id },
        })
      ).providerVerification,
    ).toBe('absent');
    expect(await auditActions(attacker.publicId, ['Victim tenant'])).toEqual([
      'integration.grant_verified',
    ]);
    // Re-running the tasks never binds it either.
    const later = h.worker({ platform }).components;
    await later.domainChecks.runOnce(10, signal());
    await later.binder.settle(attacker.id, signal(), 'it-forged-claim');
    expect(
      (await h.prisma.providerConnection.findUniqueOrThrow({ where: { id: attacker.id } }))
        .activeTenantKey,
    ).toBeNull();

    // Organization A, which controls a domain of the tenant, binds it afterwards.
    const owner = await h.connection(org, 'microsoft_365');
    await h.link(owner, (await h.domain(org, victimDomain)).id);
    await h.grant(owner, { authMethod: 'platform_app', claimedTenantId: tenantId });
    await h.worker({ platform }).components.verifier.runOnce(10, signal());
    expect(
      await h.prisma.providerConnection.findUniqueOrThrow({ where: { id: owner.id } }),
    ).toMatchObject({
      status: 'active',
      externalTenantId: tenantId,
      externalTenantName: 'Victim tenant',
      activeTenantKey: `microsoft_365:${tenantId}`,
    });
    // B's grant stays usable for nothing: its connection is still unbound.
    expect(
      (
        await h.prisma.providerConnectionGrant.findUniqueOrThrow({
          where: { id: attackerGrant.id },
        })
      ).status,
    ).toBe('active');
  });

  it('a provider result of an earlier claim is never taken as proof (re-checked after verification)', async () => {
    const domainName = h.name('stale');
    const tenant = h.m365Tenant({ domains: [] });
    const connection = await h.connection(org, 'microsoft_365');
    const link = await h.link(connection, (await h.domain(org, domainName)).id);
    // Left over from an earlier claim: "verified" before the current grant was verified.
    await h.prisma.providerConnectionDomain.update({
      where: { id: link.id },
      data: { providerVerification: 'verified', providerCheckedAt: h.clock.now() },
    });
    await h.grant(connection, {
      authMethod: 'customer_app_secret',
      clientId: tenant.clientId,
      claimedTenantId: tenant.tenantId,
      credential: { method: 'customer_app_secret', clientSecret: tenant.secret },
    });
    await h.worker().components.verifier.runOnce(10, signal());
    const conn = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    expect(conn).toMatchObject({ status: 'configuring', activeTenantKey: null });
    expect(
      (await h.prisma.providerConnectionDomain.findUniqueOrThrow({ where: { id: link.id } }))
        .providerVerification,
    ).toBe('absent');
  });

  it('customer_service_account (Google): JWT bearer with the delegated admin', async () => {
    const domainName = h.name('google-a');
    const admin = `admin@${domainName}`;
    const customerId = `C0${h.suffix.replace(/[^0-9a-z]/g, '').slice(0, 6)}x`;
    const sa = testing.testServiceAccountKey(
      `reader@${h.name('sa')}`,
      h.fake.endpoints().googleTokenUrl,
    );
    h.fake.addGoogleCustomer({
      customerId,
      primaryDomain: domainName,
      organizationName: 'Google Org',
      domains: [{ domainName, verified: true, isPrimary: true }],
      admins: [admin],
    });
    h.fake.addGoogleServiceAccount(sa.account);
    h.fake.delegate(customerId, sa.account.clientId, [...GOOGLE_MAIL_FLOW_PROFILE.permissions]);
    const domain = await h.domain(org, domainName);
    const connection = await h.connection(org, 'google_workspace');
    await h.link(connection, domain.id);
    const grant = await h.grant(connection, {
      authMethod: 'customer_service_account',
      subjectEmail: admin,
      credential: { method: 'customer_service_account', key: sa.document },
    });
    await h.worker().components.verifier.runOnce(10, signal());
    const after = await h.prisma.providerConnectionGrant.findUniqueOrThrow({
      where: { id: grant.id },
    });
    expect(after.status).toBe('active');
    const conn = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    expect(conn).toMatchObject({
      status: 'active',
      externalTenantId: customerId,
      activeTenantKey: `google_workspace:${customerId}`,
    });
  });

  it('provider unavailable: the grant stays verifying with back-off, then verifies', async () => {
    const tenant = h.m365Tenant({ domains: [{ name: h.name('m365-503') }] });
    const connection = await h.connection(org, 'microsoft_365');
    const grant = await h.grant(connection, {
      authMethod: 'customer_app_secret',
      clientId: tenant.clientId,
      claimedTenantId: tenant.tenantId,
      credential: { method: 'customer_app_secret', clientSecret: tenant.secret },
    });
    h.fake.failNext({ endpoint: 'm365.token', status: 503, times: 1 });
    const { components } = h.worker();
    await components.verifier.runOnce(10, signal());
    let after = await h.prisma.providerConnectionGrant.findUniqueOrThrow({
      where: { id: grant.id },
    });
    expect(after).toMatchObject({
      status: 'verifying',
      consecutiveFailures: 1,
      lastErrorCode: 'provider_unavailable',
    });
    expect(after.verifyClaimedUntil!.getTime()).toBeGreaterThan(h.clock.now().getTime());
    // Not claimed again before the back-off ends.
    expect((await components.verifier.claim(10)).map((c) => c.id)).not.toContain(grant.id);
    h.clock.advance(31 * 60_000);
    await components.verifier.runOnce(10, signal());
    after = await h.prisma.providerConnectionGrant.findUniqueOrThrow({ where: { id: grant.id } });
    expect(after).toMatchObject({ status: 'active', consecutiveFailures: 0 });
    h.clock.set(new Date());
  });

  it('claims are disjoint between workers (FOR UPDATE SKIP LOCKED) and leased', async () => {
    const tenant = h.m365Tenant({ domains: [] });
    const grants: { id: bigint }[] = [];
    for (let i = 0; i < 4; i += 1) {
      const c = await h.connection(org, 'microsoft_365');
      grants.push(
        await h.grant(c, {
          authMethod: 'customer_app_secret',
          clientId: tenant.clientId,
          claimedTenantId: tenant.tenantId,
          credential: { method: 'customer_app_secret', clientSecret: tenant.secret },
        }),
      );
    }
    const a = h.worker().components;
    const b = h.worker().components;
    const [ca, cb] = await Promise.all([a.verifier.claim(2), b.verifier.claim(2)]);
    const ids = [...ca, ...cb].map((g) => g.id.toString());
    expect(new Set(ids).size).toBe(ids.length);
    // Leased: nothing left to claim now, everything again after the lease.
    const remaining = await a.verifier.claim(10);
    expect(remaining.filter((r) => grants.some((g) => g.id === r.id))).toHaveLength(4 - ids.length);
    h.clock.advance(3 * 60_000);
    const reclaimed = await a.verifier.claim(10);
    expect(reclaimed.filter((r) => grants.some((g) => g.id === r.id)).length).toBe(4);
    h.clock.set(new Date());
    // Clean these up: they would bind one tenant four times.
    await h.prisma.providerConnectionGrant.updateMany({
      where: { id: { in: grants.map((g) => g.id) } },
      data: { status: 'error', verifyClaimedUntil: null },
    });
  });
  it('step 8.5 ATO grants on a bound connection: no tenant read, ActivityFeed.Read not compared, connection unchanged', async () => {
    const domainName = h.name('m365-ato');
    const telemetryGraph = M365_ATO_TELEMETRY_PROFILE.permissions.filter(
      (p) => p !== 'ActivityFeed.Read',
    );
    const tenant = h.m365Tenant({ domains: [{ name: domainName }] });
    const domain = await h.domain(org, domainName);
    const connection = await h.connection(org, 'microsoft_365');
    await h.link(connection, domain.id);
    const credential = { method: 'customer_app_secret' as const, clientSecret: tenant.secret };
    await h.grant(connection, {
      authMethod: 'customer_app_secret',
      clientId: tenant.clientId,
      claimedTenantId: tenant.tenantId,
      credential,
    });
    const { components } = h.worker();
    await components.verifier.runOnce(10, signal());
    const bound = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    expect(bound.status).toBe('active');
    // The customer app now also holds the ATO Graph roles (telemetry and response).
    h.fake.consent(tenant.tenantId, tenant.clientId, [
      ...M365_MAIL_FLOW_PROFILE.permissions,
      ...telemetryGraph,
      ...M365_ATO_RESPONSE_PROFILE.permissions,
    ]);
    const options = {
      authMethod: 'customer_app_secret' as const,
      clientId: tenant.clientId,
      claimedTenantId: tenant.tenantId,
      credential,
    };
    const telemetry = await h.grant(connection, {
      ...options,
      profile: M365_ATO_TELEMETRY_PROFILE,
    });
    const response = await h.grant(connection, { ...options, profile: M365_ATO_RESPONSE_PROFILE });
    await components.verifier.runOnce(10, signal());
    const t = await h.prisma.providerConnectionGrant.findUniqueOrThrow({
      where: { id: telemetry.id },
    });
    const r = await h.prisma.providerConnectionGrant.findUniqueOrThrow({
      where: { id: response.id },
    });
    expect(t).toMatchObject({ status: 'active', lastErrorCode: null, missingPermissions: null });
    // The response profile has no directory read: 8.2's tenant read would have refused it.
    expect(r).toMatchObject({ status: 'active', lastErrorCode: null, missingPermissions: null });
    const after = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    expect(after).toMatchObject({
      status: 'active',
      externalTenantId: bound.externalTenantId,
      activeTenantKey: bound.activeTenantKey,
      rowVersion: bound.rowVersion,
    });

    // A missing Graph role still errs; a grant on an unbound connection errs tenant_not_bound.
    h.fake.consent(tenant.tenantId, tenant.clientId, [...M365_MAIL_FLOW_PROFILE.permissions]);
    // Re-verification (new consent) of the telemetry grant.
    await h.prisma.providerConnectionGrant.update({
      where: { id: telemetry.id },
      data: { status: 'verifying', verifyClaimedUntil: null, verifyRequestedAt: new Date() },
    });
    const unbound = await h.connection(org, 'microsoft_365');
    const early = await h.grant(unbound, { ...options, profile: M365_ATO_TELEMETRY_PROFILE });
    await components.verifier.runOnce(10, signal());
    const m = await h.prisma.providerConnectionGrant.findUniqueOrThrow({
      where: { id: telemetry.id },
    });
    expect(m).toMatchObject({ status: 'error', lastErrorCode: 'permissions_missing' });
    expect(m.missingPermissions).not.toContain('ActivityFeed.Read');
    const e = await h.prisma.providerConnectionGrant.findUniqueOrThrow({ where: { id: early.id } });
    expect(e).toMatchObject({ status: 'error', lastErrorCode: 'tenant_not_bound' });
  });
});
