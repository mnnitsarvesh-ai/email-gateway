import { GOOGLE_MAIL_FLOW_PROFILE, testing } from '@email-gateway/provider-integrations';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Harness, signal } from './support/harness';

/**
 * Domain ownership through the bound provider tenant (step API-4 B3.3, ADR-0107; §10.3) and the
 * binding proof rule (B3.5, B4): the `ProviderOwnershipTask` of the tasks role against the
 * in-process fake provider server only (never Microsoft, Google or the Internet). Synthetic
 * `it-prov-*` organizations.
 */
const h = new Harness();
let org: bigint;
let other: bigint;

beforeAll(async () => {
  await h.start();
  org = await h.organization('ownership');
  other = await h.organization('ownership-other');
});

afterAll(async () => {
  await h.cleanup();
});

type M365Domain = { name: string; isVerified?: boolean; supportedServices?: string[] };

/** A bound, configuring Microsoft 365 connection with an active mail-flow grant. */
async function boundMicrosoft(
  organizationId: bigint,
  domains: M365Domain[],
  options: { bound?: boolean; grantStatus?: 'active' | 'revoked'; disabled?: boolean } = {},
) {
  const tenant = h.m365Tenant({ domains: [] });
  h.fake.addMicrosoftTenant({
    tenantId: tenant.tenantId,
    displayName: 'Tenant',
    domains: domains.map((d) => ({
      name: d.name,
      isVerified: d.isVerified ?? true,
      ...(d.supportedServices ? { supportedServices: d.supportedServices } : {}),
      mxHost: null,
    })),
  });
  const bound = options.bound ?? true;
  const connection = await h.connection(organizationId, 'microsoft_365', {
    status: options.disabled ? 'disabled' : 'configuring',
    ...(bound
      ? {
          externalTenantId: tenant.tenantId,
          externalTenantName: 'Tenant',
          tenantVerifiedAt: h.clock.now(),
          activeTenantKey: `microsoft_365:${tenant.tenantId}`,
        }
      : {}),
  });
  await h.grant(connection, {
    authMethod: 'customer_app_secret',
    status: options.grantStatus ?? 'active',
    clientId: tenant.clientId,
    claimedTenantId: tenant.tenantId,
    credential: { method: 'customer_app_secret', clientSecret: tenant.secret },
  });
  return { connection, tenant };
}

/** A pending domain with a pending `provider_tenant` verification row (as the api writes it). */
async function pendingCheck(
  organizationId: bigint,
  label: string,
  connectionId: bigint | null,
  verificationOrganizationId: bigint = organizationId,
) {
  const domain = await h.domain(organizationId, h.name(label), 'pending_verification');
  const verification = await h.prisma.domainVerification.create({
    data: {
      organizationId: verificationOrganizationId,
      domainId: domain.id,
      method: 'provider_tenant',
      token: 'provider-tenant',
      status: 'pending',
      providerConnectionId: connectionId,
      expiresAt: new Date(h.clock.now().getTime() + 60 * 60_000),
    },
  });
  return { domain, verification };
}

const reload = (id: bigint) => h.prisma.domainVerification.findUniqueOrThrow({ where: { id } });

/** Runs ownership passes until no row is claimed (several connections may be pending). */
async function drain(components: ReturnType<Harness['worker']>['components']) {
  for (let i = 0; i < 20; i += 1) {
    if ((await components.ownership.runOnce(signal())).length === 0) return;
  }
}

describe('provider ownership task (B3.3)', () => {
  it('Microsoft: verified (isVerified with Email), unverified, no Email service, absent', async () => {
    const names = {
      ok: h.name('own-ok'),
      unverified: h.name('own-unverified'),
      noEmail: h.name('own-no-email'),
    };
    const { connection } = await boundMicrosoft(org, [
      { name: names.ok },
      { name: names.unverified, isVerified: false },
      { name: names.noEmail, supportedServices: ['OfficeCommunicationsOnline'] },
    ]);
    const rows = await Promise.all([
      pendingCheck(org, 'own-ok', connection.id),
      pendingCheck(org, 'own-unverified', connection.id),
      pendingCheck(org, 'own-no-email', connection.id),
      pendingCheck(org, 'own-absent', connection.id),
    ]);
    const { components, metrics } = h.worker();

    // At most one check per connection per tick.
    const first = await components.ownership.runOnce(signal());
    expect(first).toHaveLength(1);
    await drain(components);

    const results = await Promise.all(rows.map((r) => reload(r.verification.id)));
    expect(results.map((r) => [r.providerResult, r.providerErrorCode])).toEqual([
      ['verified', null],
      ['unverified', null],
      ['unverified', null],
      ['absent', null],
    ]);
    for (const r of results) {
      expect(r.status).toBe('pending'); // the api applies the win (B3.4)
      expect(r.providerCheckedAt).not.toBeNull();
      expect(r.attempts).toBe(1);
    }
    // The domain rows are never changed by the worker.
    for (const { domain } of rows) {
      const after = await h.prisma.domain.findUniqueOrThrow({ where: { id: domain.id } });
      expect(after).toMatchObject({ status: 'pending_verification', ownershipMethod: null });
      expect(after.updatedAt.getTime()).toBe(domain.updatedAt.getTime());
    }
    const counted = await metrics.ownershipChecks.get();
    const of = (result: string) =>
      counted.values.find(
        (v) => v.labels.provider === 'microsoft_365' && v.labels.result === result,
      )?.value;
    expect(of('verified')).toBe(1);
    expect(of('unverified')).toBe(2);
    expect(of('absent')).toBe(1);

    // Checked rows are never picked again.
    expect(await components.ownership.runOnce(signal())).toHaveLength(0);
  });

  it('Google: verified primary and secondary domains, alias as reported', async () => {
    const primary = h.name('g-primary');
    const secondary = h.name('g-secondary');
    const alias = h.name('g-alias');
    const unverified = h.name('g-unverified');
    const admin = `admin@${primary}`;
    const customerId = `C0${h.suffix.replace(/[^0-9a-z]/g, '').slice(0, 6)}o`;
    const sa = testing.testServiceAccountKey(
      `reader@${h.name('own-sa')}`,
      h.fake.endpoints().googleTokenUrl,
    );
    h.fake.addGoogleCustomer({
      customerId,
      primaryDomain: primary,
      domains: [
        {
          domainName: primary,
          verified: true,
          isPrimary: true,
          aliases: [{ name: alias, verified: true }],
        },
        { domainName: secondary, verified: true },
        { domainName: unverified, verified: false },
      ],
      admins: [admin],
    });
    h.fake.addGoogleServiceAccount(sa.account);
    h.fake.delegate(customerId, sa.account.clientId, [...GOOGLE_MAIL_FLOW_PROFILE.permissions]);
    const connection = await h.connection(org, 'google_workspace', {
      status: 'active',
      externalTenantId: customerId,
      externalTenantName: 'Google Org',
      tenantVerifiedAt: h.clock.now(),
      activeTenantKey: `google_workspace:${customerId}`,
    });
    await h.grant(connection, {
      authMethod: 'customer_service_account',
      status: 'active',
      subjectEmail: admin,
      credential: { method: 'customer_service_account', key: sa.document },
    });
    const rows = await Promise.all([
      pendingCheck(org, 'g-primary', connection.id),
      pendingCheck(org, 'g-secondary', connection.id),
      pendingCheck(org, 'g-alias', connection.id),
      pendingCheck(org, 'g-unverified', connection.id),
    ]);
    const { components } = h.worker();
    await drain(components);
    const results = await Promise.all(rows.map((r) => reload(r.verification.id)));
    expect(results.map((r) => r.providerResult)).toEqual([
      'verified',
      'verified',
      'alias',
      'unverified',
    ]);
  });

  it('a throttled provider (429 with Retry-After) is an error with the classified code', async () => {
    const name = h.name('own-throttled');
    const { connection } = await boundMicrosoft(org, [{ name }]);
    const { verification } = await pendingCheck(org, 'own-throttled', connection.id);
    h.fake.failNext({
      endpoint: 'm365.graph',
      status: 429,
      headers: { 'retry-after': '1' },
      body: { error: { code: 'TooManyRequests' } },
    });
    const { components } = h.worker();
    await drain(components);
    const after = await reload(verification.id);
    expect(after).toMatchObject({ providerResult: 'error', providerErrorCode: 'throttled' });
    expect(after.providerCheckedAt).not.toBeNull();
  });

  it('the existing client honours Retry-After and retries before answering', async () => {
    const name = h.name('own-retried');
    const { connection } = await boundMicrosoft(org, [{ name }]);
    const { verification } = await pendingCheck(org, 'own-retried', connection.id);
    h.fake.failNext({ endpoint: 'm365.graph', status: 429, headers: { 'retry-after': '1' } });
    const { components } = h.worker({ retry: { retries: 1 } });
    const started = Date.now();
    await drain(components);
    expect(Date.now() - started).toBeGreaterThanOrEqual(900);
    expect(await reload(verification.id)).toMatchObject({
      providerResult: 'verified',
      providerErrorCode: null,
    });
  });

  it('refuses without a provider call: unbound, disabled, grant revoked, organization echo', async () => {
    const unbound = await boundMicrosoft(org, [{ name: h.name('own-unbound') }], {
      bound: false,
    });
    const disabled = await boundMicrosoft(org, [{ name: h.name('own-disabled') }], {
      disabled: true,
    });
    const revoked = await boundMicrosoft(org, [{ name: h.name('own-revoked') }], {
      grantStatus: 'revoked',
    });
    const foreign = await boundMicrosoft(other, [{ name: h.name('own-foreign') }]);
    const rows = [
      await pendingCheck(org, 'own-unbound', unbound.connection.id),
      await pendingCheck(org, 'own-disabled', disabled.connection.id),
      await pendingCheck(org, 'own-revoked', revoked.connection.id),
      // A connection of another organization.
      await pendingCheck(org, 'own-foreign', foreign.connection.id),
      // A verification row whose organization differs from its domain's.
      await pendingCheck(org, 'own-echo', unbound.connection.id, other),
      await pendingCheck(org, 'own-none', null),
    ];
    const before = h.fake.requests.filter((r) => r.endpoint === 'm365.graph').length;
    const { components } = h.worker();
    await drain(components);
    const results = await Promise.all(rows.map((r) => reload(r.verification.id)));
    expect(results.map((r) => [r.providerResult, r.providerErrorCode])).toEqual([
      ['error', 'connection_not_bound'],
      ['error', 'connection_disabled'],
      ['error', 'mail_flow_grant_inactive'],
      ['error', 'organization_mismatch'],
      ['error', 'organization_mismatch'],
      ['error', 'connection_not_found'],
    ]);
    expect(h.fake.requests.filter((r) => r.endpoint === 'm365.graph').length).toBe(before);
  });

  it('a domain that is no longer pending and expired rows are not checked at the provider', async () => {
    const name = h.name('own-not-pending');
    const { connection } = await boundMicrosoft(org, [{ name }]);
    const { domain, verification } = await pendingCheck(org, 'own-not-pending', connection.id);
    await h.prisma.domain.update({ where: { id: domain.id }, data: { status: 'failed' } });
    const expired = await pendingCheck(org, 'own-expired', connection.id);
    await h.prisma.domainVerification.update({
      where: { id: expired.verification.id },
      data: { expiresAt: new Date(h.clock.now().getTime() - 1_000) },
    });
    const { components } = h.worker();
    await drain(components);
    expect(await reload(verification.id)).toMatchObject({
      providerResult: 'error',
      providerErrorCode: 'domain_not_pending',
    });
    expect(await reload(expired.verification.id)).toMatchObject({
      providerResult: null,
      providerCheckedAt: null,
      attempts: 0,
    });
  });

  it('an interrupted claim is retried after the delay, not at once', async () => {
    const name = h.name('own-interrupted');
    const { connection } = await boundMicrosoft(org, [{ name }]);
    const { verification } = await pendingCheck(org, 'own-interrupted', connection.id);
    const { components } = h.worker();
    const aborted = new AbortController();
    aborted.abort();
    // An aborted pass claims (stamps) the row but checks nothing.
    expect(await components.ownership.runOnce(aborted.signal)).toEqual([]);
    expect(await reload(verification.id)).toMatchObject({ attempts: 1, providerResult: null });
    expect(await components.ownership.runOnce(signal())).toHaveLength(0);
    h.clock.advance(61_000);
    const outcomes = await components.ownership.runOnce(signal());
    expect(outcomes.map((o) => o.result)).toEqual(['verified']);
    expect(await reload(verification.id)).toMatchObject({ attempts: 2 });
  });
});

describe('tenant binding proof (B3.5, B4)', () => {
  /** A connecting connection whose active grant was verified a minute ago, with one link. */
  async function proofCandidate(
    label: string,
    status: 'active' | 'verified',
    ownershipMethod: 'dns_txt' | 'provider_tenant' | null,
  ) {
    const name = h.name(label);
    const tenant = h.m365Tenant({ domains: [{ name }] });
    const domain = await h.domain(org, name, status, ownershipMethod);
    const connection = await h.connection(org, 'microsoft_365', { status: 'configuring' });
    const grant = await h.grant(connection, {
      authMethod: 'customer_app_secret',
      status: 'active',
      clientId: tenant.clientId,
      claimedTenantId: tenant.tenantId,
      credential: { method: 'customer_app_secret', clientSecret: tenant.secret },
    });
    await h.prisma.providerConnectionGrant.update({
      where: { id: grant.id },
      data: { verifiedAt: new Date(h.clock.now().getTime() - 60_000) },
    });
    const link = await h.link(connection, domain.id);
    await h.prisma.providerConnectionDomain.update({
      where: { id: link.id },
      data: { providerVerification: 'verified', providerCheckedAt: h.clock.now() },
    });
    return { connection, tenant };
  }

  it('a TXT-verified domain in status verified (not yet active) proves the tenant', async () => {
    const { connection, tenant } = await proofCandidate('proof-verified', 'verified', 'dns_txt');
    const { components } = h.worker();
    expect(await components.binder.settle(connection.id, signal(), 'it-proof-1')).toBe('bound');
    const after = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    expect(after.activeTenantKey).toBe(`microsoft_365:${tenant.tenantId}`);
    // I10 uses the same proof rule: bound with a proving domain → active.
    expect(after.status).toBe('active');
  });

  it('an active domain with ownership_method NULL is treated as dns_txt', async () => {
    const { connection } = await proofCandidate('proof-null', 'active', null);
    expect(await h.worker().components.binder.settle(connection.id, signal(), 'it-proof-2')).toBe(
      'bound',
    );
  });

  it('a provider-proven domain never proves the tenant (P-I6)', async () => {
    const { connection } = await proofCandidate('proof-provider', 'active', 'provider_tenant');
    expect(await h.worker().components.binder.settle(connection.id, signal(), 'it-proof-3')).toBe(
      'unproven',
    );
    const after = await h.prisma.providerConnection.findUniqueOrThrow({
      where: { id: connection.id },
    });
    expect(after).toMatchObject({ status: 'configuring', activeTenantKey: null });
  });
});
