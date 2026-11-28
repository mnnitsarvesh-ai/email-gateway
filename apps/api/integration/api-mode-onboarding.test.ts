/**
 * Step API-4 api on the real writer and replica (docs/plan/steps/38-api-mode-parity-onboarding.md
 * A10, B3, B4, B6, B8, §3.3, §10.4): ownership through the bound provider tenant (the request
 * writes a `provider_tenant` verification row; the integration-worker's answer is simulated by
 * writing `provider_result` directly; the domain scheduler's provider pass wins ownership through
 * the first-to-verify-wins transaction with `ownership_method = provider_tenant`, superseding
 * another organization's pending claim; other answers fail the row only), the mailbox scope (the
 * `api_mode_domain_settings` row with CAS, `scope_selected`, the recompute request, the audit
 * row, the department delete refused while a scope lists it), protection by mode and the
 * onboarding state from the replica, cross-tenant 404s and the organization purge of the new
 * table. Synthetic `it-apiparity-*` organizations only.
 */
// @covers get /api/v1/api-mode/protection-coverage
// @covers get /api/v1/api-mode/domains/:domainId/onboarding
// @covers get /api/v1/api-mode/domains/:domainId/scope
// @covers put /api/v1/api-mode/domains/:domainId/scope
// @covers post /api/v1/domains/:domainId/ownership/provider-check
import { randomUUID } from 'node:crypto';
import { RedisService, S3Service, uuidv7 } from '@email-gateway/common';
import type { Response, Test } from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { KeyValueStore } from '../src/kv/key-value-store';
import { DomainProviderOwnershipService } from '../src/modules/domains/services/domain-provider-ownership.service';
import { ApiModeTenantDataRepository } from '../src/modules/tenant-data/api-mode-tenant-data.repository';
import { ProviderTenantDataRepository } from '../src/modules/tenant-data/provider-tenant-data.repository';
import { InMemoryKeyValueStore } from '../test/support/in-memory-key-value-store';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { bearer, loginWithMfa, uniqueIp } from './support/http';
import { insertDomain, type InsertedDomain } from './support/smtp';

const BASE = '/api/v1/api-mode';
const REASON = 'Integration: API-mode onboarding';
const POLL = { timeout: 15_000, interval: 200 };

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: Record<string, string>;
let readerA: Record<string, string>;
let adminB: Record<string, string>;
let apiDomain: InsertedDomain;
let connectionA: { id: bigint; publicId: string };
let mailboxes: Array<{ id: bigint; publicId: string }>;

function call(
  who: Record<string, string>,
  method: 'get' | 'post' | 'put' | 'delete',
  path: string,
  body?: object,
  key: string | null = method === 'get' || method === 'delete' ? null : `it-${randomUUID()}`,
): Test {
  let req = ctx.http[method](path).set(who).set('X-Forwarded-For', uniqueIp());
  if (key !== null) req = req.set('Idempotency-Key', key);
  return body === undefined ? req : req.send(body);
}

async function eventually(make: () => Test, accept: (res: Response) => boolean): Promise<Response> {
  let last: Response | undefined;
  await expect
    .poll(async () => {
      last = await make();
      return accept(last);
    }, POLL)
    .toBe(true);
  return last!;
}

/** A bound Microsoft 365 connection with an active mail-flow grant (and the mailbox grant). */
async function boundConnection(org: FixtureOrganization) {
  const p = ctx.prisma;
  const connection = await p.providerConnection.create({
    data: {
      organizationId: org.id,
      provider: 'microsoft_365',
      displayName: `Apiparity ${randomUUID().slice(0, 6)}`,
      status: 'active',
      externalTenantId: '3a4b5c6d-7e8f-4a0b-9c1d-2e3f4a5b6c7d',
      activeTenantKey: `microsoft_365:${randomUUID()}`,
      tenantVerifiedAt: new Date(),
      // Not due for a live integration-worker health run during the suite.
      nextHealthCheckAt: new Date(Date.now() + 24 * 3_600_000),
    },
    select: { id: true, publicId: true },
  });
  for (const profile of ['m365.mail_flow', 'm365.mailbox_remediation']) {
    await p.providerConnectionGrant.create({
      data: {
        organizationId: org.id,
        connectionId: connection.id,
        profile,
        profileVersion: 1,
        authMethod: 'platform_app',
        status: 'active',
        requestedPermissions: [],
        observedPermissions: [],
        verifiedAt: new Date(),
      },
    });
  }
  return connection;
}

beforeAll(async () => {
  ctx = await createIntegrationApp(
    { REDIS_DKIM_URL: '', DOMAIN_PROVIDER_CHECKS_PER_HOUR: '50' },
    {
      override: (builder) =>
        builder
          .overrideProvider(RedisService)
          .useValue({ healthName: 'redis', checkHealth: () => Promise.resolve() })
          .overrideProvider(S3Service)
          .useValue({ healthName: 's3', checkHealth: () => Promise.resolve() })
          .overrideProvider(KeyValueStore)
          .useValue(new InMemoryKeyValueStore()),
    },
  );
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization({ planCode: 'enterprise', slugPrefix: 'apiparity' });
  orgB = await fx.createOrganization({ planCode: 'enterprise', slugPrefix: 'apiparity' });
  const login = async (org: FixtureOrganization, roles: string[]) => {
    const user = await fx.createUser(org, { roles, mfa: true });
    return bearer((await loginWithMfa(ctx, fx, user)).accessToken);
  };
  adminA = await login(orgA, ['organization_admin']);
  readerA = await login(orgA, ['read_only_user']);
  adminB = await login(orgB, ['organization_admin']);
  connectionA = await boundConnection(orgA);
  // An api-mode domain of A, linked to the connection, with three mailboxes.
  apiDomain = await insertDomain(ctx, orgA, { status: 'active', label: 'apiparity' });
  await ctx.prisma.domain.update({
    where: { id: apiDomain.id },
    data: { protectionMode: 'api', ownershipMethod: 'dns_txt', inboundEnabled: false },
  });
  await ctx.prisma.providerConnectionDomain.create({
    data: { organizationId: orgA.id, connectionId: connectionA.id, domainId: apiDomain.id },
  });
  const api = await ctx.prisma.apiModeConnection.create({
    data: {
      publicId: uuidv7(),
      organizationId: orgA.id,
      providerConnectionId: connectionA.id,
      provider: 'microsoft_365',
      healthStatus: 'healthy',
    },
    select: { id: true },
  });
  mailboxes = [];
  for (const local of ['alex', 'blair', 'casey']) {
    mailboxes.push(
      await ctx.prisma.apiMailbox.create({
        data: {
          publicId: uuidv7(),
          organizationId: orgA.id,
          apiConnectionId: api.id,
          providerUserId: `user-${randomUUID()}`,
          primaryAddress: `${local}-${randomUUID().slice(0, 6)}@${apiDomain.name}`,
          domainId: apiDomain.id,
          status: 'active',
          coverageState: 'covered',
        },
        select: { id: true, publicId: true },
      }),
    );
  }
  const orgs = [orgA, orgB];
  fx.registerCleanup(async () => {
    const where = { organizationId: { in: orgs.map((o) => o.id) } };
    for (const org of orgs) {
      await ctx.get(ApiModeTenantDataRepository).purgeOrganization(systemScope(org.id));
      await ctx.prisma.domainVerification.deleteMany({ where: { organizationId: org.id } });
      await ctx.get(ProviderTenantDataRepository).purgeOrganization(systemScope(org.id));
    }
    await ctx.prisma.tenantDepartmentMember.deleteMany({ where });
    await ctx.prisma.tenantDepartment.deleteMany({ where });
    await ctx.prisma.messageOutbox.deleteMany({ where });
    await ctx.prisma.auditLog.deleteMany({ where });
  });
}, 120_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('ownership through the bound provider tenant (B3)', () => {
  it('request → simulated worker answer → scheduler win with ownership_method provider_tenant', async () => {
    const pending = await insertDomain(ctx, orgA, {
      status: 'pending_verification',
      label: 'apiparity-p',
    });
    // Another organization's pending claim on the same name is superseded by the win (D4).
    const rival = await ctx.prisma.domain.create({
      data: {
        organizationId: orgB.id,
        name: pending.name,
        status: 'pending_verification',
        statusChangedAt: new Date(),
        inboundEnabled: true,
        outboundEnabled: false,
        settings: { create: { organizationId: orgB.id } },
      },
      select: { id: true },
    });
    const path = `/api/v1/domains/${pending.publicId}/ownership/provider-check`;
    expect((await call(readerA, 'post', path, {})).status).toBe(403);
    expect((await call(adminB, 'post', path, {})).status).toBe(404);
    const res = await call(adminA, 'post', path, { connectionId: connectionA.publicId });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body).toMatchObject({ status: 'pending', connectionId: connectionA.publicId });
    const row = await ctx.prisma.domainVerification.findUniqueOrThrow({
      where: { id: BigInt(res.body.verificationId) },
    });
    expect(row).toMatchObject({
      organizationId: orgA.id,
      domainId: pending.id,
      method: 'provider_tenant',
      token: 'provider-tenant',
      status: 'pending',
      providerConnectionId: connectionA.id,
      providerResult: null,
    });
    expect(row.expiresAt.getTime()).toBeGreaterThan(Date.now() + 50 * 60_000);
    // The integration-worker's answer (written directly, as the worker does).
    await ctx.prisma.domainVerification.update({
      where: { id: row.id },
      data: { providerResult: 'verified', providerCheckedAt: new Date() },
    });
    const summary = await ctx.get(DomainProviderOwnershipService).applyDue(new Date());
    expect(summary.verified).toBeGreaterThanOrEqual(1);
    const won = await ctx.prisma.domain.findUniqueOrThrow({ where: { id: pending.id } });
    expect(won).toMatchObject({ status: 'verified', ownershipMethod: 'provider_tenant' });
    expect(won.verifiedName).toBe(pending.name);
    expect(
      await ctx.prisma.domainVerification.findUniqueOrThrow({ where: { id: row.id } }),
    ).toMatchObject({ status: 'verified' });
    expect(await ctx.prisma.domain.findUniqueOrThrow({ where: { id: rival.id } })).toMatchObject({
      status: 'failed',
      statusReason: 'claimed_by_another_organization',
    });
    const audit = await ctx.prisma.auditLog.findFirstOrThrow({
      where: { organizationId: orgA.id, action: 'domain.verified', resourceId: pending.publicId },
    });
    expect(audit.metadata).toMatchObject({
      method: 'provider_tenant',
      connectionId: connectionA.publicId,
    });
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: orgA.id, action: 'domain.provider_verification_requested' },
      }),
    ).toBeGreaterThanOrEqual(1);
    const detail = await eventually(
      () => call(adminA, 'get', `/api/v1/domains/${pending.publicId}`),
      (r) => r.status === 200 && r.body.ownership?.method === 'provider_tenant',
    );
    expect(detail.body.ownership).toMatchObject({
      providerCheck: { status: 'verified', result: 'verified', connectionId: connectionA.publicId },
      providerCheckAvailable: false,
    });
    // B4: a verified (not yet active) domain can now be linked to a connection.
    const link = await call(
      adminA,
      'put',
      `/api/v1/provider-connections/${connectionA.publicId}/domains`,
      { domainIds: [apiDomain.publicId, pending.publicId] },
    );
    expect(link.status, JSON.stringify(link.body)).toBe(200);
  });

  it('any other answer fails the row only; the domain stays pending', async () => {
    const pending = await insertDomain(ctx, orgA, {
      status: 'pending_verification',
      label: 'apiparity-n',
    });
    const res = await call(
      adminA,
      'post',
      `/api/v1/domains/${pending.publicId}/ownership/provider-check`,
      {},
    );
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    await ctx.prisma.domainVerification.update({
      where: { id: BigInt(res.body.verificationId) },
      data: { providerResult: 'absent', providerCheckedAt: new Date() },
    });
    await ctx.get(DomainProviderOwnershipService).applyDue(new Date());
    expect(
      await ctx.prisma.domainVerification.findUniqueOrThrow({
        where: { id: BigInt(res.body.verificationId) },
      }),
    ).toMatchObject({ status: 'failed', lastError: 'absent' });
    expect(await ctx.prisma.domain.findUniqueOrThrow({ where: { id: pending.id } })).toMatchObject({
      status: 'pending_verification',
      ownershipMethod: null,
    });
    // An owned domain is not waiting: 409 domain_not_pending.
    const owned = await call(
      adminA,
      'post',
      `/api/v1/domains/${apiDomain.publicId}/ownership/provider-check`,
      {},
    );
    expect(owned.status).toBe(409);
    expect(owned.body.code).toBe('domain_not_pending');
  });
});

describe('mailbox scope (B6) and the department reference', () => {
  it('departments scope: row with CAS, recompute requested, audit; the department cannot be deleted', async () => {
    const department = await ctx.prisma.tenantDepartment.create({
      data: { organizationId: orgA.id, name: `Finance ${randomUUID().slice(0, 4)}` },
      select: { id: true, publicId: true },
    });
    const path = `${BASE}/domains/${apiDomain.publicId}/scope`;
    expect(
      (
        await call(readerA, 'put', path, {
          scope: { kind: 'all' },
          reason: REASON,
          expectedRowVersion: null,
        })
      ).status,
    ).toBe(403);
    expect((await call(adminB, 'get', path)).status).toBe(404);
    const res = await call(adminA, 'put', path, {
      scope: { kind: 'departments', departmentIds: [department.publicId] },
      reason: REASON,
      expectedRowVersion: null,
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body).toMatchObject({
      kind: 'departments',
      departments: [{ id: department.publicId, memberCount: 0 }],
      rowVersion: 1,
      recomputePending: true,
      created: true,
    });
    const row = await ctx.prisma.apiModeDomainSetting.findUniqueOrThrow({
      where: { domainId: apiDomain.id },
    });
    expect(row).toMatchObject({ organizationId: orgA.id, scopeKind: 'departments', rowVersion: 1 });
    expect(row.scopeDepartmentIds).toEqual([department.publicId]);
    expect(row.scopeRecomputeRequestedAt).not.toBeNull();
    expect(
      await ctx.prisma.auditLog.findFirst({
        where: { organizationId: orgA.id, action: 'api_mode.scope_updated' },
        orderBy: { id: 'desc' },
      }),
    ).toMatchObject({
      resourceType: 'api_mode_domain_settings',
      metadata: expect.objectContaining({ from: 'all', to: 'departments', departments: 1 }),
    });
    const inUse = await call(adminA, 'delete', `/api/v1/departments/${department.publicId}`);
    expect(inUse.status).toBe(409);
    expect(inUse.body).toMatchObject({
      code: 'department_in_use',
      reference: 'api_mode_scope',
      domains: [{ domainId: apiDomain.publicId }],
    });
    // A stale version is a CAS conflict.
    const stale = await call(adminA, 'put', path, {
      scope: { kind: 'all' },
      reason: REASON,
      expectedRowVersion: null,
    });
    expect(stale.status).toBe(409);
    expect(stale.body).toMatchObject({ code: 'api_mode_scope_conflict', currentRowVersion: 1 });
  });

  it('mailboxes scope: clears and sets scope_selected for the domain only', async () => {
    const path = `${BASE}/domains/${apiDomain.publicId}/scope`;
    const current = await eventually(
      () => call(adminA, 'get', path),
      (r) => r.status === 200 && r.body.rowVersion !== null,
    );
    const res = await call(adminA, 'put', path, {
      scope: { kind: 'mailboxes' },
      mailboxIds: [mailboxes[0]!.publicId, mailboxes[1]!.publicId],
      reason: REASON,
      expectedRowVersion: current.body.rowVersion,
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body).toMatchObject({ kind: 'mailboxes', selectedMailboxes: 2 });
    const selected = await ctx.prisma.apiMailbox.findMany({
      where: { organizationId: orgA.id, domainId: apiDomain.id, scopeSelected: true },
      select: { publicId: true },
    });
    expect(selected.map((m) => m.publicId).sort()).toEqual(
      [mailboxes[0]!.publicId, mailboxes[1]!.publicId].sort(),
    );
    // Back to all: the selection is cleared in the same transaction.
    const all = await call(adminA, 'put', path, {
      scope: { kind: 'all' },
      reason: REASON,
      expectedRowVersion: res.body.rowVersion,
    });
    expect(all.status).toBe(200);
    expect(
      await ctx.prisma.apiMailbox.count({
        where: { organizationId: orgA.id, domainId: apiDomain.id, scopeSelected: true },
      }),
    ).toBe(0);
  });
});

describe('protection by mode (A10) and the onboarding state (B8) from the replica', () => {
  it('lists the organization’s domains with coverage; never another organization’s', async () => {
    const res = await eventually(
      () => call(readerA, 'get', `${BASE}/protection-coverage?effectiveMode=api`),
      (r) =>
        r.status === 200 &&
        (r.body as { items: Array<{ domainId: string }> }).items.some(
          (i) => i.domainId === apiDomain.publicId,
        ),
    );
    expect(res.body.capabilities).toHaveLength(12);
    const item = res.body.items.find(
      (i: { domainId: string }) => i.domainId === apiDomain.publicId,
    );
    expect(item).toMatchObject({
      effectiveMode: 'api',
      api: {
        connection: { id: connectionA.publicId, mailboxAccess: 'active' },
        mailboxes: { inScope: 3, covered: 3, gap: 0 },
      },
    });
    const b = await call(adminB, 'get', `${BASE}/protection-coverage`);
    expect(b.status).toBe(200);
    expect(b.body.items.map((i: { domainId: string }) => i.domainId)).not.toContain(
      apiDomain.publicId,
    );
  });

  it('the onboarding state of the api domain; another organization’s domain is 404', async () => {
    const res = await eventually(
      () => call(readerA, 'get', `${BASE}/domains/${apiDomain.publicId}/onboarding`),
      (r) => r.status === 200,
    );
    expect(res.body).toMatchObject({
      domainId: apiDomain.publicId,
      effectiveMode: 'api',
      ownership: { status: 'verified', method: 'dns_txt' },
      connection: { id: connectionA.publicId, bound: true, mailFlowGrant: 'active' },
      firstCopy: { status: 'waiting', copy: null },
    });
    expect(res.body.steps.map((s: { key: string }) => s.key)).toEqual([
      'ownership',
      'connect',
      'intake',
      'mailboxes',
      'action',
      'review',
    ]);
    expect(
      (await call(adminB, 'get', `${BASE}/domains/${apiDomain.publicId}/onboarding`)).status,
    ).toBe(404);
  });
});

describe('organization purge (§3.3)', () => {
  it('deletes api_mode_domain_settings with the other API-mode tables', async () => {
    const domainB = await insertDomain(ctx, orgB, { status: 'active', label: 'apiparity-b' });
    await ctx.prisma.apiModeDomainSetting.create({
      data: { publicId: uuidv7(), organizationId: orgB.id, domainId: domainB.id },
    });
    const beforeA = await ctx.prisma.apiModeDomainSetting.count({
      where: { organizationId: orgA.id },
    });
    const counts = await ctx
      .get(ApiModeTenantDataRepository)
      .purgeOrganization(systemScope(orgB.id), 1);
    expect(counts.api_mode_domain_settings).toBe(1);
    expect(
      await ctx.prisma.apiModeDomainSetting.count({ where: { organizationId: orgB.id } }),
    ).toBe(0);
    expect(
      await ctx.prisma.apiModeDomainSetting.count({ where: { organizationId: orgA.id } }),
    ).toBe(beforeA);
  });
});
