/**
 * Tenant isolation of identity administration and the tenant-scoped repositories (§9 WP4, the
 * step's gate). Tenant A's administrator holds every tenant permission and still sees nothing of
 * tenant B (lists exclude it, lookups and mutations are 404); an A API key cannot reach B; a
 * platform operator under an override into B sees B only and every request is audited; the
 * read-only repositories never return another tenant's rows.
 */
import { randomBytes } from 'node:crypto';
import { TENANT_PERMISSIONS } from '@email-gateway/database';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { DomainsRepository } from '../src/modules/tenant-data/domains.repository';
import { MessagesRepository } from '../src/modules/tenant-data/messages.repository';
import { PoliciesRepository } from '../src/modules/tenant-data/policies.repository';
import { QuarantineRepository } from '../src/modules/tenant-data/quarantine.repository';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
  uniqueSuffix,
  unknownId,
} from './support/fixtures';
import {
  apiKeyHeader,
  bearer,
  fromIp,
  login,
  loginWithMfa,
  type TokenResponseBody,
  uniqueIp,
} from './support/http';

let ctx: IntegrationApp;
let fx: Fixtures;

const POLL = { timeout: 10_000, interval: 200 };

/** Everything tenant B owns that tenant A must never reach. */
interface TenantB {
  org: FixtureOrganization;
  admin: FixtureUser;
  member: FixtureUser;
  memberSession: TokenResponseBody;
  customRole: string;
  apiKey: { id: string; key: string };
}

let orgA: FixtureOrganization;
let adminA: FixtureUser;
let tokenA: string;
let memberA: FixtureUser;
let b: TenantB;

const loginAs = (user: FixtureUser, ip = uniqueIp()) =>
  login(
    ctx,
    { email: user.email, password: user.password, organization: user.organization.slug },
    ip,
  );

const ids = (body: { data?: Array<{ id: string }> }) => (body.data ?? []).map((row) => row.id);

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);

  orgA = await fx.createOrganization();
  adminA = await fx.createUser(orgA, { roles: ['organization_admin'], mfa: true });
  memberA = await fx.createUser(orgA, { roles: ['read_only_user'] });
  tokenA = (await loginWithMfa(ctx, fx, adminA)).accessToken;

  const orgB = await fx.createOrganization();
  const adminB = await fx.createUser(orgB, { roles: ['organization_admin'], mfa: true });
  const tokenB = (await loginWithMfa(ctx, fx, adminB)).accessToken;
  const customRole = `b_role_${randomBytes(3).toString('hex')}`;
  await ctx.http
    .post('/api/v1/roles')
    .set(bearer(tokenB))
    .send({ key: customRole, name: 'B only', permissions: ['user:read'] })
    .expect(201);
  const memberB = await fx.createUser(orgB, { roles: ['read_only_user', customRole] });
  // Login events of B: one failure, one success (which is also a live session).
  const ip = uniqueIp();
  await login(
    ctx,
    { email: memberB.email, password: 'definitely-wrong-1', organization: orgB.slug },
    ip,
  ).expect(401);
  const memberSession = (await loginAs(memberB, ip).expect(200)).body as TokenResponseBody;
  const createdKey = await ctx.http
    .post('/api/v1/api-keys')
    .set(bearer(tokenB))
    .send({ name: 'B key', scopes: ['user:read'] })
    .expect(201);
  b = {
    org: orgB,
    admin: adminB,
    member: memberB,
    memberSession,
    customRole,
    apiKey: { id: createdKey.body.apiKey.id as string, key: createdKey.body.key as string },
  };
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('tenant A administrator (every tenant permission) versus tenant B', () => {
  it('holds every tenant permission', async () => {
    const res = await ctx.http.get('/api/v1/auth/me').set(bearer(tokenA)).expect(200);
    expect([...res.body.permissions].sort()).toEqual([...TENANT_PERMISSIONS].sort());
  });

  it('lists only A users', async () => {
    await expect
      .poll(
        async () => ids((await ctx.http.get('/api/v1/users?limit=100').set(bearer(tokenA))).body),
        POLL,
      )
      .toEqual(expect.arrayContaining([adminA.publicId, memberA.publicId]));
    const list = ids((await ctx.http.get('/api/v1/users?limit=100').set(bearer(tokenA))).body);
    expect(list).not.toContain(b.member.publicId);
    expect(list).not.toContain(b.admin.publicId);
    const filtered = await ctx.http
      .get(`/api/v1/users?q=${encodeURIComponent(b.member.email)}`)
      .set(bearer(tokenA))
      .expect(200);
    expect(filtered.body.data).toEqual([]);
    const byRole = await ctx.http
      .get(`/api/v1/users?role=${b.customRole}`)
      .set(bearer(tokenA))
      .expect(200);
    expect(byRole.body.data).toEqual([]);
  });

  it('gets 404 reading or changing a B user', async () => {
    const target = b.member.publicId;
    const auth = bearer(tokenA);
    await ctx.http.get(`/api/v1/users/${target}`).set(auth).expect(404);
    await ctx.http
      .patch(`/api/v1/users/${target}`)
      .set(auth)
      .send({ displayName: 'Hacked' })
      .expect(404);
    await ctx.http
      .patch(`/api/v1/users/${target}/status`)
      .set(auth)
      .send({ status: 'disabled', reason: 'Cross-tenant attempt' })
      .expect(404);
    await ctx.http
      .put(`/api/v1/users/${target}/roles`)
      .set(auth)
      .send({ roleKeys: ['read_only_user'] })
      .expect(404);
    await ctx.http.post(`/api/v1/users/${target}/invitation`).set(auth).expect(404);
    await ctx.http.post(`/api/v1/users/${target}/mfa/reset`).set(auth).expect(404);
    await ctx.http.delete(`/api/v1/users/${target}`).set(auth).expect(404);
    // Unknown ids look exactly the same.
    await ctx.http.get(`/api/v1/users/${unknownId()}`).set(auth).expect(404);

    const row = await ctx.prisma.user.findUniqueOrThrow({ where: { id: b.member.id } });
    expect(row).toMatchObject({ status: 'active', deletedAt: null });
    expect(row.displayName).not.toBe('Hacked');
  });

  it('cannot see or revoke B sessions', async () => {
    const auth = bearer(tokenA);
    const target = b.member.publicId;
    await ctx.http.get(`/api/v1/users/${target}/sessions`).set(auth).expect(404);
    await ctx.http.delete(`/api/v1/users/${target}/sessions`).set(auth).expect(404);
    await ctx.http
      .delete(`/api/v1/users/${target}/sessions/${b.memberSession.sessionId}`)
      .set(auth)
      .expect(404);
    // A B session id addressed through an A user is not found either.
    await ctx.http
      .delete(`/api/v1/users/${memberA.publicId}/sessions/${b.memberSession.sessionId}`)
      .set(auth)
      .expect(404);
    await ctx.http.get('/api/v1/auth/me').set(bearer(b.memberSession.accessToken)).expect(200);
  });

  it('cannot see or change B custom roles, and may reuse the key', async () => {
    const auth = bearer(tokenA);
    const list = await ctx.http.get('/api/v1/roles').set(auth).expect(200);
    expect((list.body.data as Array<{ key: string }>).map((r) => r.key)).not.toContain(
      b.customRole,
    );
    await ctx.http.get(`/api/v1/roles/${b.customRole}`).set(auth).expect(404);
    await ctx.http
      .put(`/api/v1/roles/${b.customRole}`)
      .set(auth)
      .send({ name: 'Hijack', permissions: ['user:read', 'user:manage'] })
      .expect(404);
    await ctx.http.delete(`/api/v1/roles/${b.customRole}`).set(auth).expect(404);
    // Assigning B's custom role to an A user: unknown in A.
    await ctx.http
      .put(`/api/v1/users/${memberA.publicId}/roles`)
      .set(auth)
      .send({ roleKeys: [b.customRole] })
      .expect(400);
    // Custom role keys are per organization.
    await ctx.http
      .post('/api/v1/roles')
      .set(auth)
      .send({ key: b.customRole, name: 'A copy', permissions: ['role:read'] })
      .expect(201);
    const bRole = await ctx.prisma.role.findFirstOrThrow({
      where: { organizationId: b.org.id, key: b.customRole },
      include: { permissions: { include: { permission: true } } },
    });
    expect(bRole.name).toBe('B only');
    expect(bRole.permissions.map((p) => p.permission.key)).toEqual(['user:read']);
  });

  it('cannot see or revoke B API keys; an A key cannot reach B', async () => {
    const auth = bearer(tokenA);
    const list = await ctx.http.get('/api/v1/api-keys').set(auth).expect(200);
    expect(ids(list.body)).not.toContain(b.apiKey.id);
    await ctx.http.delete(`/api/v1/api-keys/${b.apiKey.id}`).set(auth).expect(404);
    await ctx.http.get('/api/v1/users').set(apiKeyHeader(b.apiKey.key)).expect(200);

    const created = await ctx.http
      .post('/api/v1/api-keys')
      .set(auth)
      .send({ name: 'A key', scopes: ['user:read', 'user:manage', 'role:read', 'audit:read'] })
      .expect(201);
    const keyA = apiKeyHeader(created.body.key as string);
    await expect
      .poll(async () => ids((await ctx.http.get('/api/v1/users?limit=100').set(keyA)).body), POLL)
      .toContain(adminA.publicId);
    const users = ids((await ctx.http.get('/api/v1/users?limit=100').set(keyA)).body);
    expect(users).not.toContain(b.member.publicId);
    await ctx.http.get(`/api/v1/users/${b.member.publicId}`).set(keyA).expect(404);
    await ctx.http
      .patch(`/api/v1/users/${b.member.publicId}/status`)
      .set(keyA)
      .send({ status: 'disabled', reason: 'Cross-tenant key' })
      .expect(404);
    await ctx.http.get(`/api/v1/roles/${b.customRole}`).set(keyA).expect(200); // A's copy
    const events = await ctx.http
      .get(`/api/v1/audit/login-events?userId=${b.member.publicId}`)
      .set(keyA)
      .expect(200);
    expect(events.body.data).toEqual([]);
  });

  it('cannot see B login events', async () => {
    const bEvents = await ctx.prisma.loginAuditLog.findMany({
      where: { userId: b.member.id },
      select: { id: true },
    });
    expect(bEvents.length).toBeGreaterThanOrEqual(2);
    const bIds = bEvents.map((e) => e.id.toString());
    await expect
      .poll(async () => {
        const res = await ctx.http.get('/api/v1/audit/login-events?limit=100').set(bearer(tokenA));
        return ids(res.body).length;
      }, POLL)
      .toBeGreaterThan(0); // A's own logins are listed
    const res = await ctx.http
      .get('/api/v1/audit/login-events?limit=100')
      .set(bearer(tokenA))
      .expect(200);
    for (const event of res.body.data as Array<{ id: string; email: string }>) {
      expect(bIds).not.toContain(event.id);
      expect(event.email).not.toBe(b.member.email);
    }
    const filtered = await ctx.http
      .get(`/api/v1/audit/login-events?userId=${b.member.publicId}`)
      .set(bearer(tokenA))
      .expect(200);
    expect(filtered.body.data).toEqual([]);
  });

  it('B is unaffected by everything above', async () => {
    const user = await ctx.prisma.user.findUniqueOrThrow({ where: { id: b.member.id } });
    expect(user).toMatchObject({ status: 'active', deletedAt: null });
    const key = await ctx.prisma.apiKey.findUniqueOrThrow({ where: { publicId: b.apiKey.id } });
    expect(key.revokedAt).toBeNull();
    const roles = await ctx.prisma.userRole.count({ where: { userId: b.member.id } });
    expect(roles).toBe(2);
  });
});

describe('target-side no escalation inside A (user:manage is not every permission)', () => {
  let managerToken: string;
  let victim: FixtureUser;
  let weak: FixtureUser;
  let managerKey: string;

  beforeAll(async () => {
    const suffix = randomBytes(3).toString('hex');
    const managerRole = `user_mgr_${suffix}`;
    const weakRole = `user_ro_${suffix}`;
    await ctx.http
      .post('/api/v1/roles')
      .set(bearer(tokenA))
      .send({ key: managerRole, name: 'User manager', permissions: ['user:read', 'user:manage'] })
      .expect(201);
    await ctx.http
      .post('/api/v1/roles')
      .set(bearer(tokenA))
      .send({ key: weakRole, name: 'User reader', permissions: ['user:read'] })
      .expect(201);
    const manager = await fx.createUser(orgA, { roles: [managerRole], mfa: true });
    managerToken = (await loginWithMfa(ctx, fx, manager)).accessToken;
    victim = await fx.createUser(orgA, { roles: ['organization_admin'], mfa: true });
    weak = await fx.createUser(orgA, { roles: [weakRole] });
    const key = await ctx.http
      .post('/api/v1/api-keys')
      .set(bearer(tokenA))
      .send({ name: 'user manager key', scopes: ['user:read', 'user:manage'] })
      .expect(201);
    managerKey = key.body.key as string;
  });

  it('a custom role with user:manage cannot take over or disrupt an organization admin', async () => {
    const as = bearer(managerToken);
    const target = `/api/v1/users/${victim.publicId}`;
    await ctx.http
      .patch(target)
      .set(as)
      .send({ email: `attacker-${uniqueSuffix()}@example.test` })
      .expect(403);
    await ctx.http
      .patch(`${target}/status`)
      .set(as)
      .send({ status: 'disabled', reason: 'Takeover attempt' })
      .expect(403);
    await ctx.http.post(`${target}/mfa/reset`).set(as).expect(403);
    await ctx.http
      .put(`${target}/roles`)
      .set(as)
      .send({ roleKeys: ['read_only_user'] })
      .expect(403);
    await ctx.http.post(`${target}/invitation`).set(as).expect(403);
    await ctx.http.delete(target).set(as).expect(403);

    const row = await ctx.prisma.user.findUniqueOrThrow({ where: { id: victim.id } });
    expect(row).toMatchObject({
      email: victim.email,
      status: 'active',
      mfaEnabled: true,
      deletedAt: null,
    });

    // Users whose permissions the manager holds remain manageable.
    await ctx.http
      .patch(`/api/v1/users/${weak.publicId}`)
      .set(as)
      .send({ displayName: 'Managed by the user manager' })
      .expect(200);
  });

  it('an API key with user:manage cannot touch an admin and never changes emails', async () => {
    const key = apiKeyHeader(managerKey);
    await expect
      .poll(async () => (await ctx.http.get('/api/v1/users?limit=1').set(key)).status, POLL)
      .toBe(200);
    await ctx.http
      .patch(`/api/v1/users/${victim.publicId}`)
      .set(key)
      .send({ email: `attacker-${uniqueSuffix()}@example.test` })
      .expect(403);
    await ctx.http
      .patch(`/api/v1/users/${victim.publicId}/status`)
      .set(key)
      .send({ status: 'disabled', reason: 'Takeover attempt by key' })
      .expect(403);
    await ctx.http.delete(`/api/v1/users/${victim.publicId}`).set(key).expect(403);
    // Even for a user the key could otherwise manage, the email (recovery channel) is off limits.
    const refused = await ctx.http
      .patch(`/api/v1/users/${weak.publicId}`)
      .set(key)
      .send({ email: `attacker-${uniqueSuffix()}@example.test` })
      .expect(403);
    expect(refused.body.message).toBe('Email changes require a user session');
    await ctx.http
      .patch(`/api/v1/users/${weak.publicId}`)
      .set(key)
      .send({ displayName: 'Renamed by key' })
      .expect(200);
    const row = await ctx.prisma.user.findUniqueOrThrow({ where: { id: victim.id } });
    expect(row).toMatchObject({ email: victim.email, status: 'active', deletedAt: null });
  });
});

describe('platform override into B', () => {
  async function startOverride(
    operator: FixtureUser,
  ): Promise<{ overrideId: string; token: string }> {
    const session = await loginWithMfa(ctx, fx, operator);
    const started = await ctx.http
      .post('/api/v1/platform/overrides')
      .set(bearer(session.accessToken))
      .send({ organizationId: b.org.publicId, reason: 'Isolation test ticket 9001' })
      .expect(201);
    return {
      overrideId: started.body.overrideId as string,
      token: started.body.accessToken as string,
    };
  }

  const overrideRequests = async (overrideId: string) => {
    const rows = await ctx.prisma.auditLog.findMany({
      where: { action: 'platform.override_request', organizationId: b.org.id },
    });
    return rows
      .map(
        (r) =>
          r.metadata as { overrideId: string; method: string; route: string; statusCode: number },
      )
      .filter((m) => m.overrideId === overrideId)
      .map((m) => `${m.method} ${m.route} ${m.statusCode}`)
      .sort();
  };
  /** Distinct request kinds (polled lists repeat the same request). */
  const distinct = async (overrideId: string) => [...new Set(await overrideRequests(overrideId))];

  it('lists B users but not A users, and every request is audited', async () => {
    const operator = await fx.createPlatformUser(['platform_admin']);
    const { overrideId, token } = await startOverride(operator);

    await expect
      .poll(
        async () => ids((await ctx.http.get('/api/v1/users?limit=100').set(bearer(token))).body),
        POLL,
      )
      .toEqual(expect.arrayContaining([b.admin.publicId, b.member.publicId]));
    const list = ids((await ctx.http.get('/api/v1/users?limit=100').set(bearer(token))).body);
    expect(list).not.toContain(adminA.publicId);
    expect(list).not.toContain(memberA.publicId);
    expect(list).not.toContain(operator.publicId);
    await ctx.http.get(`/api/v1/users/${adminA.publicId}`).set(bearer(token)).expect(404);
    await ctx.http.get(`/api/v1/users/${b.member.publicId}`).set(bearer(token)).expect(200);
    // platform_admin is read-only in tenants: no user management under the override.
    await ctx.http
      .patch(`/api/v1/users/${b.member.publicId}/status`)
      .set(bearer(token))
      .send({ status: 'disabled', reason: 'Override without user:manage' })
      .expect(403);
    // Platform roles stay invisible inside the customer organization.
    const roles = await ctx.http.get('/api/v1/roles').set(bearer(token)).expect(200);
    const roleKeys = (roles.body.data as Array<{ key: string }>).map((r) => r.key);
    expect(roleKeys).toContain(b.customRole);
    expect(roleKeys).not.toContain('platform_admin');
    const perms = await ctx.http.get('/api/v1/permissions').set(bearer(token)).expect(200);
    expect(
      (perms.body.data as Array<{ key: string }>).some((p) => p.key.startsWith('platform:')),
    ).toBe(false);

    await expect
      .poll(() => distinct(overrideId), POLL)
      .toEqual(
        [
          'GET /api/v1/users 200',
          'GET /api/v1/users/:id 404',
          'GET /api/v1/users/:id 200',
          'PATCH /api/v1/users/:id/status 403',
          'GET /api/v1/roles 200',
          'GET /api/v1/permissions 200',
        ].sort(),
      );
  });

  it('mutations under the override are tenant-scoped and carry the override in their audit row', async () => {
    const operator = await fx.createPlatformUser(['super_admin']);
    const { overrideId, token } = await startOverride(operator);
    const target = await fx.createUser(b.org, { roles: ['read_only_user'] });

    await ctx.http
      .patch(`/api/v1/users/${target.publicId}/status`)
      .set(bearer(token))
      .send({ status: 'disabled', reason: 'Support action for ticket 9001' })
      .expect(200);
    const audit = await ctx.prisma.auditLog.findFirstOrThrow({
      where: { action: 'user.status_changed', resourceId: target.publicId },
    });
    expect(audit).toMatchObject({ organizationId: b.org.id, actorId: operator.publicId });
    expect(audit.metadata).toMatchObject({
      override: { id: overrideId, reason: 'Isolation test ticket 9001' },
    });

    // Still confined to B: A users are not found, platform roles cannot be granted in B, and no
    // API key can be minted for B.
    await ctx.http
      .patch(`/api/v1/users/${memberA.publicId}/status`)
      .set(bearer(token))
      .send({ status: 'disabled', reason: 'Escape attempt from the override' })
      .expect(404);
    // Nothing that creates standing access may be done under the time-boxed override (D9): no
    // role changes, invitations, email changes or API keys.
    await ctx.http
      .put(`/api/v1/users/${target.publicId}/roles`)
      .set(bearer(token))
      .send({ roleKeys: ['organization_admin'] })
      .expect(403);
    const invited = `override-invite-${uniqueSuffix()}@example.test`;
    await ctx.http
      .post('/api/v1/users/invitations')
      .set(bearer(token))
      .send({ email: invited, displayName: 'Override invitee', roleKeys: ['organization_admin'] })
      .expect(403);
    await ctx.http
      .patch(`/api/v1/users/${b.member.publicId}`)
      .set(bearer(token))
      .send({ email: `override-${uniqueSuffix()}@example.test` })
      .expect(403);
    await ctx.http
      .post('/api/v1/api-keys')
      .set(bearer(token))
      .send({ name: 'override key', scopes: ['user:read'] })
      .expect(403);
    const memberARow = await ctx.prisma.user.findUniqueOrThrow({ where: { id: memberA.id } });
    expect(memberARow.status).toBe('active');
    const memberBRow = await ctx.prisma.user.findUniqueOrThrow({ where: { id: b.member.id } });
    expect(memberBRow.email).toBe(b.member.email);
    expect(await ctx.prisma.user.count({ where: { email: invited } })).toBe(0);
    const targetRoles = await ctx.prisma.userRole.findMany({
      where: { userId: target.id },
      select: { role: { select: { key: true } } },
    });
    expect(targetRoles.map((r) => r.role.key)).toEqual(['read_only_user']);
    await expect
      .poll(() => overrideRequests(overrideId), POLL)
      .toEqual(
        [
          'PATCH /api/v1/users/:id/status 200',
          'PATCH /api/v1/users/:id/status 404',
          'PUT /api/v1/users/:id/roles 403',
          'POST /api/v1/users/invitations 403',
          'PATCH /api/v1/users/:id 403',
          'POST /api/v1/api-keys 403',
        ].sort(),
      );
  });
});

describe('tenant-scoped repositories (domains, policies, messages, quarantine)', () => {
  interface Rows {
    domain: string;
    policy: string;
    message: string;
    quarantine: string;
  }
  let rowsA: Rows;
  let rowsB: Rows;

  async function insertRows(org: FixtureOrganization): Promise<Rows> {
    const suffix = uniqueSuffix();
    const now = new Date();
    const domain = await ctx.prisma.domain.create({
      data: { organizationId: org.id, name: `iso-${suffix}.example.test` },
      select: { id: true, publicId: true },
    });
    const policy = await ctx.prisma.emailPolicy.create({
      data: { organizationId: org.id, name: `iso-${suffix}`, direction: 'inbound', priority: 10 },
      select: { id: true, publicId: true },
    });
    const deletedPolicy = await ctx.prisma.emailPolicy.create({
      data: {
        organizationId: org.id,
        name: `iso-deleted-${suffix}`,
        direction: 'inbound',
        priority: 11,
        deletedAt: now,
      },
      select: { id: true },
    });
    const identity = await ctx.prisma.messageIdentity.create({
      data: { organizationId: org.id, ingestKey: `iso-${suffix}`, receivedAt: now },
      select: { id: true, publicId: true },
    });
    await ctx.prisma.emailMessage.create({
      data: {
        id: identity.id,
        receivedAt: now,
        organizationId: org.id,
        direction: 'inbound',
        statusChangedAt: now,
        envelopeFrom: 'sender@example.test',
        subject: `iso ${suffix}`,
        sizeBytes: 1024,
        recipientCount: 1,
        emlObjectKey: `${org.publicId}/iso/${suffix}.eml`,
        emlSha256: 'a'.repeat(64),
      },
    });
    const quarantine = await ctx.prisma.quarantineMessage.create({
      data: {
        organizationId: org.id,
        messageId: identity.id,
        messageReceivedAt: now,
        recipientId: identity.id,
        recipientAddress: `rcpt-${suffix}@example.test`,
        reason: 'spam',
        envelopeFrom: 'sender@example.test',
        emlObjectKey: `${org.publicId}/iso/${suffix}.eml`,
        quarantinedAt: now,
        direction: 'inbound',
        kind: 'quarantine',
        origin: 'policy',
        stateChangedAt: now,
        expiresAt: new Date(now.getTime() + 86_400_000),
      },
      select: { id: true, publicId: true },
    });
    fx.registerCleanup(async () => {
      await ctx.prisma.quarantineMessage.deleteMany({ where: { id: quarantine.id } });
      await ctx.prisma.emailMessage.deleteMany({ where: { id: identity.id } });
      await ctx.prisma.messageIdentity.deleteMany({ where: { id: identity.id } });
      await ctx.prisma.emailPolicy.deleteMany({
        where: { id: { in: [policy.id, deletedPolicy.id] } },
      });
      await ctx.prisma.domain.deleteMany({ where: { id: domain.id } });
    });
    return {
      domain: domain.publicId,
      policy: policy.publicId,
      message: identity.publicId,
      quarantine: quarantine.publicId,
    };
  }

  beforeAll(async () => {
    rowsA = await insertRows(orgA);
    rowsB = await insertRows(b.org);
  });

  const scopeA = () => systemScope(orgA.id);
  const page = { take: 101 };

  it('domains', async () => {
    const repo = ctx.get(DomainsRepository);
    expect((await repo.findByPublicId(scopeA(), rowsA.domain))?.organizationId).toBe(orgA.id);
    expect(await repo.findByPublicId(scopeA(), rowsB.domain)).toBeNull();
    await expect
      .poll(async () => (await repo.list(scopeA(), page)).map((d) => d.publicId), POLL)
      .toEqual([rowsA.domain]);
  });

  it('email policies (soft-deleted excluded)', async () => {
    const repo = ctx.get(PoliciesRepository);
    expect((await repo.findByPublicId(scopeA(), rowsA.policy))?.organizationId).toBe(orgA.id);
    expect(await repo.findByPublicId(scopeA(), rowsB.policy)).toBeNull();
    await expect
      .poll(async () => (await repo.list(scopeA(), page)).map((p) => p.publicId), POLL)
      .toEqual([rowsA.policy]);
  });

  it('message identities and email messages', async () => {
    const repo = ctx.get(MessagesRepository);
    const own = await repo.findByPublicId(scopeA(), rowsA.message);
    expect(own).toMatchObject({ publicId: rowsA.message, organizationId: orgA.id });
    expect(await repo.findByPublicId(scopeA(), rowsB.message)).toBeNull();
    const range = { from: new Date(Date.now() - 3_600_000), to: new Date(Date.now() + 60_000) };
    await expect
      .poll(async () => (await repo.listRecent(scopeA(), range, page)).map((m) => m.publicId), POLL)
      .toEqual([rowsA.message]);
    expect(
      (await repo.listRecent(systemScope(b.org.id), range, page)).map((m) => m.publicId),
    ).not.toContain(rowsA.message);
  });

  it('quarantine messages', async () => {
    const repo = ctx.get(QuarantineRepository);
    expect((await repo.findByPublicId(scopeA(), rowsA.quarantine))?.organizationId).toBe(orgA.id);
    expect(await repo.findByPublicId(scopeA(), rowsB.quarantine)).toBeNull();
    await expect
      .poll(async () => (await repo.list(scopeA(), page)).map((q) => q.publicId), POLL)
      .toEqual([rowsA.quarantine]);
  });

  it('client-supplied tenant headers change nothing', async () => {
    const res = await ctx.http
      .get('/api/v1/users?limit=100')
      .set(bearer(tokenA))
      .set('X-Organization-Id', b.org.id.toString())
      .set('X-Tenant-Id', b.org.publicId)
      .set(fromIp(uniqueIp()))
      .expect(200);
    expect(ids(res.body)).not.toContain(b.member.publicId);
  });
});
