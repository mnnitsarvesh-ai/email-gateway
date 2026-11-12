/**
 * Identity administration against real MySQL (writer + replica) and Redis, in-process (§9 WP4):
 * invitations and `max_users`, status changes and session revocation, unlock, the escalation,
 * platform-role and last-administrator rules, custom roles, API keys end to end, MFA reset,
 * administrator session management and the login events listing.
 */
// ---- Route coverage (step 6.1 §3.8, test/route-coverage/legacy.ts) ----
// @covers delete /api/v1/api-keys/:id
// @covers delete /api/v1/roles/:key
// @covers delete /api/v1/users/:id
// @covers delete /api/v1/users/:id/sessions
// @covers delete /api/v1/users/:id/sessions/:sessionId
// @covers get /api/v1/api-keys
// @covers get /api/v1/audit/login-events
// @covers get /api/v1/permissions
// @covers get /api/v1/roles
// @covers get /api/v1/roles/:key
// @covers get /api/v1/users
// @covers get /api/v1/users/:id
// @covers get /api/v1/users/:id/sessions
// @covers patch /api/v1/users/:id
// @covers patch /api/v1/users/:id/status
// @covers post /api/v1/api-keys
// @covers post /api/v1/roles
// @covers post /api/v1/users/:id/invitation
// @covers post /api/v1/users/:id/mfa/reset
// @covers post /api/v1/users/invitations
// @covers put /api/v1/roles/:key
// @covers put /api/v1/users/:id/roles
// ---- end of route coverage ----
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
  strongPassword,
  uniqueSuffix,
} from './support/fixtures';
import {
  apiKeyHeader,
  bearer,
  fromIp,
  idem,
  login,
  loginWithMfa,
  type TokenResponseBody,
  uniqueIp,
} from './support/http';

let ctx: IntegrationApp;
let fx: Fixtures;

const POLL = { timeout: 10_000, interval: 200 };

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

const loginAs = (user: FixtureUser, ip = uniqueIp()) =>
  login(
    ctx,
    { email: user.email, password: user.password, organization: user.organization.slug },
    ip,
  );

async function sessionOf(user: FixtureUser): Promise<TokenResponseBody> {
  return (await loginAs(user).expect(200)).body as TokenResponseBody;
}

const auditRows = (action: string, resourceId: string) =>
  ctx.prisma.auditLog.findMany({ where: { action, resourceId }, orderBy: { id: 'asc' } });

const me = (accessToken: string) => ctx.http.get('/api/v1/auth/me').set(bearer(accessToken));

/** An organization with one MFA-enrolled organization admin and their MFA session. */
async function orgWithAdmin(
  options: Parameters<Fixtures['createOrganization']>[0] = {},
): Promise<{ org: FixtureOrganization; admin: FixtureUser; token: string }> {
  const org = await fx.createOrganization(options);
  const admin = await fx.createUser(org, { roles: ['organization_admin'], mfa: true });
  const session = await loginWithMfa(ctx, fx, admin);
  return { org, admin, token: session.accessToken };
}

const invite = (token: string, body: { email: string; displayName: string; roleKeys: string[] }) =>
  ctx.http.post('/api/v1/users/invitations').set(idem()).set(bearer(token)).send(body);

const newEmail = () => `invitee-${uniqueSuffix()}@example.test`;

describe('invitations', () => {
  it('invites with roles, emails a link that activates the account, and audits', async () => {
    const { org, token } = await orgWithAdmin();
    const email = newEmail();
    const res = await invite(token, {
      email: email.toUpperCase(),
      displayName: 'Invited Person',
      roleKeys: ['security_analyst'],
    }).expect(201);
    expect(res.body).toMatchObject({
      email,
      displayName: 'Invited Person',
      status: 'invited',
      roles: [{ key: 'security_analyst', name: 'Security Analyst' }],
      mfaEnabled: false,
      emailVerified: false,
      lockedUntil: null,
    });
    expect(Object.keys(res.body)).not.toContain('passwordHash');

    const invitationToken = ctx.emails.tokenFor(email, 'invitation');
    expect(invitationToken).toMatch(/^egt_/);
    const password = strongPassword();
    await ctx.http
      .post('/api/v1/auth/invitations/accept')
      .set(fromIp(uniqueIp()))
      .send({ token: invitationToken, password })
      .expect(204);
    await login(ctx, { email, password, organization: org.slug }).expect(200);

    const invited = await auditRows('user.invited', res.body.id);
    expect(invited).toHaveLength(1);
    expect(invited[0]).toMatchObject({ organizationId: org.id, actorType: 'user' });
    expect(ctx.logs.join('\n')).not.toContain(invitationToken!);

    await invite(token, { email, displayName: 'Again', roleKeys: ['read_only_user'] }).expect(409);
  });

  it('enforces max_users under the organization lock', async () => {
    const { org, token } = await orgWithAdmin();
    await ctx.prisma.organizationLimit.update({
      where: { organizationId_limitKey: { organizationId: org.id, limitKey: 'max_users' } },
      data: { limitValue: 3n },
    });
    // 1 admin + 2 invitations reach the limit of 3; the next one is refused.
    for (let i = 0; i < 2; i += 1) {
      await invite(token, {
        email: newEmail(),
        displayName: 'U',
        roleKeys: ['read_only_user'],
      }).expect(201);
    }
    const refused = await invite(token, {
      email: newEmail(),
      displayName: 'U',
      roleKeys: ['read_only_user'],
    }).expect(409);
    expect(refused.body.message).toBe('Organization limit reached: max_users');

    // Concurrent invitations cannot overshoot: deleting one frees exactly one slot.
    const list = await ctx.prisma.user.findMany({
      where: { organizationId: org.id, status: 'invited' },
      select: { publicId: true },
    });
    await ctx.http.delete(`/api/v1/users/${list[0]!.publicId}`).set(bearer(token)).expect(204);
    const results = await Promise.all(
      [0, 1, 2].map(() =>
        invite(token, { email: newEmail(), displayName: 'U', roleKeys: ['read_only_user'] }),
      ),
    );
    expect(results.map((r) => r.status).sort()).toEqual([201, 409, 409]);
    expect(
      await ctx.prisma.user.count({ where: { organizationId: org.id, deletedAt: null } }),
    ).toBe(3);
  });

  it('re-invites a deleted user (reinstated, credentials cleared) and resends invitations', async () => {
    const { org, token } = await orgWithAdmin();
    const former = await fx.createUser(org, { roles: ['read_only_user'], mfa: true });
    await ctx.http.delete(`/api/v1/users/${former.publicId}`).set(bearer(token)).expect(204);
    await ctx.http.get(`/api/v1/users/${former.publicId}`).set(bearer(token)).expect(404);

    const res = await invite(token, {
      email: former.email,
      displayName: 'Returning',
      roleKeys: ['domain_admin'],
    }).expect(201);
    expect(res.body).toMatchObject({ id: former.publicId, status: 'invited', mfaEnabled: false });
    const row = await ctx.prisma.user.findUniqueOrThrow({ where: { id: former.id } });
    expect(row).toMatchObject({ deletedAt: null, passwordHash: null, mfaSecretCiphertext: null });
    await loginAs(former).expect(401);

    const first = ctx.emails.tokenFor(former.email, 'invitation');
    const resent = await ctx.http
      .post(`/api/v1/users/${former.publicId}/invitation`)
      .set(idem())
      .set(bearer(token))
      .expect(202);
    expect(new Date(resent.body.expiresAt).getTime()).toBeGreaterThan(Date.now());
    const second = ctx.emails.tokenFor(former.email, 'invitation');
    expect(second).not.toBe(first);
    // The earlier link stopped working.
    await ctx.http
      .post('/api/v1/auth/invitations/inspect')
      .set(fromIp(uniqueIp()))
      .send({ token: first })
      .expect(400);
    expect(await auditRows('user.invitation_resent', former.publicId)).toHaveLength(1);

    const active = await fx.createUser(org, { roles: ['read_only_user'] });
    await ctx.http
      .post(`/api/v1/users/${active.publicId}/invitation`)
      .set(idem())
      .set(bearer(token))
      .expect(409);
  });
});

describe('roles of users', () => {
  it('denies escalation and platform roles in customer organizations', async () => {
    const { org, token } = await orgWithAdmin();
    await ctx.http
      .post('/api/v1/roles')
      .set(bearer(token))
      .send({
        key: 'user_manager',
        name: 'User manager',
        permissions: ['user:read', 'user:manage'],
      })
      .expect(201);
    const manager = await fx.createUser(org, { roles: ['user_manager'] });
    const managerToken = (await sessionOf(manager)).accessToken;

    const escalation = await invite(managerToken, {
      email: newEmail(),
      displayName: 'X',
      roleKeys: ['organization_admin'],
    }).expect(403);
    expect(escalation.body.message).toContain('organization_admin');
    await invite(managerToken, {
      email: newEmail(),
      displayName: 'X',
      roleKeys: ['user_manager'],
    }).expect(201);

    // Demoting someone with more permissions than the actor is escalation too.
    const analyst = await fx.createUser(org, { roles: ['security_analyst'] });
    await ctx.http
      .put(`/api/v1/users/${analyst.publicId}/roles`)
      .set(bearer(managerToken))
      .send({ roleKeys: ['user_manager'] })
      .expect(403);

    const platform = await invite(token, {
      email: newEmail(),
      displayName: 'X',
      roleKeys: ['platform_admin'],
    }).expect(400);
    expect(platform.body.message[0]).toContain('platform organization');
    await ctx.http
      .put(`/api/v1/users/${analyst.publicId}/roles`)
      .set(bearer(token))
      .send({ roleKeys: ['super_admin'] })
      .expect(400);
    await invite(token, { email: newEmail(), displayName: 'X', roleKeys: ['no_such_role'] }).expect(
      400,
    );
  });

  it('replaces roles, takes effect immediately and audits', async () => {
    const { org, token } = await orgWithAdmin();
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const userToken = (await sessionOf(user)).accessToken;
    await ctx.http.get('/api/v1/audit/login-events').set(bearer(userToken)).expect(403);

    const res = await ctx.http
      .put(`/api/v1/users/${user.publicId}/roles`)
      .set(bearer(token))
      .send({ roleKeys: ['compliance_auditor', 'read_only_user'] })
      .expect(200);
    expect(res.body.roles.map((r: { key: string }) => r.key)).toEqual([
      'compliance_auditor',
      'read_only_user',
    ]);
    await ctx.http.get('/api/v1/audit/login-events').set(bearer(userToken)).expect(200);
    const audit = await auditRows('user.roles_changed', user.publicId);
    expect(audit[0]?.metadata).toMatchObject({
      from: ['read_only_user'],
      to: ['compliance_auditor', 'read_only_user'],
    });
  });

  it('keeps the last active administrator', async () => {
    const { org, admin, token } = await orgWithAdmin();
    // Self role change that would leave no administrator.
    const res = await ctx.http
      .put(`/api/v1/users/${admin.publicId}/roles`)
      .set(bearer(token))
      .send({ roleKeys: ['read_only_user'] })
      .expect(409);
    expect(res.body.message).toBe('The organization must keep at least one active administrator');
    // Self suspension and deletion are refused outright.
    await ctx.http
      .patch(`/api/v1/users/${admin.publicId}/status`)
      .set(bearer(token))
      .send({ status: 'disabled', reason: 'Testing self-suspension' })
      .expect(409);
    await ctx.http.delete(`/api/v1/users/${admin.publicId}`).set(bearer(token)).expect(409);

    // An API key with user:manage cannot act on an administrator at all: the key lacks the
    // administrator's other permissions (target-side no escalation, D8).
    const created = await ctx.http
      .post('/api/v1/api-keys')
      .set(bearer(token))
      .send({ name: 'automation', scopes: ['user:read', 'user:manage'] })
      .expect(201);
    const key = apiKeyHeader(created.body.key as string);
    await ctx.http
      .patch(`/api/v1/users/${admin.publicId}/status`)
      .set(key)
      .send({ status: 'disabled', reason: 'Automation' })
      .expect(403);
    await ctx.http.delete(`/api/v1/users/${admin.publicId}`).set(key).expect(403);

    // With a second administrator, the first can be disabled (by the second).
    const second = await fx.createUser(org, { roles: ['organization_admin'], mfa: true });
    const secondToken = (await loginWithMfa(ctx, fx, second)).accessToken;
    await ctx.http
      .patch(`/api/v1/users/${admin.publicId}/status`)
      .set(bearer(secondToken))
      .send({ status: 'disabled', reason: 'Handover' })
      .expect(200);
    // …and now the second is the last one: giving up user:manage is refused.
    await ctx.http
      .put(`/api/v1/users/${second.publicId}/roles`)
      .set(bearer(secondToken))
      .send({ roleKeys: ['read_only_user'] })
      .expect(409);
  });
});

describe('status changes', () => {
  it('disabling revokes sessions immediately; re-activation allows login again', async () => {
    const { org, token } = await orgWithAdmin();
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const session = await sessionOf(user);
    await me(session.accessToken).expect(200);

    const res = await ctx.http
      .patch(`/api/v1/users/${user.publicId}/status`)
      .set(bearer(token))
      .send({ status: 'disabled', reason: 'Left the company' })
      .expect(200);
    expect(res.body).toMatchObject({ status: 'disabled', statusReason: 'Left the company' });
    await me(session.accessToken).expect(401);
    await ctx.http
      .post('/api/v1/auth/refresh')
      .set(fromIp(uniqueIp()))
      .send({ refreshToken: session.refreshToken })
      .expect(401);
    await loginAs(user).expect(401);

    await ctx.http
      .patch(`/api/v1/users/${user.publicId}/status`)
      .set(bearer(token))
      .send({ status: 'disabled', reason: 'Again' })
      .expect(409);
    await ctx.http
      .patch(`/api/v1/users/${user.publicId}/status`)
      .set(bearer(token))
      .send({ status: 'active' })
      .expect(200);
    await loginAs(user).expect(200);
    const audit = await auditRows('user.status_changed', user.publicId);
    expect(audit.map((r) => (r.metadata as { to: string }).to)).toEqual(['disabled', 'active']);
  });

  it('unlocks a locked-out account', async () => {
    const { org, token } = await orgWithAdmin();
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const ip = uniqueIp();
    for (let i = 0; i < 5; i += 1) {
      await login(
        ctx,
        { email: user.email, password: 'wrong-password-123', organization: org.slug },
        ip,
      ).expect(401);
    }
    await loginAs(user).expect(401);
    const locked = await ctx.http
      .get(`/api/v1/users/${user.publicId}`)
      .set(bearer(token))
      .expect(200);
    expect(locked.body.lockedUntil).not.toBeNull();

    const res = await ctx.http
      .patch(`/api/v1/users/${user.publicId}/status`)
      .set(bearer(token))
      .send({ status: 'active' })
      .expect(200);
    expect(res.body).toMatchObject({ status: 'active', lockedUntil: null });
    const row = await ctx.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(row).toMatchObject({ lockedUntil: null, failedLoginCount: 0 });
    expect(await ctx.kv.get(`auth:lockouts:${user.id}`)).toBeNull();
    await loginAs(user).expect(200);
  });

  it('disabling an invited user cancels the invitation', async () => {
    const { token } = await orgWithAdmin();
    const email = newEmail();
    const created = await invite(token, {
      email,
      displayName: 'Pending',
      roleKeys: ['read_only_user'],
    }).expect(201);
    const invitationToken = ctx.emails.tokenFor(email, 'invitation');
    await ctx.http
      .patch(`/api/v1/users/${created.body.id}/status`)
      .set(bearer(token))
      .send({ status: 'disabled', reason: 'Wrong person' })
      .expect(200);
    await ctx.http
      .post('/api/v1/auth/invitations/inspect')
      .set(fromIp(uniqueIp()))
      .send({ token: invitationToken })
      .expect(400);
    // Never activated: re-activation is refused (delete and invite again instead).
    await ctx.http
      .patch(`/api/v1/users/${created.body.id}/status`)
      .set(bearer(token))
      .send({ status: 'active' })
      .expect(409);
  });
});

describe('profile, deletion and MFA reset', () => {
  it('changes the email (verification sent to the new address, 409 on duplicates)', async () => {
    const { org, token } = await orgWithAdmin();
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const other = await fx.createUser(org, { roles: ['read_only_user'] });
    const email = newEmail();
    const res = await ctx.http
      .patch(`/api/v1/users/${user.publicId}`)
      .set(bearer(token))
      .send({ email, displayName: 'Renamed' })
      .expect(200);
    expect(res.body).toMatchObject({ email, displayName: 'Renamed', emailVerified: false });
    const verification = ctx.emails.tokenFor(email, 'email_verification');
    expect(verification).toMatch(/^egt_/);

    // No reset link goes to the new address until its owner has verified it (D11).
    const forgot = () =>
      ctx.http
        .post('/api/v1/auth/password/forgot')
        .set(fromIp(uniqueIp()))
        .send({ email, organization: org.slug })
        .expect(202);
    await forgot();
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(ctx.emails.tokenFor(email, 'password_reset')).toBeUndefined();
    await ctx.http
      .post('/api/v1/auth/email/verify')
      .set(fromIp(uniqueIp()))
      .send({ token: verification })
      .expect(204);
    await forgot();
    await expect.poll(() => ctx.emails.tokenFor(email, 'password_reset'), POLL).toBeDefined();

    await ctx.http
      .patch(`/api/v1/users/${user.publicId}`)
      .set(bearer(token))
      .send({ email: other.email })
      .expect(409);
    expect(await auditRows('user.updated', user.publicId)).toHaveLength(1);
  });

  it('soft-deletes: sessions revoked, hidden from lists and lookups', async () => {
    const { org, token } = await orgWithAdmin();
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const session = await sessionOf(user);
    await ctx.http.delete(`/api/v1/users/${user.publicId}`).set(bearer(token)).expect(204);
    await me(session.accessToken).expect(401);
    await ctx.http.delete(`/api/v1/users/${user.publicId}`).set(bearer(token)).expect(404);
    const row = await ctx.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(row.deletedAt).not.toBeNull();
    await expect
      .poll(async () => {
        const list = await ctx.http.get('/api/v1/users?limit=100').set(bearer(token));
        return (list.body.data as Array<{ id: string }>).map((u) => u.id);
      }, POLL)
      .not.toContain(user.publicId);
  });

  it('resets MFA with an MFA session only, revoking the target sessions', async () => {
    const { org, token } = await orgWithAdmin();
    const target = await fx.createUser(org, { roles: ['read_only_user'], mfa: true });
    const targetSession = await loginWithMfa(ctx, fx, target);

    // A password-only session of an admin without MFA is refused.
    const plainAdmin = await fx.createUser(org, { roles: ['organization_admin'] });
    const plain = await sessionOf(plainAdmin);
    const refused = await ctx.http
      .post(`/api/v1/users/${target.publicId}/mfa/reset`)
      .set(idem())
      .set(bearer(plain.accessToken))
      .expect(403);
    expect(refused.body.message).toBe('MFA required');

    await ctx.http
      .post(`/api/v1/users/${target.publicId}/mfa/reset`)
      .set(idem())
      .set(bearer(token))
      .expect(204);
    await me(targetSession.accessToken).expect(401);
    const row = await ctx.prisma.user.findUniqueOrThrow({ where: { id: target.id } });
    expect(row).toMatchObject({
      mfaEnabled: false,
      mfaSecretCiphertext: null,
      mfaLastUsedStep: null,
    });
    expect(await ctx.prisma.userMfaRecoveryCode.count({ where: { userId: target.id } })).toBe(0);
    // Password alone now suffices.
    const next = await loginAs(target).expect(200);
    expect(next.body.mfaRequired).toBeUndefined();
    expect(await auditRows('user.mfa_reset', target.publicId)).toHaveLength(1);
  });
});

describe('sessions of other users', () => {
  it('lists and revokes sessions (session:manage)', async () => {
    const { org, token } = await orgWithAdmin();
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const a = await sessionOf(user);
    const b = await sessionOf(user);

    await expect
      .poll(async () => {
        const res = await ctx.http
          .get(`/api/v1/users/${user.publicId}/sessions`)
          .set(bearer(token));
        return (res.body.data as Array<{ id: string }>).map((s) => s.id).sort();
      }, POLL)
      .toEqual([a.sessionId, b.sessionId].sort());

    await ctx.http
      .delete(`/api/v1/users/${user.publicId}/sessions/${a.sessionId}`)
      .set(bearer(token))
      .expect(204);
    await me(a.accessToken).expect(401);
    await me(b.accessToken).expect(200);
    await ctx.http
      .delete(`/api/v1/users/${user.publicId}/sessions/${a.sessionId}`)
      .set(bearer(token))
      .expect(404);

    await ctx.http.delete(`/api/v1/users/${user.publicId}/sessions`).set(bearer(token)).expect(204);
    await me(b.accessToken).expect(401);
    expect(await auditRows('session.revoked', a.sessionId)).toHaveLength(1);
    expect(await auditRows('session.revoked_all', user.publicId)).toHaveLength(1);

    // Users without session:manage cannot see them.
    const viewer = await fx.createUser(org, { roles: ['read_only_user'] });
    const viewerToken = (await sessionOf(viewer)).accessToken;
    await ctx.http
      .get(`/api/v1/users/${user.publicId}/sessions`)
      .set(bearer(viewerToken))
      .expect(403);
  });
});

describe('custom roles', () => {
  it('creates, lists, edits (effective immediately) and deletes custom roles', async () => {
    const { org, token } = await orgWithAdmin();
    const created = await ctx.http
      .post('/api/v1/roles')
      .set(bearer(token))
      .send({ key: 'mail_reviewer', name: 'Mail reviewer', permissions: ['message:read'] })
      .expect(201);
    expect(created.body).toMatchObject({
      key: 'mail_reviewer',
      system: false,
      permissions: ['message:read'],
    });
    expect(await auditRows('role.created', 'mail_reviewer')).not.toHaveLength(0);

    await expect
      .poll(async () => {
        const list = await ctx.http.get('/api/v1/roles').set(bearer(token));
        return (list.body.data as Array<{ key: string }>).map((r) => r.key);
      }, POLL)
      .toEqual(expect.arrayContaining(['organization_admin', 'read_only_user', 'mail_reviewer']));
    const list = await ctx.http.get('/api/v1/roles').set(bearer(token)).expect(200);
    const keys = (list.body.data as Array<{ key: string }>).map((r) => r.key);
    expect(keys).not.toContain('super_admin');
    expect(keys).not.toContain('platform_admin');
    await ctx.http.get('/api/v1/roles/super_admin').set(bearer(token)).expect(404);
    const perms = await ctx.http.get('/api/v1/permissions').set(bearer(token)).expect(200);
    expect(
      (perms.body.data as Array<{ key: string }>).some((p) => p.key.startsWith('platform:')),
    ).toBe(false);

    const holder = await fx.createUser(org, { roles: ['mail_reviewer'] });
    const holderToken = (await sessionOf(holder)).accessToken;
    await me(holderToken).expect(200); // caches the principal
    await ctx.http.get('/api/v1/audit/login-events').set(bearer(holderToken)).expect(403);
    await ctx.http
      .put('/api/v1/roles/mail_reviewer')
      .set(bearer(token))
      .send({ name: 'Mail reviewer', permissions: ['message:read', 'audit:read'] })
      .expect(200);
    await ctx.http.get('/api/v1/audit/login-events').set(bearer(holderToken)).expect(200);

    await ctx.http.delete('/api/v1/roles/mail_reviewer').set(bearer(token)).expect(409);
    await ctx.http
      .put(`/api/v1/users/${holder.publicId}/roles`)
      .set(bearer(token))
      .send({ roleKeys: ['read_only_user'] })
      .expect(200);
    await ctx.http.delete('/api/v1/roles/mail_reviewer').set(bearer(token)).expect(204);
    await ctx.http.get('/api/v1/roles/mail_reviewer').set(bearer(token)).expect(404);
  });

  it('protects system roles and validates custom role contents', async () => {
    const { token } = await orgWithAdmin();
    await ctx.http
      .put('/api/v1/roles/organization_admin')
      .set(bearer(token))
      .send({ name: 'Mine', permissions: ['user:read'] })
      .expect(409);
    await ctx.http.delete('/api/v1/roles/read_only_user').set(bearer(token)).expect(409);
    await ctx.http
      .post('/api/v1/roles')
      .set(bearer(token))
      .send({ key: 'domain_admin', name: 'Reserved', permissions: ['user:read'] })
      .expect(409);
    await ctx.http
      .post('/api/v1/roles')
      .set(bearer(token))
      .send({ key: 'sneaky_ops', name: 'Sneaky', permissions: ['platform:operations'] })
      .expect(400);
    await ctx.http
      .post('/api/v1/roles')
      .set(bearer(token))
      .send({ key: 'dup_role', name: 'Dup', permissions: ['user:read'] })
      .expect(201);
    await ctx.http
      .post('/api/v1/roles')
      .set(bearer(token))
      .send({ key: 'dup_role', name: 'Dup', permissions: ['user:read'] })
      .expect(409);
  });

  it('shows platform roles and permissions inside the platform organization', async () => {
    const operator = await fx.createPlatformUser(['super_admin']);
    const session = await loginWithMfa(ctx, fx, operator);
    await expect
      .poll(async () => {
        const res = await ctx.http.get('/api/v1/roles').set(bearer(session.accessToken));
        return (res.body.data as Array<{ key: string }>).map((r) => r.key);
      }, POLL)
      .toEqual(expect.arrayContaining(['super_admin', 'platform_admin']));
    const perms = await ctx.http
      .get('/api/v1/permissions')
      .set(bearer(session.accessToken))
      .expect(200);
    expect((perms.body.data as Array<{ key: string }>).map((p) => p.key)).toContain(
      'platform:tenant_override',
    );
  });
});

describe('API keys', () => {
  it('creates a key shown once that authenticates with its scopes only', async () => {
    const { org, admin, token } = await orgWithAdmin();
    const created = await ctx.http
      .post('/api/v1/api-keys')
      .set(bearer(token))
      .send({ name: 'directory sync', scopes: ['user:read', 'role:read'] })
      .expect(201);
    const key = created.body.key as string;
    expect(key).toMatch(/^egk_[0-9A-Za-z]{12}_[A-Za-z0-9_-]{43}$/);
    expect(created.body.apiKey).toMatchObject({
      name: 'directory sync',
      prefix: key.slice(0, 16),
      scopes: ['role:read', 'user:read'],
      createdBy: { id: admin.publicId, displayName: admin.displayName },
      revokedAt: null,
    });
    const expires = new Date(created.body.apiKey.expiresAt).getTime();
    expect(Math.abs(expires - (Date.now() + 365 * 86_400_000))).toBeLessThan(60_000);

    const row = await ctx.prisma.apiKey.findUniqueOrThrow({
      where: { publicId: created.body.apiKey.id },
    });
    expect(row.keyHash).toMatch(/^[0-9a-f]{64}$/);
    expect(row.keyHash).not.toContain(key.slice(17));

    // Shown once: never in lists, logs or audit rows.
    await expect
      .poll(async () => {
        const list = await ctx.http.get('/api/v1/api-keys').set(bearer(token));
        return (list.body.data as Array<{ id: string }>).map((k) => k.id);
      }, POLL)
      .toContain(created.body.apiKey.id);
    const list = await ctx.http.get('/api/v1/api-keys').set(bearer(token)).expect(200);
    expect(JSON.stringify(list.body)).not.toContain(key);
    expect(ctx.logs.join('\n')).not.toContain(key);
    const audit = await auditRows('apikey.created', created.body.apiKey.id);
    expect(audit).toHaveLength(1);
    expect(JSON.stringify(audit[0]!.metadata)).not.toContain(key);

    // Scopes are enforced.
    await expect
      .poll(async () => (await ctx.http.get('/api/v1/users').set(apiKeyHeader(key))).status, POLL)
      .toBe(200);
    await ctx.http.get('/api/v1/roles').set(apiKeyHeader(key)).expect(200);
    await ctx.http.get('/api/v1/api-keys').set(apiKeyHeader(key)).expect(403);
    await ctx.http
      .post('/api/v1/users/invitations')
      .set(idem())
      .set(apiKeyHeader(key))
      .send({ email: newEmail(), displayName: 'X', roleKeys: ['read_only_user'] })
      .expect(403);

    await expect
      .poll(
        async () =>
          (await ctx.prisma.apiKey.findUniqueOrThrow({ where: { id: row.id } })).lastUsedAt,
        POLL,
      )
      .not.toBeNull();
    expect(await ctx.prisma.apiKey.count({ where: { organizationId: org.id } })).toBe(1);
  });

  it('validates scopes and expiry', async () => {
    const { org, token } = await orgWithAdmin();
    for (const scopes of [['apikey:manage'], ['role:manage'], ['session:manage']]) {
      await ctx.http
        .post('/api/v1/api-keys')
        .set(bearer(token))
        .send({ name: 'bad', scopes })
        .expect(400);
    }
    await ctx.http
      .post('/api/v1/api-keys')
      .set(bearer(token))
      .send({ name: 'bad', scopes: ['platform:operations'] })
      .expect(400);
    await ctx.http
      .post('/api/v1/api-keys')
      .set(bearer(token))
      .send({
        name: 'bad',
        scopes: ['user:read'],
        expiresAt: new Date(Date.now() + 800 * 86_400_000).toISOString(),
      })
      .expect(400);

    // Only scopes the creator holds.
    await ctx.http
      .post('/api/v1/roles')
      .set(bearer(token))
      .send({ key: 'key_maker', name: 'Key maker', permissions: ['apikey:manage', 'user:read'] })
      .expect(201);
    const maker = await fx.createUser(org, { roles: ['key_maker'] });
    const makerToken = (await sessionOf(maker)).accessToken;
    await ctx.http
      .post('/api/v1/api-keys')
      .set(bearer(makerToken))
      .send({ name: 'too much', scopes: ['domain:manage'] })
      .expect(403);
    await ctx.http
      .post('/api/v1/api-keys')
      .set(bearer(makerToken))
      .send({ name: 'fine', scopes: ['user:read'] })
      .expect(201);
  });

  it('stops working when revoked, expired or when api_access is turned off', async () => {
    const { org, token } = await orgWithAdmin();
    const create = async () =>
      (
        await ctx.http
          .post('/api/v1/api-keys')
          .set(bearer(token))
          .send({ name: `k-${uniqueSuffix()}`, scopes: ['user:read'] })
          .expect(201)
      ).body as { key: string; apiKey: { id: string; prefix: string } };

    const revoked = await create();
    await ctx.http.get('/api/v1/users').set(apiKeyHeader(revoked.key)).expect(200);
    await ctx.http.delete(`/api/v1/api-keys/${revoked.apiKey.id}`).set(bearer(token)).expect(204);
    await ctx.http.get('/api/v1/users').set(apiKeyHeader(revoked.key)).expect(401);
    await ctx.http.delete(`/api/v1/api-keys/${revoked.apiKey.id}`).set(bearer(token)).expect(204);
    expect(await auditRows('apikey.revoked', revoked.apiKey.id)).toHaveLength(1);

    const expired = await create();
    await ctx.http.get('/api/v1/users').set(apiKeyHeader(expired.key)).expect(200);
    await ctx.prisma.apiKey.update({
      where: { publicId: expired.apiKey.id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    await ctx.kv.del(`auth:apikey:${expired.apiKey.prefix}`); // what the 60 s cache TTL does
    await ctx.http.get('/api/v1/users').set(apiKeyHeader(expired.key)).expect(401);

    const live = await create();
    await ctx.prisma.organizationFeature.update({
      where: { organizationId_featureKey: { organizationId: org.id, featureKey: 'api_access' } },
      data: { enabled: false },
    });
    await ctx.http.get('/api/v1/users').set(apiKeyHeader(live.key)).expect(401);
    const refused = await ctx.http
      .post('/api/v1/api-keys')
      .set(bearer(token))
      .send({ name: 'no access', scopes: ['user:read'] })
      .expect(403);
    expect(refused.body.message).toBe('API access is not enabled for this organization');
  });
});

describe('login events', () => {
  it('lists the organization login attempts with filters and pagination', async () => {
    const { org, token } = await orgWithAdmin();
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const ip = uniqueIp();
    await login(
      ctx,
      { email: user.email, password: 'wrong-password-123', organization: org.slug },
      ip,
    ).expect(401);
    await loginAs(user, ip).expect(200);

    type Event = {
      id: string;
      outcome: string;
      userId: string | null;
      email: string;
      ipAddress: string;
    };
    const events = async (query: string): Promise<Event[]> => {
      const res = await ctx.http.get(`/api/v1/audit/login-events${query}`).set(bearer(token));
      return (res.body.data ?? []) as Event[];
    };
    await expect
      .poll(async () => (await events(`?userId=${user.publicId}`)).map((e) => e.outcome), POLL)
      .toEqual(['success', 'failure']);
    const [success, failure] = await events(`?userId=${user.publicId}`);
    expect(success).toMatchObject({ userId: user.publicId, email: user.email, ipAddress: ip });
    expect(failure).toMatchObject({ outcome: 'failure', userId: user.publicId });
    expect(failure!.id).toMatch(/^\d+$/);
    expect(await events(`?userId=${user.publicId}&outcome=failure`)).toHaveLength(1);

    const first = await ctx.http
      .get(`/api/v1/audit/login-events?userId=${user.publicId}&limit=1`)
      .set(bearer(token))
      .expect(200);
    expect(first.body.data).toHaveLength(1);
    const second = await ctx.http
      .get(
        `/api/v1/audit/login-events?userId=${user.publicId}&limit=1&cursor=${first.body.nextCursor}`,
      )
      .set(bearer(token))
      .expect(200);
    expect(second.body.data[0].id).toBe(failure!.id);

    const past = new Date(Date.now() - 30 * 86_400_000).toISOString();
    expect(await events(`?userId=${user.publicId}&to=${past}`)).toEqual([]);
    await ctx.http
      .get(
        `/api/v1/audit/login-events?from=${new Date(Date.now() - 91 * 86_400_000).toISOString()}`,
      )
      .set(bearer(token))
      .expect(400);
    await ctx.http.get('/api/v1/audit/login-events?cursor=bogus').set(bearer(token)).expect(400);
  });
});
