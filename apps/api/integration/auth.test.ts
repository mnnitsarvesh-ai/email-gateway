import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateApiKey, TokenHasher } from '../src/crypto/tokens';
import { TransactionRunner } from '../src/database/transaction-runner';
import { InvitationService } from '../src/modules/auth/services/invitation.service';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
  strongPassword,
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
let org: FixtureOrganization;

const POLL = { timeout: 10_000, interval: 200 };

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
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

const me = (accessToken: string) => ctx.http.get('/api/v1/auth/me').set(bearer(accessToken));

const loginRows = (userId: bigint) =>
  ctx.prisma.loginAuditLog.findMany({ where: { userId }, orderBy: { id: 'asc' } });

const auditRows = (action: string, resourceId: string) =>
  ctx.prisma.auditLog.findMany({ where: { action, resourceId }, orderBy: { id: 'asc' } });

/** The captured logs must never contain any of these values. */
function expectNotLogged(...secrets: string[]): void {
  const all = ctx.logs.join('\n');
  for (const secret of secrets) expect(all.includes(secret)).toBe(false);
}

describe('login', () => {
  it('returns the token response and writes one success row', async () => {
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const res = await loginAs(user).expect(200);
    const body = res.body as TokenResponseBody;
    expect(body).toMatchObject({
      tokenType: 'Bearer',
      expiresIn: ctx.config.AUTH_ACCESS_TOKEN_TTL_SECONDS,
      mfaEnrollmentRequired: false,
      user: { id: user.publicId, email: user.email },
      organization: { id: org.publicId, slug: org.slug, kind: 'customer' },
    });
    expect(body.refreshToken).toMatch(/^egr_/);

    const profile = await me(body.accessToken).expect(200);
    expect(profile.body).toMatchObject({
      user: { id: user.publicId },
      roles: ['read_only_user'],
      session: { id: body.sessionId, mfaAuthenticated: false },
      override: null,
    });
    expect(profile.body.permissions).toContain('user:read');

    const rows = await loginRows(user.id);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      outcome: 'success',
      failureReason: null,
      emailAttempted: user.email,
    });
    expectNotLogged(user.password, body.refreshToken, body.accessToken);
  });

  it('answers every failure with the same generic 401 and audits the reason', async () => {
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const invited = await fx.createUser(org, { roles: ['read_only_user'], status: 'invited' });
    const disabled = await fx.createUser(org, { roles: ['read_only_user'], status: 'disabled' });

    const wrong = await login(ctx, { email: user.email, password: 'wrong-password-123' }).expect(
      401,
    );
    const unknown = await login(ctx, {
      email: `nobody-${user.publicId}@example.test`,
      password: 'whatever-password',
    }).expect(401);
    const notActivated = await login(ctx, {
      email: invited.email,
      password: 'anything-at-all',
    }).expect(401);
    const inactive = await loginAs(disabled).expect(401);
    for (const res of [wrong, unknown, notActivated, inactive]) {
      expect(res.body.message).toBe('Invalid credentials');
    }

    expect((await loginRows(user.id))[0]).toMatchObject({
      outcome: 'failure',
      failureReason: 'invalid_password',
    });
    expect((await loginRows(invited.id))[0]).toMatchObject({
      outcome: 'failure',
      failureReason: 'not_activated',
    });
    expect((await loginRows(disabled.id))[0]).toMatchObject({
      outcome: 'failure',
      failureReason: 'user_disabled',
    });
    const unknownRow = await ctx.prisma.loginAuditLog.findFirst({
      where: { emailAttempted: `nobody-${user.publicId}@example.test` },
    });
    expect(unknownRow).toMatchObject({
      outcome: 'failure',
      failureReason: 'unknown_account',
      userId: null,
    });
  });

  it('needs the organization slug when the email exists in several organizations', async () => {
    const other = await fx.createOrganization();
    const email = `shared-${other.slug}@example.test`;
    const a = await fx.createUser(org, { roles: ['read_only_user'], email });
    await fx.createUser(other, { roles: ['read_only_user'], email, password: a.password });
    await login(ctx, { email, password: a.password }).expect(401);
    const res = await login(ctx, { email, password: a.password, organization: other.slug }).expect(
      200,
    );
    expect(res.body.organization.id).toBe(other.publicId);
  });

  it('locks the account after 5 failures and mirrors the lock to users.locked_until', async () => {
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const ip = uniqueIp();
    for (let i = 0; i < 5; i += 1) {
      await login(ctx, { email: user.email, password: `wrong-password-${i}` }, ip).expect(401);
    }
    const row = await ctx.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(row.lockedUntil!.getTime()).toBeGreaterThan(Date.now() + 14 * 60_000);
    expect(row.failedLoginCount).toBe(5);

    // The right password is refused while locked, with the same answer.
    const res = await loginAs(user, ip).expect(401);
    expect(res.body.message).toBe('Invalid credentials');

    const rows = await loginRows(user.id);
    expect(rows.map((r) => r.failureReason)).toEqual([
      'invalid_password',
      'invalid_password',
      'invalid_password',
      'invalid_password',
      'lockout_started',
      'account_locked',
    ]);
    expect(rows[4]!.outcome).toBe('locked');
  });

  it('blocks an IP with too many failures (429, rate_limited row)', async () => {
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const ip = uniqueIp();
    await ctx.kv.set(`auth:fail:ip:${ip}`, String(ctx.config.AUTH_LOGIN_MAX_IP_FAILURES), 900);
    await loginAs(user, ip).expect(429);
    const row = await ctx.prisma.loginAuditLog.findFirst({
      where: { emailAttempted: user.email, ipAddress: ip },
    });
    expect(row).toMatchObject({ outcome: 'rate_limited', failureReason: 'ip_blocked' });
    await loginAs(user).expect(200);
  });
});

describe('sessions', () => {
  it('rotates refresh tokens and revokes the family when a rotated token is reused', async () => {
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const first = (await loginAs(user).expect(200)).body as TokenResponseBody;
    const second = (
      await ctx.http
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: first.refreshToken })
        .expect(200)
    ).body as TokenResponseBody;
    expect(second.refreshToken).not.toBe(first.refreshToken);
    expect(second.sessionId).toBe(first.sessionId);
    await me(second.accessToken).expect(200);

    // Reuse of the rotated token: 401, the whole family dies, including the new token.
    await ctx.http
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: first.refreshToken })
      .expect(401);
    await ctx.http
      .post('/api/v1/auth/refresh')
      .send({ refreshToken: second.refreshToken })
      .expect(401);
    await me(second.accessToken).expect(401);

    const rows = await ctx.prisma.userSession.findMany({ where: { familyId: first.sessionId } });
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => r.revokedAt !== null)).toBe(true);
    expect(rows.map((r) => r.revokedReason).sort()).toEqual(['reuse_detected', 'rotated']);
    const audit = await auditRows('auth.refresh_token_reused', first.sessionId);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ organizationId: org.id, actorType: 'system' });
    expectNotLogged(first.refreshToken, second.refreshToken);
  });

  it('logout invalidates the access token immediately; logout-all ends every session', async () => {
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const a = (await loginAs(user).expect(200)).body as TokenResponseBody;
    const b = (await loginAs(user).expect(200)).body as TokenResponseBody;
    const c = (await loginAs(user).expect(200)).body as TokenResponseBody;

    await expect
      .poll(async () => {
        const res = await ctx.http.get('/api/v1/auth/sessions').set(bearer(a.accessToken));
        return (res.body as { data?: unknown[] }).data?.length;
      }, POLL)
      .toBe(3);

    await ctx.http.post('/api/v1/auth/logout').set(bearer(a.accessToken)).expect(204);
    await me(a.accessToken).expect(401);
    await ctx.http.post('/api/v1/auth/refresh').send({ refreshToken: a.refreshToken }).expect(401);
    await me(b.accessToken).expect(200);

    await ctx.http
      .delete(`/api/v1/auth/sessions/${c.sessionId}`)
      .set(bearer(b.accessToken))
      .expect(204);
    await me(c.accessToken).expect(401);
    await ctx.http
      .delete(`/api/v1/auth/sessions/${c.sessionId}`)
      .set(bearer(b.accessToken))
      .expect(404);

    await ctx.http.post('/api/v1/auth/logout-all').set(bearer(b.accessToken)).expect(204);
    await me(b.accessToken).expect(401);
    expect(await auditRows('session.revoked_all', user.publicId)).toHaveLength(1);
    expect(await auditRows('session.revoked', c.sessionId)).toHaveLength(1);
  });
});

describe('password reset and change', () => {
  it('sends a single-use reset link that revokes every session', async () => {
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const session = (await loginAs(user).expect(200)).body as TokenResponseBody;

    await ctx.http
      .post('/api/v1/auth/password/forgot')
      .set(fromIp(uniqueIp()))
      .send({ email: user.email })
      .expect(202);
    await expect.poll(() => ctx.emails.tokenFor(user.email, 'password_reset'), POLL).toBeDefined();
    const email = ctx.emails.lastFor(user.email, 'password_reset')!;
    expect(email.devLink).toMatch(/\/auth\/reset-password#token=egt_/);
    const token = ctx.emails.tokenFor(user.email, 'password_reset')!;

    const newPassword = strongPassword();
    await ctx.http
      .post('/api/v1/auth/password/reset')
      .set(fromIp(uniqueIp()))
      .send({ token, newPassword: 'short' })
      .expect(400);
    await ctx.http
      .post('/api/v1/auth/password/reset')
      .set(fromIp(uniqueIp()))
      .send({ token, newPassword })
      .expect(204);
    await ctx.http
      .post('/api/v1/auth/password/reset')
      .set(fromIp(uniqueIp()))
      .send({ token, newPassword: strongPassword() })
      .expect(400);

    await me(session.accessToken).expect(401);
    await loginAs(user).expect(401);
    await loginAs({ ...user, password: newPassword }).expect(200);
    expect(await auditRows('auth.password_reset', user.publicId)).toHaveLength(1);
    expectNotLogged(token, newPassword);
  });

  it('answers 202 for unknown emails without sending anything', async () => {
    const before = ctx.emails.sent.length;
    await ctx.http
      .post('/api/v1/auth/password/forgot')
      .set(fromIp(uniqueIp()))
      .send({ email: `unknown-${org.slug}@example.test` })
      .expect(202);
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(ctx.emails.sent.length).toBe(before);
  });

  it('changes the password with the current one and keeps only the current session', async () => {
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const current = (await loginAs(user).expect(200)).body as TokenResponseBody;
    const other = (await loginAs(user).expect(200)).body as TokenResponseBody;
    const newPassword = strongPassword();
    await ctx.http
      .post('/api/v1/auth/password/change')
      .set(fromIp(uniqueIp()))
      .set(bearer(current.accessToken))
      .send({ currentPassword: 'not-the-password', newPassword })
      .expect(403);
    await ctx.http
      .post('/api/v1/auth/password/change')
      .set(fromIp(uniqueIp()))
      .set(bearer(current.accessToken))
      .send({ currentPassword: user.password, newPassword: user.email })
      .expect(400);
    await ctx.http
      .post('/api/v1/auth/password/change')
      .set(fromIp(uniqueIp()))
      .set(bearer(current.accessToken))
      .send({ currentPassword: user.password, newPassword })
      .expect(204);
    await me(current.accessToken).expect(200);
    await me(other.accessToken).expect(401);
    await loginAs({ ...user, password: newPassword }).expect(200);
  });
});

describe('email verification and invitations', () => {
  it('verifies the email address with a single-use token', async () => {
    const user = await fx.createUser(org, { roles: ['read_only_user'], emailVerified: false });
    const session = (await loginAs(user).expect(200)).body as TokenResponseBody;
    await ctx.http
      .post('/api/v1/auth/email/verification')
      .set(fromIp(uniqueIp()))
      .set(bearer(session.accessToken))
      .expect(202);
    const token = ctx.emails.tokenFor(user.email, 'email_verification');
    expect(token).toMatch(/^egt_/);

    await ctx.http
      .post('/api/v1/auth/email/verify')
      .set(fromIp(uniqueIp()))
      .send({ token })
      .expect(204);
    await ctx.http
      .post('/api/v1/auth/email/verify')
      .set(fromIp(uniqueIp()))
      .send({ token })
      .expect(400);
    const row = await ctx.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(row.emailVerifiedAt).not.toBeNull();
    expect((await me(session.accessToken).expect(200)).body.emailVerified).toBe(true);
    expect(await auditRows('auth.email_verified', user.publicId)).toHaveLength(1);
  });

  it('accepts an invitation: password set, user active, email verified', async () => {
    const invited = await fx.createUser(org, { roles: ['read_only_user'], status: 'invited' });
    const invitations = ctx.get(InvitationService);
    const issued = await ctx.get(TransactionRunner).run((tx) =>
      invitations.createToken(tx, {
        userId: invited.id,
        organizationId: org.id,
        createdByUserId: null,
      }),
    );
    expect(
      await invitations.sendInvitation({
        email: invited.email,
        displayName: invited.displayName,
        organizationName: org.name,
        token: issued.token,
        expiresAt: issued.expiresAt,
      }),
    ).toBe(true);
    const token = ctx.emails.tokenFor(invited.email, 'invitation')!;
    expect(token).toBe(issued.token);

    const inspect = await ctx.http
      .post('/api/v1/auth/invitations/inspect')
      .set(fromIp(uniqueIp()))
      .send({ token })
      .expect(200);
    expect(inspect.body).toEqual({
      email: invited.email,
      organizationName: org.name,
      expiresAt: issued.expiresAt.toISOString(),
    });

    const password = strongPassword();
    await ctx.http
      .post('/api/v1/auth/invitations/accept')
      .set(fromIp(uniqueIp()))
      .send({ token, password, displayName: 'Accepted User' })
      .expect(204);
    await ctx.http
      .post('/api/v1/auth/invitations/accept')
      .set(fromIp(uniqueIp()))
      .send({ token, password: strongPassword() })
      .expect(400);

    const row = await ctx.prisma.user.findUniqueOrThrow({ where: { id: invited.id } });
    expect(row).toMatchObject({ status: 'active', displayName: 'Accepted User' });
    expect(row.emailVerifiedAt).not.toBeNull();
    await loginAs({ ...invited, password }).expect(200);
    expect(await auditRows('user.invitation_accepted', invited.publicId)).toHaveLength(1);
    expectNotLogged(token, password);
  });
});

describe('MFA', () => {
  it('enrolls, then requires TOTP at login; codes cannot be replayed; recovery codes work once', async () => {
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const s1 = (await loginAs(user).expect(200)).body as TokenResponseBody;
    const s2 = (await loginAs(user).expect(200)).body as TokenResponseBody;

    const setup = await ctx.http
      .post('/api/v1/auth/mfa/totp/setup')
      .set(bearer(s1.accessToken))
      .expect(200);
    expect(setup.body.otpauthUri).toMatch(/^otpauth:\/\/totp\//);
    const secret: string = setup.body.secret;
    await ctx.http
      .post('/api/v1/auth/mfa/totp/enable')
      .set(fromIp(uniqueIp()))
      .set(bearer(s1.accessToken))
      .send({ code: '000000' })
      .expect(403);
    const enable = await ctx.http
      .post('/api/v1/auth/mfa/totp/enable')
      .set(fromIp(uniqueIp()))
      .set(bearer(s1.accessToken))
      .send({ code: await fx.totpFor(secret) })
      .expect(200);
    const recoveryCodes: string[] = enable.body.recoveryCodes;
    expect(recoveryCodes).toHaveLength(10);
    await me(s1.accessToken).expect(200);
    await me(s2.accessToken).expect(401);
    expect(await auditRows('auth.mfa_enabled', user.publicId)).toHaveLength(1);

    // Login now needs the second factor.
    const ip = uniqueIp();
    const challenge = await loginAs(user, ip).expect(200);
    expect(challenge.body).toMatchObject({ mfaRequired: true, expiresIn: 300 });
    expect(challenge.body.accessToken).toBeUndefined();
    const code = await fx.totpFor(secret);
    const verified = await ctx.http
      .post('/api/v1/auth/mfa/verify')
      .set(fromIp(ip))
      .send({ mfaToken: challenge.body.mfaToken, code })
      .expect(200);
    expect((await me(verified.body.accessToken).expect(200)).body.session.mfaAuthenticated).toBe(
      true,
    );
    // The challenge is single use.
    await ctx.http
      .post('/api/v1/auth/mfa/verify')
      .set(fromIp(ip))
      .send({ mfaToken: challenge.body.mfaToken, code: await fx.totpFor(secret) })
      .expect(401);

    // Replay of an accepted code is rejected.
    const again = await loginAs(user, ip).expect(200);
    await ctx.http
      .post('/api/v1/auth/mfa/verify')
      .set(fromIp(ip))
      .send({ mfaToken: again.body.mfaToken, code })
      .expect(401);

    // A recovery code works exactly once.
    await ctx.http
      .post('/api/v1/auth/mfa/verify')
      .set(fromIp(ip))
      .send({ mfaToken: again.body.mfaToken, recoveryCode: recoveryCodes[0]!.toUpperCase() })
      .expect(200);
    const third = await loginAs(user, ip).expect(200);
    await ctx.http
      .post('/api/v1/auth/mfa/verify')
      .set(fromIp(ip))
      .send({ mfaToken: third.body.mfaToken, recoveryCode: recoveryCodes[0] })
      .expect(401);

    const outcomes = (await loginRows(user.id)).map((r) => r.outcome);
    expect(outcomes.filter((o) => o === 'mfa_required')).toHaveLength(3);
    // The reused challenge is unknown, so its row has no user; replay and reused recovery code count.
    expect(outcomes.filter((o) => o === 'mfa_failure')).toHaveLength(2);
    expectNotLogged(secret, recoveryCodes[0]!, challenge.body.mfaToken);
  });

  it('restricts users of an MFA-required organization to enrollment until they enroll', async () => {
    const strict = await fx.createOrganization({ mfaRequired: true });
    const user = await fx.createUser(strict, { roles: ['organization_admin'] });
    const session = (await loginAs(user).expect(200)).body as TokenResponseBody;
    expect(session.mfaEnrollmentRequired).toBe(true);

    await me(session.accessToken).expect(200);
    await ctx.http.get('/api/v1/auth/sessions').set(bearer(session.accessToken)).expect(200);
    const blocked = await ctx.http
      .post('/api/v1/auth/password/change')
      .set(fromIp(uniqueIp()))
      .set(bearer(session.accessToken))
      .send({ currentPassword: user.password, newPassword: strongPassword() })
      .expect(403);
    expect(blocked.body.message).toBe('MFA enrollment required');

    const setup = await ctx.http
      .post('/api/v1/auth/mfa/totp/setup')
      .set(bearer(session.accessToken))
      .expect(200);
    await ctx.http
      .post('/api/v1/auth/mfa/totp/enable')
      .set(fromIp(uniqueIp()))
      .set(bearer(session.accessToken))
      .send({ code: await fx.totpFor(setup.body.secret) })
      .expect(200);
    // Enrolled: the same token is no longer restricted; MFA cannot be disabled here.
    expect((await me(session.accessToken).expect(200)).body.mfaEnrollmentRequired).toBe(false);
    await ctx.http
      .post('/api/v1/auth/mfa/totp/disable')
      .set(fromIp(uniqueIp()))
      .set(bearer(session.accessToken))
      .send({ password: user.password, code: await fx.totpFor(setup.body.secret) })
      .expect(409);
  });
});

describe('platform override', () => {
  let operator: FixtureUser;
  let target: FixtureOrganization;

  beforeAll(async () => {
    operator = await fx.createPlatformUser(['platform_admin']);
    target = await fx.createOrganization();
  });

  it('requires the override permission and an MFA session', async () => {
    const admin = await fx.createUser(org, { roles: ['organization_admin'] });
    const tenant = (await loginAs(admin).expect(200)).body as TokenResponseBody;
    await ctx.http
      .post('/api/v1/platform/overrides')
      .set(bearer(tenant.accessToken))
      .send({ organizationId: target.publicId, reason: 'Customer ticket 4711' })
      .expect(403);

    // A platform user without MFA is held at enrollment and cannot start an override.
    const noMfa = await fx.createPlatformUser(['platform_admin'], { mfa: false });
    const restricted = (await loginAs(noMfa).expect(200)).body as TokenResponseBody;
    expect(restricted.mfaEnrollmentRequired).toBe(true);
    await ctx.http
      .post('/api/v1/platform/overrides')
      .set(bearer(restricted.accessToken))
      .send({ organizationId: target.publicId, reason: 'Customer ticket 4711' })
      .expect(403);
  });

  it('is audited, scoped to the target, stripped of platform permissions and ends on DELETE', async () => {
    const session = await loginWithMfa(ctx, fx, operator);
    const started = await ctx.http
      .post('/api/v1/platform/overrides')
      .set(bearer(session.accessToken))
      .send({
        organizationId: target.publicId,
        reason: 'Customer ticket 4711',
        durationMinutes: 15,
      })
      .expect(201);
    const { overrideId, accessToken } = started.body as { overrideId: string; accessToken: string };
    expect(started.body.organization).toEqual({
      id: target.publicId,
      slug: target.slug,
      name: target.name,
    });
    expect(new Date(started.body.expiresAt).getTime()).toBeGreaterThan(Date.now() + 14 * 60_000);
    expect(started.body.refreshToken).toBeUndefined();

    const profile = (await me(accessToken).expect(200)).body;
    expect(profile.override).toMatchObject({ id: overrideId, organizationId: target.publicId });
    expect(profile.permissions.some((p: string) => p.startsWith('platform:'))).toBe(false);

    // Platform functions are not reachable with the override token.
    await ctx.http
      .post('/api/v1/platform/overrides')
      .set(bearer(accessToken))
      .send({ organizationId: target.publicId, reason: 'Nested override attempt' })
      .expect(403);

    const startedAudit = await auditRows('platform.override_started', target.publicId);
    expect(
      startedAudit.some((r) => (r.metadata as { overrideId?: string }).overrideId === overrideId),
    ).toBe(true);
    await expect
      .poll(async () => {
        const rows = await ctx.prisma.auditLog.findMany({
          where: { action: 'platform.override_request', organizationId: target.id },
        });
        return rows
          .map(
            (r) =>
              r.metadata as {
                overrideId: string;
                route: string;
                statusCode: number;
                method: string;
              },
          )
          .filter((m) => m.overrideId === overrideId)
          .map((m) => `${m.method} ${m.route} ${m.statusCode}`)
          .sort();
      }, POLL)
      .toEqual(['GET /api/v1/auth/me 200', 'POST /api/v1/platform/overrides 403']);

    await ctx.http
      .delete(`/api/v1/platform/overrides/${overrideId}`)
      .set(bearer(session.accessToken))
      .expect(204);
    await me(accessToken).expect(401);
    await ctx.http
      .delete(`/api/v1/platform/overrides/${overrideId}`)
      .set(bearer(session.accessToken))
      .expect(404);
    expect(await auditRows('platform.override_ended', target.publicId)).not.toHaveLength(0);
  });

  it('stops working when the override expires or the session is revoked', async () => {
    const session = await loginWithMfa(ctx, fx, operator);
    const start = () =>
      ctx.http
        .post('/api/v1/platform/overrides')
        .set(bearer(session.accessToken))
        .send({ organizationId: target.publicId, reason: 'Customer ticket 4712' })
        .expect(201);
    const expiring = (await start()).body as { overrideId: string; accessToken: string };
    await me(expiring.accessToken).expect(200);
    await ctx.kv.del(`auth:override:${expiring.overrideId}`); // what the TTL does at expiry
    await me(expiring.accessToken).expect(401);

    const revoked = (await start()).body as { overrideId: string; accessToken: string };
    await ctx.http.post('/api/v1/auth/logout').set(bearer(session.accessToken)).expect(204);
    await me(revoked.accessToken).expect(401);
  });
});

describe('API keys and credentials', () => {
  async function insertKey(
    organization: FixtureOrganization,
    overrides: { revokedAt?: Date } = {},
  ) {
    const { key, prefix } = generateApiKey();
    await ctx.prisma.apiKey.create({
      data: {
        organizationId: organization.id,
        name: `it-${prefix}`,
        keyPrefix: prefix,
        keyHash: ctx.get(TokenHasher).hmacHex(key),
        scopes: ['user:read', 'apikey:manage'],
        expiresAt: new Date(Date.now() + 86_400_000),
        ...overrides,
      },
    });
    return key;
  }

  it('authenticates API keys and enforces revocation and the api_access feature', async () => {
    const key = await insertKey(org);
    // Authenticated, but every self-service route is user-only.
    const res = await ctx.http.get('/api/v1/auth/me').set(apiKeyHeader(key)).expect(403);
    expect(res.body.message).toBe('This operation requires a user');
    await ctx.http
      .get('/api/v1/auth/me')
      .set(apiKeyHeader(`${key.slice(0, -2)}xx`))
      .expect(401);
    await ctx.http
      .get('/api/v1/auth/me')
      .set(apiKeyHeader(await insertKey(org, { revokedAt: new Date() })))
      .expect(401);

    const noApi = await fx.createOrganization({ features: { api_access: false } });
    await ctx.http
      .get('/api/v1/auth/me')
      .set(apiKeyHeader(await insertKey(noApi)))
      .expect(401);

    await expect
      .poll(
        async () =>
          (
            await ctx.prisma.apiKey.findFirst({
              where: { organizationId: org.id, revokedAt: null },
            })
          )?.lastUsedAt,
        POLL,
      )
      .not.toBeNull();
  });

  it('rejects requests that carry both a bearer token and an API key', async () => {
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const session = (await loginAs(user).expect(200)).body as TokenResponseBody;
    await ctx.http
      .get('/api/v1/auth/me')
      .set(bearer(session.accessToken))
      .set(apiKeyHeader(await insertKey(org)))
      .expect(401);
  });
});
