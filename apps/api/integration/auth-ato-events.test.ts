import { randomBytes } from 'node:crypto';
import { authAccountChangedV1, authLoginRecordedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuditService, SYSTEM_ACTOR } from '../src/audit/audit.service';
import { LoginAuditRepository } from '../src/modules/auth/repositories/login-audit.repository';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
  strongPassword,
} from './support/fixtures';
import { bearer, fromIp, login, type TokenResponseBody, uniqueIp } from './support/http';

/**
 * Step 8.4 D5 (WP3): the api's ATO signal producers against the real MySQL writer.
 *
 * - every `login_audit_logs` row has its `auth.login.recorded.v1` outbox row, written in the
 *   same transaction (both or neither), with the channel `portal` (trusted forwarder) or `api`;
 *   an unknown account's event goes to the platform organization;
 * - `AuditService.record` writes `auth.account.changed.v1` for the allow-listed actions of a
 *   tenant, with the audit row's id, and nothing for platform-only rows or other actions.
 *
 * Synthetic organizations and users only. The outbox rows written here are removed by the suite
 * (they would otherwise be published to `ato.events`).
 */
let ctx: IntegrationApp;
let fwd: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let platformId: bigint;
const token = randomBytes(24).toString('hex');
const outboxIds: bigint[] = [];

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fwd = await createIntegrationApp({ API_TRUSTED_FORWARDER_TOKEN: token });
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  const platform = await ctx.prisma.organization.findFirstOrThrow({
    where: { kind: 'platform' },
    select: { id: true },
  });
  platformId = platform.id;
});

afterAll(async () => {
  if (outboxIds.length > 0) {
    await ctx.prisma.messageOutbox.deleteMany({ where: { id: { in: outboxIds } } });
  }
  await fx?.cleanup();
  await fwd?.close();
  await ctx?.close();
});

/** The login event of one login row (tracked for cleanup). */
async function loginEvent(loginAuditId: bigint) {
  const rows = await ctx.prisma.messageOutbox.findMany({
    where: { aggregateType: 'login', aggregateId: loginAuditId.toString() },
  });
  outboxIds.push(...rows.map((row) => row.id));
  return rows;
}

async function accountChangeEvents(auditLogId: bigint) {
  const rows = await ctx.prisma.messageOutbox.findMany({
    where: { aggregateType: 'audit', aggregateId: auditLogId.toString() },
  });
  outboxIds.push(...rows.map((row) => row.id));
  return rows;
}

const loginRows = (where: { userId?: bigint; emailAttempted?: string }) =>
  ctx.prisma.loginAuditLog.findMany({ where, orderBy: { id: 'asc' } });

const loginAs = (app: IntegrationApp, user: FixtureUser, headers: Record<string, string> = {}) =>
  app.http
    .post('/api/v1/auth/login')
    .set({ ...fromIp(uniqueIp()), ...headers })
    .send({ email: user.email, password: user.password, organization: user.organization.slug });

describe('auth.login.recorded.v1 (step 8.4 D5)', () => {
  it('writes one event per login row with the user organization and channel api', async () => {
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    await loginAs(ctx, { ...user, password: 'wrong-password-123' }).expect(401);
    await loginAs(ctx, user).expect(200);
    const rows = await loginRows({ userId: user.id });
    expect(rows.map((r) => r.outcome)).toEqual(['failure', 'success']);
    for (const row of rows) {
      const [event] = await loginEvent(row.id);
      expect(event).toBeDefined();
      expect(event!.organizationId).toBe(org.id);
      expect(event!.eventType).toBe('auth.login.recorded.v1');
      const payload = authLoginRecordedV1.parse(event!.payload);
      expect(payload).toEqual({
        loginAuditId: row.id.toString(),
        occurredAt: row.createdAt.toISOString(),
        outcome: row.outcome,
        failureReason: row.failureReason,
        accountKnown: true,
        userId: user.id.toString(),
        channel: 'api',
      });
      // Ids and enums only: never the attempted e-mail, IP or user agent.
      const text = JSON.stringify(event!.payload);
      expect(text).not.toContain(user.email);
      expect(text).not.toContain(row.ipAddress ?? '\u0000');
    }
  });

  it('marks logins through the trusted forwarder as channel portal', async () => {
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    await loginAs(fwd, user, {
      'X-EG-Client-IP': uniqueIp(),
      'X-EG-Forwarder-Token': token,
    }).expect(200);
    // A wrong token is not the portal.
    await loginAs(fwd, user, {
      'X-EG-Client-IP': uniqueIp(),
      'X-EG-Forwarder-Token': `${token.slice(1)}0`,
    }).expect(200);
    const rows = await loginRows({ userId: user.id });
    const channels = [];
    for (const row of rows) {
      const [event] = await loginEvent(row.id);
      channels.push(authLoginRecordedV1.parse(event!.payload).channel);
    }
    expect(channels).toEqual(['portal', 'api']);
  });

  it('sends an unknown account to the platform organization (accountKnown false, no user id)', async () => {
    const email = `nobody-${randomBytes(6).toString('hex')}@example.test`;
    await login(ctx, { email, password: 'whatever-password' }).expect(401);
    const [row] = await loginRows({ emailAttempted: email });
    expect(row).toBeDefined();
    const [event] = await loginEvent(row!.id);
    expect(event!.organizationId).toBe(platformId);
    expect(authLoginRecordedV1.parse(event!.payload)).toMatchObject({
      outcome: 'failure',
      failureReason: 'unknown_account',
      accountKnown: false,
      userId: null,
    });
    expect(JSON.stringify(event!.payload)).not.toContain(email);
    await ctx.prisma.loginAuditLog.deleteMany({ where: { emailAttempted: email } });
  });

  it('writes both rows or neither (an event that cannot be formed rolls the row back)', async () => {
    const email = `atomic-${randomBytes(6).toString('hex')}@example.test`;
    const repository = ctx.app.get(LoginAuditRepository);
    await expect(
      repository.insert({
        organizationId: null,
        userId: null,
        emailAttempted: email,
        outcome: 'failure',
        // Not a contract code: the payload fails inside the transaction.
        failureReason: 'Not A Code' as never,
        ipAddress: null,
        userAgent: null,
      }),
    ).rejects.toThrow();
    expect(await loginRows({ emailAttempted: email })).toEqual([]);
  });
});

describe('auth.account.changed.v1 (step 8.4 D5)', () => {
  it('a password change writes the event with the audit row id in the same transaction', async () => {
    const user = await fx.createUser(org, { roles: ['read_only_user'] });
    const tokens = (await loginAs(ctx, user).expect(200)).body as TokenResponseBody;
    await ctx.http
      .post('/api/v1/auth/password/change')
      .set(fromIp(uniqueIp()))
      .set(bearer(tokens.accessToken))
      .send({ currentPassword: user.password, newPassword: strongPassword() })
      .expect(204);
    const [audit] = await ctx.prisma.auditLog.findMany({
      where: { action: 'auth.password_changed', resourceId: user.publicId },
    });
    expect(audit).toBeDefined();
    const [event] = await accountChangeEvents(audit!.id);
    expect(event!.organizationId).toBe(org.id);
    expect(event!.eventType).toBe('auth.account.changed.v1');
    expect(authAccountChangedV1.parse(event!.payload)).toEqual({
      auditLogId: audit!.id.toString(),
      auditCreatedAt: audit!.createdAt.toISOString(),
      action: 'auth.password_changed',
      actorType: 'user',
      actorPublicId: user.publicId,
      resourceType: audit!.resourceType,
      resourcePublicId: audit!.resourceId,
    });
  });

  it('writes no event for platform-only rows or actions outside the allow-list; rolls back with the caller', async () => {
    const auditService = ctx.app.get(AuditService);
    const resourceId = `it-${randomBytes(6).toString('hex')}`;
    await auditService.record({
      organizationId: null,
      actor: SYSTEM_ACTOR,
      action: 'auth.password_changed',
      resourceType: 'user',
      resourceId,
    });
    await auditService.record({
      organizationId: org.id,
      actor: SYSTEM_ACTOR,
      action: 'domain.created',
      resourceType: 'domain',
      resourceId,
    });
    const rows = await ctx.prisma.auditLog.findMany({ where: { resourceId } });
    expect(rows).toHaveLength(2);
    for (const row of rows) expect(await accountChangeEvents(row.id)).toEqual([]);

    // Inside a caller transaction that fails, neither row survives.
    const rolledBack = `it-${randomBytes(6).toString('hex')}`;
    await expect(
      ctx.prisma.$transaction(async (tx) => {
        await auditService.record(
          {
            organizationId: org.id,
            actor: SYSTEM_ACTOR,
            action: 'session.revoked_all',
            resourceType: 'user',
            resourceId: rolledBack,
          },
          tx,
        );
        throw new Error('caller failed');
      }),
    ).rejects.toThrow('caller failed');
    expect(await ctx.prisma.auditLog.findMany({ where: { resourceId: rolledBack } })).toEqual([]);
    const orphan = await ctx.prisma.messageOutbox.findMany({
      where: {
        aggregateType: 'audit',
        organizationId: org.id,
        eventType: 'auth.account.changed.v1',
      },
    });
    expect(
      orphan.filter(
        (row) => (row.payload as { resourcePublicId?: string }).resourcePublicId === rolledBack,
      ),
    ).toEqual([]);
  });
});
