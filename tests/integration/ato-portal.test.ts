import { hash } from 'argon2';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiBaseUrl, apiSession, type ApiSession } from './support/api-client';
import {
  atoOrganization,
  deleteAtoRows,
  purgeAtoQueues,
  saveAtoSettings,
  settleSettingsCache,
  waitForSignals,
} from './support/ato';
import { ManagementApi } from './support/broker';
import { waitFor } from './support/compose';
import { stack } from './support/env';
import { SmtpFixtures } from './support/smtp-fixtures';
import { assertStackReady, smtpStackGate } from './support/smtp-stack';

/**
 * Step 8.4 portal and API sign-in detection through the real api and ato-worker containers
 * (§10.5 `ato-portal`, D5, D7, D10): logins through the api with the trusted forwarder (the
 * admin portal BFF's headers, ADR-0060) carrying documentation-range client addresses. The
 * Compose ato-worker mounts the synthetic GeoIP databases (192.0.2.0/25 = IN, 198.51.100.0/24 =
 * GB) with the documentation-range test seam (local/ci only). Repeated failures raise A1, the
 * success after them A2, a success from another continent a minute later G2 (impossible travel),
 * and a refresh token presented twice K1 (the api audits the reuse with the system actor on the
 * session family; the worker attributes it to the family's user, step 8.4 WP6 fix).
 */
const gate = await smtpStackGate();
const fx = new SmtpFixtures();
const mgmt = new ManagementApi();
const vhost = stack.rabbitmqVhost();
let org: { id: bigint; slug: string };
let admin: ApiSession | undefined;
let user: { id: bigint; email: string; password: string };

const forwarderToken = () => {
  const token = process.env.API_TRUSTED_FORWARDER_TOKEN;
  if (!token) throw new Error('API_TRUSTED_FORWARDER_TOKEN must be set (see .env)');
  return token;
};

async function login(password: string, ip: string) {
  const res = await fetch(`${apiBaseUrl()}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-eg-client-ip': ip,
      'x-eg-forwarder-token': forwarderToken(),
    },
    body: JSON.stringify({ email: user.email, password, organization: org.slug }),
  });
  return {
    status: res.status,
    body: (await res.json().catch(() => ({}))) as Record<string, unknown>,
  };
}

async function refresh(refreshToken: string, ip: string) {
  const res = await fetch(`${apiBaseUrl()}/api/v1/auth/refresh`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-eg-client-ip': ip,
      'x-eg-forwarder-token': forwarderToken(),
    },
    body: JSON.stringify({ refreshToken }),
  });
  return {
    status: res.status,
    body: (await res.json().catch(() => ({}))) as Record<string, unknown>,
  };
}

async function gatewayAccount() {
  return waitFor(
    'the gateway_user account',
    () =>
      fx.prisma.atoAccount
        .findFirst({ where: { organizationId: org.id, kind: 'gateway_user', userId: user.id } })
        .then((r) => r ?? undefined),
    { timeoutMs: 120_000, intervalMs: 500 },
  );
}

beforeAll(async () => {
  assertStackReady(gate);
  org = await atoOrganization(fx, 'ato-portal');
  admin = await apiSession(fx.prisma, org, 'organization_admin');
  await saveAtoSettings(admin, {
    mode: 'monitor',
    learningDays: 0,
    rules: {
      'ato.auth.bruteforce': { params: { failures: 3, windowMinutes: 15 } },
      'ato.auth.success_after_failures': { params: { failures: 2, windowMinutes: 30 } },
    },
  });
  await settleSettingsCache();
  const password = `It-${randomBytes(18).toString('base64url')}!9a`;
  const email = `it-ato-${randomBytes(4).toString('hex')}@portal.integration.test`;
  const created = await fx.prisma.user.create({
    data: {
      organizationId: org.id,
      email,
      displayName: 'ATO portal stack test',
      status: 'active',
      emailVerifiedAt: new Date(),
      passwordHash: await hash(password.normalize('NFKC'), {
        type: 2,
        memoryCost: Number(process.env.AUTH_ARGON2_MEMORY_KIB ?? 19_456),
        timeCost: Number(process.env.AUTH_ARGON2_TIME_COST ?? 2),
        parallelism: Number(process.env.AUTH_ARGON2_PARALLELISM ?? 1),
      }),
    },
    select: { id: true },
  });
  const role = await fx.prisma.role.findFirstOrThrow({
    where: { key: 'security_analyst', organizationId: null },
    select: { id: true },
  });
  await fx.prisma.userRole.create({
    data: { userId: created.id, roleId: role.id, organizationId: org.id },
  });
  user = { id: created.id, email, password };
}, 300_000);

afterAll(async () => {
  if (gate.skip) return;
  await admin?.remove();
  if (user) {
    await fx.prisma.userSession.deleteMany({ where: { userId: user.id } });
    await fx.prisma.loginAuditLog.deleteMany({ where: { userId: user.id } });
    await fx.prisma.userRole.deleteMany({ where: { userId: user.id } });
    await fx.prisma.user.deleteMany({ where: { id: user.id } });
  }
  await deleteAtoRows(fx.prisma, org ? [org.id] : []);
  await fx.cleanup();
  await purgeAtoQueues(mgmt, vhost);
  await fx.prisma.$disconnect();
}, 300_000);

describe.skipIf(gate.skip)('ato stack: portal sign-ins', { timeout: 600_000 }, () => {
  it('failures then a success (A1, A2), travel IN → GB within a minute (G2), refresh-token reuse (K1)', async () => {
    const india = '192.0.2.10';
    const london = '198.51.100.20';
    for (let i = 0; i < 3; i += 1) {
      expect((await login(`${user.password}-wrong`, india)).status).toBe(401);
    }
    const first = await login(user.password, india);
    expect(first.status).toBe(200);
    // The login telemetry carries the forwarded address on the portal channel (D5).
    const audits = await fx.prisma.loginAuditLog.findMany({
      where: { userId: user.id },
      select: { outcome: true, ipAddress: true },
    });
    expect(audits.filter((a) => a.ipAddress === india).length).toBeGreaterThanOrEqual(4);

    const account = await gatewayAccount();
    await waitForSignals(fx.prisma, org.id, account.id, [
      'ato.auth.bruteforce',
      'ato.auth.success_after_failures',
    ]);
    const located = await waitFor(
      'a located auth event',
      () =>
        fx.prisma.atoAuthEvent
          .findFirst({ where: { organizationId: org.id, accountId: account.id, ipAddress: india } })
          .then((r) => (r?.countryCode ? r : undefined)),
      { timeoutMs: 60_000 },
    );
    expect(located).toMatchObject({ countryCode: 'IN', geoStatus: 'located' });

    await new Promise((r) => setTimeout(r, 30_000));
    const second = await login(user.password, london);
    expect(second.status).toBe(200);
    await waitForSignals(fx.prisma, org.id, account.id, ['ato.geo.impossible_travel']);

    // Refresh-token reuse: the spent token presented again revokes the family (K1).
    const spent = String(second.body.refreshToken);
    expect((await refresh(spent, london)).status).toBe(200);
    expect((await refresh(spent, london)).status).toBe(401);
    await waitFor(
      'the auth.refresh_token_reused audit row',
      async () =>
        (await fx.prisma.auditLog.count({
          where: { organizationId: org.id, action: 'auth.refresh_token_reused' },
        })) > 0
          ? true
          : undefined,
      { timeoutMs: 30_000 },
    );
    const [k1] = await waitForSignals(fx.prisma, org.id, account.id, [
      'ato.account.refresh_token_reuse',
    ]);
    expect(k1!.strength).toBe('strong');
    const fresh = await fx.prisma.atoAccount.findUniqueOrThrow({ where: { id: account.id } });
    expect(fresh.riskScore).toBeGreaterThanOrEqual(60);
    expect(fresh.activeIncidentId).not.toBeNull();
    // No password, token or attempted e-mail in the ATO rows.
    const events = await fx.prisma.atoAuthEvent.findMany({ where: { organizationId: org.id } });
    const text = JSON.stringify(events, (_k, v: unknown) =>
      typeof v === 'bigint' ? v.toString() : v,
    );
    expect(text).not.toContain(user.password);
    expect(text).not.toContain(user.email);
    expect(text).not.toContain(spent);
  });
});
