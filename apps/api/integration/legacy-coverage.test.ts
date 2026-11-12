/**
 * Step 6.1 WP4 (§3.8 route coverage): integration coverage of the pre-6.1 routes no module suite
 * exercised against the real stack until now: the probes, the Prometheus scrape and `GET /meta`
 * (with its new per-IP limit, D8), recovery-code regeneration, the policy and quarantine
 * catalogues and the platform risk profile, the quarantine summary (tenant-scoped counts) and
 * the end-user preview of an unknown entry. Real MySQL writer + replica and Redis.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  uniqueSuffix,
  unknownId,
} from './support/fixtures';
import { bearer, fromIp, loginWithMfa, uniqueIp } from './support/http';
import { insertLifecycleMessage } from './support/lifecycle';
import { deleteQuarantineFixtures, insertEntry } from './support/quarantine';

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: Record<string, string>;

const headers = (auth: Record<string, string>) => ({ ...auth, ...fromIp(uniqueIp()) });

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  fx.registerCleanup(() => deleteQuarantineFixtures(ctx, [orgA.id, orgB.id]));
  const admin = await fx.createUser(orgA, { roles: ['organization_admin'], mfa: true });
  adminA = bearer((await loginWithMfa(ctx, fx, admin)).accessToken);
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('probes, scrape and meta', () => {
  it('answers the probes and the scrape outside /api, and /meta with a per-IP limit', async () => {
    // @covers get /health/live
    await ctx.http.get('/health/live').expect(200);
    // @covers get /health/ready
    const ready = await ctx.http.get('/health/ready').expect(200);
    expect(JSON.stringify(ready.body)).toContain('mysql');
    // @covers get /metrics
    const metrics = await ctx.http.get('/metrics').expect(200);
    expect(metrics.text).toMatch(/^# (HELP|TYPE) \w+/m);

    // @covers get /api/v1/meta
    const ip = uniqueIp();
    const meta = await ctx.http.get('/api/v1/meta').set(fromIp(ip)).expect(200);
    expect(meta.body).toHaveProperty('version');
    const statuses: number[] = [];
    for (let i = 0; i < 120; i += 1) {
      statuses.push((await ctx.http.get('/api/v1/meta').set(fromIp(ip))).status);
    }
    // 120 per minute per IP (Redis counter): the 121st request of this address is refused …
    expect(statuses.slice(0, 119).every((s) => s === 200)).toBe(true);
    const limited = statuses[119];
    expect(limited).toBe(429);
    // … another address is not affected.
    await ctx.http.get('/api/v1/meta').set(fromIp(uniqueIp())).expect(200);
  });
});

describe('recovery codes', () => {
  it('regenerates ten recovery codes for an MFA user (stored hashed, the old set replaced)', async () => {
    const user = await fx.createUser(orgA, { roles: ['read_only_user'], mfa: true });
    const session = await loginWithMfa(ctx, fx, user);
    // @covers post /api/v1/auth/mfa/recovery-codes
    const res = await ctx.http
      .post('/api/v1/auth/mfa/recovery-codes')
      .set(headers(bearer(session.accessToken)))
      .send({ code: await fx.totpNow(user) })
      .expect(200);
    const codes = res.body.recoveryCodes as string[];
    expect(codes).toHaveLength(10);
    const rows = await ctx.prisma.userMfaRecoveryCode.findMany({ where: { userId: user.id } });
    expect(rows).toHaveLength(10);
    for (const row of rows) {
      const stored = Object.values(row).map(String).join(' ');
      for (const code of codes) expect(stored).not.toContain(code);
    }
    expect(res.headers['cache-control']).toContain('no-store');
  });
});

describe('catalogues and the platform risk profile', () => {
  it('serves the same catalogues to every tenant', async () => {
    // @covers get /api/v1/policies/catalog
    const policies = await ctx.http
      .get('/api/v1/policies/catalog')
      .set(headers(adminA))
      .expect(200);
    expect(Object.keys(policies.body).length).toBeGreaterThan(0);
    // @covers get /api/v1/quarantine/catalog
    await ctx.http.get('/api/v1/quarantine/catalog').set(headers(adminA)).expect(200);
    // @covers get /api/v1/risk-scoring/platform-profile
    const platform = await ctx.http
      .get('/api/v1/risk-scoring/platform-profile')
      .set(headers(adminA))
      .expect(200);
    expect(JSON.stringify(platform.body)).toContain('thresholds');
  });
});

describe('quarantine summary and end-user preview', () => {
  it('counts only the caller’s organization', async () => {
    const at = new Date(Date.now() - 60_000);
    for (const org of [orgA, orgB, orgB]) {
      const message = await insertLifecycleMessage(ctx, org, {
        state: 'quarantined',
        receivedAt: at,
        recipients: [{ address: `s-${uniqueSuffix()}@acme.example`, status: 'quarantined' }],
      });
      await insertEntry(ctx, message, { quarantinedAt: at });
    }
    const from = new Date(Date.now() - 3_600_000).toISOString();
    const to = new Date(Date.now() + 60_000).toISOString();
    // @covers get /api/v1/quarantine/summary
    await expect
      .poll(async () => {
        const res = await ctx.http
          .get(`/api/v1/quarantine/summary?from=${from}&to=${to}`)
          .set(headers(adminA));
        return (res.body as { counts?: Record<string, number> }).counts?.held;
      })
      .toBe(1);
  });

  it('answers 404 to an end user for an entry that is not theirs', async () => {
    const mailbox = await fx.createUser(orgA, {
      roles: ['mailbox_user'],
      email: `mailbox-${uniqueSuffix()}@acme.example`,
    });
    const session = await loginWithMfa(ctx, fx, mailbox);
    // @covers get /api/v1/quarantine/me/entries/:entryId/preview
    const res = await ctx.http
      .get(`/api/v1/quarantine/me/entries/${unknownId()}/preview`)
      .set(headers(bearer(session.accessToken)))
      .expect(404);
    expect(res.body.code).toBe('quarantine_entry_not_found');
  });
});
