/**
 * Notification settings and the preference center (step 6.2 N3, §6.1, §6.3) against the real
 * MySQL writer and replica: the defaults while nothing is stored, the strict document, the CAS
 * on `notification_settings.row_version` (also for concurrent writers), the canonical stored
 * document and its SHA-256, the audit rows with changed paths only, and the caller's own
 * preferences — opt-outs in `notification_user_preferences`, the digest opt-out in the very same
 * `quarantine_user_preferences.digest_opt_out` row the step 5.3 `/quarantine/me/preferences`
 * route reads and writes (both directions), the organization's `digest.allowOptOut`, API keys
 * refused.
 */
// @covers get /api/v1/notifications/settings
// @covers put /api/v1/notifications/settings
// @covers get /api/v1/notifications/preferences
// @covers put /api/v1/notifications/preferences
import { canonicalSettings } from '@email-gateway/webhooks';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
  uniqueSuffix,
} from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa } from './support/http';
import { POLL } from './support/messages-data';
import { bodyOf, http } from './support/webhooks';

const SETTINGS = '/api/v1/notifications/settings';
const PREFS = '/api/v1/notifications/preferences';

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let admin: ReturnType<typeof http>;
let mailboxUser: FixtureUser;
let mailbox: ReturnType<typeof http>;

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  // The quarantine settings row written below (FK RESTRICT on the organization).
  fx.registerCleanup(() =>
    ctx.prisma.quarantineSettings.deleteMany({ where: { organizationId: org.id } }),
  );
  const adminUser = await fx.createUser(org, { roles: ['organization_admin'] });
  admin = http(ctx, bearer((await loginWithMfa(ctx, fx, adminUser)).accessToken));
  mailboxUser = await fx.createUser(org, {
    roles: ['mailbox_user'],
    email: `mailbox-${uniqueSuffix()}@acme.example`,
  });
  mailbox = http(ctx, bearer((await loginWithMfa(ctx, fx, mailboxUser)).accessToken));
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('notification settings against the writer and replica', () => {
  it('serves the defaults while nothing is stored', async () => {
    const res = await admin.get(SETTINGS);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      rowVersion: 0,
      stored: null,
      invalidStored: false,
      settings: {
        alerts: { threatDetected: { enabled: true, minSeverity: 'high', throttleMinutes: 60 } },
      },
    });
  });

  it('stores the canonical document with CAS, audits changed paths, serializes concurrent writers', async () => {
    const doc = {
      alerts: {
        threatDetected: { throttleMinutes: 30, minSeverity: 'medium' },
        includeOrganizationContact: false,
      },
    };
    const res = await admin.put(SETTINGS, { settings: doc, expectedRowVersion: 0 });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ rowVersion: 1, stored: doc });
    const row = await ctx.prisma.notificationSettings.findUniqueOrThrow({
      where: { organizationId: org.id },
    });
    expect(row.settingsSha256).toBe(canonicalSettings(doc as never).sha256);
    expect(row.rowVersion).toBe(1);
    const audit = await ctx.prisma.auditLog.findMany({
      where: { organizationId: org.id, action: 'notification.settings_updated' },
    });
    expect(audit).toHaveLength(1);
    expect(audit[0]!.metadata).toMatchObject({
      changedPaths: [
        'alerts.includeOrganizationContact',
        'alerts.threatDetected.minSeverity',
        'alerts.threatDetected.throttleMinutes',
      ],
      rowVersion: 1,
    });
    // Two writers with the same expected version: exactly one wins.
    const [a, b] = await Promise.all([
      admin.put(SETTINGS, { settings: {}, expectedRowVersion: 1 }),
      admin.put(SETTINGS, { settings: { alerts: {} }, expectedRowVersion: 1 }),
    ]);
    expect([a.status, b.status].sort()).toEqual([200, 409]);
    expect([a, b].find((r) => r.status === 409)!.body).toMatchObject({
      code: 'notification_settings_conflict',
      currentRowVersion: 2,
    });
    await expect.poll(async () => bodyOf(await admin.get(SETTINGS)).rowVersion, POLL).toBe(2);
    const invalid = await admin.put(SETTINGS, {
      settings: { alerts: { webhookDisabled: { throttleMinutes: 59 } } },
      expectedRowVersion: 2,
    });
    expect(invalid.status).toBe(400);
    expect(invalid.body.code).toBe('notification_settings_invalid');
    expect(invalid.body.violations[0].path).toBe('settings.alerts.webhookDisabled.throttleMinutes');
  });

  it('RBAC: a mailbox user cannot read or write tenant settings; API keys with the permissions can', async () => {
    expect((await mailbox.get(SETTINGS)).status).toBe(403);
    const key = http(
      ctx,
      apiKeyHeader(await fx.createApiKey(org, ['organization:read', 'settings:manage'])),
    );
    const current = (await key.get(SETTINGS)).body.rowVersion as number;
    expect((await key.put(SETTINGS, { settings: {}, expectedRowVersion: current })).status).toBe(
      200,
    );
  });
});

describe('notification preferences (self) against the writer and replica', () => {
  it('stores opt-outs and shares the digest opt-out with /quarantine/me/preferences both ways', async () => {
    const empty = await mailbox.get(PREFS);
    expect(empty.status).toBe(200);
    expect(empty.body).toMatchObject({
      optOut: [],
      quarantineDigestOptOut: false,
      quarantineDigestOptOutAllowed: true,
    });
    const res = await mailbox.put(PREFS, {
      optOut: ['quarantine_admin_alert', 'threat_detected'],
      quarantineDigestOptOut: true,
    });
    expect(res.status).toBe(200);
    const row = await ctx.prisma.notificationUserPreference.findUniqueOrThrow({
      where: { userId: mailboxUser.id },
    });
    expect(row).toMatchObject({
      organizationId: org.id,
      preferences: { optOut: ['threat_detected', 'quarantine_admin_alert'] },
    });
    const digest = await ctx.prisma.quarantineUserPreference.findUniqueOrThrow({
      where: { userId: mailboxUser.id },
    });
    expect(digest.digestOptOut).toBe(true);
    // The 5.3 self route reads the same column ...
    await expect
      .poll(
        async () => bodyOf(await mailbox.get('/api/v1/quarantine/me/preferences')).digestOptOut,
        POLL,
      )
      .toBe(true);
    // ... and writes it.
    expect(
      (await mailbox.put('/api/v1/quarantine/me/preferences', { digestOptOut: false })).status,
    ).toBe(200);
    await expect
      .poll(async () => bodyOf(await mailbox.get(PREFS)).quarantineDigestOptOut, POLL)
      .toBe(false);
    const audit = await ctx.prisma.auditLog.findMany({
      where: { organizationId: org.id, action: 'notification.preferences_updated' },
    });
    expect(audit).toHaveLength(1);
    expect(audit[0]!.metadata).toMatchObject({
      added: ['threat_detected', 'quarantine_admin_alert'],
      quarantineDigestOptOut: true,
    });
  });

  it('refuses a digest opt-out the organization does not allow; API keys get 403', async () => {
    const qs = await admin.get('/api/v1/quarantine/settings');
    expect(
      (
        await admin.put('/api/v1/quarantine/settings', {
          settings: { digest: { allowOptOut: false } },
          expectedRowVersion: qs.body.rowVersion,
        })
      ).status,
    ).toBe(200);
    const refused = await mailbox.put(PREFS, { optOut: [], quarantineDigestOptOut: true });
    expect(refused.status).toBe(400);
    expect(
      (
        await ctx.prisma.quarantineUserPreference.findUniqueOrThrow({
          where: { userId: mailboxUser.id },
        })
      ).digestOptOut,
    ).toBe(false);
    const key = http(ctx, apiKeyHeader(await fx.createApiKey(org, ['organization:read'])));
    expect((await key.get(PREFS)).status).toBe(403);
    expect((await key.put(PREFS, { optOut: [], quarantineDigestOptOut: false })).status).toBe(403);
  });
});
