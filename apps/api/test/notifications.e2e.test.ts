/**
 * The notification routes (step 6.2 N3, §6.1, §6.3) over HTTP with MySQL, Redis and S3 stubbed
 * and the notification repository replaced by an in-memory double: the resolved settings with
 * defaults and bounds, the strict settings document (`400 notification_settings_invalid`), the
 * CAS (`409 notification_settings_conflict`), the audit row with changed paths only, RBAC
 * (`organization:read` / `settings:manage`, users and API keys), the self-only preference center
 * (API keys refused), the quarantine digest opt-out rule, and the response headers. The real
 * writer and replica run in integration/notifications.test.ts.
 */
// @covers get /api/v1/notifications/settings
// @covers put /api/v1/notifications/settings
// @covers get /api/v1/notifications/preferences
// @covers put /api/v1/notifications/preferences
import { NOTIFICATION_SETTINGS_DEFAULTS, PREFERENCE_KINDS } from '@email-gateway/webhooks';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { buildOpenApiDocument } from '../src/http/openapi';
import { createStubbedApiApp, immediateRunner, type StubbedApiApp } from './support/api-test-app';
import type { OpenApiOperation } from './support/messages-fixtures';
import { TransactionRunner } from '../src/database/transaction-runner';
import {
  overrideWebhooks,
  RecordingAuditService,
  WebhooksWorld,
} from './support/webhooks-fixtures';

const SETTINGS = '/api/v1/notifications/settings';
const PREFS = '/api/v1/notifications/preferences';
const USER_ID = 10n;

describe('notifications (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const world = new WebhooksWorld();
  const audit = new RecordingAuditService();

  beforeAll(async () => {
    api = await createStubbedApiApp(
      {},
      {
        override: (b) =>
          overrideWebhooks(b, world, audit)
            .overrideProvider(TransactionRunner)
            .useValue(immediateRunner),
      },
    );
  });

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    world.reset();
    audit.entries.length = 0;
    api.principals.apiKeyWith([]);
  });

  const as = async (permissions: string[]) => api.principals.user(permissions).bearer();
  const put = async (body: unknown, perms = ['settings:manage']) =>
    api
      .http()
      .put(SETTINGS)
      .set(await as(perms))
      .send(body as object);

  describe('settings', () => {
    it('resolves the defaults while nothing is stored (rowVersion 0)', async () => {
      const res = await api
        .http()
        .get(SETTINGS)
        .set(await as(['organization:read']));
      expect(res.status).toBe(200);
      expect(res.headers['cache-control']).toBe('no-store');
      expect(res.headers['x-request-id']).toEqual(expect.any(String));
      expect(res.body).toMatchObject({
        settings: JSON.parse(JSON.stringify(NOTIFICATION_SETTINGS_DEFAULTS)),
        stored: null,
        invalidStored: false,
        rowVersion: 0,
        updatedAt: null,
        bounds: { threatDetected: { minThrottleMinutes: 15, maxThrottleMinutes: 1440 } },
      });
    });

    it('replaces the document with CAS, audits changed paths only', async () => {
      const first = await put({
        settings: { alerts: { threatDetected: { minSeverity: 'medium', throttleMinutes: 30 } } },
        expectedRowVersion: 0,
      });
      expect(first.status).toBe(200);
      expect(first.body).toMatchObject({
        rowVersion: 1,
        stored: { alerts: { threatDetected: { minSeverity: 'medium', throttleMinutes: 30 } } },
        settings: {
          alerts: {
            threatDetected: { enabled: true, minSeverity: 'medium', throttleMinutes: 30 },
            domainDnsFailed: { enabled: true, throttleMinutes: 360 },
          },
        },
      });
      expect(audit.entries[0]).toMatchObject({
        action: 'notification.settings_updated',
        resourceType: 'notification_settings',
        metadata: {
          changedPaths: [
            'alerts.threatDetected.minSeverity',
            'alerts.threatDetected.throttleMinutes',
          ],
          settingsSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
          rowVersion: 1,
        },
      });
      const stale = await put({ settings: {}, expectedRowVersion: 0 });
      expect(stale.status).toBe(409);
      expect(stale.body).toMatchObject({
        code: 'notification_settings_conflict',
        currentRowVersion: 1,
      });
      const reset = await put({ settings: {}, expectedRowVersion: 1 });
      expect(reset.body).toMatchObject({ rowVersion: 2, stored: {} });
      expect(audit.entries[1]!.metadata).toMatchObject({
        changedPaths: [
          'alerts.threatDetected.minSeverity',
          'alerts.threatDetected.throttleMinutes',
        ],
      });
      const read = await api
        .http()
        .get(SETTINGS)
        .set(await as(['organization:read']));
      expect(read.body.rowVersion).toBe(2);
    });

    it('refuses invalid documents (notification_settings_invalid) and bad envelopes (validation_failed)', async () => {
      for (const settings of [
        { alerts: { threatDetected: { throttleMinutes: 5 } } },
        { alerts: { threatDetected: { minSeverity: 'low' } } },
        { alerts: { domainDnsFailed: { throttleMinutes: 20_000 } } },
        { alerts: { unknown: true } },
        { other: 1 },
        null,
      ]) {
        const res = await put({ settings, expectedRowVersion: 0 });
        expect(res.status, JSON.stringify(settings)).toBe(400);
        expect(res.body.code).toBe('notification_settings_invalid');
        expect(res.body.violations[0].path).toMatch(/^settings/);
      }
      for (const body of [
        {},
        { settings: {} },
        { settings: {}, expectedRowVersion: -1 },
        { settings: {}, expectedRowVersion: 0, extra: 1 },
      ]) {
        const res = await put(body);
        expect(res.status, JSON.stringify(body)).toBe(400);
        expect(res.body.code).toBe('validation_failed');
      }
      expect(world.settings.size).toBe(0);
    });

    it('RBAC: read needs organization:read, write settings:manage; API keys may use both', async () => {
      expect((await api.http().get(SETTINGS)).status).toBe(401);
      expect(
        (
          await api
            .http()
            .get(SETTINGS)
            .set(await as(['settings:manage']))
        ).status,
      ).toBe(403);
      expect(
        (await put({ settings: {}, expectedRowVersion: 0 }, ['organization:read'])).status,
      ).toBe(403);
      api.principals.apiKeyWith(['organization:read', 'settings:manage']);
      expect((await api.http().get(SETTINGS).set(api.principals.apiKeyHeaders)).status).toBe(200);
      const res = await api
        .http()
        .put(SETTINGS)
        .set(api.principals.apiKeyHeaders)
        .send({ settings: {}, expectedRowVersion: 0 });
      expect(res.status).toBe(200);
      expect(audit.entries[0]!.actor).toMatchObject({ type: 'api_key' });
    });
  });

  describe('preferences (self)', () => {
    it('reads and replaces the caller’s preferences and the digest opt-out', async () => {
      const bearer = await as([]);
      const empty = await api.http().get(PREFS).set(bearer);
      expect(empty.status).toBe(200);
      expect(empty.body).toEqual({
        optOut: [],
        quarantineDigestOptOut: false,
        quarantineDigestOptOutAllowed: true,
        kinds: [...PREFERENCE_KINDS],
        invalidStored: false,
      });
      const res = await api
        .http()
        .put(PREFS)
        .set(bearer)
        .send({ optOut: ['policy_alert', 'threat_detected'], quarantineDigestOptOut: true });
      expect(res.status).toBe(200);
      // Stored in catalogue order.
      expect(res.body).toMatchObject({
        optOut: ['threat_detected', 'policy_alert'],
        quarantineDigestOptOut: true,
      });
      expect(world.preferences.get(USER_ID)).toMatchObject({
        organizationId: api.principals.organizationId,
        preferences: { optOut: ['threat_detected', 'policy_alert'] },
      });
      expect(world.digest.get(USER_ID)).toMatchObject({ digestOptOut: true });
      expect(audit.entries[0]).toMatchObject({
        action: 'notification.preferences_updated',
        resourceId: api.principals.ids.user,
        metadata: {
          added: ['threat_detected', 'policy_alert'],
          removed: [],
          quarantineDigestOptOut: true,
        },
      });
      const read = await api.http().get(PREFS).set(bearer);
      expect(read.body).toMatchObject({
        optOut: ['threat_detected', 'policy_alert'],
        quarantineDigestOptOut: true,
      });
    });

    it('opting out of the digest needs digest.allowOptOut; opting back in always works', async () => {
      world.allowDigestOptOut = false;
      const bearer = await as([]);
      const refused = await api
        .http()
        .put(PREFS)
        .set(bearer)
        .send({ optOut: [], quarantineDigestOptOut: true });
      expect(refused.status).toBe(400);
      expect(refused.body.message[0]).toMatch(/quarantineDigestOptOut/);
      world.digest.set(USER_ID, {
        organizationId: api.principals.organizationId,
        digestOptOut: true,
      });
      const back = await api
        .http()
        .put(PREFS)
        .set(bearer)
        .send({ optOut: [], quarantineDigestOptOut: false });
      expect(back.status).toBe(200);
      expect(world.digest.get(USER_ID)!.digestOptOut).toBe(false);
    });

    it('validates strictly, refuses API keys and anonymous callers', async () => {
      const bearer = await as([]);
      for (const body of [
        {},
        { optOut: [] },
        { optOut: ['sender_rejected'], quarantineDigestOptOut: false },
        { optOut: ['policy_alert', 'policy_alert'], quarantineDigestOptOut: false },
        { optOut: [], quarantineDigestOptOut: 'yes' },
        { optOut: [], quarantineDigestOptOut: false, extra: 1 },
      ]) {
        const res = await api.http().put(PREFS).set(bearer).send(body);
        expect(res.status, JSON.stringify(body)).toBe(400);
        expect(res.body.code).toBe('validation_failed');
      }
      expect((await api.http().get(PREFS)).status).toBe(401);
      api.principals.apiKeyWith(['organization:read', 'settings:manage']);
      expect((await api.http().get(PREFS).set(api.principals.apiKeyHeaders)).status).toBe(403);
      expect(
        (
          await api
            .http()
            .put(PREFS)
            .set(api.principals.apiKeyHeaders)
            .send({ optOut: [], quarantineDigestOptOut: false })
        ).status,
      ).toBe(403);
      expect(world.preferences.size).toBe(0);
    });
  });

  it('documents the 4 operations with the notifications tag and examples', () => {
    const doc = buildOpenApiDocument(api.app);
    const settings = doc.paths[SETTINGS] as Record<string, OpenApiOperation>;
    const prefs = doc.paths[PREFS] as Record<string, OpenApiOperation>;
    for (const op of [settings.get!, settings.put!, prefs.get!, prefs.put!]) {
      expect(op.tags).toEqual(['notifications']);
      expect(op.responses['200']!.content['application/json']!.schema.example).toBeDefined();
    }
    expect(settings.put!['x-eg-permissions']).toEqual({
      mode: 'all',
      permissions: ['settings:manage'],
    });
    expect(prefs.put!['x-eg-permissions']).toBeUndefined();
    expect(settings.put!.responses['409']).toBeDefined();
  });
});
