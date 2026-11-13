/**
 * Tenant isolation of the step 6.2 routes (§2.0 invariant 2, §10.3) with real sessions and API
 * keys against MySQL and Redis: organization A (an admin user and a manage API key) gets `404`
 * for every subscription, delivery and replay id of organization B — on every webhook route,
 * read or write — and `422 webhook_filter_invalid` for B's domain ids in filters; A's lists never
 * contain B's rows; A's cursors are refused for B; the same Idempotency-Key used by both
 * organizations never replays the other's response; notification settings are per organization.
 * B's rows are unchanged afterwards.
 */
// @covers get /api/v1/webhooks
// @covers post /api/v1/webhooks
// @covers get /api/v1/webhooks/:webhookId
// @covers patch /api/v1/webhooks/:webhookId
// @covers delete /api/v1/webhooks/:webhookId
// @covers post /api/v1/webhooks/:webhookId/rotate-secret
// @covers post /api/v1/webhooks/:webhookId/test
// @covers get /api/v1/webhooks/:webhookId/deliveries
// @covers get /api/v1/webhooks/:webhookId/deliveries/:deliveryId
// @covers post /api/v1/webhooks/:webhookId/deliveries/:deliveryId/replay
// @covers post /api/v1/webhooks/:webhookId/replays
// @covers get /api/v1/webhooks/:webhookId/replays/:replayId
// @covers get /api/v1/notifications/settings
// @covers put /api/v1/notifications/settings
import { randomUUID } from 'node:crypto';
import { isWebhookSecret } from '@email-gateway/webhooks';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa } from './support/http';
import { POLL } from './support/messages-data';
import {
  createBody,
  http,
  type SeededDelivery,
  seedDelivery,
  subscriptionRow,
  WEBHOOKS,
  bodyOf,
} from './support/webhooks';

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: ReturnType<typeof http>;
let keyA: ReturnType<typeof http>;
let adminB: ReturnType<typeof http>;
let hookA: string;
let hookB: string;
let deliveryA: SeededDelivery;
let deliveryB: SeededDelivery;
let replayB: string;
let domainB: string;

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  const userA = await fx.createUser(orgA, { roles: ['organization_admin'] });
  const userB = await fx.createUser(orgB, { roles: ['organization_admin'] });
  adminA = http(ctx, bearer((await loginWithMfa(ctx, fx, userA)).accessToken));
  adminB = http(ctx, bearer((await loginWithMfa(ctx, fx, userB)).accessToken));
  keyA = http(
    ctx,
    apiKeyHeader(
      await fx.createApiKey(orgA, [
        'webhook:read',
        'webhook:manage',
        'organization:read',
        'settings:manage',
      ]),
    ),
  );
  hookA = (await adminA.post(WEBHOOKS, createBody(), `it-${randomUUID()}`)).body.id;
  hookB = (await adminB.post(WEBHOOKS, createBody(), `it-${randomUUID()}`)).body.id;
  const subA = await subscriptionRow(ctx, hookA);
  const subB = await subscriptionRow(ctx, hookB);
  const now = Date.now();
  deliveryA = await seedDelivery(ctx, subA, {
    occurredAt: new Date(now - 60_000),
    organizationPublicId: orgA.publicId,
    status: 'dead',
  });
  deliveryB = await seedDelivery(ctx, subB, {
    occurredAt: new Date(now - 60_000),
    organizationPublicId: orgB.publicId,
    status: 'dead',
  });
  replayB = (
    await adminB.post(
      `${WEBHOOKS}/${hookB}/replays`,
      { from: new Date(now - 3_600_000).toISOString(), to: new Date(now).toISOString() },
      `it-${randomUUID()}`,
    )
  ).body.replayId;
  domainB = (
    await ctx.prisma.domain.create({
      data: { organizationId: orgB.id, name: `iso-${randomUUID().slice(0, 8)}.example.org` },
      select: { publicId: true },
    })
  ).publicId;
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('webhooks: cross-tenant isolation', () => {
  it('answers 404 for every B id on every webhook route (admin user and API key)', async () => {
    const before = await subscriptionRow(ctx, hookB);
    for (const client of [adminA, keyA]) {
      const k = () => `it-${randomUUID()}`;
      const results = [
        await client.get(`${WEBHOOKS}/${hookB}`),
        await client.patch(`${WEBHOOKS}/${hookB}`, { expectedRowVersion: 1, name: 'pwned' }),
        await client.delete(`${WEBHOOKS}/${hookB}`, k()),
        await client.post(`${WEBHOOKS}/${hookB}/rotate-secret`, {}, k()),
        await client.post(`${WEBHOOKS}/${hookB}/test`),
        await client.get(`${WEBHOOKS}/${hookB}/deliveries`),
        await client.get(`${WEBHOOKS}/${hookB}/deliveries/${deliveryB.publicId}`),
        await client.post(`${WEBHOOKS}/${hookB}/deliveries/${deliveryB.publicId}/replay`, {}, k()),
        await client.post(
          `${WEBHOOKS}/${hookB}/replays`,
          { from: new Date(Date.now() - 3_600_000).toISOString(), to: new Date().toISOString() },
          k(),
        ),
        await client.get(`${WEBHOOKS}/${hookB}/replays/${replayB}`),
      ];
      for (const [index, res] of results.entries()) {
        expect(res.status, `request ${index}`).toBe(404);
        expect(res.body.code).toBe('webhook_not_found');
      }
      // B's delivery and replay ids under A's own webhook are unknown too.
      const underA = [
        await client.get(`${WEBHOOKS}/${hookA}/deliveries/${deliveryB.publicId}`),
        await client.post(`${WEBHOOKS}/${hookA}/deliveries/${deliveryB.publicId}/replay`, {}, k()),
      ];
      for (const res of underA) {
        expect(res.status).toBe(404);
        expect(res.body.code).toBe('webhook_delivery_not_found');
      }
      const replay = await client.get(`${WEBHOOKS}/${hookA}/replays/${replayB}`);
      expect(replay.status).toBe(404);
      expect(replay.body.code).toBe('webhook_replay_not_found');
    }
    const after = await subscriptionRow(ctx, hookB);
    expect(after).toEqual(before);
    expect(await ctx.prisma.webhookDelivery.count({ where: { subscriptionId: after.id } })).toBe(1);
    expect(await ctx.prisma.webhookReplay.count({ where: { subscriptionId: after.id } })).toBe(1);
  });

  it('never lists B rows for A, and refuses B’s domain ids in A’s filters', async () => {
    await expect
      .poll(
        async () =>
          bodyOf(await keyA.get(`${WEBHOOKS}?limit=100&status=active,paused,disabled,deleted`)).data
            ?.length,
        POLL,
      )
      .toBe(1);
    const list = await keyA.get(`${WEBHOOKS}?limit=100&status=active,paused,disabled,deleted`);
    expect(list.body.data.map((w: { id: string }) => w.id)).toEqual([hookA]);
    await expect
      .poll(
        async () => bodyOf(await keyA.get(`${WEBHOOKS}/${hookA}/deliveries`)).data?.length,
        POLL,
      )
      .toBe(1);
    const deliveries = await keyA.get(`${WEBHOOKS}/${hookA}/deliveries`);
    expect(deliveries.body.data.map((d: { id: string }) => d.id)).toEqual([deliveryA.publicId]);
    const filter = await adminA.post(
      WEBHOOKS,
      createBody({ filters: { domainIds: [domainB] } }),
      `it-${randomUUID()}`,
    );
    expect(filter.status).toBe(422);
    expect(filter.body.code).toBe('webhook_filter_invalid');
  });

  it('refuses A’s cursors for B', async () => {
    await adminA.post(WEBHOOKS, createBody(), `it-${randomUUID()}`);
    await expect
      .poll(async () => bodyOf(await adminA.get(`${WEBHOOKS}?limit=1`)).nextCursor, POLL)
      .toEqual(expect.any(String));
    const cursor = (await adminA.get(`${WEBHOOKS}?limit=1`)).body.nextCursor as string;
    const res = await adminB.get(`${WEBHOOKS}?limit=1&cursor=${encodeURIComponent(cursor)}`);
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('cursor_invalid');
  });

  it('never replays one organization’s response under the same Idempotency-Key of another', async () => {
    const key = `it-shared-${randomUUID()}`;
    const a = await adminA.post(WEBHOOKS, createBody({ name: 'A' }), key);
    expect(a.status).toBe(201);
    const b = await adminB.post(WEBHOOKS, createBody({ name: 'B' }), key);
    expect(b.status).toBe(201);
    expect(b.headers['idempotency-replayed']).toBeUndefined();
    expect(isWebhookSecret(b.body.secret)).toBe(true);
    expect(b.body.id).not.toBe(a.body.id);
    expect(b.body.name).toBe('B');
  });

  it('keeps notification settings per organization', async () => {
    const res = await keyA.put('/api/v1/notifications/settings', {
      settings: { alerts: { domainDnsFailed: { enabled: false } } },
      expectedRowVersion: 0,
    });
    expect(res.status).toBe(200);
    const b = await adminB.get('/api/v1/notifications/settings');
    expect(b.body).toMatchObject({ rowVersion: 0, stored: null });
    expect(
      await ctx.prisma.notificationSettings.count({ where: { organizationId: orgB.id } }),
    ).toBe(0);
  });
});
