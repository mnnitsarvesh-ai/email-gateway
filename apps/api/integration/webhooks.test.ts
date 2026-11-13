/**
 * Webhook subscriptions (step 6.2 W5–W7, §6.1; ADR-0057) against the real MySQL writer and
 * replica and Redis: create with the secret shown once (the stored `secret_ciphertext` decrypts
 * with the shared cipher and the AAD of organization, subscription and version; the
 * `api_idempotency_keys` row holds the redacted response with `secret: null` and no `whsec_`;
 * the replay returns `secret: null`), the feature gate and the cap under the organization lock
 * (also for concurrent creations), filter domains resolved in the tenant scope, the v1 cursor
 * list with replica polling, detail, CAS `PATCH`, soft delete cancelling pending deliveries,
 * rotation with overlap (the previous ciphertext still decrypts with the previous version's
 * AAD), the catalogue, the audit rows (`urlHost` + `urlSha256`, never the URL or the secret) and
 * the logs (no `whsec_`).
 */
// @covers get /api/v1/webhooks
// @covers post /api/v1/webhooks
// @covers get /api/v1/webhooks/event-types
// @covers get /api/v1/webhooks/:webhookId
// @covers patch /api/v1/webhooks/:webhookId
// @covers delete /api/v1/webhooks/:webhookId
// @covers post /api/v1/webhooks/:webhookId/rotate-secret
import { createHash, randomUUID } from 'node:crypto';
import { isWebhookSecret, secretAad, WEBHOOK_ENVELOPE_TYPES } from '@email-gateway/webhooks';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa } from './support/http';
import { POLL } from './support/messages-data';
import {
  cipherOf,
  createBody,
  http,
  seedDelivery,
  subscriptionRow,
  webhookAudit,
  WEBHOOKS,
  bodyOf,
} from './support/webhooks';

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let admin: ReturnType<typeof http>;
let reader: ReturnType<typeof http>;
let manager: ReturnType<typeof http>;
let domainId: string;
const sha = (v: string) => createHash('sha256').update(v).digest('hex');

beforeAll(async () => {
  ctx = await createIntegrationApp({ WEBHOOK_MAX_SUBSCRIPTIONS_PER_ORG: '4' });
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  const user = await fx.createUser(org, { roles: ['organization_admin'] });
  admin = http(ctx, bearer((await loginWithMfa(ctx, fx, user)).accessToken));
  reader = http(ctx, apiKeyHeader(await fx.createApiKey(org, ['webhook:read'])));
  manager = http(ctx, apiKeyHeader(await fx.createApiKey(org, ['webhook:read', 'webhook:manage'])));
  const domain = await ctx.prisma.domain.create({
    data: { organizationId: org.id, name: `wh-${randomUUID().slice(0, 8)}.example.org` },
    select: { publicId: true },
  });
  domainId = domain.publicId;
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('webhook subscriptions against the writer and replica', () => {
  let created: { id: string; url: string; secret: string; rowVersion: number };

  it('creates with the secret once; ciphertext, idempotency row, replay, audit and logs keep it secret', async () => {
    const body = createBody({ filters: { domainIds: [domainId], minSeverity: 'low' } });
    const key = `it-${randomUUID()}`;
    const res = await admin.post(WEBHOOKS, body, key);
    expect(res.status).toBe(201);
    expect(isWebhookSecret(res.body.secret)).toBe(true);
    created = res.body;
    const row = await subscriptionRow(ctx, res.body.id);
    expect(row).toMatchObject({
      organizationId: org.id,
      status: 'active',
      secretVersion: 1,
      rowVersion: 1,
      url: body.url,
      eventTypes: ['email.received', 'domain.dns.failed'],
      filters: { domainIds: [domainId], minSeverity: 'low' },
    });
    expect(row.secretCiphertext).not.toContain(res.body.secret);
    const decrypted = cipherOf(ctx).decrypt(
      row.secretCiphertext,
      secretAad(org.id, res.body.id, 1),
    );
    expect(decrypted.plaintext).toBe(res.body.secret);
    // Another subscription's AAD never decrypts it.
    expect(() =>
      cipherOf(ctx).decrypt(row.secretCiphertext, secretAad(org.id, randomUUID(), 1)),
    ).toThrow();

    const stored = await ctx.prisma.apiIdempotencyKey.findFirstOrThrow({
      where: { organizationId: org.id, idempotencyKey: key },
    });
    expect(stored).toMatchObject({ operation: 'webhook.create', statusCode: 201 });
    expect((stored.response as { secret: unknown }).secret).toBeNull();
    expect(JSON.stringify(stored.response)).not.toContain('whsec_');

    const replay = await admin.post(WEBHOOKS, body, key);
    expect(replay.status).toBe(201);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual({ ...res.body, secret: null });
    expect(await ctx.prisma.webhookSubscription.count({ where: { organizationId: org.id } })).toBe(
      1,
    );

    const audit = await webhookAudit(ctx, res.body.id);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ action: 'webhook.created', actorType: 'user' });
    expect(audit[0]!.metadata).toMatchObject({
      urlHost: new URL(body.url).hostname,
      urlSha256: sha(new URL(body.url).href),
    });
    const auditText = JSON.stringify(audit[0]!.metadata);
    expect(auditText).not.toContain('whsec_');
    expect(auditText).not.toContain('token=');
    expect(ctx.logs.join('\n')).not.toContain('whsec_');
  });

  it('refuses a key reuse (422), a foreign/unknown filter domain (422) and URLs breaking the rules (422)', async () => {
    const key = `it-${randomUUID()}`;
    expect((await admin.post(WEBHOOKS, createBody(), key)).status).toBe(201);
    const reused = await admin.post(WEBHOOKS, createBody({ name: 'other' }), key);
    expect(reused.status).toBe(422);
    expect(reused.body.code).toBe('idempotency_key_reused');
    const other = await fx.createOrganization();
    const foreign = await ctx.prisma.domain.create({
      data: { organizationId: other.id, name: `wh-${randomUUID().slice(0, 8)}.example.org` },
      select: { publicId: true },
    });
    const filter = await admin.post(
      WEBHOOKS,
      createBody({ filters: { domainIds: [foreign.publicId] } }),
      `it-${randomUUID()}`,
    );
    expect(filter.body).toMatchObject({
      code: 'webhook_filter_invalid',
      path: 'filters.domainIds.0',
    });
    for (const [url, reason] of [
      ['https://127.0.0.1/hook', 'loopback'],
      ['https://192.168.1.10/hook', 'private'],
      ['https://metadata.internal/hook', 'name'],
      ['https://hooks.webhooks-it.test:9000/hook', 'port'],
    ] as const) {
      const res = await admin.post(WEBHOOKS, createBody({ url }), `it-${randomUUID()}`);
      expect(res.body, url).toMatchObject({ code: 'webhook_url_not_allowed', reason });
    }
  });

  it('enforces the cap under the organization lock, also for concurrent creations', async () => {
    const live = await ctx.prisma.webhookSubscription.count({
      where: { organizationId: org.id, status: { not: 'deleted' } },
    });
    const results = await Promise.all(
      Array.from({ length: 6 }, () => manager.post(WEBHOOKS, createBody(), `it-${randomUUID()}`)),
    );
    const created201 = results.filter((r) => r.status === 201).length;
    expect(created201).toBe(4 - live);
    for (const r of results.filter((x) => x.status !== 201)) {
      expect(r.status).toBe(409);
      expect(r.body).toMatchObject({ code: 'webhook_limit_reached', limit: 4 });
    }
    expect(
      await ctx.prisma.webhookSubscription.count({
        where: { organizationId: org.id, status: { not: 'deleted' } },
      }),
    ).toBe(4);
  });

  it('refuses organizations without the webhooks feature (403)', async () => {
    const trial = await fx.createOrganization({ features: { webhooks: false } });
    const key = http(ctx, apiKeyHeader(await fx.createApiKey(trial, ['webhook:manage'])));
    const res = await key.post(WEBHOOKS, createBody(), `it-${randomUUID()}`);
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('webhooks_not_enabled');
    expect(await ctx.prisma.apiIdempotencyKey.count({ where: { organizationId: trial.id } })).toBe(
      0,
    );
  });

  it('lists from the replica with a v1 cursor and serves the detail and the catalogue', async () => {
    await expect
      .poll(async () => bodyOf(await reader.get(`${WEBHOOKS}?limit=100`)).data?.length, POLL)
      .toBe(4);
    const first = await reader.get(`${WEBHOOKS}?limit=3`);
    expect(first.status).toBe(200);
    expect(first.body.data).toHaveLength(3);
    const next = await reader.get(
      `${WEBHOOKS}?limit=3&cursor=${encodeURIComponent(first.body.nextCursor)}`,
    );
    expect(next.body.data).toHaveLength(1);
    expect(next.body.nextCursor).toBeNull();
    const ids = [...first.body.data, ...next.body.data].map((w: { id: string }) => w.id);
    expect(new Set(ids).size).toBe(4);
    expect(ids).toContain(created.id);
    expect(JSON.stringify(first.body)).not.toMatch(/whsec_|ciphertext/i);
    await expect
      .poll(async () => (await reader.get(`${WEBHOOKS}/${created.id}`)).status, POLL)
      .toBe(200);
    const one = await reader.get(`${WEBHOOKS}/${created.id}`);
    expect(one.body).toMatchObject({
      id: created.id,
      secretVersion: 1,
      createdBy: { type: 'user' },
    });
    const catalogue = await reader.get(`${WEBHOOKS}/event-types`);
    expect(catalogue.body.data.map((t: { type: string }) => t.type)).toEqual([
      ...WEBHOOK_ENVELOPE_TYPES,
    ]);
  });

  it('updates with CAS on the writer and audits without the URL; pause parks, resume un-parks', async () => {
    const pending = await seedDelivery(ctx, await subscriptionRow(ctx, created.id), {
      occurredAt: new Date(Date.now() - 60_000),
      organizationPublicId: org.publicId,
      status: 'pending',
      attempts: 0,
    });
    const nextAttempt = async () =>
      await ctx.prisma.webhookDelivery.findFirstOrThrow({
        where: { id: pending.id },
        select: { status: true, nextAttemptAt: true },
      });
    const url = `https://patched-${randomUUID().slice(0, 6)}.webhooks-it.test/hook?secret=abc`;
    const res = await admin.patch(`${WEBHOOKS}/${created.id}`, {
      expectedRowVersion: 1,
      url,
      status: 'paused',
    });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ url, status: 'paused', rowVersion: 2 });
    // Parked in the same transaction: still pending, out of the worker's due index.
    expect(await nextAttempt()).toEqual({ status: 'pending', nextAttemptAt: null });
    const stale = await admin.patch(`${WEBHOOKS}/${created.id}`, {
      expectedRowVersion: 1,
      name: 'x',
    });
    expect(stale.body).toMatchObject({ code: 'webhook_version_conflict', currentRowVersion: 2 });
    const active = await admin.patch(`${WEBHOOKS}/${created.id}`, {
      expectedRowVersion: 2,
      status: 'active',
    });
    expect(active.body).toMatchObject({ status: 'active', rowVersion: 3, consecutiveFailures: 0 });
    const resumed = await nextAttempt();
    expect(resumed.status).toBe('pending');
    expect(resumed.nextAttemptAt).not.toBeNull();
    // Leave nothing pending for the later tests of this subscription.
    await ctx.prisma.webhookDelivery.updateMany({
      where: { id: pending.id },
      data: { status: 'succeeded', nextAttemptAt: null, completedAt: new Date() },
    });
    const audit = (await webhookAudit(ctx, created.id)).filter(
      (a) => a.action === 'webhook.updated',
    );
    expect(audit).toHaveLength(2);
    expect(audit[0]!.metadata).toMatchObject({
      changedPaths: ['status', 'url'],
      urlHost: new URL(url).hostname,
      urlSha256: sha(new URL(url).href),
    });
    expect(JSON.stringify(audit[0]!.metadata)).not.toContain('secret=abc');
    expect(audit.map((a) => a.metadata)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ toStatus: 'paused', parkedDeliveries: 1 }),
        expect.objectContaining({ toStatus: 'active', resumedDeliveries: 1 }),
      ]),
    );
  });

  it('rotates with overlap: the previous ciphertext still decrypts with the previous version AAD; replay is redacted', async () => {
    const key = `it-${randomUUID()}`;
    const before = await subscriptionRow(ctx, created.id);
    const res = await admin.post(
      `${WEBHOOKS}/${created.id}/rotate-secret`,
      { overlapHours: 2 },
      key,
    );
    expect(res.status).toBe(200);
    expect(isWebhookSecret(res.body.secret)).toBe(true);
    expect(res.body.secret).not.toBe(created.secret);
    const row = await subscriptionRow(ctx, created.id);
    expect(row).toMatchObject({
      secretVersion: 2,
      previousSecretCiphertext: before.secretCiphertext,
    });
    expect(row.previousSecretExpiresAt!.getTime() - row.secretRotatedAt!.getTime()).toBe(
      2 * 3_600_000,
    );
    const cipher = cipherOf(ctx);
    expect(cipher.decrypt(row.secretCiphertext, secretAad(org.id, created.id, 2)).plaintext).toBe(
      res.body.secret,
    );
    expect(
      cipher.decrypt(row.previousSecretCiphertext!, secretAad(org.id, created.id, 1)).plaintext,
    ).toBe(created.secret);
    const replay = await admin.post(
      `${WEBHOOKS}/${created.id}/rotate-secret`,
      { overlapHours: 2 },
      key,
    );
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual({ ...res.body, secret: null });
    const stored = await ctx.prisma.apiIdempotencyKey.findFirstOrThrow({
      where: { organizationId: org.id, idempotencyKey: key },
    });
    expect(JSON.stringify(stored.response)).not.toContain('whsec_');
    const audit = (await webhookAudit(ctx, created.id)).find(
      (a) => a.action === 'webhook.secret_rotated',
    )!;
    expect(audit.metadata).toMatchObject({ version: 2, overlapHours: 2 });
    expect(JSON.stringify(audit.metadata)).not.toContain('whsec_');
    // A second rotation without overlap clears the previous secret.
    const again = await admin.post(
      `${WEBHOOKS}/${created.id}/rotate-secret`,
      { overlapHours: 0 },
      `it-${randomUUID()}`,
    );
    expect(again.body).toMatchObject({ secretVersion: 3, previousSecretExpiresAt: null });
    expect((await subscriptionRow(ctx, created.id)).previousSecretCiphertext).toBeNull();
    expect(ctx.logs.join('\n')).not.toContain('whsec_');
  });

  it('soft-deletes: pending deliveries cancelled in the same transaction, replay 204, then 404', async () => {
    const sub = await subscriptionRow(ctx, created.id);
    const pending = await seedDelivery(ctx, sub, {
      occurredAt: new Date(),
      organizationPublicId: org.publicId,
      status: 'pending',
      attempts: 0,
    });
    const key = `it-${randomUUID()}`;
    const res = await admin.delete(`${WEBHOOKS}/${created.id}`, key);
    expect(res.status).toBe(204);
    const row = await subscriptionRow(ctx, created.id);
    expect(row.status).toBe('deleted');
    expect(row.deletedAt).toBeInstanceOf(Date);
    const delivery = await ctx.prisma.webhookDelivery.findFirstOrThrow({
      where: { id: pending.id, eventOccurredAt: pending.occurredAt },
    });
    expect(delivery).toMatchObject({
      status: 'cancelled',
      lastError: 'cancelled:deleted',
      nextAttemptAt: null,
    });
    const replay = await admin.delete(`${WEBHOOKS}/${created.id}`, key);
    expect(replay.status).toBe(204);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect((await admin.delete(`${WEBHOOKS}/${created.id}`, `it-${randomUUID()}`)).status).toBe(
      404,
    );
    // Deleted subscriptions leave the default list but are readable when asked for.
    await expect
      .poll(
        async () => bodyOf(await reader.get(`${WEBHOOKS}?status=deleted`)).data?.map((w) => w.id),
        POLL,
      )
      .toContain(created.id);
    expect(
      (await reader.get(`${WEBHOOKS}?limit=100`)).body.data.map((w: { id: string }) => w.id),
    ).not.toContain(created.id);
    const audit = (await webhookAudit(ctx, created.id)).find(
      (a) => a.action === 'webhook.deleted',
    )!;
    expect(audit.metadata).toMatchObject({ cancelledDeliveries: 1 });
  });

  it('RBAC: the read key cannot mutate; users without webhook permissions get 403', async () => {
    expect((await reader.post(WEBHOOKS, createBody(), `it-${randomUUID()}`)).status).toBe(403);
    const plain = await fx.createUser(org, { roles: ['read_only_user'] });
    const user = http(ctx, bearer((await loginWithMfa(ctx, fx, plain)).accessToken));
    expect((await user.get(WEBHOOKS)).status).toBe(403);
    const analyst = await fx.createUser(org, { roles: ['security_analyst'] });
    const sa = http(ctx, bearer((await loginWithMfa(ctx, fx, analyst)).accessToken));
    expect((await sa.get(WEBHOOKS)).status).toBe(200);
    expect((await sa.post(WEBHOOKS, createBody(), `it-${randomUUID()}`)).status).toBe(403);
  });
});
