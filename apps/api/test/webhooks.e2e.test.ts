/**
 * The webhook routes (step 6.2 §6.1, W5–W7, W12; ADR-0057) over HTTP with MySQL, Redis and S3
 * stubbed, the webhook repositories replaced by in-memory doubles and the Idempotency-Key store
 * by `InMemoryIdempotencyStore` (transactional `IdempotencyService.execute` with an immediate
 * runner): every route's success path, strict bodies, queries and ids, RBAC (read vs manage,
 * users and API keys), the feature gate, the URL rules, the redacted replay of the two secret
 * routes (`secret: null` + `Idempotency-Replayed`, no `whsec_` in the stored response), key reuse
 * (422), the route limits (429 with headers), the CAS, the soft delete, the replays and the
 * response headers. The real writer, replica and stored rows run in integration/webhooks*.test.ts.
 */
// @covers get /api/v1/webhooks
// @covers post /api/v1/webhooks
// @covers get /api/v1/webhooks/event-types
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
import { randomUUID } from 'node:crypto';
import {
  isWebhookSecret,
  parseStoredEnvelope,
  WEBHOOK_ENVELOPE_TYPES,
  webhookEnvelopeSchema,
} from '@email-gateway/webhooks';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { buildOpenApiDocument } from '../src/http/openapi';
import {
  createStubbedApiApp,
  InMemoryIdempotencyStore,
  type StubbedApiApp,
} from './support/api-test-app';
import type { OpenApiOperation } from './support/messages-fixtures';
import {
  overrideWebhooks,
  RecordingAuditService,
  WebhooksWorld,
} from './support/webhooks-fixtures';

const READ = 'webhook:read';
const MANAGE = 'webhook:manage';
const OTHER_ORG = 2n;
const BASE = '/api/v1/webhooks';
const HOUR = 3_600_000;

const validBody = (patch: Record<string, unknown> = {}) => ({
  name: 'SIEM',
  url: 'https://hooks.example.com/in',
  eventTypes: ['email.received', 'email.quarantined'],
  ...patch,
});

describe('webhooks (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const world = new WebhooksWorld();
  const audit = new RecordingAuditService();
  const store = new InMemoryIdempotencyStore();
  let org: bigint;

  beforeAll(async () => {
    api = await createStubbedApiApp(
      {
        WEBHOOK_MAX_SUBSCRIPTIONS_PER_ORG: '3',
        WEBHOOK_TEST_REQUESTS_PER_MINUTE: '2',
        WEBHOOK_REPLAY_REQUESTS_PER_HOUR: '4',
        WEBHOOK_REPLAY_MAX_PER_DELIVERY: '2',
        URL_CLICK_BASE_URL: 'https://click.gateway.example',
      },
      { override: (b) => store.override(overrideWebhooks(b, world, audit)) },
    );
    org = api.principals.organizationId;
    world.users.set(10n, api.principals.ids.user);
  });

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    world.reset();
    audit.entries.length = 0;
    store.rows.clear();
    api.kv.entries.clear();
    api.principals.apiKeyWith([]);
  });

  const as = async (permissions: string[]) => api.principals.user(permissions).bearer();
  const create = async (body: unknown, key: string | null = 'key-1', perms = [MANAGE]) => {
    const req = api
      .http()
      .post(BASE)
      .set(await as(perms));
    if (key !== null) req.set('Idempotency-Key', key);
    return req.send(body as object);
  };
  const seedSub = (patch: Record<string, unknown> = {}, organizationId = org) =>
    world.addSubscription(organizationId, { publicId: randomUUID(), ...patch });

  describe('POST /webhooks (create, ADR-0057)', () => {
    it('creates (201) with the secret once; the replay returns secret null; the stored body has no secret', async () => {
      world.domains.push({ publicId: '0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b11', organizationId: org });
      const body = validBody({
        description: 'to the SOC',
        filters: { domainIds: ['0192F0C4-7D1E-7B6A-9C55-6F3E2A1D4B11'], minSeverity: 'medium' },
        maxConcurrency: 4,
      });
      const res = await create(body);
      expect(res.status).toBe(201);
      expect(res.headers['cache-control']).toBe('no-store');
      expect(res.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
      expect(res.headers['idempotency-replayed']).toBeUndefined();
      expect(isWebhookSecret(res.body.secret)).toBe(true);
      expect(res.body).toMatchObject({
        name: 'SIEM',
        description: 'to the SOC',
        url: 'https://hooks.example.com/in',
        eventTypes: ['email.received', 'email.quarantined'],
        filters: { domainIds: ['0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b11'], minSeverity: 'medium' },
        status: 'active',
        maxConcurrency: 4,
        secretVersion: 1,
        rowVersion: 1,
        createdBy: { type: 'user', id: api.principals.ids.user },
      });
      expect(JSON.stringify(res.body)).not.toMatch(/ciphertext/i);
      // The row holds a ciphertext, never the secret.
      const row = world.subscriptions[0]!;
      expect(row.secretCiphertext.startsWith('v1.k1.')).toBe(true);
      expect(row.secretCiphertext).not.toContain(res.body.secret);
      // The stored response is redacted.
      const stored = [...store.rows.values()][0]!;
      expect(stored).toMatchObject({ operation: 'webhook.create', statusCode: 201 });
      expect((stored.response as { secret: unknown }).secret).toBeNull();
      expect(JSON.stringify(stored.response)).not.toContain('whsec_');
      // Replay: same body, secret null, header set, nothing new created.
      const replay = await create(body);
      expect(replay.status).toBe(201);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body).toEqual({ ...res.body, secret: null });
      expect(world.subscriptions).toHaveLength(1);
      // Same key, other body → 422.
      const reused = await create(validBody({ name: 'other' }));
      expect(reused.status).toBe(422);
      expect(reused.body.code).toBe('idempotency_key_reused');
      // Audit: urlHost + urlSha256 only.
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]).toMatchObject({
        action: 'webhook.created',
        resourceType: 'webhook_subscription',
        resourceId: res.body.id,
        metadata: {
          urlHost: 'hooks.example.com',
          urlSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
          filterNames: ['domainIds', 'minSeverity'],
        },
      });
      const metadata = JSON.stringify(audit.entries[0]!.metadata);
      expect(metadata).not.toContain('https://');
      expect(metadata).not.toContain('whsec_');
    });

    it('requires a valid key and a strict body', async () => {
      expect((await create(validBody(), null)).body.code).toBe('idempotency_key_required');
      expect((await create(validBody(), 'bad key!')).body.code).toBe('idempotency_key_invalid');
      for (const body of [
        {},
        validBody({ extra: 1 }),
        validBody({ name: '' }),
        validBody({ name: '\u0000\u0001' }),
        validBody({ eventTypes: [] }),
        validBody({ eventTypes: ['email.*'] }),
        validBody({ eventTypes: ['webhook.ping'] }),
        validBody({ eventTypes: ['email.received', 'email.received'] }),
        validBody({ filters: { directions: ['sideways'] } }),
        validBody({ filters: { unknown: true } }),
        validBody({ status: 'disabled' }),
        validBody({ maxConcurrency: 0 }),
        validBody({ maxConcurrency: 33 }),
        validBody({ url: 'x'.repeat(2049) }),
      ]) {
        const res = await create(body, `k-${randomUUID()}`);
        expect(res.status, JSON.stringify(body).slice(0, 80)).toBe(400);
        expect(res.body.code).toBe('validation_failed');
      }
      expect(world.subscriptions).toEqual([]);
      expect(store.rows.size).toBe(0);
    });

    it('refuses endpoint URLs that break the W6 rules with the reason (422)', async () => {
      const cases: Array<[string, string]> = [
        ['http://hooks.example.com/in', 'scheme'],
        ['ftp://hooks.example.com/in', 'scheme'],
        ['https://hooks.example.com:8443/in', 'port'],
        ['https://localhost/in', 'name'],
        ['https://intranet/in', 'name'],
        ['https://printer.local/in', 'name'],
        ['https://127.0.0.1/in', 'loopback'],
        ['https://10.1.2.3/in', 'private'],
        ['https://169.254.169.254/latest', 'metadata'],
        ['https://[::1]/in', 'loopback'],
        ['https://user:pass@hooks.example.com/in', 'format'],
        ['https://hooks.example.com/in#frag', 'format'],
        ['not a url', 'format'],
        ['https://click.gateway.example/x', 'deny_list'],
        ['https://a.click.gateway.example/x', 'deny_list'],
        ['https://localhost:3001/portal', 'port'],
      ];
      for (const [url, reason] of cases) {
        const res = await create(validBody({ url }), `k-${randomUUID()}`);
        expect(res.status, url).toBe(422);
        expect(res.body, url).toMatchObject({ code: 'webhook_url_not_allowed', reason });
        expect(JSON.stringify(res.body)).not.toContain(url);
      }
      // The api's own host (the Host the request reached) is refused too.
      const own = await api
        .http()
        .post(BASE)
        .set(await as([MANAGE]))
        .set('Host', 'api.gateway.example')
        .set('Idempotency-Key', 'own')
        .send(validBody({ url: 'https://api.gateway.example/hook' }));
      expect(own.body).toMatchObject({ code: 'webhook_url_not_allowed', reason: 'deny_list' });
      expect(world.subscriptions).toEqual([]);
    });

    it('resolves filter domains in the tenant scope (422 for foreign or unknown ids)', async () => {
      const foreign = randomUUID();
      world.domains.push({ publicId: foreign, organizationId: OTHER_ORG });
      for (const id of [foreign, randomUUID()]) {
        const res = await create(validBody({ filters: { domainIds: [id] } }), `k-${id}`);
        expect(res.status).toBe(422);
        expect(res.body).toMatchObject({
          code: 'webhook_filter_invalid',
          path: 'filters.domainIds.0',
        });
      }
    });

    it('checks the plan feature (403) and the per-organization cap (409); errors are not stored', async () => {
      world.featureDisabled.add(org);
      const off = await create(validBody(), 'k-off');
      expect(off.status).toBe(403);
      expect(off.body.code).toBe('webhooks_not_enabled');
      world.featureDisabled.clear();
      seedSub();
      seedSub({ status: 'deleted' });
      seedSub({ status: 'disabled' });
      expect((await create(validBody(), 'k-a')).status).toBe(201);
      const full = await create(validBody(), 'k-b');
      expect(full.status).toBe(409);
      expect(full.body).toMatchObject({ code: 'webhook_limit_reached', limit: 3 });
      expect([...store.rows.values()].map((r) => r.idempotencyKey)).toEqual(['k-a']);
    });

    it('lets an API key with webhook:manage create (createdBy null), refuses one without it', async () => {
      api.principals.apiKeyWith([READ]);
      const refused = await api
        .http()
        .post(BASE)
        .set(api.principals.apiKeyHeaders)
        .set('Idempotency-Key', 'k-api')
        .send(validBody());
      expect(refused.status).toBe(403);
      api.principals.apiKeyWith([MANAGE]);
      const res = await api
        .http()
        .post(BASE)
        .set(api.principals.apiKeyHeaders)
        .set('Idempotency-Key', 'k-api')
        .send(validBody());
      expect(res.status).toBe(201);
      expect(res.body.createdBy).toBeNull();
      expect(isWebhookSecret(res.body.secret)).toBe(true);
      expect(audit.entries[0]!.actor).toMatchObject({ type: 'api_key' });
    });
  });

  describe('reads', () => {
    it('lists newest first without deleted ones unless asked, with a signed cursor', async () => {
      const a = seedSub({ name: 'a' });
      const b = seedSub({ name: 'b', status: 'paused' });
      const c = seedSub({ name: 'c', status: 'deleted' });
      seedSub({ name: 'foreign' }, OTHER_ORG);
      const bearer = await as([READ]);
      const q = (query = '') => api.http().get(`${BASE}${query}`).set(bearer);
      const all = await q();
      expect(all.status).toBe(200);
      expect(all.headers['cache-control']).toBe('no-store');
      expect(all.body.data.map((w: { id: string }) => w.id)).toEqual([b.publicId, a.publicId]);
      expect(JSON.stringify(all.body)).not.toMatch(/ciphertext|whsec_/i);
      expect((await q('?status=deleted')).body.data.map((w: { id: string }) => w.id)).toEqual([
        c.publicId,
      ]);
      const first = await q('?limit=1');
      expect(first.body.nextCursor).toEqual(expect.any(String));
      const second = await q(`?limit=1&cursor=${encodeURIComponent(first.body.nextCursor)}`);
      expect(second.body).toEqual({
        data: [expect.objectContaining({ id: a.publicId })],
        nextCursor: null,
      });
      // The cursor is bound to the filters.
      const other = await q(
        `?limit=1&status=active&cursor=${encodeURIComponent(first.body.nextCursor)}`,
      );
      expect(other.body.code).toBe('cursor_invalid');
      for (const query of ['?status=gone', '?foo=1', '?sort=id', '?limit=0']) {
        expect((await q(query)).status, query).toBe(400);
      }
    });

    it('gets one webhook; another organization’s or an unknown id is 404, a bad id 400', async () => {
      const own = seedSub({ status: 'deleted' });
      const foreign = seedSub({}, OTHER_ORG);
      const bearer = await as([READ]);
      const ok = await api.http().get(`${BASE}/${own.publicId}`).set(bearer);
      expect(ok.status).toBe(200);
      expect(ok.body).toMatchObject({ id: own.publicId, status: 'deleted' });
      for (const id of [foreign.publicId, randomUUID()]) {
        const res = await api.http().get(`${BASE}/${id}`).set(bearer);
        expect(res.status).toBe(404);
        expect(res.body.code).toBe('webhook_not_found');
        expect(res.body.requestId).toEqual(expect.any(String));
      }
      expect((await api.http().get(`${BASE}/not-a-uuid`).set(bearer)).status).toBe(400);
    });

    it('serves the event catalogue with a valid example envelope per type', async () => {
      const res = await api
        .http()
        .get(`${BASE}/event-types`)
        .set(await as([READ]));
      expect(res.status).toBe(200);
      expect(res.body.data.map((t: { type: string }) => t.type)).toEqual([
        ...WEBHOOK_ENVELOPE_TYPES,
      ]);
      expect(res.body.severities).toEqual(['info', 'low', 'medium', 'high']);
      for (const entry of res.body.data as Array<{ type: string; example: unknown }>) {
        expect(webhookEnvelopeSchema.safeParse(entry.example).success, entry.type).toBe(true);
      }
      expect(res.body.data.find((t: { type: string }) => t.type === 'webhook.ping')).toMatchObject({
        subscribable: false,
      });
    });

    it('RBAC: reads need webhook:read (users and API keys), mutations webhook:manage', async () => {
      const sub = seedSub();
      expect((await api.http().get(BASE)).status).toBe(401);
      expect(
        (
          await api
            .http()
            .get(BASE)
            .set(await as([MANAGE]))
        ).status,
      ).toBe(403);
      expect(
        (
          await api
            .http()
            .get(`${BASE}/event-types`)
            .set(await as(['organization:read']))
        ).status,
      ).toBe(403);
      api.principals.apiKeyWith([READ]);
      for (const path of [BASE, `${BASE}/event-types`, `${BASE}/${sub.publicId}`]) {
        expect((await api.http().get(path).set(api.principals.apiKeyHeaders)).status, path).toBe(
          200,
        );
      }
      expect(
        (
          await api
            .http()
            .patch(`${BASE}/${sub.publicId}`)
            .set(api.principals.apiKeyHeaders)
            .send({ expectedRowVersion: 1, name: 'x' })
        ).status,
      ).toBe(403);
      const bearer = await as([READ]);
      for (const [method, path] of [
        ['patch', `${BASE}/${sub.publicId}`],
        ['delete', `${BASE}/${sub.publicId}`],
        ['post', `${BASE}/${sub.publicId}/rotate-secret`],
        ['post', `${BASE}/${sub.publicId}/test`],
        ['post', `${BASE}/${sub.publicId}/replays`],
      ] as const) {
        const res = await api.http()[method](path).set(bearer).set('Idempotency-Key', 'k').send({});
        expect(res.status, `${method} ${path}`).toBe(403);
      }
    });
  });

  describe('PATCH /webhooks/{id}', () => {
    const patch = async (id: string, body: unknown, perms = [MANAGE]) =>
      api
        .http()
        .patch(`${BASE}/${id}`)
        .set(await as(perms))
        .send(body as object);

    it('updates with CAS, audits changed paths and urlHost/urlSha256 only', async () => {
      const sub = seedSub();
      const res = await patch(sub.publicId, {
        expectedRowVersion: 1,
        name: 'renamed',
        url: 'https://new.example.org/hook?token=abc',
        eventTypes: ['domain.verified'],
        filters: { minSeverity: 'high' },
        maxConcurrency: 2,
      });
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({
        name: 'renamed',
        url: 'https://new.example.org/hook?token=abc',
        eventTypes: ['domain.verified'],
        filters: { minSeverity: 'high' },
        maxConcurrency: 2,
        rowVersion: 2,
      });
      expect(audit.entries[0]).toMatchObject({
        action: 'webhook.updated',
        metadata: {
          changedPaths: ['eventTypes', 'filters', 'maxConcurrency', 'name', 'url'],
          urlHost: 'new.example.org',
          urlSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
          rowVersion: 2,
        },
      });
      expect(JSON.stringify(audit.entries[0]!.metadata)).not.toContain('token=abc');
      const stale = await patch(sub.publicId, { expectedRowVersion: 1, name: 'again' });
      expect(stale.status).toBe(409);
      expect(stale.body).toMatchObject({ code: 'webhook_version_conflict', currentRowVersion: 2 });
      // Unchanged values: no new version, no audit row.
      const same = await patch(sub.publicId, { expectedRowVersion: 2, name: 'renamed' });
      expect(same.body.rowVersion).toBe(2);
      expect(audit.entries).toHaveLength(1);
    });

    it('disables (cancels pending deliveries), pauses, and re-activates with the feature check and reset', async () => {
      const sub = seedSub({ consecutiveFailures: 7, failingSince: new Date() });
      const now = new Date();
      world.addDelivery(sub, {
        publicId: randomUUID(),
        eventId: randomUUID(),
        eventOccurredAt: now,
        status: 'pending',
      });
      const disabled = await patch(sub.publicId, { expectedRowVersion: 1, status: 'disabled' });
      expect(disabled.body).toMatchObject({ status: 'disabled', disabledReason: 'manual' });
      expect(world.deliveries[0]).toMatchObject({
        status: 'cancelled',
        lastError: 'cancelled:disabled',
      });
      expect(audit.entries.at(-1)!.metadata).toMatchObject({
        fromStatus: 'active',
        toStatus: 'disabled',
        cancelledDeliveries: 1,
      });
      world.featureDisabled.add(org);
      const refused = await patch(sub.publicId, { expectedRowVersion: 2, status: 'active' });
      expect(refused.status).toBe(403);
      expect(refused.body.code).toBe('webhooks_not_enabled');
      // Pausing does not need the feature.
      expect(
        (await patch(sub.publicId, { expectedRowVersion: 2, status: 'paused' })).body,
      ).toMatchObject({ status: 'paused', disabledReason: null });
      world.featureDisabled.clear();
      const active = await patch(sub.publicId, { expectedRowVersion: 3, status: 'active' });
      expect(active.body).toMatchObject({
        status: 'active',
        consecutiveFailures: 0,
        failingSince: null,
        disabledReason: null,
        disabledAt: null,
        rowVersion: 4,
      });
    });

    it('pause parks pending deliveries (out of the due index); resume makes them due now', async () => {
      const sub = seedSub();
      const other = seedSub({ name: 'other' });
      const due = new Date(Date.now() - 60_000);
      const mk = (s: typeof sub) =>
        world.addDelivery(s, {
          publicId: randomUUID(),
          eventId: randomUUID(),
          eventOccurredAt: due,
          status: 'pending',
          nextAttemptAt: due,
          completedAt: null,
        });
      const a = mk(sub);
      const b = mk(sub);
      const untouched = mk(other);
      const paused = await patch(sub.publicId, { expectedRowVersion: 1, status: 'paused' });
      expect(paused.body).toMatchObject({ status: 'paused' });
      expect([a.nextAttemptAt, b.nextAttemptAt]).toEqual([null, null]);
      expect([a.status, b.status]).toEqual(['pending', 'pending']);
      expect(untouched.nextAttemptAt).toEqual(due);
      expect(audit.entries.at(-1)!.metadata).toMatchObject({
        fromStatus: 'active',
        toStatus: 'paused',
        parkedDeliveries: 2,
      });
      const before = Date.now();
      const resumed = await patch(sub.publicId, { expectedRowVersion: 2, status: 'active' });
      expect(resumed.body).toMatchObject({ status: 'active' });
      expect(a.nextAttemptAt!.getTime()).toBeGreaterThanOrEqual(before - 1_000);
      expect(b.nextAttemptAt).toEqual(a.nextAttemptAt);
      expect(audit.entries.at(-1)!.metadata).toMatchObject({
        fromStatus: 'paused',
        toStatus: 'active',
        resumedDeliveries: 2,
      });
    });

    it('validates the body, the URL and the id; another organization’s webhook is 404', async () => {
      const sub = seedSub();
      const foreign = seedSub({}, OTHER_ORG);
      for (const body of [
        {},
        { expectedRowVersion: 1 },
        { name: 'x' },
        { expectedRowVersion: 1, status: 'deleted' },
        { expectedRowVersion: 1, extra: true },
        { expectedRowVersion: 0, name: 'x' },
      ]) {
        const res = await patch(sub.publicId, body);
        expect(res.status, JSON.stringify(body)).toBe(400);
      }
      const url = await patch(sub.publicId, { expectedRowVersion: 1, url: 'https://10.0.0.1/' });
      expect(url.body).toMatchObject({ code: 'webhook_url_not_allowed', reason: 'private' });
      expect((await patch(foreign.publicId, { expectedRowVersion: 1, name: 'x' })).status).toBe(
        404,
      );
      expect(foreign.name).toBe('hook');
      expect((await patch('nope', { expectedRowVersion: 1, name: 'x' })).status).toBe(400);
    });
  });

  describe('DELETE /webhooks/{id}', () => {
    const del = async (id: string, key: string | null = 'del-1') => {
      const req = api
        .http()
        .delete(`${BASE}/${id}`)
        .set(await as([MANAGE, READ]));
      if (key !== null) req.set('Idempotency-Key', key);
      return req;
    };

    it('soft-deletes (204), cancels pending deliveries, replays 204; a new key is 404', async () => {
      const sub = seedSub();
      world.addDelivery(sub, {
        publicId: randomUUID(),
        eventId: randomUUID(),
        eventOccurredAt: new Date(),
        status: 'pending',
      });
      const res = await del(sub.publicId);
      expect(res.status).toBe(204);
      expect(res.text).toBe('');
      expect(world.subscriptions[0]).toMatchObject({ status: 'deleted' });
      expect(world.subscriptions[0]!.deletedAt).toBeInstanceOf(Date);
      expect(world.deliveries[0]).toMatchObject({ status: 'cancelled' });
      const replay = await del(sub.publicId);
      expect(replay.status).toBe(204);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      const again = await del(sub.publicId, 'del-2');
      expect(again.status).toBe(404);
      expect(audit.entries).toEqual([
        expect.objectContaining({
          action: 'webhook.deleted',
          metadata: expect.objectContaining({
            formerStatus: 'active',
            urlHost: 'hooks.example.com',
            cancelledDeliveries: 1,
          }),
        }),
      ]);
      expect((await del(sub.publicId, null)).body.code).toBe('idempotency_key_required');
      expect((await del(seedSub({}, OTHER_ORG).publicId, 'del-3')).status).toBe(404);
    });
  });

  describe('POST /webhooks/{id}/rotate-secret (ADR-0057)', () => {
    const rotate = async (id: string, body: unknown, key: string | null = 'rot-1') => {
      const req = api
        .http()
        .post(`${BASE}/${id}/rotate-secret`)
        .set(await as([MANAGE]));
      if (key !== null) req.set('Idempotency-Key', key);
      return req.send(body as object);
    };

    it('rotates with the default 24 h overlap, returns the secret once and redacts the replay', async () => {
      const sub = seedSub({ secretCiphertext: 'v1.k1.old' });
      const before = Date.now();
      const res = await rotate(sub.publicId, {});
      expect(res.status).toBe(200);
      expect(isWebhookSecret(res.body.secret)).toBe(true);
      expect(res.body).toMatchObject({ id: sub.publicId, secretVersion: 2 });
      const expires = new Date(res.body.previousSecretExpiresAt).getTime();
      expect(expires - before).toBeGreaterThanOrEqual(24 * HOUR - 1000);
      expect(expires - before).toBeLessThan(24 * HOUR + 60_000);
      expect(world.subscriptions[0]).toMatchObject({
        secretVersion: 2,
        previousSecretCiphertext: 'v1.k1.old',
      });
      expect(world.subscriptions[0]!.secretCiphertext).not.toBe('v1.k1.old');
      const stored = [...store.rows.values()][0]!;
      expect(stored).toMatchObject({ operation: 'webhook.secret_rotate', statusCode: 200 });
      expect(JSON.stringify(stored.response)).not.toContain('whsec_');
      const replay = await rotate(sub.publicId, {});
      expect(replay.status).toBe(200);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body).toEqual({ ...res.body, secret: null });
      expect(world.subscriptions[0]!.secretVersion).toBe(2);
      expect((await rotate(sub.publicId, { overlapHours: 1 })).status).toBe(422);
      expect(audit.entries).toEqual([
        expect.objectContaining({
          action: 'webhook.secret_rotated',
          metadata: expect.objectContaining({ version: 2, overlapHours: 24 }),
        }),
      ]);
      expect(JSON.stringify(audit.entries.map((e) => e.metadata))).not.toContain('whsec_');
    });

    it('overlap 0 clears the previous secret; bounds and ids are validated; foreign is 404', async () => {
      const sub = seedSub({ previousSecretCiphertext: 'v1.k1.older' });
      const res = await rotate(sub.publicId, { overlapHours: 0 }, 'rot-0');
      expect(res.body.previousSecretExpiresAt).toBeNull();
      expect(world.subscriptions[0]!.previousSecretCiphertext).toBeNull();
      for (const body of [{ overlapHours: -1 }, { overlapHours: 169 }, { other: 1 }]) {
        expect((await rotate(sub.publicId, body, `r-${randomUUID()}`)).status).toBe(400);
      }
      expect((await rotate(seedSub({}, OTHER_ORG).publicId, {}, 'rot-f')).status).toBe(404);
      expect((await rotate(sub.publicId, {}, null)).body.code).toBe('idempotency_key_required');
    });
  });

  describe('POST /webhooks/{id}/test', () => {
    it('queues a webhook.ping event and a test delivery (202), refuses inactive webhooks, limits per webhook (429)', async () => {
      const sub = seedSub();
      const bearer = await as([MANAGE]);
      const res = await api.http().post(`${BASE}/${sub.publicId}/test`).set(bearer);
      expect(res.status).toBe(202);
      const event = world.events.find((e) => e.eventId === res.body.eventId)!;
      expect(event).toMatchObject({ eventType: 'webhook.ping', severity: 'info' });
      const envelope = parseStoredEnvelope(event.payloadJson);
      expect(envelope).toMatchObject({
        type: 'webhook.ping',
        organizationId: api.principals.ids.org,
        data: { subscriptionId: sub.publicId },
      });
      expect(world.deliveries[0]).toMatchObject({
        publicId: res.body.deliveryId,
        trigger: 'test',
        status: 'pending',
        deliverySeq: 0,
      });
      expect(audit.entries[0]).toMatchObject({ action: 'webhook.test_requested' });
      expect((await api.http().post(`${BASE}/${sub.publicId}/test`).set(bearer)).status).toBe(202);
      const limited = await api.http().post(`${BASE}/${sub.publicId}/test`).set(bearer);
      expect(limited.status).toBe(429);
      expect(limited.body).toMatchObject({ code: 'rate_limited', scope: 'route' });
      expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
      expect(limited.headers['ratelimit-limit']).toBeDefined();
      // Another webhook has its own counter; a paused one is 409.
      const paused = seedSub({ status: 'paused' });
      const notActive = await api.http().post(`${BASE}/${paused.publicId}/test`).set(bearer);
      expect(notActive.status).toBe(409);
      expect(notActive.body).toMatchObject({ code: 'webhook_not_active', status: 'paused' });
      world.featureDisabled.add(org);
      const other = seedSub();
      expect((await api.http().post(`${BASE}/${other.publicId}/test`).set(bearer)).body.code).toBe(
        'webhooks_not_enabled',
      );
    });
  });

  describe('deliveries and replays', () => {
    const now = Date.now();
    const at = (minutesAgo: number) => new Date(now - minutesAgo * 60_000);

    it('lists the history in the bounded range newest first, with filters and a signed cursor', async () => {
      const sub = seedSub();
      const other = seedSub();
      const d1 = world.addDelivery(sub, {
        publicId: randomUUID(),
        eventId: randomUUID(),
        eventOccurredAt: at(10),
      });
      const d2 = world.addDelivery(sub, {
        publicId: randomUUID(),
        eventId: randomUUID(),
        eventOccurredAt: at(5),
        status: 'dead',
        lastError: 'http_500',
        eventType: 'email.quarantined',
      });
      world.addDelivery(sub, {
        publicId: randomUUID(),
        eventId: randomUUID(),
        eventOccurredAt: at(60 * 30),
      });
      world.addDelivery(other, {
        publicId: randomUUID(),
        eventId: randomUUID(),
        eventOccurredAt: at(1),
      });
      const bearer = await as([READ]);
      const q = (query = '') =>
        api.http().get(`${BASE}/${sub.publicId}/deliveries${query}`).set(bearer);
      const res = await q();
      expect(res.status).toBe(200);
      expect(res.body.data.map((d: { id: string }) => d.id)).toEqual([d2.publicId, d1.publicId]);
      expect(res.body.data[0]).toMatchObject({
        eventType: 'email.quarantined',
        status: 'dead',
        lastError: 'http_500',
        trigger: 'event',
        deliverySeq: 0,
      });
      expect((await q('?status=dead')).body.data).toHaveLength(1);
      expect((await q('?eventType=email.received&trigger=event')).body.data).toHaveLength(1);
      const from = encodeURIComponent(at(60 * 31).toISOString());
      expect((await q(`?from=${from}`)).body.data).toHaveLength(3);
      const first = await q('?limit=1');
      const next = await q(`?limit=1&cursor=${encodeURIComponent(first.body.nextCursor)}`);
      expect(next.body.data.map((d: { id: string }) => d.id)).toEqual([d1.publicId]);
      // A cursor never moves to another webhook.
      const moved = await api
        .http()
        .get(
          `${BASE}/${other.publicId}/deliveries?limit=1&cursor=${encodeURIComponent(first.body.nextCursor)}`,
        )
        .set(bearer);
      expect(moved.body.code).toBe('cursor_invalid');
      const longRange = `?from=${encodeURIComponent(at(60 * 24 * 40).toISOString())}`;
      for (const query of [longRange, '?status=nope', '?trigger=x', '?foo=1', '?cursor=bad']) {
        expect((await q(query)).status, query).toBe(400);
      }
      const foreign = seedSub({}, OTHER_ORG);
      expect(
        (await api.http().get(`${BASE}/${foreign.publicId}/deliveries`).set(bearer)).body.code,
      ).toBe('webhook_not_found');
    });

    it('gets a delivery with attempts and the stored envelope (null after retention)', async () => {
      const sub = seedSub();
      const d = world.addDelivery(sub, {
        publicId: randomUUID(),
        eventId: randomUUID(),
        eventOccurredAt: at(3),
      });
      world.attempts.push({
        organizationId: org,
        deliveryId: d.id,
        deliveryEventOccurredAt: d.eventOccurredAt,
        attemptNo: 1,
        attemptedAt: at(2),
        outcome: 'http_error',
        httpStatus: 503,
        latencyMs: 40,
        responseSnippet: 'busy',
        retryAfterSeconds: 30,
        errorCode: 'http_503',
        signatureCount: 2,
      });
      const lost = world.addDelivery(
        sub,
        { publicId: randomUUID(), eventId: randomUUID(), eventOccurredAt: at(4) },
        { noEvent: true },
      );
      const bearer = await as([READ]);
      const res = await api
        .http()
        .get(`${BASE}/${sub.publicId}/deliveries/${d.publicId}`)
        .set(bearer);
      expect(res.status).toBe(200);
      expect(res.body.attempts).toEqual([
        {
          attemptNo: 1,
          attemptedAt: at(2).toISOString(),
          outcome: 'http_error',
          httpStatus: 503,
          latencyMs: 40,
          responseSnippet: 'busy',
          retryAfterSeconds: 30,
          errorCode: 'http_503',
          signatureCount: 2,
        },
      ]);
      expect(res.body.event).toMatchObject({ id: d.eventId, type: 'webhook.ping' });
      const gone = await api
        .http()
        .get(`${BASE}/${sub.publicId}/deliveries/${lost.publicId}`)
        .set(bearer);
      expect(gone.body.event).toBeNull();
      const other = seedSub();
      for (const path of [
        `${BASE}/${other.publicId}/deliveries/${d.publicId}`,
        `${BASE}/${sub.publicId}/deliveries/${randomUUID()}`,
      ]) {
        const r = await api.http().get(path).set(bearer);
        expect(r.status).toBe(404);
        expect(r.body.code).toBe('webhook_delivery_not_found');
      }
      expect(
        (await api.http().get(`${BASE}/${sub.publicId}/deliveries/x`).set(bearer)).status,
      ).toBe(400);
    });

    it('replays one delivery (202, seq + 1), idempotently, within the limit; expired is 410', async () => {
      const sub = seedSub();
      const d = world.addDelivery(sub, {
        publicId: randomUUID(),
        eventId: randomUUID(),
        eventOccurredAt: at(3),
        status: 'dead',
      });
      const bearer = await as([MANAGE]);
      const replay = (deliveryId: string, key: string) =>
        api
          .http()
          .post(`${BASE}/${sub.publicId}/deliveries/${deliveryId}/replay`)
          .set(bearer)
          .set('Idempotency-Key', key);
      const res = await replay(d.publicId, 'rp-1');
      expect(res.status).toBe(202);
      const created = world.deliveries.find((x) => x.publicId === res.body.deliveryId)!;
      expect(created).toMatchObject({
        eventId: d.eventId,
        deliverySeq: 1,
        trigger: 'replay',
        status: 'pending',
      });
      const again = await replay(d.publicId, 'rp-1');
      expect(again.status).toBe(202);
      expect(again.headers['idempotency-replayed']).toBe('true');
      expect(again.body).toEqual(res.body);
      expect((await replay(d.publicId, 'rp-2')).status).toBe(202);
      const limited = await replay(d.publicId, 'rp-3');
      expect(limited.status).toBe(409);
      expect(limited.body).toMatchObject({ code: 'webhook_replay_limit', limit: 2 });
      expect(audit.entries.filter((e) => e.action === 'webhook.delivery_replayed')).toHaveLength(2);
      const lost = world.addDelivery(
        sub,
        { publicId: randomUUID(), eventId: randomUUID(), eventOccurredAt: at(5) },
        { noEvent: true },
      );
      const expired = await replay(lost.publicId, 'rp-4');
      expect(expired.status).toBe(410);
      expect(expired.body.code).toBe('webhook_event_expired');
      expect((await replay(randomUUID(), 'rp-5')).body.code).toBe('webhook_delivery_not_found');
      expect((await replay(d.publicId, 'rp-1')).status).toBe(202);
      expect(
        (
          await api
            .http()
            .post(`${BASE}/${sub.publicId}/deliveries/${d.publicId}/replay`)
            .set(bearer)
        ).body.code,
      ).toBe('idempotency_key_required');
      const paused = seedSub({ status: 'paused' });
      const pd = world.addDelivery(paused, {
        publicId: randomUUID(),
        eventId: randomUUID(),
        eventOccurredAt: at(1),
      });
      const notActive = await api
        .http()
        .post(`${BASE}/${paused.publicId}/deliveries/${pd.publicId}/replay`)
        .set(bearer)
        .set('Idempotency-Key', 'rp-6');
      expect(notActive.body.code).toBe('webhook_not_active');
    });

    it('queues a range replay (202), one at a time, validates the range, limits per organization (429)', async () => {
      const sub = seedSub({ eventTypes: ['email.received', 'email.scanned'] });
      const bearer = await as([MANAGE, READ]);
      const post = (body: unknown, key: string, id = sub.publicId) =>
        api
          .http()
          .post(`${BASE}/${id}/replays`)
          .set(bearer)
          .set('Idempotency-Key', key)
          .send(body as object);
      const body = { from: at(120).toISOString(), to: at(1).toISOString() };
      const res = await post(body, 'rr-1');
      expect(res.status).toBe(202);
      expect(res.body).toEqual({ replayId: expect.any(String), status: 'queued' });
      expect(world.replays[0]).toMatchObject({
        statuses: ['failed', 'dead'],
        eventTypes: null,
        requestedByType: 'user',
        requestedById: api.principals.ids.user,
      });
      const view = await api
        .http()
        .get(`${BASE}/${sub.publicId}/replays/${res.body.replayId}`)
        .set(bearer);
      expect(view.status).toBe(200);
      expect(view.body).toMatchObject({
        id: res.body.replayId,
        status: 'queued',
        from: at(120).toISOString(),
        statuses: ['failed', 'dead'],
        matchedCount: 0,
        truncated: false,
      });
      const busy = await post({ ...body, statuses: ['succeeded'] }, 'rr-2');
      expect(busy.status).toBe(409);
      expect(busy.body).toMatchObject({
        code: 'webhook_replay_in_progress',
        replayId: res.body.replayId,
      });
      // The route limit counts every request of the organization (4 per hour here).
      expect((await post({ ...body, statuses: ['dead'] }, 'rr-3')).status).toBe(409);
      const replayed = await post(body, 'rr-1');
      expect(replayed.status).toBe(202);
      expect(replayed.headers['idempotency-replayed']).toBe('true');
      const fifth = await post(body, 'rr-4');
      expect(fifth.status).toBe(429);
      expect(fifth.body).toMatchObject({ code: 'rate_limited', scope: 'route' });
      expect(Number(fifth.headers['retry-after'])).toBeGreaterThan(0);
    });

    it('validates range replay bodies; foreign webhooks and replays are 404', async () => {
      const sub = seedSub();
      const bearer = await as([MANAGE, READ]);
      const post = (body: unknown) => {
        // Validation is what this test checks: start every request with a fresh route window.
        api.kv.entries.clear();
        return api
          .http()
          .post(`${BASE}/${sub.publicId}/replays`)
          .set(bearer)
          .set('Idempotency-Key', `v-${randomUUID()}`)
          .send(body as object);
      };
      for (const body of [
        {},
        { from: at(10).toISOString() },
        { from: at(1).toISOString(), to: at(10).toISOString() },
        { from: at(60 * 80).toISOString(), to: at(1).toISOString() },
        { from: at(10).toISOString(), to: new Date(now + 3_600_000).toISOString() },
        { from: at(10).toISOString(), to: at(1).toISOString(), statuses: ['pending'] },
        { from: at(10).toISOString(), to: at(1).toISOString(), eventTypes: ['webhook.ping'] },
        { from: at(10).toISOString(), to: at(1).toISOString(), extra: 1 },
      ]) {
        const res = await post(body);
        expect(res.status, JSON.stringify(body)).toBe(400);
      }
      const old = new Date(now - 63 * 86_400_000);
      expect(
        (await post({ from: old.toISOString(), to: new Date(old.getTime() + HOUR).toISOString() }))
          .status,
      ).toBe(400);
      const foreign = seedSub({}, OTHER_ORG);
      world.replays.push({
        ...world.replays[0]!,
        id: 1n,
        publicId: randomUUID(),
        organizationId: OTHER_ORG,
        subscriptionId: foreign.id,
        requestedByType: 'user',
        requestedById: randomUUID(),
        status: 'queued',
        rangeFrom: at(5),
        rangeTo: at(1),
        statuses: ['dead'],
        eventTypes: null,
        matchedCount: 0,
        createdCount: 0,
        truncated: false,
        errorCode: null,
        createdAt: new Date(),
        startedAt: null,
        completedAt: null,
      });
      const foreignReplay = world.replays.at(-1)!;
      for (const path of [
        `${BASE}/${foreign.publicId}/replays/${foreignReplay.publicId}`,
        `${BASE}/${sub.publicId}/replays/${foreignReplay.publicId}`,
      ]) {
        expect((await api.http().get(path).set(bearer)).status, path).toBe(404);
      }
    });
  });

  it('documents the 13 webhook operations (tag, permissions, idempotency, examples)', () => {
    const doc = buildOpenApiDocument(api.app);
    const ops: Array<[string, string]> = [
      ['/api/v1/webhooks', 'get'],
      ['/api/v1/webhooks', 'post'],
      ['/api/v1/webhooks/event-types', 'get'],
      ['/api/v1/webhooks/{webhookId}', 'get'],
      ['/api/v1/webhooks/{webhookId}', 'patch'],
      ['/api/v1/webhooks/{webhookId}', 'delete'],
      ['/api/v1/webhooks/{webhookId}/rotate-secret', 'post'],
      ['/api/v1/webhooks/{webhookId}/test', 'post'],
      ['/api/v1/webhooks/{webhookId}/deliveries', 'get'],
      ['/api/v1/webhooks/{webhookId}/deliveries/{deliveryId}', 'get'],
      ['/api/v1/webhooks/{webhookId}/deliveries/{deliveryId}/replay', 'post'],
      ['/api/v1/webhooks/{webhookId}/replays', 'post'],
      ['/api/v1/webhooks/{webhookId}/replays/{replayId}', 'get'],
    ];
    for (const [path, method] of ops) {
      const op = (doc.paths[path] as Record<string, OpenApiOperation>)[method]!;
      expect(op.tags, `${method} ${path}`).toEqual(['webhooks']);
      for (const status of ['401', '403', '429', '500', '503']) {
        expect(op.responses[status], `${method} ${path} ${status}`).toBeDefined();
      }
    }
    const create = (doc.paths['/api/v1/webhooks'] as Record<string, OpenApiOperation>).post!;
    expect(create['x-eg-idempotency']).toBe('required');
    expect(create['x-eg-secret-replay']).toBe('redacted');
    expect(create.responses['201']!.headers['Idempotency-Replayed']).toBeDefined();
    expect(create.responses['422']).toBeDefined();
  });
});

describe('webhooks: sensitive class 429', () => {
  let api: StubbedApiApp;
  const world = new WebhooksWorld();
  const store = new InMemoryIdempotencyStore();
  beforeAll(async () => {
    api = await createStubbedApiApp(
      { API_RATE_SENSITIVE_PER_MINUTE: '2' },
      { override: (b) => store.override(overrideWebhooks(b, world, new RecordingAuditService())) },
    );
  });
  afterAll(async () => {
    await api?.close();
  });

  it('answers 429 with scope sensitive, RateLimit headers and Retry-After', async () => {
    const bearer = await api.principals.user([MANAGE, READ]).bearer();
    for (let i = 0; i < 2; i += 1) {
      const ok = await api
        .http()
        .post(BASE)
        .set(bearer)
        .set('Idempotency-Key', `s-${i}`)
        .send(validBody());
      expect(ok.status).toBe(201);
    }
    const res = await api
      .http()
      .post(`${BASE}/${world.subscriptions[0]!.publicId}/rotate-secret`)
      .set(bearer)
      .set('Idempotency-Key', 's-9')
      .send({});
    expect(res.status).toBe(429);
    expect(res.body).toMatchObject({ code: 'rate_limited', scope: 'sensitive' });
    expect(res.headers['ratelimit-remaining']).toBe('0');
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
    expect((await api.http().get(BASE).set(bearer)).status).toBe(200);
  });
});
