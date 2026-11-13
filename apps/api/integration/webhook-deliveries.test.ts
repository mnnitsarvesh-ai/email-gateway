/**
 * Webhook delivery history, test pings and replays (step 6.2 W8, W12, §6.1) against the real
 * MySQL writer and replica and Redis: the test route writes a valid `webhook.ping` event and a
 * `trigger = test` delivery in one transaction (limited per webhook in Redis), the history is a
 * bounded v1 cursor list on the replica (EXPLAIN: `webhook_deliveries_sub_occurred_id_idx`,
 * pruned partitions, no filesort), the detail joins attempts and the stored envelope (null once
 * the event is gone), the single replay inserts `delivery_seq = max + 1` in the api transaction
 * (limit, `410` for an expired event), and the range replay queues one `webhook_replays` row at a
 * time (limited per organization).
 */
// @covers post /api/v1/webhooks/:webhookId/test
// @covers get /api/v1/webhooks/:webhookId/deliveries
// @covers get /api/v1/webhooks/:webhookId/deliveries/:deliveryId
// @covers post /api/v1/webhooks/:webhookId/deliveries/:deliveryId/replay
// @covers post /api/v1/webhooks/:webhookId/replays
// @covers get /api/v1/webhooks/:webhookId/replays/:replayId
import { randomUUID } from 'node:crypto';
import { parseStoredEnvelope } from '@email-gateway/webhooks';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  deliveriesBoundarySql,
  deliveriesPageSql,
} from '../src/modules/webhooks/repositories/webhook-deliveries.repository';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { bearer, loginWithMfa } from './support/http';
import { explain, partitionsOf } from './support/insights';
import { POLL } from './support/messages-data';
import {
  createBody,
  http,
  type SeededDelivery,
  seedDelivery,
  subscriptionRow,
  webhookAudit,
  WEBHOOKS,
  bodyOf,
} from './support/webhooks';

const MINUTE = 60_000;

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let admin: ReturnType<typeof http>;
let hook: string;
let sub: Awaited<ReturnType<typeof subscriptionRow>>;
const seeded: SeededDelivery[] = [];
const base = Date.now() - 30 * MINUTE;

beforeAll(async () => {
  ctx = await createIntegrationApp({
    WEBHOOK_TEST_REQUESTS_PER_MINUTE: '2',
    WEBHOOK_REPLAY_REQUESTS_PER_HOUR: '3',
    WEBHOOK_REPLAY_MAX_PER_DELIVERY: '2',
  });
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  const user = await fx.createUser(org, { roles: ['organization_admin'] });
  admin = http(ctx, bearer((await loginWithMfa(ctx, fx, user)).accessToken));
  const res = await admin.post(WEBHOOKS, createBody(), `it-${randomUUID()}`);
  hook = res.body.id;
  sub = await subscriptionRow(ctx, hook);
  for (let i = 0; i < 5; i += 1) {
    seeded.push(
      await seedDelivery(ctx, sub, {
        occurredAt: new Date(base + i * MINUTE),
        organizationPublicId: org.publicId,
        status: i % 2 === 0 ? 'succeeded' : 'dead',
        attempts: i % 2 === 0 ? 1 : 3,
      }),
    );
  }
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('webhook deliveries against the writer and replica', () => {
  it('lists the history newest first with a v1 cursor, filters and replica polling', async () => {
    const path = `${WEBHOOKS}/${hook}/deliveries`;
    await expect
      .poll(async () => bodyOf(await admin.get(`${path}?limit=100`)).data?.length, POLL)
      .toBe(5);
    const all = (await admin.get(`${path}?limit=100`)).body.data as Array<{ id: string }>;
    expect(all.map((d) => d.id)).toEqual([...seeded].reverse().map((d) => d.publicId));
    const first = await admin.get(`${path}?limit=2`);
    const second = await admin.get(
      `${path}?limit=2&cursor=${encodeURIComponent(first.body.nextCursor)}`,
    );
    const third = await admin.get(
      `${path}?limit=2&cursor=${encodeURIComponent(second.body.nextCursor)}`,
    );
    expect(
      [...first.body.data, ...second.body.data, ...third.body.data].map(
        (d: { id: string }) => d.id,
      ),
    ).toEqual(all.map((d) => d.id));
    expect(third.body.nextCursor).toBeNull();
    const dead = await admin.get(`${path}?status=dead`);
    expect(dead.body.data.map((d: { id: string }) => d.id)).toEqual([
      seeded[3]!.publicId,
      seeded[1]!.publicId,
    ]);
    expect(dead.body.data[0]).toMatchObject({
      status: 'dead',
      lastError: 'http_500',
      attemptCount: 3,
    });
    const old = encodeURIComponent(new Date(Date.now() - 40 * 86_400_000).toISOString());
    expect((await admin.get(`${path}?from=${old}`)).status).toBe(400);
    expect((await admin.get(`${path}?cursor=nope`)).body.code).toBe('cursor_invalid');
  });

  it('reads the history over the keyset index with pruned partitions and no filesort (EXPLAIN)', async () => {
    const all = await partitionsOf(ctx, 'webhook_deliveries');
    const input = {
      organizationId: org.id,
      subscriptionId: sub.id,
      range: { from: new Date(Date.now() - 86_400_000), to: new Date() },
      direction: 'desc' as const,
      take: 26,
    };
    for (const sql of [
      deliveriesPageSql(input),
      deliveriesPageSql({
        ...input,
        after: { at: new Date(base + 3 * MINUTE), id: seeded[3]!.id },
        filters: { statuses: ['dead'], eventTypes: ['webhook.ping'], triggers: ['event'] },
        boundary: { at: new Date(base), id: seeded[0]!.id },
      }),
      deliveriesBoundarySql({ ...input, budget: 5000 }),
    ]) {
      const { tables, text } = await explain(ctx, sql);
      const t = tables.find((x) => x.table_name === 'webhook_deliveries')!;
      expect(t.key, text).toBe('webhook_deliveries_sub_occurred_id_idx');
      expect(['range', 'ref']).toContain(t.access_type);
      expect(t.partitions!.length, text).toBeLessThan(all.length);
      expect(text).not.toMatch(/"using_filesort": true/);
    }
  });

  it('serves a delivery with its attempts and the stored envelope; null once the event is gone', async () => {
    const d = seeded[1]!;
    await expect
      .poll(
        async () => (await admin.get(`${WEBHOOKS}/${hook}/deliveries/${d.publicId}`)).status,
        POLL,
      )
      .toBe(200);
    const res = await admin.get(`${WEBHOOKS}/${hook}/deliveries/${d.publicId}`);
    expect(res.body.attempts.map((a: { attemptNo: number }) => a.attemptNo)).toEqual([1, 2, 3]);
    expect(res.body.attempts[0]).toMatchObject({
      outcome: 'http_error',
      httpStatus: 500,
      signatureCount: 1,
    });
    expect(res.body.event).toMatchObject({
      id: d.eventId,
      type: 'webhook.ping',
      organizationId: org.publicId,
    });
    const gone = await seedDelivery(ctx, sub, {
      occurredAt: new Date(base + 10 * MINUTE),
      organizationPublicId: org.publicId,
      withoutEvent: true,
    });
    await expect
      .poll(
        async () => (await admin.get(`${WEBHOOKS}/${hook}/deliveries/${gone.publicId}`)).status,
        POLL,
      )
      .toBe(200);
    expect(
      (await admin.get(`${WEBHOOKS}/${hook}/deliveries/${gone.publicId}`)).body.event,
    ).toBeNull();
    const missing = await admin.get(`${WEBHOOKS}/${hook}/deliveries/${randomUUID()}`);
    expect(missing.body.code).toBe('webhook_delivery_not_found');
  });

  it('replays one delivery in the api transaction (seq + 1, limit, idempotent); 410 when the event is gone', async () => {
    const d = seeded[3]!;
    const url = `${WEBHOOKS}/${hook}/deliveries/${d.publicId}/replay`;
    const key = `it-${randomUUID()}`;
    const res = await admin.post(url, {}, key);
    expect(res.status).toBe(202);
    const row = await ctx.prisma.webhookDelivery.findFirstOrThrow({
      where: { publicId: res.body.deliveryId, organizationId: org.id },
    });
    expect(row).toMatchObject({
      subscriptionId: sub.id,
      eventId: d.eventId,
      eventOccurredAt: d.occurredAt,
      deliverySeq: 1,
      trigger: 'replay',
      status: 'pending',
    });
    const replay = await admin.post(url, {}, key);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual(res.body);
    expect((await admin.post(url, {}, `it-${randomUUID()}`)).status).toBe(202);
    const limited = await admin.post(url, {}, `it-${randomUUID()}`);
    expect(limited.body).toMatchObject({ code: 'webhook_replay_limit', limit: 2 });
    expect(
      await ctx.prisma.webhookDelivery.count({
        where: { subscriptionId: sub.id, eventId: d.eventId, eventOccurredAt: d.occurredAt },
      }),
    ).toBe(3);
    const audit = (await webhookAudit(ctx, hook)).filter(
      (a) => a.action === 'webhook.delivery_replayed',
    );
    expect(audit).toHaveLength(2);
    expect(audit[0]!.metadata).toMatchObject({ deliveryId: d.publicId, deliverySeq: 1 });
    // The event's partition row is gone (retention): 410.
    const lost = await seedDelivery(ctx, sub, {
      occurredAt: new Date(base + 11 * MINUTE),
      organizationPublicId: org.publicId,
      withoutEvent: true,
    });
    const expired = await admin.post(
      `${WEBHOOKS}/${hook}/deliveries/${lost.publicId}/replay`,
      {},
      `it-${randomUUID()}`,
    );
    expect(expired.status).toBe(410);
    expect(expired.body.code).toBe('webhook_event_expired');
  });

  it('queues a test ping (valid envelope, test delivery) and limits it per webhook in Redis', async () => {
    const url = `${WEBHOOKS}/${hook}/test`;
    const res = await admin.post(url);
    expect(res.status).toBe(202);
    const event = await ctx.prisma.webhookEvent.findFirstOrThrow({
      where: { eventId: res.body.eventId, organizationId: org.id },
    });
    expect(event).toMatchObject({ eventType: 'webhook.ping', severity: 'info' });
    expect(parseStoredEnvelope(event.payloadJson)).toMatchObject({
      id: res.body.eventId,
      organizationId: org.publicId,
      data: { subscriptionId: hook },
    });
    const delivery = await ctx.prisma.webhookDelivery.findFirstOrThrow({
      where: { publicId: res.body.deliveryId },
    });
    expect(delivery).toMatchObject({
      trigger: 'test',
      status: 'pending',
      deliverySeq: 0,
      eventOccurredAt: event.occurredAt,
    });
    expect((await admin.post(url)).status).toBe(202);
    const limited = await admin.post(url);
    expect(limited.status).toBe(429);
    expect(limited.body).toMatchObject({ code: 'rate_limited', scope: 'route' });
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('queues a range replay, one at a time, readable from the replica; limited per organization', async () => {
    const url = `${WEBHOOKS}/${hook}/replays`;
    const body = {
      from: new Date(base - MINUTE).toISOString(),
      to: new Date().toISOString(),
      eventTypes: ['email.received'],
    };
    const res = await admin.post(url, body, `it-${randomUUID()}`);
    expect(res.status).toBe(202);
    expect(res.body.status).toBe('queued');
    const row = await ctx.prisma.webhookReplay.findUniqueOrThrow({
      where: { publicId: res.body.replayId },
    });
    expect(row).toMatchObject({
      organizationId: org.id,
      subscriptionId: sub.id,
      requestedByType: 'user',
      status: 'queued',
      statuses: ['failed', 'dead'],
      eventTypes: ['email.received'],
    });
    await expect
      .poll(
        async () => (await admin.get(`${WEBHOOKS}/${hook}/replays/${res.body.replayId}`)).status,
        POLL,
      )
      .toBe(200);
    const view = await admin.get(`${WEBHOOKS}/${hook}/replays/${res.body.replayId}`);
    expect(view.body).toMatchObject({ id: res.body.replayId, status: 'queued', matchedCount: 0 });
    const busy = await admin.post(url, body, `it-${randomUUID()}`);
    expect(busy.body).toMatchObject({
      code: 'webhook_replay_in_progress',
      replayId: res.body.replayId,
    });
    await ctx.prisma.webhookReplay.update({
      where: { id: row.id },
      data: { status: 'completed', completedAt: new Date() },
    });
    expect((await admin.post(url, body, `it-${randomUUID()}`)).status).toBe(202);
    const limited = await admin.post(url, body, `it-${randomUUID()}`);
    expect(limited.status).toBe(429);
    expect(limited.body).toMatchObject({ code: 'rate_limited', scope: 'route' });
    expect(
      (await webhookAudit(ctx, hook)).filter((a) => a.action === 'webhook.replay_requested'),
    ).toHaveLength(2);
  });
});
