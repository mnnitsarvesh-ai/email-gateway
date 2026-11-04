/**
 * Per-recipient delivery status (step 2.3 R13) against the real MySQL writer and replica, with
 * message, recipient, delivery and status-event rows inserted by SQL (the delivery-worker and
 * the smtp-adapter write them): the message view, the audit trail (oldest first, rcptSeq
 * filter, pagination), the tenant-wide list (filters, the 31-day range limit, keyset
 * pagination) and the permission.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  unknownId,
} from './support/fixtures';
import { apiKeyHeader } from './support/http';
import {
  type DeliveredMessage,
  DeliveryApi,
  deleteDeliveryFixtures,
  insertDeliveredMessage,
} from './support/routing';

const POLL = { timeout: 10_000, interval: 200 };

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let api: DeliveryApi;
let mixed: DeliveredMessage;
let older: DeliveredMessage;
const base = new Date(Date.now() - 2 * 3600_000);

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  fx.registerCleanup(() => deleteDeliveryFixtures(ctx, [org.id]));
  api = new DeliveryApi(ctx, apiKeyHeader(await fx.createApiKey(org, ['delivery:read'])));
  mixed = await insertDeliveredMessage(ctx, org, {
    direction: 'outbound',
    receivedAt: base,
    recipients: [
      {
        address: 'colleague@acme.example',
        direction: 'internal',
        status: 'delivered',
        attemptCount: 1,
        events: [
          { source: 'planner', fromStatus: null, toStatus: 'pending' },
          { source: 'reinjection', fromStatus: 'pending', toStatus: 'queued' },
          { source: 'postfix_log', fromStatus: 'queued', toStatus: 'delivered' },
        ],
      },
      {
        address: 'gone@partner.example',
        direction: 'outbound',
        status: 'bounced',
        attemptCount: 1,
        lastErrorClass: 'remote_5xx',
        dsnQueueId: 'DSN42',
        events: [
          { source: 'planner', fromStatus: null, toStatus: 'pending' },
          { source: 'postfix_log', fromStatus: 'pending', toStatus: 'bounced' },
          {
            source: 'bounce_notice',
            fromStatus: 'bounced',
            toStatus: 'bounced',
            applied: false,
            detail: 'smtp; 550 5.1.1 unknown',
          },
        ],
      },
    ],
  });
  older = await insertDeliveredMessage(ctx, org, {
    direction: 'inbound',
    receivedAt: new Date(Date.now() - 3 * 86_400_000),
    recipients: [{ address: 'alice@acme.example', status: 'deferred', lastErrorClass: 'connect' }],
  });
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('GET /messages/{messageId}/deliveries', () => {
  it('returns every recipient’s delivery with the R13 fields and no internal ids', async () => {
    await expect.poll(async () => (await api.forMessage(mixed.publicId)).status, POLL).toBe(200);
    const res = await api.forMessage(mixed.publicId).expect(200);
    expect(res.body.message).toEqual({
      id: mixed.publicId,
      direction: 'outbound',
      status: 'delivery_pending',
      statusReason: null,
      receivedAt: base.toISOString(),
    });
    expect(res.body.deliveries).toHaveLength(2);
    expect(res.body.deliveries[0]).toEqual({
      rcptSeq: 0,
      deliverySeq: 0,
      recipient: 'colleague@acme.example',
      direction: 'internal',
      status: 'delivered',
      attemptCount: 1,
      lastAttemptAt: null,
      deliveredAt: null,
      remoteHost: null,
      finalSmtpCode: null,
      enhancedStatus: null,
      finalSmtpResponse: null,
      lastErrorClass: null,
      failureReason: null,
      dsnGenerated: false,
      statusChangedAt: base.toISOString(),
    });
    expect(res.body.deliveries[1]).toMatchObject({
      rcptSeq: 1,
      status: 'bounced',
      lastErrorClass: 'remote_5xx',
      dsnGenerated: true,
    });
    const text = JSON.stringify(res.body);
    for (const id of [...mixed.deliveryIds, ...mixed.recipientIds, mixed.id]) {
      expect(text).not.toContain(`"${id.toString()}"`);
    }
    expect(text).not.toContain('DSN42');
  });

  it('404 for an unknown message id', async () => {
    await api.forMessage(unknownId()).expect(404);
    await api.events(unknownId()).expect(404);
  });
});

describe('GET /messages/{messageId}/deliveries/events', () => {
  it('lists the audit trail oldest first, paginated, with an rcptSeq filter', async () => {
    const first = await api.events(mixed.publicId, '?limit=4').expect(200);
    expect(
      first.body.data.map((e: { rcptSeq: number; toStatus: string }) => [e.rcptSeq, e.toStatus]),
    ).toEqual([
      [0, 'pending'],
      [0, 'queued'],
      [0, 'delivered'],
      [1, 'pending'],
    ]);
    expect(first.body.nextCursor).toEqual(expect.any(String));
    const second = await api
      .events(mixed.publicId, `?limit=4&cursor=${first.body.nextCursor as string}`)
      .expect(200);
    expect(
      second.body.data.map((e: { toStatus: string; applied: boolean }) => [e.toStatus, e.applied]),
    ).toEqual([
      ['bounced', true],
      ['bounced', false],
    ]);
    expect(second.body.nextCursor).toBeNull();
    expect(second.body.data[1]).toMatchObject({
      source: 'bounce_notice',
      fromStatus: 'bounced',
      deliverySeq: 0,
      detail: 'smtp; 550 5.1.1 unknown',
    });

    const one = await api.events(mixed.publicId, '?rcptSeq=1').expect(200);
    expect(one.body.data.map((e: { rcptSeq: number }) => e.rcptSeq)).toEqual([1, 1, 1]);
    const none = await api.events(mixed.publicId, '?rcptSeq=7').expect(200);
    expect(none.body).toEqual({ data: [], nextCursor: null });
    await api.events(mixed.publicId, '?cursor=not-a-cursor').expect(400);
  });
});

describe('GET /deliveries', () => {
  it('lists the last 24 hours by default, newest first', async () => {
    const res = await api.list().expect(200);
    const mine = (res.body.data as Array<{ messageId: string; rcptSeq: number }>).filter(
      (d) => d.messageId === mixed.publicId,
    );
    expect(mine.map((d) => d.rcptSeq)).toEqual([1, 0]);
    expect(res.body.data.some((d: { messageId: string }) => d.messageId === older.publicId)).toBe(
      false,
    );
    expect(res.body.data[0]).toEqual({
      messageId: mixed.publicId,
      rcptSeq: 1,
      recipient: 'gone@partner.example',
      direction: 'outbound',
      status: 'bounced',
      attemptCount: 1,
      lastErrorClass: 'remote_5xx',
      statusChangedAt: base.toISOString(),
    });
  });

  it('filters by status and direction, and by an explicit range', async () => {
    const internal = await api.list('?direction=internal').expect(200);
    expect(internal.body.data.map((d: { recipient: string }) => d.recipient)).toEqual([
      'colleague@acme.example',
    ]);
    const bounced = await api.list('?status=bounced').expect(200);
    expect(bounced.body.data.map((d: { recipient: string }) => d.recipient)).toEqual([
      'gone@partner.example',
    ]);
    const from = new Date(Date.now() - 5 * 86_400_000).toISOString();
    // `to` defaults to now.
    expect((await api.list(`?from=${from}`).expect(200)).body.data).toHaveLength(3);
    const to = new Date().toISOString();
    const ranged = await api.list(`?from=${from}&to=${to}`).expect(200);
    expect(ranged.body.data.map((d: { messageId: string }) => d.messageId)).toEqual([
      mixed.publicId,
      mixed.publicId,
      older.publicId,
    ]);
  });

  it('refuses a range over 31 days and an inverted range (400)', async () => {
    const to = new Date();
    const from = new Date(to.getTime() - 32 * 86_400_000);
    const res = await api.list(`?from=${from.toISOString()}&to=${to.toISOString()}`).expect(400);
    expect(res.body.message).toEqual(['to: the range may cover at most 31 days']);
    await api.list(`?from=${to.toISOString()}&to=${from.toISOString()}`).expect(400);
  });

  it('paginates with a keyset cursor', async () => {
    const from = new Date(Date.now() - 5 * 86_400_000).toISOString();
    const seen: string[] = [];
    let cursor: string | null = null;
    do {
      const query: string = `?from=${from}&to=${new Date().toISOString()}&limit=1${cursor ? `&cursor=${cursor}` : ''}`;
      const res = await api.list(query).expect(200);
      for (const d of res.body.data as Array<{ messageId: string; rcptSeq: number }>) {
        seen.push(`${d.messageId}:${d.rcptSeq}`);
      }
      cursor = res.body.nextCursor as string | null;
    } while (cursor !== null);
    expect(seen).toEqual([`${mixed.publicId}:1`, `${mixed.publicId}:0`, `${older.publicId}:0`]);
    await api.list('?cursor=bogus').expect(400);
  });

  it('needs delivery:read', async () => {
    const none = new DeliveryApi(ctx, apiKeyHeader(await fx.createApiKey(org, ['domain:read'])));
    await none.list().expect(403);
    await none.forMessage(mixed.publicId).expect(403);
    await none.events(mixed.publicId).expect(403);
  });
});
