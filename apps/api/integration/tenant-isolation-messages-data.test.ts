/**
 * Tenant isolation of the step 6.1 WP2 routes (§9 cross-tenant): organizations A and B hold
 * identical fixture shapes (same recipient address, same attachment hash, same URL, clicks and a
 * suppression of the same address). An organization admin and an API key of A with every
 * permission get `404` for every B id (message detail, recipients, attachments, URLs,
 * suppression get/delete, the `messageId` and `domainId` filters), lists never contain B rows,
 * an A cursor presented by B is `400 cursor_invalid`, an Idempotency-Key used by B never replays
 * B's response for A, and nothing of B changes.
 */
// @covers get /api/v1/messages
// @covers get /api/v1/messages/:messageId
// @covers get /api/v1/messages/:messageId/recipients
// @covers get /api/v1/messages/:messageId/attachments
// @covers get /api/v1/attachments
// @covers get /api/v1/messages/:messageId/urls
// @covers get /api/v1/url-protection/clicks
// @covers get /api/v1/recipients/suppressions
// @covers get /api/v1/recipients/suppressions/:suppressionId
// @covers post /api/v1/recipients/suppressions
// @covers delete /api/v1/recipients/suppressions/:suppressionId
import { createHash, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa, uniqueIp } from './support/http';
import {
  dataLength,
  deleteMessagesData,
  getAs,
  POLL,
  type SeededMessage,
  seedMessage,
} from './support/messages-data';

const EVERY = ['message:read', 'delivery:read', 'delivery:suppression_manage'];
const MIN = 60_000;

interface Tenant {
  org: FixtureOrganization;
  message: SeededMessage;
  domainPublicId: string;
  suppressionId: bigint;
  admin: Record<string, string>;
  key: Record<string, string>;
}

let ctx: IntegrationApp;
let fx: Fixtures;
let a: Tenant;
let b: Tenant;
const run = randomUUID().slice(0, 8);
const shared = `shared-${run}@acme.example`;
const hash = createHash('sha256').update(run).digest('hex');

async function tenant(): Promise<Tenant> {
  const org = await fx.createOrganization();
  const domain = await ctx.prisma.domain.create({
    data: { organizationId: org.id, name: `iso-${uniqueName()}.example` },
    select: { id: true, publicId: true },
  });
  const now = Date.now();
  const message = await seedMessage(ctx, org, {
    receivedAt: new Date(now - 20 * MIN),
    domainId: domain.id,
    recipients: [shared],
    envelopeFrom: `same-${run}@vendor.example`,
    attachments: [{ sha256: hash }],
    urls: [{ url: `https://same-${run}.example/`, host: `same-${run}.example` }],
    clicks: [{ urlSeq: 0, decision: 'blocked', clickedAt: new Date(now - 10 * MIN) }],
  });
  const suppression = await ctx.prisma.deliverySuppression.create({
    data: { organizationId: org.id, address: shared, reason: 'manual', source: 'api' },
    select: { id: true },
  });
  const admin = bearer(
    (await loginWithMfa(ctx, fx, await fx.createUser(org, { roles: ['organization_admin'] })))
      .accessToken,
  );
  const key = apiKeyHeader(await fx.createApiKey(org, EVERY));
  return {
    org,
    message,
    domainPublicId: domain.publicId,
    suppressionId: suppression.id,
    admin,
    key,
  };
}

let counter = 0;
const uniqueName = () => `${run}-${(counter += 1)}`;

async function snapshotB() {
  const where = { organizationId: b.org.id };
  return {
    suppressions: await ctx.prisma.deliverySuppression.findMany({ where, orderBy: { id: 'asc' } }),
    keys: await ctx.prisma.apiIdempotencyKey.count({ where }),
    messages: await ctx.prisma.emailMessage.count({ where }),
    clicks: await ctx.prisma.urlClickEvent.count({ where }),
    audits: await ctx.prisma.auditLog.count({
      where: { ...where, action: { startsWith: 'recipient_suppression.' } },
    }),
  };
}

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  a = await tenant();
  b = await tenant();
  fx.registerCleanup(() => deleteMessagesData(ctx, [a.org.id, b.org.id]));
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe.each([
  ['organization admin', () => a.admin],
  ['API key with every permission', () => a.key],
])('tenant A (%s)', (_label, headersOf) => {
  it('sees its own rows (replica visibility)', async () => {
    const headers = headersOf();
    await expect
      .poll(async () => (await getAs(ctx, headers, `/messages/${a.message.publicId}`)).status, POLL)
      .toBe(200);
    await expect
      .poll(async () => dataLength(await getAs(ctx, headers, '/url-protection/clicks')), POLL)
      .toBe(1);
  });

  it('gets 404 for every B id and every B id filter; nothing of B changes', async () => {
    const headers = headersOf();
    const before = await snapshotB();
    const id = b.message.publicId;
    for (const path of [
      `/messages/${id}`,
      `/messages/${id}/recipients`,
      `/messages/${id}/attachments`,
      `/messages/${id}/urls`,
      `/url-protection/clicks?messageId=${id}`,
    ]) {
      const res = await getAs(ctx, headers, path);
      expect({ path, status: res.status, code: res.body.code }).toEqual({
        path,
        status: 404,
        code: 'message_not_found',
      });
    }
    const domain = await getAs(ctx, headers, `/messages?domainId=${b.domainPublicId}`);
    expect(domain.status).toBe(404);
    expect(domain.body.code).toBe('domain_not_found');
    const get = await getAs(ctx, headers, `/recipients/suppressions/${b.suppressionId}`);
    expect(get.status).toBe(404);
    expect(get.body.code).toBe('suppression_not_found');
    const del = await ctx.http
      .delete(`/api/v1/recipients/suppressions/${b.suppressionId}`)
      .set(headers)
      .set('X-Forwarded-For', uniqueIp())
      .set('Idempotency-Key', `iso-del-${randomUUID()}`);
    expect(del.status).toBe(404);
    expect(del.body.code).toBe('suppression_not_found');
    expect(await snapshotB()).toEqual(before);
  });

  it('lists never contain B rows (identical shapes)', async () => {
    const headers = headersOf();
    const from = new Date(Date.now() - 86_400_000).toISOString();
    const queries = [
      '/messages',
      `/messages?recipient=${shared}`,
      `/messages?sender=same-${run}@vendor.example`,
      '/messages?verdict=clean',
      `/attachments?sha256=${hash}&from=${from}`,
      '/url-protection/clicks',
      '/recipients/suppressions',
      `/recipients/suppressions?address=${shared}`,
    ];
    for (const path of queries) {
      const res = await getAs(ctx, headers, path);
      expect(res.status, path).toBe(200);
      const text = JSON.stringify(res.body);
      expect(text, path).not.toContain(b.message.publicId);
      expect(text, path).not.toContain(`"${b.suppressionId}"`);
      expect(text, path).not.toContain(b.domainPublicId);
    }
    expect((await getAs(ctx, headers, `/messages?recipient=${shared}`)).body.data).toEqual([
      expect.objectContaining({ id: a.message.publicId, domainId: a.domainPublicId }),
    ]);
  });
});

describe('cursors and Idempotency-Keys across tenants', () => {
  it('a cursor of A presented by B is 400 cursor_invalid on every v1 list', async () => {
    await expect
      .poll(async () => dataLength(await getAs(ctx, a.key, '/messages?limit=1')), POLL)
      .toBe(1);
    // A second A row of each list, so that A's first page has a nextCursor.
    const extra = await seedMessage(ctx, a.org, {
      receivedAt: new Date(Date.now() - 30 * MIN),
      recipients: [shared, `two-${run}@acme.example`],
      attachments: [{ sha256: hash }, { sha256: hash }],
      urls: [
        { url: `https://x-${run}.example/`, host: `x-${run}.example` },
        { url: `https://y-${run}.example/`, host: `y-${run}.example` },
      ],
      clicks: [{ urlSeq: 0, decision: 'allowed', clickedAt: new Date(Date.now() - 5 * MIN) }],
    });
    await ctx.prisma.deliverySuppression.create({
      data: {
        organizationId: a.org.id,
        address: `second-${run}@acme.example`,
        reason: 'manual',
        source: 'api',
      },
    });
    const from = new Date(Date.now() - 86_400_000).toISOString();
    const lists = [
      '/messages?limit=1',
      `/messages/${extra.publicId}/recipients?limit=1`,
      `/messages/${extra.publicId}/attachments?limit=1`,
      `/messages/${extra.publicId}/urls?limit=1`,
      `/attachments?sha256=${hash}&from=${from}&limit=1`,
      '/url-protection/clicks?limit=1',
      '/recipients/suppressions?limit=1',
    ];
    for (const path of lists) {
      let cursor: string | null = null;
      await expect
        .poll(async () => {
          cursor = (await getAs(ctx, a.key, path)).body.nextCursor as string | null;
          return typeof cursor;
        }, POLL)
        .toBe('string');
      const res = await getAs(ctx, b.key, `${path}&cursor=${encodeURIComponent(cursor!)}`);
      // Message sub-resources of A are 404 for B before the cursor matters.
      if (path.includes(extra.publicId)) {
        expect([400, 404], path).toContain(res.status);
        const own = path.replace(extra.publicId, b.message.publicId);
        const bound = await getAs(ctx, b.key, `${own}&cursor=${encodeURIComponent(cursor!)}`);
        expect(bound.status, own).toBe(400);
        expect(bound.body.code).toBe('cursor_invalid');
      } else {
        expect(res.status, path).toBe(400);
        expect(res.body.code, path).toBe('cursor_invalid');
      }
    }
  });

  it("an Idempotency-Key used by B never replays B's response for A", async () => {
    const key = `shared-key-${run}`;
    const body = { address: `idem-${run}@acme.example` };
    const post = (headers: Record<string, string>) =>
      ctx.http
        .post('/api/v1/recipients/suppressions')
        .set(headers)
        .set('X-Forwarded-For', uniqueIp())
        .set('Idempotency-Key', key)
        .send(body);
    const fromB = await post(b.key);
    expect(fromB.status).toBe(201);
    const fromA = await post(a.key);
    expect(fromA.status).toBe(201);
    expect(fromA.headers['idempotency-replayed']).toBeUndefined();
    expect(fromA.body.id).not.toBe(fromB.body.id);
    const rowA = await ctx.prisma.deliverySuppression.findUniqueOrThrow({
      where: { id: BigInt(fromA.body.id) },
    });
    expect(rowA.organizationId).toBe(a.org.id);
    expect(await ctx.prisma.apiIdempotencyKey.count({ where: { idempotencyKey: key } })).toBe(2);
    // A delete with B's key and B's row id: 404 for A, B's row stays.
    const del = await ctx.http
      .delete(`/api/v1/recipients/suppressions/${fromB.body.id}`)
      .set(a.key)
      .set('X-Forwarded-For', uniqueIp())
      .set('Idempotency-Key', `del-${key}`);
    expect(del.status).toBe(404);
    expect(
      await ctx.prisma.deliverySuppression.findUnique({ where: { id: BigInt(fromB.body.id) } }),
    ).not.toBeNull();
  });
});
