/**
 * The recipient suppression list (step 6.1 WP2, §3.3) against the real MySQL writer and
 * replica: create (lower-cased address, `source = api`, creator), replay and reuse of the
 * Idempotency-Key (`api_idempotency_keys` rows, state `completed`), `409 suppression_exists` and
 * `409 suppression_limit_reached` under the organization row lock (also for concurrent
 * creations), delete (unsuppress) of an API row and of a bounce row, the audit rows (address only
 * as SHA-256), list/get on the replica with the filters, and RBAC per permission.
 */
// @covers get /api/v1/recipients/suppressions
// @covers get /api/v1/recipients/suppressions/:suppressionId
// @covers post /api/v1/recipients/suppressions
// @covers delete /api/v1/recipients/suppressions/:suppressionId
import { createHash, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
} from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa, uniqueIp } from './support/http';
import { dataLength, deleteMessagesData, getAs, POLL } from './support/messages-data';

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let adminUser: FixtureUser;
let admin: Record<string, string>;
let reader: Record<string, string>;
let bounceId: bigint;
const run = randomUUID().slice(0, 8);
const sha = (v: string) => createHash('sha256').update(v).digest('hex');

beforeAll(async () => {
  ctx = await createIntegrationApp({ RECIPIENT_SUPPRESSIONS_MAX_MANUAL: '3' });
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  fx.registerCleanup(() => deleteMessagesData(ctx, [org.id]));
  adminUser = await fx.createUser(org, { roles: ['organization_admin'] });
  admin = bearer((await loginWithMfa(ctx, fx, adminUser)).accessToken);
  reader = apiKeyHeader(await fx.createApiKey(org, ['delivery:read']));
  const bounce = await ctx.prisma.deliverySuppression.create({
    data: {
      organizationId: org.id,
      address: `bounced-${run}@example.org`,
      reason: 'hard_bounce',
      source: 'bounce',
    },
    select: { id: true },
  });
  bounceId = bounce.id;
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

const post = (body: unknown, key?: string, headers = admin) => {
  const req = ctx.http
    .post('/api/v1/recipients/suppressions')
    .set(headers)
    .set('X-Forwarded-For', uniqueIp());
  if (key) req.set('Idempotency-Key', key);
  return req.send(body as object);
};
const del = (id: bigint | string, key?: string, headers = admin) => {
  const req = ctx.http
    .delete(`/api/v1/recipients/suppressions/${id}`)
    .set(headers)
    .set('X-Forwarded-For', uniqueIp());
  if (key) req.set('Idempotency-Key', key);
  return req;
};

describe('recipient suppressions against the writer and replica', () => {
  let createdId: string;
  const address = `Manual-${run}@Example.COM`;

  it('creates a suppression in one transaction with its audit row and stored response', async () => {
    const key = `create-${run}`;
    const body = {
      address: `  ${address} `,
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    };
    const res = await post(body, key);
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      address: address.toLowerCase(),
      reason: 'manual',
      source: 'api',
      active: true,
      createdBy: adminUser.publicId,
    });
    createdId = res.body.id as string;
    const row = await ctx.prisma.deliverySuppression.findUniqueOrThrow({
      where: { id: BigInt(createdId) },
    });
    expect(row).toMatchObject({
      organizationId: org.id,
      address: address.toLowerCase(),
      reason: 'manual',
      source: 'api',
      createdByUserId: adminUser.id,
    });
    expect(row.expiresAt).not.toBeNull();
    const stored = await ctx.prisma.apiIdempotencyKey.findFirstOrThrow({
      where: { organizationId: org.id, idempotencyKey: key },
    });
    expect(stored).toMatchObject({
      operation: 'recipient_suppression.create',
      statusCode: 201,
      state: 'completed',
      resourceId: '-',
    });
    const audit = await ctx.prisma.auditLog.findFirstOrThrow({
      where: {
        organizationId: org.id,
        action: 'recipient_suppression.created',
        resourceId: createdId,
      },
    });
    expect(audit.metadata).toMatchObject({
      reason: 'manual',
      source: 'api',
      addressSha256: sha(address.toLowerCase()),
    });
    expect(JSON.stringify(audit.metadata)).not.toContain(address.toLowerCase());

    const replay = await post(body, key);
    expect(replay.status).toBe(201);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual(res.body);
    expect(
      await ctx.prisma.deliverySuppression.count({
        where: { organizationId: org.id, address: address.toLowerCase() },
      }),
    ).toBe(1);
    expect(
      await ctx.prisma.auditLog.count({
        where: {
          organizationId: org.id,
          action: 'recipient_suppression.created',
          resourceId: createdId,
        },
      }),
    ).toBe(1);
  });

  it('replays an identical request and refuses a reused key (422)', async () => {
    const key = `replay-${run}`;
    const body = { address: `replay-${run}@example.com`, reason: 'unsubscribe' };
    const first = await post(body, key);
    expect(first.status).toBe(201);
    const again = await post(body, key);
    expect(again.status).toBe(201);
    expect(again.headers['idempotency-replayed']).toBe('true');
    expect(again.body).toEqual(first.body);
    const reused = await post({ address: `other-${run}@example.com` }, key);
    expect(reused.status).toBe(422);
    expect(reused.body.code).toBe('idempotency_key_reused');
    expect(
      await ctx.prisma.deliverySuppression.count({
        where: { organizationId: org.id, address: `other-${run}@example.com` },
      }),
    ).toBe(0);
  });

  it('conflicts: existing address (with id), manual limit under concurrency; nothing stored', async () => {
    const exists = await post({ address: `BOUNCED-${run}@example.org` }, `exists-${run}`);
    expect(exists.status).toBe(409);
    expect(exists.body).toMatchObject({ code: 'suppression_exists', id: bounceId.toString() });
    // Two creatable rows exist (manual + unsubscribe); the limit is 3: of two concurrent
    // creations exactly one succeeds.
    const results = await Promise.all(
      [1, 2].map((i) => post({ address: `race-${i}-${run}@example.com` }, `race-${i}-${run}`)),
    );
    expect(results.map((r) => r.status).sort()).toEqual([201, 409]);
    expect(results.find((r) => r.status === 409)!.body).toMatchObject({
      code: 'suppression_limit_reached',
      limit: 3,
    });
    const refusedKey = results[0]!.status === 409 ? `race-1-${run}` : `race-2-${run}`;
    expect(
      await ctx.prisma.apiIdempotencyKey.count({
        where: { organizationId: org.id, idempotencyKey: { in: [`exists-${run}`, refusedKey] } },
      }),
    ).toBe(0);
  });

  it('lists and gets from the replica with filters', async () => {
    await expect
      .poll(async () => dataLength(await getAs(ctx, reader, '/recipients/suppressions')), POLL)
      .toBe(4);
    const all = await getAs(ctx, reader, '/recipients/suppressions');
    expect(all.body.data.at(-1)).toMatchObject({
      id: bounceId.toString(),
      reason: 'hard_bounce',
      source: 'bounce',
      active: true,
      createdBy: null,
    });
    expect(
      (await getAs(ctx, reader, '/recipients/suppressions?reason=hard_bounce')).body.data,
    ).toHaveLength(1);
    expect(
      (await getAs(ctx, reader, `/recipients/suppressions?address=${address}`)).body.data,
    ).toEqual([expect.objectContaining({ id: createdId })]);
    expect(
      (await getAs(ctx, reader, '/recipients/suppressions?active=false')).body.data,
    ).toHaveLength(0);
    const page = await getAs(ctx, reader, '/recipients/suppressions?limit=3');
    const next = await getAs(
      ctx,
      reader,
      `/recipients/suppressions?limit=3&cursor=${encodeURIComponent(page.body.nextCursor)}`,
    );
    expect(next.body).toEqual({
      data: [expect.objectContaining({ id: bounceId.toString() })],
      nextCursor: null,
    });
    const one = await getAs(ctx, reader, `/recipients/suppressions/${createdId}`);
    expect(one.body).toMatchObject({ id: createdId, address: address.toLowerCase() });
    expect((await getAs(ctx, reader, '/recipients/suppressions/999999999999')).body.code).toBe(
      'suppression_not_found',
    );
  });

  it('deletes an API row and a bounce row (unsuppress), replays 204, audits the former reason', async () => {
    const key = `delete-${run}`;
    const res = await del(bounceId, key);
    expect(res.status).toBe(204);
    expect(await ctx.prisma.deliverySuppression.findUnique({ where: { id: bounceId } })).toBeNull();
    const replay = await del(bounceId, key);
    expect(replay.status).toBe(204);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect((await del(bounceId, `delete-again-${run}`)).status).toBe(404);
    expect((await del(createdId, `delete-api-${run}`)).status).toBe(204);
    const audits = await ctx.prisma.auditLog.findMany({
      where: { organizationId: org.id, action: 'recipient_suppression.deleted' },
      orderBy: { id: 'asc' },
    });
    expect(audits.map((a) => a.resourceId)).toEqual([bounceId.toString(), createdId]);
    expect(audits[0]!.metadata).toMatchObject({
      formerReason: 'hard_bounce',
      formerSource: 'bounce',
      addressSha256: sha(`bounced-${run}@example.org`),
    });
    const stored = await ctx.prisma.apiIdempotencyKey.findFirstOrThrow({
      where: { organizationId: org.id, idempotencyKey: key },
    });
    expect(stored).toMatchObject({
      operation: 'recipient_suppression.delete',
      statusCode: 204,
      resourceId: bounceId.toString(),
      state: 'completed',
    });
  });

  it('RBAC: delivery:read cannot mutate; missing key is 400', async () => {
    const res = await post({ address: `nope-${run}@example.com` }, `rbac-${run}`, reader);
    expect(res.status).toBe(403);
    expect((await del('1', `rbac-d-${run}`, reader)).status).toBe(403);
    const missing = await post({ address: `nope-${run}@example.com` });
    expect(missing.status).toBe(400);
    expect(missing.body.code).toBe('idempotency_key_required');
  });
});
