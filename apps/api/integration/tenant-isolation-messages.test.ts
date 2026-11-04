/**
 * Tenant isolation of the step 3.3 lifecycle routes (L10.1, L12, ADR-0016): an organization
 * admin and an API key of tenant A with every lifecycle permission get `404 message_not_found`
 * (never `403`) for the lifecycle reads, the rescan and the release of a tenant B message, and
 * change nothing of B (state, version, history, outbox, idempotency records). An Idempotency-Key
 * of A never replays B's response. Platform users see nothing without an override; super_admin
 * under an override into B can release B's message, audited with `metadata.override`.
 */
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
} from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa, uniqueIp } from './support/http';
import {
  deleteLifecycleFixtures,
  insertLifecycleMessage,
  LifecycleApi,
  type LifecycleMessage,
  writerState,
} from './support/lifecycle';
import { pauseLiveRelay } from './support/live-relay';

const ALL = ['message:read', 'message:rescan', 'quarantine:release'];
const POLL = { timeout: 15_000, interval: 200 };
const reason = 'tenant isolation probe of the lifecycle';

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let messageA: LifecycleMessage;
let messageB: LifecycleMessage;
let adminA: Record<string, string>;
let keyA: Record<string, string>;
let keyB: Record<string, string>;

const headersFor = async (user: FixtureUser) =>
  bearer((await loginWithMfa(ctx, fx, user)).accessToken);

async function snapshotB() {
  const state = await writerState(ctx, messageB);
  return {
    row: state.row,
    history: state.history.length,
    outbox: state.outbox.length,
    events: state.events.length,
    keys: await ctx.prisma.apiIdempotencyKey.count({ where: { organizationId: orgB.id } }),
  };
}

/** Every lifecycle route on B's message answers `status` (with exceptions) and changes nothing. */
async function expectEveryRoute(
  headers: Record<string, string>,
  status: number,
  except: Record<string, number> = {},
): Promise<void> {
  const api = new LifecycleApi(ctx, headers);
  const body = { expectedVersion: messageB.version, reason };
  const before = await snapshotB();
  const calls: Array<[string, () => ReturnType<LifecycleApi['lifecycle']>]> = [
    ['GET lifecycle', () => api.lifecycle(messageB.publicId)],
    ['GET history', () => api.history(messageB.publicId)],
    ['POST rescan', () => api.rescan(messageB.publicId, body, `iso-${randomUUID()}`)],
    ['POST release', () => api.release(messageB.publicId, body, `iso-${randomUUID()}`)],
  ];
  for (const [label, call] of calls) {
    const res = await call();
    const expected = except[label] ?? status;
    expect({ label, status: res.status }).toEqual({ label, status: expected });
    if (expected === 404) {
      expect(res.body.code, label).toBe('message_not_found');
      const text = JSON.stringify(res.body);
      expect(text).not.toContain('quarantined');
      expect(text).not.toContain(orgB.publicId);
    }
  }
  expect(await snapshotB()).toEqual(before);
}

let resumeLiveRelay: (() => Promise<void>) | undefined;

beforeAll(async () => {
  // A live event-relay would publish this suite's approval/rescan rows (L16, live-relay.ts).
  resumeLiveRelay = await pauseLiveRelay();
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  [orgA, orgB] = [await fx.createOrganization(), await fx.createOrganization()];
  fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgA.id, orgB.id]));
  adminA = await headersFor(await fx.createUser(orgA, { roles: ['organization_admin'] }));
  keyA = apiKeyHeader(await fx.createApiKey(orgA, ALL));
  keyB = apiKeyHeader(await fx.createApiKey(orgB, ALL));
  messageA = await insertLifecycleMessage(ctx, orgA, { state: 'quarantined' });
  messageB = await insertLifecycleMessage(ctx, orgB, { state: 'quarantined' });
}, 180_000);

afterAll(async () => {
  try {
    await fx?.cleanup();
    await ctx?.close();
  } finally {
    await resumeLiveRelay?.();
  }
}, 180_000);

describe('tenant A (organization admin and API key)', () => {
  it('reads its own message and gets 404 for every lifecycle route of B, changing nothing', async () => {
    await expect
      .poll(
        async () => (await new LifecycleApi(ctx, keyA).lifecycle(messageA.publicId)).status,
        POLL,
      )
      .toBe(200);
    await expectEveryRoute(adminA, 404);
    await expectEveryRoute(keyA, 404);
  });

  it('a read-only user of A gets 404 for reads and 403 for writes (permission first)', async () => {
    const headers = await headersFor(await fx.createUser(orgA, { roles: ['read_only_user'] }));
    await expectEveryRoute(headers, 404, { 'POST rescan': 403, 'POST release': 403 });
  });

  it('an Idempotency-Key used by B is A’s own key space (no replay of B’s response)', async () => {
    const idempotencyKey = `shared-${randomUUID()}`;
    const b = await new LifecycleApi(ctx, keyB)
      .rescan(messageB.publicId, { expectedVersion: messageB.version, reason }, idempotencyKey)
      .expect(202);
    messageB = { ...messageB, version: b.body.version as number };
    // A with the same key and B's path: still 404, B's stored response is never shown.
    const replayAttempt = await new LifecycleApi(ctx, keyA)
      .rescan(messageB.publicId, { expectedVersion: messageB.version - 1, reason }, idempotencyKey)
      .expect(404);
    expect(replayAttempt.headers['idempotency-replayed']).toBeUndefined();
    expect(JSON.stringify(replayAttempt.body)).not.toContain(b.body.rescanEventId as string);
    // A's own message with the same key works: keys are per organization.
    await new LifecycleApi(ctx, keyA)
      .rescan(messageA.publicId, { expectedVersion: messageA.version, reason }, idempotencyKey)
      .expect(202);
  });
});

describe('platform users', () => {
  it('see nothing of a tenant without an override', async () => {
    for (const roles of [['platform_admin'], ['super_admin']]) {
      const headers = await headersFor(await fx.createPlatformUser(roles));
      // platform_admin holds message:read but no lifecycle write permission.
      const except: Record<string, number> =
        roles[0] === 'platform_admin' ? { 'POST rescan': 403, 'POST release': 403 } : {};
      await expectEveryRoute(headers, 404, except);
    }
  });

  it('super_admin under an override into B releases B’s message, audited with the override', async () => {
    const operator = await fx.createPlatformUser(['super_admin']);
    const session = await loginWithMfa(ctx, fx, operator);
    const overrideReason = 'Customer ticket 3301';
    const started = await ctx.http
      .post('/api/v1/platform/overrides')
      .set(bearer(session.accessToken))
      .set('X-Forwarded-For', uniqueIp())
      .send({ organizationId: orgB.publicId, reason: overrideReason, durationMinutes: 15 })
      .expect(201);
    const api = new LifecycleApi(ctx, bearer(started.body.accessToken as string));
    const current = (await writerState(ctx, messageB)).row;
    const res = await api
      .release(
        messageB.publicId,
        { expectedVersion: current.version, reason },
        `ovr-${randomUUID()}`,
      )
      .expect(409);
    // B's message was rescanned above (scanning): a release is a state conflict, not a 404.
    expect(res.body).toMatchObject({ code: 'message_state_conflict', currentState: 'scanning' });
    const fresh = await insertLifecycleMessage(ctx, orgB, { state: 'held_for_review' });
    const released = await api
      .release(fresh.publicId, { expectedVersion: fresh.version, reason }, `ovr-${randomUUID()}`)
      .expect(202);
    expect(released.body.state).toBe('approved');
    await api
      .rescan(
        messageA.publicId,
        { expectedVersion: messageA.version, reason },
        `ovr-${randomUUID()}`,
      )
      .expect(404);

    const rows = await ctx.prisma.auditLog.findMany({
      where: { action: 'message.quarantine_released', actorId: operator.publicId },
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.organizationId).toBe(orgB.id);
    expect(rows[0]!.resourceId).toBe(fresh.publicId);
    expect(rows[0]!.metadata).toMatchObject({
      override: { id: started.body.overrideId as string, reason: overrideReason },
    });
    const history = (await writerState(ctx, fresh)).history.at(-1)!;
    expect(history).toMatchObject({
      actorRole: 'operator',
      actorType: 'user',
      actorId: operator.publicId,
    });
  });
});
