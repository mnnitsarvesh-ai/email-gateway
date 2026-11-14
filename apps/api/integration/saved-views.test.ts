/**
 * Saved Email Explorer views (step 7.2 §2 E4, §3.3) against the real MySQL writer, Redis and the
 * in-process api: create, list, get, replace and delete as users of two organizations (two users
 * in the first), the rows written (`saved_views`: organization, user, kind, definition,
 * `row_version`), isolation between users and tenants (404 / empty lists), the case-insensitive
 * unique name, the per-user limit, the `rowVersion` conflict, the audit rows (public id and kind
 * only), API keys and a platform override session refused, and the filter permissions of the
 * definition with real roles.
 */
// @covers get /api/v1/saved-views
// @covers post /api/v1/saved-views
// @covers get /api/v1/saved-views/:viewId
// @covers put /api/v1/saved-views/:viewId
// @covers delete /api/v1/saved-views/:viewId
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SAVED_VIEW_EXAMPLES } from '../src/modules/saved-views/saved-views.schemas';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type FixtureUser,
  type Fixtures,
} from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa, uniqueIp } from './support/http';

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let analystA: FixtureUser;
let readerA: FixtureUser;
let analystB: FixtureUser;
const auth: Record<string, Record<string, string>> = {};
const base = '/api/v1/saved-views';
const definition = SAVED_VIEW_EXAMPLES.create.definition;

beforeAll(async () => {
  ctx = await createIntegrationApp({ SAVED_VIEWS_MAX_PER_USER: '3' });
  fx = createFixtures(ctx);
  [orgA, orgB] = [await fx.createOrganization(), await fx.createOrganization()];
  analystA = await fx.createUser(orgA, { roles: ['security_analyst'] });
  readerA = await fx.createUser(orgA, { roles: ['read_only_user'] });
  analystB = await fx.createUser(orgB, { roles: ['security_analyst'] });
  for (const [name, user] of Object.entries({ analystA, readerA, analystB })) {
    auth[name] = bearer((await loginWithMfa(ctx, fx, user)).accessToken);
  }
}, 120_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 120_000);

const as = (who: string) => ({ ...auth[who]!, 'X-Forwarded-For': uniqueIp() });
const create = (who: string, body: object = SAVED_VIEW_EXAMPLES.create) =>
  ctx.http.post(base).set(as(who)).send(body);

describe('saved views on the writer (step 7.2 §2 E4)', () => {
  let viewId: string;

  it('creates a view: 201, the row in saved_views, the audit row with id and kind only', async () => {
    const res = await create('analystA');
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      kind: 'message_explorer',
      name: SAVED_VIEW_EXAMPLES.create.name,
      definition,
      rowVersion: 1,
    });
    viewId = res.body.id;
    const row = await ctx.prisma.savedView.findUniqueOrThrow({ where: { publicId: viewId } });
    expect(row).toMatchObject({
      organizationId: orgA.id,
      userId: analystA.id,
      kind: 'message_explorer',
      rowVersion: 1,
    });
    expect(row.definition).toEqual(definition);
    const audit = await ctx.prisma.auditLog.findFirstOrThrow({
      where: { organizationId: orgA.id, action: 'saved_view.created', resourceId: viewId },
    });
    expect(audit).toMatchObject({ resourceType: 'saved_view', actorType: 'user' });
    expect(audit.metadata).toMatchObject({ kind: 'message_explorer' });
    expect(JSON.stringify(audit.metadata)).not.toMatch(/phishing|example\.com|Inbound/);
  });

  it('reads it back immediately (writer) in the list and by id', async () => {
    const list = await ctx.http.get(`${base}?kind=message_explorer`).set(as('analystA'));
    expect(list.status).toBe(200);
    expect(list.body.data.map((v: { id: string }) => v.id)).toEqual([viewId]);
    const one = await ctx.http.get(`${base}/${viewId}`).set(as('analystA'));
    expect(one.body).toMatchObject({ id: viewId, rowVersion: 1 });
  });

  it('isolates users and tenants: another user of A and a user of B get 404 and empty lists', async () => {
    for (const who of ['readerA', 'analystB']) {
      expect((await ctx.http.get(`${base}/${viewId}`).set(as(who))).status, who).toBe(404);
      const put = await ctx.http
        .put(`${base}/${viewId}`)
        .set(as(who))
        .send(SAVED_VIEW_EXAMPLES.update);
      expect(put.status, who).toBe(404);
      expect(put.body.code).toBe('saved_view_not_found');
      expect((await ctx.http.delete(`${base}/${viewId}`).set(as(who))).status, who).toBe(404);
      const list = await ctx.http.get(`${base}?kind=message_explorer`).set(as(who));
      expect(list.body.data, who).toEqual([]);
    }
    // B's own view with the same name is allowed (per user).
    const b = await create('analystB');
    expect(b.status).toBe(201);
    expect(await ctx.prisma.savedView.count({ where: { publicId: viewId } })).toBe(1);
  });

  it('replaces with expectedRowVersion; a stale version is 409 saved_view_conflict', async () => {
    const ok = await ctx.http
      .put(`${base}/${viewId}`)
      .set(as('analystA'))
      .send(SAVED_VIEW_EXAMPLES.update);
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ name: SAVED_VIEW_EXAMPLES.update.name, rowVersion: 2 });
    const stale = await ctx.http
      .put(`${base}/${viewId}`)
      .set(as('analystA'))
      .send(SAVED_VIEW_EXAMPLES.update);
    expect(stale.status).toBe(409);
    expect(stale.body).toMatchObject({ code: 'saved_view_conflict', currentRowVersion: 2 });
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: orgA.id, action: 'saved_view.updated', resourceId: viewId },
      }),
    ).toBe(1);
  });

  it('enforces the case-insensitive unique name and the per-user limit (409)', async () => {
    const dup = await create('analystA', {
      ...SAVED_VIEW_EXAMPLES.create,
      name: SAVED_VIEW_EXAMPLES.update.name.toUpperCase(),
    });
    expect(dup.status).toBe(409);
    expect(dup.body.code).toBe('saved_view_name_taken');
    expect(
      (await create('analystA', { ...SAVED_VIEW_EXAMPLES.create, name: 'Second' })).status,
    ).toBe(201);
    expect(
      (await create('analystA', { ...SAVED_VIEW_EXAMPLES.create, name: 'Third' })).status,
    ).toBe(201);
    const full = await create('analystA', { ...SAVED_VIEW_EXAMPLES.create, name: 'Fourth' });
    expect(full.status).toBe(409);
    expect(full.body).toMatchObject({ code: 'saved_view_limit_reached', limit: 3 });
    expect(
      await ctx.prisma.savedView.count({ where: { organizationId: orgA.id, userId: analystA.id } }),
    ).toBe(3);
    // Pages newest first with the cursor.
    const first = await ctx.http.get(`${base}?kind=message_explorer&limit=2`).set(as('analystA'));
    const second = await ctx.http
      .get(
        `${base}?kind=message_explorer&limit=2&cursor=${encodeURIComponent(first.body.nextCursor)}`,
      )
      .set(as('analystA'));
    expect([...first.body.data, ...second.body.data].map((v: { name: string }) => v.name)).toEqual([
      'Third',
      'Second',
      SAVED_VIEW_EXAMPLES.update.name,
    ]);
    // A cursor of user A is refused for user B (other organization).
    const foreign = await ctx.http
      .get(`${base}?kind=message_explorer&cursor=${encodeURIComponent(first.body.nextCursor)}`)
      .set(as('analystB'));
    expect(foreign.status).toBe(400);
    expect(foreign.body.code).toBe('cursor_invalid');
  });

  it('applies the filter permissions of the definition with real roles', async () => {
    const subject = {
      ...SAVED_VIEW_EXAMPLES.create,
      name: 'Subjects',
      definition: { ...definition, filters: { subject: 'Invoice overdue' } },
    };
    const denied = await create('readerA', subject);
    expect(denied.status).toBe(403);
    expect(denied.body).toMatchObject({
      code: 'message_filter_forbidden',
      filter: 'subject',
      permission: 'message:reveal',
    });
    // security_analyst holds message:reveal (step 7.2 catalog).
    expect((await create('analystB', subject)).status).toBe(201);
  });

  it('deletes (204, audited); API keys and a platform override session are refused', async () => {
    const del = await ctx.http.delete(`${base}/${viewId}`).set(as('analystA'));
    expect(del.status).toBe(204);
    expect(await ctx.prisma.savedView.count({ where: { publicId: viewId } })).toBe(0);
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: orgA.id, action: 'saved_view.deleted', resourceId: viewId },
      }),
    ).toBe(1);

    const key = apiKeyHeader(await fx.createApiKey(orgA, ['message:read']));
    const byKey = await ctx.http.get(`${base}?kind=message_explorer`).set(key);
    expect(byKey.status).toBe(403);
    expect(byKey.body.code).toBe('user_required');

    const operator = await fx.createPlatformUser(['platform_admin']);
    const session = await loginWithMfa(ctx, fx, operator);
    const started = await ctx.http
      .post('/api/v1/platform/overrides')
      .set(bearer(session.accessToken))
      .set('X-Forwarded-For', uniqueIp())
      .send({ organizationId: orgA.publicId, reason: 'Saved views isolation check' });
    expect(started.status).toBe(201);
    const override = bearer(started.body.accessToken as string);
    const res = await ctx.http
      .get(`${base}?kind=message_explorer`)
      .set({ ...override, 'X-Forwarded-For': uniqueIp() });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('saved_views_member_only');
    await ctx.http
      .delete(`/api/v1/platform/overrides/${started.body.overrideId as string}`)
      .set(bearer(session.accessToken))
      .set('X-Forwarded-For', uniqueIp());
  });
});
