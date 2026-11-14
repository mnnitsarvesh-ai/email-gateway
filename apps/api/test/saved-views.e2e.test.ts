/**
 * `/api/v1/saved-views` (step 7.2 §2 E4, §3.3) over HTTP with MySQL, Redis and S3 stubbed and
 * the saved views repository replaced by an in-memory double (test/support/saved-views-fixtures.ts):
 * every route's success with its documented example shape, strict 400s, 401, 403 for API keys,
 * a missing permission, a platform override session and a gated filter, 404 for another user's
 * and another organization's view, the three 409s, the 429 of the principal limiter and the
 * operations in the OpenAPI document. The real writer runs in integration/saved-views.test.ts.
 */
// @covers get /api/v1/saved-views
// @covers post /api/v1/saved-views
// @covers get /api/v1/saved-views/:viewId
// @covers put /api/v1/saved-views/:viewId
// @covers delete /api/v1/saved-views/:viewId
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { buildOpenApiDocument } from '../src/http/openapi';
import { PlatformOverrideService } from '../src/modules/auth/services/platform-override.service';
import { TokenService } from '../src/modules/auth/services/token.service';
import { SAVED_VIEW_EXAMPLES } from '../src/modules/saved-views/saved-views.schemas';
import { createStubbedApiApp, type StubbedApiApp } from './support/api-test-app';
import { type OpenApiOperation, RecordingAuditService } from './support/messages-fixtures';
import { overrideSavedViews, SavedViewsWorld } from './support/saved-views-fixtures';
import { AuditService } from '../src/audit/audit.service';

const READ = 'message:read';
/** The test user's internal id (TestPrincipals snapshot `user.id`). */
const USER = 10n;
const OTHER_ORG = 2n;
const base = '/api/v1/saved-views';
const definition = SAVED_VIEW_EXAMPLES.create.definition;

describe('/api/v1/saved-views (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  let world: SavedViewsWorld;
  const audit = new RecordingAuditService();
  const overrideId = randomUUID();

  beforeAll(async () => {
    world = new SavedViewsWorld();
    api = await createStubbedApiApp(
      { SAVED_VIEWS_MAX_PER_USER: '3' },
      {
        override: (b) =>
          overrideSavedViews(b, world)
            .overrideProvider(AuditService)
            .useValue(audit)
            .overrideProvider(PlatformOverrideService)
            .useValue({
              resolve: (id: string) =>
                Promise.resolve(
                  id === overrideId
                    ? {
                        id,
                        reason: 'support case',
                        targetOrganizationId: OTHER_ORG,
                        targetOrganizationPublicId: randomUUID(),
                        expiresAt: new Date(Date.now() + 600_000),
                      }
                    : null,
                ),
            }),
      },
    );
  });

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    world.rows = [];
    audit.entries.length = 0;
    api.kv.entries.clear();
  });

  const as = async (permissions: string[] = [READ]) => api.principals.user(permissions).bearer();
  const org = () => api.principals.organizationId;

  it('POST creates a view (201, the documented shape), audited with id and kind only', async () => {
    const res = await api
      .http()
      .post(base)
      .set(await as())
      .send(SAVED_VIEW_EXAMPLES.create);
    expect(res.status).toBe(201);
    expect(Object.keys(res.body).sort()).toEqual(
      ['createdAt', 'definition', 'id', 'kind', 'name', 'rowVersion', 'updatedAt'].sort(),
    );
    expect(res.body).toMatchObject({
      kind: 'message_explorer',
      name: SAVED_VIEW_EXAMPLES.create.name,
      definition,
      rowVersion: 1,
    });
    expect(world.rows[0]).toMatchObject({ organizationId: org(), userId: USER });
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]).toMatchObject({
      action: 'saved_view.created',
      resourceType: 'saved_view',
      resourceId: res.body.id,
      metadata: { kind: 'message_explorer' },
    });
    expect(JSON.stringify(audit.entries[0]!.metadata)).not.toMatch(/phishing|example\.com/);
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('GET lists only my views of the kind, newest first, with a v1 cursor', async () => {
    const mine = [world.add(org(), USER), world.add(org(), USER), world.add(org(), USER)];
    world.add(org(), 11n); // another user of my organization
    world.add(OTHER_ORG, USER); // same user id in another organization
    const first = await api
      .http()
      .get(`${base}?kind=message_explorer&limit=2`)
      .set(await as());
    expect(first.status).toBe(200);
    expect(first.body.data.map((v: { id: string }) => v.id)).toEqual([
      mine[2]!.publicId,
      mine[1]!.publicId,
    ]);
    const second = await api
      .http()
      .get(
        `${base}?kind=message_explorer&limit=2&cursor=${encodeURIComponent(first.body.nextCursor)}`,
      )
      .set(await as());
    expect(second.body).toEqual({
      data: [expect.objectContaining({ id: mine[0]!.publicId })],
      nextCursor: null,
    });
  });

  it('GET/PUT/DELETE one view; PUT bumps rowVersion; DELETE answers 204', async () => {
    const view = world.add(org(), USER, { name: 'Original' });
    const got = await api
      .http()
      .get(`${base}/${view.publicId}`)
      .set(await as());
    expect(got.status).toBe(200);
    expect(got.body).toMatchObject({ id: view.publicId, name: 'Original', rowVersion: 1 });
    const put = await api
      .http()
      .put(`${base}/${view.publicId.toUpperCase()}`)
      .set(await as())
      .send(SAVED_VIEW_EXAMPLES.update);
    expect(put.status).toBe(200);
    expect(put.body).toMatchObject({ name: SAVED_VIEW_EXAMPLES.update.name, rowVersion: 2 });
    const del = await api
      .http()
      .delete(`${base}/${view.publicId}`)
      .set(await as());
    expect(del.status).toBe(204);
    expect(world.rows).toHaveLength(0);
    expect(audit.entries.map((e) => e.action)).toEqual([
      'saved_view.updated',
      'saved_view.deleted',
    ]);
  });

  it('404 saved_view_not_found for another user’s view, another organization’s and unknown ids', async () => {
    const otherUser = world.add(org(), 11n);
    const otherOrg = world.add(OTHER_ORG, USER);
    for (const id of [otherUser.publicId, otherOrg.publicId, randomUUID()]) {
      const headers = await as();
      for (const send of [
        () => api.http().get(`${base}/${id}`).set(headers),
        () => api.http().put(`${base}/${id}`).set(headers).send(SAVED_VIEW_EXAMPLES.update),
        () => api.http().delete(`${base}/${id}`).set(headers),
      ]) {
        const res = await send();
        expect(res.status, id).toBe(404);
        expect(res.body).toMatchObject({
          code: 'saved_view_not_found',
          requestId: expect.any(String),
        });
      }
    }
    expect(world.rows).toHaveLength(2);
  });

  it.each([
    ['GET list without kind', 'get', `${base}`, undefined, 'kind'],
    [
      'GET list with another sort',
      'get',
      `${base}?kind=message_explorer&sort=name`,
      undefined,
      'sort',
    ],
    [
      'GET list unknown parameter',
      'get',
      `${base}?kind=message_explorer&user=1`,
      undefined,
      'Unrecognized',
    ],
    ['GET a non-UUID id', 'get', `${base}/not-a-uuid`, undefined, ''],
    [
      'POST unknown field',
      'post',
      base,
      { ...SAVED_VIEW_EXAMPLES.create, extra: 1 },
      'Unrecognized',
    ],
    [
      'POST another kind',
      'post',
      base,
      { ...SAVED_VIEW_EXAMPLES.create, kind: 'quarantine' },
      'kind',
    ],
    ['POST empty name', 'post', base, { ...SAVED_VIEW_EXAMPLES.create, name: '  ' }, 'name'],
    [
      'POST unknown filter',
      'post',
      base,
      { ...SAVED_VIEW_EXAMPLES.create, definition: { ...definition, filters: { foo: 'x' } } },
      'definition.filters',
    ],
    [
      'POST bad filter value',
      'post',
      base,
      {
        ...SAVED_VIEW_EXAMPLES.create,
        definition: { ...definition, filters: { senderDomain: 'not a domain' } },
      },
      'definition.filters.senderDomain',
    ],
    [
      'POST a non-filter parameter',
      'post',
      base,
      { ...SAVED_VIEW_EXAMPLES.create, definition: { ...definition, filters: { limit: '5' } } },
      'definition.filters.limit',
    ],
    [
      'POST a long absolute range',
      'post',
      base,
      {
        ...SAVED_VIEW_EXAMPLES.create,
        definition: {
          ...definition,
          range: { kind: 'absolute', from: '2026-01-01T00:00:00Z', to: '2026-03-01T00:00:00Z' },
        },
      },
      'definition.range.to',
    ],
    [
      'PUT without expectedRowVersion',
      'put',
      `${base}/${randomUUID()}`,
      { name: 'x', definition },
      'expectedRowVersion',
    ],
  ] as const)('400 validation_failed: %s', async (_label, method, path, body, text) => {
    const req = api
      .http()
      [method](path)
      .set(await as());
    const res = body === undefined ? await req : await req.send(body);
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('validation_failed');
    expect(JSON.stringify(res.body.message)).toContain(text);
    expect(world.rows).toHaveLength(0);
  });

  it('401 without credentials on every route', async () => {
    const id = randomUUID();
    for (const send of [
      () => api.http().get(`${base}?kind=message_explorer`),
      () => api.http().post(base).send(SAVED_VIEW_EXAMPLES.create),
      () => api.http().get(`${base}/${id}`),
      () => api.http().put(`${base}/${id}`).send(SAVED_VIEW_EXAMPLES.update),
      () => api.http().delete(`${base}/${id}`),
    ]) {
      expect((await send()).status).toBe(401);
    }
  });

  it('403: API keys (user_required, even with message:read), a missing message:read (forbidden)', async () => {
    api.principals.apiKeyWith([READ]);
    const id = randomUUID();
    const routes = (headers: Record<string, string>) => [
      () => api.http().get(`${base}?kind=message_explorer`).set(headers),
      () => api.http().post(base).set(headers).send(SAVED_VIEW_EXAMPLES.create),
      () => api.http().get(`${base}/${id}`).set(headers),
      () => api.http().put(`${base}/${id}`).set(headers).send(SAVED_VIEW_EXAMPLES.update),
      () => api.http().delete(`${base}/${id}`).set(headers),
    ];
    for (const send of routes(api.principals.apiKeyHeaders)) {
      const res = await send();
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('user_required');
    }
    for (const send of routes(await as(['delivery:read']))) {
      const res = await send();
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('forbidden');
    }
  });

  it('403 saved_views_member_only for a platform override session (audited override, not a member)', async () => {
    api.principals.user(['platform:tenant_override', READ], {
      orgKind: 'platform',
      mfaAuthenticated: true,
    });
    const tokens = new TokenService(api.config);
    const { token } = await tokens.issue({
      userPublicId: api.principals.ids.user,
      organizationPublicId: api.principals.ids.org,
      sessionId: api.principals.ids.session,
      amr: ['pwd', 'otp'],
      overrideId,
    });
    const headers = { Authorization: `Bearer ${token}` };
    const res = await api.http().get(`${base}?kind=message_explorer`).set(headers);
    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({
      code: 'saved_views_member_only',
      requestId: expect.any(String),
    });
    const created = await api.http().post(base).set(headers).send(SAVED_VIEW_EXAMPLES.create);
    expect(created.status).toBe(403);
    expect(created.body.code).toBe('saved_views_member_only');
    expect(world.rows).toHaveLength(0);
  });

  it('403 message_filter_forbidden when the definition uses a filter the caller may not use', async () => {
    const cases: Array<[Record<string, string>, string, string]> = [
      [{ subject: 'Hello' }, 'subject', 'message:reveal'],
      [{ subjectPrefix: 'Hel' }, 'subjectPrefix', 'message:reveal'],
      [{ deliveryStatus: 'bounced' }, 'deliveryStatus', 'delivery:read'],
      [{ quarantineStatus: 'held' }, 'quarantineStatus', 'quarantine:read'],
    ];
    for (const [filters, filter, permission] of cases) {
      const res = await api
        .http()
        .post(base)
        .set(await as())
        .send({ ...SAVED_VIEW_EXAMPLES.create, definition: { ...definition, filters } });
      expect(res.status, filter).toBe(403);
      expect(res.body).toMatchObject({ code: 'message_filter_forbidden', filter, permission });
    }
    const ok = await api
      .http()
      .post(base)
      .set(await as([READ, 'message:reveal', 'delivery:read', 'quarantine:read']))
      .send({
        ...SAVED_VIEW_EXAMPLES.create,
        definition: {
          ...definition,
          filters: { subject: 'Hello', deliveryStatus: 'bounced', quarantineStatus: 'held' },
        },
      });
    expect(ok.status).toBe(201);
  });

  it('409: name taken (case-insensitive), limit reached, stale rowVersion', async () => {
    world.add(org(), USER, { name: 'Phishing' });
    const dup = await api
      .http()
      .post(base)
      .set(await as())
      .send({ ...SAVED_VIEW_EXAMPLES.create, name: 'PHISHING' });
    expect(dup.status).toBe(409);
    expect(dup.body.code).toBe('saved_view_name_taken');
    world.add(org(), USER);
    world.add(org(), USER);
    const full = await api
      .http()
      .post(base)
      .set(await as())
      .send(SAVED_VIEW_EXAMPLES.create);
    expect(full.status).toBe(409);
    expect(full.body).toMatchObject({ code: 'saved_view_limit_reached', limit: 3 });
    const view = world.rows[1]!;
    const stale = await api
      .http()
      .put(`${base}/${view.publicId}`)
      .set(await as())
      .send({ ...SAVED_VIEW_EXAMPLES.update, expectedRowVersion: 5 });
    expect(stale.status).toBe(409);
    expect(stale.body).toMatchObject({ code: 'saved_view_conflict', currentRowVersion: 1 });
    const rename = await api
      .http()
      .put(`${base}/${view.publicId}`)
      .set(await as())
      .send({ ...SAVED_VIEW_EXAMPLES.update, name: 'phishing' });
    expect(rename.status).toBe(409);
    expect(rename.body.code).toBe('saved_view_name_taken');
  });

  it('is documented: tag, permissions, cursor, examples and coded errors', () => {
    const doc = buildOpenApiDocument(api.app);
    const op = (path: string, method: string) =>
      (doc.paths[path] as Record<string, unknown>)[method] as OpenApiOperation;
    const list = op('/api/v1/saved-views', 'get');
    expect(list.tags).toEqual(['saved-views']);
    expect(list['x-eg-permissions']).toEqual({ mode: 'all', permissions: [READ] });
    expect(list['x-eg-cursor']).toBe('v1');
    expect(list.description).toContain('writer');
    expect(list.parameters.find((p) => p.name === 'kind')?.required).toBe(true);
    const create = op('/api/v1/saved-views', 'post');
    expect(create.responses['201']!.content['application/json']!.schema.example).toMatchObject({
      kind: 'message_explorer',
    });
    for (const status of ['400', '401', '403', '409', '429', '503']) {
      expect(create.responses[status], status).toBeDefined();
    }
    const one = op('/api/v1/saved-views/{viewId}', 'delete');
    expect(one.responses['204']).toBeDefined();
    expect(one.responses['404']).toBeDefined();
    expect(JSON.stringify(op('/api/v1/saved-views/{viewId}', 'put').responses['409'])).toContain(
      'saved_view_conflict',
    );
  });
});

describe('/api/v1/saved-views 429 (principal limit)', () => {
  let api: StubbedApiApp;
  beforeAll(async () => {
    api = await createStubbedApiApp(
      { API_RATE_PRINCIPAL_PER_MINUTE: '10' },
      { override: (b) => overrideSavedViews(b, new SavedViewsWorld()) },
    );
  });
  afterAll(async () => {
    await api?.close();
  });

  it('answers 429 rate_limited with RateLimit headers and Retry-After', async () => {
    const bearer = await api.principals.user([READ]).bearer();
    for (let i = 0; i < 10; i += 1) {
      const ok = await api.http().get(`${base}?kind=message_explorer`).set(bearer);
      expect(ok.status).toBe(200);
    }
    const res = await api.http().get(`${base}?kind=message_explorer`).set(bearer);
    expect(res.status).toBe(429);
    expect(res.body).toMatchObject({ code: 'rate_limited', scope: 'principal' });
    expect(res.headers['ratelimit-limit']).toBe('10');
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
  });
});
