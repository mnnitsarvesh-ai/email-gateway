/**
 * The recipient suppression list (step 6.1 WP2, §3.3) over HTTP with MySQL, Redis and S3
 * stubbed, the suppression repository replaced by an in-memory double and the Idempotency-Key
 * store by `InMemoryIdempotencyStore` (transactional `IdempotencyService.execute` with an
 * immediate runner): list/get shapes and filters, strict bodies and ids, RBAC (read vs manage,
 * users and API keys), the Idempotency-Key contract of both mutations (required, replay with
 * `Idempotency-Replayed`, reuse 422), the conflicts, the audit entries, the `sensitive` class 429
 * and the OpenAPI operations. The real writer, audit rows and stored keys run in
 * integration/recipient-suppressions.test.ts.
 */
// @covers get /api/v1/recipients/suppressions
// @covers get /api/v1/recipients/suppressions/:suppressionId
// @covers post /api/v1/recipients/suppressions
// @covers delete /api/v1/recipients/suppressions/:suppressionId
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { buildOpenApiDocument } from '../src/http/openapi';
import {
  createStubbedApiApp,
  InMemoryIdempotencyStore,
  type StubbedApiApp,
} from './support/api-test-app';
import {
  type OpenApiOperation,
  MessagesWorld,
  overrideMessagesData,
  RecordingAuditService,
} from './support/messages-fixtures';

const READ = 'delivery:read';
const MANAGE = 'delivery:suppression_manage';
const OTHER_ORG = 2n;

describe('recipient suppressions (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const world = new MessagesWorld();
  const audit = new RecordingAuditService();
  const store = new InMemoryIdempotencyStore();

  beforeAll(async () => {
    api = await createStubbedApiApp(
      { RECIPIENT_SUPPRESSIONS_MAX_MANUAL: '3' },
      { override: (b) => store.override(overrideMessagesData(b, world, audit)) },
    );
  });

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    world.suppressions = [];
    audit.entries.length = 0;
    store.rows.clear();
    api.kv.entries.clear();
    const org = api.principals.organizationId;
    const at = new Date();
    world.suppressions.push(
      {
        id: 10n,
        organizationId: org,
        address: 'bounced@example.org',
        reason: 'hard_bounce',
        source: 'bounce',
        expiresAt: null,
        createdAt: at,
        createdBy: null,
      },
      {
        id: 11n,
        organizationId: org,
        address: 'old@example.org',
        reason: 'manual',
        source: 'api',
        expiresAt: new Date(at.getTime() - 1000),
        createdAt: at,
        createdBy: null,
      },
      {
        id: 12n,
        organizationId: OTHER_ORG,
        address: 'bounced@example.org',
        reason: 'hard_bounce',
        source: 'bounce',
        expiresAt: null,
        createdAt: at,
        createdBy: null,
      },
    );
  });

  const as = async (permissions: string[]) => api.principals.user(permissions).bearer();
  const create = async (body: unknown, key: string | null = 'key-1', perms = [MANAGE]) => {
    const req = api
      .http()
      .post('/api/v1/recipients/suppressions')
      .set(await as(perms));
    if (key !== null) req.set('Idempotency-Key', key);
    return req.send(body as object);
  };
  const remove = async (id: string, key: string | null = 'del-1', perms = [MANAGE]) => {
    const req = api
      .http()
      .delete(`/api/v1/recipients/suppressions/${id}`)
      .set(await as(perms));
    if (key !== null) req.set('Idempotency-Key', key);
    return req;
  };

  it('lists own suppressions newest first with active computed; filters', async () => {
    const res = await api
      .http()
      .get('/api/v1/recipients/suppressions')
      .set(await as([READ]));
    expect(res.status).toBe(200);
    expect(res.body.data.map((d: { id: string }) => d.id)).toEqual(['11', '10']);
    expect(res.body.data[0]).toMatchObject({
      reason: 'manual',
      active: false,
      source: 'api',
      createdBy: null,
    });
    expect(res.body.data[1]).toMatchObject({ address: 'bounced@example.org', active: true });
    const bearer = await as([READ]);
    const q = (query: string) =>
      api.http().get(`/api/v1/recipients/suppressions${query}`).set(bearer);
    expect((await q('?active=true')).body.data.map((d: { id: string }) => d.id)).toEqual(['10']);
    expect(
      (await q('?reason=manual,unsubscribe')).body.data.map((d: { id: string }) => d.id),
    ).toEqual(['11']);
    expect(
      (await q('?address=Bounced@Example.org')).body.data.map((d: { id: string }) => d.id),
    ).toEqual(['10']);
    const paged = await q('?limit=1');
    const next = await q(`?limit=1&cursor=${encodeURIComponent(paged.body.nextCursor)}`);
    expect(next.body).toEqual({ data: [expect.objectContaining({ id: '10' })], nextCursor: null });
    for (const query of ['?reason=spam', '?active=yes', '?address=nope', '?foo=1', '?sort=id']) {
      expect((await q(query)).status, query).toBe(400);
    }
    expect((await q('?cursor=bad')).body.code).toBe('cursor_invalid');
  });

  it('gets one by decimal id; another organization or unknown id is 404, a bad id 400', async () => {
    const bearer = await as([READ]);
    const ok = await api.http().get('/api/v1/recipients/suppressions/10').set(bearer);
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ id: '10', reason: 'hard_bounce', active: true });
    for (const id of ['12', '999']) {
      const res = await api.http().get(`/api/v1/recipients/suppressions/${id}`).set(bearer);
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('suppression_not_found');
    }
    for (const id of ['abc', '0', '-1', '1.5']) {
      expect(
        (await api.http().get(`/api/v1/recipients/suppressions/${id}`).set(bearer)).status,
      ).toBe(400);
    }
  });

  it('creates (201), replays with Idempotency-Replayed, refuses key reuse (422), audits', async () => {
    const res = await create({ address: ' New.Person@Example.COM ', reason: 'unsubscribe' });
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      address: 'new.person@example.com',
      reason: 'unsubscribe',
      source: 'api',
      active: true,
      expiresAt: null,
    });
    expect(res.headers['idempotency-replayed']).toBeUndefined();
    const replay = await create({ address: ' New.Person@Example.COM ', reason: 'unsubscribe' });
    expect(replay.status).toBe(201);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual(res.body);
    expect(world.suppressions.filter((s) => s.address === 'new.person@example.com')).toHaveLength(
      1,
    );
    const reused = await create({ address: 'someone.else@example.com' });
    expect(reused.status).toBe(422);
    expect(reused.body.code).toBe('idempotency_key_reused');
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]).toMatchObject({
      action: 'recipient_suppression.created',
      resourceType: 'recipient_suppression',
      resourceId: res.body.id,
      metadata: {
        reason: 'unsubscribe',
        source: 'api',
        addressSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      },
    });
    expect(JSON.stringify(audit.entries[0]!.metadata)).not.toContain('new.person');
    const stored = [...store.rows.values()][0]!;
    expect(stored).toMatchObject({
      operation: 'recipient_suppression.create',
      statusCode: 201,
      organizationId: api.principals.organizationId,
    });
  });

  it('create: missing or invalid key, strict body, conflicts and the manual limit', async () => {
    const missing = await create({ address: 'a@b.example' }, null);
    expect(missing.status).toBe(400);
    expect(missing.body.code).toBe('idempotency_key_required');
    expect((await create({ address: 'a@b.example' }, 'bad key!')).body.code).toBe(
      'idempotency_key_invalid',
    );
    const future = new Date(Date.now() + 3651 * 86_400_000).toISOString();
    for (const body of [
      {},
      { address: 'a@b.example', extra: 1 },
      { address: 'not-an-address' },
      { address: 'a@b.example', reason: 'hard_bounce' },
      { address: 'a@b.example', expiresAt: '2020-01-01T00:00:00Z' },
      { address: 'a@b.example', expiresAt: future },
    ]) {
      const res = await create(body, `k-${JSON.stringify(body).length}-${Math.random()}`);
      expect(res.status, JSON.stringify(body)).toBe(400);
      expect(res.body.code).toBe('validation_failed');
    }
    const exists = await create({ address: 'Bounced@example.org' }, 'k-exists');
    expect(exists.status).toBe(409);
    expect(exists.body).toMatchObject({ code: 'suppression_exists', id: '10' });
    // Limit 3 manual/unsubscribe rows: one exists (11), two more fit, the next is refused.
    expect((await create({ address: 'one@x.example' }, 'k-a')).status).toBe(201);
    expect((await create({ address: 'two@x.example' }, 'k-b')).status).toBe(201);
    const limited = await create({ address: 'three@x.example' }, 'k-c');
    expect(limited.status).toBe(409);
    expect(limited.body).toMatchObject({ code: 'suppression_limit_reached', limit: 3 });
    // Errors are never stored under their keys.
    expect([...store.rows.values()].map((r) => r.idempotencyKey).sort()).toEqual(['k-a', 'k-b']);
  });

  it('deletes (204), replays 204 with Idempotency-Replayed, 404 for foreign or removed rows', async () => {
    const res = await remove('10');
    expect(res.status).toBe(204);
    expect(res.text).toBe('');
    expect(world.suppressions.find((s) => s.id === 10n)).toBeUndefined();
    const replay = await remove('10');
    expect(replay.status).toBe(204);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect((await remove('11')).status).toBe(422);
    const again = await remove('10', 'del-2');
    expect(again.status).toBe(404);
    expect(again.body.code).toBe('suppression_not_found');
    const foreign = await remove('12', 'del-3');
    expect(foreign.status).toBe(404);
    expect(world.suppressions.find((s) => s.id === 12n)).toBeDefined();
    expect((await remove('10', null)).body.code).toBe('idempotency_key_required');
    expect((await remove('abc', 'del-4')).status).toBe(400);
    expect(audit.entries).toEqual([
      expect.objectContaining({
        action: 'recipient_suppression.deleted',
        resourceId: '10',
        metadata: expect.objectContaining({ formerReason: 'hard_bounce', formerSource: 'bounce' }),
      }),
    ]);
  });

  it('RBAC: reads need delivery:read, mutations delivery:suppression_manage (users and API keys)', async () => {
    expect((await api.http().get('/api/v1/recipients/suppressions')).status).toBe(401);
    expect(
      (
        await api
          .http()
          .get('/api/v1/recipients/suppressions')
          .set(await as([MANAGE]))
      ).status,
    ).toBe(403);
    expect(
      (
        await api
          .http()
          .get('/api/v1/recipients/suppressions/10')
          .set(await as(['message:read']))
      ).status,
    ).toBe(403);
    expect((await create({ address: 'a@b.example' }, 'k-r', [READ])).status).toBe(403);
    expect((await remove('10', 'k-r2', [READ])).status).toBe(403);
    api.principals.apiKeyWith([READ]);
    expect(
      (await api.http().get('/api/v1/recipients/suppressions').set(api.principals.apiKeyHeaders))
        .status,
    ).toBe(200);
    expect(
      (
        await api
          .http()
          .post('/api/v1/recipients/suppressions')
          .set(api.principals.apiKeyHeaders)
          .set('Idempotency-Key', 'k-api')
          .send({ address: 'a@b.example' })
      ).status,
    ).toBe(403);
    api.principals.apiKeyWith([MANAGE]);
    const created = await api
      .http()
      .post('/api/v1/recipients/suppressions')
      .set(api.principals.apiKeyHeaders)
      .set('Idempotency-Key', 'k-api')
      .send({ address: 'api@b.example' });
    expect(created.status).toBe(201);
    expect(created.body.createdBy).toBeNull();
  });

  it('documents the four operations (tag, permissions, idempotency, rate class, examples)', () => {
    const doc = buildOpenApiDocument(api.app);
    const list = doc.paths['/api/v1/recipients/suppressions']!;
    const one = doc.paths['/api/v1/recipients/suppressions/{suppressionId}']!;
    const ops = [list.get, list.post, one.get, one.delete] as unknown as OpenApiOperation[];
    for (const op of ops) {
      expect(op.tags).toEqual(['recipients']);
      expect(op.summary).toEqual(expect.any(String));
    }
    expect(list.get!['x-eg-cursor' as never]).toBe('v1');
    for (const op of [list.post, one.delete] as unknown as OpenApiOperation[]) {
      expect(op['x-eg-permissions']).toEqual({ mode: 'all', permissions: [MANAGE] });
      expect(op['x-eg-idempotency']).toBe('required');
      expect(op['x-eg-rate-class']).toBe('sensitive');
      expect(
        op.parameters.find((p: { name: string }) => p.name === 'Idempotency-Key')!.required,
      ).toBe(true);
      for (const status of ['400', '401', '403', '409', '422', '429'])
        expect(op.responses[status]).toBeDefined();
    }
    const post = list.post as unknown as OpenApiOperation;
    expect(post.responses['201']!.content['application/json']!.schema.example).toMatchObject({
      source: 'api',
    });
    expect(post.responses['201']!.headers['Idempotency-Replayed']).toBeDefined();
    expect((one.delete as unknown as OpenApiOperation).responses['204']).toBeDefined();
    expect((one.get as unknown as OpenApiOperation).responses['404']).toBeDefined();
  });
});

describe('recipient suppressions 429 (sensitive class)', () => {
  let api: StubbedApiApp;
  const store = new InMemoryIdempotencyStore();
  beforeAll(async () => {
    api = await createStubbedApiApp(
      { API_RATE_SENSITIVE_PER_MINUTE: '2' },
      {
        override: (b) =>
          store.override(overrideMessagesData(b, new MessagesWorld(), new RecordingAuditService())),
      },
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
        .post('/api/v1/recipients/suppressions')
        .set(bearer)
        .set('Idempotency-Key', `k-${i}`)
        .send({ address: `p${i}@x.example` });
      expect(ok.status).toBe(201);
    }
    const res = await api
      .http()
      .delete('/api/v1/recipients/suppressions/1')
      .set(bearer)
      .set('Idempotency-Key', 'k-9');
    expect(res.status).toBe(429);
    expect(res.body).toMatchObject({ code: 'rate_limited', scope: 'sensitive' });
    expect(res.headers['ratelimit-remaining']).toBe('0');
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
    expect((await api.http().get('/api/v1/recipients/suppressions').set(bearer)).status).toBe(200);
  });
});
