/**
 * The archive routes of step 8.1 (docs/plan/steps/23-journaling-archiving.md §4.4 #1–#23, §9.3)
 * over HTTP with MySQL, Redis, S3 and OpenSearch stubbed: the archive repositories, the archive
 * bucket and the tenant search alias replaced by the in-memory `ArchiveWorld` (records seeded
 * with the real `@email-gateway/archive` crypto, so journal, security, preview, reveal and
 * downloads really decrypt), the Idempotency-Key store by `InMemoryIdempotencyStore`. For every
 * operation: success with the OpenAPI example, strict bodies, 401, 403 for each system role (A20
 * matrix) and for API keys on MFA routes, 404 for another organization's ids, Idempotency-Key
 * replay and reuse, route and class limits (429 with `RateLimit-*` and `Retry-After`), tampered
 * and foreign cursors. The real writer, replica, MinIO and OpenSearch run in
 * integration/archive*.test.ts.
 */
// @covers get /api/v1/archive/settings
// @covers put /api/v1/archive/settings
// @covers get /api/v1/archive/retention-policies
// @covers post /api/v1/archive/retention-policies
// @covers get /api/v1/archive/retention-policies/:policyId
// @covers put /api/v1/archive/retention-policies/:policyId
// @covers delete /api/v1/archive/retention-policies/:policyId
// @covers get /api/v1/archive/keys
// @covers post /api/v1/archive/keys/rotate
// @covers get /api/v1/archive/status
// @covers get /api/v1/archive/capture-issues
// @covers post /api/v1/archive/capture-issues/:messageId/retry
// @covers get /api/v1/archive/disposals
// @covers get /api/v1/archive/export-signing-keys
// @covers get /api/v1/archive/messages
// @covers get /api/v1/archive/messages/:messageId
// @covers get /api/v1/archive/messages/:messageId/journal
// @covers get /api/v1/archive/messages/:messageId/security
// @covers post /api/v1/archive/messages/:messageId/reveal
// @covers get /api/v1/archive/messages/:messageId/preview
// @covers post /api/v1/archive/messages/:messageId/download-grants
// @covers get /api/v1/archive/downloads/:token
// @covers post /api/v1/archive/messages/:messageId/dispose
import { createHash, randomUUID } from 'node:crypto';
import { SYSTEM_ROLES } from '@email-gateway/database';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { CursorCodec } from '../src/http/cursor/cursor-codec';
import { ARCHIVE_EXAMPLE_IDS, ARCHIVE_EXAMPLES } from '../src/modules/archive/dto/archive.schemas';
import {
  createStubbedApiApp,
  InMemoryIdempotencyStore,
  type StubbedApiApp,
} from './support/api-test-app';
import {
  ArchiveWorld,
  overrideArchive,
  RecordingAuditService,
  TEST_REAUTH_PASSWORD,
} from './support/archive-fixtures';

const READ = 'archive:read';
const SEARCH = 'archive:search';
const RETRIEVE = 'archive:retrieve';
const EXPORT = 'archive:export';
const MANAGE = 'archive:manage';
const HOLD = 'archive:legal_hold';
const EDISC = 'ediscovery:manage';
const REVEAL = 'message:reveal';
// Step 8.6 (ADR-0089): the Journaling area.
const JREAD = 'journal:read';
const JMANAGE = 'journal:manage';
const ALL = [
  READ,
  SEARCH,
  RETRIEVE,
  EXPORT,
  MANAGE,
  HOLD,
  EDISC,
  REVEAL,
  'dlp:read',
  JREAD,
  JMANAGE,
];
const OTHER_ORG = 2n;
const BASE = '/api/v1/archive';
const DAY = 86_400_000;
const RANGE = (() => {
  const to = new Date(Date.now() + DAY).toISOString();
  const from = new Date(Date.now() - 30 * DAY).toISOString();
  return `from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;
})();

type Method = 'get' | 'post' | 'put' | 'patch' | 'delete';

/** What every test seeds into the world (own organization unless noted). */
interface Ctx {
  record: string;
  review: string;
  policy: string;
  spare: string;
  failed: string;
  foreignRecord: string;
  foreignPolicy: string;
}

interface Spec {
  id: string;
  method: Method;
  path: (c: Ctx, api: StubbedApiApp) => string | Promise<string>;
  all?: string[];
  any?: string[];
  mfa?: boolean;
  body?: () => object;
  keyed?: boolean;
  ok: number;
}

describe('archive routes (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const world = new ArchiveWorld();
  const audit = new RecordingAuditService();
  const store = new InMemoryIdempotencyStore();
  let org: bigint;

  beforeAll(async () => {
    api = await createStubbedApiApp(
      {
        ARCHIVE_PREVIEW_PER_MINUTE: '600',
        ARCHIVE_REVEAL_PER_MINUTE: '600',
        ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR: '1000',
        ARCHIVE_RETENTION_POLICIES_MAX_PER_ORG: '5',
      },
      { override: (b) => store.override(overrideArchive(b, world, audit)) },
    );
    org = api.principals.organizationId;
    world.rootKey = api.config;
  });

  afterAll(async () => {
    await api?.close();
  });

  let ctx: Ctx;
  beforeEach(async () => {
    world.reset();
    audit.entries.length = 0;
    store.rows.clear();
    api.kv.entries.clear();
    api.principals.apiKeyWith([]);
    ctx = await seed();
  });

  /** The standard world: settings (example ids), two policies, records, a failed intent. */
  async function seed(): Promise<Ctx> {
    const policy = world.addPolicy(org, {
      publicId: ARCHIVE_EXAMPLE_IDS.policy,
      name: 'Default seven years',
      retentionDays: 2555,
      onExpiry: 'review',
    });
    const spare = world.addPolicy(org, { name: 'Spare', retentionDays: 30 });
    world.domains.push({
      organizationId: org,
      publicId: ARCHIVE_EXAMPLE_IDS.domain,
      name: 'corp.example',
      verified: true,
    });
    world.setSettings(org, {
      enabled: true,
      defaultRetentionPolicyId: policy.id,
      rowVersion: 2,
      settings: { access: { previewEnabled: true, downloadEnabled: true } },
    });
    const record = await world.addRecord(org, {
      subject: 'Quarterly report',
      recipients: ['alice.recipient@corp.example', 'bob@corp.example'],
      attachments: [
        { partIndex: 2, fileName: 'report.pdf', sha256: 'b'.repeat(64), sizeBytes: 1024 },
      ],
      retentionPolicyId: policy.id,
    });
    const review = await world.addRecord(org, {
      status: 'expiry_review',
      retainUntil: new Date(Date.now() - DAY),
      receivedAt: new Date(Date.now() - 400 * DAY),
    });
    world.intents.push({
      id: world.id(),
      organizationId: org,
      receivedAt: record.record.receivedAt,
      messageId: record.record.messageId,
      messagePublicId: record.record.messagePublicId,
      status: 'failed',
      skipReason: null,
      lastErrorCode: 'storage_error',
      attempts: 3,
      sourceJournal: true,
      sourcePolicy: false,
      nextCheckAt: new Date(),
      createdAt: new Date(Date.now() - DAY),
    });
    world.disposals.push({
      id: world.id(),
      organizationId: org,
      requestedAt: new Date(Date.now() - DAY),
      messagePublicId: randomUUID(),
      messageReceivedAt: new Date(Date.now() - 900 * DAY),
      reason: 'retention_expired',
      state: 'completed',
      sha256: 'a'.repeat(64),
      sizeBytes: 100,
      attempts: 1,
      completedAt: new Date(),
    });
    const foreign = await world.addRecord(OTHER_ORG, { subject: 'Other tenant' });
    const foreignPolicy = world.addPolicy(OTHER_ORG, { name: 'Other' });
    return {
      record: record.record.messagePublicId,
      review: review.record.messagePublicId,
      policy: policy.publicId,
      spare: spare.publicId,
      failed: record.record.messagePublicId,
      foreignRecord: foreign.record.messagePublicId,
      foreignPolicy: foreignPolicy.publicId,
    };
  }

  const asUser = (permissions: string[], mfa = true) =>
    api.principals.user(permissions, { mfaAuthenticated: mfa }).bearer();

  /** A fresh single-use token for the record (as a fully privileged MFA user). */
  async function grantToken(messageId: string): Promise<string> {
    const res = await api
      .http()
      .post(`${BASE}/messages/${messageId}/download-grants`)
      .set(await asUser(ALL))
      .send({ password: TEST_REAUTH_PASSWORD });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    return res.body.token as string;
  }

  const SPECS: Spec[] = [
    { id: '#1', method: 'get', path: () => `${BASE}/settings`, any: [READ, JREAD], ok: 200 },
    {
      // Step 8.6 D11: any of journal:manage / archive:manage at the route, then per changed
      // path; the example changes paths of both areas, so it needs both.
      id: '#2',
      method: 'put',
      path: () => `${BASE}/settings`,
      all: [JMANAGE, MANAGE],
      mfa: true,
      keyed: true,
      body: () => ARCHIVE_EXAMPLES.settingsUpdate,
      ok: 200,
    },
    { id: '#3', method: 'get', path: () => `${BASE}/retention-policies`, all: [READ], ok: 200 },
    {
      id: '#4',
      method: 'post',
      path: () => `${BASE}/retention-policies`,
      all: [MANAGE],
      keyed: true,
      body: () => ARCHIVE_EXAMPLES.policyCreate,
      ok: 201,
    },
    {
      id: '#5',
      method: 'get',
      path: (c) => `${BASE}/retention-policies/${c.policy}`,
      all: [READ],
      ok: 200,
    },
    {
      id: '#6',
      method: 'put',
      path: (c) => `${BASE}/retention-policies/${c.policy}`,
      all: [MANAGE],
      keyed: true,
      body: () => ARCHIVE_EXAMPLES.policyUpdate,
      ok: 200,
    },
    {
      id: '#7',
      method: 'delete',
      path: (c) => `${BASE}/retention-policies/${c.spare}`,
      all: [MANAGE],
      keyed: true,
      ok: 204,
    },
    { id: '#8', method: 'get', path: () => `${BASE}/keys`, all: [READ], ok: 200 },
    {
      id: '#9',
      method: 'post',
      path: () => `${BASE}/keys/rotate`,
      all: [MANAGE],
      mfa: true,
      keyed: true,
      body: () => ARCHIVE_EXAMPLES.rotate,
      ok: 201,
    },
    { id: '#10', method: 'get', path: () => `${BASE}/status`, any: [READ, JREAD], ok: 200 },
    {
      id: '#11',
      method: 'get',
      path: () => `${BASE}/capture-issues`,
      any: [JMANAGE, MANAGE],
      ok: 200,
    },
    {
      id: '#12',
      method: 'post',
      path: (c) => `${BASE}/capture-issues/${c.failed}/retry`,
      any: [JMANAGE, MANAGE],
      keyed: true,
      ok: 200,
    },
    { id: '#13', method: 'get', path: () => `${BASE}/disposals`, all: [READ], ok: 200 },
    { id: '#14', method: 'get', path: () => `${BASE}/export-signing-keys`, all: [READ], ok: 200 },
    { id: '#15', method: 'get', path: () => `${BASE}/messages?${RANGE}`, all: [SEARCH], ok: 200 },
    // Step 8.6 D12 (ADR-0089): record routes need archive:search (was archive:read).
    {
      id: '#16',
      method: 'get',
      path: (c) => `${BASE}/messages/${c.record}`,
      all: [SEARCH],
      ok: 200,
    },
    {
      id: '#17',
      method: 'get',
      path: (c) => `${BASE}/messages/${c.record}/journal`,
      all: [SEARCH],
      ok: 200,
    },
    {
      id: '#18',
      method: 'get',
      path: (c) => `${BASE}/messages/${c.record}/security`,
      all: [SEARCH],
      ok: 200,
    },
    {
      id: '#19',
      method: 'post',
      path: (c) => `${BASE}/messages/${c.record}/reveal`,
      all: [SEARCH, REVEAL],
      body: () => ARCHIVE_EXAMPLES.reveal,
      ok: 200,
    },
    {
      id: '#20',
      method: 'get',
      path: (c) => `${BASE}/messages/${c.record}/preview`,
      all: [RETRIEVE],
      mfa: true,
      ok: 200,
    },
    {
      id: '#21',
      method: 'post',
      path: (c) => `${BASE}/messages/${c.record}/download-grants`,
      all: [RETRIEVE],
      mfa: true,
      body: () => ({ password: TEST_REAUTH_PASSWORD }),
      ok: 201,
    },
    {
      id: '#22',
      method: 'get',
      path: async (c) => `${BASE}/downloads/${await grantToken(c.record)}`,
      any: [RETRIEVE, EXPORT],
      ok: 200,
    },
    {
      id: '#23',
      method: 'post',
      path: (c) => `${BASE}/messages/${c.review}/dispose`,
      all: [MANAGE],
      mfa: true,
      keyed: true,
      body: () => ARCHIVE_EXAMPLES.dispose,
      ok: 202,
    },
  ];

  /** One request of a spec with the given principal (`perms` null = no credentials). */
  async function send(
    spec: Spec,
    options: {
      perms?: string[] | null;
      mfa?: boolean;
      apiKey?: string[];
      key?: string;
      body?: object;
      path?: string;
    } = {},
  ) {
    const path = options.path ?? (await spec.path(ctx, api));
    const req = api.http()[spec.method](path);
    if (options.apiKey) {
      api.principals.apiKeyWith(options.apiKey);
      req.set(api.principals.apiKeyHeaders);
    } else if (options.perms !== null) {
      req.set(await asUser(options.perms ?? ALL, options.mfa ?? true));
    }
    if (spec.keyed) req.set('Idempotency-Key', options.key ?? randomUUID());
    const body = options.body ?? spec.body?.();
    return body === undefined ? req : req.send(body);
  }

  const allowed = (spec: Spec, held: ReadonlySet<string>) =>
    spec.all ? spec.all.every((p) => held.has(p)) : (spec.any ?? []).some((p) => held.has(p));

  describe('every operation (success with the OpenAPI example, auth, RBAC)', () => {
    it.each(SPECS.map((s) => [s.id, s] as const))(
      '%s succeeds for a fully privileged MFA user',
      async (_id, spec) => {
        const res = await send(spec);
        expect(res.status, JSON.stringify(res.body)).toBe(spec.ok);
        expect(res.headers['cache-control']).toBe('no-store');
        expect(res.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
      },
    );

    it.each(SPECS.map((s) => [s.id, s] as const))(
      '%s answers 401 without credentials',
      async (_id, spec) => {
        const res = await send(spec, { perms: null, path: await spec.path(ctx, api) });
        expect(res.status).toBe(401);
      },
    );

    it.each(SPECS.map((s) => [s.id, s] as const))(
      '%s answers 403 without its permission',
      async (_id, spec) => {
        const held = ALL.filter((p) => !(spec.all ?? spec.any ?? []).includes(p));
        const res = await send(spec, { perms: held });
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('forbidden');
      },
    );

    it('MFA routes refuse a session without MFA (403 mfa_required) and API keys (403 user_required)', async () => {
      for (const spec of SPECS.filter((s) => s.mfa)) {
        const noMfa = await send(spec, { mfa: false });
        expect(noMfa.status, spec.id).toBe(403);
        expect(noMfa.body.code, spec.id).toBe('mfa_required');
        const key = await send(spec, { apiKey: ALL });
        expect(key.status, spec.id).toBe(403);
        expect(key.body.code, spec.id).toBe('user_required');
      }
      // The download route is user-only too.
      const download = SPECS.find((s) => s.id === '#22')!;
      const key = await send(download, { apiKey: ALL });
      expect(key.status).toBe(403);
      expect(key.body.code).toBe('user_required');
    });

    it('API keys may use the read, search, retention, status and capture routes (scopes)', async () => {
      for (const spec of SPECS.filter((s) => !s.mfa && s.id !== '#22')) {
        world.reset();
        store.rows.clear();
        ctx = await seed();
        const res = await send(spec, { apiKey: ALL });
        expect(res.status, `${spec.id} ${JSON.stringify(res.body)}`).toBe(spec.ok);
      }
    });

    it.each(SYSTEM_ROLES.map((r) => [r.key, [...r.permissions] as string[]] as const))(
      'the A20 matrix holds for role %s',
      async (_role, permissions) => {
        const held = new Set(permissions);
        for (const spec of SPECS) {
          world.reset();
          store.rows.clear();
          ctx = await seed();
          const path = await spec.path(ctx, api);
          const res = await send(spec, { perms: permissions, path });
          if (allowed(spec, held)) {
            expect(res.status, `${spec.id} ${JSON.stringify(res.body)}`).not.toBe(403);
          } else {
            expect(res.status, spec.id).toBe(403);
          }
        }
      },
    );
  });

  describe('strict bodies and ids', () => {
    it.each(SPECS.filter((s) => s.body).map((s) => [s.id, s] as const))(
      '%s refuses an unknown body field (400)',
      async (_id, spec) => {
        const res = await send(spec, { body: { ...spec.body!(), extra: true } });
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('validation_failed');
      },
    );

    it('path ids must be UUIDs (400) and lists refuse unknown parameters (400)', async () => {
      const auth = await asUser(ALL);
      for (const path of [`${BASE}/messages/nope`, `${BASE}/retention-policies/nope`]) {
        const res = await api.http().get(path).set(auth);
        expect(res.status, path).toBe(400);
      }
      for (const path of [`${BASE}/keys?bogus=1`, `${BASE}/messages?${RANGE}&bogus=1`]) {
        const res = await api.http().get(path).set(auth);
        expect(res.status, path).toBe(400);
        expect(res.body.code).toBe('validation_failed');
      }
    });
  });

  describe('tenant isolation (another organization’s ids answer 404)', () => {
    it('messages, policies, capture issues and disposal of another organization are 404', async () => {
      const auth = await asUser(ALL);
      const checks: Array<[Method, string, object | undefined, string]> = [
        ['get', `${BASE}/messages/${ctx.foreignRecord}`, undefined, 'archive_message_not_found'],
        [
          'get',
          `${BASE}/messages/${ctx.foreignRecord}/journal`,
          undefined,
          'archive_message_not_found',
        ],
        [
          'get',
          `${BASE}/messages/${ctx.foreignRecord}/security`,
          undefined,
          'archive_message_not_found',
        ],
        [
          'get',
          `${BASE}/messages/${ctx.foreignRecord}/preview`,
          undefined,
          'archive_message_not_found',
        ],
        [
          'post',
          `${BASE}/messages/${ctx.foreignRecord}/reveal`,
          { fields: ['subject'] },
          'archive_message_not_found',
        ],
        [
          'post',
          `${BASE}/messages/${ctx.foreignRecord}/download-grants`,
          { password: TEST_REAUTH_PASSWORD },
          'archive_message_not_found',
        ],
        [
          'get',
          `${BASE}/retention-policies/${ctx.foreignPolicy}`,
          undefined,
          'archive_retention_policy_not_found',
        ],
      ];
      for (const [method, path, body, code] of checks) {
        const req = api.http()[method](path).set(auth);
        const res = await (body ? req.send(body) : req);
        expect(res.status, path).toBe(404);
        expect(res.body.code, path).toBe(code);
      }
      const keyed: Array<[Method, string, object | undefined, string]> = [
        [
          'put',
          `${BASE}/retention-policies/${ctx.foreignPolicy}`,
          ARCHIVE_EXAMPLES.policyUpdate,
          'archive_retention_policy_not_found',
        ],
        [
          'delete',
          `${BASE}/retention-policies/${ctx.foreignPolicy}`,
          undefined,
          'archive_retention_policy_not_found',
        ],
        [
          'post',
          `${BASE}/capture-issues/${ctx.foreignRecord}/retry`,
          undefined,
          'archive_capture_issue_not_found',
        ],
        [
          'post',
          `${BASE}/messages/${ctx.foreignRecord}/dispose`,
          ARCHIVE_EXAMPLES.dispose,
          'archive_message_not_found',
        ],
      ];
      for (const [method, path, body, code] of keyed) {
        const req = api.http()[method](path).set(auth).set('Idempotency-Key', randomUUID());
        const res = await (body ? req.send(body) : req);
        expect(res.status, path).toBe(404);
        expect(res.body.code, path).toBe(code);
      }
      // Search runs through the caller's alias only: the other tenant's document never shows.
      const search = await api.http().get(`${BASE}/messages?${RANGE}`).set(auth);
      expect(search.status).toBe(200);
      expect(search.body.data.map((m: { messageId: string }) => m.messageId)).not.toContain(
        ctx.foreignRecord,
      );
      expect(world.searchCalls.every((c) => c.organizationId === org)).toBe(true);
    });

    it('a download token is bound to its organization and user', async () => {
      const token = await grantToken(ctx.record);
      // Another user of the same organization.
      const original = api.principals.ids.user;
      (api.principals.ids as { user: string }).user = randomUUID();
      const other = await api
        .http()
        .get(`${BASE}/downloads/${token}`)
        .set(await asUser(ALL));
      (api.principals.ids as { user: string }).user = original;
      expect(other.status).toBe(404);
      expect(other.body.code).toBe('archive_download_token_invalid');
    });
  });

  describe('Idempotency-Key (keyed routes)', () => {
    it.each(SPECS.filter((s) => s.keyed).map((s) => [s.id, s] as const))(
      '%s replays the stored response and refuses a reused key',
      async (_id, spec) => {
        const key = `key-${spec.id.slice(1)}-${randomUUID()}`;
        const first = await send(spec, { key });
        expect(first.status, JSON.stringify(first.body)).toBe(spec.ok);
        const replay = await send(spec, { key });
        expect(replay.status).toBe(spec.ok);
        expect(replay.headers['idempotency-replayed']).toBe('true');
        expect(replay.body).toEqual(first.body);
        // The same key for another request (another path) is refused.
        const other =
          spec.method === 'delete'
            ? await send(spec, { key, path: `${BASE}/retention-policies/${ctx.policy}` })
            : await send(spec, {
                key,
                ...(spec.body
                  ? { body: { ...spec.body(), ...differentBody(spec.id) } }
                  : { path: (await spec.path(ctx, api)).replace(ctx.failed, ctx.review) }),
              });
        expect(other.status, JSON.stringify(other.body)).toBe(422);
        expect(other.body.code).toBe('idempotency_key_reused');
      },
    );

    it('a keyed route without the header is 400 idempotency_key_required', async () => {
      const spec = SPECS.find((s) => s.id === '#4')!;
      const res = await api
        .http()
        .post(`${BASE}/retention-policies`)
        .set(await asUser(ALL))
        .send(ARCHIVE_EXAMPLES.policyCreate);
      expect(spec.keyed).toBe(true);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('idempotency_key_required');
    });
  });

  /** A body that differs from the spec's example (key reuse). */
  function differentBody(id: string): object {
    switch (id) {
      case '#2':
        return { expectedRowVersion: 3 };
      case '#4':
        return { name: 'Another name' };
      case '#6':
        return { retentionDays: 100 };
      case '#9':
        return { reason: 'Another reason' };
      case '#23':
        return { reason: 'Another reason' };
      default:
        return {};
    }
  }

  describe('lists: v1 cursors', () => {
    const LISTS: Array<[string, string, () => void | Promise<void>]> = [
      ['retention policies', `${BASE}/retention-policies?limit=1`, () => undefined],
      [
        'keys',
        `${BASE}/keys?limit=1`,
        async () => {
          await world.tenantKey(org, 2);
        },
      ],
      [
        'capture issues',
        `${BASE}/capture-issues?limit=1`,
        () => {
          const rec = world.records[1]!;
          world.intents.push({
            ...world.intents[0]!,
            id: world.id(),
            messageId: rec.messageId,
            messagePublicId: rec.messagePublicId,
            receivedAt: rec.receivedAt,
            status: 'lost',
          });
        },
      ],
      [
        'disposals',
        `${BASE}/disposals?limit=1`,
        () => {
          world.disposals.push({
            ...world.disposals[0]!,
            id: world.id(),
            requestedAt: new Date(Date.now() - 2 * DAY),
          });
        },
      ],
      ['messages', `${BASE}/messages?${RANGE}&limit=1`, () => undefined],
    ];

    it.each(LISTS)(
      '%s pages with a signed cursor; tampered and foreign cursors are 400',
      async (_name, path, more) => {
        await more();
        const auth = await asUser(ALL);
        const first = await api.http().get(path).set(auth);
        expect(first.status, JSON.stringify(first.body)).toBe(200);
        expect(first.body.data).toHaveLength(1);
        const cursor = first.body.nextCursor as string;
        expect(typeof cursor).toBe('string');
        const second = await api
          .http()
          .get(`${path}&cursor=${encodeURIComponent(cursor)}`)
          .set(auth);
        expect(second.status, JSON.stringify(second.body)).toBe(200);
        expect(second.body.data[0]).not.toEqual(first.body.data[0]);
        const tampered = `${cursor.slice(0, -2)}${cursor.endsWith('AA') ? 'BB' : 'AA'}`;
        const bad = await api
          .http()
          .get(`${path}&cursor=${encodeURIComponent(tampered)}`)
          .set(auth);
        expect(bad.status).toBe(400);
        expect(bad.body.code).toBe('cursor_invalid');
        const foreign = api.app.get(CursorCodec).encode({
          resource: 'archive_messages',
          organizationPublicId: randomUUID(),
          keys: ['1', randomUUID()],
          filterHash: 'f'.repeat(16),
          direction: 'desc',
        });
        const other = await api
          .http()
          .get(`${path}&cursor=${encodeURIComponent(foreign)}`)
          .set(auth);
        expect(other.status).toBe(400);
        expect(other.body.code).toBe('cursor_invalid');
      },
    );
  });

  describe('settings (#1, #2; A22)', () => {
    it('GET shows the effective settings, the entitlement and the lock availability', async () => {
      world.settings.delete(org);
      const res = await api
        .http()
        .get(`${BASE}/settings`)
        .set(await asUser([READ]));
      expect(res.body).toMatchObject({
        enabled: false,
        entitled: true,
        immutability: 'none',
        objectLockAvailable: true,
        rowVersion: 0,
        settings: {
          directions: { inbound: true, outbound: true, internal: true },
          include: { rejected: false, quarantined: false, failed: false },
          access: { previewEnabled: true, downloadEnabled: false },
        },
      });
    });

    it('PUT applies the CAS, bumps the generation, signals the lock pass and audits changed paths only', async () => {
      const auth = await asUser([MANAGE, JMANAGE]);
      const conflict = await api
        .http()
        .put(`${BASE}/settings`)
        .set(auth)
        .set('Idempotency-Key', 'k1')
        .send({ expectedRowVersion: 1, enabled: false });
      expect(conflict.status).toBe(409);
      expect(conflict.body).toMatchObject({
        code: 'archive_settings_conflict',
        currentRowVersion: 2,
      });
      const res = await api
        .http()
        .put(`${BASE}/settings`)
        .set(auth)
        .set('Idempotency-Key', 'k2')
        .send(ARCHIVE_EXAMPLES.settingsUpdate);
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ immutability: 'governance', rowVersion: 3, generation: 2 });
      expect(world.lockLoggingCursors).toEqual([`archive:lock:${org}`]);
      const entry = audit.entries.find((e) => e.action === 'archive.settings_updated')!;
      expect(entry.metadata).toMatchObject({
        changedPaths: ['immutability', 'settings'],
        applyLockPass: true,
      });
      expect(JSON.stringify(entry.metadata)).not.toContain('legal@example.com');
    });

    it('PUT refuses enabling without entitlement or default, scope ids of another tenant, downgrades and missing Object Lock', async () => {
      const auth = await asUser([MANAGE, JMANAGE]);
      const put = (body: object) =>
        api
          .http()
          .put(`${BASE}/settings`)
          .set(auth)
          .set('Idempotency-Key', randomUUID())
          .send(body);
      world.settings.get(org)!.enabled = false;
      world.archivingDisabled.add(org);
      expect((await put({ expectedRowVersion: 2, enabled: true })).body.code).toBe(
        'archiving_not_enabled',
      );
      world.archivingDisabled.clear();
      world.settings.get(org)!.defaultRetentionPolicyId = null;
      const noDefault = await put({ expectedRowVersion: 2, enabled: true });
      expect(noDefault.status).toBe(422);
      expect(noDefault.body.code).toBe('archive_default_retention_required');
      const foreignDomain = randomUUID();
      world.domains.push({
        organizationId: OTHER_ORG,
        publicId: foreignDomain,
        name: 'other.example',
        verified: true,
      });
      const scopeRes = await put({
        expectedRowVersion: 2,
        settings: { scope: { mode: 'include', domainIds: [foreignDomain] } },
      });
      expect(scopeRes.status).toBe(422);
      expect(scopeRes.body).toMatchObject({
        code: 'archive_scope_reference_invalid',
        path: 'settings.scope.domainIds.0',
      });
      world.settings.get(org)!.objectLockMode = 'compliance';
      const down = await put({ expectedRowVersion: 2, immutability: 'governance' });
      expect(down.status).toBe(409);
      expect(down.body.code).toBe('archive_immutability_downgrade_forbidden');
      world.settings.get(org)!.objectLockMode = 'none';
      world.lockAvailable = false;
      const lock = await put({ expectedRowVersion: 2, immutability: 'compliance' });
      expect(lock.status).toBe(409);
      expect(lock.body.code).toBe('archive_object_lock_unavailable');
    });
  });

  describe('retention policies (#3–#7; A11)', () => {
    it('creates under the caps and refuses names, limits, entitlement and the default delete', async () => {
      const auth = await asUser([MANAGE, READ]);
      const post = (body: object) =>
        api
          .http()
          .post(`${BASE}/retention-policies`)
          .set(auth)
          .set('Idempotency-Key', randomUUID())
          .send(body);
      const created = await post(ARCHIVE_EXAMPLES.policyCreate);
      expect(created.status).toBe(201);
      expect(created.body).toMatchObject({
        name: 'Seven years',
        retentionDays: 2555,
        isDefault: false,
      });
      expect((await post(ARCHIVE_EXAMPLES.policyCreate)).body.code).toBe(
        'archive_retention_policy_name_taken',
      );
      world.retentionLimit.set(org, 2555n);
      const tooLong = await post({
        ...ARCHIVE_EXAMPLES.policyCreate,
        name: 'Long',
        retentionDays: 3000,
      });
      expect(tooLong.status).toBe(422);
      expect(tooLong.body).toMatchObject({ code: 'archive_retention_exceeds_limit', limit: 2555 });
      world.retentionLimit.set(org, 0n);
      expect((await post({ ...ARCHIVE_EXAMPLES.policyCreate, name: 'Zero' })).body.code).toBe(
        'archive_retention_exceeds_limit',
      );
      world.retentionLimit.clear();
      world.addPolicy(org);
      world.addPolicy(org);
      const limit = await post({ ...ARCHIVE_EXAMPLES.policyCreate, name: 'Sixth' });
      expect(limit.status).toBe(422);
      expect(limit.body).toMatchObject({ code: 'archive_retention_policy_limit', limit: 5 });
      world.archivingDisabled.add(org);
      expect((await post({ ...ARCHIVE_EXAMPLES.policyCreate, name: 'X' })).body.code).toBe(
        'archiving_not_enabled',
      );
      world.archivingDisabled.clear();
      const del = await api
        .http()
        .delete(`${BASE}/retention-policies/${ctx.policy}`)
        .set(auth)
        .set('Idempotency-Key', randomUUID());
      expect(del.status).toBe(409);
      expect(del.body.code).toBe('archive_retention_policy_is_default');
      const ok = await api
        .http()
        .delete(`${BASE}/retention-policies/${ctx.spare}`)
        .set(auth)
        .set('Idempotency-Key', randomUUID());
      expect(ok.status).toBe(204);
      expect(
        (await api.http().get(`${BASE}/retention-policies/${ctx.spare}`).set(auth)).status,
      ).toBe(404);
      // The name of a deleted policy can be reused.
      expect((await post({ ...ARCHIVE_EXAMPLES.policyCreate, name: 'Spare' })).status).toBe(201);
    });

    it('PUT is a CAS replacement and audits the changed paths', async () => {
      const auth = await asUser([MANAGE]);
      const stale = await api
        .http()
        .put(`${BASE}/retention-policies/${ctx.policy}`)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send({ ...ARCHIVE_EXAMPLES.policyUpdate, expectedRowVersion: 7 });
      expect(stale.status).toBe(409);
      expect(stale.body).toMatchObject({
        code: 'archive_retention_policy_conflict',
        currentRowVersion: 1,
      });
      const res = await api
        .http()
        .put(`${BASE}/retention-policies/${ctx.policy}`)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send(ARCHIVE_EXAMPLES.policyUpdate);
      expect(res.body).toMatchObject({ retentionDays: 2920, rowVersion: 2, isDefault: true });
      const entry = audit.entries.find((e) => e.action === 'archive.retention_policy_updated')!;
      expect(entry.metadata).toMatchObject({
        changedPaths: ['criteria', 'name', 'retentionDays'],
        previousRetentionDays: 2555,
      });
    });
  });

  describe('keys (#8, #9; A9)', () => {
    it('rotation creates the next active version and retires the previous one (no key material)', async () => {
      const auth = await asUser([MANAGE, READ, SEARCH]);
      const res = await api
        .http()
        .post(`${BASE}/keys/rotate`)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send({ reason: 'Annual rotation' });
      expect(res.status).toBe(201);
      expect(res.body).toMatchObject({
        previousVersion: 1,
        key: { version: 2, status: 'active', rootKeyId: 'r1' },
      });
      const list = await api.http().get(`${BASE}/keys`).set(auth);
      expect(
        list.body.data.map((k: { version: number; status: string }) => [k.version, k.status]),
      ).toEqual([
        [2, 'active'],
        [1, 'retired'],
      ]);
      expect(JSON.stringify(list.body)).not.toMatch(/wrapped|v1\.r1\./);
      expect(audit.entries.find((e) => e.action === 'archive.key_rotated')!.metadata).toMatchObject(
        { fromVersion: 1, toVersion: 2 },
      );
      // Records captured under version 1 stay readable.
      expect(
        (await api.http().get(`${BASE}/messages/${ctx.record}/journal`).set(auth)).status,
      ).toBe(200);
    });
  });

  describe('status, capture issues, disposals, signing keys (#10–#14)', () => {
    it('reports counts, retries a failed intent only, lists the log and the public keys', async () => {
      const auth = await asUser([READ, MANAGE]);
      const status = await api.http().get(`${BASE}/status`).set(auth);
      expect(status.body).toMatchObject({
        capture: { failed: 1 },
        records: { active: 1, expiryReview: 1 },
        objectLock: { available: true },
        search: { configured: true, available: true },
      });
      const issues = await api.http().get(`${BASE}/capture-issues`).set(auth);
      expect(issues.body.data).toEqual([
        expect.objectContaining({ messageId: ctx.failed, status: 'failed', code: 'storage_error' }),
      ]);
      const retry = await api
        .http()
        .post(`${BASE}/capture-issues/${ctx.failed}/retry`)
        .set(auth)
        .set('Idempotency-Key', randomUUID());
      expect(retry.body).toMatchObject({ messageId: ctx.failed, status: 'pending' });
      world.intents[0]!.status = 'lost';
      const lost = await api
        .http()
        .post(`${BASE}/capture-issues/${ctx.failed}/retry`)
        .set(auth)
        .set('Idempotency-Key', randomUUID());
      expect(lost.status).toBe(409);
      expect(lost.body).toMatchObject({
        code: 'archive_capture_retry_not_allowed',
        status: 'lost',
      });
      const disposals = await api.http().get(`${BASE}/disposals`).set(auth);
      expect(disposals.body.data[0]).toMatchObject({
        reason: 'retention_expired',
        state: 'completed',
      });
      const keys = await api.http().get(`${BASE}/export-signing-keys`).set(auth);
      expect(keys.body.data).toEqual([
        expect.objectContaining({
          id: 'es1',
          algorithm: 'Ed25519',
          current: true,
          publicKey: api.config.ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY,
        }),
      ]);
    });
  });

  describe('search (#15; A17)', () => {
    it('masks results, sets the lag header, audits the first page only and gates reveal filters', async () => {
      world.indexQueue.push({
        organizationId: org,
        createdAt: new Date(Date.now() - 5000),
        op: 'upsert',
        messagePublicId: ctx.record,
      });
      const auth = await asUser([SEARCH]);
      const res = await api.http().get(`${BASE}/messages?${RANGE}&limit=1`).set(auth);
      expect(res.status).toBe(200);
      expect(Number(res.headers['x-eg-index-lag-seconds'])).toBeGreaterThanOrEqual(4);
      const item = res.body.data[0];
      expect(item.subject).toBeNull();
      expect(item.subjectMasked).toBe(true);
      expect(item.recipients.every((r: string) => r.includes('***@'))).toBe(true);
      expect(JSON.stringify(res.body)).not.toMatch(/Quarterly|alice\.recipient/);
      expect(audit.entries.filter((e) => e.action === 'archive.searched')).toHaveLength(1);
      await api
        .http()
        .get(`${BASE}/messages?${RANGE}&limit=1&cursor=${encodeURIComponent(res.body.nextCursor)}`)
        .set(auth);
      expect(audit.entries.filter((e) => e.action === 'archive.searched')).toHaveLength(1);
      for (const [param, filter] of [
        ['recipient=alice.recipient%40corp.example', 'recipient'],
        ['subject=Quarterly', 'subject'],
        ['custodian=alice.recipient%40corp.example', 'custodian'],
        [`holdId=${randomUUID()}`, 'holdId'],
      ] as const) {
        const before = world.searchCalls.length;
        const forbidden = await api.http().get(`${BASE}/messages?${RANGE}&${param}`).set(auth);
        expect(forbidden.status, param).toBe(403);
        expect(forbidden.body).toMatchObject({ code: 'archive_filter_forbidden', filter });
        expect(world.searchCalls.length).toBe(before);
      }
      const revealer = await asUser([SEARCH, REVEAL]);
      const ok = await api.http().get(`${BASE}/messages?${RANGE}&subject=Quarterly`).set(revealer);
      expect(ok.status).toBe(200);
      const metadata = JSON.stringify(audit.entries.at(-1)!.metadata);
      expect(metadata).not.toContain('Quarterly');
      expect(metadata).toContain(createHash('sha256').update('quarterly').digest('hex'));
    });

    it('requires a bounded range and answers 503 when search is unavailable', async () => {
      const auth = await asUser([SEARCH]);
      expect((await api.http().get(`${BASE}/messages`).set(auth)).status).toBe(400);
      const wide = await api
        .http()
        .get(`${BASE}/messages?from=2020-01-01T00:00:00Z&to=2026-01-01T00:00:00Z`)
        .set(auth);
      expect(wide.status).toBe(400);
      expect(wide.body).toMatchObject({ code: 'archive_search_range_invalid', maxDays: 366 });
      world.searchDown = true;
      const down = await api.http().get(`${BASE}/messages?${RANGE}`).set(auth);
      expect(down.status).toBe(503);
      expect(down.body.code).toBe('archive_search_unavailable');
      // Detail keeps working without search.
      expect(
        (
          await api
            .http()
            .get(`${BASE}/messages/${ctx.record}`)
            .set(await asUser([SEARCH]))
        ).status,
      ).toBe(200);
    });
  });

  describe('detail, journal, security, reveal, preview (#16–#20; A19)', () => {
    it('detail masks parties and shows holds only to hold permissions', async () => {
      world.addHold(org, { criteria: { custodians: ['bob@corp.example'] }, name: 'Bob hold' });
      const plain = await api
        .http()
        .get(`${BASE}/messages/${ctx.record}`)
        .set(await asUser([SEARCH]));
      expect(plain.body).toMatchObject({
        subject: null,
        subjectMasked: true,
        holds: null,
        retention: { expiryAction: 'delete' },
      });
      expect(plain.body.parties.recipients.map((r: { address: string }) => r.address)).toEqual([
        'a***@corp.example',
        'b***@corp.example',
      ]);
      const holder = await api
        .http()
        .get(`${BASE}/messages/${ctx.record}`)
        .set(await asUser([SEARCH, HOLD]));
      expect(holder.body.holds).toEqual([expect.objectContaining({ name: 'Bob hold' })]);
      expect(audit.entries.filter((e) => e.action === 'archive.message_viewed')).toHaveLength(2);
    });

    it('journal decrypts and masks; security maps the frozen round; reveal is audited before values', async () => {
      const auth = await asUser([SEARCH, REVEAL]);
      const journal = await api.http().get(`${BASE}/messages/${ctx.record}/journal`).set(auth);
      expect(journal.status).toBe(200);
      expect(journal.body.headers).toEqual(
        expect.arrayContaining([
          { name: 'Subject', value: null, masked: true },
          { name: 'To', value: null, masked: true },
          expect.objectContaining({ name: 'From', masked: false }),
        ]),
      );
      expect(journal.body.attachments[0]).toMatchObject({ fileName: 'report.pdf', partIndex: 2 });
      const security = await api.http().get(`${BASE}/messages/${ctx.record}/security`).set(auth);
      expect(security.body.rounds[0]).toMatchObject({
        round: 1,
        revision: 1,
        scan: { round: 1, verdict: 'clean' },
      });
      expect(security.status).toBe(200);
      // The frozen decimal strings are restored before the live mapper (WP3 D2).
      expect(security.body.rounds[0].scan.engines[0]).toMatchObject({
        engine: 'rspamd',
        score: 1.5,
        requiredScore: 15,
      });
      expect(security.body.dlpEvidence).toBe('not_retained');
      const reveal = await api
        .http()
        .post(`${BASE}/messages/${ctx.record}/reveal`)
        .set(auth)
        .send({ fields: ['subject', 'recipients', 'headers'] });
      expect(reveal.body).toMatchObject({
        subject: 'Quarterly report',
        recipients: [
          { seq: 0, address: 'alice.recipient@corp.example' },
          { seq: 1, address: 'bob@corp.example' },
        ],
      });
      expect(reveal.body.headers.map((h: { name: string }) => h.name).sort()).toEqual([
        'Subject',
        'To',
      ]);
      const entry = audit.entries.find((e) => e.action === 'archive.revealed')!;
      expect(entry.metadata).toMatchObject({
        fields: ['headers', 'recipients', 'subject'],
        recipientCount: 2,
        headerCount: 2,
      });
      expect(JSON.stringify(entry.metadata)).not.toMatch(/Quarterly|alice/);
    });

    it('preview is sanitized, needs the tenant switch and refuses platform overrides', async () => {
      const auth = await asUser([RETRIEVE]);
      const res = await api.http().get(`${BASE}/messages/${ctx.record}/preview`).set(auth);
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ version: 'preview/1', body: { source: 'text' } });
      expect(res.body.body.text).not.toContain('https://phish.example');
      expect(audit.entries.at(-1)!.action).toBe('archive.previewed');
      world.settings.get(org)!.settings = { access: { previewEnabled: false } };
      const disabled = await api.http().get(`${BASE}/messages/${ctx.record}/preview`).set(auth);
      expect(disabled.status).toBe(403);
      expect(disabled.body.code).toBe('archive_preview_disabled');
    });

    it('content routes refuse a disposing record (410) after the writer re-check', async () => {
      const r = world.records.find((x) => x.messagePublicId === ctx.record)!;
      r.status = 'disposing';
      r.wrappedDek = null;
      const auth = await asUser(ALL);
      for (const path of ['journal', 'security', 'preview']) {
        const res = await api.http().get(`${BASE}/messages/${ctx.record}/${path}`).set(auth);
        expect(res.status, path).toBe(410);
        expect(res.body.code).toBe('archive_content_unavailable');
      }
    });
  });

  describe('downloads (#21, #22; A19)', () => {
    it('grant → single-use download streams the verified original as an attachment', async () => {
      const auth = await asUser([RETRIEVE]);
      const wrong = await api
        .http()
        .post(`${BASE}/messages/${ctx.record}/download-grants`)
        .set(auth)
        .send({ password: 'wrong' });
      expect(wrong.status).toBe(401);
      expect(wrong.body.code).toBe('quarantine_reauth_failed');
      const grant = await api
        .http()
        .post(`${BASE}/messages/${ctx.record}/download-grants`)
        .set(auth)
        .send({ password: TEST_REAUTH_PASSWORD });
      expect(grant.status).toBe(201);
      expect(grant.body.token).toMatch(/^v1\./);
      const record = world.records.find((x) => x.messagePublicId === ctx.record)!;
      expect(grant.body).toMatchObject({ sha256: record.sha256, sizeBytes: record.sizeBytes });
      const res = await api
        .http()
        .get(`${BASE}/downloads/${grant.body.token}`)
        .set(auth)
        .buffer(true)
        .parse((r, cb) => {
          const chunks: Buffer[] = [];
          r.on('data', (c: Buffer) => chunks.push(c));
          r.on('end', () => cb(null, Buffer.concat(chunks)));
        });
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toBe('application/octet-stream');
      expect(res.headers['content-disposition']).toBe(
        `attachment; filename="message-${ctx.record}.eml"`,
      );
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['content-security-policy']).toBe("sandbox; default-src 'none'");
      expect(
        createHash('sha256')
          .update(res.body as Buffer)
          .digest('hex'),
      ).toBe(record.sha256);
      expect(audit.entries.map((e) => e.action)).toEqual(
        expect.arrayContaining(['archive.download_granted', 'archive.downloaded']),
      );
      const again = await api.http().get(`${BASE}/downloads/${grant.body.token}`).set(auth);
      expect(again.status).toBe(410);
      expect(again.body.code).toBe('archive_download_token_used');
      const forged = await api.http().get(`${BASE}/downloads/v1.EXAMPLE.EXAMPLE`).set(auth);
      expect(forged.status).toBe(404);
    });

    it('grants need the download switch, refuse malicious records and platform overrides', async () => {
      const auth = await asUser([RETRIEVE]);
      world.settings.get(org)!.settings = { access: { downloadEnabled: false } };
      const disabled = await api
        .http()
        .post(`${BASE}/messages/${ctx.record}/download-grants`)
        .set(auth)
        .send({ password: TEST_REAUTH_PASSWORD });
      expect(disabled.body.code).toBe('archive_download_disabled');
      world.settings.get(org)!.settings = { access: { downloadEnabled: true } };
      world.records.find((x) => x.messagePublicId === ctx.record)!.malicious = true;
      const blocked = await api
        .http()
        .post(`${BASE}/messages/${ctx.record}/download-grants`)
        .set(auth)
        .send({ password: TEST_REAUTH_PASSWORD });
      expect(blocked.status).toBe(409);
      expect(blocked.body).toMatchObject({ code: 'archive_download_blocked', reason: 'malicious' });
    });
  });

  describe('dispose (#23; A13, A14)', () => {
    it('crypto-shreds a reviewed record and queues the disposal; holds and retention refuse', async () => {
      const auth = await asUser([MANAGE]);
      const hold = world.addHold(org, { criteria: {} });
      const held = await api
        .http()
        .post(`${BASE}/messages/${ctx.review}/dispose`)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send({ reason: 'Reviewed' });
      expect(held.status).toBe(409);
      expect(held.body).toMatchObject({
        code: 'archive_dispose_not_allowed',
        reason: 'legal_hold',
      });
      hold.status = 'released';
      const active = await api
        .http()
        .post(`${BASE}/messages/${ctx.record}/dispose`)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send({ reason: 'Reviewed' });
      expect(active.body).toMatchObject({ code: 'archive_dispose_not_allowed', reason: 'active' });
      const res = await api
        .http()
        .post(`${BASE}/messages/${ctx.review}/dispose`)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send({ reason: 'Reviewed' });
      expect(res.status).toBe(202);
      const r = world.records.find((x) => x.messagePublicId === ctx.review)!;
      expect(r).toMatchObject({ status: 'disposing', wrappedDek: null });
      expect(world.disposals.at(-1)).toMatchObject({
        reason: 'review_disposed',
        state: 'shredded',
      });
      expect(world.indexQueue.at(-1)).toMatchObject({ op: 'delete', messagePublicId: ctx.review });
      const journal = await api
        .http()
        .get(`${BASE}/messages/${ctx.review}/journal`)
        .set(await asUser([SEARCH]));
      expect(journal.status).toBe(410);
    });
  });

  describe('route limits (429 with RateLimit-* and Retry-After)', () => {
    let limited: StubbedApiApp;
    const lworld = new ArchiveWorld();
    const lstore = new InMemoryIdempotencyStore();
    let record: string;

    beforeAll(async () => {
      limited = await createStubbedApiApp(
        {
          ARCHIVE_PREVIEW_PER_MINUTE: '1',
          ARCHIVE_REVEAL_PER_MINUTE: '1',
          ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR: '1',
          API_RATE_EXPENSIVE_PER_MINUTE: '1',
        },
        {
          override: (b) => lstore.override(overrideArchive(b, lworld, new RecordingAuditService())),
        },
      );
      lworld.rootKey = limited.config;
      lworld.setSettings(limited.principals.organizationId, {
        enabled: true,
        settings: { access: { downloadEnabled: true } },
      });
      record = (await lworld.addRecord(limited.principals.organizationId)).record.messagePublicId;
    });

    afterAll(async () => {
      await limited?.close();
    });

    const twice = async (
      call: () => Promise<{
        status: number;
        headers: Record<string, string>;
        body: { code?: string; scope?: string };
      }>,
    ) => {
      const first = await call();
      expect(first.status).toBeLessThan(400);
      const second = await call();
      expect(second.status).toBe(429);
      expect(second.body.code).toBe('rate_limited');
      expect(second.headers['retry-after']).toMatch(/^\d+$/);
      expect(second.headers['ratelimit-limit']).toBe('1');
      expect(second.headers['ratelimit-remaining']).toBe('0');
      return second;
    };

    it('preview, reveal, grants and downloads have route limits; search has the expensive class', async () => {
      const auth = await limited.principals.user(ALL, { mfaAuthenticated: true }).bearer();
      const http = () => limited.http();
      expect(
        (await twice(() => http().get(`${BASE}/messages/${record}/preview`).set(auth))).body.scope,
      ).toBe('route');
      await twice(() =>
        http()
          .post(`${BASE}/messages/${record}/reveal`)
          .set(auth)
          .send({ fields: ['subject'] }),
      );
      await twice(() =>
        http()
          .post(`${BASE}/messages/${record}/download-grants`)
          .set(auth)
          .send({ password: TEST_REAUTH_PASSWORD }),
      );
      const expensive = await twice(() => http().get(`${BASE}/messages?${RANGE}`).set(auth));
      expect(expensive.body.scope).toBe('expensive');
    });
  });
});
