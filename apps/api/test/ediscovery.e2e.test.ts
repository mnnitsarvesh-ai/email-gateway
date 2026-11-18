/**
 * The legal hold and eDiscovery routes of step 8.1 (docs/plan/steps/23-journaling-archiving.md
 * §4.4 #24–#41, §9.3) over HTTP with every dependency stubbed (`ArchiveWorld` doubles, records and
 * export packages encrypted with the real `@email-gateway/archive` crypto, the in-memory
 * Idempotency-Key store). For every operation: success with the OpenAPI example, strict bodies,
 * 401, 403 for each system role (A20 matrix) and API keys on MFA/user routes, 404 for another
 * organization's ids, Idempotency-Key replay and reuse, the shared download-grant limit (429),
 * tampered and foreign cursors, and the rules of A12/A18 (confidential holds, case limits,
 * reveal-gated criteria, completeness, review bounds, export bounds and the malicious
 * acknowledgement, single-use export downloads verified against the package SHA-256).
 */
// @covers get /api/v1/legal-holds
// @covers get /api/v1/legal-holds/:holdId
// @covers post /api/v1/legal-holds/:holdId/release
// @covers post /api/v1/ediscovery/cases/:caseId/holds
// @covers get /api/v1/ediscovery/cases
// @covers post /api/v1/ediscovery/cases
// @covers get /api/v1/ediscovery/cases/:caseId
// @covers patch /api/v1/ediscovery/cases/:caseId
// @covers post /api/v1/ediscovery/cases/:caseId/close
// @covers post /api/v1/ediscovery/cases/:caseId/searches
// @covers get /api/v1/ediscovery/cases/:caseId/searches
// @covers get /api/v1/ediscovery/cases/:caseId/searches/:searchId
// @covers get /api/v1/ediscovery/cases/:caseId/searches/:searchId/hits
// @covers post /api/v1/ediscovery/cases/:caseId/searches/:searchId/review
// @covers post /api/v1/ediscovery/cases/:caseId/exports
// @covers get /api/v1/ediscovery/cases/:caseId/exports
// @covers get /api/v1/ediscovery/cases/:caseId/exports/:exportId
// @covers post /api/v1/ediscovery/cases/:caseId/exports/:exportId/download-grants
import { createHash, randomUUID } from 'node:crypto';
import {
  encryptArchiveObject,
  exportObjectKey,
  generateDataKey,
  wrapExportKey,
} from '@email-gateway/archive';
import { SYSTEM_ROLES } from '@email-gateway/database';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { CursorCodec } from '../src/http/cursor/cursor-codec';
import {
  EDISCOVERY_EXAMPLE_IDS,
  EDISCOVERY_EXAMPLES,
} from '../src/modules/ediscovery/dto/ediscovery.schemas';
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

const SEARCH = 'archive:search';
const EXPORT = 'archive:export';
const HOLD = 'archive:legal_hold';
const EDISC = 'ediscovery:manage';
const REVEAL = 'message:reveal';
const RETRIEVE = 'archive:retrieve';
const ALL = ['archive:read', SEARCH, EXPORT, HOLD, EDISC, REVEAL, RETRIEVE, 'archive:manage'];
const OTHER_ORG = 2n;
const DAY = 86_400_000;

type Method = 'get' | 'post' | 'put' | 'patch' | 'delete';

interface Ctx {
  case: string;
  hold: string;
  search: string;
  export: string;
  record: string;
  foreignCase: string;
  foreignHold: string;
  foreignSearch: string;
  foreignExport: string;
}

interface Spec {
  id: string;
  method: Method;
  path: (c: Ctx) => string;
  all?: string[];
  any?: string[];
  mfa?: boolean;
  user?: boolean;
  body?: () => object;
  keyed?: boolean;
  ok: number;
}

describe('legal hold and eDiscovery routes (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const world = new ArchiveWorld();
  const audit = new RecordingAuditService();
  const store = new InMemoryIdempotencyStore();
  let org: bigint;
  let ctx: Ctx;
  let packageBytes: Buffer;

  beforeAll(async () => {
    api = await createStubbedApiApp(
      {
        ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR: '1000',
        ARCHIVE_CASES_MAX_OPEN_PER_ORG: '3',
        ARCHIVE_CASE_MAX_CUSTODIANS: '3',
        ARCHIVE_HOLDS_MAX_ACTIVE_PER_ORG: '3',
        ARCHIVE_CASE_MAX_ACTIVE_SEARCHES: '1',
        ARCHIVE_REVIEW_MAX_ITEMS: '2',
        ARCHIVE_EXPORT_MAX_ITEMS: '5',
      },
      { override: (b) => store.override(overrideArchive(b, world, audit)) },
    );
    org = api.principals.organizationId;
    world.rootKey = api.config;
  });

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(async () => {
    world.reset();
    audit.entries.length = 0;
    store.rows.clear();
    api.kv.entries.clear();
    api.principals.apiKeyWith([]);
    ctx = await seed();
  });

  /** A completed, encrypted export package of `organizationId` (what the worker writes). */
  async function completedExport(organizationId: bigint, caseId: bigint, searchId: bigint) {
    const key = await world.tenantKey(organizationId);
    const publicId = organizationId === org ? EDISCOVERY_EXAMPLE_IDS.export : randomUUID();
    const createdAt = new Date();
    const zip = Buffer.from(`PK-EXAMPLE-PACKAGE-${publicId}`, 'utf8');
    const dek = generateDataKey();
    const wrappedDek = wrapExportKey(
      key.key,
      { organizationId, exportPublicId: publicId, keyVersion: key.version },
      dek,
    );
    const object = encryptArchiveObject(zip, {
      dek,
      kind: 'export',
      organizationId,
      subjectId: publicId,
    });
    const objectKey = exportObjectKey({ organizationId, createdAt, exportPublicId: publicId });
    world.objects.set(objectKey, object.object);
    world.addExport(organizationId, caseId, searchId, {
      publicId,
      status: 'completed',
      objectKey,
      keyVersion: key.version,
      wrappedDek,
      packageBytes: BigInt(zip.length),
      packageSha256: createHash('sha256').update(zip).digest('hex'),
      expiresAt: new Date(Date.now() + DAY),
      createdAt,
    });
    if (organizationId === org) packageBytes = zip;
    return publicId;
  }

  async function seed(): Promise<Ctx> {
    world.setSettings(org, { enabled: true });
    const c = world.addCase(org, { name: 'Existing case' });
    world.custodians.push({
      organizationId: org,
      caseId: c.id,
      publicId: randomUUID(),
      address: 'custodian@example.com',
      userPublicId: null,
    });
    const hold = world.addHold(org, {
      caseId: c.id,
      criteria: { custodians: ['custodian@example.com'] },
    });
    const record = await world.addRecord(org, { recipients: ['custodian@example.com'] });
    const search = world.addSearch(org, c.id, {
      publicId: EDISCOVERY_EXAMPLE_IDS.search,
      hitCount: 1,
    });
    world.addHit(org, search.id, record.record);
    const exportId = await completedExport(org, c.id, search.id);
    const fc = world.addCase(OTHER_ORG, { name: 'Other' });
    const fh = world.addHold(OTHER_ORG, { caseId: fc.id });
    const fs = world.addSearch(OTHER_ORG, fc.id);
    const fe = await completedExport(OTHER_ORG, fc.id, fs.id);
    return {
      case: c.publicId,
      hold: hold.publicId,
      search: search.publicId,
      export: exportId,
      record: record.record.messagePublicId,
      foreignCase: fc.publicId,
      foreignHold: fh.publicId,
      foreignSearch: fs.publicId,
      foreignExport: fe,
    };
  }

  const X = EDISCOVERY_EXAMPLES;
  const C = '/api/v1/ediscovery/cases';
  const SPECS: Spec[] = [
    { id: '#24', method: 'get', path: () => '/api/v1/legal-holds', any: [HOLD, EDISC], ok: 200 },
    {
      id: '#25',
      method: 'get',
      path: (c) => `/api/v1/legal-holds/${c.hold}`,
      any: [HOLD, EDISC],
      ok: 200,
    },
    {
      id: '#26',
      method: 'post',
      path: (c) => `/api/v1/legal-holds/${c.hold}/release`,
      all: [HOLD],
      mfa: true,
      keyed: true,
      body: () => X.release,
      ok: 200,
    },
    {
      id: '#27',
      method: 'post',
      path: (c) => `${C}/${c.case}/holds`,
      all: [HOLD, EDISC],
      mfa: true,
      keyed: true,
      body: () => X.holdCreate,
      ok: 201,
    },
    { id: '#28', method: 'get', path: () => C, all: [EDISC], ok: 200 },
    {
      id: '#29',
      method: 'post',
      path: () => C,
      all: [EDISC],
      keyed: true,
      body: () => X.caseCreate,
      ok: 201,
    },
    { id: '#30', method: 'get', path: (c) => `${C}/${c.case}`, all: [EDISC], ok: 200 },
    {
      id: '#31',
      method: 'patch',
      path: (c) => `${C}/${c.case}`,
      all: [EDISC],
      keyed: true,
      body: () => X.caseUpdate,
      ok: 200,
    },
    {
      id: '#32',
      method: 'post',
      path: (c) => `${C}/${c.case}/close`,
      all: [EDISC],
      mfa: true,
      keyed: true,
      ok: 200,
    },
    {
      id: '#33',
      method: 'post',
      path: (c) => `${C}/${c.case}/searches`,
      all: [EDISC, SEARCH],
      keyed: true,
      body: () => X.searchCreate,
      ok: 202,
    },
    { id: '#34', method: 'get', path: (c) => `${C}/${c.case}/searches`, all: [EDISC], ok: 200 },
    {
      id: '#35',
      method: 'get',
      path: (c) => `${C}/${c.case}/searches/${c.search}`,
      all: [EDISC],
      ok: 200,
    },
    {
      id: '#36',
      method: 'get',
      path: (c) => `${C}/${c.case}/searches/${c.search}/hits`,
      all: [EDISC],
      ok: 200,
    },
    {
      id: '#37',
      method: 'post',
      path: (c) => `${C}/${c.case}/searches/${c.search}/review`,
      all: [EDISC],
      user: true,
      keyed: true,
      body: () => ({ tag: 'relevant', messageIds: [ctx.record] }),
      ok: 200,
    },
    {
      id: '#38',
      method: 'post',
      path: (c) => `${C}/${c.case}/exports`,
      all: [EDISC, EXPORT],
      keyed: true,
      body: () => X.exportCreate,
      ok: 202,
    },
    { id: '#39', method: 'get', path: (c) => `${C}/${c.case}/exports`, all: [EDISC], ok: 200 },
    {
      id: '#40',
      method: 'get',
      path: (c) => `${C}/${c.case}/exports/${c.export}`,
      all: [EDISC],
      ok: 200,
    },
    {
      id: '#41',
      method: 'post',
      path: (c) => `${C}/${c.case}/exports/${c.export}/download-grants`,
      all: [EDISC, EXPORT],
      mfa: true,
      body: () => ({ password: TEST_REAUTH_PASSWORD }),
      ok: 201,
    },
  ];

  const asUser = (permissions: string[], mfa = true) =>
    api.principals.user(permissions, { mfaAuthenticated: mfa }).bearer();

  /** Close-case needs no active hold: the spec's success path releases the case hold first. */
  const prepare = (spec: Spec) => {
    if (spec.id === '#32') for (const h of world.holds) h.status = 'released';
  };

  async function send(
    spec: Spec,
    o: {
      perms?: string[] | null;
      mfa?: boolean;
      apiKey?: string[];
      key?: string;
      body?: object;
      path?: string;
    } = {},
  ) {
    const req = api.http()[spec.method](o.path ?? spec.path(ctx));
    if (o.apiKey) {
      api.principals.apiKeyWith(o.apiKey);
      req.set(api.principals.apiKeyHeaders);
    } else if (o.perms !== null) {
      req.set(await asUser(o.perms ?? ALL, o.mfa ?? true));
    }
    if (spec.keyed) req.set('Idempotency-Key', o.key ?? randomUUID());
    const body = o.body ?? spec.body?.();
    return body === undefined ? req : req.send(body);
  }

  const reset = async () => {
    world.reset();
    store.rows.clear();
    ctx = await seed();
  };

  describe('every operation', () => {
    it.each(SPECS.map((s) => [s.id, s] as const))(
      '%s succeeds with the OpenAPI example',
      async (_id, spec) => {
        prepare(spec);
        const res = await send(spec);
        expect(res.status, JSON.stringify(res.body)).toBe(spec.ok);
        expect(res.headers['cache-control']).toBe('no-store');
      },
    );

    it.each(SPECS.map((s) => [s.id, s] as const))(
      '%s answers 401 without credentials and 403 without its permission',
      async (_id, spec) => {
        expect((await send(spec, { perms: null })).status).toBe(401);
        const held = ALL.filter((p) => !(spec.all ?? spec.any ?? []).includes(p));
        const res = await send(spec, { perms: held });
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('forbidden');
      },
    );

    it('MFA routes refuse sessions without MFA; MFA and user routes refuse API keys', async () => {
      for (const spec of SPECS.filter((s) => s.mfa)) {
        const res = await send(spec, { mfa: false });
        expect(res.body.code, spec.id).toBe('mfa_required');
      }
      for (const spec of SPECS.filter((s) => s.mfa || s.user)) {
        const res = await send(spec, { apiKey: ALL });
        expect(res.body.code, spec.id).toBe('user_required');
      }
    });

    it('API keys may use the hold reads, case, search and export-request routes', async () => {
      for (const spec of SPECS.filter((s) => !s.mfa && !s.user)) {
        await reset();
        const res = await send(spec, { apiKey: ALL });
        expect(res.status, `${spec.id} ${JSON.stringify(res.body)}`).toBe(spec.ok);
      }
    });

    it.each(SYSTEM_ROLES.map((r) => [r.key, [...r.permissions] as string[]] as const))(
      'the A20 matrix holds for role %s',
      async (_role, permissions) => {
        const held = new Set(permissions);
        for (const spec of SPECS) {
          await reset();
          prepare(spec);
          const res = await send(spec, { perms: permissions });
          const ok = spec.all
            ? spec.all.every((p) => held.has(p))
            : spec.any!.some((p) => held.has(p));
          if (ok) expect(res.status, `${spec.id} ${JSON.stringify(res.body)}`).not.toBe(403);
          else expect(res.status, spec.id).toBe(403);
        }
      },
    );

    it.each(SPECS.filter((s) => s.body).map((s) => [s.id, s] as const))(
      '%s refuses an unknown body field (400)',
      async (_id, spec) => {
        const res = await send(spec, { body: { ...spec.body!(), extra: 1 } });
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('validation_failed');
      },
    );
  });

  describe('tenant isolation', () => {
    it('another organization’s holds, cases, searches and exports answer 404', async () => {
      const f = ctx;
      const paths: Array<[Spec['id'], string, string]> = [
        ['#25', `/api/v1/legal-holds/${f.foreignHold}`, 'legal_hold_not_found'],
        ['#26', `/api/v1/legal-holds/${f.foreignHold}/release`, 'legal_hold_not_found'],
        ['#27', `${C}/${f.foreignCase}/holds`, 'ediscovery_case_not_found'],
        ['#30', `${C}/${f.foreignCase}`, 'ediscovery_case_not_found'],
        ['#31', `${C}/${f.foreignCase}`, 'ediscovery_case_not_found'],
        ['#32', `${C}/${f.foreignCase}/close`, 'ediscovery_case_not_found'],
        ['#33', `${C}/${f.foreignCase}/searches`, 'ediscovery_case_not_found'],
        ['#34', `${C}/${f.foreignCase}/searches`, 'ediscovery_case_not_found'],
        ['#35', `${C}/${f.case}/searches/${f.foreignSearch}`, 'ediscovery_search_not_found'],
        [
          '#36',
          `${C}/${f.foreignCase}/searches/${f.foreignSearch}/hits`,
          'ediscovery_case_not_found',
        ],
        ['#37', `${C}/${f.case}/searches/${f.foreignSearch}/review`, 'ediscovery_search_not_found'],
        ['#38', `${C}/${f.foreignCase}/exports`, 'ediscovery_case_not_found'],
        ['#39', `${C}/${f.foreignCase}/exports`, 'ediscovery_case_not_found'],
        ['#40', `${C}/${f.case}/exports/${f.foreignExport}`, 'ediscovery_export_not_found'],
        [
          '#41',
          `${C}/${f.case}/exports/${f.foreignExport}/download-grants`,
          'ediscovery_export_not_found',
        ],
      ];
      for (const [id, path, code] of paths) {
        const spec = SPECS.find((s) => s.id === id)!;
        const res = await send(spec, { path });
        expect(res.status, `${id} ${JSON.stringify(res.body)}`).toBe(404);
        expect(res.body.code, id).toBe(code);
      }
      const list = await send(SPECS[0]!);
      expect(list.body.data.map((h: { id: string }) => h.id)).not.toContain(f.foreignHold);
      const cases = await send(SPECS.find((s) => s.id === '#28')!);
      expect(cases.body.data.map((x: { id: string }) => x.id)).not.toContain(f.foreignCase);
    });
  });

  describe('Idempotency-Key', () => {
    it.each(SPECS.filter((s) => s.keyed).map((s) => [s.id, s] as const))(
      '%s replays and refuses a reused key',
      async (_id, spec) => {
        prepare(spec);
        const key = randomUUID();
        const first = await send(spec, { key });
        expect(first.status, JSON.stringify(first.body)).toBe(spec.ok);
        const replay = await send(spec, { key });
        expect(replay.status).toBe(spec.ok);
        expect(replay.headers['idempotency-replayed']).toBe('true');
        expect(replay.body).toEqual(first.body);
        const reused = spec.body
          ? await send(spec, {
              key,
              body: {
                ...spec.body(),
                ...(spec.id === '#37'
                  ? { tag: 'privileged' }
                  : spec.id === '#38'
                    ? { acknowledgeMalicious: true }
                    : spec.id === '#33'
                      ? { criteria: { from: '2026-02-01', to: '2026-03-01' } }
                      : spec.id === '#31'
                        ? { name: 'Renamed' }
                        : spec.id === '#26'
                          ? { reason: 'Other reason' }
                          : { name: 'Other' }),
              },
            })
          : await send(spec, { key, path: spec.path(ctx).replace(ctx.case, randomUUID()) });
        expect(reused.status, JSON.stringify(reused.body)).toBe(422);
        expect(reused.body.code).toBe('idempotency_key_reused');
      },
    );
  });

  describe('lists: v1 cursors', () => {
    it.each([
      ['legal holds', '/api/v1/legal-holds?limit=1', (): unknown => world.addHold(org)],
      ['cases', `${C}?limit=1`, (): unknown => world.addCase(org)],
      ['searches', '', (): unknown => undefined],
      [
        'hits',
        '',
        async (): Promise<unknown> =>
          world.addHit(org, world.searches[0]!.id, (await world.addRecord(org)).record),
      ],
      [
        'exports',
        '',
        (): unknown => world.addExport(org, world.cases[0]!.id, world.searches[0]!.id),
      ],
    ] as const)('%s pages; tampered and foreign cursors are 400', async (name, fixed, more) => {
      await more();
      if (name === 'searches') world.addSearch(org, world.cases[0]!.id);
      const path =
        fixed ||
        {
          searches: `${C}/${ctx.case}/searches?limit=1`,
          hits: `${C}/${ctx.case}/searches/${ctx.search}/hits?limit=1`,
          exports: `${C}/${ctx.case}/exports?limit=1`,
        }[name];
      const auth = await asUser(ALL);
      const first = await api.http().get(path).set(auth);
      expect(first.status, JSON.stringify(first.body)).toBe(200);
      const cursor = first.body.nextCursor as string;
      expect(cursor).toEqual(expect.any(String));
      const second = await api
        .http()
        .get(`${path}&cursor=${encodeURIComponent(cursor)}`)
        .set(auth);
      expect(second.status).toBe(200);
      expect(second.body.data[0]).not.toEqual(first.body.data[0]);
      const tampered = `${cursor.slice(0, -2)}${cursor.endsWith('AA') ? 'BB' : 'AA'}`;
      expect(
        (
          await api
            .http()
            .get(`${path}&cursor=${encodeURIComponent(tampered)}`)
            .set(auth)
        ).body.code,
      ).toBe('cursor_invalid');
      const foreign = api.app.get(CursorCodec).encode({
        resource: 'legal_holds',
        organizationPublicId: randomUUID(),
        keys: ['1'],
        filterHash: 'f'.repeat(16),
        direction: 'desc',
      });
      expect(
        (
          await api
            .http()
            .get(`${path}&cursor=${encodeURIComponent(foreign)}`)
            .set(auth)
        ).body.code,
      ).toBe('cursor_invalid');
    });
  });

  describe('legal holds (A12)', () => {
    it('creates with the case custodians, refuses conflicts and limits, releases once', async () => {
      const auth = await asUser([HOLD, EDISC, REVEAL]);
      const post = (body: object) =>
        api
          .http()
          .post(`${C}/${ctx.case}/holds`)
          .set(auth)
          .set('Idempotency-Key', randomUUID())
          .send(body);
      const created = await post(X.holdCreate);
      expect(created.status).toBe(201);
      expect(created.body).toMatchObject({
        criteria: { custodians: ['custodian@example.com'] },
        criteriaVersion: 'archive-hold/1',
        caseId: ctx.case,
      });
      const entry = audit.entries.find((e) => e.action === 'legal_hold.created')!;
      expect(JSON.stringify(entry.metadata)).not.toContain('custodian@example.com');
      expect(entry.metadata).toMatchObject({ custodianCount: 1, useCaseCustodians: true });
      const conflict = await post({ ...X.holdCreate, criteria: { custodians: ['x@example.com'] } });
      expect(conflict.body).toMatchObject({
        code: 'legal_hold_criteria_invalid',
        reason: 'custodians_conflict',
      });
      await post({ name: 'H3', reason: 'r' });
      const limit = await post({ name: 'H4', reason: 'r' });
      expect(limit.status).toBe(422);
      expect(limit.body).toMatchObject({ code: 'legal_hold_limit_reached', limit: 3 });
      const release = () =>
        api
          .http()
          .post(`/api/v1/legal-holds/${ctx.hold}/release`)
          .set(auth)
          .set('Idempotency-Key', randomUUID())
          .send(X.release);
      expect((await release()).body).toMatchObject({
        status: 'released',
        releaseReason: 'Matter settled',
      });
      expect((await release()).body.code).toBe('legal_hold_already_released');
      world.cases[0]!.status = 'closed';
      expect((await post({ name: 'H5', reason: 'r' })).body.code).toBe('ediscovery_case_closed');
    });

    it('holds are confidential: archive:read alone cannot list them', async () => {
      const res = await api
        .http()
        .get('/api/v1/legal-holds')
        .set(await asUser(['archive:read']));
      expect(res.status).toBe(403);
    });
  });

  describe('cases (A18)', () => {
    it('create, update custodians with CAS, close only without active holds', async () => {
      const auth = await asUser([EDISC, REVEAL]);
      const created = await api
        .http()
        .post(C)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send(X.caseCreate);
      expect(created.status).toBe(201);
      expect(created.body.custodians.map((c: { address: string }) => c.address)).toEqual([
        'custodian@example.com',
      ]);
      const dup = await api
        .http()
        .post(C)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send(X.caseCreate);
      expect(dup.body.code).toBe('ediscovery_case_name_taken');
      const many = await api
        .http()
        .post(C)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send({
          name: 'Many',
          custodians: ['a@x.example', 'b@x.example', 'c@x.example', 'd@x.example'],
        });
      expect(many.body).toMatchObject({ code: 'ediscovery_custodian_limit', limit: 3 });
      await api
        .http()
        .post(C)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send({ name: 'Third' });
      const limit = await api
        .http()
        .post(C)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send({ name: 'Fourth' });
      expect(limit.body).toMatchObject({ code: 'ediscovery_case_limit', limit: 3 });
      const stale = await api
        .http()
        .patch(`${C}/${ctx.case}`)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send({ expectedRowVersion: 9, name: 'x' });
      expect(stale.body).toMatchObject({ code: 'ediscovery_case_conflict', currentRowVersion: 1 });
      const patched = await api
        .http()
        .patch(`${C}/${ctx.case}`)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send(X.caseUpdate);
      expect(patched.body).toMatchObject({ rowVersion: 2, counts: { custodians: 2 } });
      const close = () =>
        api.http().post(`${C}/${ctx.case}/close`).set(auth).set('Idempotency-Key', randomUUID());
      const blocked = await close();
      expect(blocked.body).toMatchObject({
        code: 'ediscovery_case_has_active_holds',
        activeHolds: 1,
      });
      world.holds[0]!.status = 'released';
      expect((await close()).body).toMatchObject({ status: 'closed' });
      world.archivingDisabled.add(org);
      const ent = await api
        .http()
        .post(C)
        .set(auth)
        .set('Idempotency-Key', randomUUID())
        .send({ name: 'Ent' });
      expect(ent.body.code).toBe('archiving_not_enabled');
    });
  });

  describe('custodian addresses need message:reveal (A17, ADR-0062 decision 6)', () => {
    it('a case manager without message:reveal cannot write custodians to probe recipients', async () => {
      // A custom role: case management and archive search, no message:reveal.
      const auth = await asUser([EDISC, SEARCH, HOLD]);
      const send = (method: 'post' | 'patch', path: string, body: object) =>
        api.http()[method](path).set(auth).set('Idempotency-Key', randomUUID()).send(body);
      const created = await send('post', C, { name: 'Probe', custodians: ['ceo@example.com'] });
      expect(created.status).toBe(403);
      expect(created.body).toMatchObject({
        code: 'archive_filter_forbidden',
        filter: 'custodians',
      });
      const patched = await send('patch', `${C}/${ctx.case}`, {
        expectedRowVersion: 1,
        custodians: ['ceo@example.com'],
      });
      expect(patched.status).toBe(403);
      expect(patched.body).toMatchObject({
        code: 'archive_filter_forbidden',
        filter: 'custodians',
      });
      // Nothing was written: the case keeps the custodian a reveal holder set.
      const detail = await api.http().get(`${C}/${ctx.case}`).set(auth);
      expect(detail.body).toMatchObject({ rowVersion: 1 });
      expect(detail.body.custodians.map((c: { address: string }) => c.address)).toEqual([
        'custodian@example.com',
      ]);
      const hold = await send('post', `${C}/${ctx.case}/holds`, {
        name: 'Probe hold',
        reason: 'r',
        criteria: { custodians: ['ceo@example.com'] },
      });
      expect(hold.status).toBe(403);
      expect(hold.body).toMatchObject({
        code: 'archive_filter_forbidden',
        filter: 'criteria.custodians',
      });
      // Without addresses the same caller still manages the case and searches its own list.
      const plain = await send('post', C, { name: 'Plain' });
      expect(plain.status).toBe(201);
      const renamed = await send('patch', `${C}/${ctx.case}`, {
        expectedRowVersion: 1,
        name: 'Renamed',
      });
      expect(renamed.status).toBe(200);
      const cleared = await send('patch', `${C}/${plain.body.id}`, {
        expectedRowVersion: plain.body.rowVersion,
        custodians: [],
      });
      expect(cleared.status).toBe(200);
      const search = await send('post', `${C}/${ctx.case}/searches`, {
        criteria: { from: '2026-01-01', to: '2026-02-01', custodians: 'case' },
      });
      expect(search.status).toBe(202);
    });
  });

  describe('searches, hits and review (A17, A18)', () => {
    it('gates reveal criteria, bounds the range and active searches, masks criteria and hits', async () => {
      const auth = await asUser([EDISC, SEARCH]);
      const post = (criteria: object) =>
        api
          .http()
          .post(`${C}/${ctx.case}/searches`)
          .set(auth)
          .set('Idempotency-Key', randomUUID())
          .send({ criteria });
      for (const [criteria, filter] of [
        [{ from: '2026-01-01', to: '2026-02-01', subject: 'invoice' }, 'criteria.subject'],
        [
          { from: '2026-01-01', to: '2026-02-01', recipients: ['a@x.example'] },
          'criteria.recipients',
        ],
        [
          { from: '2026-01-01', to: '2026-02-01', custodians: ['a@x.example'] },
          'criteria.custodians',
        ],
      ] as const) {
        const res = await post(criteria);
        expect(res.status).toBe(403);
        expect(res.body).toMatchObject({ code: 'archive_filter_forbidden', filter });
      }
      const wide = await post({ from: '2000-01-01', to: '2026-01-01' });
      expect(wide.body).toMatchObject({ code: 'archive_search_range_invalid', maxDays: 3650 });
      const queued = await post(X.searchCreate.criteria);
      expect(queued.status).toBe(202);
      expect(queued.body).toMatchObject({ status: 'queued', indexComplete: null });
      const busy = await post(X.searchCreate.criteria);
      expect(busy.status).toBe(429);
      expect(busy.body).toMatchObject({ code: 'ediscovery_search_limit', limit: 1 });
      world.searches.at(-1)!.criteria = {
        from: '2026-01-01',
        to: '2026-02-01',
        subject: 'secret plan',
        recipients: ['a.b@x.example'],
      };
      const view = await api
        .http()
        .get(`${C}/${ctx.case}/searches/${world.searches.at(-1)!.publicId}`)
        .set(await asUser([EDISC]));
      expect(view.body.criteria).toMatchObject({
        subject: null,
        subjectMasked: true,
        recipients: ['a***@x.example'],
      });
      const hits = await api
        .http()
        .get(`${C}/${ctx.case}/searches/${ctx.search}/hits`)
        .set(await asUser([EDISC]));
      expect(hits.body.data[0]).toMatchObject({
        messageId: ctx.record,
        reviewTag: 'untagged',
        message: { subject: null, recipients: ['c***@example.com'] },
      });
      expect(audit.entries.filter((e) => e.action === 'ediscovery.hits_viewed')).toHaveLength(1);
    });

    it('review tags completed searches only, within the item bound', async () => {
      const auth = await asUser([EDISC]);
      const review = (searchId: string, body: object) =>
        api
          .http()
          .post(`${C}/${ctx.case}/searches/${searchId}/review`)
          .set(auth)
          .set('Idempotency-Key', randomUUID())
          .send(body);
      const res = await review(ctx.search, {
        tag: 'privileged',
        messageIds: [ctx.record, randomUUID()],
      });
      expect(res.body).toMatchObject({ updated: 1, notFound: 1, tag: 'privileged' });
      const tooMany = await review(ctx.search, {
        tag: 'relevant',
        messageIds: [randomUUID(), randomUUID(), randomUUID()],
      });
      expect(tooMany.status).toBe(400);
      expect(tooMany.body).toMatchObject({ code: 'ediscovery_review_limit', limit: 2 });
      const running = world.addSearch(org, world.cases[0]!.id, { status: 'running' });
      const notDone = await review(running.publicId, { tag: 'relevant', messageIds: [ctx.record] });
      expect(notDone.body).toMatchObject({
        code: 'ediscovery_search_not_completed',
        status: 'running',
      });
    });
  });

  describe('exports (A18)', () => {
    it('queues within bounds, requires the malicious acknowledgement, downloads once', async () => {
      const auth = await asUser([EDISC, EXPORT]);
      const post = (body: object) =>
        api
          .http()
          .post(`${C}/${ctx.case}/exports`)
          .set(auth)
          .set('Idempotency-Key', randomUUID())
          .send(body);
      world.records[0]!.malicious = true;
      const ack = await post({ searchId: ctx.search });
      expect(ack.status).toBe(409);
      expect(ack.body).toMatchObject({
        code: 'ediscovery_export_malicious_ack_required',
        maliciousCount: 1,
      });
      const ok = await post({ searchId: ctx.search, acknowledgeMalicious: true });
      expect(ok.status).toBe(202);
      expect(ok.body).toMatchObject({
        status: 'queued',
        itemCount: 1,
        maliciousCount: 1,
        reviewTags: ['privileged', 'relevant', 'untagged'],
      });
      for (let i = 0; i < 5; i += 1)
        world.addHit(org, world.searches[0]!.id, (await world.addRecord(org)).record);
      const big = await post({ searchId: ctx.search, acknowledgeMalicious: true });
      expect(big.body).toMatchObject({
        code: 'ediscovery_export_too_large',
        limit: 5,
        unit: 'items',
      });
      const running = world.addSearch(org, world.cases[0]!.id, { status: 'running' });
      expect((await post({ searchId: running.publicId })).body.code).toBe(
        'ediscovery_search_not_completed',
      );

      const grant = await api
        .http()
        .post(`${C}/${ctx.case}/exports/${ctx.export}/download-grants`)
        .set(auth)
        .send({ password: TEST_REAUTH_PASSWORD });
      expect(grant.status).toBe(201);
      const download = await api
        .http()
        .get(`/api/v1/archive/downloads/${grant.body.token}`)
        .set(auth)
        .buffer(true)
        .parse((r, cb) => {
          const chunks: Buffer[] = [];
          r.on('data', (c: Buffer) => chunks.push(c));
          r.on('end', () => cb(null, Buffer.concat(chunks)));
        });
      expect(download.status).toBe(200);
      expect((download.body as Buffer).equals(packageBytes)).toBe(true);
      expect(download.headers['content-disposition']).toBe(
        `attachment; filename="ediscovery-export-${ctx.export}.zip"`,
      );
      expect(audit.entries.map((e) => e.action)).toEqual(
        expect.arrayContaining(['ediscovery.download_granted', 'ediscovery.downloaded']),
      );
      expect(
        (await api.http().get(`/api/v1/archive/downloads/${grant.body.token}`).set(auth)).body.code,
      ).toBe('archive_download_token_used');
      const wrong = await api
        .http()
        .post(`${C}/${ctx.case}/exports/${ctx.export}/download-grants`)
        .set(auth)
        .send({ password: 'nope' });
      expect(wrong.body.code).toBe('quarantine_reauth_failed');
    });

    it('grants refuse exports that are not ready or expired', async () => {
      const auth = await asUser([EDISC, EXPORT]);
      const queued = world.addExport(org, world.cases[0]!.id, world.searches[0]!.id);
      const notReady = await api
        .http()
        .post(`${C}/${ctx.case}/exports/${queued.publicId}/download-grants`)
        .set(auth)
        .send({ password: TEST_REAUTH_PASSWORD });
      expect(notReady.body).toMatchObject({
        code: 'ediscovery_export_not_ready',
        status: 'queued',
      });
      world.exports.find((e) => e.publicId === ctx.export)!.expiresAt = new Date(Date.now() - 1000);
      const expired = await api
        .http()
        .post(`${C}/${ctx.case}/exports/${ctx.export}/download-grants`)
        .set(auth)
        .send({ password: TEST_REAUTH_PASSWORD });
      expect(expired.status).toBe(410);
      expect(expired.body.code).toBe('ediscovery_export_expired');
    });
  });

  describe('route limit of export grants (429)', () => {
    let limited: StubbedApiApp;
    const lworld = new ArchiveWorld();

    beforeAll(async () => {
      limited = await createStubbedApiApp(
        { ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR: '1' },
        {
          override: (b) =>
            new InMemoryIdempotencyStore().override(
              overrideArchive(b, lworld, new RecordingAuditService()),
            ),
        },
      );
      lworld.rootKey = limited.config;
    });

    afterAll(async () => {
      await limited?.close();
    });

    it('shares ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR with message grants', async () => {
      const orgId = limited.principals.organizationId;
      const c = lworld.addCase(orgId);
      const s = lworld.addSearch(orgId, c.id);
      const e = lworld.addExport(orgId, c.id, s.id);
      const auth = await limited.principals.user(ALL, { mfaAuthenticated: true }).bearer();
      const grant = () =>
        limited
          .http()
          .post(`${C}/${c.publicId}/exports/${e.publicId}/download-grants`)
          .set(auth)
          .send({ password: TEST_REAUTH_PASSWORD });
      expect((await grant()).status).toBe(409);
      const second = await grant();
      expect(second.status).toBe(429);
      expect(second.headers['retry-after']).toMatch(/^\d+$/);
      expect(second.headers['ratelimit-limit']).toBe('1');
    });
  });
});
