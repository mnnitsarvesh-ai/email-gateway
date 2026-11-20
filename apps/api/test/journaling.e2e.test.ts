/**
 * The step 8.6 journaling routes (docs/plan/steps/27-journal-intake-and-archive-split.md D1, D8,
 * D10, D11, §9.4) over HTTP with MySQL, Redis and S3 stubbed: the archive settings through the
 * 8.1 `ArchiveWorld`, the journaling repository through `JournalingWorld`, the Idempotency-Key
 * store in memory. For every operation: success, 401, 403 without its permission, MFA and API
 * key rules, 404 for another organization's ids; then creation (address revealed once and
 * derived from JOURNAL_INTAKE_ADDRESS_SECRET, only hashes stored, redacted idempotent replay),
 * the kind-specific rules, entitlement and limits, reveal (permission + audit), rotation with
 * overlap, CAS, pause/resume/disable, attestations, wizard, guide (JSON and Markdown) and the
 * status. The real writer and replica run in integration/journaling.test.ts.
 */
// @covers get /api/v1/journaling/settings
// @covers put /api/v1/journaling/settings
// @covers get /api/v1/journaling/status
// @covers get /api/v1/journaling/intake-sources
// @covers post /api/v1/journaling/intake-sources
// @covers get /api/v1/journaling/intake-sources/:sourceId
// @covers patch /api/v1/journaling/intake-sources/:sourceId
// @covers delete /api/v1/journaling/intake-sources/:sourceId
// @covers post /api/v1/journaling/intake-sources/:sourceId/rotate-address
// @covers get /api/v1/journaling/intake-sources/:sourceId/wizard
// @covers get /api/v1/journaling/intake-sources/:sourceId/setup-guide
// @covers post /api/v1/journaling/intake-sources/:sourceId/attestations
import { randomUUID } from 'node:crypto';
import {
  deriveIntakeAddressToken,
  deriveIntakeHeaderToken,
  intakeAddressHash,
  intakeHeaderTokenHash,
  intakeLocalPart,
  parseIntakeAddressSecret,
} from '@email-gateway/archive';
import { SYSTEM_ROLES } from '@email-gateway/database';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  JOURNALING_EXAMPLES,
  type IntakeSourceView,
} from '../src/modules/journaling/dto/journaling.schemas';
import {
  createStubbedApiApp,
  InMemoryIdempotencyStore,
  type StubbedApiApp,
} from './support/api-test-app';
import { ArchiveWorld, overrideArchive, RecordingAuditService } from './support/archive-fixtures';
import { JournalingWorld, overrideJournaling } from './support/journaling-fixtures';

const JREAD = 'journal:read';
const JMANAGE = 'journal:manage';
const AREAD = 'archive:read';
const ALL = [JREAD, JMANAGE, AREAD];
const BASE = '/api/v1/journaling';
const SRC = `${BASE}/intake-sources`;
const OTHER_ORG = 2n;
const INTAKE_DOMAIN = 'journal.gateway.test';

type Method = 'get' | 'post' | 'put' | 'patch' | 'delete';

interface Ctx {
  source: string;
  google: string;
  foreign: string;
  connection: string;
}

interface Spec {
  id: string;
  method: Method;
  path: (c: Ctx) => string;
  all?: string[];
  any?: string[];
  mfa?: boolean;
  keyed?: boolean;
  body?: (c: Ctx) => object;
  ok: number;
}

describe('journaling routes (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const archive = new ArchiveWorld();
  const world = new JournalingWorld();
  const audit = new RecordingAuditService();
  const store = new InMemoryIdempotencyStore();
  let org: bigint;
  let secret: Buffer;

  beforeAll(async () => {
    api = await createStubbedApiApp(
      {},
      {
        override: (b) =>
          store.override(overrideJournaling(overrideArchive(b, archive, audit), world)),
      },
    );
    org = api.principals.organizationId;
    archive.rootKey = api.config;
    secret = parseIntakeAddressSecret(api.config.JOURNAL_INTAKE_ADDRESS_SECRET!);
  });

  afterAll(async () => {
    await api?.close();
  });

  let ctx: Ctx;
  beforeEach(async () => {
    archive.reset();
    world.reset();
    audit.entries.length = 0;
    store.rows.clear();
    api.kv.entries.clear();
    api.principals.apiKeyWith([]);
    ctx = await seed();
  });

  const asUser = (permissions: string[], mfa = true) =>
    api.principals.user(permissions, { mfaAuthenticated: mfa }).bearer();

  /** Archiving enabled with a default policy, intake entitled, a bound connection, domains. */
  async function seed(): Promise<Ctx> {
    const policy = archive.addPolicy(org, { name: 'Seven years', retentionDays: 2555 });
    archive.setSettings(org, { enabled: true, defaultRetentionPolicyId: policy.id, rowVersion: 2 });
    archive.intakeEntitled.add(org);
    const connection = world.addConnection(org);
    const google = world.addConnection(org, {
      provider: 'google_workspace',
      displayName: 'Contoso Google',
      activeTenantKey: 'google_workspace:C0123abc',
      externalTenantId: 'C0123abc',
    });
    world.domains.push(
      { organizationId: org, name: 'corp.example', verified: true, connectionId: connection.id },
      { organizationId: org, name: 'mail.corp.example', verified: true, connectionId: google.id },
    );
    const source = await create({
      kind: 'microsoft_365_journal',
      displayName: 'Contoso Microsoft 365',
      providerConnectionId: connection.publicId,
    });
    const googleSource = await create({
      kind: 'google_workspace_copy',
      displayName: 'Contoso Google copies',
      providerConnectionId: google.publicId,
    });
    // Another organization's source (seeded directly).
    world.sources.push({
      ...world.sources[0]!,
      id: world.id(),
      publicId: randomUUID(),
      organizationId: OTHER_ORG,
      displayName: 'Other tenant',
      addressHash: 'f'.repeat(64),
    });
    audit.entries.length = 0;
    store.rows.clear();
    return {
      source: source.source.id,
      google: googleSource.source.id,
      foreign: world.sources.at(-1)!.publicId,
      connection: connection.publicId,
    };
  }

  async function create(body: object): Promise<{ source: IntakeSourceView; address: string }> {
    const res = await api
      .http()
      .post(SRC)
      .set(await asUser(ALL))
      .set('Idempotency-Key', randomUUID())
      .send(body);
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    return res.body as { source: IntakeSourceView; address: string };
  }

  const SPECS: Spec[] = [
    {
      id: 'settings.get',
      method: 'get',
      path: () => `${BASE}/settings`,
      any: [JREAD, AREAD],
      ok: 200,
    },
    {
      id: 'settings.put',
      method: 'put',
      path: () => `${BASE}/settings`,
      all: [JMANAGE],
      mfa: true,
      keyed: true,
      body: () => ({ ...JOURNALING_EXAMPLES.settingsUpdate, expectedRowVersion: 2 }),
      ok: 200,
    },
    { id: 'status', method: 'get', path: () => `${BASE}/status`, all: [JREAD], ok: 200 },
    { id: 'list', method: 'get', path: () => SRC, all: [JREAD], ok: 200 },
    {
      id: 'create',
      method: 'post',
      path: () => SRC,
      all: [JMANAGE],
      mfa: true,
      keyed: true,
      body: () => ({
        kind: 'smtp_bcc',
        displayName: `Relay ${randomUUID().slice(0, 8)}`,
        networks: ['198.51.100.0/28'],
      }),
      ok: 201,
    },
    { id: 'get', method: 'get', path: (c) => `${SRC}/${c.source}`, all: [JREAD], ok: 200 },
    {
      id: 'patch',
      method: 'patch',
      path: (c) => `${SRC}/${c.source}`,
      all: [JMANAGE],
      mfa: true,
      keyed: true,
      body: () => ({ expectedRowVersion: 1, silenceAlertMinutes: 600 }),
      ok: 200,
    },
    {
      id: 'delete',
      method: 'delete',
      path: (c) => `${SRC}/${c.source}`,
      all: [JMANAGE],
      mfa: true,
      ok: 200,
    },
    {
      id: 'rotate',
      method: 'post',
      path: (c) => `${SRC}/${c.source}/rotate-address`,
      all: [JMANAGE],
      mfa: true,
      keyed: true,
      ok: 200,
    },
    {
      id: 'wizard',
      method: 'get',
      path: (c) => `${SRC}/${c.source}/wizard`,
      all: [JREAD],
      ok: 200,
    },
    {
      id: 'guide',
      method: 'get',
      path: (c) => `${SRC}/${c.source}/setup-guide`,
      all: [JREAD],
      ok: 200,
    },
    {
      id: 'attest',
      method: 'post',
      path: (c) => `${SRC}/${c.source}/attestations`,
      all: [JMANAGE],
      mfa: true,
      body: () => JOURNALING_EXAMPLES.attestation,
      ok: 200,
    },
  ];

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
    const req = api.http()[spec.method](options.path ?? spec.path(ctx));
    if (options.apiKey) {
      api.principals.apiKeyWith(options.apiKey);
      req.set(api.principals.apiKeyHeaders);
    } else if (options.perms !== null) {
      req.set(await asUser(options.perms ?? ALL, options.mfa ?? true));
    }
    if (spec.keyed) req.set('Idempotency-Key', options.key ?? randomUUID());
    const body = options.body ?? spec.body?.(ctx);
    return body === undefined ? req : req.send(body);
  }

  const allowed = (spec: Spec, held: ReadonlySet<string>) =>
    spec.all ? spec.all.every((p) => held.has(p)) : (spec.any ?? []).some((p) => held.has(p));

  describe('every operation (success, auth, RBAC)', () => {
    it.each(SPECS.map((s) => [s.id, s] as const))(
      '%s succeeds for a privileged MFA user',
      async (_id, spec) => {
        const res = await send(spec);
        expect(res.status, JSON.stringify(res.body)).toBe(spec.ok);
        expect(res.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
      },
    );

    it.each(SPECS.map((s) => [s.id, s] as const))(
      '%s answers 401 without credentials',
      async (_id, spec) => {
        expect((await send(spec, { perms: null })).status).toBe(401);
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

    it('MFA routes refuse a session without MFA and API keys', async () => {
      for (const spec of SPECS.filter((s) => s.mfa)) {
        const noMfa = await send(spec, { mfa: false });
        expect(noMfa.status, spec.id).toBe(403);
        expect(noMfa.body.code, spec.id).toBe('mfa_required');
        const key = await send(spec, { apiKey: ALL });
        expect(key.status, spec.id).toBe(403);
        expect(key.body.code, spec.id).toBe('user_required');
      }
    });

    it('API keys with journal:* scopes may use the read routes', async () => {
      for (const spec of SPECS.filter((s) => !s.mfa)) {
        const res = await send(spec, { apiKey: ALL });
        expect(res.status, `${spec.id} ${JSON.stringify(res.body)}`).toBe(spec.ok);
      }
    });

    it.each(SYSTEM_ROLES.map((r) => [r.key, [...r.permissions] as string[]] as const))(
      'the D12 matrix holds for role %s',
      async (_role, permissions) => {
        const held = new Set(permissions);
        for (const spec of SPECS) {
          archive.reset();
          world.reset();
          store.rows.clear();
          ctx = await seed();
          const res = await send(spec, { perms: permissions });
          if (allowed(spec, held)) {
            expect(res.status, `${spec.id} ${JSON.stringify(res.body)}`).not.toBe(403);
          } else {
            expect(res.status, spec.id).toBe(403);
          }
        }
      },
    );

    it('organization admins and domain admins manage journaling; compliance officers only read it', () => {
      const perms = (key: string) =>
        new Set<string>(SYSTEM_ROLES.find((r) => r.key === key)!.permissions);
      expect(perms('organization_admin').has(JMANAGE)).toBe(true);
      expect(perms('domain_admin').has(JMANAGE)).toBe(true);
      expect(perms('compliance_officer').has(JREAD)).toBe(true);
      expect(perms('compliance_officer').has(JMANAGE)).toBe(false);
      expect(perms('read_only_user').has(JREAD)).toBe(true);
    });
  });

  describe('tenant isolation and ids', () => {
    it('another organization’s source answers 404 on every source route', async () => {
      for (const spec of SPECS.filter((s) => s.path(ctx).includes(ctx.source))) {
        const res = await send(spec, { path: spec.path({ ...ctx, source: ctx.foreign }) });
        expect(res.status, spec.id).toBe(404);
        expect(res.body.code, spec.id).toBe('journal_intake_source_not_found');
      }
      const list = await send(SPECS.find((s) => s.id === 'list')!);
      expect(list.body.data.map((s: IntakeSourceView) => s.id)).not.toContain(ctx.foreign);
    });

    it('path ids must be UUIDs and lists refuse unknown parameters', async () => {
      const auth = await asUser(ALL);
      expect((await api.http().get(`${SRC}/nope`).set(auth)).status).toBe(400);
      const res = await api.http().get(`${SRC}?bogus=1`).set(auth);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('validation_failed');
    });
  });

  describe('creation (D1, ADR-0057)', () => {
    it('reveals the derived address once, stores only hashes, audits ids and replays redacted', async () => {
      const key = randomUUID();
      const body = {
        kind: 'google_workspace_copy',
        displayName: 'Second Google route',
        providerConnectionId: world.connections[1]!.publicId,
      };
      const res = await api
        .http()
        .post(SRC)
        .set(await asUser(ALL))
        .set('Idempotency-Key', key)
        .send(body);
      expect(res.status, JSON.stringify(res.body)).toBe(201);
      const id = res.body.source.id as string;
      const token = deriveIntakeAddressToken(secret, id, 1);
      const header = deriveIntakeHeaderToken(secret, id, 1);
      expect(res.body.address).toBe(`journal-${token}@${INTAKE_DOMAIN}`);
      expect(res.body.headerToken).toBe(header);
      expect(res.body.source).toMatchObject({
        status: 'pending_verification',
        revealed: false,
        address: `journal-••••${token.slice(-4)}@${INTAKE_DOMAIN}`,
        headerToken: `••••${header.slice(-4)}`,
        requireTls: true,
        silenceAlertMinutes: 240,
      });
      const stored = world.sources.find((s) => s.publicId === id)!;
      expect(stored.addressHash).toBe(intakeAddressHash(intakeLocalPart(token)));
      expect(stored.headerTokenHash).toBe(intakeHeaderTokenHash(header));
      const entry = audit.entries.find((e) => e.action === 'journal_intake.source_created')!;
      expect(entry).toMatchObject({ resourceType: 'journal_intake_source', resourceId: id });
      expect(JSON.stringify(entry.metadata)).not.toContain(token);
      // The stored idempotent response never holds the clear address or token.
      const row = [...store.rows.values()].find((r) => r.idempotencyKey === key)!;
      expect(JSON.stringify(row.response)).not.toContain(token);
      expect(JSON.stringify(row.response)).not.toContain(header);
      const replay = await api
        .http()
        .post(SRC)
        .set(await asUser(ALL))
        .set('Idempotency-Key', key)
        .send(body);
      expect(replay.status).toBe(201);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body).toMatchObject({ address: null, headerToken: null, source: { id } });
      const reused = await api
        .http()
        .post(SRC)
        .set(await asUser(ALL))
        .set('Idempotency-Key', key)
        .send({ ...body, displayName: 'Other' });
      expect(reused.status).toBe(422);
      expect(reused.body.code).toBe('idempotency_key_reused');
    });

    it('applies the kind-specific field rules (400)', async () => {
      const post = async (body: object) =>
        api
          .http()
          .post(SRC)
          .set(await asUser(ALL))
          .set('Idempotency-Key', randomUUID())
          .send(body);
      for (const body of [
        { kind: 'microsoft_365_journal', displayName: 'No connection' },
        { kind: 'smtp_bcc', displayName: 'No networks' },
        {
          kind: 'microsoft_365_journal',
          displayName: 'With networks',
          providerConnectionId: ctx.connection,
          networks: ['198.51.100.0/28'],
        },
        { kind: 'smtp_bcc', displayName: 'X', networks: ['198.51.100.0/28'], extra: true },
      ]) {
        const res = await post(body);
        expect(res.status, JSON.stringify(body)).toBe(400);
        expect(res.body.code).toBe('validation_failed');
      }
    });

    it('refuses networks overlapping a provider egress range, too broad or invalid (422)', async () => {
      const post = async (networks: string[]) =>
        api
          .http()
          .post(SRC)
          .set(await asUser(ALL))
          .set('Idempotency-Key', randomUUID())
          .send({ kind: 'exchange_onprem_journal', displayName: 'On-prem', networks });
      const overlap = await post(['198.51.100.0/28', '40.92.1.0/24']);
      expect(overlap.status).toBe(422);
      expect(overlap.body).toMatchObject({
        code: 'journal_intake_networks_invalid',
        issues: [{ code: 'provider_overlap', index: 1 }],
      });
      expect((await post(['8.0.0.0/8'])).body.issues).toEqual([{ code: 'too_broad', index: 0 }]);
      expect((await post(['198.51.100.1/28'])).body.issues).toEqual([
        { code: 'host_bits_set', index: 0 },
      ]);
      expect(JSON.stringify((await post(['nonsense!'])).body)).not.toContain('nonsense');
    });

    it('refuses a connection of another provider, another tenant, disabled or unbound (422)', async () => {
      const foreign = world.addConnection(OTHER_ORG);
      const disabled = world.addConnection(org, { status: 'disabled' });
      const unbound = world.addConnection(org, { activeTenantKey: null, status: 'configuring' });
      const cases: Array<[string, string]> = [
        [world.connections[1]!.publicId, 'provider_mismatch'],
        [foreign.publicId, 'not_found'],
        [disabled.publicId, 'disabled'],
        [unbound.publicId, 'tenant_not_bound'],
        [randomUUID(), 'not_found'],
      ];
      for (const [connectionId, reason] of cases) {
        const res = await api
          .http()
          .post(SRC)
          .set(await asUser(ALL))
          .set('Idempotency-Key', randomUUID())
          .send({
            kind: 'microsoft_365_journal',
            displayName: `M365 ${reason}`,
            providerConnectionId: connectionId,
          });
        expect(res.status, reason).toBe(422);
        expect(res.body).toMatchObject({ code: 'journal_intake_connection_invalid', reason });
      }
    });

    it('needs the entitlement, archiving with a default policy, a verified domain, a free name and a free slot', async () => {
      const post = async (displayName: string) =>
        api
          .http()
          .post(SRC)
          .set(await asUser(ALL))
          .set('Idempotency-Key', randomUUID())
          .send({ kind: 'smtp_bcc', displayName, networks: ['198.51.100.16/28'] });
      archive.intakeEntitled.delete(org);
      expect((await post('A')).body.code).toBe('journal_intake_not_enabled');
      archive.intakeEntitled.add(org);
      archive.settings.get(org)!.enabled = false;
      const off = await post('B');
      expect(off.status).toBe(409);
      expect(off.body.code).toBe('archiving_not_enabled');
      archive.settings.get(org)!.enabled = true;
      const domains = world.domains;
      world.domains = [];
      const noDomain = await post('C');
      expect(noDomain.status).toBe(409);
      expect(noDomain.body).toMatchObject({
        code: 'journal_intake_domain_required',
        reason: 'no_verified_domain',
      });
      world.domains = domains;
      expect((await post('Contoso Microsoft 365')).body.code).toBe(
        'journal_intake_source_name_taken',
      );
      for (let i = world.sources.filter((s) => s.organizationId === org).length; i < 20; i += 1) {
        expect((await post(`Fill ${i}`)).status).toBe(201);
      }
      const limit = await post('Over the limit');
      expect(limit.status).toBe(409);
      expect(limit.body).toMatchObject({ code: 'journal_intake_source_limit', limit: 20 });
    });
  });

  describe('reveal, rotation and changes', () => {
    it('masks the address; ?reveal=true needs journal:manage and is audited before the response', async () => {
      const masked = await api
        .http()
        .get(`${SRC}/${ctx.source}`)
        .set(await asUser([JREAD]));
      expect(masked.status).toBe(200);
      const token = deriveIntakeAddressToken(secret, ctx.source, 1);
      expect(masked.body).toMatchObject({ revealed: false, counters: [] });
      expect(masked.body.address).not.toContain(token);
      const refused = await api
        .http()
        .get(`${SRC}/${ctx.source}?reveal=true`)
        .set(await asUser([JREAD]));
      expect(refused.status).toBe(403);
      expect(audit.entries).toHaveLength(0);
      const revealed = await api
        .http()
        .get(`${SRC}/${ctx.source}?reveal=true`)
        .set(await asUser([JREAD, JMANAGE]));
      expect(revealed.body).toMatchObject({
        revealed: true,
        address: `journal-${token}@${INTAKE_DOMAIN}`,
      });
      expect(audit.entries.map((e) => [e.action, e.metadata?.via])).toEqual([
        ['journal_intake.address_revealed', 'detail'],
      ]);
    });

    it('rotation moves the current hashes to previous with the overlap and reveals the new address once', async () => {
      const before = { ...world.sources.find((s) => s.publicId === ctx.google)! };
      const key = randomUUID();
      const res = await api
        .http()
        .post(`${SRC}/${ctx.google}/rotate-address`)
        .set(await asUser(ALL))
        .set('Idempotency-Key', key);
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      const token = deriveIntakeAddressToken(secret, ctx.google, 2);
      expect(res.body.address).toBe(`journal-${token}@${INTAKE_DOMAIN}`);
      expect(res.body.headerToken).toBe(deriveIntakeHeaderToken(secret, ctx.google, 2));
      const after = world.sources.find((s) => s.publicId === ctx.google)!;
      expect(after).toMatchObject({
        addressVersion: 2,
        addressHash: intakeAddressHash(intakeLocalPart(token)),
        previousAddressHash: before.addressHash,
        previousHeaderTokenHash: before.headerTokenHash,
      });
      const overlap = after.previousValidUntil!.getTime() - Date.now();
      expect(overlap).toBeGreaterThan(6.9 * 86_400_000);
      expect(overlap).toBeLessThanOrEqual(7 * 86_400_000);
      expect(res.body.source.previousAddressValidUntil).toBe(
        after.previousValidUntil!.toISOString(),
      );
      const entry = audit.entries.find((e) => e.action === 'journal_intake.address_rotated')!;
      expect(entry.metadata).toMatchObject({ fromVersion: 1, toVersion: 2, overlapDays: 7 });
      expect(JSON.stringify(entry.metadata)).not.toContain(token);
      const replay = await api
        .http()
        .post(`${SRC}/${ctx.google}/rotate-address`)
        .set(await asUser(ALL))
        .set('Idempotency-Key', key);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body).toMatchObject({ address: null, headerToken: null });
      expect(world.sources.find((s) => s.publicId === ctx.google)!.addressVersion).toBe(2);
    });

    it('PATCH applies CAS, pauses and resumes (re-checking the rules) and audits each', async () => {
      const patch = async (body: object) =>
        api
          .http()
          .patch(`${SRC}/${ctx.source}`)
          .set(await asUser(ALL))
          .set('Idempotency-Key', randomUUID())
          .send(body);
      const stale = await patch({ expectedRowVersion: 9, status: 'paused' });
      expect(stale.status).toBe(409);
      expect(stale.body).toMatchObject({
        code: 'journal_intake_source_conflict',
        currentRowVersion: 1,
      });
      const paused = await patch({ expectedRowVersion: 1, status: 'paused' });
      expect(paused.body).toMatchObject({ status: 'paused', rowVersion: 2 });
      archive.intakeEntitled.delete(org);
      expect((await patch({ expectedRowVersion: 2, status: 'active' })).body.code).toBe(
        'journal_intake_not_enabled',
      );
      archive.intakeEntitled.add(org);
      const resumed = await patch({ expectedRowVersion: 2, status: 'active' });
      expect(resumed.body).toMatchObject({ status: 'pending_verification', rowVersion: 3 });
      const networks = await patch({ expectedRowVersion: 3, networks: ['198.51.100.0/28'] });
      expect(networks.status).toBe(400);
      expect(audit.entries.map((e) => e.action)).toEqual([
        'journal_intake.source_paused',
        'journal_intake.source_resumed',
      ]);
    });

    it('DELETE disables for good; a disabled source cannot change', async () => {
      const auth = await asUser(ALL);
      const first = await api.http().delete(`${SRC}/${ctx.source}`).set(auth);
      expect(first.body).toMatchObject({ status: 'disabled' });
      expect(first.body.disabledAt).not.toBeNull();
      const again = await api.http().delete(`${SRC}/${ctx.source}`).set(auth);
      expect(again.status).toBe(200);
      expect(
        audit.entries.filter((e) => e.action === 'journal_intake.source_disabled'),
      ).toHaveLength(1);
      const rotate = await api
        .http()
        .post(`${SRC}/${ctx.source}/rotate-address`)
        .set(auth)
        .set('Idempotency-Key', randomUUID());
      expect(rotate.status).toBe(409);
      expect(rotate.body.code).toBe('journal_intake_source_disabled');
      const attest = await api
        .http()
        .post(`${SRC}/${ctx.source}/attestations`)
        .set(auth)
        .send(JOURNALING_EXAMPLES.attestation);
      expect(attest.body.code).toBe('journal_intake_source_disabled');
    });

    it('attestations accept only codes of the kind and feed the wizard', async () => {
      const auth = await asUser(ALL);
      const wrong = await api
        .http()
        .post(`${SRC}/${ctx.source}/attestations`)
        .set(auth)
        .send({ code: 'journal.google.route_created', attested: true });
      expect(wrong.status).toBe(422);
      expect(wrong.body.code).toBe('journal_intake_attestation_unknown');
      const before = await api.http().get(`${SRC}/${ctx.source}/wizard`).set(auth);
      expect(before.body.missingAttestations).toEqual([
        'journal.m365.rule_created',
        'journal.m365.ndr_mailbox_set',
      ]);
      for (const code of before.body.missingAttestations as string[]) {
        const res = await api
          .http()
          .post(`${SRC}/${ctx.source}/attestations`)
          .set(auth)
          .send({ code, attested: true });
        expect(res.status).toBe(200);
      }
      const wizard = await api.http().get(`${SRC}/${ctx.source}/wizard`).set(auth);
      expect(wizard.body.steps.map((s: { status: string }) => s.status)).toEqual([
        'done',
        'done',
        'done',
        'done',
        'in_progress',
        'blocked',
      ]);
      expect(wizard.body.nextAction).toEqual({ step: 'verify', action: 'send_first_message' });
    });
  });

  describe('guide, settings and status', () => {
    it('the guide is masked for readers, revealed (and audited) for managers, and renders Markdown', async () => {
      const token = deriveIntakeAddressToken(secret, ctx.source, 1);
      const reader = await api
        .http()
        .get(`${SRC}/${ctx.source}/setup-guide`)
        .set(await asUser([JREAD]));
      expect(reader.status).toBe(200);
      expect(reader.body).toMatchObject({ schema: 'journal-intake-guide/1', revealed: false });
      expect(JSON.stringify(reader.body)).not.toContain(token);
      expect(audit.entries).toHaveLength(0);
      const manager = await api
        .http()
        .get(`${SRC}/${ctx.source}/setup-guide`)
        .set(await asUser(ALL));
      expect(JSON.stringify(manager.body)).toContain(token);
      expect(audit.entries.map((e) => e.metadata?.via)).toEqual(['guide']);
      const md = await api
        .http()
        .get(`${SRC}/${ctx.source}/setup-guide`)
        .set(await asUser([JREAD]))
        .set('Accept', 'text/markdown');
      expect(md.headers['content-type']).toMatch(/^text\/markdown/);
      expect(md.headers['content-disposition']).toMatch(/attachment; filename=".+\.md"/);
      expect(md.text).toContain('# Journal intake setup guide');
      const query = await api
        .http()
        .get(`${SRC}/${ctx.source}/setup-guide?format=markdown`)
        .set(await asUser([JREAD]));
      expect(query.headers['content-type']).toMatch(/^text\/markdown/);
    });

    it('PUT /journaling/settings writes the shared row, keeps access and audits area journaling', async () => {
      archive.setSettings(org, {
        enabled: true,
        defaultRetentionPolicyId: archive.policies[0]!.id,
        rowVersion: 2,
        settings: { access: { previewEnabled: false, downloadEnabled: true } },
      });
      const res = await api
        .http()
        .put(`${BASE}/settings`)
        .set(await asUser([JMANAGE]))
        .set('Idempotency-Key', randomUUID())
        .send({ expectedRowVersion: 2, settings: { intake: { scanEnabled: true } } });
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body).toMatchObject({
        rowVersion: 3,
        settings: { intake: { scanEnabled: true } },
        intakeEntitled: true,
        intakeAvailable: true,
      });
      expect(res.body.settings).not.toHaveProperty('access');
      const archiveView = await api
        .http()
        .get('/api/v1/archive/settings')
        .set(await asUser([JREAD]));
      expect(archiveView.body).toMatchObject({
        rowVersion: 3,
        settings: {
          access: { previewEnabled: false, downloadEnabled: true },
          intake: { scanEnabled: true },
        },
      });
      const entry = audit.entries.find((e) => e.action === 'archive.settings_updated')!;
      expect(entry.metadata).toMatchObject({
        area: 'journaling',
        settingsPaths: ['settings.intake'],
      });
      const stale = await api
        .http()
        .put(`${BASE}/settings`)
        .set(await asUser([JMANAGE]))
        .set('Idempotency-Key', randomUUID())
        .send({ expectedRowVersion: 2, enabled: false });
      expect(stale.status).toBe(409);
      expect(stale.body).toMatchObject({ code: 'archive_settings_conflict', currentRowVersion: 3 });
      const unknown = await api
        .http()
        .put(`${BASE}/settings`)
        .set(await asUser([JMANAGE]))
        .set('Idempotency-Key', randomUUID())
        .send({ expectedRowVersion: 3, settings: { access: { downloadEnabled: false } } });
      expect(unknown.status).toBe(400);
    });

    it('the status counts intents, sources and today’s intake', async () => {
      const today = new Date(new Date().toISOString().slice(0, 10));
      const source = world.sources.find((s) => s.publicId === ctx.source)!;
      world.counters.push({
        organizationId: org,
        sourceId: source.id,
        day: today,
        accepted: 12,
        duplicates: 1,
        bytes: 4096n,
        refusedAddress: 0,
        refusedNetwork: 2,
        refusedTls: 0,
        refusedSize: 1,
        refusedRate: 0,
        refusedUnavailable: 0,
        droppedProof: 3,
        unwrapFailed: 0,
      });
      world.intents.push({ organizationId: org, status: 'pending', createdAt: new Date() });
      const res = await api
        .http()
        .get(`${BASE}/status`)
        .set(await asUser([JREAD]));
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({
        settings: { enabled: true, intakeEntitled: true, intakeAvailable: true },
        capture: { pending: 1 },
        sources: {
          total: 2,
          byStatus: { pending_verification: 2, active: 0, paused: 0, disabled: 0 },
          byHealth: { unknown: 2 },
        },
        intakeToday: { accepted: 12, duplicates: 1, bytes: 4096, refused: 3, droppedProof: 3 },
      });
      const detail = await api
        .http()
        .get(`${SRC}/${ctx.source}`)
        .set(await asUser([JREAD]));
      expect(detail.body.counters).toEqual([
        expect.objectContaining({ day: today.toISOString().slice(0, 10), accepted: 12 }),
      ]);
    });
  });
});

describe('journaling routes without an intake domain (D1: intake off)', () => {
  let api: StubbedApiApp;
  const archive = new ArchiveWorld();
  const world = new JournalingWorld();
  const audit = new RecordingAuditService();
  const store = new InMemoryIdempotencyStore();

  beforeAll(async () => {
    api = await createStubbedApiApp(
      { JOURNAL_INTAKE_DOMAIN: '', JOURNAL_INTAKE_ADDRESS_SECRET: '' },
      {
        override: (b) =>
          store.override(overrideJournaling(overrideArchive(b, archive, audit), world)),
      },
    );
  });

  afterAll(async () => {
    await api?.close();
  });

  it('creation answers 503 journal_intake_unavailable and settings say so', async () => {
    const auth = await api.principals.user(ALL, { mfaAuthenticated: true }).bearer();
    const res = await api
      .http()
      .post(SRC)
      .set(auth)
      .set('Idempotency-Key', randomUUID())
      .send({ kind: 'smtp_bcc', displayName: 'Relay', networks: ['198.51.100.0/28'] });
    expect(res.status).toBe(503);
    expect(res.body.code).toBe('journal_intake_unavailable');
    const settings = await api.http().get(`${BASE}/settings`).set(auth);
    expect(settings.body).toMatchObject({ intakeAvailable: false });
  });
});
