/**
 * The step API-2 API-mode remediation routes (docs/plan/steps/36-api-mode-remediation.md R12,
 * R13, §9.4) over HTTP with MySQL, Redis and S3 stubbed: the API-mode and remediation
 * repositories and the action-row writer through `ApiModeWorld`, the quarantine repositories
 * through `QuarantineWorld` (the restore of a quarantined copy delegates to the quarantine
 * release), the Idempotency-Key store and the audit in memory. For every operation: success,
 * 401, 403 without its permission (a read-only user on every write), API keys, 404 for another
 * organization's ids; then Idempotency-Key replay and reuse, the policy CAS and hard-delete
 * refusals, the R12 rules, the delegation (`quarantine:release` 403, the `restore_inbox` row, no
 * `release_requested` outbox event), v1 cursors and filters, provider ids never returned, and the
 * API-1 additions (detection fields and filter, overview block, the pause switch). The real
 * writer and replica run in integration/api-mode-remediation.test.ts.
 */
// @covers get /api/v1/api-mode/remediation-policy
// @covers put /api/v1/api-mode/remediation-policy
// @covers put /api/v1/api-mode/remediation-policy/domains/:domainId
// @covers delete /api/v1/api-mode/remediation-policy/domains/:domainId
// @covers get /api/v1/api-mode/remediations
// @covers get /api/v1/api-mode/remediations/:remediationId
// @covers post /api/v1/api-mode/remediations/:remediationId/retry
// @covers post /api/v1/api-mode/detections/:detectionId/remediate
// @covers post /api/v1/api-mode/detections/:detectionId/restore
import { randomUUID } from 'node:crypto';
import { DEFAULT_REMEDIATION_POLICY } from '@email-gateway/mailbox-api';
import { EventTypes } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AuditService } from '../src/audit/audit.service';
import { REMEDIATION_EXAMPLES } from '../src/modules/api-mode/dto/api-mode-remediation.schemas';
import {
  ApiModeWorld,
  overrideApiMode,
  type StoredConnection,
  type StoredCopy,
  type StoredMailbox,
} from './support/api-mode-fixtures';
import {
  createStubbedApiApp,
  InMemoryIdempotencyStore,
  type StubbedApiApp,
} from './support/api-test-app';
import { overrideQuarantineWorld, QuarantineWorld } from './support/in-memory-quarantine';
import { RecordingAuditService } from './support/messages-fixtures';

const READ = 'remediation:read';
const WRITE = 'remediation:write';
const RELEASE = 'quarantine:release';
const ALL = [READ, WRITE];
const BASE = '/api/v1/api-mode';
const OTHER_ORG = 2n;
const P1 = structuredClone(DEFAULT_REMEDIATION_POLICY.document);
const REASON = 'Tighten the policy for the pilot';

type Method = 'get' | 'post' | 'put' | 'delete';

interface Ctx {
  domain: string;
  foreignDomain: string;
  clean: string;
  tagged: string;
  quarantined: string;
  entry: string;
  failed: string;
  succeeded: string;
  foreignDetection: string;
  foreignRemediation: string;
}

interface Spec {
  id: string;
  method: Method;
  path: (c: Ctx) => string;
  perm: string;
  keyed?: boolean;
  body?: (c: Ctx) => object;
  ok: number;
}

const policyBody = (patch: Record<string, unknown> = {}) => ({
  mode: 'detect_only',
  document: P1,
  reason: REASON,
  expectedRowVersion: null,
  ...patch,
});

const SPECS: Spec[] = [
  { id: 'policy', method: 'get', path: () => `${BASE}/remediation-policy`, perm: READ, ok: 200 },
  {
    id: 'putPolicy',
    method: 'put',
    path: () => `${BASE}/remediation-policy`,
    perm: WRITE,
    keyed: true,
    body: () => policyBody(),
    ok: 200,
  },
  {
    id: 'putDomainPolicy',
    method: 'put',
    path: (c) => `${BASE}/remediation-policy/domains/${c.domain}`,
    perm: WRITE,
    keyed: true,
    body: () => policyBody({ mode: 'enforce' }),
    ok: 200,
  },
  {
    id: 'deleteDomainPolicy',
    method: 'delete',
    path: (c) => `${BASE}/remediation-policy/domains/${c.domain}`,
    perm: WRITE,
    keyed: true,
    ok: 204,
  },
  { id: 'list', method: 'get', path: () => `${BASE}/remediations`, perm: READ, ok: 200 },
  {
    id: 'detail',
    method: 'get',
    path: (c) => `${BASE}/remediations/${c.succeeded}`,
    perm: READ,
    ok: 200,
  },
  {
    id: 'retry',
    method: 'post',
    path: (c) => `${BASE}/remediations/${c.failed}/retry`,
    perm: WRITE,
    keyed: true,
    ok: 202,
  },
  {
    id: 'remediate',
    method: 'post',
    path: (c) => `${BASE}/detections/${c.clean}/remediate`,
    perm: WRITE,
    keyed: true,
    body: () => ({ action: 'tag', reason: 'Confirmed by the analyst' }),
    ok: 202,
  },
  {
    id: 'restore',
    method: 'post',
    path: (c) => `${BASE}/detections/${c.tagged}/restore`,
    perm: WRITE,
    keyed: true,
    body: () => ({ reason: 'False positive' }),
    ok: 202,
  },
];

describe('API-mode remediation routes (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const world = new ApiModeWorld();
  const q = new QuarantineWorld();
  const audit = new RecordingAuditService();
  const store = new InMemoryIdempotencyStore();
  let org: bigint;
  let ctx: Ctx;
  let m365: StoredConnection;
  let mailbox: StoredMailbox;
  let copies: Record<string, StoredCopy>;

  beforeAll(async () => {
    api = await createStubbedApiApp(
      {},
      {
        override: (b) =>
          store.override(
            overrideQuarantineWorld(overrideApiMode(b, world), q)
              .overrideProvider(AuditService)
              .useValue(audit),
          ),
      },
    );
    org = api.principals.organizationId;
  });

  afterAll(async () => {
    await api?.close();
  });

  function seed(): Ctx {
    world.addOrganization(org, api.principals.ids.org);
    world.addOrganization(OTHER_ORG, randomUUID());
    world.entitled.add(org);
    m365 = world.addConnection(org, {
      displayName: 'Contoso Microsoft 365',
      grant: {
        profile: 'm365.mailbox_remediation',
        status: 'active',
        authMethod: 'platform_app',
        clientId: null,
        subjectEmail: null,
      },
    });
    m365.api = world.apiRow({ healthStatus: 'healthy' });
    const domain = world.addDomain(org, 'contoso.example', { connectionId: m365.id });
    const foreignDomain = world.addDomain(OTHER_ORG, 'other.example');
    mailbox = world.addMailbox(m365, 'alex@contoso.example');
    const foreignConnection = world.addConnection(OTHER_ORG, { displayName: 'Other' });
    const foreignMailbox = world.addMailbox(foreignConnection, 'eve@other.example');
    const clean = world.addCopy(mailbox, { receivedAt: new Date(Date.now() - 300_000) });
    const tagged = world.addCopy(mailbox, {
      verdict: 'suspicious',
      riskScore: 500,
      remediationState: 'remediated',
      remediationAction: 'tag',
      receivedAt: new Date(Date.now() - 240_000),
    });
    const tag = world.addAction(tagged, { action: 'tag' });
    tagged.lastActionId = tag.id;
    const quarantined = world.addCopy(mailbox, {
      verdict: 'phishing',
      riskScore: 950,
      remediationState: 'remediated',
      remediationAction: 'move_quarantine',
      receivedAt: new Date(Date.now() - 180_000),
    });
    const moved = world.addAction(quarantined, { action: 'move_quarantine' });
    quarantined.lastActionId = moved.id;
    // The copy's mailbox-located entry in the quarantine world, linked to the same copy.
    const entry = q.addMailboxEntry({ address: 'alex@contoso.example' });
    const qc = q.copies.at(-1)!;
    Object.assign(qc, {
      copyId: quarantined.id,
      copyReceivedAt: quarantined.receivedAt,
      copyPublicId: quarantined.publicId,
      apiConnectionId: quarantined.apiConnectionId,
      mailboxId: quarantined.mailboxId,
    });
    Object.assign(entry, {
      apiCopyId: quarantined.id,
      apiCopyReceivedAt: quarantined.receivedAt,
      apiRemediationActionId: moved.id,
    });
    Object.assign(
      q.entries.find((e) => e.id === entry.id)!,
      entry,
    );
    world.copyEntries.set(quarantined.id, { publicId: entry.publicId, state: 'held' });
    const failedCopy = world.addCopy(mailbox, {
      verdict: 'malware',
      remediationState: 'failed',
      remediationAction: 'move_junk',
      receivedAt: new Date(Date.now() - 120_000),
    });
    const failed = world.addAction(failedCopy, {
      action: 'move_junk',
      status: 'failed',
      attempts: 8,
      lastErrorCode: 'provider_unavailable',
      reasonCode: 'provider_unavailable',
    });
    const foreignDetection = world.addCopy(foreignMailbox);
    const foreignRemediation = world.addAction(foreignDetection);
    copies = { clean, tagged, quarantined, failedCopy };
    return {
      domain: domain.publicId,
      foreignDomain: foreignDomain.publicId,
      clean: clean.publicId,
      tagged: tagged.publicId,
      quarantined: quarantined.publicId,
      entry: entry.publicId,
      failed: failed.publicId,
      succeeded: moved.publicId,
      foreignDetection: foreignDetection.publicId,
      foreignRemediation: foreignRemediation.publicId,
    };
  }

  beforeEach(() => {
    world.reset();
    q.reset();
    audit.entries.length = 0;
    store.rows.clear();
    api.kv.entries.clear();
    api.principals.apiKeyWith([]);
    q.identities.set(10n, { email: 'operator@contoso.example', verified: true });
    ctx = seed();
  });

  const asUser = (permissions: string[]) => api.principals.user(permissions).bearer();

  async function send(
    spec: Spec,
    options: { perms?: string[] | null; apiKey?: string[]; key?: string; body?: object } = {},
  ) {
    const req = api.http()[spec.method](spec.path(ctx));
    if (options.apiKey) {
      api.principals.apiKeyWith(options.apiKey);
      req.set(api.principals.apiKeyHeaders);
    } else if (options.perms !== null) {
      req.set(await asUser(options.perms ?? ALL));
    }
    if (spec.keyed) req.set('Idempotency-Key', options.key ?? randomUUID());
    const body = options.body ?? spec.body?.(ctx);
    return body === undefined ? req : req.send(body);
  }

  const spec = (id: string) => SPECS.find((s) => s.id === id)!;

  describe('every operation (success, auth, RBAC)', () => {
    it.each(SPECS.map((s) => [s.id, s] as const))(
      '%s succeeds with its permission',
      async (_id, s) => {
        const res = await send(s, { perms: [s.perm] });
        expect(res.status, JSON.stringify(res.body)).toBe(s.ok);
      },
    );

    it.each(SPECS.map((s) => [s.id, s] as const))(
      '%s answers 401 without credentials',
      async (_id, s) => {
        expect((await send(s, { perms: null })).status).toBe(401);
      },
    );

    it.each(SPECS.map((s) => [s.id, s] as const))(
      '%s answers 403 without its permission',
      async (_id, s) => {
        const res = await send(s, { perms: ALL.filter((p) => p !== s.perm) });
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('forbidden');
      },
    );

    it('a read-only user (the tenant read set) is refused every write and reads every view', async () => {
      const readOnly = [READ, 'organization:read', 'domain:read', 'quarantine:read'];
      for (const s of SPECS) {
        const res = await send(s, { perms: readOnly });
        if (s.method === 'get') expect(res.status, s.id).toBe(s.ok);
        else expect(res.status, s.id).toBe(403);
      }
      expect(world.actions.filter((a) => a.trigger === 'admin')).toHaveLength(0);
      expect(world.policies).toHaveLength(0);
    });

    it('API keys with remediation:* use the remediation routes', async () => {
      for (const s of SPECS) {
        world.reset();
        q.reset();
        store.rows.clear();
        ctx = seed();
        const res = await send(s, { apiKey: [READ, WRITE] });
        expect(res.status, `${s.id} ${JSON.stringify(res.body)}`).toBe(s.ok);
      }
    });

    it('another organization’s ids answer 404 like unknown ids (tenant from the credential)', async () => {
      const cases: Array<[Method, string, string, object?]> = [
        [
          'put',
          `${BASE}/remediation-policy/domains/${ctx.foreignDomain}`,
          'domain_not_found',
          policyBody(),
        ],
        ['delete', `${BASE}/remediation-policy/domains/${ctx.foreignDomain}`, 'domain_not_found'],
        ['get', `${BASE}/remediations/${ctx.foreignRemediation}`, 'api_mode_remediation_not_found'],
        ['get', `${BASE}/remediations/${randomUUID()}`, 'api_mode_remediation_not_found'],
        [
          'post',
          `${BASE}/remediations/${ctx.foreignRemediation}/retry`,
          'api_mode_remediation_not_found',
        ],
        [
          'post',
          `${BASE}/detections/${ctx.foreignDetection}/remediate`,
          'api_mode_detection_not_found',
          { action: 'tag', reason: 'x' },
        ],
        [
          'post',
          `${BASE}/detections/${ctx.foreignDetection}/restore`,
          'api_mode_detection_not_found',
          { reason: 'x' },
        ],
      ];
      for (const [method, path, code, body] of cases) {
        const req = api
          .http()
          [method](path)
          .set(await asUser(ALL));
        if (method !== 'get') req.set('Idempotency-Key', randomUUID());
        const res = await (body ? req.send(body) : req);
        expect(res.status, path).toBe(404);
        expect(res.body.code, path).toBe(code);
      }
      const list = await api
        .http()
        .get(`${BASE}/remediations`)
        .set(await asUser(ALL));
      expect(list.body.data.map((r: { id: string }) => r.id)).not.toContain(ctx.foreignRemediation);
      expect(world.actions.filter((a) => a.organizationId === OTHER_ORG)[0]!.status).toBe(
        'succeeded',
      );
    });

    it('a bad id is 400 before any read', async () => {
      const res = await api
        .http()
        .get(`${BASE}/remediations/not-a-uuid`)
        .set(await asUser(ALL));
      expect(res.status).toBe(400);
    });
  });

  describe('policy (R13 #1-#4)', () => {
    it('GET shows the platform default, presets and hard delete unavailable', async () => {
      const res = await send(spec('policy'));
      expect(res.body.organization).toMatchObject({
        source: 'platform_default',
        id: null,
        mode: 'enforce',
        rowVersion: null,
      });
      expect(Object.keys(res.body.presets).sort()).toEqual(['detectOnlyStart', 'p1', 'strict']);
      expect(res.body.hardDeleteAvailable).toBe(false);
      expect(res.headers['cache-control']).toBeDefined();
    });

    it('PUT: create (null), CAS 409 with the current version, replay with the header, key reuse 422', async () => {
      const key = randomUUID();
      const first = await send(spec('putPolicy'), { key });
      expect(first.status).toBe(200);
      expect(first.body).toMatchObject({ scope: 'organization', rowVersion: 1, created: true });
      const replay = await send(spec('putPolicy'), { key });
      expect(replay.status).toBe(200);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body).toEqual(first.body);
      const reuse = await send(spec('putPolicy'), {
        key,
        body: policyBody({ mode: 'enforce' }),
      });
      expect(reuse.status).toBe(422);
      expect(reuse.body.code).toBe('idempotency_key_reused');
      const stale = await send(spec('putPolicy'));
      expect(stale.status).toBe(409);
      expect(stale.body).toMatchObject({
        code: 'api_mode_remediation_policy_conflict',
        currentRowVersion: 1,
      });
      const next = await send(spec('putPolicy'), {
        body: policyBody({ mode: 'enforce', expectedRowVersion: 1 }),
      });
      expect(next.body).toMatchObject({ rowVersion: 2, mode: 'enforce', created: false });
      const updates = audit.entries.filter(
        (e) => e.action === 'api_mode.remediation_policy_updated',
      );
      expect(updates).toHaveLength(2);
      expect(updates[1]!.metadata).toMatchObject({
        from: { mode: 'detect_only' },
        to: { mode: 'enforce' },
        reason: REASON,
      });
      const get = await send(spec('policy'));
      expect(get.body.organization).toMatchObject({ source: 'organization', rowVersion: 2 });
    });

    it('validation: strict body, document paths, hard_delete refused (422), reserved key', async () => {
      const cases: Array<[object, number, string?]> = [
        [policyBody({ extra: 1 }), 400],
        [policyBody({ document: { ...P1, v: 2 } }), 400],
        [policyBody({ expectedRowVersion: undefined }), 400],
        [
          policyBody({
            document: {
              v: 1,
              rules: [
                { id: 'r', when: { verdicts: ['spam'], policyDispositions: [] }, action: 'tag' },
              ],
            },
          }),
          400,
        ],
        [
          policyBody({
            document: {
              v: 1,
              rules: [{ id: 'nuke', when: { verdicts: ['malware'] }, action: 'hard_delete' }],
            },
          }),
          422,
          'api_mode_hard_delete_disabled',
        ],
      ];
      for (const [body, status, code] of cases) {
        const res = await send(spec('putPolicy'), { body });
        expect(res.status, JSON.stringify(body)).toBe(status);
        if (code) expect(res.body).toMatchObject({ code, ruleIds: 'nuke' });
      }
      const res = await send(spec('putPolicy'), {
        body: policyBody({ document: { v: 1, rules: [] } }),
      });
      expect(res.body.code).toBe('validation_failed');
      expect(JSON.stringify(res.body.message)).toContain('document.rules');
      // Missing Idempotency-Key: 400 before anything else.
      const noKey = await api
        .http()
        .put(`${BASE}/remediation-policy`)
        .set(await asUser(ALL))
        .send(policyBody());
      expect(noKey.status).toBe(400);
      expect(noKey.body.code).toBe('idempotency_key_required');
      expect(world.policies).toHaveLength(0);
    });

    it('domain override: PUT, listed with its name, DELETE back to inheriting (204, no-op 204)', async () => {
      expect((await send(spec('putDomainPolicy'))).status).toBe(200);
      const get = await send(spec('policy'));
      expect(get.body.domains).toEqual([
        expect.objectContaining({ domainId: ctx.domain, domainName: 'contoso.example' }),
      ]);
      const del = await send(spec('deleteDomainPolicy'));
      expect(del.status).toBe(204);
      expect(del.text).toBe('');
      expect((await send(spec('policy'))).body.domains).toEqual([]);
      expect((await send(spec('deleteDomainPolicy'))).status).toBe(204);
      expect(
        audit.entries.filter((e) => e.action === 'api_mode.remediation_policy_updated'),
      ).toHaveLength(2);
    });
  });

  describe('history (R13 #5, #6)', () => {
    it('v1 cursor pages, filters, the cursor bound to its filters, provider ids never returned', async () => {
      const first = await api
        .http()
        .get(`${BASE}/remediations`)
        .query({ limit: '2' })
        .set(await asUser(ALL));
      expect(first.status).toBe(200);
      expect(first.body.data).toHaveLength(2);
      expect(first.body.nextCursor).toEqual(expect.any(String));
      const second = await api
        .http()
        .get(`${BASE}/remediations`)
        .query({ limit: '2', cursor: first.body.nextCursor })
        .set(await asUser(ALL));
      expect(second.body.data).toHaveLength(1);
      expect(second.body.nextCursor).toBeNull();
      const other = await api
        .http()
        .get(`${BASE}/remediations`)
        .query({ limit: '2', status: 'failed', cursor: first.body.nextCursor })
        .set(await asUser(ALL));
      expect(other.status).toBe(400);
      const failed = await api
        .http()
        .get(`${BASE}/remediations`)
        .query({ status: 'failed', detectionId: copies.failedCopy!.publicId })
        .set(await asUser(ALL));
      expect(failed.body.data.map((r: { id: string }) => r.id)).toEqual([ctx.failed]);
      const detail = await send(spec('detail'));
      expect(detail.body).toMatchObject({
        id: ctx.succeeded,
        action: 'move_quarantine',
        trigger: 'policy',
        providerRefs: { container: 'quarantine_folder', before: 1, after: 1 },
        mailbox: { address: 'alex@contoso.example' },
      });
      const text = JSON.stringify([first.body, second.body, detail.body]);
      expect(text).not.toContain('provider-id');
      expect(text).not.toMatch(/AAMk/);
      // The documented example is valid against the view schema (spot check of the shape).
      expect(Object.keys(detail.body).sort()).toEqual(
        Object.keys(REMEDIATION_EXAMPLES.remediationDetail).sort(),
      );
    });
  });

  describe('manual requests (R12)', () => {
    it('remediate: 202 pending admin row, copy pending, audit; replay; in progress; already applied', async () => {
      const key = randomUUID();
      const res = await send(spec('remediate'), { key });
      expect(res.status).toBe(202);
      expect(res.body.remediation).toMatchObject({
        action: 'tag',
        trigger: 'admin',
        status: 'pending',
        detectionId: ctx.clean,
      });
      expect(copies.clean).toMatchObject({ remediationState: 'pending', remediationAction: 'tag' });
      expect(audit.entries.at(-1)).toMatchObject({ action: 'api_mode.remediation_requested' });
      const replay = await send(spec('remediate'), { key });
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body).toEqual(res.body);
      expect(world.actions.filter((a) => a.trigger === 'admin')).toHaveLength(1);
      const busy = await send(spec('remediate'));
      expect(busy.status).toBe(409);
      expect(busy.body.code).toBe('api_mode_remediation_in_progress');
      const applied = await api
        .http()
        .post(`${BASE}/detections/${ctx.tagged}/remediate`)
        .set(await asUser(ALL))
        .set('Idempotency-Key', randomUUID())
        .send({ action: 'tag', reason: 'again' });
      expect(applied.status).toBe(409);
      expect(applied.body).toMatchObject({
        code: 'api_mode_remediation_already_applied',
        action: 'tag',
      });
    });

    it('remediate: hard delete 422, invalid action 400, no grant 409', async () => {
      const hard = await send(spec('remediate'), {
        body: { action: 'hard_delete', reason: 'x' },
      });
      expect(hard.status).toBe(422);
      expect(hard.body.code).toBe('api_mode_hard_delete_not_manual');
      expect(
        (await send(spec('remediate'), { body: { action: 'none', reason: 'x' } })).status,
      ).toBe(400);
      mailbox.grantActive = false;
      const noGrant = await send(spec('remediate'));
      expect(noGrant.status).toBe(409);
      expect(noGrant.body.code).toBe('api_mode_mailbox_access_required');
      expect(world.actions.filter((a) => a.trigger === 'admin')).toHaveLength(0);
    });

    it('restore of a tag: remove_tag row reversing it; nothing in effect 409', async () => {
      const res = await send(spec('restore'));
      expect(res.status).toBe(202);
      expect(res.body).toMatchObject({
        detectionId: ctx.tagged,
        via: 'mailbox_action',
        release: null,
        remediation: { action: 'remove_tag', status: 'pending' },
      });
      const nothing = await api
        .http()
        .post(`${BASE}/detections/${ctx.clean}/restore`)
        .set(await asUser(ALL))
        .set('Idempotency-Key', randomUUID())
        .send({ reason: 'x' });
      expect(nothing.status).toBe(409);
      expect(nothing.body).toMatchObject({
        code: 'api_mode_nothing_to_restore',
        remediationState: 'none',
      });
    });

    it('restore of a quarantined copy delegates to the quarantine release: 403 without quarantine:release, then the restore_inbox row and no release_requested event', async () => {
      const path = `${BASE}/detections/${ctx.quarantined}/restore`;
      const denied = await api
        .http()
        .post(path)
        .set(await asUser(ALL))
        .set('Idempotency-Key', randomUUID())
        .send({ reason: 'False positive' });
      expect(denied.status).toBe(403);
      expect(denied.body.code).toBe('quarantine_permission_required');
      expect(q.entries.find((e) => e.publicId === ctx.entry)!.state).toBe('held');
      const key = randomUUID();
      const ok = await api
        .http()
        .post(path)
        .set(await asUser([...ALL, RELEASE]))
        .set('Idempotency-Key', key)
        .send({ reason: 'False positive' });
      expect(ok.status, JSON.stringify(ok.body)).toBe(202);
      expect(ok.body).toMatchObject({
        detectionId: ctx.quarantined,
        via: 'quarantine_release',
        remediation: null,
        release: { outcome: 'queued', entryId: ctx.entry, state: 'releasing' },
      });
      expect(q.entries.find((e) => e.publicId === ctx.entry)!.state).toBe('releasing');
      expect(q.releases).toHaveLength(1);
      expect(
        q.outbox.filter((o) => o.eventType === EventTypes.QuarantineReleaseRequested),
      ).toHaveLength(0);
      const restore = world.actions.find((a) => a.action === 'restore_inbox')!;
      expect(restore).toMatchObject({
        trigger: 'release',
        status: 'pending',
        copyId: copies.quarantined!.id,
        reversesActionId: copies.quarantined!.lastActionId,
      });
      expect(audit.entries.map((e) => e.action)).toEqual(
        expect.arrayContaining(['quarantine.release_requested', 'api_mode.restore_requested']),
      );
      const replay = await api
        .http()
        .post(path)
        .set(await asUser([...ALL, RELEASE]))
        .set('Idempotency-Key', key)
        .send({ reason: 'False positive' });
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body).toEqual(ok.body);
      expect(world.actions.filter((a) => a.action === 'restore_inbox')).toHaveLength(1);
    });

    it('restore of a hard-blocked quarantined copy: approval requested (a second approver); hard delete is never restorable', async () => {
      Object.assign(
        q.entries.find((e) => e.publicId === ctx.entry)!,
        { hasHardBlock: true },
      );
      const res = await api
        .http()
        .post(`${BASE}/detections/${ctx.quarantined}/restore`)
        .set(await asUser([...ALL, RELEASE]))
        .set('Idempotency-Key', randomUUID())
        .send({ reason: 'False positive' });
      expect(res.status).toBe(202);
      expect(res.body.release).toMatchObject({
        outcome: 'approval_requested',
        approvalReasons: ['hard_block'],
      });
      expect(world.actions.filter((a) => a.action === 'restore_inbox')).toHaveLength(0);
      const hard = world.addCopy(mailbox, {
        remediationState: 'remediated',
        remediationAction: 'hard_delete',
      });
      const refused = await api
        .http()
        .post(`${BASE}/detections/${hard.publicId}/restore`)
        .set(await asUser([...ALL, RELEASE]))
        .set('Idempotency-Key', randomUUID())
        .send({ reason: 'x' });
      expect(refused.status).toBe(409);
      expect(refused.body).toMatchObject({
        code: 'api_mode_restore_not_possible',
        cause: 'hard_delete',
      });
    });

    it('retry: failed → pending (202), not retryable twice (409 with the status)', async () => {
      const res = await send(spec('retry'));
      expect(res.status).toBe(202);
      expect(res.body).toMatchObject({ id: ctx.failed, status: 'pending', attempts: 0 });
      const again = await send(spec('retry'));
      expect(again.status).toBe(409);
      expect(again.body).toMatchObject({
        code: 'api_mode_remediation_not_retryable',
        cause: 'pending',
      });
      expect(
        audit.entries.filter((e) => e.action === 'api_mode.remediation_retry_requested'),
      ).toHaveLength(1);
    });
  });

  describe('API-1 additions (R13)', () => {
    it('detections carry the remediation fields and filter by remediation state', async () => {
      const list = await api
        .http()
        .get(`${BASE}/detections`)
        .query({ remediationState: 'remediated' })
        .set(await asUser(ALL));
      expect(list.status).toBe(200);
      expect(list.body.data.map((d: { id: string }) => d.id).sort()).toEqual(
        [ctx.tagged, ctx.quarantined].sort(),
      );
      const detail = await api
        .http()
        .get(`${BASE}/detections/${ctx.quarantined}`)
        .set(await asUser(ALL));
      expect(detail.body).toMatchObject({
        remediationState: 'remediated',
        remediationAction: 'move_quarantine',
        remediationId: ctx.succeeded,
        quarantineEntryId: ctx.entry,
      });
    });

    it('the overview and the connection carry the remediation block; settings pause it (audited)', async () => {
      world.actions.find((a) => a.publicId === ctx.failed)!.status = 'pending';
      const overview = await api
        .http()
        .get(`${BASE}/overview`)
        .set(await asUser(ALL));
      expect(overview.body.remediation).toMatchObject({
        policyMode: 'enforce',
        policySource: 'platform_default',
        paused: false,
        backlog: { pending: 1, capped: false },
      });
      expect(overview.body.remediation.backlog.oldestPendingAgeSeconds).toEqual(expect.any(Number));
      expect(overview.body.connections[0].remediation).toMatchObject({ backlog: { pending: 1 } });
      const settings = await api
        .http()
        .put(`${BASE}/connections/${m365.publicId}/settings`)
        .set(await asUser(ALL))
        .set('Idempotency-Key', randomUUID())
        .send({ feedsEnabled: false, remediationPaused: true, expectedRowVersion: 1 });
      expect(settings.status, JSON.stringify(settings.body)).toBe(200);
      expect(settings.body).toMatchObject({ remediationPaused: true });
      expect(settings.body.remediationPausedAt).toEqual(expect.any(String));
      expect(audit.entries.at(-1)).toMatchObject({
        action: 'api_mode.settings_updated',
        metadata: { remediationPaused: true, changedPaths: ['remediationPaused'] },
      });
      const detail = await api
        .http()
        .get(`${BASE}/connections/${m365.publicId}`)
        .set(await asUser(ALL));
      expect(detail.body.remediation).toMatchObject({ paused: true });
    });
  });
});
