/**
 * The step API-3 clawback and settings routes (docs/plan/steps/37-api-mode-clawback-reporting.md
 * C6, C7, C14 #1-#10, #18, #19, §9.4) over HTTP with MySQL, Redis and S3 stubbed: the API-mode
 * repositories through `ApiModeWorld` and its `ClawbackStore`, the Idempotency-Key store and the
 * audit in memory (the mailbox-worker's materialization is simulated by seeding clawbacks and
 * targets). For every operation: success, 401, 403 without its permission (a read-only user on
 * every write), API keys, 404 for another organization's ids; then Idempotency-Key replay and
 * reuse, CAS 409, criteria normalization and refusal, v1 cursors and filters, the
 * `remediation:purge` gating of target fields, the approval rules (API key, requester, expiry),
 * hard delete (422 while disabled; always approval when enabled), cancel and restore
 * (`quarantine:release`), the `api_mode_purge_approval` outbox row, and the additive API-1/API-2
 * changes (overview blocks, detection fields and filter, remediation trigger filter and
 * `clawbackId`). The real writer and replica run in integration/api-mode-clawback.test.ts.
 */
// @covers post /api/v1/api-mode/clawbacks
// @covers get /api/v1/api-mode/clawbacks
// @covers get /api/v1/api-mode/clawbacks/:clawbackId
// @covers get /api/v1/api-mode/clawbacks/:clawbackId/targets
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/submit
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/submit-hard-delete
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/approve
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/deny
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/cancel
// @covers post /api/v1/api-mode/clawbacks/:clawbackId/restore
// @covers get /api/v1/api-mode/settings
// @covers put /api/v1/api-mode/settings
import { randomUUID } from 'node:crypto';
import { EventTypes } from '@email-gateway/event-contracts';
import { copyMessageIdHash } from '@email-gateway/mailbox-api';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AuditService } from '../src/audit/audit.service';
import {
  seedClawback,
  seedTarget,
  type StoredClawback,
} from './support/api-mode-clawback-fixtures';
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
import { RecordingAuditService } from './support/messages-fixtures';

const READ = 'remediation:read';
const WRITE = 'remediation:write';
const PURGE = 'remediation:purge';
const RELEASE = 'quarantine:release';
const ALL = [READ, WRITE, PURGE, RELEASE];
const BASE = '/api/v1/api-mode';
const OTHER_ORG = 2n;
const OTHER_USER = 77n;
const SUBMITTER = 78n;
const REASON = 'Phishing campaign confirmed by the SOC';

type Method = 'get' | 'post' | 'put';

interface Ctx {
  ready: StoredClawback;
  ready2: StoredClawback;
  pending: StoredClawback;
  pending2: StoredClawback;
  completed: StoredClawback;
  running: StoredClawback;
  foreign: StoredClawback;
  copies: StoredCopy[];
  foreignCopy: StoredCopy;
}

interface Spec {
  id: string;
  method: Method;
  path: (c: Ctx) => string;
  perms: string[];
  keyed?: boolean;
  body?: (c: Ctx) => object;
  ok: number;
}

const WINDOW = {
  from: new Date(Date.now() - 86_400_000).toISOString(),
  to: new Date().toISOString(),
};
const windowNow = () => WINDOW;

const settingsBody = (patch: Record<string, unknown> = {}) => ({
  internalMailEnabled: true,
  autoClawback: 'review',
  autoMaxMailboxes: 400,
  purgeApprovalMailboxes: 20,
  clawbackLookbackDays: 10,
  tiMinConfidence: 85,
  reportAckEnabled: true,
  reportFeedbackEnabled: false,
  reason: 'Review automatic clawbacks for the pilot',
  expectedRowVersion: null,
  ...patch,
});

const SPECS: Spec[] = [
  {
    id: 'create',
    method: 'post',
    path: () => `${BASE}/clawbacks`,
    perms: [PURGE],
    keyed: true,
    body: () => ({
      criteria: { messageId: '<c-1@fabrikam.example>', ...windowNow() },
      reason: REASON,
    }),
    ok: 202,
  },
  { id: 'list', method: 'get', path: () => `${BASE}/clawbacks`, perms: [READ], ok: 200 },
  {
    id: 'detail',
    method: 'get',
    path: (c) => `${BASE}/clawbacks/${c.ready.publicId}`,
    perms: [READ],
    ok: 200,
  },
  {
    id: 'targets',
    method: 'get',
    path: (c) => `${BASE}/clawbacks/${c.ready.publicId}/targets`,
    perms: [READ],
    ok: 200,
  },
  {
    id: 'submit',
    method: 'post',
    path: (c) => `${BASE}/clawbacks/${c.ready.publicId}/submit`,
    perms: [PURGE],
    keyed: true,
    body: () => ({ mode: 'explicit', action: 'move_junk', reason: REASON, expectedRowVersion: 2 }),
    ok: 202,
  },
  {
    // The platform setting is off in this app: the refusal is the route's answer.
    id: 'submitHardDelete',
    method: 'post',
    path: (c) => `${BASE}/clawbacks/${c.ready.publicId}/submit-hard-delete`,
    perms: [PURGE],
    keyed: true,
    body: () => ({ reason: REASON, expectedRowVersion: 2 }),
    ok: 422,
  },
  {
    id: 'approve',
    method: 'post',
    path: (c) => `${BASE}/clawbacks/${c.pending.publicId}/approve`,
    perms: [PURGE],
    keyed: true,
    body: () => ({ reason: 'Verified', expectedRowVersion: 4 }),
    ok: 200,
  },
  {
    id: 'deny',
    method: 'post',
    path: (c) => `${BASE}/clawbacks/${c.pending2.publicId}/deny`,
    perms: [PURGE],
    keyed: true,
    body: () => ({ reason: 'Wrong sender', expectedRowVersion: 4 }),
    ok: 200,
  },
  {
    id: 'cancel',
    method: 'post',
    path: (c) => `${BASE}/clawbacks/${c.ready2.publicId}/cancel`,
    perms: [PURGE],
    keyed: true,
    body: () => ({ reason: 'Wrong criteria' }),
    ok: 202,
  },
  {
    id: 'restore',
    method: 'post',
    path: (c) => `${BASE}/clawbacks/${c.completed.publicId}/restore`,
    perms: [PURGE, RELEASE],
    keyed: true,
    body: () => ({ reason: 'False positive' }),
    ok: 202,
  },
  { id: 'settings', method: 'get', path: () => `${BASE}/settings`, perms: [READ], ok: 200 },
  {
    id: 'putSettings',
    method: 'put',
    path: () => `${BASE}/settings`,
    perms: [WRITE],
    keyed: true,
    body: () => settingsBody(),
    ok: 200,
  },
];

function seedWorld(
  world: ApiModeWorld,
  org: bigint,
  orgPublicId: string,
  userPublicId: string,
): Ctx {
  world.addOrganization(org, orgPublicId);
  world.addOrganization(OTHER_ORG, randomUUID());
  world.entitled.add(org);
  world.userPublicIds.set(10n, userPublicId);
  world.userPublicIds.set(OTHER_USER, randomUUID());
  world.userPublicIds.set(SUBMITTER, randomUUID());
  const m365: StoredConnection = world.addConnection(org, {
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
  world.addDomain(org, 'contoso.example', { connectionId: m365.id, configured: 'api' });
  const mailboxes: StoredMailbox[] = ['alex', 'sam', 'kim'].map((n) =>
    world.addMailbox(m365, `${n}@contoso.example`),
  );
  const copies = mailboxes.map((m, i) =>
    world.addCopy(m, {
      verdict: 'phishing',
      riskScore: 900,
      receivedAt: new Date(Date.now() - (i + 1) * 60_000),
      direction: i === 2 ? 'internal' : 'inbound',
    }),
  );
  const foreignConnection = world.addConnection(OTHER_ORG, { displayName: 'Other' });
  const foreignMailbox = world.addMailbox(foreignConnection, 'eve@other.example');
  const foreignCopy = world.addCopy(foreignMailbox);
  const pendingPatch = {
    status: 'pending_approval' as const,
    decisionMode: 'explicit' as const,
    action: 'move_junk' as const,
    requiresApproval: true,
    approvalReasons: ['mailbox_threshold'],
    approvalStatus: 'pending' as const,
    approvalRequestedAt: new Date(Date.now() - 60_000),
    approvalExpiresAt: new Date(Date.now() + 3_600_000),
    requestedByUserId: OTHER_USER,
    submittedByUserId: SUBMITTER,
    submittedAt: new Date(Date.now() - 60_000),
    mailboxesEligible: 60,
    rowVersion: 4,
  };
  const ready = seedClawback(world, org, { requestedByUserId: OTHER_USER });
  for (const c of copies) seedTarget(world, ready, c);
  return {
    ready,
    ready2: seedClawback(world, org, { createdAt: new Date(Date.now() - 120_000) }),
    pending: seedClawback(world, org, {
      ...pendingPatch,
      createdAt: new Date(Date.now() - 180_000),
    }),
    pending2: seedClawback(world, org, {
      ...pendingPatch,
      createdAt: new Date(Date.now() - 240_000),
    }),
    completed: seedClawback(world, org, {
      status: 'completed',
      decisionMode: 'explicit',
      action: 'move_quarantine',
      targetsSucceeded: 3,
      completedAt: new Date(Date.now() - 30_000),
      createdAt: new Date(Date.now() - 300_000),
    }),
    running: seedClawback(world, org, {
      status: 'running',
      trigger: 'late_verdict',
      targetsQueued: 3,
      createdAt: new Date(Date.now() - 360_000),
    }),
    foreign: seedClawback(world, OTHER_ORG),
    copies,
    foreignCopy,
  };
}

describe('API-mode clawback and settings routes (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const world = new ApiModeWorld();
  const audit = new RecordingAuditService();
  const store = new InMemoryIdempotencyStore();
  let org: bigint;
  let ctx: Ctx;

  beforeAll(async () => {
    api = await createStubbedApiApp(
      {},
      {
        override: (b) =>
          store.override(overrideApiMode(b, world).overrideProvider(AuditService).useValue(audit)),
      },
    );
    org = api.principals.organizationId;
  });

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    world.reset();
    audit.entries.length = 0;
    world.claw.audit = audit.entries;
    store.rows.clear();
    api.kv.entries.clear();
    api.principals.apiKeyWith([]);
    ctx = seedWorld(world, org, api.principals.ids.org, api.principals.ids.user);
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

  async function call(method: Method, path: string, body?: object, perms = ALL) {
    const req = api
      .http()
      [method](path)
      .set(await asUser(perms));
    if (method !== 'get') req.set('Idempotency-Key', randomUUID());
    return body === undefined ? req : req.send(body);
  }

  const spec = (id: string) => SPECS.find((s) => s.id === id)!;
  const outboxOf = (eventType: string) =>
    world.claw.outbox.filter((o) => o.eventType === eventType);

  describe('every operation (success, auth, RBAC)', () => {
    it.each(SPECS.map((s) => [s.id, s] as const))(
      '%s answers with its permission',
      async (_id, s) => {
        const res = await send(s, { perms: s.perms });
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
      '%s answers 403 without each of its permissions',
      async (_id, s) => {
        for (const perm of s.perms) {
          const res = await send(s, { perms: ALL.filter((p) => p !== perm) });
          expect(res.status, perm).toBe(403);
          expect(res.body.code).toBe('forbidden');
        }
      },
    );

    it('a read-only user is refused every write and reads every view', async () => {
      const readOnly = [READ, 'organization:read', 'domain:read', 'quarantine:read'];
      for (const s of SPECS) {
        const res = await send(s, { perms: readOnly });
        if (s.method === 'get') expect(res.status, s.id).toBe(s.ok);
        else expect(res.status, s.id).toBe(403);
      }
      expect(world.claw.clawbacks.filter((k) => k.status === 'searching')).toHaveLength(0);
      expect(world.claw.settings.size).toBe(0);
      expect(audit.entries).toHaveLength(0);
    });

    it('a remediation:write user without remediation:purge cannot search, submit or approve', async () => {
      for (const s of SPECS.filter((x) => x.perms.includes(PURGE))) {
        const res = await send(s, { perms: [READ, WRITE, RELEASE] });
        expect(res.status, s.id).toBe(403);
      }
    });

    it('API keys: every route with its permission, but never approve or deny (api_key)', async () => {
      for (const s of SPECS) {
        world.reset();
        world.claw.audit = audit.entries;
        store.rows.clear();
        ctx = seedWorld(world, org, api.principals.ids.org, api.principals.ids.user);
        const res = await send(s, { apiKey: ALL });
        if (s.id === 'approve' || s.id === 'deny') {
          expect(res.status, s.id).toBe(403);
          expect(res.body).toMatchObject({
            code: 'api_mode_purge_approval_forbidden',
            reason: 'api_key',
          });
        } else {
          expect(res.status, `${s.id} ${JSON.stringify(res.body)}`).toBe(s.ok);
        }
      }
    });

    it('another organization’s clawbacks and detections answer 404 like unknown ids', async () => {
      const id = ctx.foreign.publicId;
      const cases: Array<[Method, string, object?]> = [
        ['get', `${BASE}/clawbacks/${id}`],
        ['get', `${BASE}/clawbacks/${id}/targets`],
        ['get', `${BASE}/clawbacks/${randomUUID()}`],
        [
          'post',
          `${BASE}/clawbacks/${id}/submit`,
          { mode: 'policy', reason: REASON, expectedRowVersion: 2 },
        ],
        ['post', `${BASE}/clawbacks/${id}/approve`, { reason: 'x', expectedRowVersion: 2 }],
        ['post', `${BASE}/clawbacks/${id}/deny`, { reason: 'x', expectedRowVersion: 2 }],
        ['post', `${BASE}/clawbacks/${id}/cancel`, { reason: 'x' }],
        ['post', `${BASE}/clawbacks/${id}/restore`, { reason: 'x' }],
      ];
      for (const [method, path, body] of cases) {
        const res = await call(method, path, body);
        expect(res.status, path).toBe(404);
        expect(res.body.code, path).toBe('api_mode_clawback_not_found');
      }
      const seeded = await call('post', `${BASE}/clawbacks`, {
        seedDetectionId: ctx.foreignCopy.publicId,
        reason: REASON,
      });
      expect(seeded.status).toBe(404);
      expect(seeded.body.code).toBe('api_mode_detection_not_found');
      const list = await call('get', `${BASE}/clawbacks`);
      expect(list.body.data.map((k: { id: string }) => k.id)).not.toContain(id);
      expect(ctx.foreign.status).toBe('ready');
      expect((await call('get', `${BASE}/clawbacks/not-a-uuid`)).status).toBe(400);
    });
  });

  describe('create (C14 #1, C4.4, C2.4)', () => {
    it('normalizes the Message-ID, stores the criteria and audits key counts only', async () => {
      const res = await send(spec('create'));
      expect(res.body).toMatchObject({ status: 'searching', trigger: 'admin', rowVersion: 1 });
      const row = world.claw.clawbacks.find((k) => k.publicId === res.body.id)!;
      expect(row.organizationId).toBe(org);
      expect((row.criteria as { keys: unknown }).keys).toEqual({
        messageIdHashes: [copyMessageIdHash(org, 'c-1@fabrikam.example')],
      });
      expect(row.requestedByUserId).toBe(10n);
      const created = audit.entries.find((e) => e.action === 'api_mode.clawback_created')!;
      expect(created.metadata).toMatchObject({ trigger: 'admin', keys: { messageIdHashes: 1 } });
      expect(JSON.stringify(created.metadata)).not.toContain('fabrikam');
    });

    it('a seed detection with expand is a campaign with the seed keys', async () => {
      const res = await call('post', `${BASE}/clawbacks`, {
        seedDetectionId: ctx.copies[0]!.publicId,
        expand: { attachments: true, urls: true, senderSubjectHours: 48 },
        reason: REASON,
      });
      expect(res.status, JSON.stringify(res.body)).toBe(202);
      expect(res.body.trigger).toBe('campaign');
      const row = world.claw.clawbacks.find((k) => k.publicId === res.body.id)!;
      expect(Object.keys((row.criteria as { keys: object }).keys).sort()).toEqual([
        'attachmentSha256',
        'messageIdHashes',
        'senderSubject',
        'urlSha256',
      ]);
      expect(row.seedCopyId).toBe(ctx.copies[0]!.id);
      expect((row.signal as { kind: string }).kind).toBe('campaign');
    });

    it('invalid criteria → 422 with codes; strict body and missing keys → 400', async () => {
      const cases: Array<[object, number, string?]> = [
        [
          {
            criteria: {
              messageId: '<a@b>',
              from: new Date(Date.now() - 40 * 86_400_000).toISOString(),
              to: new Date().toISOString(),
            },
            reason: REASON,
          },
          422,
          'window_too_long',
        ],
        [
          { criteria: { sender: 'a@b.example', ...windowNow() }, reason: REASON },
          422,
          'sender_subject_together',
        ],
        [
          { criteria: { url: 'mailto:a@b.example', ...windowNow() }, reason: REASON },
          422,
          'url_invalid',
        ],
        [{ reason: REASON }, 400],
        [{ criteria: { messageId: '<a@b>', ...windowNow() }, reason: REASON, extra: 1 }, 400],
        [{ criteria: { attachmentSha256: ['nothex'], ...windowNow() }, reason: REASON }, 400],
      ];
      for (const [body, status, code] of cases) {
        const res = await call('post', `${BASE}/clawbacks`, body);
        expect(res.status, JSON.stringify(body)).toBe(status);
        if (code) {
          expect(res.body.code).toBe('api_mode_clawback_criteria_invalid');
          expect(res.body.codes).toContain(code);
        }
      }
      expect(world.claw.clawbacks.filter((k) => k.status === 'searching')).toHaveLength(0);
    });

    it('Idempotency-Key: replay returns the same clawback; reuse with another body is 422', async () => {
      const key = randomUUID();
      const first = await send(spec('create'), { key });
      const replay = await send(spec('create'), { key });
      expect(replay.status).toBe(202);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body).toEqual(first.body);
      const reuse = await send(spec('create'), {
        key,
        body: { criteria: { messageId: '<other@x.example>', ...windowNow() }, reason: REASON },
      });
      expect(reuse.status).toBe(422);
      expect(reuse.body.code).toBe('idempotency_key_reused');
      expect(world.claw.clawbacks.filter((k) => k.status === 'searching')).toHaveLength(1);
    });
  });

  describe('list, detail, targets (C14 #2-#4)', () => {
    it('v1 cursor pages and filters; the cursor is bound to its filters', async () => {
      const first = await api
        .http()
        .get(`${BASE}/clawbacks`)
        .query({ limit: '2' })
        .set(await asUser([READ]));
      expect(first.body.data).toHaveLength(2);
      expect(first.body.data[0].id).toBe(ctx.ready.publicId);
      expect(first.body.nextCursor).toEqual(expect.any(String));
      const second = await api
        .http()
        .get(`${BASE}/clawbacks`)
        .query({ limit: '2', cursor: first.body.nextCursor })
        .set(await asUser([READ]));
      expect(second.body.data.map((k: { id: string }) => k.id)).toEqual([
        ctx.pending.publicId,
        ctx.pending2.publicId,
      ]);
      const rebound = await api
        .http()
        .get(`${BASE}/clawbacks`)
        .query({ limit: '2', status: 'ready', cursor: first.body.nextCursor })
        .set(await asUser([READ]));
      expect(rebound.status).toBe(400);
      const filtered = await api
        .http()
        .get(`${BASE}/clawbacks`)
        .query({ approvalStatus: 'pending', trigger: 'admin' })
        .set(await asUser([READ]));
      expect(filtered.body.data.map((k: { id: string }) => k.id).sort()).toEqual(
        [ctx.pending.publicId, ctx.pending2.publicId].sort(),
      );
      expect(filtered.body.data[0].approval).toMatchObject({
        required: true,
        status: 'pending',
        reasons: ['mailbox_threshold'],
      });
      const tooLong = await api
        .http()
        .get(`${BASE}/clawbacks`)
        .query({
          from: new Date(Date.now() - 100 * 86_400_000).toISOString(),
          to: new Date().toISOString(),
        })
        .set(await asUser([READ]));
      expect(tooLong.status).toBe(400);
    });

    it('detail: truncated hashes, actors and hints for the caller', async () => {
      const res = await call('get', `${BASE}/clawbacks/${ctx.pending.publicId}`);
      expect(res.body.criteria.keys.messageIdHashes).toEqual([`${'ab'.repeat(6)}…`]);
      expect(res.body.hints).toEqual({
        canSubmit: false,
        canApprove: true,
        canCancel: true,
        canRestore: false,
      });
      expect(res.body.requestedBy.userId).toBe(world.userPublicIds.get(OTHER_USER));
      const asRequester = await call('get', `${BASE}/clawbacks/${ctx.completed.publicId}`);
      expect(asRequester.body.hints).toMatchObject({ canRestore: true, canApprove: false });
      const readOnly = await call('get', `${BASE}/clawbacks/${ctx.ready.publicId}`, undefined, [
        READ,
      ]);
      expect(readOnly.body.hints).toEqual({
        canSubmit: false,
        canApprove: false,
        canCancel: false,
        canRestore: false,
      });
    });

    it('targets: masked mailbox and no sender/subject without remediation:purge; cursor; filter', async () => {
      const masked = await call(
        'get',
        `${BASE}/clawbacks/${ctx.ready.publicId}/targets`,
        undefined,
        [READ],
      );
      expect(masked.body.data).toHaveLength(3);
      expect(masked.body.data[0]).toMatchObject({
        mailbox: { address: 'a***@contoso.example' },
        headerFrom: null,
        subject: null,
        matchKeys: ['message_id'],
        status: 'matched',
        detectionId: ctx.copies[0]!.publicId,
      });
      const full = await call('get', `${BASE}/clawbacks/${ctx.ready.publicId}/targets`, undefined, [
        READ,
        PURGE,
      ]);
      expect(full.body.data[0]).toMatchObject({
        mailbox: { address: 'alex@contoso.example' },
        headerFrom: 'billing@fabrikam.example',
        subject: 'Quarterly invoice',
      });
      const page = await api
        .http()
        .get(`${BASE}/clawbacks/${ctx.ready.publicId}/targets`)
        .query({ limit: '2' })
        .set(await asUser([READ]));
      expect(page.status, JSON.stringify(page.body)).toBe(200);
      expect(page.body.data).toHaveLength(2);
      const next = await api
        .http()
        .get(`${BASE}/clawbacks/${ctx.ready.publicId}/targets`)
        .query({ limit: '2', cursor: page.body.nextCursor })
        .set(await asUser([READ]));
      expect(next.body.data).toHaveLength(1);
      expect(next.body.nextCursor).toBeNull();
      // A cursor of one clawback is refused on another.
      const crossed = await api
        .http()
        .get(`${BASE}/clawbacks/${ctx.ready2.publicId}/targets`)
        .query({ limit: '2', cursor: page.body.nextCursor })
        .set(await asUser([READ]));
      expect(crossed.status).toBe(400);
      const skipped = await api
        .http()
        .get(`${BASE}/clawbacks/${ctx.ready.publicId}/targets`)
        .query({ status: 'skipped' })
        .set(await asUser([READ]));
      expect(skipped.body.data).toEqual([]);
    });
  });

  describe('submit (C14 #5, #6; C6)', () => {
    it('below the threshold: queued, submitter recorded, no approval and no alert', async () => {
      const res = await send(spec('submit'));
      expect(res.body).toMatchObject({
        status: 'queued',
        requiresApproval: false,
        approvalReasons: [],
        approvalExpiresAt: null,
        rowVersion: 3,
      });
      expect(ctx.ready).toMatchObject({
        status: 'queued',
        decisionMode: 'explicit',
        action: 'move_junk',
        submittedByUserId: 10n,
      });
      expect(outboxOf(EventTypes.NotificationAlertRequested)).toHaveLength(0);
      expect(audit.entries.map((e) => e.action)).toEqual(['api_mode.clawback_submitted']);
    });

    it('above the organization threshold: pending_approval, TTL, one throttled alert', async () => {
      // A settings row with a threshold of 2 distinct mailboxes (3 eligible here).
      world.claw.settings.set(org, {
        internalMailEnabled: true,
        autoClawback: 'enforce',
        autoMaxMailboxes: 500,
        purgeApprovalMailboxes: 2,
        clawbackLookbackDays: 14,
        tiMinConfidence: 80,
        reportAckEnabled: true,
        reportFeedbackEnabled: true,
        rowVersion: 1,
        updatedAt: new Date(),
        purgeApprovalRaisedBy: null,
        purgeApprovalBeforeRaise: null,
      });
      const res = await send(spec('submit'), {
        body: { mode: 'policy', verdict: 'malware', reason: REASON, expectedRowVersion: 2 },
      });
      expect(res.body).toMatchObject({
        status: 'pending_approval',
        requiresApproval: true,
        approvalReasons: ['mailbox_threshold'],
      });
      const ttl = Date.parse(res.body.approvalExpiresAt) - Date.now();
      expect(ttl).toBeGreaterThan(71 * 3_600_000);
      expect(ttl).toBeLessThanOrEqual(72 * 3_600_000);
      expect(ctx.ready).toMatchObject({
        decisionMode: 'policy',
        action: null,
        signalVerdict: 'malware',
        signalLevel: 'critical',
        signalHardBlocks: ['hb.clawback.analyst'],
        approvalStatus: 'pending',
      });
      const alerts = outboxOf(EventTypes.NotificationAlertRequested);
      expect(alerts).toHaveLength(1);
      expect(alerts[0]!.payload).toMatchObject({
        kind: 'api_mode_purge_approval',
        severity: 'medium',
        refs: { clawbackId: ctx.ready.publicId },
      });
      expect(alerts[0]!.aggregateType).toBe('organization');
      expect(audit.entries.map((e) => e.action)).toEqual([
        'api_mode.clawback_submitted',
        'api_mode.clawback_approval_requested',
      ]);
    });

    it('CAS and state: a stale version or a queued clawback is 409 with the current version', async () => {
      const stale = await send(spec('submit'), {
        body: { mode: 'policy', reason: REASON, expectedRowVersion: 1 },
      });
      expect(stale.status).toBe(409);
      expect(stale.body).toMatchObject({
        code: 'api_mode_clawback_state_conflict',
        status: 'ready',
        currentRowVersion: 2,
      });
      const running = await call('post', `${BASE}/clawbacks/${ctx.running.publicId}/submit`, {
        mode: 'policy',
        reason: REASON,
        expectedRowVersion: 2,
      });
      expect(running.status).toBe(409);
      expect(running.body.status).toBe('running');
      const replayKey = randomUUID();
      const first = await send(spec('submit'), { key: replayKey });
      const replay = await send(spec('submit'), { key: replayKey });
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body).toEqual(first.body);
    });

    it('explicit mode never takes hard_delete; hard delete is 422 while the setting is off', async () => {
      const explicit = await send(spec('submit'), {
        body: { mode: 'explicit', action: 'hard_delete', reason: REASON, expectedRowVersion: 2 },
      });
      expect(explicit.status).toBe(400);
      const hard = await send(spec('submitHardDelete'));
      expect(hard.status).toBe(422);
      expect(hard.body.code).toBe('api_mode_hard_delete_disabled');
      expect(ctx.ready.status).toBe('ready');
    });
  });

  describe('approve and deny (C14 #7, #8)', () => {
    it('approve: queued, the approver and permission hash stored and audited', async () => {
      const res = await send(spec('approve'));
      expect(res.body).toMatchObject({ status: 'queued', approval: { status: 'approved' } });
      expect(ctx.pending.approvedByUserId).toBe(10n);
      const row = audit.entries.find((e) => e.action === 'api_mode.clawback_approved')!;
      expect(row.metadata).toMatchObject({
        clawbackId: ctx.pending.publicId,
        approverPermissionsHash: expect.stringMatching(/^[0-9a-f]{64}$/),
      });
      const detail = await call('get', `${BASE}/clawbacks/${ctx.pending.publicId}`);
      expect(detail.body.approvalDecision).toEqual({
        decidedBy: api.principals.ids.user,
        reason: 'Verified',
      });
    });

    it('deny: denied, nothing queued', async () => {
      const res = await send(spec('deny'));
      expect(res.body).toMatchObject({ status: 'denied', approval: { status: 'denied' } });
      expect(ctx.pending2.completedAt).not.toBeNull();
    });

    it('the requester or submitter cannot decide; expired and decided requests are not pending', async () => {
      ctx.pending.submittedByUserId = 10n;
      const own = await send(spec('approve'));
      expect(own.status).toBe(403);
      expect(own.body).toMatchObject({
        code: 'api_mode_purge_approval_forbidden',
        reason: 'requester',
      });
      ctx.pending2.approvalExpiresAt = new Date(Date.now() - 1000);
      const expired = await send(spec('deny'));
      expect(expired.status).toBe(409);
      expect(expired.body).toMatchObject({
        code: 'api_mode_purge_approval_not_pending',
        reason: 'expired',
      });
      const notPending = await call('post', `${BASE}/clawbacks/${ctx.ready.publicId}/approve`, {
        reason: 'x',
        expectedRowVersion: 2,
      });
      expect(notPending.status).toBe(409);
      expect(notPending.body.reason).toBe('not_pending');
      const stale = await send(spec('approve'), { body: { reason: 'x', expectedRowVersion: 3 } });
      expect(stale.status).toBe(409);
      expect(stale.body.code).toBe('api_mode_clawback_state_conflict');
      expect(ctx.pending.approvalStatus).toBe('pending');
    });

    it('a submit then the same user’s approval is refused (two people above the threshold)', async () => {
      ctx.ready.mailboxesEligible = 80;
      const submitted = await send(spec('submit'));
      expect(submitted.body.status).toBe('pending_approval');
      const approve = await call('post', `${BASE}/clawbacks/${ctx.ready.publicId}/approve`, {
        reason: 'x',
        expectedRowVersion: submitted.body.rowVersion,
      });
      expect(approve.status).toBe(403);
      expect(approve.body.reason).toBe('requester');
    });
  });

  describe('purge threshold separation of duties (P2 review fix)', () => {
    const settingsRow = (raise: { by: string | null; before: number | null }) => ({
      internalMailEnabled: true,
      autoClawback: 'enforce' as const,
      autoMaxMailboxes: 500,
      purgeApprovalMailboxes: 10_000,
      clawbackLookbackDays: 14,
      tiMinConfidence: 80,
      reportAckEnabled: true,
      reportFeedbackEnabled: true,
      rowVersion: 4,
      updatedAt: new Date(),
      purgeApprovalRaisedBy: raise.by,
      purgeApprovalBeforeRaise: raise.before,
    });

    it('a user who raised the threshold still needs a second approver above the earlier value', async () => {
      const me = `user:${api.principals.ids.user}`;
      const raised = await send(spec('putSettings'), {
        body: settingsBody({ purgeApprovalMailboxes: 10_000 }),
      });
      expect(raised.status).toBe(200);
      expect(raised.body.settings.purgeApprovalMailboxes).toBe(10_000);
      expect(world.claw.settings.get(org)).toMatchObject({
        purgeApprovalRaisedBy: me,
        purgeApprovalBeforeRaise: 50,
      });
      const update = audit.entries.find((e) => e.action === 'api_mode.settings_org_updated')!;
      expect(update.metadata).toMatchObject({ purgeApprovalSelfCheck: { beforeRaise: 50 } });

      ctx.ready.mailboxesEligible = 80;
      const submitted = await send(spec('submit'));
      expect(submitted.body).toMatchObject({
        status: 'pending_approval',
        requiresApproval: true,
        approvalReasons: ['mailbox_threshold'],
      });
      const requested = audit.entries.find(
        (e) => e.action === 'api_mode.clawback_approval_requested',
      )!;
      expect(requested.metadata).toMatchObject({
        threshold: 50,
        storedThreshold: 10_000,
        selfRaisedThreshold: true,
      });
      // And the same person cannot approve it.
      const approve = await call('post', `${BASE}/clawbacks/${ctx.ready.publicId}/approve`, {
        reason: 'x',
        expectedRowVersion: submitted.body.rowVersion,
      });
      expect(approve.status).toBe(403);
      expect(approve.body.reason).toBe('requester');
    });

    it('a threshold raised by someone else applies; lowering it to the earlier value clears the record', async () => {
      world.claw.settings.set(org, settingsRow({ by: `user:${randomUUID()}`, before: 50 }));
      ctx.ready.mailboxesEligible = 80;
      const submitted = await send(spec('submit'));
      expect(submitted.body).toMatchObject({ status: 'queued', requiresApproval: false });

      const lowered = await send(spec('putSettings'), {
        body: settingsBody({ purgeApprovalMailboxes: 50, expectedRowVersion: 4 }),
      });
      expect(lowered.status).toBe(200);
      expect(world.claw.settings.get(org)).toMatchObject({
        purgeApprovalMailboxes: 50,
        purgeApprovalRaisedBy: null,
        purgeApprovalBeforeRaise: null,
      });
    });

    it('an API key that raised the threshold is checked against the earlier value too', async () => {
      world.claw.settings.set(
        org,
        settingsRow({ by: `api_key:${api.principals.apiKey.apiKeyPublicId}`, before: 50 }),
      );
      ctx.ready.mailboxesEligible = 80;
      const submitted = await send(spec('submit'), { apiKey: ALL });
      expect(submitted.body).toMatchObject({
        status: 'pending_approval',
        approvalReasons: ['mailbox_threshold'],
      });
    });
  });

  describe('cancel and restore (C14 #9, #10)', () => {
    it('ready and pending_approval are cancelled at once; running gets a cancel request once', async () => {
      expect((await send(spec('cancel'))).body).toMatchObject({ status: 'cancelled' });
      const pending = await call('post', `${BASE}/clawbacks/${ctx.pending.publicId}/cancel`, {
        reason: 'x',
      });
      expect(pending.body).toMatchObject({
        status: 'cancelled',
        approval: { status: 'cancelled' },
      });
      const running = await call('post', `${BASE}/clawbacks/${ctx.running.publicId}/cancel`, {
        reason: 'x',
      });
      expect(running.status).toBe(202);
      expect(running.body).toMatchObject({ status: 'running', cancelRequested: true });
      const again = await call('post', `${BASE}/clawbacks/${ctx.running.publicId}/cancel`, {
        reason: 'x',
      });
      expect(again.status).toBe(202);
      expect(audit.entries.filter((e) => e.action === 'api_mode.clawback_cancelled')).toHaveLength(
        3,
      );
      const done = await call('post', `${BASE}/clawbacks/${ctx.completed.publicId}/cancel`, {
        reason: 'x',
      });
      expect(done.status).toBe(409);
      expect(done.body).toMatchObject({
        code: 'api_mode_clawback_not_cancellable',
        status: 'completed',
      });
    });

    it('restore needs quarantine:release, a final clawback and no restore in progress', async () => {
      const noRelease = await send(spec('restore'), { perms: [READ, PURGE] });
      expect(noRelease.status).toBe(403);
      const ok = await send(spec('restore'));
      expect(ok.body.restore.status).toBe('requested');
      expect(ctx.completed.restoreStatus).toBe('requested');
      const twice = await send(spec('restore'));
      expect(twice.status).toBe(409);
      expect(twice.body).toMatchObject({
        code: 'api_mode_clawback_not_restorable',
        restoreStatus: 'requested',
      });
      const running = await call('post', `${BASE}/clawbacks/${ctx.running.publicId}/restore`, {
        reason: 'x',
      });
      expect(running.status).toBe(409);
      expect(
        audit.entries.filter((e) => e.action === 'api_mode.clawback_restore_requested'),
      ).toHaveLength(1);
    });
  });

  describe('settings (C14 #18, #19)', () => {
    it('GET: defaults, bounds and platform facts', async () => {
      const res = await send(spec('settings'));
      expect(res.body).toMatchObject({
        source: 'defaults',
        rowVersion: null,
        settings: { autoClawback: 'enforce', purgeApprovalMailboxes: 50, tiMinConfidence: 80 },
        bounds: { autoMaxMailboxes: { min: 1, max: 20_000 } },
        platform: {
          hardDeleteAvailable: false,
          clawbackMaxWindowDays: 31,
          purgeApprovalTtlHours: 72,
          reportMailboxesMax: 5,
        },
      });
    });

    it('PUT: create (null), CAS 409, replay, bounds 400, audit from/to', async () => {
      const key = randomUUID();
      const first = await send(spec('putSettings'), { key });
      expect(first.body).toMatchObject({
        source: 'row',
        rowVersion: 1,
        created: true,
        settings: { autoClawback: 'review', purgeApprovalMailboxes: 20 },
      });
      expect(first.body.changed.sort()).toEqual(
        [
          'autoClawback',
          'autoMaxMailboxes',
          'clawbackLookbackDays',
          'purgeApprovalMailboxes',
          'reportFeedbackEnabled',
          'tiMinConfidence',
        ].sort(),
      );
      const replay = await send(spec('putSettings'), { key });
      expect(replay.headers['idempotency-replayed']).toBe('true');
      const stale = await send(spec('putSettings'));
      expect(stale.status).toBe(409);
      expect(stale.body).toMatchObject({
        code: 'api_mode_settings_conflict',
        currentRowVersion: 1,
      });
      const next = await send(spec('putSettings'), {
        body: settingsBody({ autoClawback: 'off', expectedRowVersion: 1 }),
      });
      expect(next.body).toMatchObject({ rowVersion: 2, changed: ['autoClawback'] });
      const updates = audit.entries.filter((e) => e.action === 'api_mode.settings_org_updated');
      expect(updates).toHaveLength(2);
      expect(updates[1]!.metadata).toMatchObject({
        from: { autoClawback: 'review' },
        to: { autoClawback: 'off' },
      });
      for (const bad of [
        settingsBody({ autoMaxMailboxes: 0 }),
        settingsBody({ tiMinConfidence: 49 }),
        settingsBody({ clawbackLookbackDays: 61 }),
        settingsBody({ purgeApprovalMailboxes: 10_001 }),
        settingsBody({ autoClawback: 'always' }),
        settingsBody({ extra: true }),
      ]) {
        expect((await send(spec('putSettings'), { body: bad })).status).toBe(400);
      }
    });
  });

  describe('additive changes (C13, C14)', () => {
    it('overview: internal, clawback and reports blocks (organization and per connection)', async () => {
      const connection = world.connections.find((c) => c.organizationId === org)!;
      world.claw.counters.push({
        organizationId: org,
        apiConnectionId: connection.api!.id,
        hour: new Date(Math.floor(Date.now() / 3_600_000) * 3_600_000),
        internalCopies: 4,
        clawbackTargetsQueued: 6,
        clawbackTargetsSucceeded: 5,
        clawbackTargetsFailed: 1,
        reportsReceived: 2,
        reportsResolved: 1,
      });
      const res = await call('get', `${BASE}/overview`, undefined, [READ]);
      expect(res.status).toBe(200);
      expect(res.body.internal).toEqual({ copies24h: 4, enabled: true });
      expect(res.body.clawback).toMatchObject({
        active: 5,
        reviewRequired: 0,
        pendingApproval: 2,
        completed24h: 1,
        targetsSucceeded24h: 5,
        targetsFailed24h: 1,
      });
      expect(res.body.clawback.oldestActiveAgeSeconds).toBeGreaterThanOrEqual(350);
      expect(res.body.reports).toMatchObject({ received24h: 2, resolved24h: 1, pendingTriage: 0 });
      expect(res.body.connections[0]).toMatchObject({
        internal: { copies24h: 4, enabled: true },
        clawback: { targetsQueued24h: 6, targetsSucceeded24h: 5, targetsFailed24h: 1 },
      });
    });

    it('detections: direction, verdictRevision, clawbacks (≤ 5) and the direction filter', async () => {
      ctx.copies[0]!.verdictRevision = 1;
      const list = await call('get', `${BASE}/detections`, undefined, [READ]);
      const first = list.body.data.find((d: { id: string }) => d.id === ctx.copies[0]!.publicId);
      expect(first).toMatchObject({
        direction: 'inbound',
        verdictRevision: 1,
        clawbacks: [ctx.ready.publicId],
      });
      const internal = await api
        .http()
        .get(`${BASE}/detections`)
        .query({ direction: 'internal' })
        .set(await asUser([READ]));
      expect(internal.body.data.map((d: { id: string }) => d.id)).toEqual([
        ctx.copies[2]!.publicId,
      ]);
      const detail = await call('get', `${BASE}/detections/${ctx.copies[2]!.publicId}`, undefined, [
        READ,
      ]);
      expect(detail.body).toMatchObject({ direction: 'internal', clawbacks: [ctx.ready.publicId] });
    });

    it('remediation history: trigger clawback|purge filter and clawbackId', async () => {
      world.addAction(ctx.copies[0]!, {
        trigger: 'purge',
        action: 'move_junk',
        clawbackPublicId: ctx.ready.publicId,
      });
      world.addAction(ctx.copies[1]!, { trigger: 'policy', action: 'tag' });
      const res = await api
        .http()
        .get(`${BASE}/remediations`)
        .query({ trigger: 'clawback,purge' })
        .set(await asUser([READ]));
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.data).toEqual([
        expect.objectContaining({ trigger: 'purge', clawbackId: ctx.ready.publicId }),
      ]);
    });
  });
});

describe('API-mode hard-delete purge with the platform setting on (e2e)', () => {
  let api: StubbedApiApp;
  const world = new ApiModeWorld();
  const audit = new RecordingAuditService();
  const store = new InMemoryIdempotencyStore();
  let ctx: Ctx;

  beforeAll(async () => {
    api = await createStubbedApiApp(
      { API_MODE_HARD_DELETE_ENABLED: 'true' },
      {
        override: (b) =>
          store.override(overrideApiMode(b, world).overrideProvider(AuditService).useValue(audit)),
      },
    );
  });

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    world.reset();
    audit.entries.length = 0;
    world.claw.audit = audit.entries;
    store.rows.clear();
    ctx = seedWorld(
      world,
      api.principals.organizationId,
      api.principals.ids.org,
      api.principals.ids.user,
    );
  });

  it('always pending_approval (hard_delete) with a high-severity alert, even below the threshold', async () => {
    const res = await api
      .http()
      .post(`${BASE}/clawbacks/${ctx.ready.publicId}/submit-hard-delete`)
      .set(await api.principals.user([READ, PURGE]).bearer())
      .set('Idempotency-Key', randomUUID())
      .send({ reason: REASON, expectedRowVersion: 2 });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body).toMatchObject({
      status: 'pending_approval',
      requiresApproval: true,
      approvalReasons: ['hard_delete'],
    });
    expect(ctx.ready).toMatchObject({ decisionMode: 'explicit', action: 'hard_delete' });
    const alert = world.claw.outbox.find(
      (o) => o.eventType === EventTypes.NotificationAlertRequested,
    )!;
    expect(alert.payload).toMatchObject({ kind: 'api_mode_purge_approval', severity: 'high' });
    const settings = await api
      .http()
      .get(`${BASE}/settings`)
      .set(await api.principals.user([READ]).bearer());
    expect(settings.body.platform.hardDeleteAvailable).toBe(true);
  });
});
