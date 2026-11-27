/**
 * The step API-3 user-report routes (docs/plan/steps/37-api-mode-clawback-reporting.md C9.1,
 * C11, C12, C14 #11-#17, §9.4) over HTTP with MySQL, Redis and S3 stubbed: the API-mode
 * repositories through `ApiModeWorld` and its `ClawbackStore` (reports seeded as the
 * mailbox-worker's `reports` role leaves them), the Idempotency-Key store and the audit in memory.
 * For every operation: success, 401, 403 without its permission (a read-only user on every
 * write), API keys, 404 for another organization's ids; then triage (verdict rules, CAS 409,
 * reopen once, group resolution with one `mail.report.feedback_requested.v1` row per resolved
 * report and the counters, history from the audit rows), the clawback from a report (report vs
 * campaign trigger, unknown original, rejected report), v1 cursors and filters, and the report
 * mailboxes (designation rules, limit, by address with the discovered-mailbox creation, out of
 * scope). The real writer and replica run in integration/api-mode-clawback.test.ts.
 */
// @covers get /api/v1/api-mode/reports
// @covers get /api/v1/api-mode/reports/:reportId
// @covers post /api/v1/api-mode/reports/:reportId/triage
// @covers post /api/v1/api-mode/reports/:reportId/clawback
// @covers get /api/v1/api-mode/report-mailboxes
// @covers post /api/v1/api-mode/report-mailboxes
// @covers put /api/v1/api-mode/mailboxes/:mailboxId/report-mailbox
import { randomUUID } from 'node:crypto';
import { EventTypes } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AuditService } from '../src/audit/audit.service';
import { seedReport, type StoredReport } from './support/api-mode-clawback-fixtures';
import {
  ApiModeWorld,
  overrideApiMode,
  type StoredConnection,
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
const ALL = [READ, WRITE, PURGE];
const BASE = '/api/v1/api-mode';
const OTHER_ORG = 2n;

type Method = 'get' | 'post' | 'put';

interface Ctx {
  reportMailbox: StoredMailbox;
  alex: StoredMailbox;
  inlineMailbox: StoredMailbox;
  foreignMailbox: StoredMailbox;
  report: StoredReport;
  sibling: StoredReport;
  parsing: StoredReport;
  noOriginal: StoredReport;
  foreign: StoredReport;
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

const triageBody = (patch: Record<string, unknown> = {}) => ({
  status: 'resolved',
  verdict: 'malicious',
  note: 'Credential phishing',
  expectedRowVersion: 3,
  ...patch,
});

const SPECS: Spec[] = [
  { id: 'list', method: 'get', path: () => `${BASE}/reports`, perm: READ, ok: 200 },
  {
    id: 'detail',
    method: 'get',
    path: (c) => `${BASE}/reports/${c.report.publicId}`,
    perm: READ,
    ok: 200,
  },
  {
    id: 'triage',
    method: 'post',
    path: (c) => `${BASE}/reports/${c.report.publicId}/triage`,
    perm: WRITE,
    keyed: true,
    body: () => triageBody(),
    ok: 200,
  },
  {
    id: 'clawback',
    method: 'post',
    path: (c) => `${BASE}/reports/${c.report.publicId}/clawback`,
    perm: PURGE,
    keyed: true,
    body: () => ({ reason: 'Remove it everywhere' }),
    ok: 202,
  },
  {
    id: 'listMailboxes',
    method: 'get',
    path: () => `${BASE}/report-mailboxes`,
    perm: READ,
    ok: 200,
  },
  {
    id: 'addMailbox',
    method: 'post',
    path: () => `${BASE}/report-mailboxes`,
    perm: WRITE,
    keyed: true,
    body: () => ({ address: 'Alex@Contoso.Example', reason: 'Users forward phishing here' }),
    ok: 200,
  },
  {
    id: 'setMailbox',
    method: 'put',
    path: (c) => `${BASE}/mailboxes/${c.alex.publicId}/report-mailbox`,
    perm: WRITE,
    keyed: true,
    body: () => ({ enabled: true, reason: 'Users forward phishing here' }),
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
  const m365: StoredConnection = world.addConnection(org, { displayName: 'Contoso 365' });
  m365.api = world.apiRow({ healthStatus: 'healthy' });
  world.addDomain(org, 'contoso.example', { connectionId: m365.id, configured: 'api' });
  world.addDomain(org, 'inline.example', { connectionId: m365.id, configured: 'inline' });
  world.addDomain(org, 'fresh.example', { connectionId: m365.id, configured: 'hybrid' });
  const reportMailbox = world.addMailbox(m365, 'report-phishing@contoso.example', {
    status: 'disabled',
  });
  const alex = world.addMailbox(m365, 'alex@contoso.example');
  const inlineMailbox = world.addMailbox(m365, 'ops@inline.example');
  world.claw.reportMailboxes.set(reportMailbox.id, new Date(Date.now() - 86_400_000));
  const foreignConnection = world.addConnection(OTHER_ORG, { displayName: 'Other' });
  const foreignMailbox = world.addMailbox(foreignConnection, 'eve@other.example');
  const report = seedReport(world, reportMailbox);
  const sibling = seedReport(world, reportMailbox, {
    reporterAddress: 'kim@contoso.example',
    reportedAt: new Date(Date.now() - 60_000),
    rowVersion: 2,
  });
  const parsing = seedReport(world, reportMailbox, {
    status: 'parsing',
    groupKey: null,
    original: null,
    identification: null,
    reportedAt: new Date(Date.now() - 180_000),
  });
  const noOriginal = seedReport(world, reportMailbox, {
    identification: 'none',
    original: null,
    groupKey: null,
    reportedAt: new Date(Date.now() - 240_000),
  });
  const foreign = seedReport(world, foreignMailbox);
  return {
    reportMailbox,
    alex,
    inlineMailbox,
    foreignMailbox,
    report,
    sibling,
    parsing,
    noOriginal,
    foreign,
  };
}

describe('API-mode report routes (e2e, dependencies stubbed)', () => {
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
  const feedback = () =>
    world.claw.outbox.filter((o) => o.eventType === EventTypes.ReportFeedbackRequested);

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

    it('a read-only user is refused every write and reads every view', async () => {
      const readOnly = [READ, 'organization:read', 'domain:read', 'quarantine:read'];
      for (const s of SPECS) {
        const res = await send(s, { perms: readOnly });
        if (s.method === 'get') expect(res.status, s.id).toBe(s.ok);
        else expect(res.status, s.id).toBe(403);
      }
      expect(ctx.report.status).toBe('pending_triage');
      expect(world.claw.clawbacks).toHaveLength(0);
      expect(world.claw.reportMailboxes.size).toBe(1);
    });

    it('API keys with remediation:* use every route', async () => {
      for (const s of SPECS) {
        world.reset();
        world.claw.audit = audit.entries;
        store.rows.clear();
        ctx = seedWorld(world, org, api.principals.ids.org, api.principals.ids.user);
        const res = await send(s, { apiKey: ALL });
        expect(res.status, `${s.id} ${JSON.stringify(res.body)}`).toBe(s.ok);
      }
    });

    it('another organization’s reports and mailboxes answer 404 like unknown ids', async () => {
      const id = ctx.foreign.publicId;
      for (const [method, path, body] of [
        ['get', `${BASE}/reports/${id}`],
        ['get', `${BASE}/reports/${randomUUID()}`],
        ['post', `${BASE}/reports/${id}/triage`, triageBody()],
        ['post', `${BASE}/reports/${id}/clawback`, { reason: 'x' }],
      ] as Array<[Method, string, object?]>) {
        const res = await call(method, path, body);
        expect(res.status, path).toBe(404);
        expect(res.body.code, path).toBe('api_mode_report_not_found');
      }
      const mailbox = await call(
        'put',
        `${BASE}/mailboxes/${ctx.foreignMailbox.publicId}/report-mailbox`,
        { enabled: true, reason: 'x' },
      );
      expect(mailbox.status).toBe(404);
      expect(mailbox.body.code).toBe('api_mode_mailbox_not_found');
      const byAddress = await call('post', `${BASE}/report-mailboxes`, {
        address: 'eve@other.example',
        reason: 'x',
      });
      expect(byAddress.status).toBe(422);
      expect(byAddress.body.code).toBe('api_mode_report_address_out_of_scope');
      const list = await call('get', `${BASE}/reports`);
      expect(list.body.data.map((r: { id: string }) => r.id)).not.toContain(id);
      expect(ctx.foreign.status).toBe('pending_triage');
    });
  });

  describe('list and detail (C14 #11, #12)', () => {
    it('v1 cursor pages, filters and group sizes', async () => {
      const first = await api
        .http()
        .get(`${BASE}/reports`)
        .query({ limit: '2' })
        .set(await asUser([READ]));
      expect(first.body.data.map((r: { id: string }) => r.id)).toEqual([
        ctx.sibling.publicId,
        ctx.report.publicId,
      ]);
      expect(first.body.data[0]).toMatchObject({ groupSize: 2, assessment: 'malicious' });
      const second = await api
        .http()
        .get(`${BASE}/reports`)
        .query({ limit: '2', cursor: first.body.nextCursor })
        .set(await asUser([READ]));
      expect(second.body.data.map((r: { id: string }) => r.id)).toEqual([
        ctx.parsing.publicId,
        ctx.noOriginal.publicId,
      ]);
      expect(second.body.data[0].groupSize).toBe(1);
      const rebound = await api
        .http()
        .get(`${BASE}/reports`)
        .query({ limit: '2', status: 'parsing', cursor: first.body.nextCursor })
        .set(await asUser([READ]));
      expect(rebound.status).toBe(400);
      const byReporter = await api
        .http()
        .get(`${BASE}/reports`)
        .query({ reporter: 'KIM@contoso.example', status: 'pending_triage' })
        .set(await asUser([READ]));
      expect(byReporter.body.data.map((r: { id: string }) => r.id)).toEqual([ctx.sibling.publicId]);
    });

    it('detail: original keys (hash truncated), group members, feedback, empty history', async () => {
      const res = await send(spec('detail'));
      expect(res.body).toMatchObject({
        reporter: { address: 'sam@contoso.example' },
        reportMailbox: { id: ctx.reportMailbox.publicId },
        original: {
          messageIdHash: `${'cd'.repeat(6)}…`,
          sender: 'billing@fabrikam.example',
          subjectKey: 'Invoice overdue',
          attachmentCount: 1,
          urlCount: 1,
        },
        group: { size: 2, members: [expect.objectContaining({ id: ctx.sibling.publicId })] },
        history: [],
        feedback: { acknowledgement: 'queued', result: 'none' },
      });
      const none = await call('get', `${BASE}/reports/${ctx.noOriginal.publicId}`);
      expect(none.body).toMatchObject({ original: null, group: { size: 1, members: [] } });
    });
  });

  describe('triage (C14 #13, C11)', () => {
    it('resolve with the group: both resolved, one feedback row each, counters and history', async () => {
      const res = await send(spec('triage'));
      expect(res.body).toMatchObject({
        report: { status: 'resolved', analystVerdict: 'malicious', rowVersion: 4 },
        groupResolved: 1,
        feedbackQueued: 2,
      });
      expect(ctx.sibling).toMatchObject({ status: 'resolved', resultFeedback: 'queued' });
      expect(
        feedback()
          .map((o) => (o.payload as { reportId: string }).reportId)
          .sort(),
      ).toEqual([ctx.report.publicId, ctx.sibling.publicId].sort());
      expect(feedback()[0]!.payload).toMatchObject({ kind: 'resolved' });
      expect(Object.keys(feedback()[0]!.payload as object).sort()).toEqual([
        'kind',
        'reportId',
        'requestedAt',
      ]);
      expect(world.claw.resolvedCounters).toEqual([
        { apiConnectionId: ctx.report.apiConnectionId, n: 2 },
      ]);
      const rows = audit.entries.filter((e) => e.action === 'api_mode.report_triaged');
      expect(rows).toHaveLength(2);
      expect(JSON.stringify(rows.map((r) => r.metadata))).not.toContain('Credential phishing');
      const detail = await send(spec('detail'));
      expect(detail.body.analyst).toMatchObject({
        verdict: 'malicious',
        note: 'Credential phishing',
        triagedBy: api.principals.ids.user,
      });
      expect(detail.body.history).toEqual([
        expect.objectContaining({ from: 'pending_triage', to: 'resolved', verdict: 'malicious' }),
      ]);
    });

    it('applyToGroup false and notifyReporter false: only this report, no feedback', async () => {
      const res = await send(spec('triage'), {
        body: triageBody({ applyToGroup: false, notifyReporter: false }),
      });
      expect(res.body).toMatchObject({ groupResolved: 0, feedbackQueued: 0 });
      expect(ctx.report.resultFeedback).toBe('skipped');
      expect(ctx.sibling.status).toBe('pending_triage');
      expect(feedback()).toHaveLength(0);
    });

    it('the organization feedback setting is the default of notifyReporter', async () => {
      world.claw.settings.set(org, {
        internalMailEnabled: true,
        autoClawback: 'enforce',
        autoMaxMailboxes: 500,
        purgeApprovalMailboxes: 50,
        clawbackLookbackDays: 14,
        tiMinConfidence: 80,
        reportAckEnabled: true,
        reportFeedbackEnabled: false,
        rowVersion: 1,
        updatedAt: new Date(),
        purgeApprovalRaisedBy: null,
        purgeApprovalBeforeRaise: null,
      });
      const res = await send(spec('triage'));
      expect(res.body.feedbackQueued).toBe(0);
    });

    it('verdict rules (400), CAS and state (409), reopen once', async () => {
      expect(
        (await send(spec('triage'), { body: triageBody({ verdict: undefined }) })).status,
      ).toBe(400);
      expect(
        (await send(spec('triage'), { body: triageBody({ status: 'in_review' }) })).status,
      ).toBe(400);
      const stale = await send(spec('triage'), { body: triageBody({ expectedRowVersion: 2 }) });
      expect(stale.status).toBe(409);
      expect(stale.body).toMatchObject({
        code: 'api_mode_report_state_conflict',
        status: 'pending_triage',
        currentRowVersion: 3,
      });
      const parsing = await call(
        'post',
        `${BASE}/reports/${ctx.parsing.publicId}/triage`,
        triageBody(),
      );
      expect(parsing.status).toBe(409);
      expect(parsing.body.status).toBe('parsing');
      await send(spec('triage'), { body: triageBody({ applyToGroup: false }) });
      const reopen = await send(spec('triage'), {
        body: { status: 'in_review', expectedRowVersion: 4 },
      });
      expect(reopen.body.report.status).toBe('in_review');
      const resolveAgain = await send(spec('triage'), {
        body: triageBody({ expectedRowVersion: 5 }),
      });
      expect(resolveAgain.body.report.status).toBe('resolved');
      const reopenTwice = await send(spec('triage'), {
        body: { status: 'in_review', expectedRowVersion: 6 },
      });
      expect(reopenTwice.status).toBe(409);
      expect(reopenTwice.body.code).toBe('api_mode_report_not_reopenable');
    });

    it('reject is a dismissal with analyst_rejected; replay returns the stored answer', async () => {
      const key = randomUUID();
      const first = await send(spec('triage'), {
        key,
        body: { status: 'rejected', expectedRowVersion: 3 },
      });
      expect(first.body.report).toMatchObject({
        status: 'rejected',
        rejectReason: 'analyst_rejected',
      });
      const replay = await send(spec('triage'), {
        key,
        body: { status: 'rejected', expectedRowVersion: 3 },
      });
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body).toEqual(first.body);
      expect(ctx.sibling.status).toBe('pending_triage');
    });
  });

  describe('clawback from a report (C14 #14, C11.5)', () => {
    it('Message-ID clawback (report) and an expanded one (campaign), linked to the report', async () => {
      const res = await send(spec('clawback'));
      expect(res.body).toMatchObject({
        reportId: ctx.report.publicId,
        status: 'searching',
        trigger: 'report',
      });
      const row = world.claw.clawbacks.find((k) => k.publicId === res.body.clawbackId)!;
      expect(row).toMatchObject({ reportId: ctx.report.id, trigger: 'report' });
      expect((row.criteria as { keys: object }).keys).toEqual({
        messageIdHashes: ['cd'.repeat(32)],
      });
      expect((row.signal as { refs: object }).refs).toEqual({ reportId: ctx.report.publicId });
      expect(ctx.report.clawbackId).toBe(row.id);
      const campaign = await call('post', `${BASE}/reports/${ctx.sibling.publicId}/clawback`, {
        expand: { attachments: true, urls: true, senderSubjectHours: 24 },
        reason: 'Campaign',
      });
      expect(campaign.body.trigger).toBe('campaign');
      expect(audit.entries.map((e) => e.action)).toEqual([
        'api_mode.report_clawback_requested',
        'api_mode.clawback_created',
        'api_mode.report_clawback_requested',
        'api_mode.clawback_created',
      ]);
      const detail = await send(spec('detail'));
      expect(detail.body.clawbackId).toBe(res.body.clawbackId);
    });

    it('an unidentified original → 409; a rejected report → 409; nothing is created', async () => {
      const unknown = await call('post', `${BASE}/reports/${ctx.noOriginal.publicId}/clawback`, {
        reason: 'x',
      });
      expect(unknown.status).toBe(409);
      expect(unknown.body.code).toBe('api_mode_report_original_unknown');
      ctx.report.status = 'rejected';
      const rejected = await send(spec('clawback'));
      expect(rejected.status).toBe(409);
      expect(rejected.body.code).toBe('api_mode_report_state_conflict');
      expect(world.claw.clawbacks).toHaveLength(0);
    });
  });

  describe('report mailboxes (C14 #15-#17, C9.1)', () => {
    it('list: designated mailboxes with the limit and the last report', async () => {
      const res = await send(spec('listMailboxes'));
      expect(res.body.max).toBe(5);
      expect(res.body.data).toEqual([
        expect.objectContaining({
          id: ctx.reportMailbox.publicId,
          address: 'report-phishing@contoso.example',
          status: 'disabled',
          reportMailbox: true,
          lastReportAt: expect.any(String),
        }),
      ]);
    });

    it('set: designate and clear (no-op twice), not eligible for an inline domain', async () => {
      const on = await send(spec('setMailbox'));
      expect(on.body).toMatchObject({ changed: true, mailbox: { reportMailbox: true } });
      const again = await send(spec('setMailbox'));
      expect(again.body.changed).toBe(false);
      const off = await send(spec('setMailbox'), { body: { enabled: false, reason: 'Done' } });
      expect(off.body).toMatchObject({ changed: true, mailbox: { reportMailbox: false } });
      const inline = await call(
        'put',
        `${BASE}/mailboxes/${ctx.inlineMailbox.publicId}/report-mailbox`,
        { enabled: true, reason: 'x' },
      );
      expect(inline.status).toBe(409);
      expect(inline.body).toMatchObject({
        code: 'api_mode_report_mailbox_not_eligible',
        cause: 'domain_not_api',
      });
      expect(
        audit.entries.filter((e) => e.action === 'api_mode.report_mailbox_updated'),
      ).toHaveLength(2);
    });

    it('add by address: a known mailbox, a new discovered mailbox, out of scope, the limit', async () => {
      const known = await send(spec('addMailbox'));
      expect(known.body).toMatchObject({
        created: false,
        changed: true,
        mailbox: { id: ctx.alex.publicId, reportMailbox: true },
      });
      const fresh = await call('post', `${BASE}/report-mailboxes`, {
        address: 'abuse@fresh.example',
        reason: 'x',
      });
      expect(fresh.body).toMatchObject({
        created: true,
        mailbox: { address: 'abuse@fresh.example', status: 'discovered', reportMailbox: true },
      });
      for (const address of ['nobody@unknown.example', 'ops2@inline.example', 'not-an-address']) {
        const res = await call('post', `${BASE}/report-mailboxes`, { address, reason: 'x' });
        expect([400, 422], address).toContain(res.status);
        if (res.status === 422) expect(res.body.code).toBe('api_mode_report_address_out_of_scope');
      }
      // 3 designated now; two more reach the limit of 5.
      for (const n of ['a1', 'a2']) {
        const ok = await call('post', `${BASE}/report-mailboxes`, {
          address: `${n}@fresh.example`,
          reason: 'x',
        });
        expect(ok.status).toBe(200);
      }
      const limit = await call('post', `${BASE}/report-mailboxes`, {
        address: 'a3@fresh.example',
        reason: 'x',
      });
      expect(limit.status).toBe(409);
      expect(limit.body).toMatchObject({ code: 'api_mode_report_mailbox_limit', max: 5 });
      expect(world.mailboxes.some((m) => m.primaryAddress === 'a3@fresh.example')).toBe(false);
    });
  });
});
