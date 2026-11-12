/**
 * Quarantine API (step 5.3 WP4, Q7, Q9–Q18, Q24, Q30) against the real MySQL writer and
 * replica, Redis and MinIO, with messages, rounds and entries put in place by SQL fixtures (the
 * policy-engine writes entries in production): search filters, keyset pagination and the
 * EXPLAIN plans of the search shapes on a seeded organization; detail, history and their audit
 * rows; the sanitized, DLP-masked preview of stored parts; download grants (re-authorization,
 * single use, expiry, binding, malware gating); the release pre-check outcomes; approvals and
 * separation of duties; reject, delete under a legal hold and retention; manual quarantine; bulk
 * limits and partial failures; self-service scoping; the Q30 operator release; the tenant purge.
 *
 * `QUARANTINE_PERF_ROWS` (default 50 000) sets the size of the seeded organization of the plan
 * check; the 1 000 000-row run is opt-in (`QUARANTINE_PERF_ROWS=1000000`).
 */
import { randomUUID } from 'node:crypto';
import { type PrismaReadService } from '@email-gateway/common';
import { loadQuarantineEntries, PrismaClient } from '@email-gateway/database';
import { EventTypes, quarantineReleaseRequestedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { QuarantineReadRepository } from '../src/modules/quarantine/repositories/quarantine-read.repository';
import {
  QuarantinePurgeRefusedError,
  QuarantineTenantDataRepository,
} from '../src/modules/tenant-data/quarantine-tenant-data.repository';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
  uniqueSuffix,
  unknownId,
} from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa } from './support/http';
import { insertLifecycleMessage, LifecycleApi, type LifecycleMessage } from './support/lifecycle';
import { pauseLiveRelay } from './support/live-relay';
import {
  deleteObjects,
  deleteQuarantineFixtures,
  type EntryOptions,
  type FixtureEntry,
  insertApproval,
  insertCompletedRound,
  insertEntry,
  insertParse,
  putObject,
  QuarantineApi,
  windowAround,
} from './support/quarantine';

const PERF_ROWS = Number(process.env.QUARANTINE_PERF_ROWS ?? '50000');
const reason = 'reviewed by the security team';

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let perfOrg: FixtureOrganization | undefined;
let admin: FixtureUser;
let admin2: FixtureUser;
let analyst: FixtureUser;
let reviewer: FixtureUser;
let mailbox: FixtureUser;
let adminApi: QuarantineApi;
let admin2Api: QuarantineApi;
let analystApi: QuarantineApi;
let reviewerApi: QuarantineApi;
let mailboxApi: QuarantineApi;
let readerKeyApi: QuarantineApi;
let adminBApi: QuarantineApi;
const objects: string[] = [];
let resumeLiveRelay: (() => Promise<void>) | undefined;

const tokenOf = async (user: FixtureUser) =>
  bearer((await loginWithMfa(ctx, fx, user)).accessToken);

const audits = (org: FixtureOrganization, action: string, resourceId?: string) =>
  ctx.prisma.auditLog.findMany({
    where: { organizationId: org.id, action, ...(resourceId !== undefined && { resourceId }) },
    orderBy: { id: 'asc' },
  });

const entryRow = (publicId: string) =>
  ctx.prisma.quarantineMessage.findFirstOrThrow({ where: { publicId } });

async function message(
  org: FixtureOrganization,
  options: Parameters<typeof insertLifecycleMessage>[2],
): Promise<LifecycleMessage> {
  return insertLifecycleMessage(ctx, org, options);
}

/** A held entry on a fresh `quarantined` message (one recipient). */
async function heldEntry(
  org: FixtureOrganization,
  o: EntryOptions & { recipient?: string; messageState?: 'quarantined' | 'held_for_review' } = {},
): Promise<{ message: LifecycleMessage; entry: FixtureEntry }> {
  const m = await message(org, {
    state: o.messageState ?? 'quarantined',
    direction: o.direction ?? 'inbound',
    recipients: [
      { address: o.recipient ?? `rcpt-${uniqueSuffix()}@acme.example`, status: 'quarantined' },
    ],
  });
  const { messageState: _s, recipient: _r, ...entryOptions } = o;
  return {
    message: m,
    entry: await insertEntry(ctx, m, { direction: o.direction, ...entryOptions }),
  };
}

/** A valid Luhn card number that is not one of the well-known test numbers. */
function cardNumber(): string {
  const body = '453914880343646';
  // Luhn check digit for the 15 given digits.
  let sum = 0;
  const payload = body.split('').map(Number);
  for (let i = 0; i < payload.length; i += 1) {
    let d = payload[payload.length - 1 - i]!;
    if (i % 2 === 0) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return `${body}${(10 - (sum % 10)) % 10}`;
}

beforeAll(async () => {
  resumeLiveRelay = await pauseLiveRelay();
  ctx = await createIntegrationApp({
    QUARANTINE_BULK_MAX_ITEMS: '5',
    QUARANTINE_BULK_MAX_ITEMS_PER_MINUTE: '10',
  });
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  fx.registerCleanup(async () => {
    await deleteObjects(objects);
    await deleteQuarantineFixtures(ctx, [orgA.id, orgB.id, ...(perfOrg ? [perfOrg.id] : [])]);
  });
  admin = await fx.createUser(orgA, { roles: ['organization_admin'], mfa: true });
  admin2 = await fx.createUser(orgA, { roles: ['organization_admin'], mfa: true });
  analyst = await fx.createUser(orgA, { roles: ['security_analyst'], mfa: true });
  reviewer = await fx.createUser(orgA, { roles: ['quarantine_reviewer'], mfa: true });
  mailbox = await fx.createUser(orgA, {
    roles: ['mailbox_user'],
    email: `mailbox-${uniqueSuffix()}@acme.example`,
  });
  const adminB = await fx.createUser(orgB, { roles: ['organization_admin'], mfa: true });
  adminApi = new QuarantineApi(ctx, await tokenOf(admin));
  admin2Api = new QuarantineApi(ctx, await tokenOf(admin2));
  analystApi = new QuarantineApi(ctx, await tokenOf(analyst));
  reviewerApi = new QuarantineApi(ctx, await tokenOf(reviewer));
  mailboxApi = new QuarantineApi(ctx, await tokenOf(mailbox));
  adminBApi = new QuarantineApi(ctx, await tokenOf(adminB));
  readerKeyApi = new QuarantineApi(
    ctx,
    apiKeyHeader(await fx.createApiKey(orgA, ['quarantine:read'])),
  );
}, 240_000);

afterAll(async () => {
  try {
    await fx?.cleanup();
    await ctx?.close();
  } finally {
    await resumeLiveRelay?.();
  }
}, 1_800_000);

describe('search (Q9)', () => {
  it('filters, keyset pagination, subject visibility, tenant isolation and one audit row', async () => {
    const policyId = randomUUID();
    const base = Date.now() - 3_600_000;
    const at = (n: number) => new Date(base + n * 1000);
    const a = await heldEntry(orgA, {
      quarantinedAt: at(1),
      reason: 'spam',
      recipient: 'p1@acme.example',
    });
    const b = await heldEntry(orgA, {
      quarantinedAt: at(2),
      reason: 'phishing',
      riskLevel: 'high',
      hardBlocks: ['hb.phishing.url'],
      recipient: 'p2@acme.example',
    });
    const c = await heldEntry(orgA, {
      quarantinedAt: at(3),
      reason: 'policy',
      decisivePolicyPublicId: policyId,
      recipient: 'p3@acme.example',
      envelopeFrom: 'boss@partner.example',
    });
    const d = await heldEntry(orgA, {
      quarantinedAt: at(3),
      reason: 'bulk',
      recipient: 'p4@acme.example',
    });
    await ctx.prisma.quarantineMessage.update({
      where: { id: d.entry.id },
      data: { status: 'rejected' },
    });
    await ctx.prisma.emailMessage.updateMany({
      where: { id: a.message.id },
      data: { subject: 'Hello‮ there' },
    });
    const other = await heldEntry(orgB, { quarantinedAt: at(2), recipient: 'p1@acme.example' });
    const w = {
      from: new Date(base - 60_000).toISOString(),
      to: new Date(base + 60_000).toISOString(),
    };

    const all = await analystApi.get('/entries', w).expect(200);
    expect(all.headers['cache-control']).toBe('no-store');
    const ids = all.body.items.map((i: { id: string }) => i.id) as string[];
    expect(ids).toHaveLength(4);
    expect(ids).not.toContain(other.entry.publicId);
    // (quarantinedAt DESC, id DESC): the two at(3) entries first (higher id first), then b, a.
    expect(ids.slice(2)).toEqual([b.entry.publicId, a.entry.publicId]);
    const first = all.body.items.find((i: { id: string }) => i.id === a.entry.publicId);
    expect(first).toMatchObject({
      messageId: a.message.publicId,
      state: 'held',
      reason: 'spam',
      recipient: 'p1@acme.example',
      subject: 'Hello there',
    });

    // Filters.
    const q = async (extra: Record<string, string>) =>
      (
        (await analystApi.get('/entries', { ...w, ...extra }).expect(200)).body.items as Array<{
          id: string;
        }>
      ).map((i) => i.id);
    expect(await q({ state: 'rejected' })).toEqual([d.entry.publicId]);
    expect(await q({ reason: 'phishing,policy' })).toEqual([c.entry.publicId, b.entry.publicId]);
    expect(await q({ recipient: 'P2@ACME.EXAMPLE' })).toEqual([b.entry.publicId]);
    expect(await q({ sender: 'boss@partner.example' })).toEqual([c.entry.publicId]);
    expect(await q({ senderDomain: 'partner.example' })).toEqual([c.entry.publicId]);
    expect(await q({ policyId })).toEqual([c.entry.publicId]);
    expect(await q({ hasHardBlock: 'true' })).toEqual([b.entry.publicId]);
    expect(await q({ minRiskLevel: 'high' })).toEqual([b.entry.publicId]);
    expect(await q({ messageId: a.message.publicId })).toEqual([a.entry.publicId]);
    expect(await q({ messageId: other.message.publicId })).toEqual([]);

    // Keyset pagination: 2 + 2, the cursor bound to the filters.
    const p1 = await analystApi.get('/entries', { ...w, limit: '2' }).expect(200);
    expect(p1.body.items).toHaveLength(2);
    expect(p1.body.nextCursor).toEqual(expect.any(String));
    const p2 = await analystApi
      .get('/entries', { ...w, limit: '2', cursor: p1.body.nextCursor })
      .expect(200);
    expect([...p1.body.items, ...p2.body.items].map((i: { id: string }) => i.id)).toEqual(ids);
    expect(p2.body.nextCursor).toBeNull();
    const wrong = await analystApi
      .get('/entries', { ...w, limit: '2', reason: 'spam', cursor: p1.body.nextCursor })
      .expect(400);
    expect(wrong.body.code).toBe('quarantine_cursor_invalid');
    const tooWide = await analystApi
      .get('/entries', { from: new Date(base - 63 * 86_400_000).toISOString(), to: w.to })
      .expect(400);
    expect(tooWide.body.code).toBe('quarantine_search_range_invalid');
    await analystApi.get('/entries', { from: w.from }).expect(400);

    // Subjects only for quarantine:preview holders (the reviewer has none; an API key neither).
    const asReviewer = await reviewerApi.get('/entries', w).expect(200);
    expect(asReviewer.body.items.every((i: { subject: unknown }) => i.subject === null)).toBe(true);
    await readerKeyApi.get('/entries', w).expect(200);

    // Another tenant never sees these entries, and their ids are 404 there.
    const asB = await adminBApi.get('/entries', w).expect(200);
    expect(asB.body.items.map((i: { id: string }) => i.id)).toEqual([other.entry.publicId]);
    expect((await adminBApi.get(`/entries/${a.entry.publicId}`).expect(404)).body.code).toBe(
      'quarantine_entry_not_found',
    );

    // One audit row per search, filter hash and count only (never the addresses).
    const searched = await audits(orgA, 'quarantine.searched');
    expect(searched.length).toBeGreaterThanOrEqual(10);
    const json = JSON.stringify(searched.map((r) => r.metadata));
    expect(json).not.toContain('acme.example');
    expect(json).not.toContain('partner.example');
    expect(searched.at(-1)!.metadata).toMatchObject({
      filterHash: expect.any(String),
      self: false,
    });
  });

  it(`EXPLAIN: the api's search SQL uses the (organization_id, …, quarantined_at) indexes on ${PERF_ROWS} rows`, async () => {
    perfOrg = await fx.createOrganization();
    const started = Date.now();
    const loaded = await loadQuarantineEntries(ctx.prisma, {
      organizationId: perfOrg.id,
      count: PERF_ROWS,
      now: new Date(),
      days: 60,
      firstMessageId: 8_000_000_000_000n + BigInt(Math.floor(Math.random() * 1e9)) * 1000n,
    });
    expect(loaded.rows).toBeGreaterThanOrEqual(PERF_ROWS);
    await ctx.prisma.$executeRawUnsafe('ANALYZE TABLE quarantine_messages');
    const loadMs = Date.now() - started;

    // The repository's own SQL, captured from a logging client on the writer.
    const logging = new PrismaClient({
      datasourceUrl: process.env.DATABASE_URL,
      log: [{ emit: 'event', level: 'query' }],
    });
    const queries: Array<{ query: string; params: string }> = [];
    logging.$on('query', (e) => queries.push({ query: e.query, params: e.params }));
    try {
      const repo = new QuarantineReadRepository(
        { client: logging } as unknown as PrismaReadService,
        ctx.prisma,
      );
      const scope = systemScope(perfOrg.id);
      const range = {
        from: new Date(loaded.sample.from),
        to: new Date(loaded.sample.to),
        take: 51,
      };
      const shapes: Array<[string, Parameters<QuarantineReadRepository['search']>[1], RegExp]> = [
        [
          'default view',
          range,
          /organization_id_quarantined_at_id_idx|organization_id_status_quarantined_at_id_idx/,
        ],
        [
          'recipient',
          { ...range, recipient: loaded.sample.recipient },
          /recipient_address_quaran_idx/,
        ],
        ['sender', { ...range, sender: loaded.sample.sender }, /envelope_from_quarantine_idx/],
        // A rare state: the status index or the ordered default index with a row filter (both
        // organization-leading and ordered by quarantined_at; the optimizer picks by statistics).
        [
          'state',
          { ...range, states: ['pending_approval'] },
          /organization_id_(status_)?quarantined_at_id_idx/,
        ],
        [
          'decisive policy',
          { ...range, policyId: loaded.sample.policyPublicId },
          /decisive_policy_public_i_idx/,
        ],
      ];
      const plans: Record<string, { key: string | null; rows: number; extra: string }> = {};
      for (const [label, filter, expectedKey] of shapes) {
        queries.length = 0;
        const found = await repo.search(scope, filter);
        expect(found.length, label).toBeGreaterThan(0);
        const select = queries.find((qq) => /FROM `[^`]+`\.`quarantine_messages`/.test(qq.query));
        expect(select, label).toBeDefined();
        const params = (JSON.parse(select!.params) as unknown[]).map((p) =>
          typeof p === 'string' && /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)? UTC$/.test(p)
            ? new Date(p.replace(' UTC', 'Z').replace(' ', 'T'))
            : p,
        );
        // Prisma returns the EXPLAIN columns positionally (f0…f11): f6 key, f9 rows, f11 Extra.
        const rows = await ctx.prisma.$queryRawUnsafe<Array<Record<string, unknown>>>(
          `EXPLAIN ${select!.query}`,
          ...params,
        );
        const raw = rows[0]!;
        const plan = {
          key: (raw.f6 as string | null) ?? null,
          rows: Number(raw.f9),
          Extra: (raw.f11 as string | null) ?? '',
        };
        plans[label] = { key: plan.key, rows: plan.rows, extra: plan.Extra };
        expect(plan.key ?? '', `${label}: ${JSON.stringify(plans[label])}`).toMatch(expectedKey);
        expect(plan.Extra, label).not.toContain('Using filesort');
      }
      // Recorded in the package note (rows estimate and keys per shape).
      process.stdout.write(
        `${JSON.stringify({ quarantinePlanCheck: { rows: loaded.rows, loadMs, plans } })}\n`,
      );
    } finally {
      await logging.$disconnect();
      // The seeded rows go now, in large batches (the tenant purge's 500-row batches would make
      // the shared cleanup hook slow for the opt-in 1 000 000-row run).
      for (;;) {
        const deleted = await ctx.prisma.$executeRaw`DELETE FROM quarantine_messages
          WHERE organization_id = ${perfOrg.id} LIMIT 50000`;
        if (deleted < 50_000) break;
      }
      // The replica applies the bulk insert and delete with a delay; the next tests read the
      // replica (detail, preview, pre-check, settings, self routes) right after their own
      // writer inserts, so wait until it has executed everything the writer has (GTID set).
      await waitForReplica();
    }
  }, 1_800_000);
});

/** Waits until the replica has executed the writer's GTID set (≤ 120 s; WP5 regression). */
async function waitForReplica(): Promise<void> {
  const [gtidRow] = await ctx.prisma.$queryRaw<
    Array<{ gtid: string }>
  >`SELECT @@GLOBAL.gtid_executed AS gtid`;
  const reader = new PrismaClient({ datasourceUrl: process.env.DATABASE_READ_URL });
  try {
    const [waited] = await reader.$queryRaw<
      Array<{ timedOut: bigint | number }>
    >`SELECT WAIT_FOR_EXECUTED_GTID_SET(${gtidRow!.gtid}, 120) AS timedOut`;
    if (Number(waited!.timedOut) !== 0)
      throw new Error('the replica did not catch up within 120 s');
  } finally {
    await reader.$disconnect();
  }
}

describe('detail, history (Q10) and settings (Q24)', () => {
  it('detail has allowedActions, writes a view action and an audit row; history lists actions', async () => {
    const { entry } = await heldEntry(orgA);
    // GET /entries/{id} reads the replica: wait for the fixture rows to replicate.
    await waitForReplica();
    const res = await analystApi.get(`/entries/${entry.publicId}`).expect(200);
    expect(res.body).toMatchObject({
      id: entry.publicId,
      state: 'held',
      contentAvailable: true,
      allowedActions: ['preview', 'release', 'reject', 'delete'],
    });
    expect(res.body.explanation.lines).toHaveLength(1);
    const reviewerView = await reviewerApi.get(`/entries/${entry.publicId}`).expect(200);
    expect(reviewerView.body.allowedActions).toEqual([
      'release',
      'request_release',
      'reject',
      'delete',
    ]);
    expect((await entryRowActions(entry)).filter((a) => a === 'view')).toHaveLength(2);
    expect(await audits(orgA, 'quarantine.entry_viewed', entry.publicId)).toHaveLength(2);
    const history = await readerKeyApi.get(`/entries/${entry.publicId}/history`).expect(200);
    expect(history.body.actions.map((a: { action: string }) => a.action)).toEqual(['view', 'view']);
    await mailboxApi.get(`/entries/${entry.publicId}`).expect(403);
  });

  it('settings: GET effective/raw/bounds, PUT with CAS and violations by path', async () => {
    const before = await adminApi.get('/settings').expect(200);
    expect(before.body.effective.download.enabled).toBe(false);
    const bad = await adminApi
      .put('/settings', {
        settings: { review: { days: 99 }, nope: true },
        expectedRowVersion: before.body.rowVersion,
      })
      .expect(400);
    expect(bad.body.code).toBe('quarantine_settings_invalid');
    expect(bad.body.violations.map((v: { path: string }) => v.path)).toEqual([
      'nope',
      'review.days',
    ]);
    const ok = await adminApi
      .put('/settings', {
        settings: { endUser: { selfRelease: true, selfReleaseReasons: ['spam'] } },
        expectedRowVersion: before.body.rowVersion,
      })
      .expect(200);
    expect(ok.body.effective.endUser.selfRelease).toBe(true);
    const stale = await adminApi
      .put('/settings', { settings: {}, expectedRowVersion: before.body.rowVersion })
      .expect(409);
    expect(stale.body.code).toBe('quarantine_settings_conflict');
    const audit = await audits(orgA, 'quarantine.settings_updated');
    expect(audit.at(-1)!.metadata).toMatchObject({
      changedPaths: ['endUser.selfRelease', 'endUser.selfReleaseReasons'],
    });
    await analystApi
      .put('/settings', { settings: {}, expectedRowVersion: ok.body.rowVersion })
      .expect(403);
  });
});

async function entryRowActions(entry: FixtureEntry): Promise<string[]> {
  const rows = await ctx.prisma.quarantineAction.findMany({
    where: { quarantineMessageId: entry.id },
    orderBy: { id: 'asc' },
  });
  return rows.map((r) => r.action);
}

describe('preview (Q11)', () => {
  it('renders stored parts as text: no active content, defanged links, masked card number; audited first', async () => {
    const card = cardNumber();
    const { message: m, entry } = await heldEntry(orgA);
    const htmlKey = `org/${orgA.id.toString()}/part/2026/11/12/${m.id.toString()}/1.html`;
    await putObject(
      objects,
      htmlKey,
      `<html><head><script>alert(1)</script><style>body{background:url(http://track.example/p.gif)}</style></head>` +
        `<body onload="steal()"><p>Pay invoice with card ${card} today.</p>` +
        `<img src="http://tracker.example/pixel.gif"><img src="data:image/png;base64,AAAA">` +
        `<a href="javascript:alert(2)">click</a> <a href="http://evil.example/login">login</a>` +
        `<iframe src="http://evil.example/frame"></iframe></body></html>`,
    );
    await insertParse(ctx, m, { htmlKey, htmlSize: 600 });
    const res = await analystApi.get(`/entries/${entry.publicId}/preview`).expect(200);
    expect(res.headers['cache-control']).toBe('no-store');
    const body = JSON.stringify(res.body);
    for (const forbidden of [
      '<script',
      'alert(1)',
      'onload',
      'data:image',
      'alert(2)',
      '<iframe',
      'http://evil.example',
      'tracker.example/pixel',
      card,
    ]) {
      expect(body, forbidden).not.toContain(forbidden);
    }
    expect(res.body.body.source).toBe('html');
    expect(res.body.body.text).toContain('[image]');
    expect(res.body.body.text).toContain(`${card.slice(0, 6)}`);
    expect(res.body.body.text).toContain(card.slice(-4));
    expect(res.body.dlp.masked).toBeGreaterThanOrEqual(1);
    expect(res.body.links.map((l: { displayUrl: string }) => l.displayUrl)).toContain(
      'hxxp://evil[.]example/login',
    );
    const audit = await audits(orgA, 'quarantine.previewed', entry.publicId);
    expect(audit).toHaveLength(1);
    expect(audit[0]!.metadata).toMatchObject({ bodySource: 'html' });
    expect(JSON.stringify(audit[0]!.metadata)).not.toContain(card);
    expect(await entryRowActions(entry)).toContain('preview');
    await reviewerApi.get(`/entries/${entry.publicId}/preview`).expect(403);
  });

  it('a missing part object is shown as purged; a deleted entry with purged objects is 410', async () => {
    const { message: m, entry } = await heldEntry(orgA);
    await insertParse(ctx, m, {
      textKey: `org/${orgA.id.toString()}/part/missing/${m.id.toString()}/0.text`,
    });
    // The preview reads the entry and the parse rows from the replica.
    await waitForReplica();
    const res = await analystApi.get(`/entries/${entry.publicId}/preview`).expect(200);
    expect(res.body.body).toMatchObject({ source: null, unavailableReason: 'purged' });
    await ctx.prisma.quarantineMessage.update({
      where: { id: entry.id },
      data: { status: 'deleted', objectPurgedAt: new Date() },
    });
    await waitForReplica();
    expect((await analystApi.get(`/entries/${entry.publicId}/preview`).expect(410)).body.code).toBe(
      'quarantine_content_purged',
    );
  });
});

describe('download door (Q12)', () => {
  it('disabled → 403; wrong password → 401 with lockout accounting; grant → single use; binding; expiry; malware gating', async () => {
    const { message: m, entry } = await heldEntry(orgA);
    const eml = Buffer.from('From: a@b.example\r\nSubject: x\r\n\r\nhello\r\n');
    await putObject(objects, m.emlObjectKey, eml);
    await ctx.prisma.emailMessage.updateMany({
      where: { id: m.id },
      data: { sizeBytes: eml.length },
    });
    const grantBody = async (user: FixtureUser, password = user.password, totp = true) => ({
      object: 'eml',
      password,
      ...(totp && { totpCode: await fx.totpNow(user) }),
    });
    const disabled = await adminApi
      .post(
        `/entries/${entry.publicId}/download-grants`,
        await grantBody(admin, admin.password, false),
        null,
      )
      .expect(403);
    expect(disabled.body.code).toBe('quarantine_download_disabled');

    const current = await adminApi.get('/settings').expect(200);
    await adminApi
      .put('/settings', {
        settings: { ...(current.body.raw ?? {}), download: { enabled: true } },
        expectedRowVersion: current.body.rowVersion,
      })
      .expect(200);

    const failedBefore = (await ctx.prisma.user.findUniqueOrThrow({ where: { id: admin.id } }))
      .failedLoginCount;
    const wrong = await adminApi
      .post(
        `/entries/${entry.publicId}/download-grants`,
        await grantBody(admin, 'not-the-password-1!', false),
        null,
      )
      .expect(401);
    expect(wrong.body.code).toBe('quarantine_reauth_failed');
    const failedAfter = (await ctx.prisma.user.findUniqueOrThrow({ where: { id: admin.id } }))
      .failedLoginCount;
    expect(failedAfter).toBe(failedBefore + 1);
    expect(await audits(orgA, 'quarantine.download_refused', entry.publicId)).toHaveLength(1);

    // The analyst holds no quarantine:download.
    await analystApi
      .post(
        `/entries/${entry.publicId}/download-grants`,
        await grantBody(analyst, analyst.password, false),
        null,
      )
      .expect(403);

    const grant = await adminApi
      .post(`/entries/${entry.publicId}/download-grants`, await grantBody(admin), null)
      .expect(201);
    expect(grant.body).toMatchObject({
      filename: `message-${entry.publicId}.eml.bin`,
      sizeBytes: eml.length,
    });
    expect(grant.headers['cache-control']).toBe('no-store');
    // Another user of the same organization cannot use it (binding) …
    const foreign = await admin2Api.get(`/downloads/${grant.body.token}`).expect(404);
    expect(foreign.body.code).toBe('quarantine_download_token_invalid');
    // … the owner downloads once …
    const file = await adminApi
      .get(`/downloads/${grant.body.token}`)
      .buffer(true)
      .parse((res, cb) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => cb(null, Buffer.concat(chunks)));
      })
      .expect(200);
    expect(Buffer.compare(file.body as Buffer, eml)).toBe(0);
    expect(file.headers).toMatchObject({
      'content-type': 'application/octet-stream',
      'content-disposition': `attachment; filename="message-${entry.publicId}.eml.bin"`,
      'x-content-type-options': 'nosniff',
      'cache-control': 'no-store',
      'content-security-policy': "sandbox; default-src 'none'",
    });
    // … and never twice.
    expect((await adminApi.get(`/downloads/${grant.body.token}`).expect(410)).body.code).toBe(
      'quarantine_download_token_used',
    );
    expect(await audits(orgA, 'quarantine.downloaded', entry.publicId)).toHaveLength(1);

    // Expired grant: the row is past expires_at → 404 (the token's own exp is still ahead).
    const late = await adminApi
      .post(`/entries/${entry.publicId}/download-grants`, await grantBody(admin), null)
      .expect(201);
    await ctx.prisma.quarantineDownloadGrant.updateMany({
      where: { quarantineMessageId: entry.id, consumedAt: null },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    expect((await adminApi.get(`/downloads/${late.body.token}`).expect(404)).body.code).toBe(
      'quarantine_download_token_invalid',
    );
    // A tampered token.
    await adminApi.get(`/downloads/${late.body.token.slice(0, -2)}AA`).expect(404);

    // Malware gating: a hard-blocked entry is never downloadable.
    const blocked = await heldEntry(orgA, {
      hardBlocks: ['hb.malware.attachment'],
      reason: 'malware',
    });
    const refused = await adminApi
      .post(`/entries/${blocked.entry.publicId}/download-grants`, await grantBody(admin), null)
      .expect(409);
    expect(refused.body).toMatchObject({
      code: 'quarantine_download_blocked',
      reason: 'hard_block',
    });
  }, 180_000);
});

describe('release with the pre-check (Q13.1) and the Q30 operator release', () => {
  it('no completed round → approval_requested (no_scan_round); a fresh clean round → queued', async () => {
    const noRound = await heldEntry(orgA);
    const r1 = await analystApi
      .post(`/entries/${noRound.entry.publicId}/release`, { reason })
      .expect(202);
    expect(r1.body).toMatchObject({
      outcome: 'approval_requested',
      state: 'pending_approval',
      approvalReasons: ['no_scan_round'],
    });
    const approval = await ctx.prisma.quarantineApprovalRequest.findFirstOrThrow({
      where: { publicId: r1.body.approvalRequestId },
    });
    expect(approval).toMatchObject({
      kind: 'release_approval',
      status: 'pending',
      requestedByUserId: analyst.id,
    });

    const fresh = await heldEntry(orgA);
    await insertCompletedRound(ctx, fresh.message);
    const key = `it-${randomUUID()}`;
    const r2 = await analystApi
      .post(`/entries/${fresh.entry.publicId}/release`, { reason }, key)
      .expect(202);
    expect(r2.body).toMatchObject({
      outcome: 'queued',
      state: 'releasing',
      releaseId: expect.any(String),
    });
    const log = await ctx.prisma.quarantineReleaseLog.findFirstOrThrow({
      where: { releasePublicId: r2.body.releaseId },
    });
    expect(log).toMatchObject({ status: 'pending', mode: 'operator', requestedByType: 'user' });
    expect(log.precheck).toMatchObject({ outcome: 'release', approvalReasons: [] });
    const outbox = await ctx.prisma.messageOutbox.findMany({
      where: {
        organizationId: orgA.id,
        eventType: EventTypes.QuarantineReleaseRequested,
        aggregateId: fresh.message.id.toString(),
      },
    });
    expect(outbox).toHaveLength(1);
    expect(quarantineReleaseRequestedV1.parse(outbox[0]!.payload)).toMatchObject({
      releaseId: r2.body.releaseId,
      entryIds: [fresh.entry.publicId],
      mode: 'operator',
    });
    // Replay: same response, nothing new.
    const replay = await analystApi
      .post(`/entries/${fresh.entry.publicId}/release`, { reason }, key)
      .expect(202);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual(r2.body);
    // Same key, other body → 422.
    await analystApi
      .post(`/entries/${fresh.entry.publicId}/release`, { reason: 'something else' }, key)
      .expect(422);
    // The entry is releasing now: a second release conflicts.
    expect(
      (await analystApi.post(`/entries/${fresh.entry.publicId}/release`, { reason }).expect(409))
        .body.code,
    ).toBe('quarantine_state_conflict');
    // The detail shows the release attempt and its pre-check summary.
    const detail = await analystApi.get(`/entries/${fresh.entry.publicId}`).expect(200);
    expect(detail.body.releases[0]).toMatchObject({
      id: r2.body.releaseId,
      status: 'pending',
      mode: 'operator',
    });
    const rel = await readerKeyApi.get(`/releases/${r2.body.releaseId}`).expect(200);
    expect(rel.body.entryIds).toEqual([fresh.entry.publicId]);
    await adminBApi.get(`/releases/${r2.body.releaseId}`).expect(404);
  });

  it('stale verdicts on a rescannable message → 409 rescan_required, only the refusal audited', async () => {
    const stale = await heldEntry(orgA, { hasAttachments: true });
    await insertCompletedRound(ctx, stale.message, { completedAgoMs: 100 * 3_600_000 });
    const res = await analystApi
      .post(`/entries/${stale.entry.publicId}/release`, { reason })
      .expect(409);
    expect(res.body).toMatchObject({
      code: 'quarantine_rescan_required',
      staleness: 'verdict_age',
    });
    expect((await entryRow(stale.entry.publicId)).status).toBe('held');
    expect(
      await ctx.prisma.quarantineReleaseLog.count({
        where: { quarantineMessageId: stale.entry.id },
      }),
    ).toBe(0);
    expect(await audits(orgA, 'quarantine.release_refused', stale.entry.publicId)).toHaveLength(1);
  });

  it('Q30: POST /messages/{id}/release answers 409 quarantine_workflow_required', async () => {
    const { message: m } = await heldEntry(orgA);
    const ops = new LifecycleApi(
      ctx,
      apiKeyHeader(await fx.createApiKey(orgA, ['quarantine:release'])),
    );
    const res = await ops
      .release(m.publicId, { expectedVersion: m.version, reason }, `it-${randomUUID()}`)
      .expect(409);
    expect(res.body).toMatchObject({
      code: 'quarantine_workflow_required',
      entries: 1,
      route: 'POST /api/v1/quarantine/entries/{entryId}/release',
    });
  });
});

describe('approvals and separation of duties (Q14)', () => {
  it('requester and recipient are refused; a second admin approves; deny of a policy review rejects', async () => {
    // The analyst's own address is the recipient of this entry.
    const { entry } = await heldEntry(orgA, { recipient: analyst.email });
    const req = await reviewerApi
      .post(`/entries/${entry.publicId}/request-release`, { reason })
      .expect(202);
    expect(req.body.outcome).toBe('approval_requested');
    const id = req.body.approvalRequestId as string;
    const asRequester = await reviewerApi.post(`/approvals/${id}/approve`, { reason }).expect(403);
    expect(asRequester.body).toMatchObject({
      code: 'quarantine_approval_forbidden',
      reason: 'requester',
    });
    const asRecipient = await analystApi.post(`/approvals/${id}/approve`, { reason }).expect(403);
    expect(asRecipient.body).toMatchObject({
      code: 'quarantine_approval_forbidden',
      reason: 'recipient',
    });
    await mailboxApi.post(`/approvals/${id}/approve`, { reason }).expect(403);
    await readerKeyApi.post(`/approvals/${id}/approve`, { reason }).expect(403);
    const ok = await adminApi.post(`/approvals/${id}/approve`, { reason }).expect(202);
    expect(ok.body).toMatchObject({
      status: 'approved',
      entryState: 'releasing',
      releaseId: expect.any(String),
    });
    const row = await ctx.prisma.quarantineApprovalRequest.findFirstOrThrow({
      where: { publicId: id },
    });
    expect(row).toMatchObject({ status: 'approved', decidedByUserId: admin.id });
    expect(row.deciderPermissionsHash).toMatch(/^[0-9a-f]{64}$/);
    expect(
      (await adminApi.post(`/approvals/${id}/approve`, { reason }).expect(409)).body.code,
    ).toBe('quarantine_approval_not_pending');
    // GET /approvals reads the replica (Q26): wait for the approval to replicate.
    await waitForReplica();
    const list = await readerKeyApi.get('/approvals', { status: 'approved' }).expect(200);
    expect(list.body.items.map((a: { id: string }) => a.id)).toContain(id);
    await adminBApi.get(`/approvals/${id}`).expect(404);
    expect(await audits(orgA, 'quarantine.approval_approved', id)).toHaveLength(1);

    // Deny of a policy review → entry rejected, recipient discarded, message rejected (E18).
    const review = await heldEntry(orgA, {
      kind: 'review',
      messageState: 'held_for_review',
      state: 'pending_approval',
    });
    const pr = await insertApproval(ctx, review.entry, orgA.id, {
      kind: 'policy_review',
      reasons: ['review'],
    });
    const denied = await adminApi.post(`/approvals/${pr.publicId}/deny`, { reason }).expect(200);
    expect(denied.body).toMatchObject({
      status: 'denied',
      entryState: 'rejected',
      messageTransition: 'E18',
    });
    const msg = await ctx.prisma.emailMessage.findFirstOrThrow({
      where: { id: review.message.id },
    });
    expect(msg).toMatchObject({ status: 'rejected', statusReason: 'review_rejected' });
    const rcpt = await ctx.prisma.emailRecipient.findFirstOrThrow({
      where: { messageId: review.message.id },
    });
    expect(rcpt.status).toBe('discarded');

    // Cancel by the requester returns the entry to held; a policy review cannot be cancelled.
    const another = await heldEntry(orgA);
    const r = await reviewerApi
      .post(`/entries/${another.entry.publicId}/request-release`, { reason })
      .expect(202);
    const cancelled = await reviewerApi
      .post(`/approvals/${r.body.approvalRequestId}/cancel`, { reason })
      .expect(200);
    expect(cancelled.body).toMatchObject({ status: 'cancelled', entryState: 'held' });
    const review2 = await heldEntry(orgA, {
      kind: 'review',
      messageState: 'held_for_review',
      state: 'pending_approval',
    });
    const pr2 = await insertApproval(ctx, review2.entry, orgA.id, {
      kind: 'policy_review',
      reasons: ['review'],
    });
    expect(
      (await adminApi.post(`/approvals/${pr2.publicId}/cancel`, { reason }).expect(409)).body.code,
    ).toBe('quarantine_state_conflict');
  });
});

describe('approvals: an API-key requester is its creator (Q14)', () => {
  it('the creator of the requesting key is refused as the requester; another admin approves', async () => {
    // The admin holds quarantine:approve and creates a key that may request releases.
    const keyApi = new QuarantineApi(
      ctx,
      apiKeyHeader(
        await fx.createApiKey(orgA, ['quarantine:read', 'quarantine:request_release'], {
          createdBy: admin,
        }),
      ),
    );
    const { entry } = await heldEntry(orgA);
    const req = await keyApi
      .post(`/entries/${entry.publicId}/request-release`, { reason })
      .expect(202);
    expect(req.body.outcome).toBe('approval_requested');
    const id = req.body.approvalRequestId as string;
    const stored = await ctx.prisma.quarantineApprovalRequest.findFirstOrThrow({
      where: { publicId: id },
    });
    expect(stored).toMatchObject({ requestedByType: 'api_key', requestedByUserId: null });
    expect(stored.requestedByApiKeyId).not.toBeNull();
    for (const verb of ['approve', 'deny'] as const) {
      const refused = await adminApi.post(`/approvals/${id}/${verb}`, { reason }).expect(403);
      expect(refused.body).toMatchObject({
        code: 'quarantine_approval_forbidden',
        reason: 'requester',
      });
    }
    const ok = await admin2Api.post(`/approvals/${id}/approve`, { reason }).expect(202);
    expect(ok.body).toMatchObject({ status: 'approved', entryState: 'releasing' });
    expect(
      await ctx.prisma.quarantineApprovalRequest.findFirstOrThrow({ where: { publicId: id } }),
    ).toMatchObject({ status: 'approved', decidedByUserId: admin2.id });
  });
});

describe('reject (Q16) and delete under legal hold and retention (Q17)', () => {
  it('reject: recipient discarded, E17 on the last entry, sender notice only for outbound', async () => {
    const outbound = await heldEntry(orgA, { direction: 'outbound' });
    const res = await analystApi
      .post(`/entries/${outbound.entry.publicId}/reject`, { reason })
      .expect(200);
    expect(res.body).toMatchObject({ state: 'rejected', messageTransition: 'E17' });
    const msg = await ctx.prisma.emailMessage.findFirstOrThrow({
      where: { id: outbound.message.id },
    });
    expect(msg).toMatchObject({ status: 'rejected', statusReason: 'quarantine_deleted' });
    const notices = await ctx.prisma.messageOutbox.findMany({
      where: {
        organizationId: orgA.id,
        eventType: EventTypes.QuarantineNotificationRequested,
        aggregateType: 'quarantine',
      },
    });
    expect(
      notices.some(
        (n) =>
          (n.payload as { refs?: { entryId?: string } }).refs?.entryId === outbound.entry.publicId,
      ),
    ).toBe(true);

    const inbound = await heldEntry(orgA, { direction: 'inbound' });
    await analystApi
      .post(`/entries/${inbound.entry.publicId}/reject`, { reason, notifySender: true })
      .expect(200);
    const after = await ctx.prisma.messageOutbox.findMany({
      where: { organizationId: orgA.id, eventType: EventTypes.QuarantineNotificationRequested },
    });
    expect(
      after.some(
        (n) =>
          (n.payload as { refs?: { entryId?: string } }).refs?.entryId === inbound.entry.publicId,
      ),
    ).toBe(false);
    expect(await audits(orgA, 'quarantine.rejected', inbound.entry.publicId)).toHaveLength(1);
    // The operator's reason is in quarantine_actions, not in the audit metadata.
    const action = await ctx.prisma.quarantineAction.findFirstOrThrow({
      where: { quarantineMessageId: inbound.entry.id, action: 'reject' },
    });
    expect(action.reason).toBe(reason);
    expect(
      JSON.stringify(
        (await audits(orgA, 'quarantine.rejected', inbound.entry.publicId))[0]!.metadata,
      ),
    ).not.toContain(reason);
  });

  it('delete: refused under an active legal hold and archive retention; otherwise deleted with a purge row', async () => {
    const held = await heldEntry(orgA);
    const hold = await ctx.prisma.archiveLegalHold.create({
      data: {
        organizationId: orgA.id,
        name: `hold-${uniqueSuffix()}`,
        reason: 'litigation',
        criteria: {},
      },
    });
    const refused = await analystApi
      .post(`/entries/${held.entry.publicId}/delete`, { reason })
      .expect(409);
    expect(refused.body).toMatchObject({
      code: 'quarantine_legal_hold',
      legalHoldId: hold.id.toString(),
    });
    expect((await entryRow(held.entry.publicId)).status).toBe('held');
    expect(await audits(orgA, 'quarantine.delete_refused', held.entry.publicId)).toHaveLength(1);
    // The tenant purge is refused while the hold is active.
    await expect(
      ctx.get(QuarantineTenantDataRepository).purgeOrganization(systemScope(orgA.id)),
    ).rejects.toBeInstanceOf(QuarantinePurgeRefusedError);
    await ctx.prisma.archiveLegalHold.update({
      where: { id: hold.id },
      data: { status: 'released' },
    });

    await ctx.prisma.archiveSetting.create({
      data: { organizationId: orgA.id, enabled: true, scope: 'all' },
    });
    const policy = await ctx.prisma.archiveRetentionPolicy.create({
      data: {
        organizationId: orgA.id,
        name: `ret-${uniqueSuffix()}`,
        retentionDays: 3650,
        priority: 1,
      },
    });
    const retained = await analystApi
      .post(`/entries/${held.entry.publicId}/delete`, { reason })
      .expect(409);
    expect(retained.body.code).toBe('quarantine_retention_active');
    await ctx.prisma.archiveRetentionPolicy.delete({ where: { id: policy.id } });
    await ctx.prisma.archiveSetting.deleteMany({ where: { organizationId: orgA.id } });

    const done = await analystApi
      .post(`/entries/${held.entry.publicId}/delete`, { reason })
      .expect(200);
    expect(done.body).toMatchObject({
      state: 'deleted',
      messageTransition: 'E17',
      purge: 'pending',
    });
    const purge = await ctx.prisma.quarantineObjectPurge.findFirstOrThrow({
      where: { messageId: held.message.id },
    });
    expect(purge.status).toBe('pending');
  });
});

describe('manual quarantine (Q7)', () => {
  it('held_for_review → E16; a policy-rejected message with its EML → E29 and manual entries; others 409', async () => {
    const review = await heldEntry(orgA, {
      kind: 'review',
      messageState: 'held_for_review',
      state: 'pending_approval',
    });
    await insertApproval(ctx, review.entry, orgA.id, {
      kind: 'policy_review',
      reasons: ['review'],
    });
    const res = await analystApi
      .post('/entries', { messageId: review.message.publicId, reason })
      .expect(201);
    expect(res.body).toMatchObject({
      messageTransition: 'E16',
      entries: [{ id: review.entry.publicId, state: 'held' }],
    });
    expect((await entryRow(review.entry.publicId)).kind).toBe('quarantine');

    const rejected = await message(orgA, {
      state: 'rejected',
      recipients: [
        { address: 'x1@acme.example', status: 'discarded' },
        { address: 'x2@acme.example', status: 'discarded' },
      ],
    });
    await ctx.prisma.emailMessage.updateMany({
      where: { id: rejected.id },
      data: { statusReason: 'policy_reject' },
    });
    const missing = await analystApi
      .post('/entries', { messageId: rejected.publicId, reason })
      .expect(409);
    expect(missing.body).toMatchObject({
      code: 'quarantine_manual_not_allowed',
      cause: 'content_missing',
    });
    await putObject(objects, rejected.emlObjectKey, 'From: a@b\r\n\r\nx\r\n');
    const created = await analystApi
      .post('/entries', { messageId: rejected.publicId, rcptSeqs: [1], reason })
      .expect(201);
    expect(created.body).toMatchObject({
      messageTransition: 'E29',
      entries: [{ rcptSeq: 1, state: 'held' }],
    });
    const entry = await entryRow(created.body.entries[0].id);
    expect(entry).toMatchObject({
      origin: 'manual',
      reason: 'manual',
      kind: 'quarantine',
      recipientAddress: 'x2@acme.example',
    });
    expect(entry.subject).toBeNull();
    const rcpts = await ctx.prisma.emailRecipient.findMany({
      where: { messageId: rejected.id },
      orderBy: { rcptSeq: 'asc' },
    });
    expect(rcpts.map((r) => r.status)).toEqual(['discarded', 'quarantined']);

    const delivered = await message(orgA, { state: 'delivered' });
    expect(
      (await analystApi.post('/entries', { messageId: delivered.publicId, reason }).expect(409))
        .body.code,
    ).toBe('quarantine_state_conflict');
    await reviewerApi.post('/entries', { messageId: delivered.publicId, reason }).expect(403);
    expect(
      (await analystApi.post('/entries', { messageId: unknownId(), reason }).expect(404)).body.code,
    ).toBe('quarantine_entry_not_found');
  });
});

describe('bulk (Q18)', () => {
  it('limits per request, partial failures per item, the per-minute item counter', async () => {
    const tooMany = await analystApi
      .post('/bulk', {
        action: 'reject',
        ids: Array.from({ length: 6 }, () => randomUUID()),
        reason,
      })
      .expect(400);
    expect(tooMany.body).toMatchObject({ code: 'quarantine_bulk_limit', cause: 'too_many' });
    // Approve needs a user with MFA: the API key is refused.
    await readerKeyApi
      .post('/bulk', { action: 'approve', ids: [randomUUID()], reason })
      .expect(403);

    // Stay inside one minute for the counter.
    const second = new Date().getUTCSeconds();
    if (second > 50) await new Promise((r) => setTimeout(r, (61 - second) * 1000));
    const a = await heldEntry(orgA);
    const b = await heldEntry(orgA);
    const unknown = randomUUID();
    const key = `it-${randomUUID()}`;
    const res = await analystApi
      .post(
        '/bulk',
        { action: 'reject', ids: [a.entry.publicId, unknown, b.entry.publicId], reason },
        key,
      )
      .expect(200);
    expect(res.body.results).toEqual([
      { id: a.entry.publicId, status: 'done' },
      { id: unknown, status: 'not_found', code: 'quarantine_entry_not_found' },
      { id: b.entry.publicId, status: 'done' },
    ]);
    expect(res.body.counts).toMatchObject({ done: 2, not_found: 1 });
    const replay = await analystApi
      .post(
        '/bulk',
        { action: 'reject', ids: [a.entry.publicId, unknown, b.entry.publicId], reason },
        key,
      )
      .expect(200);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    expect(replay.body).toEqual(res.body);
    expect(await audits(orgA, 'quarantine.bulk')).toHaveLength(1);
    // 3 items counted; 5 more pass (8), 3 more exceed 10 → 429.
    await analystApi
      .post('/bulk', {
        action: 'delete',
        ids: Array.from({ length: 5 }, () => randomUUID()),
        reason,
      })
      .expect(200);
    const limited = await analystApi
      .post('/bulk', {
        action: 'delete',
        ids: Array.from({ length: 3 }, () => randomUUID()),
        reason,
      })
      .expect(429);
    expect(limited.body.code).toBe('quarantine_bulk_rate_limited');
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
  });
});

describe('self-service (Q15)', () => {
  it('own entries only (another address 404), self-release under the bounds, preferences', async () => {
    const own = await heldEntry(orgA, {
      recipient: mailbox.email,
      reason: 'spam',
      riskLevel: 'low',
    });
    await insertCompletedRound(ctx, own.message);
    const foreign = await heldEntry(orgA, { recipient: 'someone-else@acme.example' });
    const w = windowAround();
    const list = await mailboxApi.get('/me/entries', w).expect(200);
    expect(list.body.items.map((i: { id: string }) => i.id)).toEqual([own.entry.publicId]);
    await mailboxApi.get(`/me/entries/${foreign.entry.publicId}`).expect(404);
    await mailboxApi.get(`/me/entries/${own.entry.publicId}`).expect(200);
    // Mailbox users reach /me routes only.
    await mailboxApi.get('/entries', w).expect(403);
    await mailboxApi.post(`/entries/${own.entry.publicId}/reject`, { reason }).expect(403);
    // Operators are not mailbox users.
    await analystApi.get('/me/entries', w).expect(403);

    // Self-release was enabled for spam (settings test); the round is fresh and clean.
    const queued = await mailboxApi
      .post(`/me/entries/${own.entry.publicId}/release`, { reason: 'mine' })
      .expect(202);
    expect(queued.body).toMatchObject({ outcome: 'queued', state: 'releasing' });
    const log = await ctx.prisma.quarantineReleaseLog.findFirstOrThrow({
      where: { releasePublicId: queued.body.releaseId },
    });
    expect(log.mode).toBe('self');
    expect(await audits(orgA, 'quarantine.self_released', own.entry.publicId)).toHaveLength(1);

    const bulky = await heldEntry(orgA, {
      recipient: mailbox.email,
      reason: 'bulk',
      riskLevel: 'low',
    });
    const refused = await mailboxApi
      .post(`/me/entries/${bulky.entry.publicId}/release`, { reason: 'mine' })
      .expect(403);
    expect(refused.body).toMatchObject({
      code: 'quarantine_self_release_not_allowed',
      cause: 'reason_not_allowed',
    });
    await mailboxApi
      .post(`/me/entries/${bulky.entry.publicId}/request-release`, { reason: 'mine' })
      .expect(202);

    const prefs = await mailboxApi.put('/me/preferences', { digestOptOut: true }).expect(200);
    expect(prefs.body).toEqual({ digestOptOut: true, allowOptOut: true });
    expect((await mailboxApi.get('/me/preferences').expect(200)).body.digestOptOut).toBe(true);
    expect((await mailboxApi.get('/catalog').expect(200)).body.selfService.selfRelease).toBe(true);
  });
});

describe('tenant purge (Q17)', () => {
  it('deletes every quarantine row of the organization in RESTRICT-safe order', async () => {
    const org = await fx.createOrganization();
    const m = await message(org, { state: 'quarantined' });
    const e = await insertEntry(ctx, m, {});
    await insertApproval(ctx, e, org.id, {});
    await ctx.prisma.quarantineSettings.create({
      data: { organizationId: org.id, settings: {}, settingsSha256: '0'.repeat(64) },
    });
    const counts = await ctx
      .get(QuarantineTenantDataRepository)
      .purgeOrganization(systemScope(org.id));
    expect(counts).toMatchObject({
      quarantine_messages: 1,
      quarantine_approval_requests: 1,
      quarantine_settings: 1,
    });
    expect(await ctx.prisma.quarantineMessage.count({ where: { organizationId: org.id } })).toBe(0);
    await deleteQuarantineFixtures(ctx, [org.id]);
  });
});
