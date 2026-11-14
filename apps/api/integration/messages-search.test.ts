/**
 * The step 7.2 search drivers of `GET /api/v1/messages` (docs/plan/steps/21-email-explorer-details.md
 * §2 E1, E2, §3.2) against the real MySQL writer and replica, Redis and the in-process api: a
 * seeded fixture with known senders, From headers, domains, subjects (with reply markers),
 * Message-IDs, recipient domains, deliveries in several statuses and quarantine entries in
 * several states. Every driver and residual combinations return exactly the expected rows; the
 * foreign drivers list a message once across pages; filter-level permissions per real role; the
 * subject prefix above a low cap is `422 message_search_too_broad`; subject searches are audited
 * with the hash of the normalized value; another organization's identical rows never appear. The
 * EXPLAIN plans at volume and the timeout path run in messages-explain.test.ts.
 */
// @covers get /api/v1/messages
import { createHash, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader } from './support/http';
import {
  bulkMessages,
  deleteMessagesData,
  getAs,
  POLL,
  type SeededMessage,
  seedMessage,
} from './support/messages-data';

const MIN = 60_000;
const ALL = ['message:read', 'message:reveal', 'delivery:read', 'quarantine:read'];

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let other: FixtureOrganization;
let key: Record<string, string>;
const run = randomUUID().slice(0, 8);
const vendor = `vendor-${run}.example`;
const partner = `partner-${run}.example`;
const corp = `corp-${run}.example`;
const m: Record<string, SeededMessage> = {};

beforeAll(async () => {
  // The lowest cap the config allows (500) so the 422 path is reachable with a few hundred rows.
  ctx = await createIntegrationApp({ API_MESSAGES_SEARCH_MAX_MATCHES: '500' });
  fx = createFixtures(ctx);
  [org, other] = [await fx.createOrganization(), await fx.createOrganization()];
  fx.registerCleanup(() => deleteMessagesData(ctx, [org.id, other.id]));
  key = apiKeyHeader(await fx.createApiKey(org, ALL));
  const now = Date.now();
  const at = (i: number) => new Date(now - (i + 1) * 10 * MIN);
  m.invoice = await seedMessage(ctx, org, {
    receivedAt: at(5),
    envelopeFrom: `billing@${vendor}`,
    headerFrom: `Billing <billing@${vendor}>`,
    subject: `Re: Invoice ${run} overdue`,
    internetMessageId: `<inv-${run}@${vendor}>`,
    recipients: [`ap@${partner}`],
    deliveryStatuses: ['bounced'],
    verdict: 'phishing',
  });
  m.report = await seedMessage(ctx, org, {
    receivedAt: at(4),
    envelopeFrom: `reports@${corp}`,
    subject: `Weekly report ${run}`,
    recipients: [`ceo@${corp}`, `cfo@${corp}`],
    deliveryStatuses: ['delivered', 'deferred'],
    quarantine: [{ rcptSeq: 1, status: 'held' }],
  });
  m.reminder = await seedMessage(ctx, org, {
    receivedAt: at(3),
    envelopeFrom: `x@evil-${run}.example`,
    subject: `Invoice ${run} reminder`,
    recipients: [`ap@${partner}`, `bob@${partner}`],
    deliveryStatuses: ['suppressed', 'suppressed'],
    quarantine: [
      { rcptSeq: 0, status: 'held' },
      { rcptSeq: 1, status: 'released' },
    ],
    direction: 'outbound',
  });
  m.forward = await seedMessage(ctx, org, {
    receivedAt: at(2),
    envelopeFrom: `BILLING@${vendor.toUpperCase()}`,
    subject: `Fwd:  invoice ${run}   OVERDUE`,
    internetMessageId: null,
    recipients: [`ar@${corp}`],
    deliveryStatuses: ['delivered'],
  });
  m.plain = await seedMessage(ctx, org, {
    receivedAt: at(1),
    envelopeFrom: `news@list-${run}.example`,
    subject: 'Newsletter',
    recipients: [`all@${corp}`],
  });
  // Identical keys in another organization: never listed.
  await seedMessage(ctx, other, {
    receivedAt: at(5),
    envelopeFrom: `billing@${vendor}`,
    headerFrom: `Billing <billing@${vendor}>`,
    subject: `Re: Invoice ${run} overdue`,
    internetMessageId: `<inv-${run}@${vendor}>`,
    recipients: [`ap@${partner}`],
    deliveryStatuses: ['bounced'],
    quarantine: [{ rcptSeq: 0, status: 'held' }],
  });
  // 600 messages whose subjects start with "Promo <run>" (above the cap of 500).
  await bulkMessages(ctx, org, {
    count: 600,
    from: new Date(now - 30 * 60 * MIN),
    to: new Date(now - 20 * 60 * MIN),
    verdicts: ['clean'],
    hotAddress: `hot@${run}.example`,
    recipientEvery: 1_000,
    subjectOf: (k) => `Promo ${run} ${k}`,
  });
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

const ids = (body: { data: Array<{ id: string }> }) => body.data.map((d) => d.id);
const list = (query: string, headers = key) => getAs(ctx, headers, `/messages${query}`);
const q = encodeURIComponent;

describe('GET /messages search drivers against the replica (step 7.2 §2 E1)', () => {
  it('waits for the replica', async () => {
    await expect
      .poll(async () => ids((await list(`?senderDomain=list-${run}.example`)).body), POLL)
      .toEqual([m.plain!.publicId]);
  });

  it.each([
    [
      'internetMessageId (brackets optional)',
      () => `?internetMessageId=${q(`inv-${run}@${vendor}`)}`,
      () => ['invoice'],
    ],
    [
      'internetMessageId (with brackets)',
      () => `?internetMessageId=${q(`<inv-${run}@${vendor}>`)}`,
      () => ['invoice'],
    ],
    [
      'sender (case-insensitive)',
      () => `?sender=${q(`Billing@${vendor}`)}`,
      () => ['forward', 'invoice'],
    ],
    ['headerFrom', () => `?headerFrom=${q(`Billing <billing@${vendor}>`)}`, () => ['invoice']],
    ['recipient', () => `?recipient=${q(`ap@${partner}`)}`, () => ['reminder', 'invoice']],
    [
      'subject (markers, spacing, case ignored)',
      () => `?subject=${q(`AW: invoice ${run} overdue`)}`,
      () => ['forward', 'invoice'],
    ],
    ['senderDomain', () => `?senderDomain=${q(`@${vendor}`)}`, () => ['forward', 'invoice']],
    [
      'recipientDomain (two recipients: once)',
      () => `?recipientDomain=${partner}`,
      () => ['reminder', 'invoice'],
    ],
    [
      'subjectPrefix',
      () => `?subjectPrefix=${q(`Re: invoice ${run}`)}`,
      () => ['forward', 'reminder', 'invoice'],
    ],
    ['quarantineStatus', () => '?quarantineStatus=held', () => ['reminder', 'report']],
    [
      'deliveryStatus (two deliveries: once)',
      () => '?deliveryStatus=suppressed',
      () => ['reminder'],
    ],
    ['verdict', () => '?verdict=phishing', () => ['invoice']],
  ])('%s returns exactly its messages', async (_label, query, expected) => {
    const res = await list(query());
    expect(res.status).toBe(200);
    expect(ids(res.body)).toEqual(expected().map((name) => m[name]!.publicId));
    // An exact driver page: never a short page with a cursor.
    expect(res.body.nextCursor).toBeNull();
  });

  it.each([
    [
      'recipientDomain + quarantineStatus',
      () => `?recipientDomain=${partner}&quarantineStatus=held`,
      () => ['reminder'],
    ],
    [
      'deliveryStatus + direction',
      () => '?deliveryStatus=bounced&direction=inbound',
      () => ['invoice'],
    ],
    [
      'sender + subjectPrefix',
      () => `?sender=billing@${vendor}&subjectPrefix=${q(`Fwd: invoice ${run} ov`)}`,
      () => ['forward', 'invoice'],
    ],
    [
      'senderDomain + deliveryStatus',
      () => `?senderDomain=${vendor}&deliveryStatus=delivered`,
      () => ['forward'],
    ],
    [
      'subject + recipientDomain',
      () => `?subject=${q(`invoice ${run} overdue`)}&recipientDomain=${corp}`,
      () => ['forward'],
    ],
    [
      'quarantineStatus + verdict list',
      () => '?quarantineStatus=held&verdict=clean,phishing&direction=outbound',
      () => ['reminder'],
    ],
    [
      'subjectPrefix + quarantineStatus',
      () => `?subjectPrefix=${q(`invoice ${run}`)}&quarantineStatus=released`,
      () => ['reminder'],
    ],
    [
      'residuals only (scan)',
      () =>
        `?riskScore.gte=0&direction=outbound&hasAttachments=false&from=${new Date(Date.now() - 2 * 60 * MIN).toISOString()}`,
      () => ['reminder'],
    ],
  ])('residual combination %s returns exactly its messages', async (_label, query, expected) => {
    const res = await list(query());
    expect(res.status).toBe(200);
    expect(ids(res.body)).toEqual(expected().map((name) => m[name]!.publicId));
  });

  it('foreign drivers page without duplicates (limit 1, each message once)', async () => {
    for (const query of [
      `?recipientDomain=${partner}`,
      `?recipientDomain=${corp}`,
      '?quarantineStatus=held',
      '?deliveryStatus=delivered',
    ]) {
      const seen: string[] = [];
      let cursor: string | null = null;
      for (let page = 0; page < 10; page += 1) {
        const res = await list(
          `${query}&limit=1${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`,
        );
        expect(res.status, query).toBe(200);
        seen.push(...ids(res.body));
        cursor = res.body.nextCursor;
        if (!cursor) break;
      }
      expect(new Set(seen).size, query).toBe(seen.length);
      expect(seen.length, query).toBeGreaterThan(0);
    }
    // recipientDomain=corp: report (2 recipients), forward, plain.
    const all = await list(`?recipientDomain=${corp}&limit=10`);
    expect(ids(all.body)).toEqual(['plain', 'forward', 'report'].map((n) => m[n]!.publicId));
  });

  it('refuses a prefix matching more than API_MESSAGES_SEARCH_MAX_MATCHES (422), a narrower one is served', async () => {
    const from = new Date(Date.now() - 31 * 60 * MIN).toISOString();
    const broad = await list(`?subjectPrefix=${q(`Promo ${run}`)}&from=${from}`);
    expect(broad.status).toBe(422);
    expect(broad.body).toMatchObject({ code: 'message_search_too_broad', maxMatches: 500 });
    // "Promo <run> 1" matches 1, 10-19, 100-199: 111 messages, within the cap; sorted page.
    const narrow = await list(`?subjectPrefix=${q(`Promo ${run} 1`)}&from=${from}&limit=100`);
    expect(narrow.status).toBe(200);
    expect(narrow.body.data).toHaveLength(100);
    expect(narrow.body.nextCursor).toEqual(expect.any(String));
    const rest = await list(
      `?subjectPrefix=${q(`Promo ${run} 1`)}&from=${from}&limit=100&cursor=${encodeURIComponent(narrow.body.nextCursor)}`,
    );
    expect(rest.body.data).toHaveLength(11);
    expect(rest.body.nextCursor).toBeNull();
    const times = [...narrow.body.data, ...rest.body.data].map((d: { receivedAt: string }) =>
      Date.parse(d.receivedAt),
    );
    expect([...times].sort((a, b) => b - a)).toEqual(times);
  });

  it('filter-level permissions with real API key scopes (403 message_filter_forbidden)', async () => {
    const readOnly = apiKeyHeader(await fx.createApiKey(org, ['message:read']));
    for (const [query, permission] of [
      [`?recipient=${q(`ap@${partner}`)}`, 'message:reveal'],
      [`?subject=${q('Newsletter')}`, 'message:reveal'],
      ['?subjectPrefix=New', 'message:reveal'],
      ['?deliveryStatus=bounced', 'delivery:read'],
      ['?quarantineStatus=held', 'quarantine:read'],
    ] as const) {
      const res = await list(query, readOnly);
      expect(res.status, query).toBe(403);
      expect(res.body).toMatchObject({ code: 'message_filter_forbidden', permission });
    }
    expect((await list(`?senderDomain=${vendor}`, readOnly)).status).toBe(200);
    // The recipient domain stays open (the masked address keeps its domain in clear).
    expect((await list(`?recipientDomain=${partner}`, readOnly)).status).toBe(200);
  });

  it('audits subject searches with the SHA-256 of the normalized value (first page only)', async () => {
    const before = new Date(Date.now() - 1000);
    const typed = `RE:  Invoice ${run}  OVERDUE`;
    const first = await list(`?subject=${q(typed)}&limit=1`);
    expect(first.status).toBe(200);
    await list(`?subject=${q(typed)}&limit=1&cursor=${encodeURIComponent(first.body.nextCursor)}`);
    const hash = createHash('sha256').update(`Invoice ${run} OVERDUE`).digest('hex');
    const rows = (
      await ctx.prisma.auditLog.findMany({
        where: { organizationId: org.id, action: 'message.searched', createdAt: { gte: before } },
      })
    ).filter(
      (r) => (r.metadata as { valueSha256?: { subject?: string } }).valueSha256?.subject === hash,
    );
    // One row for the first page; the cursor page is not audited.
    expect(rows).toHaveLength(1);
    expect(rows[0]!.metadata).toMatchObject({
      filters: ['subject'],
      plan: 'subject',
      budgeted: false,
      valueSha256: { subject: hash },
    });
    expect(JSON.stringify(rows[0]!.metadata)).not.toContain(run);
    // Domain and status filters are not identifying: no audit row.
    const count = await ctx.prisma.auditLog.count({
      where: { organizationId: org.id, action: 'message.searched', createdAt: { gte: before } },
    });
    await list(`?senderDomain=${vendor}&deliveryStatus=bounced`);
    expect(
      await ctx.prisma.auditLog.count({
        where: { organizationId: org.id, action: 'message.searched', createdAt: { gte: before } },
      }),
    ).toBe(count);
  });

  it('another organization’s identical rows never appear; its cursor is cursor_invalid', async () => {
    const keyB = apiKeyHeader(await fx.createApiKey(other, ALL));
    const b = await list(`?subject=${q(`invoice ${run} overdue`)}`, keyB);
    expect(b.status).toBe(200);
    expect(b.body.data).toHaveLength(1);
    expect(ids(b.body)).not.toContain(m.invoice!.publicId);
    const bPage = await list(`?senderDomain=${vendor}&limit=1`, keyB);
    const res = await list(
      `?senderDomain=${vendor}&limit=1&cursor=${encodeURIComponent(bPage.body.nextCursor ?? 'x')}`,
    );
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('cursor_invalid');
  });
});
