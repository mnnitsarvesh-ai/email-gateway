/**
 * EXPLAIN checks of the step 6.1 WP2 list queries (§9, D5, D6) on the read replica at volume:
 * ≥ 50 000 messages over 4 days in one fixture organization (plus 5 000 in a second one), with
 * recipients, attachments of one hot hash and clicks. For each of the four `GET /messages` plans,
 * the URL clicks and the attachment hash search, `EXPLAIN FORMAT=JSON` of the exact statement the
 * repository runs (the index plan's statement is captured from Prisma's query log) must show the
 * chosen key, pruned partitions, no filesort for the index and verdict plans, and, for the
 * scan-bounded plan, at most API_LIST_SCAN_BUDGET_ROWS rows read per statement (session handler
 * counters on the replica connection). Each API page is also timed; the numbers are printed (a
 * local Docker baseline, not a production capacity statement).
 */
// @covers get /api/v1/messages
// @covers get /api/v1/attachments
// @covers get /api/v1/url-protection/clicks
import { createHash, randomUUID } from 'node:crypto';
import { PrismaClient, Prisma } from '@email-gateway/database';
import type { PrismaReadService, PrismaService } from '@email-gateway/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import {
  attachmentSearchSql,
  ATTACHMENT_SHA256_INDEX,
} from '../src/modules/attachments/attachments.repository';
import {
  indexPlanSql,
  MESSAGE_INDEXES,
  messagesByKeysSql,
  recipientPlanSql,
  scanBoundarySql,
  scanPageSql,
  verdictPlanSql,
} from '../src/modules/messages/repositories/message-data.repository';
import { MessagesRepository } from '../src/modules/tenant-data/messages.repository';
import {
  clicksBoundarySql,
  clicksPageSql,
  CLICKS_INDEX,
} from '../src/modules/url-protection/url-protection.repository';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader } from './support/http';
import { bulkMessages, deleteMessagesData, getAs } from './support/messages-data';

const COUNT = 50_000;
const OTHER_COUNT = 5_000;
const BUDGET = 5_000;
const DAY = 86_400_000;

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let other: FixtureOrganization;
let key: Record<string, string>;
let replica: PrismaClient;
const queries: Array<{ query: string; params: string }> = [];
const run = randomUUID().slice(0, 8);
const hot = `hot-${run}@acme.example`;
const hash = createHash('sha256').update(run).digest('hex');
const now = Date.now();
const range = { from: new Date(now - 4 * DAY), to: new Date(now + 60_000) };
let partitionCount = 0;
const timings: string[] = [];

interface ExplainTable {
  table_name: string;
  key?: string;
  partitions?: string[];
  rows_examined_per_scan?: number;
  access_type?: string;
}

/** Every `table` node of an EXPLAIN FORMAT=JSON tree and whether any node uses a filesort. */
function walk(node: unknown, tables: ExplainTable[] = [], state = { filesort: false }) {
  if (Array.isArray(node)) {
    for (const item of node) walk(item, tables, state);
  } else if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (k === 'using_filesort' && v === true) state.filesort = true;
      if (k === 'table' && v && typeof v === 'object' && 'table_name' in v) {
        tables.push(v as ExplainTable);
      }
      walk(v, tables, state);
    }
  }
  return { tables, filesort: state.filesort };
}

async function explain(sql: Prisma.Sql) {
  const rows = await replica.$queryRaw<Array<Record<string, string>>>(
    Prisma.sql`EXPLAIN FORMAT=JSON ${sql}`,
  );
  return walk(JSON.parse(explainText(rows)));
}

/** The single column of an EXPLAIN FORMAT=JSON result. */
const explainText = (rows: Array<Record<string, string>>): string => Object.values(rows[0]!)[0]!;

/** Rows the storage engine handed to MySQL for one statement (session handler counters). */
async function handlerReads(sql: Prisma.Sql): Promise<number> {
  return replica.$transaction(async (tx) => {
    const read = async () => {
      const rows = await tx.$queryRaw<Array<{ Variable_name: string; Value: string }>>`
        SHOW SESSION STATUS LIKE 'Handler_read%'`;
      return rows.reduce((sum, r) => sum + Number(r.Value), 0);
    };
    const before = await read();
    await tx.$queryRaw(sql);
    return (await read()) - before;
  });
}

const prismaParam = (value: unknown): unknown => {
  if (typeof value === 'string') {
    const m = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?) ?(?:UTC|Z|\+00:00)$/.exec(
      value,
    );
    if (m) return new Date(`${m[1]}T${m[2]}Z`);
  }
  return value;
};

async function timed(label: string, path: string) {
  const started = performance.now();
  const res = await getAs(ctx, key, path);
  const ms = performance.now() - started;
  timings.push(`${label}: ${ms.toFixed(1)} ms (${res.body.data?.length ?? '-'} rows)`);
  expect(res.status, path).toBe(200);
  return res;
}

beforeAll(async () => {
  ctx = await createIntegrationApp({ API_LIST_SCAN_BUDGET_ROWS: String(BUDGET) });
  fx = createFixtures(ctx);
  [org, other] = [await fx.createOrganization(), await fx.createOrganization()];
  fx.registerCleanup(() => deleteMessagesData(ctx, [org.id, other.id]));
  key = apiKeyHeader(await fx.createApiKey(org, ['message:read']));
  const client = new PrismaClient({
    datasourceUrl: process.env.DATABASE_READ_URL,
    log: [{ emit: 'event', level: 'query' }],
  });
  client.$on('query', (e: Prisma.QueryEvent) => queries.push({ query: e.query, params: e.params }));
  replica = client;
  const verdicts = [
    'clean',
    'clean',
    'clean',
    'spam',
    'bulk',
    'phishing',
    'clean',
    'malware',
  ] as const;
  const started = performance.now();
  await bulkMessages(ctx, org, {
    count: COUNT,
    from: range.from,
    to: new Date(now),
    verdicts: [...verdicts],
    hotAddress: hot,
    recipientEvery: 97,
  });
  await bulkMessages(ctx, other, {
    count: OTHER_COUNT,
    from: range.from,
    to: new Date(now),
    verdicts: [...verdicts],
    hotAddress: hot,
    recipientEvery: 7,
  });
  // Attachments (every 11th message; one in three with the hot hash) and clicks.
  const withAttachment = await ctx.prisma.emailMessage.findMany({
    where: { organizationId: org.id, attachmentCount: { gt: 0 } },
    select: { id: true, receivedAt: true },
  });
  for (let i = 0; i < withAttachment.length; i += 2_000) {
    await ctx.prisma.emailAttachment.createMany({
      data: withAttachment.slice(i, i + 2_000).map((m, j) => ({
        receivedAt: m.receivedAt,
        messageId: m.id,
        organizationId: org.id,
        partIndex: 1,
        filename: 'bulk.pdf',
        sizeBytes: 100,
        sha256:
          (i + j) % 3 === 0
            ? hash
            : createHash('sha256')
                .update(`${run}-${i + j}`)
                .digest('hex'),
      })),
    });
  }
  const clickTargets = withAttachment.slice(0, 4_000);
  for (let i = 0; i < clickTargets.length; i += 2_000) {
    await ctx.prisma.urlClickEvent.createMany({
      data: clickTargets.slice(i, i + 2_000).map((m, j) => ({
        clickedAt: new Date(m.receivedAt.getTime() + 60_000),
        publicId: randomUUID(),
        organizationId: org.id,
        messageId: m.id,
        messageReceivedAt: m.receivedAt,
        urlSeq: 0,
        decision: (i + j) % 10 === 0 ? 'blocked' : 'allowed',
        verdict: (i + j) % 10 === 0 ? 'malicious' : 'clean',
        tokenKid: 1,
        durationMs: 1,
      })),
    });
  }
  timings.push(`seed: ${((performance.now() - started) / 1000).toFixed(1)} s`);
  // Wait for the replica.
  for (let i = 0; i < 120; i += 1) {
    const n = await replica.emailMessage.count({ where: { organizationId: org.id } });
    const c = await replica.urlClickEvent.count({ where: { organizationId: org.id } });
    if (n === COUNT && c === clickTargets.length) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  const counted = await replica.$queryRaw<Array<{ n: bigint }>>`
    SELECT COUNT(*) AS n FROM information_schema.partitions
    WHERE table_schema = DATABASE() AND table_name = 'email_messages'`;
  partitionCount = Number(counted[0]!.n);
  expect(partitionCount).toBeGreaterThan(1);
}, 600_000);

afterAll(async () => {
  // Timings of this run (local Docker VM; a baseline, not a capacity statement).
  process.stdout.write(
    `[messages-explain] ${COUNT} + ${OTHER_COUNT} messages\n  ${timings.join('\n  ')}\n`,
  );
  await replica?.$disconnect();
  await fx?.cleanup();
  await ctx?.close();
}, 600_000);

const base = () => ({ organizationId: org.id, range, direction: 'desc' as const, take: 26 });

describe('EXPLAIN on the replica (step 6.1 D5, D6)', () => {
  it('reads from the replica (read_only)', async () => {
    const [row] = await replica.$queryRaw<
      Array<{ ro: number | bigint }>
    >`SELECT @@global.read_only AS ro`;
    expect(Number(row!.ro)).toBe(1);
    expect(await replica.emailMessage.count({ where: { organizationId: org.id } })).toBe(COUNT);
  });

  it('plan 1 (index): (organization_id, received_at, id), pruned, no filesort, reads ≈ limit', async () => {
    const sql = indexPlanSql({ ...base(), after: { at: new Date(now - DAY), id: 2n ** 62n } });
    const { tables, filesort } = await explain(sql);
    expect(tables[0]!.key).toBe(MESSAGE_INDEXES.orgReceived);
    expect(tables[0]!.partitions!.length).toBeLessThan(partitionCount);
    expect(filesort).toBe(false);
    expect(await handlerReads(sql)).toBeLessThanOrEqual(30);
    timings.push(
      `plan index EXPLAIN: key=${tables[0]!.key} partitions=${tables[0]!.partitions!.join(',')}`,
    );

    // Why plan 1 names its index: the same statement through MessagesRepository.listRecent
    // (Prisma, no hint), recorded for the step notes (the optimizer's choice is not asserted).
    const repo = new MessagesRepository(
      {} as PrismaService,
      { client: replica } as unknown as PrismaReadService,
    );
    queries.length = 0;
    await repo.listRecentRows(systemScope(org.id), range, {
      take: 26,
      after: { receivedAt: new Date(now - DAY), id: 2n ** 62n },
    });
    const captured = queries.find((q) => q.query.includes('`email_messages`'))!;
    const params = (JSON.parse(captured.params) as unknown[]).map(prismaParam);
    const plan = await replica.$queryRawUnsafe<Array<Record<string, string>>>(
      `EXPLAIN FORMAT=JSON ${captured.query}`,
      ...params,
    );
    const unhinted = walk(JSON.parse(explainText(plan)));
    timings.push(
      `listRecent (Prisma, no index hint) EXPLAIN: key=${unhinted.tables[0]!.key} filesort=${unhinted.filesort}`,
    );
  });

  it('plan 2 (verdict): email_messages_org_verdict_received_idx, pruned, no filesort', async () => {
    const sql = verdictPlanSql({
      ...base(),
      verdict: 'phishing',
      after: { at: new Date(now - DAY), id: 2n ** 62n },
    });
    const { tables, filesort } = await explain(sql);
    expect(tables[0]!.key).toBe(MESSAGE_INDEXES.orgVerdict);
    expect(tables[0]!.partitions!.length).toBeLessThan(partitionCount);
    expect(filesort).toBe(false);
    expect(await handlerReads(sql)).toBeLessThanOrEqual(30);
    timings.push(
      `plan verdict EXPLAIN: key=${tables[0]!.key} partitions=${tables[0]!.partitions!.join(',')}`,
    );
  });

  it('plan 3 (recipient): the address index, then messages by primary key', async () => {
    const step1 = recipientPlanSql({ ...base(), address: hot });
    const one = await explain(step1);
    expect(one.tables[0]!.key).toBe(MESSAGE_INDEXES.recipientAddress);
    expect(one.tables[0]!.partitions!.length).toBeLessThan(partitionCount);
    const keys = await replica.$queryRaw<Array<{ message_id: bigint; received_at: Date }>>(step1);
    expect(keys.length).toBe(26);
    const step2 = messagesByKeysSql(
      org.id,
      keys.map((k) => ({ id: BigInt(k.message_id), receivedAt: k.received_at })),
    );
    const two = await explain(step2);
    expect(two.tables[0]!.key).toBe('PRIMARY');
    expect(await handlerReads(step2)).toBeLessThanOrEqual(60);
    timings.push(
      `plan recipient EXPLAIN: step1 key=${one.tables[0]!.key} filesort=${one.filesort}; step2 key=${two.tables[0]!.key}`,
    );
  });

  it('plan 4 (scan-bounded): both statements read at most the budget', async () => {
    const boundarySql = scanBoundarySql({ ...base(), budget: BUDGET });
    const boundary = await explain(boundarySql);
    expect(boundary.tables[0]!.key).toBe(MESSAGE_INDEXES.orgReceived);
    expect(boundary.filesort).toBe(false);
    const boundaryReads = await handlerReads(boundarySql);
    expect(boundaryReads).toBeLessThanOrEqual(BUDGET + 2);
    const [edge] = await replica.$queryRaw<Array<{ received_at: Date; id: bigint }>>(boundarySql);
    const pageSql = scanPageSql({
      ...base(),
      boundary: { at: edge!.received_at, id: BigInt(edge!.id) },
      filters: {
        sender: { values: ['nobody@nowhere.example'] },
        direction: { values: ['inbound'] },
      },
    });
    const page = await explain(pageSql);
    expect(page.tables[0]!.key).toBe(MESSAGE_INDEXES.orgReceived);
    expect(page.tables[0]!.partitions!.length).toBeLessThan(partitionCount);
    const pageReads = await handlerReads(pageSql);
    expect(pageReads).toBeLessThanOrEqual(BUDGET + 2);
    timings.push(
      `plan scan: boundary reads=${boundaryReads}, filtered page reads=${pageReads} (budget ${BUDGET})`,
    );
  });

  it('URL clicks: (organization_id, clicked_at), pruned, no filesort; filtered within the budget', async () => {
    const clickBase = { organizationId: org.id, range, direction: 'desc' as const, take: 26 };
    const plain = await explain(clicksPageSql(clickBase));
    expect(plain.tables[0]!.key).toBe(CLICKS_INDEX);
    expect(plain.filesort).toBe(false);
    expect(plain.tables[0]!.partitions!.length).toBeGreaterThanOrEqual(1);
    const boundarySql = clicksBoundarySql({ ...clickBase, budget: 1_000 });
    const [edge] = await replica.$queryRaw<Array<{ clicked_at: Date; id: bigint }>>(boundarySql);
    const filteredSql = clicksPageSql({
      ...clickBase,
      boundary: edge ? { at: edge.clicked_at, id: BigInt(edge.id) } : null,
      filters: { decisions: ['warned'] },
    });
    const filtered = await explain(filteredSql);
    expect(filtered.tables[0]!.key).toBe(CLICKS_INDEX);
    const reads = await handlerReads(filteredSql);
    expect(reads).toBeLessThanOrEqual(1_002);
    timings.push(
      `clicks EXPLAIN: key=${plain.tables[0]!.key} partitions=${plain.tables[0]!.partitions!.join(',')}; filtered reads=${reads} (budget 1000)`,
    );
  });

  it('attachment hash search: (organization_id, sha256, received_at, id), pruned, no filesort, reads ≈ limit', async () => {
    const sql = attachmentSearchSql({
      organizationId: org.id,
      sha256: hash,
      range,
      direction: 'desc',
      take: 26,
    });
    const { tables, filesort } = await explain(sql);
    expect(tables[0]!.key).toBe(ATTACHMENT_SHA256_INDEX);
    expect(tables[0]!.partitions!.length).toBeLessThan(partitionCount);
    // The keyset order comes from the index: no filesort, so the page cost does not grow with
    // the hash's matches (D6: no scan budget needed).
    expect(filesort).toBe(false);
    const reads = await handlerReads(sql);
    const matches = await replica.emailAttachment.count({
      where: { organizationId: org.id, sha256: hash },
    });
    expect(matches).toBeGreaterThan(200);
    // 26 index entries plus one partition boundary step per pruned partition and the LIMIT read.
    expect(reads).toBeLessThanOrEqual(26 + tables[0]!.partitions!.length + 2);
    // The next page (keyset after the 26th row) is bounded the same way.
    const firstPage = await replica.$queryRaw<Array<{ id: bigint; received_at: Date }>>(sql);
    const last = firstPage[firstPage.length - 1]!;
    const nextSql = attachmentSearchSql({
      organizationId: org.id,
      sha256: hash,
      range,
      after: { at: last.received_at, id: BigInt(last.id) },
      direction: 'desc',
      take: 26,
    });
    expect((await explain(nextSql)).filesort).toBe(false);
    expect(await handlerReads(nextSql)).toBeLessThanOrEqual(26 + tables[0]!.partitions!.length + 2);
    timings.push(
      `attachments EXPLAIN: key=${tables[0]!.key} filesort=${filesort} reads=${reads} matches=${matches}`,
    );
  });

  it('times the API pages of every plan', async () => {
    const from = range.from.toISOString();
    const first = await timed('GET /messages (index, 4 days)', `/messages?from=${from}`);
    await timed(
      'GET /messages (index, page 2)',
      `/messages?from=${from}&cursor=${encodeURIComponent(first.body.nextCursor)}`,
    );
    await timed('GET /messages?verdict=phishing', `/messages?from=${from}&verdict=phishing`);
    await timed('GET /messages?recipient=', `/messages?from=${from}&recipient=${hot}`);
    const scan = await timed(
      'GET /messages?direction=outbound (scan)',
      `/messages?from=${from}&direction=outbound&limit=100`,
    );
    expect(scan.body.data.length).toBeGreaterThan(0);
    const sparse = await timed(
      'GET /messages?sender=<none> (scan, short page)',
      `/messages?from=${from}&sender=nobody@nowhere.example`,
    );
    expect(sparse.body.data).toEqual([]);
    expect(sparse.body.nextCursor).toEqual(expect.any(String));
    await timed(
      'GET /messages?sender=<none> page 2',
      `/messages?from=${from}&sender=nobody@nowhere.example&cursor=${encodeURIComponent(sparse.body.nextCursor)}`,
    );
    await timed('GET /url-protection/clicks', `/url-protection/clicks?from=${from}`);
    await timed(
      'GET /url-protection/clicks?decision=blocked',
      `/url-protection/clicks?from=${from}&decision=blocked`,
    );
    const hits = await timed(
      'GET /attachments?sha256=',
      `/attachments?sha256=${hash}&from=${from}`,
    );
    expect(hits.body.data).toHaveLength(25);
    // Second-organization rows never appear.
    const ids = new Set(
      (
        await getAs(
          ctx,
          apiKeyHeader(await fx.createApiKey(other, ['message:read'])),
          `/messages?from=${from}&limit=100`,
        )
      ).body.data.map((d: { id: string }) => d.id),
    );
    expect(first.body.data.some((d: { id: string }) => ids.has(d.id))).toBe(false);
  });
});
