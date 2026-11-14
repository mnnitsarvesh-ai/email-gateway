/**
 * EXPLAIN checks of the message list (step 6.1 WP2 §9, D5, D6; step 7.2 §2 E1, §3.2, §9) on the
 * read replica at volume: ≥ 50 000 messages over 4 days in one fixture organization (plus 5 000
 * in a second one), with subjects, From headers, Message-IDs, recipients, a delivery per
 * message in rotating statuses, quarantine entries on every tenth message, attachments of one hot
 * hash and clicks. For every step 7.2 search driver, `EXPLAIN FORMAT=JSON` of the exact
 * statement the repository runs (message-list-drivers.ts) must show the chosen key, pruned
 * partitions and no filesort for exact drivers without residuals; the session handler counters
 * on the replica connection bound the rows read (≈ limit for exact pages, the budget for
 * budgeted statements); the foreign drivers group without a temporary table or a sort; the
 * subject prefix probe is index-only and is refused above the cap; a probe interrupted by
 * `MAX_EXECUTION_TIME` is `503 message_search_timeout`. The URL clicks and the attachment hash
 * search are checked as in 6.1. Each API page is also timed; the numbers are printed (a local
 * Docker baseline, not a production capacity statement).
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
import { MessageDataRepository } from '../src/modules/messages/repositories/message-data.repository';
import {
  type DriverWindow,
  foreignBoundarySql,
  foreignKeysSql,
  foreignPageSql,
  MESSAGE_INDEXES,
  messagesBoundarySql,
  messagesByKeysSql,
  MESSAGES_DRIVERS,
  type MessagesTableDriver,
  messagesPageSql,
  prefixPageSql,
  prefixProbeSql,
  recipientBoundarySql,
  recipientPageSql,
  recipientRowsSql,
  residualSql,
  FOREIGN_DRIVERS,
} from '../src/modules/messages/repositories/message-list-drivers';
import { subjectPrefixPattern } from '../src/modules/messages/domain/search-keys';
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
const DELIVERY_ROTATION = ['delivered', 'delivered', 'deferred', 'bounced'] as const;
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
  using_index?: boolean;
}

/** Every `table` node of an EXPLAIN FORMAT=JSON tree and whether any node uses a filesort. */
function walk(
  node: unknown,
  tables: ExplainTable[] = [],
  state = { filesort: false, temporary: false },
) {
  if (Array.isArray(node)) {
    for (const item of node) walk(item, tables, state);
  } else if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (k === 'using_filesort' && v === true) state.filesort = true;
      if (k === 'using_temporary_table' && v === true) state.temporary = true;
      if (k === 'table' && v && typeof v === 'object' && 'table_name' in v) {
        tables.push(v as ExplainTable);
      }
      walk(v, tables, state);
    }
  }
  return { tables, filesort: state.filesort, temporary: state.temporary };
}

async function explain(sql: Prisma.Sql) {
  const rows = await replica.$queryRaw<Array<Record<string, string>>>(
    Prisma.sql`EXPLAIN FORMAT=JSON ${sql}`,
  );
  const text = explainText(rows);
  return { ...walk(JSON.parse(text)), text };
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
  key = apiKeyHeader(
    await fx.createApiKey(org, [
      'message:read',
      'message:reveal',
      'delivery:read',
      'quarantine:read',
    ]),
  );
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
    // Step 7.2: 50 subjects (1 000 messages each), 97 From headers, unique Message-IDs, one
    // delivery per message in rotating statuses, a quarantine entry on every tenth message.
    subjectOf: (k) => `Re: Bulk subject ${run} ${k % 50}`,
    headerFromOf: (k) => `Bulk ${k % 97} <bulk${k % 97}@sender.example>`,
    messageIdOf: (k) => `<bulk-${run}-${k}@sender.example>`,
    deliveryOf: (k) => DELIVERY_ROTATION[k % DELIVERY_ROTATION.length]!,
    quarantineOf: (k) => (k % 10 === 0 ? (k % 20 === 0 ? 'held' : 'released') : null),
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
  // Fresh optimizer statistics of the driver tables (step 7.2 WP2 fix, §13): InnoDB recalculates
  // persistent statistics in the background after bulk changes, so a run that follows other
  // suites could EXPLAIN with stale estimates (5 rows of quarantine_messages → a loose index scan
  // with a temporary table and a filesort). ANALYZE TABLE is replicated; the click rows written
  // after it (awaited on the replica below) prove that the replica applied it.
  await ctx.prisma.$queryRawUnsafe(
    'ANALYZE TABLE `email_messages`, `email_recipients`, `email_deliveries`, `quarantine_messages`',
  );
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

const window = (): DriverWindow => ({
  organizationId: org.id,
  range,
  direction: 'desc',
  nonce: 'n',
});
/** A cursor position one day back (the page then spans a partition boundary at most once). */
const deepAfter = () => ({ at: new Date(now - DAY), id: 2n ** 62n });
/** Exact pages read `limit + 1` entries plus one boundary step per pruned partition and one. */
const exactBound = (tables: ExplainTable[]) =>
  26 + Math.max(...tables.map((t) => t.partitions?.length ?? 1)) + 2;

describe('EXPLAIN on the replica (step 6.1 D5, D6; step 7.2 §2 E1, §9)', () => {
  it('reads from the replica (read_only)', async () => {
    const [row] = await replica.$queryRaw<
      Array<{ ro: number | bigint }>
    >`SELECT @@global.read_only AS ro`;
    expect(Number(row!.ro)).toBe(1);
    expect(await replica.emailMessage.count({ where: { organizationId: org.id } })).toBe(COUNT);
  });

  it('driver none (6.1 index plan): (organization_id, received_at, id), pruned, no filesort, reads ≈ limit', async () => {
    const sql = messagesPageSql({ ...window(), driver: 'none', take: 26, after: deepAfter() });
    const { tables, filesort } = await explain(sql);
    expect(tables[0]!.key).toBe(MESSAGE_INDEXES.orgReceived);
    expect(tables[0]!.partitions!.length).toBeLessThan(partitionCount);
    expect(filesort).toBe(false);
    expect(await handlerReads(sql)).toBeLessThanOrEqual(exactBound(tables));
    timings.push(
      `driver none EXPLAIN: key=${tables[0]!.key} partitions=${tables[0]!.partitions!.join(',')}`,
    );

    // Why the drivers name their index: the 6.1 statement through MessagesRepository.listRecent
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

  const EXACT_DRIVERS: Array<[MessagesTableDriver, string]> = [
    ['internetMessageId', `bulk-${run}-25000@sender.example`],
    ['sender', 'bulk5@sender.example'],
    ['headerFrom', 'Bulk 5 <bulk5@sender.example>'],
    ['subject', `Bulk subject ${run} 7`],
    ['senderDomain', 'sender.example'],
    ['verdict', 'phishing'],
  ];
  it.each(EXACT_DRIVERS)(
    'exact %s driver: its index, pruned, no filesort, reads ≈ limit',
    async (driver, driverKey) => {
      const sql = messagesPageSql({
        ...window(),
        driver,
        key: driverKey,
        take: 26,
        after: deepAfter(),
      });
      const { tables, filesort } = await explain(sql);
      expect(tables[0]!.key).toBe(MESSAGES_DRIVERS[driver].index);
      expect(tables[0]!.partitions!.length).toBeLessThan(partitionCount);
      expect(filesort).toBe(false);
      const reads = await handlerReads(sql);
      expect(reads).toBeLessThanOrEqual(exactBound(tables));
      const rows = await replica.$queryRaw<unknown[]>(sql);
      if (driver !== 'internetMessageId') expect(rows).toHaveLength(26);
      timings.push(
        `driver ${driver} EXPLAIN: key=${tables[0]!.key} partitions=${tables[0]!.partitions!.length} reads=${reads}`,
      );
    },
  );

  it('budgeted email_messages driver: boundary index-only at the budget, page within the budget', async () => {
    for (const driver of ['subject', 'senderDomain', 'scan'] as const) {
      const key =
        driver === 'subject'
          ? `Bulk subject ${run} 7`
          : driver === 'senderDomain'
            ? 'sender.example'
            : undefined;
      const boundarySql = messagesBoundarySql({ ...window(), driver, key, budget: BUDGET });
      const boundary = await explain(boundarySql);
      expect(boundary.tables[0]!.key).toBe(MESSAGES_DRIVERS[driver as MessagesTableDriver].index);
      expect(boundary.tables[0]!.using_index).toBe(true);
      expect(boundary.filesort).toBe(false);
      const boundaryReads = await handlerReads(boundarySql);
      expect(boundaryReads).toBeLessThanOrEqual(BUDGET + 2);
      const [edge] = await replica.$queryRaw<Array<{ received_at: Date; id: bigint }>>(boundarySql);
      const pageSql = messagesPageSql({
        ...window(),
        driver,
        key,
        take: 26,
        boundary: edge ? { at: edge.received_at, id: BigInt(edge.id) } : null,
        residuals: residualSql(org.id, { direction: ['outbound'], hasAttachments: true }),
      });
      const page = await explain(pageSql);
      expect(page.tables[0]!.key).toBe(MESSAGES_DRIVERS[driver as MessagesTableDriver].index);
      expect(page.tables[0]!.partitions!.length).toBeLessThan(partitionCount);
      const pageReads = await handlerReads(pageSql);
      expect(pageReads).toBeLessThanOrEqual(BUDGET + 2);
      timings.push(
        `driver ${driver} budgeted: boundary reads=${boundaryReads}, page reads=${pageReads} (budget ${BUDGET})`,
      );
    }
  });

  it('recipient driver: the address index (exact), budgeted join ordered by the recipient keyset', async () => {
    const step1 = recipientRowsSql({ ...window(), address: hot, take: 26 });
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
    const boundarySql = recipientBoundarySql({ ...window(), address: hot, budget: 200 });
    expect((await explain(boundarySql)).tables[0]!.key).toBe(MESSAGE_INDEXES.recipientAddress);
    const [edge] = await replica.$queryRaw<Array<{ received_at: Date; id: bigint }>>(boundarySql);
    const pageSql = recipientPageSql({
      ...window(),
      address: hot,
      take: 26,
      boundary: edge ? { at: edge.received_at, id: BigInt(edge.id) } : null,
      residuals: residualSql(org.id, { verdict: ['clean', 'phishing'] }),
    });
    const page = await explain(pageSql);
    const r = page.tables.find((t) => t.table_name === 'r')!;
    const m = page.tables.find((t) => t.table_name === 'm')!;
    expect(r.key).toBe(MESSAGE_INDEXES.recipientAddress);
    expect(m.key).toBe('PRIMARY');
    // Budget entries plus at most one primary-key lookup of the message each.
    const reads = await handlerReads(pageSql);
    expect(reads).toBeLessThanOrEqual(2 * (200 + 2));
    timings.push(
      `driver recipient: step1 key=${one.tables[0]!.key}; budgeted page r=${r.key} m=${m.key} reads=${reads} (budget 200)`,
    );
  });

  it.each([
    ['recipientDomain', 'acme.example'],
    ['deliveryStatus', 'bounced'],
    ['quarantineStatus', 'held'],
  ] as const)(
    'foreign %s driver: grouped keys in index order (no temporary table, no filesort), budgeted join',
    async (driver, key) => {
      const sql = foreignKeysSql({ ...window(), driver, key, take: 26, after: deepAfter() });
      const plan = await explain(sql);
      const t = plan.tables.find((x) => x.table_name === 't')!;
      expect(t.key).toBe(FOREIGN_DRIVERS[driver].index);
      expect(t.partitions?.length ?? 0).toBeLessThanOrEqual(partitionCount);
      expect(plan.filesort, plan.text).toBe(false);
      expect(plan.temporary, plan.text).toBe(false);
      const reads = await handlerReads(sql);
      // One driver entry per message in this fixture: ≈ limit groups.
      expect(reads).toBeLessThanOrEqual(exactBound(plan.tables));
      const keys = await replica.$queryRaw<Array<{ id: bigint; received_at: Date }>>(sql);
      expect(keys).toHaveLength(26);
      const boundarySql = foreignBoundarySql({ ...window(), driver, key, budget: BUDGET });
      const boundary = await explain(boundarySql);
      expect(boundary.tables[0]!.key).toBe(FOREIGN_DRIVERS[driver].index);
      expect(boundary.tables[0]!.using_index).toBe(true);
      const boundaryReads = await handlerReads(boundarySql);
      expect(boundaryReads).toBeLessThanOrEqual(BUDGET + 2);
      const [edge] = await replica.$queryRaw<Array<{ received_at: Date; id: bigint }>>(boundarySql);
      const pageSql = foreignPageSql({
        ...window(),
        driver,
        key,
        take: 26,
        boundary: edge ? { at: edge.received_at, id: BigInt(edge.id) } : null,
        residuals: residualSql(org.id, { direction: ['outbound'] }),
      });
      const page = await explain(pageSql);
      expect(page.tables.find((x) => x.table_name === 't')!.key).toBe(
        FOREIGN_DRIVERS[driver].index,
      );
      expect(page.tables.find((x) => x.table_name === 'm')!.key).toBe('PRIMARY');
      // The budget's index entries, the grouped keys read back from the materialized derived
      // table (at most the budget) and one primary-key lookup of the message each.
      const pageReads = await handlerReads(pageSql);
      expect(pageReads).toBeLessThanOrEqual(3 * (BUDGET + 2));
      timings.push(
        `driver ${driver}: exact reads=${reads}; budgeted boundary reads=${boundaryReads}, page reads=${pageReads} (budget ${BUDGET})`,
      );
    },
  );

  it('subject prefix driver: index-only probe bounded by the cap, sorted page within the cap', async () => {
    const pattern = subjectPrefixPattern(`Bulk subject ${run} 4`);
    // "… 4" matches subjects 4 and 40-49: 11 × 1 000 = 11 000 messages, above the default cap.
    const probe = prefixProbeSql({ ...window(), pattern, cap: 5_000, timeoutMs: 5_000 });
    const plan = await explain(probe);
    const t = plan.tables.find((x) => x.table_name === 'm')!;
    expect(t.key).toBe(MESSAGE_INDEXES.subjectKey);
    expect(t.using_index).toBe(true);
    expect(plan.filesort).toBe(false);
    const probeReads = await handlerReads(probe);
    expect(probeReads).toBeLessThanOrEqual(5_000 + 2);
    // The 5 001st match exists: too broad.
    expect(await replica.$queryRaw<unknown[]>(probe)).toHaveLength(1);
    // An exact-length prefix of one subject (1 000 matches) sorts within the cap.
    const narrow = subjectPrefixPattern(`Bulk subject ${run} 7`);
    const pageSql = prefixPageSql({
      ...window(),
      pattern: narrow,
      take: 26,
      timeoutMs: 5_000,
      residuals: [],
    });
    const page = await explain(pageSql);
    expect(page.tables[0]!.key).toBe(MESSAGE_INDEXES.subjectKey);
    const pageReads = await handlerReads(pageSql);
    expect(pageReads).toBeLessThanOrEqual(5_000 + 2);
    timings.push(
      `driver subjectPrefix: probe key=${t.key} index-only=${t.using_index} reads=${probeReads}; page filesort=${page.filesort} reads=${pageReads}`,
    );
  });

  it('a probe interrupted by MAX_EXECUTION_TIME is 503 message_search_timeout', async () => {
    const repo = ctx.get(MessageDataRepository);
    await expect(
      repo.prefixProbe(systemScope(org.id), {
        organizationId: org.id,
        range,
        direction: 'desc',
        pattern: subjectPrefixPattern('Bul'),
        cap: 49_000,
        timeoutMs: 1,
      }),
    ).rejects.toMatchObject({ code: 'message_search_timeout', status: 503 });
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

  it('times the API pages of every driver', async () => {
    const from = range.from.toISOString();
    const first = await timed('GET /messages (none, 4 days)', `/messages?from=${from}`);
    await timed(
      'GET /messages (none, page 2)',
      `/messages?from=${from}&cursor=${encodeURIComponent(first.body.nextCursor)}`,
    );
    await timed('GET /messages?verdict=phishing', `/messages?from=${from}&verdict=phishing`);
    await timed('GET /messages?recipient=', `/messages?from=${from}&recipient=${hot}`);
    await timed(
      'GET /messages?internetMessageId=',
      `/messages?from=${from}&internetMessageId=${encodeURIComponent(`bulk-${run}-25000@sender.example`)}`,
    );
    await timed('GET /messages?sender=', `/messages?from=${from}&sender=bulk5@sender.example`);
    await timed(
      'GET /messages?headerFrom=',
      `/messages?from=${from}&headerFrom=${encodeURIComponent('Bulk 5 <bulk5@sender.example>')}`,
    );
    await timed(
      'GET /messages?subject=',
      `/messages?from=${from}&subject=${encodeURIComponent(`Bulk subject ${run} 7`)}`,
    );
    await timed(
      'GET /messages?senderDomain=',
      `/messages?from=${from}&senderDomain=sender.example`,
    );
    await timed(
      'GET /messages?recipientDomain=',
      `/messages?from=${from}&recipientDomain=acme.example`,
    );
    await timed(
      'GET /messages?subjectPrefix= (1 000 matches)',
      `/messages?from=${from}&subjectPrefix=${encodeURIComponent(`Bulk subject ${run} 7`)}`,
    );
    const broad = await getAs(
      ctx,
      key,
      `/messages?from=${from}&subjectPrefix=${encodeURIComponent(`Bulk subject ${run} 4`)}`,
    );
    expect(broad.status).toBe(422);
    expect(broad.body.code).toBe('message_search_too_broad');
    await timed(
      'GET /messages?quarantineStatus=held',
      `/messages?from=${from}&quarantineStatus=held`,
    );
    await timed(
      'GET /messages?deliveryStatus=bounced',
      `/messages?from=${from}&deliveryStatus=bounced`,
    );
    await timed(
      'GET /messages?deliveryStatus=bounced&direction=outbound (budgeted)',
      `/messages?from=${from}&deliveryStatus=bounced&direction=outbound`,
    );
    const scan = await timed(
      'GET /messages?direction=outbound (scan)',
      `/messages?from=${from}&direction=outbound&limit=100`,
    );
    expect(scan.body.data.length).toBeGreaterThan(0);
    // A sender that never sent: an exact driver answers an empty last page at once.
    const sparse = await timed(
      'GET /messages?sender=<none> (exact, empty)',
      `/messages?from=${from}&sender=nobody@nowhere.example`,
    );
    expect(sparse.body.data).toEqual([]);
    expect(sparse.body.nextCursor).toBeNull();
    // Residuals only, a rare match: the budget ends short pages.
    const rare = await timed(
      'GET /messages?riskScore.gte=999 (scan, short page)',
      `/messages?from=${from}&riskScore.gte=999`,
    );
    expect(rare.body.nextCursor).toEqual(expect.any(String));
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
