/**
 * Step 6.1 WP3 integration (real MySQL writer + replica, Redis): the reports
 * (docs/plan/steps/18-rest-api.md §3.3, D12) against seeded messages over several days,
 * directions and verdicts, quarantine entries and URL clicks; counts equal to SQL ground truth on
 * the writer, the Redis cache (hit on the second call), `MAX_EXECUTION_TIME` → report_timeout,
 * and EXPLAIN FORMAT=JSON of the report statements (index, index-only traffic, pruned partitions).
 * Step 7.1 (docs/plan/steps/20-admin-portal.md §3.3): the delivery, processing and top-domains
 * reports and the threats `outcomes` against a second, hand-computed fixture organization
 * (deliveries, scan rounds, an active, a deleted and a clean domain, messages without a domain),
 * their cache, timeout and EXPLAIN (covering index, index-only, pruning).
 */
// @covers get /api/v1/reports/traffic
// @covers get /api/v1/reports/threats
// @covers get /api/v1/reports/url-clicks
// @covers get /api/v1/reports/delivery
// @covers get /api/v1/reports/processing
// @covers get /api/v1/reports/top-domains
import { HttpStatus } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { CodedHttpException } from '../src/http/coded-exception';
import { KeyValueStore } from '../src/kv/key-value-store';
import { reportCacheKey } from '../src/modules/reports/domain/report-cache-key';
import { ReportExecutor } from '../src/modules/reports/report-executor';
import { ReportMetrics } from '../src/modules/reports/report-metrics';
import { reportSql, ReportsRepository } from '../src/modules/reports/reports.repository';
import { ReportsService } from '../src/modules/reports/reports.service';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, login } from './support/http';
import {
  DAY_MS,
  deleteInsightFixtures,
  explain,
  HOUR_MS,
  insertClicks,
  insertDeliveries,
  insertDomain,
  insertMessages,
  insertQuarantineEntries,
  insertScanRounds,
  type MessageSpec,
  partitionsOf,
  POLL,
  reader,
  utcDay,
  waitFor,
} from './support/insights';

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let token: string;
let apiKey: string;

const DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;
const VERDICTS = ['clean', 'spam', 'phishing', null] as const;
const ACTIONS = ['deliver', 'quarantine', 'reject', null] as const;
const MESSAGES = 60;

const from = utcDay(3);
const to = utcDay(0);

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  fx.registerCleanup(() => deleteInsightFixtures(ctx, [org.id]));
  const admin = await fx.createUser(org, { roles: ['organization_admin'] });
  token = (
    await login(ctx, { email: admin.email, password: admin.password, organization: org.slug })
  ).body.accessToken as string;
  apiKey = await fx.createApiKey(org, ['report:read']);

  // 60 messages over the 3 days before today, every direction, verdict (null too) and action.
  const specs: MessageSpec[] = [];
  for (let i = 0; i < MESSAGES; i += 1) {
    specs.push({
      receivedAt: new Date(from.getTime() + (i % 3) * DAY_MS + (i % 24) * HOUR_MS + i * 1000),
      direction: DIRECTIONS[i % 3]!,
      verdict: VERDICTS[i % 4]!,
      action: ACTIONS[(i >> 1) % 4]!,
    });
  }
  // Outside the window (must not count): today and four days ago.
  specs.push({
    receivedAt: new Date(to.getTime() + HOUR_MS),
    direction: 'inbound',
    verdict: 'spam',
  });
  specs.push({
    receivedAt: new Date(from.getTime() - HOUR_MS),
    direction: 'inbound',
    verdict: 'spam',
  });
  await insertMessages(ctx, org, specs);
  await insertQuarantineEntries(ctx, org, [
    { quarantinedAt: new Date(from.getTime() + HOUR_MS), reason: 'phishing', primaryEngine: 'url' },
    {
      quarantinedAt: new Date(from.getTime() + 2 * HOUR_MS),
      reason: 'phishing',
      primaryEngine: 'url',
    },
    { quarantinedAt: new Date(from.getTime() + DAY_MS), reason: 'spam', primaryEngine: 'rspamd' },
    {
      quarantinedAt: new Date(to.getTime() + HOUR_MS),
      reason: 'malware',
      primaryEngine: 'attachment',
    },
  ]);
  await insertClicks(ctx, org, [
    { clickedAt: new Date(from.getTime() + 3 * HOUR_MS), decision: 'allowed' },
    { clickedAt: new Date(from.getTime() + 3 * HOUR_MS + 1), decision: 'blocked' },
    { clickedAt: new Date(from.getTime() + DAY_MS + 5 * HOUR_MS), decision: 'warned' },
    { clickedAt: new Date(from.getTime() - HOUR_MS), decision: 'blocked' },
  ]);
  // The replica must have every row before the first (cached) report.
  const read = reader(ctx);
  await waitFor(
    async () =>
      (await read.emailMessage.count({ where: { organizationId: org.id } })) +
      (await read.quarantineMessage.count({ where: { organizationId: org.id } })) +
      (await read.urlClickEvent.count({ where: { organizationId: org.id } })),
    MESSAGES + 2 + 4 + 4,
  );
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

const q = (path: string, params: Record<string, string>) =>
  `${path}?${new URLSearchParams(params).toString()}`;

/** Ground truth on the writer: plain GROUP BY without the report code. */
async function truthByDayDirectionVerdict(): Promise<Map<string, number>> {
  const rows = await ctx.prisma.$queryRaw<
    Array<{ d: string; direction: string; verdict: string | null; n: bigint }>
  >`SELECT DATE_FORMAT(received_at, '%Y-%m-%d') AS d, direction, final_verdict AS verdict, COUNT(*) AS n
    FROM email_messages WHERE organization_id = ${org.id}
      AND received_at >= ${from} AND received_at < ${to}
    GROUP BY d, direction, verdict`;
  return new Map(rows.map((r) => [`${r.d}|${r.direction}|${r.verdict ?? 'none'}`, Number(r.n)]));
}

describe('GET /reports/traffic', () => {
  it('equals the SQL ground truth per day, direction and verdict', async () => {
    const res = await ctx.http
      .get(
        q('/api/v1/reports/traffic', {
          from: from.toISOString(),
          to: to.toISOString(),
          granularity: 'day',
        }),
      )
      .set(bearer(token))
      .expect(200);
    expect(res.body.from).toBe(from.toISOString());
    expect(res.body.to).toBe(to.toISOString());
    expect(res.body.buckets).toHaveLength(3);
    const truth = await truthByDayDirectionVerdict();
    let total = 0;
    for (const bucket of res.body.buckets as Array<
      Record<string, unknown> & { start: string; verdicts: Record<string, number> }
    >) {
      const day = bucket.start.slice(0, 10);
      for (const direction of DIRECTIONS) {
        const expected = [...truth]
          .filter(([k]) => k.startsWith(`${day}|${direction}|`))
          .reduce((a, [, n]) => a + n, 0);
        expect(bucket[direction], `${day} ${direction}`).toBe(expected);
      }
      for (const verdict of ['clean', 'spam', 'phishing', 'none']) {
        const expected = [...truth]
          .filter(([k]) => k.startsWith(`${day}|`) && k.endsWith(`|${verdict}`))
          .reduce((a, [, n]) => a + n, 0);
        expect(bucket.verdicts[verdict], `${day} ${verdict}`).toBe(expected);
      }
      total += bucket.total as number;
    }
    expect(total).toBe(MESSAGES);
    expect(res.body.totals.total).toBe(MESSAGES);
    expect(res.body.totals.verdicts.none).toBe(MESSAGES / 4);
  });

  it('aligns hour buckets, filters by direction and accepts API keys', async () => {
    const res = await ctx.http
      .get(
        q('/api/v1/reports/traffic', {
          from: new Date(from.getTime() + 30 * 60_000).toISOString(),
          to: new Date(from.getTime() + DAY_MS - 1).toISOString(),
          granularity: 'hour',
          direction: 'inbound',
        }),
      )
      .set(apiKeyHeader(apiKey))
      .expect(200);
    expect(res.body.buckets).toHaveLength(24);
    expect(res.body.buckets[0].start).toBe(from.toISOString());
    expect(res.body.totals.outbound).toBe(0);
    const [truth] = await ctx.prisma.$queryRaw<Array<{ n: bigint }>>`
      SELECT COUNT(*) AS n FROM email_messages WHERE organization_id = ${org.id}
        AND direction = 'inbound' AND received_at >= ${from} AND received_at < ${new Date(from.getTime() + DAY_MS)}`;
    expect(res.body.totals.inbound).toBe(Number(truth!.n));
    expect(res.body.totals.total).toBe(Number(truth!.n));
  });

  it('caches per organization and window in Redis (hit on the second call)', async () => {
    const path = q('/api/v1/reports/traffic', { from: from.toISOString(), to: to.toISOString() });
    const first = await ctx.http.get(path).set(bearer(token)).expect(200);
    const second = await ctx.http.get(path).set(bearer(token)).expect(200);
    expect(second.body.generatedAt).toBe(first.body.generatedAt);
    const key = reportCacheKey(org.id, 'traffic', {
      from: from.toISOString(),
      to: to.toISOString(),
      granularity: 'day',
      direction: null,
    });
    const stored = JSON.parse((await ctx.get(KeyValueStore).get(key))!) as Record<string, unknown>;
    expect(stored).toMatchObject({ v: 1, organizationId: org.id.toString(), report: 'traffic' });
    expect(await ctx.get(KeyValueStore).ttl(key)).toBeLessThanOrEqual(
      ctx.config.REPORTS_CACHE_TTL_SECONDS,
    );
  });
});

describe('GET /reports/threats', () => {
  it('equals the SQL ground truth of verdicts, actions, reasons and engines', async () => {
    const res = await ctx.http
      .get(q('/api/v1/reports/threats', { from: from.toISOString(), to: to.toISOString() }))
      .set(bearer(token))
      .expect(200);
    const actions = await ctx.prisma.$queryRaw<Array<{ a: string | null; n: bigint }>>`
      SELECT final_action AS a, COUNT(*) AS n FROM email_messages WHERE organization_id = ${org.id}
        AND received_at >= ${from} AND received_at < ${to} GROUP BY a`;
    for (const row of actions)
      expect(res.body.messages.actions[row.a ?? 'none']).toBe(Number(row.n));
    // Step 7.1: the verdict × action matrix equals the plain GROUP BY.
    const pairs = await ctx.prisma.$queryRaw<
      Array<{ v: string | null; a: string | null; n: bigint }>
    >`SELECT final_verdict AS v, final_action AS a, COUNT(*) AS n FROM email_messages
        WHERE organization_id = ${org.id} AND received_at >= ${from} AND received_at < ${to}
        GROUP BY v, a`;
    const outcomes = res.body.outcomes as Array<{ verdict: string; action: string; count: number }>;
    expect(outcomes).toHaveLength(pairs.length);
    for (const row of pairs) {
      expect(
        outcomes.find((o) => o.verdict === (row.v ?? 'none') && o.action === (row.a ?? 'none'))
          ?.count,
      ).toBe(Number(row.n));
    }
    for (let i = 1; i < outcomes.length; i += 1) {
      expect(outcomes[i - 1]!.count).toBeGreaterThanOrEqual(outcomes[i]!.count);
    }
    expect(res.body.messages.total).toBe(MESSAGES);
    expect(res.body.quarantine).toMatchObject({
      total: 3,
      reasons: { phishing: 2, spam: 1, malware: 0 },
      primaryEngines: { url: 2, rspamd: 1, attachment: 0 },
    });
  });
});

describe('GET /reports/url-clicks', () => {
  it('buckets clicks by decision inside the window only', async () => {
    const res = await ctx.http
      .get(q('/api/v1/reports/url-clicks', { from: from.toISOString(), to: to.toISOString() }))
      .set(bearer(token))
      .expect(200);
    expect(res.body.totals).toEqual({
      total: 3,
      decisions: { allowed: 1, warned: 1, blocked: 1, continued: 0, expired: 0, not_found: 0 },
    });
    expect(res.body.buckets.map((b: { total: number }) => b.total)).toEqual([2, 1, 0]);
  });
});

describe('report statements (EXPLAIN FORMAT=JSON)', () => {
  const scopeOf = () => systemScope(org.id);
  const window = () => ({ from, to });

  it('traffic and billing directions are index-only over the covering index with pruned partitions', async () => {
    const all = await partitionsOf(ctx, 'email_messages');
    for (const sql of [
      reportSql.traffic(scopeOf(), window(), 'day', undefined, 10_000),
      reportSql.traffic(scopeOf(), window(), 'hour', 'inbound', 10_000),
      reportSql.directions(scopeOf(), window(), 10_000),
    ]) {
      const { tables, text } = await explain(ctx, sql);
      const t = tables.find((x) => x.table_name === 'email_messages')!;
      expect(t.key, text).toBe('email_messages_org_received_dir_verdict_idx');
      expect(t.access_type).toBe('range');
      expect(t.using_index, text).toBe(true);
      expect(t.partitions!.length).toBeLessThan(all.length);
      expect(text).not.toContain('"table_name": "email_messages", "access_type": "ALL"');
    }
  });

  it('threats, quarantine and clicks use their (organization_id, time) indexes with pruning', async () => {
    // The threats outcomes (verdict x action) are index-only too: final_action is covered.
    const outcomes = await explain(ctx, reportSql.outcomes(scopeOf(), window(), 10_000));
    const m = outcomes.tables.find((x) => x.table_name === 'email_messages')!;
    expect(m.key, outcomes.text).toBe('email_messages_org_received_dir_verdict_idx');
    expect(m.access_type).toBe('range');
    expect(m.using_index, outcomes.text).toBe(true);
    const quarantine = await explain(ctx, reportSql.quarantine(scopeOf(), window(), 10_000));
    const qt = quarantine.tables.find((x) => x.table_name === 'quarantine_messages')!;
    expect(qt.key).toMatch(/^quarantine_messages_organization_id_/);
    expect(['range', 'ref']).toContain(qt.access_type);
    const clicks = await explain(ctx, reportSql.clicks(scopeOf(), window(), 'day', 10_000));
    const ct = clicks.tables.find((x) => x.table_name === 'url_click_events')!;
    expect(ct.key).toBe('url_click_events_organization_id_clicked_at_idx');
    expect(ct.access_type).toBe('range');
    expect(ct.partitions!.length).toBeLessThan(
      (await partitionsOf(ctx, 'url_click_events')).length,
    );
  });
});

describe('report timeout', () => {
  it('a statement interrupted by MAX_EXECUTION_TIME is 503 report_timeout (tiny timeout)', async () => {
    // A separate organization with enough rows that a 1 ms budget cannot finish the GROUP BY.
    const big = await fx.createOrganization();
    fx.registerCleanup(() => deleteInsightFixtures(ctx, [big.id]));
    const start = utcDay(2);
    const specs: MessageSpec[] = [];
    for (let i = 0; i < 40_000; i += 1) {
      specs.push({
        receivedAt: new Date(start.getTime() + (i % ((2 * DAY_MS) / 1000)) * 1000 + (i % 997)),
        direction: DIRECTIONS[i % 3]!,
        verdict: VERDICTS[i % 4]!,
      });
    }
    await insertMessages(ctx, big, specs);
    await expect
      .poll(() => reader(ctx).emailMessage.count({ where: { organizationId: big.id } }), POLL)
      .toBe(specs.length);

    // The production classes with a 1 ms budget (config requires ≥ 1000 ms; constructed directly).
    const repository = new ReportsRepository(ctx.get(PrismaReadService), {
      REPORTS_QUERY_TIMEOUT_MS: 1,
    });
    const executor = new ReportExecutor(ctx.get(KeyValueStore), ctx.get(ReportMetrics), {
      REPORTS_CACHE_TTL_SECONDS: 10,
    });
    const service = new ReportsService(repository, executor, { REPORTS_MAX_RANGE_DAYS: 31 });
    const scope = systemScope(big.id);
    let caught: unknown;
    const started = Date.now();
    try {
      await service.traffic(scope, { from: start, to: utcDay(0), granularity: 'hour' });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(CodedHttpException);
    expect((caught as CodedHttpException).getStatus()).toBe(HttpStatus.SERVICE_UNAVAILABLE);
    expect((caught as CodedHttpException).code).toBe('report_timeout');
    expect(Date.now() - started).toBeLessThan(5_000);
    // Nothing was cached for the failed window.
    const key = reportCacheKey(big.id, 'traffic', {
      from: start.toISOString(),
      to: utcDay(0).toISOString(),
      granularity: 'hour',
      direction: null,
    });
    expect(await ctx.get(KeyValueStore).get(key)).toBeNull();

    // With the configured budget the same report completes and counts every row.
    const ok = await ctx
      .get(ReportsService)
      .traffic(scope, { from: start, to: utcDay(0), granularity: 'hour' });
    expect(ok.totals.total).toBe(specs.length);
    // The metric was counted.
    const metrics = await ctx.http.get('/metrics').expect(200);
    expect(metrics.text.split('\n').filter((l) => l.startsWith('api_report'))).toContainEqual(
      expect.stringMatching(/^api_report_timeouts_total\{[^}]*report="traffic"[^}]*\} [1-9]/),
    );
  });
});

// ---- Step 7.1: delivery, processing and top-domains (hand-computed expectations) ------------

describe('step 7.1 reports (docs/plan/steps/20-admin-portal.md §3.3)', () => {
  let portal: FixtureOrganization;
  let portalToken: string;
  let portalKey: string;
  const pFrom = utcDay(2);
  const pTo = utcDay(0);
  const domainIds: Record<
    'alpha' | 'beta' | 'gamma',
    { id: bigint; publicId: string; name: string }
  > = {} as never;

  beforeAll(async () => {
    portal = await fx.createOrganization();
    fx.registerCleanup(() => deleteInsightFixtures(ctx, [portal.id]));
    const admin = await fx.createUser(portal, { roles: ['organization_admin'] });
    portalToken = (
      await login(ctx, {
        email: admin.email,
        password: admin.password,
        organization: portal.slug,
      })
    ).body.accessToken as string;
    portalKey = await fx.createApiKey(portal, ['report:read']);
    domainIds.alpha = await insertDomain(ctx, portal, `alpha-${portal.slug}.example.test`);
    domainIds.beta = await insertDomain(ctx, portal, `beta-${portal.slug}.example.test`, {
      deleted: true,
    });
    domainIds.gamma = await insertDomain(ctx, portal, `gamma-${portal.slug}.example.test`);
    const a = domainIds.alpha.id;
    const b = domainIds.beta.id;
    const g = domainIds.gamma.id;
    const day0 = (minutes: number) => new Date(pFrom.getTime() + HOUR_MS + minutes * 60_000);
    const day1 = (minutes: number) =>
      new Date(pFrom.getTime() + DAY_MS + HOUR_MS + minutes * 60_000);
    const m = await insertMessages(ctx, portal, [
      {
        receivedAt: day0(1),
        direction: 'inbound',
        verdict: 'spam',
        action: 'quarantine',
        domainId: a,
      },
      {
        receivedAt: day0(2),
        direction: 'inbound',
        verdict: 'phishing',
        action: 'quarantine',
        domainId: a,
      },
      {
        receivedAt: day0(3),
        direction: 'inbound',
        verdict: 'clean',
        action: 'deliver',
        domainId: a,
      },
      {
        receivedAt: day0(4),
        direction: 'inbound',
        verdict: 'malware',
        action: 'reject',
        domainId: b,
      },
      { receivedAt: day0(5), direction: 'inbound', verdict: 'spam', action: 'tag', domainId: b },
      {
        receivedAt: day0(6),
        direction: 'inbound',
        verdict: 'clean',
        action: 'deliver',
        domainId: g,
      },
      { receivedAt: day0(7), direction: 'inbound', verdict: 'suspicious', action: 'deliver' },
      { receivedAt: day0(8), direction: 'inbound', verdict: 'clean', action: 'deliver' },
      { receivedAt: day0(9), direction: 'outbound', verdict: 'spam', action: 'tag', domainId: a },
      {
        receivedAt: day1(1),
        direction: 'inbound',
        verdict: 'bec',
        action: 'quarantine',
        domainId: a,
      },
      {
        receivedAt: day1(2),
        direction: 'inbound',
        verdict: 'clean',
        action: 'deliver',
        domainId: b,
      },
      { receivedAt: day1(3), direction: 'inbound', verdict: null, action: null },
      // Outside the window.
      {
        receivedAt: new Date(pTo.getTime() + HOUR_MS),
        direction: 'inbound',
        verdict: 'spam',
        domainId: a,
      },
    ]);
    const [m1, m2, m3, m4, , m6, , , , m10, m11, m12, m13] = m;
    await insertDeliveries(ctx, portal, [
      { message: m1!, status: 'delivered', deliveredAfterMs: 500 },
      { message: m1!, status: 'delivered', deliveredAfterMs: 7000 },
      { message: m2!, status: 'bounced' },
      { message: m3!, status: 'delivered', deliveredAfterMs: 7_200_000 },
      { message: m4!, status: 'failed' },
      { message: m6!, status: 'deferred' },
      { message: m10!, status: 'delivered' },
      { message: m10!, status: 'expired' },
      { message: m11!, status: 'queued' },
      { message: m13!, status: 'delivered', deliveredAfterMs: 100 },
    ]);
    await insertScanRounds(ctx, portal, [
      { message: m1!, status: 'completed', completedAfterMs: 200 },
      { message: m2!, status: 'completed', completedAfterMs: 800 },
      { message: m3!, status: 'completed', completedAfterMs: 3000 },
      { message: m4!, status: 'timed_out', completedAfterMs: 120_000 },
      {
        message: m4!,
        status: 'completed',
        kind: 'rescan',
        lifecycleRound: 1,
        completedAfterMs: 100,
      },
      { message: m10!, status: 'running' },
      { message: m11!, status: 'completed', completedAfterMs: 400_000 },
      { message: m12!, status: 'completed', completedAfterMs: 1_000_000 },
      { message: m13!, status: 'completed', completedAfterMs: 10 },
    ]);
    const read = reader(ctx);
    await waitFor(
      async () =>
        (await read.emailMessage.count({ where: { organizationId: portal.id } })) +
        (await read.emailDelivery.count({ where: { organizationId: portal.id } })) +
        (await read.emailScan.count({ where: { organizationId: portal.id } })) +
        (await read.domain.count({ where: { organizationId: portal.id } })),
      13 + 10 + 9 + 3,
    );
  });

  const range = () => ({ from: pFrom.toISOString(), to: pTo.toISOString() });

  it('GET /reports/delivery: statuses, success rates and latency per the fixture', async () => {
    const res = await ctx.http
      .get(q('/api/v1/reports/delivery', range()))
      .set(bearer(portalToken))
      .expect(200);
    expect(res.body.granularity).toBe('day');
    expect(
      res.body.buckets.map((b: { total: number; successRate: number | null }) => [
        b.total,
        b.successRate,
      ]),
    ).toEqual([
      [6, 0.6],
      [3, 0.5],
    ]);
    expect(res.body.buckets[0].statuses).toMatchObject({
      delivered: 3,
      bounced: 1,
      failed: 1,
      deferred: 1,
      queued: 0,
    });
    expect(res.body.totals).toEqual({
      total: 9,
      statuses: {
        pending: 0,
        in_progress: 0,
        queued: 1,
        deferred: 1,
        delivered: 4,
        bounced: 1,
        expired: 1,
        failed: 1,
        suppressed: 0,
        unknown: 0,
      },
      successRate: 0.5714,
    });
    expect(res.body.latency).toMatchObject({
      delivered: 3,
      averageMs: 2_402_500,
      p50UpperBoundMs: 10_000,
      p95UpperBoundMs: 14_400_000,
    });
    expect(
      (res.body.latency.histogram as Array<{ leMs: number | null; count: number }>).filter(
        (h) => h.count > 0,
      ),
    ).toEqual([
      { leMs: 1000, count: 1 },
      { leMs: 10_000, count: 1 },
      { leMs: 14_400_000, count: 1 },
    ]);
    // API keys with report:read; served from the Redis cache the second time.
    const again = await ctx.http
      .get(q('/api/v1/reports/delivery', range()))
      .set(apiKeyHeader(portalKey))
      .expect(200);
    expect(again.body.generatedAt).toBe(res.body.generatedAt);
    const key = reportCacheKey(portal.id, 'delivery', { ...range(), granularity: 'day' });
    expect(JSON.parse((await ctx.get(KeyValueStore).get(key))!)).toMatchObject({
      organizationId: portal.id.toString(),
      report: 'delivery',
    });
  });

  it('GET /reports/processing: initial rounds by status and the time to verdict', async () => {
    const res = await ctx.http
      .get(q('/api/v1/reports/processing', range()))
      .set(bearer(portalToken))
      .expect(200);
    expect(res.body.buckets).toEqual([
      {
        start: pFrom.toISOString(),
        rounds: 4,
        statuses: { pending: 0, running: 0, completed: 3, failed: 0, timed_out: 1 },
        averageMs: 1333,
        p95UpperBoundMs: 5000,
      },
      {
        start: new Date(pFrom.getTime() + DAY_MS).toISOString(),
        rounds: 3,
        statuses: { pending: 0, running: 1, completed: 2, failed: 0, timed_out: 0 },
        averageMs: 700_000,
        p95UpperBoundMs: null,
      },
    ]);
    expect(res.body.totals).toMatchObject({
      rounds: 7,
      statuses: { pending: 0, running: 1, completed: 5, failed: 0, timed_out: 1 },
      averageMs: 280_800,
      p50UpperBoundMs: 5000,
      p95UpperBoundMs: null,
    });
    expect(
      (res.body.totals.histogram as Array<{ leMs: number | null; count: number }>).filter(
        (h) => h.count > 0,
      ),
    ).toEqual([
      { leMs: 250, count: 1 },
      { leMs: 1000, count: 1 },
      { leMs: 5000, count: 1 },
      { leMs: 900_000, count: 1 },
      { leMs: null, count: 1 },
    ]);
  });

  it('GET /reports/top-domains: ranking, deleted domains, unattributed, limit', async () => {
    const res = await ctx.http
      .get(q('/api/v1/reports/top-domains', range()))
      .set(bearer(portalToken))
      .expect(200);
    expect(res.body.domains).toEqual([
      {
        domainId: domainIds.alpha.publicId,
        name: domainIds.alpha.name,
        status: 'active',
        deleted: false,
        inbound: 4,
        threats: 3,
        verdicts: { spam: 1, phishing: 1, malware: 0, bec: 1, suspicious: 0 },
      },
      {
        domainId: domainIds.beta.publicId,
        name: domainIds.beta.name,
        status: 'deleted',
        deleted: true,
        inbound: 3,
        threats: 2,
        verdicts: { spam: 1, phishing: 0, malware: 1, bec: 0, suspicious: 0 },
      },
    ]);
    expect(res.body.unattributed).toEqual({ inbound: 3, threats: 1 });
    const one = await ctx.http
      .get(q('/api/v1/reports/top-domains', { ...range(), limit: '1' }))
      .set(apiKeyHeader(portalKey))
      .expect(200);
    expect(one.body.domains.map((d: { name: string }) => d.name)).toEqual([domainIds.alpha.name]);
  });

  it('GET /reports/threats: the outcomes matrix of the fixture', async () => {
    const res = await ctx.http
      .get(q('/api/v1/reports/threats', range()))
      .set(bearer(portalToken))
      .expect(200);
    expect(res.body.outcomes).toEqual([
      { verdict: 'clean', action: 'deliver', count: 4 },
      { verdict: 'spam', action: 'tag', count: 2 },
      { verdict: 'bec', action: 'quarantine', count: 1 },
      { verdict: 'malware', action: 'reject', count: 1 },
      { verdict: 'none', action: 'none', count: 1 },
      { verdict: 'phishing', action: 'quarantine', count: 1 },
      { verdict: 'spam', action: 'quarantine', count: 1 },
      { verdict: 'suspicious', action: 'deliver', count: 1 },
    ]);
  });

  it('a domain id that does not resolve inside the tenant is 503 inconsistent_read', async () => {
    // A message of this organization pointing at another organization's domain (corrupt data):
    // the name is never shown.
    const stranger = await fx.createOrganization();
    const foreign = await insertDomain(ctx, stranger, `foreign-${stranger.slug}.example.test`);
    const [bad] = await insertMessages(ctx, portal, [
      {
        receivedAt: new Date(pFrom.getTime() + 2 * HOUR_MS),
        direction: 'inbound',
        verdict: 'phishing',
        domainId: foreign.id,
      },
    ]);
    try {
      await expect
        .poll(() => reader(ctx).emailMessage.count({ where: { organizationId: portal.id } }), POLL)
        .toBe(14);
      const res = await ctx.http
        .get(q('/api/v1/reports/top-domains', { ...range(), limit: '7' }))
        .set(bearer(portalToken))
        .expect(503);
      expect(res.body.code).toBe('inconsistent_read');
      expect(JSON.stringify(res.body)).not.toContain(foreign.name);
    } finally {
      await ctx.prisma.emailMessage.deleteMany({
        where: { id: bad!.id, receivedAt: bad!.receivedAt },
      });
    }
  });

  it('EXPLAIN: the three statements use their covering index, index-only, with pruning', async () => {
    const scope = systemScope(portal.id);
    const window = { from: pFrom, to: pTo };
    for (const [table, sql, key] of [
      [
        'email_deliveries',
        reportSql.deliveries(scope, window, 'day', 10_000),
        'email_deliveries_org_received_status_idx',
      ],
      [
        'email_deliveries',
        reportSql.deliveries(scope, window, 'hour', 10_000),
        'email_deliveries_org_received_status_idx',
      ],
      [
        'email_scans',
        reportSql.scanRounds(scope, window, 'day', 10_000),
        'email_scans_org_received_kind_status_idx',
      ],
      [
        'email_messages',
        reportSql.domainVerdicts(scope, window, 10_000),
        'email_messages_org_received_dir_verdict_idx',
      ],
    ] as const) {
      const { tables, text } = await explain(ctx, sql);
      const t = tables.find((x) => x.table_name === table)!;
      expect(t.key, text).toBe(key);
      expect(t.access_type, text).toBe('range');
      expect(t.using_index, text).toBe(true);
      expect(t.partitions!.length, text).toBeLessThan((await partitionsOf(ctx, table)).length);
    }
  });
});

describe('step 7.1 report timeouts', () => {
  it('delivery, processing and top-domains interrupted by MAX_EXECUTION_TIME are 503 report_timeout', async () => {
    const big = await fx.createOrganization();
    fx.registerCleanup(() => deleteInsightFixtures(ctx, [big.id]));
    const start = utcDay(2);
    const n = 40_000;
    const messages = await insertMessages(
      ctx,
      big,
      Array.from({ length: n }, (_, i) => ({
        receivedAt: new Date(start.getTime() + (i % ((2 * DAY_MS) / 1000)) * 1000 + (i % 997)),
        direction: 'inbound' as const,
        verdict: VERDICTS[i % 4]!,
      })),
    );
    await insertDeliveries(
      ctx,
      big,
      messages.map((message, i) => ({
        message,
        status: i % 2 === 0 ? ('delivered' as const) : ('deferred' as const),
        deliveredAfterMs: i % 2 === 0 ? (i % 50) * 1000 : null,
      })),
    );
    await insertScanRounds(
      ctx,
      big,
      messages.map((message, i) => ({ message, status: 'completed', completedAfterMs: i % 5000 })),
    );
    const read = reader(ctx);
    await waitFor(
      async () =>
        (await read.emailMessage.count({ where: { organizationId: big.id } })) +
        (await read.emailDelivery.count({ where: { organizationId: big.id } })) +
        (await read.emailScan.count({ where: { organizationId: big.id } })),
      3 * n,
    );
    const repository = new ReportsRepository(ctx.get(PrismaReadService), {
      REPORTS_QUERY_TIMEOUT_MS: 1,
    });
    const executor = new ReportExecutor(ctx.get(KeyValueStore), ctx.get(ReportMetrics), {
      REPORTS_CACHE_TTL_SECONDS: 10,
    });
    const service = new ReportsService(repository, executor, { REPORTS_MAX_RANGE_DAYS: 31 });
    const scope = systemScope(big.id);
    const query = { from: start, to: utcDay(0), granularity: 'hour' as const };
    for (const [name, run] of [
      ['delivery', () => service.delivery(scope, query)],
      ['processing', () => service.processing(scope, query)],
      ['top-domains', () => service.topDomains(scope, { from: start, to: utcDay(0) })],
    ] as const) {
      let caught: unknown;
      try {
        await run();
      } catch (err) {
        caught = err;
      }
      expect(caught, name).toBeInstanceOf(CodedHttpException);
      expect((caught as CodedHttpException).code, name).toBe('report_timeout');
    }
    // With the configured budget the same reports complete and count every row.
    const reports = ctx.get(ReportsService);
    const delivery = await reports.delivery(scope, query);
    expect(delivery.totals.total).toBe(n);
    expect(delivery.latency.delivered).toBe(n / 2);
    const processing = await reports.processing(scope, query);
    expect(processing.totals.rounds).toBe(n);
    const top = await reports.topDomains(scope, { from: start, to: utcDay(0) });
    expect(top.unattributed.inbound).toBe(n);
    const metrics = await ctx.http.get('/metrics').expect(200);
    for (const report of ['delivery', 'processing', 'top-domains']) {
      expect(metrics.text.split('\n')).toContainEqual(
        expect.stringMatching(
          new RegExp(`^api_report_timeouts_total\\{[^}]*report="${report}"[^}]*\\} [1-9]`),
        ),
      );
    }
  }, 120_000);
});
