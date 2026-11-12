/**
 * Step 6.1 WP3 integration (real MySQL writer + replica, Redis): the reports
 * (docs/plan/steps/18-rest-api.md §3.3, D12) against seeded messages over several days,
 * directions and verdicts, quarantine entries and URL clicks; counts equal to SQL ground truth on
 * the writer, the Redis cache (hit on the second call), `MAX_EXECUTION_TIME` → report_timeout,
 * and EXPLAIN FORMAT=JSON of the report statements (index, index-only traffic, pruned partitions).
 */
// @covers get /api/v1/reports/traffic
// @covers get /api/v1/reports/threats
// @covers get /api/v1/reports/url-clicks
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
  insertMessages,
  insertQuarantineEntries,
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
