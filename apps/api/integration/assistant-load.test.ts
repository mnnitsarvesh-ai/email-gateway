/**
 * Opt-in load test of the AI assistant (step AI-6 D11, docs/plan/steps/34-ai-chat-hardening-
 * operations.md; method and results in docs/performance/assistant-load.md). Skipped unless
 * ASSISTANT_LOAD_TEST=1; never part of the targeted or full integration chains:
 *
 *   cd apps/api && ASSISTANT_LOAD_TEST=1 npx vitest run --config vitest.integration.config.ts \
 *     integration/assistant-load.test.ts
 *
 * Parameters (support/assistant-load.ts): ASSISTANT_LOAD_USERS (20), ASSISTANT_LOAD_TURNS (5),
 * ASSISTANT_LOAD_MIX (`read=2,chain=1,write=1,report=1`), ASSISTANT_LOAD_LATENCY_MS (300),
 * ASSISTANT_LOAD_USERS_PER_ORG (2), ASSISTANT_LOAD_PACE_MS (0), ASSISTANT_LOAD_SIGNAL_PATH.
 *
 * The real api pipeline in-process on its ephemeral loopback port (guards, RBAC, the API rate
 * classes and the assistant's limits at their production defaults, MySQL writer and replica,
 * Redis, MinIO) with the deterministic fake provider only (`assertFakeProvider`; a per-round
 * delay of ASSISTANT_LOAD_LATENCY_MS and chunked deltas), synthetic `it-load-*` organizations.
 * Scenarios, one printed result line each:
 *
 * 1. `mixed`: every user runs ASSISTANT_LOAD_TURNS JSON turns in its own conversation at once:
 *    reads of one tool round (demo intents and directives), `/chain` reads of three rounds, write
 *    proposals (the fake's create-policy plan: two read rounds and the proposal; then
 *    `add dlp dictionary` proposals) each confirmed right away, and one report of 30 days (a
 *    background job, D5). Only `429 rate_limited` / `503 assistant_busy` are acceptable errors.
 * 2. `report-jobs`: the queued jobs run through `ReportJobProcessor.handle` with the envelopes of
 *    their outbox rows (what the consumer receives), ASSISTANT_REPORT_JOB_CONCURRENCY at a time.
 *    The live event-relay container is paused for the suite (support/live-relay.ts), so the rows
 *    are not published; the RabbitMQ hop is covered by assistant-report-jobs.test.ts, not here.
 * 3. `burst`: in a fresh minute, min(users × 5, ASSISTANT_MAX_CONCURRENT_TURNS + 10) one-round
 *    turns at once in separate conversations: the per-process concurrency limit answers
 *    `503 assistant_busy` beyond 20 running turns, nothing else.
 *
 * Consistency (after the scenarios): one execution row per tool call the client saw and one
 * audit row per execution; every confirmed write sent exactly once and audited once; the Redis
 * token counters (tenant and user) equal the usage rows; no turn left `running`; every report job
 * succeeded with its object stored. Every row, object and counter of the run is removed.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { assistantKeys, utcDayKey } from '../src/modules/assistant/assistant.constants';
import { budgetTokens } from '../src/modules/assistant/repositories/usage.repository';
import {
  ReportJobProcessor,
  ReportJobRetryError,
} from '../src/modules/assistant/services/reports/report-job.processor';
import { DlpTenantDataRepository } from '../src/modules/tenant-data/dlp-tenant-data.repository';
import { AssistantTenantDataRepository } from '../src/modules/tenant-data/assistant-tenant-data.repository';
import { PolicyTenantDataRepository } from '../src/modules/tenant-data/policy-tenant-data.repository';
import type { IntegrationApp } from './support/app';
import {
  A,
  ALL_TENANT_PERMISSIONS,
  allFeatures,
  call,
  clearAssistantCounters,
  type ConfirmationJson,
  confirm,
  confirmationsOfTurn,
  enableAssistant,
  type Member,
  memberWith,
  newConversation,
  platformMember,
  recordLoopback,
  trackReports,
  turn,
} from './support/assistant';
import {
  createLoadApp,
  countError,
  describeParams,
  loadParams,
  markLoadOrganization,
  newStats,
  nextMinute,
  percentile,
  print,
  pool,
  reportJobEnvelopes,
  resultLine,
  type ScenarioStats,
  signalStart,
  sleep,
  startProbes,
  type TurnKind,
  turnPlan,
} from './support/assistant-load';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { pauseLiveRelay } from './support/live-relay';

const params = loadParams();
const RUN = !!process.env.ASSISTANT_LOAD_TEST;
/** Generous per-test timeout: the default profile runs in about a minute, larger ones longer. */
const LONG = 30 * 60_000;

/** One-round reads (demo intents and directives; tool names are registry names). */
const READS = ['show policies', 'list the domains', 'list users', '/tool roles_list {}'];
/** A three-round read through the load provider's `/chain` directive. */
const CHAIN_READ = '/chain users_list,domains_list,policy_management_list';
const POLICY_PLAN = 'create an inbound policy that quarantines executables';
const REPORT_30_DAYS = 'generate a report for the last 30 days';
/** Codes the documented limits may answer under load (D11). */
const ACCEPTABLE = new Set(['429 rate_limited', '503 assistant_busy']);

interface LoadUser {
  member: Member;
  org: FixtureOrganization;
  /** Index of the user within its organization (0 = the one that runs the policy plan). */
  slot: number;
  conversation: string;
}

interface Confirmed {
  confirmation: ConfirmationJson;
}

let ctx: IntegrationApp;
let fx: Fixtures;
let resumeRelay: (() => Promise<void>) | undefined;
let recorder: ReturnType<typeof recordLoopback> | undefined;
const orgIds: bigint[] = [];
const users: LoadUser[] = [];
const confirmed: Confirmed[] = [];
/** Tool executions the client saw (turn results + confirm results). */
let observedExecutions = 0;
let queuedReports = 0;
/** Report turns that were answered (not refused by a limit). */
let answeredReports = 0;
let runDay = '';

describe.skipIf(!RUN)('assistant load test (step AI-6 D11, fake provider only)', () => {
  beforeAll(async () => {
    print(`[assistant-load] params ${describeParams(params)}`);
    resumeRelay = await pauseLiveRelay();
    ctx = await createLoadApp(params.latencyMs);
    fx = createFixtures(ctx);
    trackReports(ctx, fx, orgIds);
    fx.registerCleanup(async () => {
      for (const id of orgIds) {
        const scope = systemScope(id);
        await ctx.get(AssistantTenantDataRepository).purgeOrganization(scope);
        await ctx.get(PolicyTenantDataRepository).purgeOrganization(scope);
        await ctx.get(DlpTenantDataRepository).purgeOrganization(scope);
      }
    });
    const operator = await platformMember(ctx, fx);
    const orgCount = Math.ceil(params.users / params.usersPerOrg);
    const all = { permissions: [...ALL_TENANT_PERMISSIONS] };
    for (let o = 0; o < orgCount; o += 1) {
      const org = await markLoadOrganization(
        ctx,
        await fx.createOrganization({ features: allFeatures() }),
      );
      orgIds.push(org.id);
      const inOrg = Math.min(params.usersPerOrg, params.users - o * params.usersPerOrg);
      for (let slot = 0; slot < inOrg; slot += 1) {
        const member = await memberWith(ctx, fx, org, all);
        if (slot === 0) {
          await enableAssistant(ctx, operator, org, member);
          // The per-user daily budget (D1) on, so the user token counters are part of the run.
          const current = await call(ctx, member.headers, 'get', `${A}/settings`);
          const res = await call(ctx, member.headers, 'put', `${A}/settings`, {
            expectedRowVersion: current.body.rowVersion as number,
            enabled: true,
            externalProcessingAcknowledged: true,
            dailyTokenBudget: null,
            retentionDays: 30,
            userDailyTokenBudget: 5_000_000,
          });
          if (res.status !== 200) throw new Error(`user budget: ${res.status} ${res.body?.code}`);
        }
        users.push({ member, org, slot, conversation: await newConversation(ctx, member) });
      }
    }
    recorder = recordLoopback(ctx);
  }, LONG);

  afterAll(async () => {
    recorder?.restore();
    try {
      if (ctx) {
        await clearAssistantCounters(ctx, orgIds);
        const day = utcDayKey(new Date());
        for (const u of users) {
          await ctx.kv.del(assistantKeys.userTokens(u.member.user.publicId, runDay || day));
        }
      }
      await fx?.cleanup();
      await ctx?.close();
    } finally {
      await resumeRelay?.();
    }
  }, LONG);

  /** One JSON turn; records latency, executions and errors. */
  async function runTurn(
    stats: ScenarioStats,
    who: LoadUser,
    message: string,
    conversation = who.conversation,
  ): Promise<Record<string, unknown> | null> {
    const started = Date.now();
    const res = await turn(ctx, who.member.headers, conversation, message);
    stats.turnLatencies.push(Date.now() - started);
    stats.turns += 1;
    if (res.status !== 200) {
      countError(stats, `${res.status} ${String(res.body?.code ?? 'unknown')}`);
      return null;
    }
    const body = res.body as Record<string, unknown>;
    const executions = (body.executions as unknown[] | undefined) ?? [];
    stats.toolCalls += executions.length;
    observedExecutions += executions.length;
    const view = body.turn as { status: string; errorCode: string | null };
    if (view.status !== 'completed') countError(stats, `turn ${view.errorCode ?? view.status}`);
    return body;
  }

  function messageOf(kind: TurnKind, who: LoadUser, index: number, writes: number): string {
    switch (kind) {
      case 'read':
        return READS[(index + who.slot) % READS.length]!;
      case 'chain':
        return CHAIN_READ;
      case 'write':
        // Policy names are unique per organization: one plan per organization, then dictionaries.
        return who.slot === 0 && writes === 0
          ? POLICY_PLAN
          : `add dlp dictionary "Load ${who.member.user.publicId.slice(-12)} ${index}" with terms alpha, beta`;
      case 'report':
        return REPORT_30_DAYS;
    }
  }

  it(
    'mixed: reads of 1-3 rounds, confirmed writes and one async report per user',
    async () => {
      runDay = utcDayKey(new Date());
      const plan = turnPlan(params);
      const stats = newStats('mixed');
      stats.extra.push(`users=${users.length} orgs=${orgIds.length} plan=${plan.join('>')}`);
      signalStart(params);
      const probes = startProbes();
      const started = Date.now();
      await Promise.all(
        users.map(async (who, u) => {
          // Paced runs spread the users' starts over one pace interval (no lockstep bursts).
          if (params.paceMs > 0) await sleep(Math.floor((u * params.paceMs) / users.length));
          let writes = 0;
          for (let i = 0; i < plan.length; i += 1) {
            const turnStarted = Date.now();
            const kind = plan[i]!;
            const body = await runTurn(stats, who, messageOf(kind, who, i, writes));
            if (body && kind === 'write') {
              writes += 1;
              for (const pair of confirmationsOfTurn(body)) {
                if (pair.token === null) continue;
                const t0 = Date.now();
                const res = await confirm(ctx, who.member, {
                  confirmation: pair.confirmation,
                  token: pair.token,
                });
                stats.confirmLatencies.push(Date.now() - t0);
                if (res.status !== 200) {
                  countError(stats, `confirm ${res.status} ${String(res.body?.code)}`);
                  continue;
                }
                if (res.body.execution) observedExecutions += 1;
                confirmed.push({ confirmation: res.body.confirmation as ConfirmationJson });
              }
            }
            if (body && kind === 'report') {
              answeredReports += 1;
              const executions = body.executions as Array<{ tool: string; httpStatus: number }>;
              if (executions.some((e) => e.tool === 'report_generate' && e.httpStatus === 202)) {
                queuedReports += 1;
              } else {
                countError(stats, 'report not_queued');
              }
            }
            const wait = params.paceMs - (Date.now() - turnStarted);
            if (wait > 0 && i < plan.length - 1) await sleep(wait);
          }
        }),
      );
      stats.wallMs = Date.now() - started;
      probes.stop(stats);
      stats.extra.push(`confirmed=${confirmed.length} reports_queued=${queuedReports}`);
      print(resultLine(stats));

      const unexpected = [...stats.errors.keys()].filter((key) => !ACCEPTABLE.has(key));
      expect(unexpected).toEqual([]);
      // Every answered report turn queued its job (turns refused by a limit never reach the tool).
      expect(answeredReports).toBeGreaterThan(0);
      expect(queuedReports).toBe(answeredReports);
      expect(confirmed.every((c) => c.confirmation.status === 'executed')).toBe(true);
    },
    LONG,
  );

  it(
    'report-jobs: every queued job is composed through the loopback with a job token',
    async () => {
      const envelopes = await reportJobEnvelopes(ctx, orgIds);
      expect(envelopes).toHaveLength(queuedReports);
      const processor = ctx.get(ReportJobProcessor);
      const stats = newStats('report-jobs');
      const durations: number[] = [];
      let retries = 0;
      const probes = startProbes();
      const started = Date.now();
      await pool(envelopes, ctx.config.ASSISTANT_REPORT_JOB_CONCURRENCY, async (envelope) => {
        const t0 = Date.now();
        for (let attempt = 1; ; attempt += 1) {
          try {
            await processor.handle(envelope);
            break;
          } catch (error) {
            // The queue would redeliver after its hold (10–60 s); here at once, at most 5 times.
            if (!(error instanceof ReportJobRetryError) || attempt >= 5) throw error;
            retries += 1;
          }
        }
        durations.push(Date.now() - t0);
      });
      stats.wallMs = Date.now() - started;
      probes.stop(stats);
      const jobs = await ctx.prisma.aiChatReportJob.findMany({
        where: { organizationId: { in: orgIds } },
        select: {
          status: true,
          errorCode: true,
          createdAt: true,
          finishedAt: true,
          reportId: true,
        },
      });
      const succeeded = jobs.filter((j) => j.status === 'succeeded').length;
      stats.extra.push(
        `jobs=${jobs.length} succeeded=${succeeded} retries=${retries} ` +
          `job_p50=${percentile(durations, 50)}ms job_p95=${percentile(durations, 95)}ms ` +
          `concurrency=${ctx.config.ASSISTANT_REPORT_JOB_CONCURRENCY}`,
      );
      for (const job of jobs) {
        if (job.status !== 'succeeded') countError(stats, `job ${job.errorCode ?? job.status}`);
      }
      print(resultLine(stats));

      expect(succeeded).toBe(queuedReports);
      const reports = await ctx.prisma.aiChatReport.findMany({
        where: { id: { in: jobs.map((j) => j.reportId) } },
        select: { status: true, objectKey: true },
      });
      expect(reports.every((r) => r.status === 'available' && r.objectKey !== null)).toBe(true);
      const audits = await ctx.prisma.auditLog.count({
        where: { organizationId: { in: orgIds }, action: 'assistant.report_generated' },
      });
      expect(audits).toBe(queuedReports);
    },
    LONG,
  );

  it(
    'burst: concurrent turns beyond ASSISTANT_MAX_CONCURRENT_TURNS answer 503 assistant_busy only',
    async () => {
      const limit = ctx.config.ASSISTANT_MAX_CONCURRENT_TURNS;
      const total = Math.min(users.length * 5, limit + 10);
      const jobs: Array<{ who: LoadUser; conversation: string }> = [];
      for (let i = 0; i < total; i += 1) {
        const who = users[i % users.length]!;
        jobs.push({ who, conversation: await newConversation(ctx, who.member) });
      }
      await nextMinute();
      const stats = newStats('burst');
      const probes = startProbes();
      const started = Date.now();
      await Promise.all(
        jobs.map(({ who, conversation }) =>
          runTurn(stats, who, '/tool users_list {}', conversation),
        ),
      );
      stats.wallMs = Date.now() - started;
      probes.stop(stats);
      const busy = stats.errors.get('503 assistant_busy') ?? 0;
      stats.extra.push(`concurrent=${total} limit=${limit} busy=${busy}`);
      print(resultLine(stats));

      expect([...stats.errors.keys()].filter((k) => k !== '503 assistant_busy')).toEqual([]);
      if (total > limit) expect(busy).toBeGreaterThan(0);
      else expect(busy).toBe(0);
    },
    LONG,
  );

  it(
    'consistency: executions, audit rows, confirmed writes, token counters and turns',
    async () => {
      const where = { organizationId: { in: orgIds } };
      // No orphan running turn.
      expect(await ctx.prisma.aiChatTurn.count({ where: { ...where, status: 'running' } })).toBe(0);

      // One execution row per tool call the client saw, and one audit row per execution.
      const executions = await ctx.prisma.aiChatToolExecution.findMany({
        where,
        select: { publicId: true },
      });
      expect(executions).toHaveLength(observedExecutions);
      const audits = await ctx.prisma.auditLog.groupBy({
        by: ['resourceId'],
        where: {
          ...where,
          resourceType: 'assistant_tool_execution',
          action: { in: ['assistant.tool_executed', 'assistant.tool_denied'] },
        },
        _count: { _all: true },
      });
      const perExecution = new Map(audits.map((a) => [a.resourceId, a._count._all]));
      const missingOrDuplicated = executions.filter((e) => perExecution.get(e.publicId) !== 1);
      expect(missingOrDuplicated).toEqual([]);

      // Every confirmed write was sent exactly once and audited once.
      const calls = recorder?.calls ?? [];
      for (const { confirmation } of confirmed) {
        const request = confirmation.summary?.request;
        expect(request).toBeDefined();
        const row = await ctx.prisma.aiChatActionConfirmation.findUniqueOrThrow({
          where: { publicId: confirmation.id },
          select: { status: true, resultExecutionId: true },
        });
        expect(row.status).toBe('executed');
        expect(row.resultExecutionId).not.toBeNull();
        // The write of this confirmation: its result execution's correlation id (other users of
        // the run POST to the same path).
        const result = await ctx.prisma.aiChatToolExecution.findUniqueOrThrow({
          where: { id: row.resultExecutionId! },
          select: { correlationId: true },
        });
        const sent = calls.filter(
          (c) =>
            c.correlationId === result.correlationId &&
            c.method === request!.method &&
            c.path.split('?')[0] === request!.path,
        );
        expect(sent.length, `${confirmation.tool} ${request!.method} ${request!.path}`).toBe(1);
        expect(
          await ctx.prisma.auditLog.count({
            where: {
              ...where,
              resourceId: confirmation.id,
              action: 'assistant.confirmation_executed',
            },
          }),
        ).toBe(1);
      }

      // Redis token counters equal the usage rows (tenant and user, today's UTC day).
      const day = utcDayKey(new Date());
      if (day === runDay) {
        const dayDate = new Date(
          `${runDay.slice(0, 4)}-${runDay.slice(4, 6)}-${runDay.slice(6, 8)}T00:00:00.000Z`,
        );
        for (const id of orgIds) {
          const counter = await ctx.kv.get(assistantKeys.tenantTokens(id, runDay));
          const sums = await ctx.prisma.aiChatUsageDaily.aggregate({
            where: { organizationId: id, day: dayDate },
            _sum: {
              inputTokens: true,
              outputTokens: true,
              cacheReadTokens: true,
              cacheWriteTokens: true,
            },
          });
          const fromRows = budgetTokens({
            inputTokens: sums._sum.inputTokens ?? 0n,
            outputTokens: sums._sum.outputTokens ?? 0n,
            cacheReadTokens: sums._sum.cacheReadTokens ?? 0n,
            cacheWriteTokens: sums._sum.cacheWriteTokens ?? 0n,
          });
          expect(counter, `tenant counter of organization ${id}`).not.toBeNull();
          expect(Number(counter)).toBe(fromRows);
        }
        for (const u of users) {
          const counter = await ctx.kv.get(
            assistantKeys.userTokens(u.member.user.publicId, runDay),
          );
          const sums = await ctx.prisma.aiChatUsageUserDaily.aggregate({
            where: { organizationId: u.org.id, userId: u.member.user.id, day: dayDate },
            _sum: {
              inputTokens: true,
              outputTokens: true,
              cacheReadTokens: true,
              cacheWriteTokens: true,
            },
          });
          const fromRows = budgetTokens({
            inputTokens: sums._sum.inputTokens ?? 0n,
            outputTokens: sums._sum.outputTokens ?? 0n,
            cacheReadTokens: sums._sum.cacheReadTokens ?? 0n,
            cacheWriteTokens: sums._sum.cacheWriteTokens ?? 0n,
          });
          expect(counter, `user counter of ${u.member.user.publicId}`).not.toBeNull();
          expect(Number(counter)).toBe(fromRows);
        }
        // Every finished turn is one usage row increment.
        const usage = await ctx.prisma.aiChatUsageDaily.aggregate({
          where: { ...where, day: dayDate },
          _sum: { turns: true },
        });
        const finished = await ctx.prisma.aiChatTurn.count({
          where: { ...where, status: { in: ['completed', 'failed', 'cancelled'] } },
        });
        expect(Number(usage._sum.turns ?? 0)).toBe(finished);
      } else {
        print('[assistant-load] the UTC day changed during the run: counters not compared');
      }
      print(
        `[assistant-load] scenario=consistency executions=${executions.length} ` +
          `confirmed_writes=${confirmed.length} report_jobs=${queuedReports} orphan_running=0 ` +
          `counters=${day === runDay ? 'equal' : 'skipped'}`,
      );
    },
    LONG,
  );
});
