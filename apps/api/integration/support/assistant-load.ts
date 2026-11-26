/**
 * Helpers of the opt-in assistant load test (step AI-6 D11, docs/plan/steps/34-ai-chat-hardening-
 * operations.md; results in docs/performance/assistant-load.md). The api runs in-process on its
 * ephemeral loopback port with the deterministic fake provider only (a `FakeProvider` subclass
 * with a per-round `latencyMs` and a `/chain` directive for multi-round reads; never a real LLM,
 * nothing reaches the internet), the production defaults of the API rate classes and of the
 * assistant's per-user and per-process limits, and synthetic `it-load-*` organizations. It builds
 * on `support/assistant.ts` (not modified).
 */
import { monitorEventLoopDelay } from 'node:perf_hooks';
import { writeFileSync } from 'node:fs';
import {
  FakeProvider,
  type FakeProviderOptions,
  type FakeTranscriptEntry,
  type LlmRequest,
  type LlmResponse,
} from '@email-gateway/assistant';
import type {
  AssistantReportGenerateRequestedV1,
  EventEnvelope,
} from '@email-gateway/event-contracts';
import {
  LLM_PROVIDER_FACTORY,
  type LlmProviderFactory,
} from '../../src/modules/assistant/services/assistant-provider.service';
import { createIntegrationApp, type IntegrationApp } from './app';
import { assertFakeProvider, assistantEnv } from './assistant';
import type { FixtureOrganization } from './fixtures';

// ---------------------------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------------------------

/** The turn kinds of the mix (D11): reads of 1–3 tool rounds, write proposals, one async report. */
export const TURN_KINDS = ['read', 'chain', 'write', 'report'] as const;
export type TurnKind = (typeof TURN_KINDS)[number];
export type Mix = Record<TurnKind, number>;

export interface LoadParams {
  /** ASSISTANT_LOAD_USERS (default 20): concurrent users, each in its own conversation. */
  users: number;
  /** ASSISTANT_LOAD_TURNS (default 5): turns per user in the mixed scenario. */
  turns: number;
  /** ASSISTANT_LOAD_MIX (default `read=2,chain=1,write=1,report=1`): weights of the turn kinds. */
  mix: Mix;
  /** ASSISTANT_LOAD_LATENCY_MS (default 300): the fake's delay before every model round. */
  latencyMs: number;
  /**
   * ASSISTANT_LOAD_USERS_PER_ORG (default 2): users per synthetic organization, so a tenant stays
   * under the `standard` plan's 300 API requests per minute (turns, loopback tool calls, confirms).
   */
  usersPerOrg: number;
  /**
   * ASSISTANT_LOAD_PACE_MS (default 0): least time between two turn starts of one user (10 000
   * keeps every user under ASSISTANT_TURNS_PER_USER_PER_MINUTE = 6 for a sustained run).
   */
  paceMs: number;
  /**
   * ASSISTANT_LOAD_SIGNAL_PATH: written when the mixed scenario starts (side-by-side runs). Not
   * `…_FILE`: the config loader would read a `<KEY>_FILE` as a secret file.
   */
  signalFile: string | null;
}

const DEFAULT_MIX: Mix = { read: 2, chain: 1, write: 1, report: 1 };

function intParam(
  env: NodeJS.ProcessEnv,
  key: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const raw = env[key];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${key} must be an integer from ${min} to ${max}`);
  }
  return value;
}

/** `read=2,chain=1,write=1,report=1` → weights (unknown kinds and negative weights refused). */
export function parseMix(raw: string | undefined): Mix {
  if (raw === undefined || raw.trim() === '') return { ...DEFAULT_MIX };
  const mix: Mix = { read: 0, chain: 0, write: 0, report: 0 };
  for (const part of raw.split(',')) {
    const [name, weight] = part.split('=').map((s) => s.trim());
    if (!(TURN_KINDS as readonly string[]).includes(name ?? '')) {
      throw new Error(`ASSISTANT_LOAD_MIX: unknown turn kind ${name ?? ''}`);
    }
    const value = Number(weight);
    if (!Number.isSafeInteger(value) || value < 0 || value > 100) {
      throw new Error(`ASSISTANT_LOAD_MIX: weight of ${name} must be an integer from 0 to 100`);
    }
    mix[name as TurnKind] = value;
  }
  if (TURN_KINDS.every((kind) => mix[kind] === 0)) {
    throw new Error('ASSISTANT_LOAD_MIX: at least one weight must be positive');
  }
  return mix;
}

export function loadParams(env: NodeJS.ProcessEnv = process.env): LoadParams {
  return {
    users: intParam(env, 'ASSISTANT_LOAD_USERS', 20, 1, 200),
    turns: intParam(env, 'ASSISTANT_LOAD_TURNS', 5, 1, 50),
    mix: parseMix(env.ASSISTANT_LOAD_MIX),
    latencyMs: intParam(env, 'ASSISTANT_LOAD_LATENCY_MS', 300, 0, 10_000),
    usersPerOrg: intParam(env, 'ASSISTANT_LOAD_USERS_PER_ORG', 2, 1, 50),
    paceMs: intParam(env, 'ASSISTANT_LOAD_PACE_MS', 0, 0, 60_000),
    signalFile: env.ASSISTANT_LOAD_SIGNAL_PATH?.trim() || null,
  };
}

export const describeParams = (p: LoadParams): string =>
  `users=${p.users} turns=${p.turns} mix=${TURN_KINDS.map((k) => `${k}=${p.mix[k]}`).join(',')} ` +
  `latencyMs=${p.latencyMs} usersPerOrg=${p.usersPerOrg} paceMs=${p.paceMs}`;

/**
 * The turn kinds of one user, deterministic: the weighted kinds in a fixed order, repeated; at
 * most one `report` per user (the async report of the mix; later report slots become reads).
 */
export function turnPlan(params: Pick<LoadParams, 'turns' | 'mix'>): TurnKind[] {
  const cycle = TURN_KINDS.flatMap((kind) => Array<TurnKind>(params.mix[kind]).fill(kind));
  const plan: TurnKind[] = [];
  let reports = 0;
  for (let i = 0; i < params.turns; i += 1) {
    let kind = cycle[i % cycle.length]!;
    if (kind === 'report' && (reports += 1) > 1) kind = 'read';
    plan.push(kind);
  }
  return plan;
}

// ---------------------------------------------------------------------------------------------
// The load provider and the app
// ---------------------------------------------------------------------------------------------

/** `/chain a,b,c`: one `call_tool` per round, in order, then the fake's result summary. */
const CHAIN = /(^|\n)\/chain ([a-z_]+(?:,[a-z_]+){0,4})\s*$/;

/**
 * The package's deterministic fake (directives, demo intents and plans, `latencyMs`) plus the
 * `/chain` directive: a read of up to five tool rounds without arguments (the fake's own plans
 * end every multi-round chain with a write). Each round is answered by the fake's directive mode
 * (`/tool <name> {}`), so tool-call ids, latency and streaming are the fake's.
 */
export class LoadFakeProvider extends FakeProvider {
  override complete(
    request: LlmRequest,
    signal: AbortSignal,
    onDelta: (text: string) => void,
  ): Promise<LlmResponse> {
    const transcript = request.transcript as readonly FakeTranscriptEntry[];
    const lastUser = transcript.map((entry) => entry.role).lastIndexOf('user');
    const user = lastUser >= 0 ? transcript[lastUser] : undefined;
    const chain = user?.role === 'user' ? CHAIN.exec(user.text) : null;
    if (!chain) return super.complete(request, signal, onDelta);
    const tools = chain[2]!.split(',');
    const done = transcript
      .slice(lastUser + 1)
      .reduce((n, entry) => n + (entry.role === 'assistant' ? entry.toolCalls.length : 0), 0);
    if (done >= tools.length) return super.complete(request, signal, onDelta);
    const next: FakeTranscriptEntry[] = [
      ...transcript,
      { role: 'user', text: `/tool ${tools[done]!} {}` },
    ];
    return super.complete({ ...request, transcript: next }, signal, onDelta);
  }
}

/**
 * The env of the load app: the assistant suites' env with the PRODUCTION defaults of the limits
 * under test (API rate classes, 6 turns per user and minute, 20 concurrent turns per process),
 * no fallback provider, and the report-job consumer off (the test drives `ReportJobProcessor`).
 */
export function loadEnv(): Record<string, string> {
  return assistantEnv({
    API_RATE_PRINCIPAL_PER_MINUTE: '600',
    API_RATE_TENANT_DEFAULT_PER_MINUTE: '300',
    API_RATE_TENANT_MIN_PER_MINUTE: '10',
    API_RATE_TENANT_MAX_PER_MINUTE: '10000',
    API_RATE_SENSITIVE_PER_MINUTE: '30',
    API_RATE_EXPENSIVE_PER_MINUTE: '60',
    ASSISTANT_TURNS_PER_USER_PER_MINUTE: '6',
    ASSISTANT_MAX_CONCURRENT_TURNS: '20',
    ASSISTANT_FALLBACK_PROVIDER: 'none',
    ASSISTANT_REPORT_JOBS_ENABLED: 'true',
    ASSISTANT_REPORT_JOBS_CONSUMER: 'false',
    LOG_LEVEL: 'warn',
  });
}

export async function createLoadApp(latencyMs: number): Promise<IntegrationApp> {
  let provider: LoadFakeProvider | undefined;
  const factory: LlmProviderFactory = (spec) => {
    if (spec.ASSISTANT_PROVIDER !== 'fake') {
      throw new Error('the assistant load test runs the fake provider only');
    }
    const options: FakeProviderOptions = { nodeEnv: spec.NODE_ENV, model: 'fake', latencyMs };
    provider ??= new LoadFakeProvider(options);
    return provider;
  };
  const ctx = await createIntegrationApp(loadEnv(), {
    override: (builder) => builder.overrideProvider(LLM_PROVIDER_FACTORY).useValue(factory),
  });
  try {
    assertFakeProvider(ctx);
  } catch (error) {
    await ctx.close();
    throw error;
  }
  return ctx;
}

/** Renames a fixture organization to the load test's synthetic prefix `it-load-*`. */
export async function markLoadOrganization(
  ctx: IntegrationApp,
  org: FixtureOrganization,
): Promise<FixtureOrganization> {
  const suffix = org.slug.replace(/^it-/, '');
  const updated = await ctx.prisma.organization.update({
    where: { id: org.id },
    data: { slug: `it-load-${suffix}`, name: `Load test ${suffix}` },
    select: { slug: true, name: true },
  });
  return { ...org, ...updated };
}

// ---------------------------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------------------------

/** Nearest-rank percentile of `values` (milliseconds); 0 for an empty list. */
export function percentile(values: readonly number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.min(sorted.length, Math.max(1, Math.ceil((p / 100) * sorted.length)));
  return sorted[rank - 1]!;
}

export interface ScenarioStats {
  name: string;
  wallMs: number;
  turns: number;
  turnLatencies: number[];
  toolCalls: number;
  confirmLatencies: number[];
  /** `<status> <code>` → count (non-2xx responses, failed turns as `turn <code>`). */
  errors: Map<string, number>;
  lagP99Ms: number;
  lagMaxMs: number;
  rssMaxMb: number;
  /** Free-form `key=value` additions of a scenario. */
  extra: string[];
}

export function newStats(name: string): ScenarioStats {
  return {
    name,
    wallMs: 0,
    turns: 0,
    turnLatencies: [],
    toolCalls: 0,
    confirmLatencies: [],
    errors: new Map(),
    lagP99Ms: 0,
    lagMaxMs: 0,
    rssMaxMb: 0,
    extra: [],
  };
}

export function countError(stats: ScenarioStats, key: string): void {
  stats.errors.set(key, (stats.errors.get(key) ?? 0) + 1);
}

/**
 * Event-loop delay (`monitorEventLoopDelay`, 10 ms resolution) and the process RSS (sampled every
 * 250 ms) while a scenario runs. The api and the load client share this process, so both include
 * the client's own work.
 */
export function startProbes(): { stop(stats: ScenarioStats): void } {
  const lag = monitorEventLoopDelay({ resolution: 10 });
  lag.enable();
  let rssMax = process.memoryUsage().rss;
  const timer = setInterval(() => {
    rssMax = Math.max(rssMax, process.memoryUsage().rss);
  }, 250);
  timer.unref();
  return {
    stop(stats) {
      clearInterval(timer);
      lag.disable();
      rssMax = Math.max(rssMax, process.memoryUsage().rss);
      stats.lagP99Ms = lag.percentile(99) / 1e6;
      stats.lagMaxMs = lag.max / 1e6;
      stats.rssMaxMb = rssMax / (1024 * 1024);
    },
  };
}

const fixed = (n: number, digits = 1): string => n.toFixed(digits);

/** The one result line of a scenario (D11). */
export function resultLine(stats: ScenarioStats): string {
  const seconds = Math.max(stats.wallMs, 1) / 1000;
  const errors =
    stats.errors.size === 0
      ? 'none'
      : [...stats.errors.entries()]
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([key, count]) => `${key.replace(/ /g, ':')}x${count}`)
          .join(',');
  const confirm =
    stats.confirmLatencies.length === 0
      ? 'n/a'
      : `p50=${percentile(stats.confirmLatencies, 50)}ms p95=${percentile(stats.confirmLatencies, 95)}ms (n=${stats.confirmLatencies.length})`;
  const turns =
    stats.turns === 0
      ? []
      : [
          `turns=${stats.turns} (${fixed(stats.turns / seconds, 2)}/s)`,
          `turn_p50=${percentile(stats.turnLatencies, 50)}ms`,
          `p95=${percentile(stats.turnLatencies, 95)}ms`,
          `p99=${percentile(stats.turnLatencies, 99)}ms`,
          `tool_calls=${stats.toolCalls} (${fixed(stats.toolCalls / seconds, 2)}/s)`,
          `confirm=${confirm}`,
        ];
  return [
    `[assistant-load] scenario=${stats.name}`,
    `wall=${fixed(seconds)}s`,
    ...turns,
    `errors=${errors}`,
    `loop_lag_p99=${fixed(stats.lagP99Ms)}ms max=${fixed(stats.lagMaxMs)}ms`,
    `rss_max=${fixed(stats.rssMaxMb, 0)}MiB`,
    ...stats.extra,
  ].join(' ');
}

/** Prints one line to stdout (vitest shows it; the repository's lint forbids `console`). */
export function print(line: string): void {
  process.stdout.write(`${line}\n`);
}

/** Writes the side-by-side signal file (D11 run with the SMTP benchmark); no-op without one. */
export function signalStart(params: LoadParams): void {
  if (params.signalFile) writeFileSync(params.signalFile, `${new Date().toISOString()}\n`);
}

/** Runs `work` for each item with at most `limit` in flight. */
export async function pool<T>(
  items: readonly T[],
  limit: number,
  work: (item: T, index: number) => Promise<void>,
): Promise<void> {
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      await work(items[index]!, index);
    }
  });
  await Promise.all(runners);
}

export const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/** Waits until the next UTC minute starts (+ 1 s), so per-minute windows start empty. */
export async function nextMinute(): Promise<void> {
  const now = Date.now();
  await sleep(60_000 - (now % 60_000) + 1_000);
}

// ---------------------------------------------------------------------------------------------
// Report jobs
// ---------------------------------------------------------------------------------------------

/**
 * The `assistant.report.generate_requested.v1` envelopes of the outbox rows of these
 * organizations, exactly as the consumer receives them from the relay (eventId, type, time,
 * correlation, numeric organization id, payload).
 */
export async function reportJobEnvelopes(
  ctx: IntegrationApp,
  organizationIds: readonly bigint[],
): Promise<Array<EventEnvelope<AssistantReportGenerateRequestedV1>>> {
  const rows = await ctx.prisma.messageOutbox.findMany({
    where: {
      organizationId: { in: [...organizationIds] },
      eventType: 'assistant.report.generate_requested.v1',
    },
    select: {
      eventId: true,
      eventType: true,
      createdAt: true,
      correlationId: true,
      organizationId: true,
      payload: true,
    },
    orderBy: { id: 'asc' },
  });
  return rows.map((row) => ({
    eventId: row.eventId,
    eventType: row.eventType,
    occurredAt: row.createdAt.toISOString(),
    correlationId: row.correlationId,
    organizationId: String(row.organizationId),
    payload: row.payload as unknown as AssistantReportGenerateRequestedV1,
  }));
}
