/**
 * Helpers of the step AI-6 assistant integration suites (docs/plan/steps/34-ai-chat-hardening-
 * operations.md §9 item 5, WP5): synthetic tenant keys and the local fake LLM endpoint the real
 * Anthropic/OpenAI provider classes reach through an injected `fetch` (never the network), the
 * tenant-key routes, Redis counters and breakers of the suites, deep scans of JSON for content
 * that must never appear, job tokens of a user's live session, the report-job consumer of the
 * in-process api (stop/start) and the outbox → RabbitMQ path of `assistant.report.
 * generate_requested.v1` (the live event-relay when it runs; otherwise this helper publishes the
 * suite's own rows with the relay's envelope rules and the relay's role user). Synthetic `it-*` organizations only; no
 * value here matches a secret-scanner pattern.
 */
import { setTimeout as sleep } from 'node:timers/promises';
import {
  AmqpConnection,
  ConfirmPublisher,
  DEFAULT_MAX_MESSAGE_BYTES,
  type PrismaService,
} from '@email-gateway/common';
import {
  type AssistantReportGenerateRequestedV1,
  eventDefinition,
  type EventEnvelope,
  eventEnvelopeSchema,
} from '@email-gateway/event-contracts';
import type { MessageOutbox } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import type { Response as HttpResponse } from 'supertest';
import { utcDayKey } from '../../src/modules/assistant/assistant.constants';
import { ReportJobConsumer } from '../../src/modules/assistant/services/reports/report-job.consumer';
import { TokenService } from '../../src/modules/auth/services/token.service';
import type { IntegrationApp } from './app';
import { A, call, type Member } from './assistant';

// ---------------------------------------------------------------------------------------------
// Tenant keys and the local fake provider endpoint (D7)
// ---------------------------------------------------------------------------------------------

/** Synthetic tenant keys (20-512 printable ASCII; match no secret-scanner pattern). */
export const TENANT_KEY_A = 'test-tenant-key-0001-not-a-secret';
export const TENANT_KEY_B = 'test-tenant-key-0002-not-a-secret';
/** The OpenAI model id the fallback suite offers for tenant keys (a synthetic id). */
export const TENANT_OPENAI_MODEL = 'gpt-tenant-fixture-1';

/** What the fake endpoint answers to a probe (`GET …/models/{model}`) and a chat completion. */
export type FakeEndpointMode = 'valid' | 'unauthorized' | 'server_error';

export interface FakeEndpointCall {
  method: string;
  url: string;
  /** The `authorization` header as sent (compared in memory only; never printed). */
  authorization: string | null;
  /** Anthropic's `x-api-key` header as sent (same rule). */
  apiKeyHeader: string | null;
}

/**
 * A local stand-in for the Anthropic and OpenAI HTTP APIs behind the provider classes' injected
 * `fetch` (design D7: "tests use local fakes only"). Probes answer 200 with a model object, 401
 * or 500 by `mode`; OpenAI Chat Completions answer a short streamed text with the configured
 * usage. Any other request is refused (the suite fails loudly instead of reaching the network).
 */
export class FakeLlmEndpoint {
  mode: FakeEndpointMode = 'valid';
  /** Reported usage of a chat completion (tokens). */
  usage = { prompt: 1_200, completion: 40 };
  /** The text a chat completion streams. */
  answer = 'Answered with the organization key.';
  readonly calls: FakeEndpointCall[] = [];

  readonly fetch = (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    try {
      return Promise.resolve(this.respond(input, init));
    } catch (error: unknown) {
      return Promise.reject(error instanceof Error ? error : new Error(String(error)));
    }
  };

  private respond(input: string | URL | Request, init?: RequestInit): Response {
    const url = String(input instanceof Request ? input.url : input);
    const headers = new Headers(input instanceof Request ? input.headers : init?.headers);
    const method = (
      init?.method ?? (input instanceof Request ? input.method : 'GET')
    ).toUpperCase();
    this.calls.push({
      method,
      url,
      authorization: headers.get('authorization'),
      apiKeyHeader: headers.get('x-api-key'),
    });
    if (init?.signal?.aborted) throw new DOMException('aborted', 'AbortError');
    const path = new URL(url).pathname;
    if (this.mode === 'unauthorized') {
      return json(401, { error: { type: 'authentication_error', message: 'invalid key' } });
    }
    if (this.mode === 'server_error') {
      return json(500, { error: { type: 'api_error', message: 'upstream failure' } });
    }
    const model = /\/models\/([^/]+)$/.exec(path);
    if (method === 'GET' && model) {
      const id = decodeURIComponent(model[1]!);
      return json(200, {
        type: 'model',
        id,
        object: 'model',
        display_name: 'Fixture model',
        created_at: '2026-01-01T00:00:00Z',
        created: 1_767_225_600,
        owned_by: 'fixture',
      });
    }
    if (method === 'POST' && path.endsWith('/chat/completions')) {
      const chunk = (choice: Record<string, unknown> | null, extra = {}) => ({
        id: 'chatcmpl-fixture',
        object: 'chat.completion.chunk',
        model: TENANT_OPENAI_MODEL,
        choices: choice ? [{ index: 0, ...choice }] : [],
        ...extra,
      });
      const body =
        [
          chunk({ delta: { role: 'assistant', content: this.answer }, finish_reason: null }),
          chunk({ delta: {}, finish_reason: 'stop' }),
          chunk(null, {
            usage: {
              prompt_tokens: this.usage.prompt,
              completion_tokens: this.usage.completion,
              total_tokens: this.usage.prompt + this.usage.completion,
            },
          }),
        ]
          .map((c) => `data: ${JSON.stringify(c)}\n\n`)
          .join('') + 'data: [DONE]\n\n';
      return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } });
    }
    throw new Error(`the fake LLM endpoint does not serve ${method} ${path}`);
  }

  /** Whether some call carried `key` (Bearer or `x-api-key`). */
  sawKey(key: string): boolean {
    return this.calls.some((c) => c.authorization === `Bearer ${key}` || c.apiKeyHeader === key);
  }

  reset(mode: FakeEndpointMode = 'valid'): void {
    this.mode = mode;
    this.calls.length = 0;
  }
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** `PUT /assistant/settings/provider-key` from the current settings `rowVersion`. */
export async function putProviderKey(
  ctx: IntegrationApp,
  admin: Member,
  body: { provider: string; model: string; apiKey: string },
): Promise<HttpResponse> {
  const current = await call(ctx, admin.headers, 'get', `${A}/settings`);
  return call(ctx, admin.headers, 'put', `${A}/settings/provider-key`, {
    ...body,
    expectedRowVersion: current.body.rowVersion as number,
  });
}

/** `DELETE /assistant/settings/provider-key?expectedRowVersion=` from the current version. */
export async function removeProviderKey(ctx: IntegrationApp, admin: Member): Promise<HttpResponse> {
  const current = await call(ctx, admin.headers, 'get', `${A}/settings`);
  return call(
    ctx,
    admin.headers,
    'delete',
    `${A}/settings/provider-key?expectedRowVersion=${String(current.body.rowVersion)}`,
  );
}

// ---------------------------------------------------------------------------------------------
// Redis keys of the suites
// ---------------------------------------------------------------------------------------------

/**
 * Deletes today's per-user token counters (D1) of these users and the tenant-key breakers of
 * these organizations, plus the fake platform breakers (`as:brk:fake`, `as:brk:fake:fb`) a
 * fallback test opened (short windows; shared Redis).
 */
export async function clearHardeningKeys(
  ctx: IntegrationApp,
  keys: { userPublicIds?: readonly string[]; organizationPublicIds?: readonly string[] } = {},
): Promise<void> {
  const day = utcDayKey(new Date());
  for (const id of keys.userPublicIds ?? []) await ctx.kv.del(`as:tok:u:${id}:${day}`);
  for (const id of keys.organizationPublicIds ?? []) await ctx.kv.del(`as:brk:t:${id}`);
  await ctx.kv.del('as:brk:fake');
  await ctx.kv.del('as:brk:fake:fb');
}

// ---------------------------------------------------------------------------------------------
// Deep scans (I24, I27)
// ---------------------------------------------------------------------------------------------

/** Every string in a JSON-like value (keys included), depth first. */
export function allStrings(value: unknown, out: string[] = []): string[] {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) for (const item of value) allStrings(item, out);
  else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      out.push(key);
      allStrings(item, out);
    }
  }
  return out;
}

/**
 * The needles found anywhere in `value` (strings at any depth, keys included, case-insensitive).
 * Empty needles are ignored.
 */
export function needlesIn(value: unknown, needles: readonly string[]): string[] {
  const haystack = allStrings(value).join('\u0000').toLowerCase();
  return needles.filter((n) => n.length > 0 && haystack.includes(n.toLowerCase()));
}

/** The keys present anywhere in `value` (depth first). */
export function keysIn(value: unknown, out = new Set<string>()): Set<string> {
  if (Array.isArray(value)) for (const item of value) keysIn(item, out);
  else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      out.add(key);
      keysIn(item, out);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Sessions and job tokens (D5, I26)
// ---------------------------------------------------------------------------------------------

/** The claims of an access token (decoded, not verified: the api verifies). */
export function claimsOf(token: string): Record<string, unknown> {
  const payload = token.split('.')[1];
  if (!payload) throw new Error('not a JWT');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<string, unknown>;
}

/** A job token of `who`'s live session (the consumer's construction, D5 step 3). */
export async function mintJobToken(
  ctx: IntegrationApp,
  who: Member,
  jobPublicId: string,
): Promise<string> {
  const claims = claimsOf(who.token);
  const { token } = await ctx.get(TokenService).issueAssistantJobAccess({
    userPublicId: claims.sub as string,
    organizationPublicId: claims.org as string,
    sessionId: claims.sid as string,
    amr: claims.amr as Array<'pwd' | 'otp'>,
    jobId: jobPublicId,
  });
  return token;
}

// ---------------------------------------------------------------------------------------------
// The report-job consumer and the outbox path (D5)
// ---------------------------------------------------------------------------------------------

/** The in-process `ReportJobConsumer` (started at bootstrap when the env asks for it). */
export function reportJobConsumer(ctx: IntegrationApp): ReportJobConsumer {
  return ctx.get(ReportJobConsumer);
}

/** Stops the in-process consumer (messages stay in `assistant.reports`). */
export async function stopReportJobConsumer(ctx: IntegrationApp): Promise<void> {
  await reportJobConsumer(ctx).onModuleDestroy();
}

/** Starts the in-process consumer again (no-op while running). */
export function startReportJobConsumer(ctx: IntegrationApp): void {
  const consumer = reportJobConsumer(ctx);
  if (!consumer.running) consumer.onApplicationBootstrap();
}

const RELAY_PORT = (): number => Number(process.env.EVENT_RELAY_HOST_PORT ?? 3070);

/** Whether the live event-relay (Compose `apps` profile) answers its readiness probe. */
export async function liveRelayRunning(): Promise<boolean> {
  try {
    const res = await fetch(`http://127.0.0.1:${RELAY_PORT()}/health/ready`, {
      signal: AbortSignal.timeout(2_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/** The envelope the relay publishes for an outbox row (relay rules: Q2, Q3). */
export function envelopeOfOutboxRow(row: {
  eventId: string;
  eventType: string;
  createdAt: Date;
  correlationId: string;
  organizationId: bigint;
  payload: unknown;
}): EventEnvelope<AssistantReportGenerateRequestedV1> {
  const definition = eventDefinition(row.eventType);
  if (!definition) throw new Error(`unknown event type ${row.eventType}`);
  const payload = definition.schema.parse(row.payload) as AssistantReportGenerateRequestedV1;
  const envelope = eventEnvelopeSchema.parse({
    eventId: row.eventId,
    eventType: row.eventType,
    occurredAt: row.createdAt.toISOString(),
    correlationId: row.correlationId,
    organizationId: row.organizationId.toString(),
    payload,
  });
  return { ...envelope, payload };
}

/** The outbox row of a report job (eventId = the job public id). */
export function jobOutboxRow(
  prisma: PrismaService,
  jobPublicId: string,
): Promise<MessageOutbox | null> {
  return prisma.messageOutbox.findFirst({
    where: { eventId: jobPublicId, eventType: 'assistant.report.generate_requested.v1' },
  });
}

/**
 * Waits until the job's outbox row is published. The live event-relay publishes it when the
 * Compose `apps` profile runs (the documented path); without a live relay, this helper is the
 * relay for the suite's own row: it claims the row (`published_at` set only when still NULL) and
 * publishes the relay's envelope to `email.policy` with publisher confirms as the relay's
 * role user (RABBITMQ_RELAY_URL). Returns who published it.
 */
export async function awaitJobPublished(
  ctx: IntegrationApp,
  jobPublicId: string,
  timeoutMs = 15_000,
): Promise<'live-relay' | 'suite'> {
  const live = await liveRelayRunning();
  const deadline = Date.now() + (live ? timeoutMs : 0);
  for (;;) {
    const row = await jobOutboxRow(ctx.prisma, jobPublicId);
    if (!row) throw new Error(`no outbox row for job ${jobPublicId}`);
    if (row.publishedAt !== null) return 'live-relay';
    if (Date.now() >= deadline) break;
    await sleep(100);
  }
  const row = (await jobOutboxRow(ctx.prisma, jobPublicId))!;
  const claimed = await ctx.prisma.messageOutbox.updateMany({
    where: { id: row.id, createdAt: row.createdAt, publishedAt: null },
    data: { publishedAt: new Date() },
  });
  if (claimed.count === 0) return 'live-relay';
  await publishEnvelope(envelopeOfOutboxRow(row));
  return 'suite';
}

/**
 * Publishes one envelope to its registry exchange (confirmed) as the event-relay's role user
 * (RABBITMQ_RELAY_URL: the `eg-assistant` user may publish only its retry routing keys).
 */
export async function publishEnvelope(envelope: EventEnvelope): Promise<void> {
  const url = process.env.RABBITMQ_RELAY_URL;
  if (!url) throw new Error('RABBITMQ_RELAY_URL must be set (see .env)');
  const logger = createLogger({ service: 'api-integration-relay', level: 'silent' });
  const connection = new AmqpConnection({
    urls: [url],
    connectionName: 'it-assistant-relay',
    logger,
  });
  connection.start();
  try {
    await connection.waitUntilConnected(10_000);
    const publisher = new ConfirmPublisher({
      connection,
      logger,
      appId: 'it-assistant-relay',
      confirmTimeoutMs: 10_000,
      maxMessageBytes: DEFAULT_MAX_MESSAGE_BYTES,
    });
    try {
      await publisher.publish({ envelope });
    } finally {
      await publisher.close().catch(() => undefined);
    }
  } finally {
    await connection.close().catch(() => undefined);
  }
}
