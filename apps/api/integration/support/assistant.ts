/**
 * Helpers of the step AI-1 assistant integration suites (docs/plan/steps/28-ai-chat-management.md
 * §9 item 4, WP4): an api with the assistant on and the deterministic fake provider (never a real
 * provider; `assertFakeProvider` guards it), the api listening on its ephemeral loopback port so
 * every tool call goes through the real `/api/v1` pipeline, the documented enablement path (the
 * platform features route for `ai_assistant`, then `PUT /assistant/settings` with the
 * external-processing acknowledgement), users with chosen roles, turns as JSON or as an
 * `assistant-stream/1` event stream, and readers of the stored rows (executions, transcripts with
 * the model envelopes). Synthetic `it-*` organizations only; tests never reach an LLM or the
 * internet.
 */
import { randomUUID } from 'node:crypto';
import {
  FakeProvider,
  type FakeProviderOptions,
  type FakeTranscriptEntry,
  type LlmProvider,
  type LlmRequest,
  type LlmResponse,
  type LlmToolResult,
  OPERATION_TOOLS,
  type OperationTool,
} from '@email-gateway/assistant';
import { uuidv7 } from '@email-gateway/common';
import { type AiChatToolExecution, TENANT_PERMISSIONS } from '@email-gateway/database';
import type { Response } from 'supertest';
import type { UserPrincipal } from '../../src/auth-contracts/principal';
import { systemScope } from '../../src/auth-contracts/tenant-scope';
import { utcDayKey } from '../../src/modules/assistant/assistant.constants';
import type { Owner } from '../../src/modules/assistant/repositories/conversations.repository';
import { ConversationsRepository } from '../../src/modules/assistant/repositories/conversations.repository';
import {
  AssistantProviderService,
  LLM_PROVIDER_FACTORY,
  type LlmProviderFactory,
} from '../../src/modules/assistant/services/assistant-provider.service';
import {
  type LoopbackCall,
  LoopbackClient,
} from '../../src/modules/assistant/services/loopback-client';
import {
  type ExecutionOutcome,
  ToolExecutorService,
} from '../../src/modules/assistant/services/tool-executor.service';
import { PrincipalLoaderService } from '../../src/modules/auth/services/principal-loader.service';
import { TokenService } from '../../src/modules/auth/services/token.service';
import { createIntegrationApp, type IntegrationApp, type IntegrationAppOptions } from './app';
import type { FixtureOrganization, Fixtures, FixtureUser } from './fixtures';
import { bearer, loginWithMfa, uniqueIp } from './http';

export const A = '/api/v1/assistant';
export const DAY_MS = 86_400_000;

/**
 * The env of an assistant suite: the platform switch on, the fake provider, no provider key, the
 * loopback to this process's own listening port (empty URL), no background timer (suites call
 * the retention service themselves), generous per-user and token limits (suites that test a
 * limit set it through the settings route or fill the Redis window).
 */
export function assistantEnv(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    ASSISTANT_ENABLED: 'true',
    ASSISTANT_PROVIDER: 'fake',
    ASSISTANT_ANTHROPIC_API_KEY: '',
    ASSISTANT_OPENAI_API_KEY: '',
    ASSISTANT_AZURE_OPENAI_API_KEY: '',
    ASSISTANT_LOOPBACK_URL: '',
    ASSISTANT_BACKGROUND_JOBS_ENABLED: 'false',
    ASSISTANT_TURNS_PER_USER_PER_MINUTE: '120',
    ASSISTANT_TENANT_DAILY_TOKENS_DEFAULT: '50000000',
    ASSISTANT_TENANT_DAILY_TOKENS_MAX: '50000000',
    ASSISTANT_PLATFORM_DAILY_TOKENS: '0',
    ...overrides,
  };
}

/**
 * The fake provider with a hold gate: a user message `/hold` waits until `release()` (or until
 * the turn is aborted: cancel route, client disconnect), then answers `Held.`; everything else is
 * the package's `FakeProvider` (directives, demo intents, templates, optional obedient mode).
 * Lets a suite observe a running turn (lock, `409`, cancellation).
 */
export class HoldableFakeProvider implements LlmProvider {
  readonly id = 'fake' as const;
  readonly model: string;
  private readonly inner: FakeProvider;
  private readonly gates: Array<() => void> = [];
  /** Turns currently waiting at the gate. */
  holding = 0;

  constructor(options: FakeProviderOptions) {
    this.inner = new FakeProvider(options);
    this.model = this.inner.model;
  }

  userEntry(text: string): unknown[] {
    return this.inner.userEntry(text);
  }

  toolResultEntries(results: readonly LlmToolResult[]): unknown[] {
    return this.inner.toolResultEntries(results);
  }

  release(): void {
    for (const open of this.gates.splice(0)) open();
  }

  async complete(
    request: LlmRequest,
    signal: AbortSignal,
    onDelta: (text: string) => void,
  ): Promise<LlmResponse> {
    const transcript = request.transcript as readonly FakeTranscriptEntry[];
    const last = transcript.at(-1);
    if (last?.role === 'user' && /(^|\n)\/hold\s*$/.test(last.text)) {
      this.holding += 1;
      try {
        await new Promise<void>((resolve, reject) => {
          const onAbort = (): void => reject(new Error('turn aborted while held'));
          if (signal.aborted) return onAbort();
          signal.addEventListener('abort', onAbort, { once: true });
          this.gates.push(() => {
            signal.removeEventListener('abort', onAbort);
            resolve();
          });
        });
      } finally {
        this.holding -= 1;
      }
      const replaced: FakeTranscriptEntry[] = [
        ...transcript.slice(0, -1),
        { role: 'user', text: '/text Held.' },
      ];
      return this.inner.complete({ ...request, transcript: replaced }, signal, onDelta);
    }
    return this.inner.complete(request, signal, onDelta);
  }
}

export interface AssistantAppOptions extends IntegrationAppOptions {
  env?: Record<string, string>;
  /** Adversarial fake (tests only): follows instruction-shaped text in tool results. */
  obedient?: boolean;
}

export interface AssistantApp {
  ctx: IntegrationApp;
  provider: HoldableFakeProvider;
}

/**
 * An integration app with the assistant on. The provider factory refuses anything but the fake
 * (and the result is checked again by `assertFakeProvider`).
 */
export async function createAssistantApp(options: AssistantAppOptions = {}): Promise<AssistantApp> {
  let provider: HoldableFakeProvider | undefined;
  const factory: LlmProviderFactory = (config) => {
    if (config.ASSISTANT_PROVIDER !== 'fake') {
      throw new Error('assistant integration suites run the fake provider only');
    }
    provider ??= new HoldableFakeProvider({
      nodeEnv: config.NODE_ENV,
      model: 'fake',
      obedient: options.obedient ?? false,
    });
    return provider;
  };
  const ctx = await createIntegrationApp(assistantEnv(options.env), {
    ...(options.imports && { imports: options.imports }),
    override: (builder) => {
      const next = builder.overrideProvider(LLM_PROVIDER_FACTORY).useValue(factory);
      return options.override ? options.override(next) : next;
    },
  });
  try {
    assertFakeProvider(ctx);
  } catch (error) {
    await ctx.close();
    throw error;
  }
  return { ctx, provider: provider! };
}

/** Guard (design §9, I8): the suite's assistant runs the deterministic fake provider. */
export function assertFakeProvider(ctx: IntegrationApp): void {
  const service = ctx.get(AssistantProviderService);
  const provider = service.provider();
  if (
    ctx.config.ASSISTANT_PROVIDER !== 'fake' ||
    service.providerId !== 'fake' ||
    provider.id !== 'fake' ||
    !(provider instanceof HoldableFakeProvider || provider instanceof FakeProvider)
  ) {
    throw new Error('the assistant integration suites must run ASSISTANT_PROVIDER=fake');
  }
}

/** Polls `read` until `accept` holds (usable in hooks, unlike `expect.poll`); throws on timeout. */
export async function waitFor<T>(
  read: () => Promise<T>,
  accept: (value: T) => boolean,
  timeoutMs = 15_000,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await read();
    if (accept(value)) return value;
    if (Date.now() > deadline) throw new Error('waitFor: condition not met in time');
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
}

/** Every tenant permission (the "all tenant permissions" synthetic role). */
export const ALL_TENANT_PERMISSIONS: readonly string[] = TENANT_PERMISSIONS;

/** An organization with every feature on (the assistant included) unless overridden. */
export function allFeatures(): Record<string, boolean> {
  return {
    inbound_filtering: true,
    outbound_filtering: true,
    internal_inspection: true,
    url_rewriting: true,
    attachment_sandbox: true,
    dlp: true,
    bec_detection: true,
    archiving: true,
    api_access: true,
    sso: true,
    webhooks: true,
    ato_detection: true,
    journal_intake: true,
  };
}

export interface Member {
  user: FixtureUser;
  token: string;
  headers: Record<string, string>;
}

/** A user of `org` with these roles (system or custom keys), signed in with MFA. */
export async function member(
  ctx: IntegrationApp,
  fx: Fixtures,
  org: FixtureOrganization,
  roles: string[],
  options: { displayName?: string } = {},
): Promise<Member> {
  const user = await fx.createUser(org, {
    roles,
    mfa: true,
    ...(options.displayName && { displayName: options.displayName }),
  });
  const session = await loginWithMfa(ctx, fx, user);
  return { user, token: session.accessToken, headers: bearer(session.accessToken) };
}

/** A platform user (`super_admin` by default), signed in with MFA. */
export async function platformMember(
  ctx: IntegrationApp,
  fx: Fixtures,
  roles: string[] = ['platform_admin'],
): Promise<Member> {
  const user = await fx.createPlatformUser(roles);
  const session = await loginWithMfa(ctx, fx, user);
  return { user, token: session.accessToken, headers: bearer(session.accessToken) };
}

/** A request helper: a fresh client IP per call. */
export function call(
  ctx: IntegrationApp,
  headers: Record<string, string>,
  method: 'get' | 'post' | 'put' | 'patch' | 'delete',
  path: string,
  body?: object,
) {
  const req = ctx.http[method](path).set(headers).set('X-Forwarded-For', uniqueIp());
  return body === undefined ? req : req.send(body);
}

/** Turns `ai_assistant` on (or off) through the platform features route (a platform operator). */
export async function setAssistantFeature(
  ctx: IntegrationApp,
  operator: Member,
  org: FixtureOrganization,
  enabled: boolean,
): Promise<void> {
  const res = await call(
    ctx,
    operator.headers,
    'put',
    `/api/v1/organizations/${org.publicId}/features/ai_assistant`,
    { enabled },
  );
  if (res.status !== 200) {
    throw new Error(`feature ai_assistant=${enabled} failed: ${res.status} ${res.body?.code}`);
  }
}

export interface SettingsInput {
  enabled?: boolean;
  externalProcessingAcknowledged?: boolean;
  dailyTokenBudget?: number | null;
  retentionDays?: number;
}

/** `PUT /assistant/settings` from the current `rowVersion` (read first). */
export async function putSettings(
  ctx: IntegrationApp,
  admin: Member,
  input: SettingsInput,
): Promise<Response> {
  const current = await call(ctx, admin.headers, 'get', `${A}/settings`);
  if (current.status !== 200) throw new Error(`settings read failed: ${current.status}`);
  return call(ctx, admin.headers, 'put', `${A}/settings`, {
    expectedRowVersion: current.body.rowVersion as number,
    enabled: input.enabled ?? true,
    externalProcessingAcknowledged: input.externalProcessingAcknowledged ?? true,
    dailyTokenBudget: input.dailyTokenBudget === undefined ? null : input.dailyTokenBudget,
    retentionDays: input.retentionDays ?? 30,
  });
}

/** The documented enablement: the platform feature, then the tenant setting (by `admin`). */
export async function enableAssistant(
  ctx: IntegrationApp,
  operator: Member,
  org: FixtureOrganization,
  admin: Member,
  input: SettingsInput = {},
): Promise<void> {
  await setAssistantFeature(ctx, operator, org, true);
  const res = await putSettings(ctx, admin, input);
  if (res.status !== 200) {
    throw new Error(`assistant settings failed: ${res.status} ${JSON.stringify(res.body)}`);
  }
}

/** `POST /assistant/conversations` → the conversation public id. */
export async function newConversation(
  ctx: IntegrationApp,
  who: Member | Record<string, string>,
  title?: string,
): Promise<string> {
  const headers = 'headers' in who ? (who.headers as Record<string, string>) : who;
  const res = await call(ctx, headers, 'post', `${A}/conversations`, title ? { title } : {});
  if (res.status !== 201) {
    throw new Error(`conversation create failed: ${res.status} ${JSON.stringify(res.body)}`);
  }
  return res.body.id as string;
}

export interface TurnOptions {
  clientTurnId?: string;
  timeZone?: string;
}

/** A JSON turn (`{ turn, message, executions }` on 200). */
export function turn(
  ctx: IntegrationApp,
  headers: Record<string, string>,
  conversationId: string,
  message: string,
  options: TurnOptions = {},
) {
  return call(ctx, headers, 'post', `${A}/conversations/${conversationId}/turns`, {
    clientTurnId: options.clientTurnId ?? randomUUID(),
    message,
    ...(options.timeZone && { timeZone: options.timeZone }),
  });
}

/** `/tool <name> <json>` (the fake's directive). */
export const directive = (name: string, args: Record<string, unknown> = {}): string =>
  `/tool ${name} ${JSON.stringify(args)}`;

export type StreamEvent = [string, Record<string, unknown>];

/** `assistant-stream/1` text → `[event, data]` pairs (heartbeat comments dropped). */
export function parseStream(text: string): StreamEvent[] {
  const events: StreamEvent[] = [];
  for (const block of text.split('\n\n')) {
    let name: string | null = null;
    let data = '';
    for (const line of block.split('\n')) {
      if (line.startsWith(':') || line.length === 0) continue;
      if (line.startsWith('event: ')) name = line.slice('event: '.length);
      else if (line.startsWith('data: ')) data += line.slice('data: '.length);
    }
    if (name !== null) events.push([name, JSON.parse(data) as Record<string, unknown>]);
  }
  return events;
}

/** A turn as an event stream: the raw response (headers) and the parsed events. */
export async function streamTurn(
  ctx: IntegrationApp,
  headers: Record<string, string>,
  conversationId: string,
  message: string,
  options: TurnOptions = {},
): Promise<{ res: Response; raw: string; events: StreamEvent[] }> {
  const res = await call(ctx, headers, 'post', `${A}/conversations/${conversationId}/turns`, {
    clientTurnId: options.clientTurnId ?? randomUUID(),
    message,
  })
    .set('accept', 'text/event-stream')
    .buffer(true)
    .parse((stream, done) => {
      let text = '';
      stream.setEncoding('utf8');
      stream.on('data', (chunk: string) => (text += chunk));
      stream.on('end', () => done(null, text));
    });
  const raw = typeof res.body === 'string' ? res.body : '';
  return { res, raw, events: res.status === 200 ? parseStream(raw) : [] };
}

/** Stored executions of a conversation, oldest first. */
export async function executionsOf(
  ctx: IntegrationApp,
  conversationPublicId: string,
): Promise<AiChatToolExecution[]> {
  return ctx.prisma.aiChatToolExecution.findMany({
    where: { conversation: { publicId: conversationPublicId } },
    orderBy: { seq: 'asc' },
  });
}

/** The tool-result envelopes the model received in a turn (from the stored native transcript). */
export async function envelopesOf(
  ctx: IntegrationApp,
  turnPublicId: string,
): Promise<Array<{ raw: string; parsed: Record<string, unknown> }>> {
  const row = await ctx.prisma.aiChatTurn.findUniqueOrThrow({
    where: { publicId: turnPublicId },
    select: { providerTranscript: true },
  });
  if (row.providerTranscript === null) return [];
  const entries = JSON.parse(row.providerTranscript) as FakeTranscriptEntry[];
  return entries
    .filter((e): e is Extract<FakeTranscriptEntry, { role: 'tool' }> => e.role === 'tool')
    .map((e) => ({ raw: e.content, parsed: JSON.parse(e.content) as Record<string, unknown> }));
}

/** The credential-key pattern of the audit log and the minimizer (with its safe list). */
const CREDENTIAL_KEY = /password|secret|token|code|key$/i;
const SAFE_KEYS = new Set([
  'statusCode',
  'planCode',
  'featureKey',
  'limitKey',
  'roleKey',
  'permissionKey',
]);

/** Paths of keys (at any depth of `value`) that match the credential pattern. */
export function credentialKeys(value: unknown, path = '$'): string[] {
  if (Array.isArray(value))
    return value.flatMap((item, i) => credentialKeys(item, `${path}[${i}]`));
  if (value === null || typeof value !== 'object') return [];
  return Object.entries(value as Record<string, unknown>).flatMap(([key, item]) => [
    ...(CREDENTIAL_KEY.test(key) && !SAFE_KEYS.has(key) ? [`${path}.${key}`] : []),
    ...credentialKeys(item, `${path}.${key}`),
  ]);
}

/**
 * Credential-pattern keys in the record parts of an envelope (`data`: any such key, the minimizer
 * drops them) and of a card (`rows`, `fields`: any such key holding a value; the card keeps a
 * display column whose name matches the pattern but withholds its cells as null). The envelope's
 * and card's own metadata keys (`code` of an error) are part of their contracts.
 */
export function credentialKeysInResult(
  envelope: Record<string, unknown> | null,
  card: Record<string, unknown> | null,
): string[] {
  const out: string[] = [];
  if (envelope) out.push(...credentialKeys(envelope.data ?? null, 'envelope.data'));
  if (card) {
    const rows = (card.rows as Array<Record<string, unknown>> | undefined) ?? [];
    rows.forEach((row, i) => {
      for (const [key, value] of Object.entries(row)) {
        if (CREDENTIAL_KEY.test(key) && !SAFE_KEYS.has(key) && value !== null) {
          out.push(`card.rows[${i}].${key}`);
        }
        out.push(...credentialKeys(value, `card.rows[${i}].${key}`));
      }
    });
    for (const field of (card.fields as Array<{ key: string; value: unknown }> | undefined) ?? []) {
      if (CREDENTIAL_KEY.test(field.key) && !SAFE_KEYS.has(field.key) && field.value !== null) {
        out.push(`card.fields.${field.key}`);
      }
    }
  }
  return out;
}

/** Display columns of a card whose name matches the credential pattern (cells withheld). */
export function withheldColumns(card: Record<string, unknown> | null): string[] {
  return ((card?.columns as Array<{ key: string }> | undefined) ?? [])
    .map((c) => c.key)
    .filter((key) => CREDENTIAL_KEY.test(key) && !SAFE_KEYS.has(key));
}

/** Records every loopback request of the app (the real client still sends it). */
export function recordLoopback(ctx: IntegrationApp): {
  calls: Array<Pick<LoopbackCall, 'method' | 'path' | 'correlationId'>>;
  restore: () => void;
} {
  const client = ctx.get(LoopbackClient);
  const original = client.send.bind(client);
  const calls: Array<Pick<LoopbackCall, 'method' | 'path' | 'correlationId'>> = [];
  client.send = (c: LoopbackCall) => {
    calls.push({ method: c.method, path: c.path, correlationId: c.correlationId });
    return original(c);
  };
  return { calls, restore: () => void (client.send = original) };
}

/** Deletes the assistant's Redis token counters of the organizations (today's UTC day). */
export async function clearAssistantCounters(
  ctx: IntegrationApp,
  organizationIds: readonly bigint[],
): Promise<void> {
  const day = utcDayKey(new Date());
  for (const id of organizationIds) await ctx.kv.del(`as:tok:o:${id}:${day}`);
}

/** The enabled tools of the registry (AI-1: the read tools). */
export const ENABLED_TOOLS: readonly OperationTool[] = OPERATION_TOOLS.filter((t) => t.enabled);

/** Values of required parameters that are not UUIDs, enums, dates or integers. */
const SPECIAL_VALUES: Readonly<Record<string, unknown>> = {
  sha256: 'a'.repeat(64),
  kind: 'message_explorer',
  key: 'it_unknown_role',
  suppressionId: '999999999999',
  versionNo: 1,
};

/**
 * Minimal valid arguments from a tool's input schema: required parameters and the path
 * parameters (a bound one only when `bound` is false: platform users get no binding), synthetic
 * UUIDs for ids, the first enum value, `from` = now − 1 day and `to` = now for date-times,
 * integers at their minimum (or 1).
 */
export function minimalArguments(
  tool: OperationTool,
  options: { bound?: boolean; now?: Date } = {},
): Record<string, unknown> {
  const now = options.now ?? new Date();
  const bound = options.bound ?? true;
  const schema = tool.inputSchema as {
    properties?: Record<string, Record<string, unknown>>;
    required?: string[];
  };
  const args: Record<string, unknown> = {};
  const names = new Set(schema.required ?? []);
  for (const param of tool.pathParams) if (!(bound && tool.bind[param])) names.add(param);
  for (const name of names) {
    const prop = schema.properties?.[name] ?? {};
    if (name in SPECIAL_VALUES) args[name] = SPECIAL_VALUES[name];
    else if (Array.isArray(prop.enum)) args[name] = prop.enum[0];
    else if (prop.format === 'uuid') args[name] = randomUUID();
    else if (prop.format === 'date-time') {
      args[name] = (name === 'to' ? now : new Date(now.getTime() - DAY_MS)).toISOString();
    } else if (prop.type === 'integer' || prop.type === 'number') {
      args[name] = typeof prop.minimum === 'number' ? prop.minimum : 1;
    } else if (prop.type === 'boolean') args[name] = false;
    else args[name] = 'it-unknown';
  }
  return args;
}

/**
 * The real principal of an access token (the guard's base path: verified claims and the
 * principal snapshot), for suites that call the executor directly.
 */
export async function principalOf(ctx: IntegrationApp, token: string): Promise<UserPrincipal> {
  const claims = await ctx.get(TokenService).verify(token);
  if (!claims) throw new Error('invalid access token');
  const snapshot = await ctx.get(PrincipalLoaderService).load(claims.sub);
  if (!snapshot) throw new Error('unknown principal');
  return {
    kind: 'user',
    userId: BigInt(snapshot.user.id),
    userPublicId: snapshot.user.publicId,
    organizationId: BigInt(snapshot.org.id),
    organizationPublicId: snapshot.org.publicId,
    organizationKind: snapshot.org.kind,
    sessionId: claims.sid,
    mfaAuthenticated: claims.amr.includes('otp'),
    mfaEnrollmentRequired: snapshot.org.mfaRequired && !snapshot.user.mfaEnabled,
    permissions: new Set(snapshot.permissions),
  };
}

/**
 * The executor (D5) for one tool call outside a turn, storing the conversation and its
 * executions under `storageOrg` (a synthetic organization). Used for the platform-only tools: a
 * turn of a platform user needs the assistant enabled in the platform organization, which the
 * suites never change. Everything after the turn wrapper is real: pre-filter, schema, the
 * loopback with the user's bearer through the api's pipeline, card, envelope, execution row and
 * audit row.
 */
export class DirectExecutor {
  private seq = 1;
  private conversation: { id: bigint; publicId: string } | null = null;

  constructor(
    private readonly ctx: IntegrationApp,
    private readonly member: Member,
    private readonly principal: UserPrincipal,
    private readonly storageOrg: FixtureOrganization,
  ) {}

  private get owner(): Owner {
    return { scope: systemScope(this.storageOrg.id), userId: this.principal.userId };
  }

  async execute(name: string, args: Record<string, unknown>): Promise<ExecutionOutcome> {
    if (!this.conversation) {
      const now = new Date();
      const row = await this.ctx.get(ConversationsRepository).create(this.owner, {
        publicId: uuidv7(),
        title: 'it platform tools',
        platformOverrideId: null,
        now,
        purgeAfter: new Date(now.getTime() + 30 * DAY_MS),
      });
      this.conversation = { id: row.id, publicId: row.publicId };
    }
    const conversation = this.conversation;
    const base = `it-direct-${randomUUID()}`;
    return this.ctx.get(ToolExecutorService).execute(
      {
        principal: this.principal,
        owner: this.owner,
        conversationId: conversation.id,
        conversationPublicId: conversation.publicId,
        turnId: null,
        turnPublicId: null,
        parentExecutionId: null,
        parentExecutionPublicId: null,
        authorization: `Bearer ${this.member.token}`,
        clientIp: uniqueIp(),
        correlationBase: base,
        signal: new AbortController().signal,
        allocateSeq: () => this.seq++,
      },
      { name, arguments: args },
      0,
    );
  }
}
