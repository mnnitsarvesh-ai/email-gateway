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
import { randomBytes, randomUUID } from 'node:crypto';
import { HttpException } from '@nestjs/common';
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
import {
  type AiChatActionConfirmation,
  type AiChatToolExecution,
  type AuditLog,
  TENANT_PERMISSIONS,
} from '@email-gateway/database';
import type { Response } from 'supertest';
import type { UserPrincipal } from '../../src/auth-contracts/principal';
import { systemScope } from '../../src/auth-contracts/tenant-scope';
import { assistantKeys, utcDayKey } from '../../src/modules/assistant/assistant.constants';
import type { Owner } from '../../src/modules/assistant/repositories/conversations.repository';
import { ConversationsRepository } from '../../src/modules/assistant/repositories/conversations.repository';
import { ExecutionsRepository } from '../../src/modules/assistant/repositories/executions.repository';
import {
  AssistantProviderService,
  LLM_PROVIDER_FACTORY,
  type LlmProviderFactory,
} from '../../src/modules/assistant/services/assistant-provider.service';
import {
  type LoopbackCall,
  LoopbackClient,
} from '../../src/modules/assistant/services/loopback-client';
import { ConfirmationService } from '../../src/modules/assistant/services/confirmation.service';
import { ConfirmationViewsService } from '../../src/modules/assistant/services/confirmation-views.service';
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

export type RecordedCall = Pick<LoopbackCall, 'method' | 'path' | 'correlationId'> & {
  /** The `Idempotency-Key` the executor set (confirmed writes of `required`/`legacy` routes). */
  idempotencyKey: string | null;
};

/** Records every loopback request of the app (the real client still sends it). */
export function recordLoopback(ctx: IntegrationApp): {
  calls: RecordedCall[];
  restore: () => void;
} {
  const client = ctx.get(LoopbackClient);
  const original = client.send.bind(client);
  const calls: RecordedCall[] = [];
  client.send = (c: LoopbackCall) => {
    calls.push({
      method: c.method,
      path: c.path,
      correlationId: c.correlationId,
      idempotencyKey: c.idempotencyKey ?? null,
    });
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

/** The enabled tools of the registry (the reads and the confirmable writes; AI-3: 257). */
export const ENABLED_TOOLS: readonly OperationTool[] = OPERATION_TOOLS.filter((t) => t.enabled);
/** The enabled read tools (step AI-2: 178; step AI-3: 179 with `api_keys_get`). */
export const ENABLED_READS: readonly OperationTool[] = ENABLED_TOOLS.filter(
  (t) => t.access === 'read',
);
/** The enabled write tools (step AI-2: 31; step AI-3: 78), each behind a confirmation. */
export const ENABLED_WRITES: readonly OperationTool[] = ENABLED_TOOLS.filter(
  (t) => t.access === 'write',
);

/** Values of required parameters that are not UUIDs, enums, dates or integers. */
const SPECIAL_VALUES: Readonly<Record<string, unknown>> = {
  sha256: 'a'.repeat(64),
  kind: 'message_explorer',
  key: 'it_unknown_role',
  suppressionId: '999999999999',
  versionNo: 1,
};

/**
 * The required members of an object schema, recursively (the request bodies of the AI-2 tools:
 * an object member is built from its own required members, `{}` when it has none).
 */
function minimalObject(schema: Record<string, unknown>): Record<string, unknown> {
  const properties = (schema.properties ?? {}) as Record<string, Record<string, unknown>>;
  const out: Record<string, unknown> = {};
  for (const name of (schema.required as string[] | undefined) ?? []) {
    const prop = properties[name] ?? {};
    if (prop.type === 'object') out[name] = minimalObject(prop);
    else if (Array.isArray(prop.enum)) out[name] = prop.enum[0];
    else if (prop.type === 'integer' || prop.type === 'number') {
      out[name] = typeof prop.minimum === 'number' ? prop.minimum : 1;
    } else if (prop.type === 'boolean') out[name] = false;
    else if (prop.type === 'array') out[name] = [];
    else out[name] = 'it-unknown';
  }
  return out;
}

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
    else if (prop.type === 'object') args[name] = minimalObject(prop);
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
    // From the stored sequence: a confirmed proposal (`DirectConfirmer`) adds its result
    // execution to the same conversation.
    let seq = await this.ctx.get(ExecutionsRepository).nextSeq(this.owner, conversation.id);
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
        allocateSeq: () => seq++,
      },
      { name, arguments: args },
      0,
    );
  }
}

// ---------------------------------------------------------------------------------------------
// Step AI-2: write proposals and their confirmations (docs/plan/steps/29-ai-chat-confirmations-
// mail-writes.md D1, D2, D6, D7, §9 item 4; contracts §35.1)
// ---------------------------------------------------------------------------------------------

/** The `ConfirmationView` of the routes and turn results (contracts §35.1). */
export interface ConfirmationJson {
  id: string;
  executionId: string;
  resultExecutionId: string | null;
  conversationId: string;
  tool: string;
  operationId: string;
  risk: 'low' | 'medium' | 'high';
  requiresReauth: boolean;
  reauthFresh: boolean;
  status: 'pending' | 'executing' | 'executed' | 'failed' | 'expired' | 'cancelled';
  summary: {
    version: string;
    title: string;
    action: string;
    target: Array<{ label: string; value: string; untrusted?: boolean }>;
    changes: Array<{ label: string; before?: string | null; after: string }>;
    impact: string[];
    warnings: string[];
    reversible: boolean;
    request: { method: string; path: string };
  } | null;
  actionDigest: string;
  expiresAt: string;
  createdAt: string;
  decidedAt: string | null;
  executedAt: string | null;
  result: { httpStatus: number | null; error: string | null } | null;
}

/** A pending proposal as the proposing tab holds it: the card's data and the single-use token. */
export interface Pending {
  confirmation: ConfirmationJson;
  token: string;
}

/** A turn that proposed exactly one write. */
export interface Proposal extends Pending {
  res: Response;
  conversation: string;
  /** The proposal execution (`status: 'pending_confirmation'`). */
  execution: Record<string, unknown>;
}

/** `{ confirmation, token }` pairs of a JSON turn result (`token` null on a replay). */
export function confirmationsOfTurn(
  body: Record<string, unknown>,
): Array<{ confirmation: ConfirmationJson; token: string | null }> {
  return (
    (body.confirmations as Array<{ confirmation: ConfirmationJson; token: string | null }>) ?? []
  );
}

/** `{ confirmation, token }` of every `confirmation.required` event of a stream. */
export function requiredOf(events: readonly StreamEvent[]): Pending[] {
  return events
    .filter(([name]) => name === 'confirmation.required')
    .map(([, data]) => data as unknown as Pending);
}

/**
 * A JSON turn that must propose exactly one write (`pending_confirmation`): in `conversation`
 * when given, else in a new conversation of `who`. Throws with the turn's answer otherwise.
 */
export async function propose(
  ctx: IntegrationApp,
  who: Member,
  message: string,
  conversation?: string,
): Promise<Proposal> {
  const id = conversation ?? (await newConversation(ctx, who));
  const res = await turn(ctx, who.headers, id, message);
  const pairs = res.status === 200 ? confirmationsOfTurn(res.body) : [];
  const execution = (res.body?.executions as Array<Record<string, unknown>> | undefined)?.find(
    (e) => e.status === 'pending_confirmation',
  );
  const token = pairs[0]?.token;
  if (pairs.length !== 1 || !execution || typeof token !== 'string') {
    throw new Error(
      `expected one proposal: ${res.status} ${JSON.stringify(
        (res.body?.executions as Array<Record<string, unknown>> | undefined)?.map((e) => ({
          tool: e.tool,
          decision: e.decision,
          status: e.status,
          httpStatus: e.httpStatus,
          errorCode: e.errorCode,
        })) ?? res.body,
      )}`,
    );
  }
  return {
    res,
    conversation: id,
    execution,
    confirmation: pairs[0]!.confirmation,
    token,
  };
}

/** A fresh, well-formed token that is not the confirmation's (43 base64url characters). */
export const wrongToken = (): string => randomBytes(32).toString('base64url');

export interface ReauthInput {
  password: string;
  totpCode?: string;
}

export interface ConfirmOverrides {
  token?: string;
  actionDigest?: string;
  reauth?: ReauthInput;
}

/** `POST /assistant/confirmations/{id}/confirm` with the proposal's token and digest. */
export function confirm(
  ctx: IntegrationApp,
  who: Member | Record<string, string>,
  pending: Pending,
  overrides: ConfirmOverrides = {},
) {
  const headers = 'headers' in who ? (who.headers as Record<string, string>) : who;
  return call(ctx, headers, 'post', `${A}/confirmations/${pending.confirmation.id}/confirm`, {
    token: overrides.token ?? pending.token,
    actionDigest: overrides.actionDigest ?? pending.confirmation.actionDigest,
    ...(overrides.reauth && { reauth: overrides.reauth }),
  });
}

/** `POST /assistant/confirmations/{id}/cancel`. */
export function cancelConfirmation(
  ctx: IntegrationApp,
  who: Member | Record<string, string>,
  confirmationId: string,
) {
  const headers = 'headers' in who ? (who.headers as Record<string, string>) : who;
  return call(ctx, headers, 'post', `${A}/confirmations/${confirmationId}/cancel`);
}

/** `GET /assistant/confirmations/{id}`. */
export function getConfirmation(
  ctx: IntegrationApp,
  who: Member | Record<string, string>,
  confirmationId: string,
) {
  const headers = 'headers' in who ? (who.headers as Record<string, string>) : who;
  return call(ctx, headers, 'get', `${A}/confirmations/${confirmationId}`);
}

/** The re-authentication of a high-risk confirm: the password and, with MFA, a fresh code. */
export async function reauthOf(fx: Fixtures, who: Member): Promise<ReauthInput> {
  return {
    password: who.user.password,
    ...(who.user.totpSecret !== undefined && { totpCode: await fx.totpNow(who.user) }),
  };
}

/**
 * A user of `org` holding exactly `permissions` (a custom role; `assistant:use` is added) or the
 * given system roles, signed in (with MFA unless `mfa: false`).
 */
export async function memberWith(
  ctx: IntegrationApp,
  fx: Fixtures,
  org: FixtureOrganization,
  grant: { permissions?: readonly string[]; roles?: readonly string[] },
  options: { mfa?: boolean; email?: string; displayName?: string } = {},
): Promise<Member> {
  const roles = [...(grant.roles ?? [])];
  if (grant.permissions) {
    roles.push(
      await fx.createCustomRole(org, [...new Set(['assistant:use', ...grant.permissions])]),
    );
  }
  const user = await fx.createUser(org, {
    roles,
    mfa: options.mfa ?? true,
    ...(options.email && { email: options.email }),
    ...(options.displayName && { displayName: options.displayName }),
  });
  const session = await loginWithMfa(ctx, fx, user);
  return { user, token: session.accessToken, headers: bearer(session.accessToken) };
}

/** A second sign-in of the same user: a new session family (`principal.sessionId`). */
export async function secondSession(
  ctx: IntegrationApp,
  fx: Fixtures,
  who: Member,
): Promise<Member> {
  const session = await loginWithMfa(ctx, fx, who.user);
  return { user: who.user, token: session.accessToken, headers: bearer(session.accessToken) };
}

/**
 * Moves the clock of the confirm route and of the confirmation views to `at` (both services
 * expose `now()`); returns the function that restores the real clock.
 */
export function confirmationClock(ctx: IntegrationApp, at: Date): () => void {
  const service = ctx.get(ConfirmationService);
  const views = ctx.get(ConfirmationViewsService);
  const original = { service: service.now, views: views.now };
  service.now = () => new Date(at);
  views.now = () => new Date(at);
  return () => {
    service.now = original.service;
    views.now = original.views;
  };
}

/** The stored confirmation row. */
export function confirmationRow(
  ctx: IntegrationApp,
  publicId: string,
): Promise<AiChatActionConfirmation> {
  return ctx.prisma.aiChatActionConfirmation.findUniqueOrThrow({ where: { publicId } });
}

/** Audit rows of an organization with this correlation id, oldest first. */
export function auditByCorrelation(
  ctx: IntegrationApp,
  organizationId: bigint,
  correlationId: string,
): Promise<AuditLog[]> {
  return ctx.prisma.auditLog.findMany({
    where: { organizationId, correlationId },
    orderBy: { id: 'asc' },
  });
}

/** Audit rows of a confirmation (resource id = its public id), oldest first. */
export function confirmationAudit(
  ctx: IntegrationApp,
  organizationId: bigint,
  publicId: string,
): Promise<AuditLog[]> {
  return ctx.prisma.auditLog.findMany({
    where: { organizationId, resourceType: 'assistant_action_confirmation', resourceId: publicId },
    orderBy: { id: 'asc' },
  });
}

/** The execution row (writer) of a public id. */
export function executionRow(ctx: IntegrationApp, publicId: string): Promise<AiChatToolExecution> {
  return ctx.prisma.aiChatToolExecution.findUniqueOrThrow({ where: { publicId } });
}

const jsonOf = (value: unknown): string =>
  JSON.stringify(value, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));

/**
 * Everything stored for a conversation and an organization that must never carry a token:
 * native transcripts, message contents, execution rows (cards, refs), confirmation rows and the
 * organization's audit rows (metadata included), as one string.
 */
export async function storedTraces(
  ctx: IntegrationApp,
  organizationId: bigint,
  conversationPublicId: string,
): Promise<string> {
  const conversation = { publicId: conversationPublicId };
  const [turns, messages, executions, confirmations, audit] = await Promise.all([
    ctx.prisma.aiChatTurn.findMany({ where: { conversation } }),
    ctx.prisma.aiChatMessage.findMany({ where: { conversation } }),
    ctx.prisma.aiChatToolExecution.findMany({ where: { conversation } }),
    ctx.prisma.aiChatActionConfirmation.findMany({ where: { conversation } }),
    ctx.prisma.auditLog.findMany({ where: { organizationId } }),
  ]);
  return jsonOf({ turns, messages, executions, confirmations, audit });
}

/**
 * Polls a GET of `who` until it answers 200 and `accept` holds (the precondition reads of
 * policies, quarantine entries, messages and suppressions are served by the replica).
 */
export async function waitForRead(
  ctx: IntegrationApp,
  who: Member,
  path: string,
  accept: (body: Record<string, unknown>) => boolean = () => true,
): Promise<Record<string, unknown>> {
  const res = await waitFor(
    () => call(ctx, who.headers, 'get', path),
    (r) => r.status === 200 && accept(r.body as Record<string, unknown>),
  );
  return res.body as Record<string, unknown>;
}

/** Writes without the assistant (`assistant.*`) audit actions among audit rows. */
export const operationAudit = (rows: ReadonlyArray<{ action: string }>): string[] =>
  rows.map((r) => r.action).filter((action) => !action.startsWith('assistant.'));

// ---------------------------------------------------------------------------------------------
// Step AI-3: identity and tenant administration writes (docs/plan/steps/30-ai-chat-identity-
// tenant-admin.md D3–D6, D10, §9 item 4; contracts §35.2)
// ---------------------------------------------------------------------------------------------

/** A proposed and confirmed write (directive turn + confirm route). */
export interface ChatWrite {
  proposal: Proposal;
  res: Response;
  /** Loopback requests of the confirm (the precondition re-read and the write). */
  calls: RecordedCall[];
}

/**
 * Proposes `tool` through a directive turn of `who` (in `conversation` when given) and confirms
 * it, re-authenticating (password + TOTP) when the stored risk needs it and the session's window
 * is closed. `reauth: false` never sends the re-authentication.
 */
export async function proposeAndConfirm(
  ctx: IntegrationApp,
  fx: Fixtures,
  who: Member,
  tool: string,
  args: Record<string, unknown>,
  options: { conversation?: string; reauth?: boolean } = {},
): Promise<ChatWrite> {
  const proposal = await propose(ctx, who, directive(tool, args), options.conversation);
  if (proposal.confirmation.tool !== tool) {
    throw new Error(`proposed ${proposal.confirmation.tool}, expected ${tool}`);
  }
  const recorder = recordLoopback(ctx);
  try {
    const reauth =
      options.reauth !== false &&
      proposal.confirmation.requiresReauth &&
      !proposal.confirmation.reauthFresh
        ? await reauthOf(fx, who)
        : undefined;
    const res = await confirm(ctx, who, proposal, reauth ? { reauth } : {});
    return { proposal, res, calls: [...recorder.calls] };
  } finally {
    recorder.restore();
  }
}

/** A loopback path template (`/api/v1/users/{id}/roles`) as an anchored expression. */
function templatePattern(template: string): RegExp {
  const escaped = template
    .split(/\{[^}]+\}/)
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('[^/?]+');
  return new RegExp(`^${escaped}(\\?.*)?$`);
}

/** The recorded non-GET requests to a route of this path template (none expected). */
export function writesTo(recorder: { calls: RecordedCall[] }, template: string): RecordedCall[] {
  const pattern = templatePattern(template);
  return recorder.calls.filter((c) => c.method !== 'GET' && pattern.test(c.path));
}

/** No request of any method reached the route of this path template (I12: not even a read). */
export function requestsTo(recorder: { calls: RecordedCall[] }, template: string): RecordedCall[] {
  const pattern = templatePattern(template);
  return recorder.calls.filter((c) => pattern.test(c.path));
}

/** Throws when a write request reached the route of this path template. */
export function expectNoWrite(recorder: { calls: RecordedCall[] }, template: string): void {
  const sent = writesTo(recorder, template);
  if (sent.length > 0) {
    throw new Error(`write request(s) reached ${template}: ${JSON.stringify(sent)}`);
  }
}

/** The correlation id of a confirm's result execution (the operation's own audit row has it). */
export async function resultCorrelationId(
  ctx: IntegrationApp,
  confirmed: { body: Record<string, unknown> },
): Promise<string> {
  const execution = confirmed.body.execution as { id: string } | undefined;
  if (!execution) throw new Error(`no result execution: ${JSON.stringify(confirmed.body)}`);
  return (await executionRow(ctx, execution.id)).correlationId;
}

/** Audit actions (any organization) carrying this correlation id, oldest first. */
export async function actionsByCorrelation(
  ctx: IntegrationApp,
  correlationId: string,
): Promise<string[]> {
  const rows = await ctx.prisma.auditLog.findMany({
    where: { correlationId },
    orderBy: { id: 'asc' },
    select: { action: true },
  });
  return rows.map((r) => r.action);
}

/** Closes the session's assistant re-authentication window (the next high confirm asks again). */
export async function closeReauthWindow(ctx: IntegrationApp, who: Member): Promise<void> {
  const principal = await principalOf(ctx, who.token);
  await ctx.kv.del(assistantKeys.reauthWindow(principal.sessionId));
}

/** A pending proposal of a direct execution (`DirectExecutor`), as the browser holds it. */
export function pendingOf(outcome: ExecutionOutcome): Pending {
  if (!outcome.confirmation) {
    throw new Error(
      `expected a proposal: ${outcome.tool} ${outcome.decision} ${outcome.status} ` +
        `${outcome.httpStatus} ${outcome.errorCode}`,
    );
  }
  return {
    confirmation: JSON.parse(jsonOf(outcome.confirmation.view)) as ConfirmationJson,
    token: outcome.confirmation.token,
  };
}

/** The answer of a direct confirm: the route's body on success, the coded error otherwise. */
export interface DirectAnswer {
  status: number;
  /** Untyped like a supertest body (tests read the route's documented shape). */
  body: Response['body'];
}

/**
 * The confirm route's service (`ConfirmationService.confirm`, D2) for the proposals of a
 * `DirectExecutor`: the same platform principal and the storage organization's `systemScope`
 * as the executor's owner, the user's bearer for the precondition re-read and the write (the
 * real `/api/v1` pipeline). No production seam: the controller does exactly this with the
 * principal and scope of the request. The storage organization must have the assistant enabled
 * (`enableStorage`), because confirm checks the availability of the owner's scope.
 */
export class DirectConfirmer {
  constructor(
    private readonly ctx: IntegrationApp,
    private readonly member: Member,
    private readonly principal: UserPrincipal,
    private readonly storageOrg: FixtureOrganization,
  ) {}

  async confirm(pending: Pending, overrides: ConfirmOverrides = {}): Promise<DirectAnswer> {
    try {
      const body = await this.ctx.get(ConfirmationService).confirm(
        this.principal,
        systemScope(this.storageOrg.id),
        pending.confirmation.id,
        {
          token: overrides.token ?? pending.token,
          actionDigest: overrides.actionDigest ?? pending.confirmation.actionDigest,
          ...(overrides.reauth && { reauth: overrides.reauth }),
        },
        { authorization: `Bearer ${this.member.token}`, clientIp: uniqueIp() },
      );
      return { status: 200, body: JSON.parse(jsonOf(body)) };
    } catch (error) {
      if (error instanceof HttpException) {
        const response = error.getResponse();
        return {
          status: error.getStatus(),
          body:
            typeof response === 'object' && response !== null ? response : { message: response },
        };
      }
      throw error;
    }
  }
}

/** A platform user's direct executor and confirmer over one storage `it-*` organization. */
export interface DirectPlatform {
  member: Member;
  principal: UserPrincipal;
  executor: DirectExecutor;
  confirmer: DirectConfirmer;
  /** Executes `tool` and returns its pending proposal (throws otherwise). */
  propose: (tool: string, args: Record<string, unknown>) => Promise<Pending>;
  /** Confirms a proposal, re-authenticating when it needs it and the window is closed. */
  confirm: (pending: Pending, options?: { reauth?: boolean }) => Promise<DirectAnswer>;
}

/**
 * A platform user (`super_admin` by default) with a `DirectExecutor` and a `DirectConfirmer`
 * storing under `storageOrg` (a synthetic organization whose assistant `enableStorage` turned
 * on). Platform writes always name their target organization explicitly (never the
 * `self_organization` binding of a platform user's own organization).
 */
export async function directPlatform(
  ctx: IntegrationApp,
  fx: Fixtures,
  storageOrg: FixtureOrganization,
  roles: string[] = ['super_admin'],
): Promise<DirectPlatform> {
  const who = await platformMember(ctx, fx, roles);
  const principal = await principalOf(ctx, who.token);
  const executor = new DirectExecutor(ctx, who, principal, storageOrg);
  const confirmer = new DirectConfirmer(ctx, who, principal, storageOrg);
  return {
    member: who,
    principal,
    executor,
    confirmer,
    propose: async (tool, args) => pendingOf(await executor.execute(tool, args)),
    confirm: async (pending, options = {}) => {
      const reauth =
        options.reauth !== false &&
        pending.confirmation.requiresReauth &&
        !(await ctx.kv.exists(assistantKeys.reauthWindow(principal.sessionId)))
          ? await reauthOf(fx, who)
          : undefined;
      return confirmer.confirm(pending, reauth ? { reauth } : {});
    },
  };
}

/**
 * Turns the assistant on for a storage organization of `DirectExecutor` proposals (the platform
 * feature, then the tenant setting by a temporary administrator of that organization).
 */
export async function enableStorage(
  ctx: IntegrationApp,
  fx: Fixtures,
  operator: Member,
  storageOrg: FixtureOrganization,
): Promise<void> {
  const admin = await memberWith(ctx, fx, storageOrg, {
    permissions: ['assistant:configure', 'organization:read'],
  });
  await enableAssistant(ctx, operator, storageOrg, admin);
}
