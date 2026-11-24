import { z } from 'zod';
import { ApiError } from '@/lib/api/errors';
import { isAbortError, openOperationStream } from '@/lib/api/stream';
import {
  CARD_VERSION,
  CONFIRMATION_SUMMARY_VERSION,
  type AssistantStreamEvent,
  type ConfirmationView,
  type TurnResult,
} from './types';

/**
 * Client of `assistant-stream/1` (step AI-1 §4.2, D14): an incremental Server-Sent Events parser
 * (chunk boundaries anywhere, CR/LF/CRLF line ends, multi-line `data`, comment heartbeats, a cap
 * on the size of one event), a runtime validator of the event payloads, and `runTurn`, which
 * POSTs a turn through the BFF with `accept: text/event-stream`, feeds every event to the caller
 * and falls back to the JSON answer when the response is not an event stream or the stream breaks
 * (the same `clientTurnId` replays a completed turn; contracts §35).
 */

/** Largest single event accepted (the api caps a card at 64 KiB and assistant text at 16 000 chars). */
export const MAX_EVENT_CHARS = 1024 * 1024;

export class StreamProtocolError extends Error {
  constructor(
    readonly code: 'event_too_large' | 'stream_ended' | 'invalid_response',
    message: string,
  ) {
    super(message);
    this.name = 'StreamProtocolError';
  }
}

export interface RawSseEvent {
  /** `event:` field (default `message`). */
  readonly event: string;
  /** `data:` lines joined with `\n`. */
  readonly data: string;
}

/**
 * Incremental SSE parser (WHATWG "event stream interpretation"): feed decoded text with `push`,
 * call `end` at EOF (an unterminated event is dropped, as the specification requires). Comment
 * lines (`:` first, the api's heartbeat) and unknown fields are ignored; `id` and `retry` are
 * accepted and unused (the turn is never resumed by `Last-Event-ID`).
 */
export class SseParser {
  private buffer = '';
  private skipLeadingLf = false;
  private eventName = '';
  private dataLines: string[] = [];
  private eventChars = 0;

  constructor(
    private readonly onEvent: (event: RawSseEvent) => void,
    private readonly maxEventChars: number = MAX_EVENT_CHARS,
  ) {}

  push(text: string): void {
    let chunk = text;
    if (this.skipLeadingLf && chunk.startsWith('\n')) chunk = chunk.slice(1);
    this.skipLeadingLf = false;
    this.buffer += chunk;
    let start = 0;
    for (let i = 0; i < this.buffer.length; i += 1) {
      const char = this.buffer[i];
      if (char !== '\n' && char !== '\r') continue;
      this.line(this.buffer.slice(start, i));
      if (char === '\r') {
        if (i + 1 < this.buffer.length) {
          if (this.buffer[i + 1] === '\n') i += 1;
        } else {
          // A CR at the end of this chunk: a LF starting the next chunk belongs to it.
          this.skipLeadingLf = true;
        }
      }
      start = i + 1;
    }
    this.buffer = this.buffer.slice(start);
    if (this.eventChars + this.buffer.length > this.maxEventChars) {
      this.reset();
      throw new StreamProtocolError('event_too_large', 'A streamed event exceeded the size limit');
    }
  }

  end(): void {
    // The specification discards an event that was not terminated by a blank line.
    this.reset();
  }

  private reset(): void {
    this.buffer = '';
    this.eventName = '';
    this.dataLines = [];
    this.eventChars = 0;
  }

  private line(line: string): void {
    if (line === '') {
      this.dispatch();
      return;
    }
    this.eventChars += line.length + 1;
    if (this.eventChars > this.maxEventChars) {
      this.reset();
      throw new StreamProtocolError('event_too_large', 'A streamed event exceeded the size limit');
    }
    if (line.startsWith(':')) return;
    const colon = line.indexOf(':');
    const field = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'event') this.eventName = value;
    else if (field === 'data') this.dataLines.push(value);
  }

  private dispatch(): void {
    const data = this.dataLines;
    const name = this.eventName || 'message';
    this.eventName = '';
    this.dataLines = [];
    this.eventChars = 0;
    if (data.length === 0) return;
    this.onEvent({ event: name, data: data.join('\n') });
  }
}

const id = z.string().min(1).max(128);
const decision = z.enum([
  'allowed',
  'denied_permission',
  'denied_unknown_tool',
  'denied_disabled',
  'denied_not_applicable',
  'denied_schema',
  'denied_ref',
  'denied_budget',
  'denied_guard',
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const cardValue = z.union([z.string(), z.number(), z.boolean(), z.null()]);

/** `CardSchema.report` (step AI-R): a report card carries its id, period and figures only. */
const reportCardSchema = z.object({
  reportId: z.string().regex(UUID),
  title: z.string().max(500),
  period: z.object({
    from: z.string(),
    to: z.string(),
    granularity: z.string(),
    atoRange: z.string().nullable(),
    label: z.string().max(200),
  }),
  generatedAt: z.string(),
  sizeBytes: z.number().int().nonnegative(),
  sections: z.array(z.string()),
  omitted: z.array(
    z.object({
      section: z.string(),
      reason: z.enum(['permission', 'not_enabled', 'unavailable', 'unexpected_response']),
      code: z.string().nullable().optional(),
    }),
  ),
  figures: z.array(z.object({ label: z.string(), value: z.string() })).max(50),
});

export const cardSchema = z
  .object({
    version: z.literal(CARD_VERSION),
    executionId: z.string(),
    tool: z.string(),
    title: z.string(),
    status: z.enum(['ok', 'error']),
    kind: z.enum(['table', 'kv', 'series', 'message', 'error', 'report']),
    columns: z.array(z.object({ key: z.string(), label: z.string() })).optional(),
    rows: z.array(z.record(z.string(), cardValue)).optional(),
    fields: z.array(z.object({ key: z.string(), label: z.string(), value: cardValue })).optional(),
    series: z
      .object({
        x: z.array(z.string()),
        series: z.array(z.object({ name: z.string(), values: z.array(z.number().nullable()) })),
      })
      .optional(),
    total: z.number().optional(),
    nextCursor: z.boolean().optional(),
    portalLinks: z.array(
      z.object({ label: z.string(), href: z.string(), ref: z.string().optional() }),
    ),
    refs: z.array(z.string()),
    truncated: z.boolean().optional(),
    message: z.string().optional(),
    error: z.object({ httpStatus: z.number(), code: z.string(), message: z.string() }).optional(),
    report: reportCardSchema.optional(),
  })
  .refine((card) => card.kind !== 'report' || card.report !== undefined, {
    message: 'A report card carries its report',
    path: ['report'],
  });

const confirmationSummarySchema = z.object({
  version: z.literal(CONFIRMATION_SUMMARY_VERSION),
  title: z.string(),
  action: z.string(),
  target: z.array(
    z.object({ label: z.string(), value: z.string(), untrusted: z.boolean().optional() }),
  ),
  changes: z.array(
    z.object({ label: z.string(), before: z.string().nullable().optional(), after: z.string() }),
  ),
  definition: z
    .object({
      direction: z.string(),
      priority: z.number(),
      rules: z.array(z.object({ id: z.string(), when: z.string(), actions: z.string() })),
    })
    .optional(),
  impact: z.array(z.string()),
  warnings: z.array(z.string()),
  reversible: z.boolean(),
  portalRoute: z.string().nullable(),
  request: z.object({ method: z.string(), path: z.string() }),
});

/** `ConfirmationView` (contracts §35.1); unknown keys are dropped, never the token. */
export const confirmationViewSchema = z.object({
  id,
  executionId: id,
  resultExecutionId: id.nullable(),
  conversationId: id,
  tool: z.string(),
  operationId: z.string(),
  risk: z.enum(['low', 'medium', 'high']),
  requiresReauth: z.boolean(),
  reauthFresh: z.boolean(),
  status: z.enum(['pending', 'executing', 'executed', 'failed', 'expired', 'cancelled']),
  summary: confirmationSummarySchema.nullable(),
  actionDigest: z.string().regex(/^[0-9a-f]{64}$/),
  expiresAt: z.string(),
  createdAt: z.string(),
  decidedAt: z.string().nullable(),
  executedAt: z.string().nullable(),
  result: z.object({ httpStatus: z.number().nullable(), error: z.string().nullable() }).nullable(),
});

/** The single-use confirmation token: 32 random bytes, base64url (43 characters). */
export const CONFIRMATION_TOKEN = /^[A-Za-z0-9_-]{43}$/;

/** A validated confirmation view, or null (malformed views are never rendered). */
export function parseConfirmationView(value: unknown): ConfirmationView | null {
  const parsed = confirmationViewSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

const eventSchemas = {
  'turn.started': z.object({ turnId: id, conversationId: id, seq: z.number() }),
  'text.delta': z.object({ text: z.string() }),
  'tool.started': z.object({ executionId: id, tool: z.string(), title: z.string() }),
  'tool.completed': z.object({
    executionId: id,
    status: z.enum(['succeeded', 'failed', 'refused', 'timeout', 'pending_confirmation']),
    decision,
    card: cardSchema,
  }),
  'confirmation.required': z.object({
    confirmation: confirmationViewSchema,
    token: z.string().regex(CONFIRMATION_TOKEN),
  }),
  'tool.denied': z.object({
    executionId: id,
    tool: z.string(),
    decision: decision.exclude(['allowed']),
    message: z.string(),
  }),
  'turn.completed': z.object({
    turnId: id,
    status: z.enum(['completed', 'cancelled']),
    usage: z.object({ inputTokens: z.number(), outputTokens: z.number() }),
    messageId: z.string(),
  }),
  'turn.failed': z.object({ turnId: z.string(), code: z.string(), message: z.string() }),
} as const;

/**
 * Validates one raw event: the known `assistant-stream/1` types only; anything else (an unknown
 * event of a later contract version, malformed JSON, a wrong shape) is `null` and skipped.
 */
export function parseStreamEvent(raw: RawSseEvent): AssistantStreamEvent | null {
  if (!Object.prototype.hasOwnProperty.call(eventSchemas, raw.event)) return null;
  const type = raw.event as keyof typeof eventSchemas;
  let json: unknown;
  try {
    json = JSON.parse(raw.data);
  } catch {
    return null;
  }
  const parsed = eventSchemas[type].safeParse(json);
  if (!parsed.success) return null;
  return { type, ...parsed.data } as AssistantStreamEvent;
}

/** The terminal state of a turn as the UI sees it. */
export type TurnOutcome =
  | { readonly kind: 'completed'; readonly turnId: string; readonly messageId: string | null }
  | { readonly kind: 'cancelled'; readonly turnId: string | null }
  | {
      readonly kind: 'failed';
      readonly turnId: string | null;
      readonly code: string;
      readonly message: string;
    };

/**
 * Events equivalent to the JSON answer of a turn (`{ turn, message, executions, confirmations }`):
 * a proposal's `tool.completed` is followed by its `confirmation.required` (token null on a
 * replay, when the api never repeats it).
 */
export function eventsFromTurnResult(result: TurnResult): AssistantStreamEvent[] {
  const { turn, message, executions } = result;
  const proposals = new Map<string, { confirmation: ConfirmationView; token: string | null }>();
  for (const entry of Array.isArray(result.confirmations) ? result.confirmations : []) {
    const confirmation = parseConfirmationView(entry?.confirmation);
    if (!confirmation) continue;
    const token =
      typeof entry.token === 'string' && CONFIRMATION_TOKEN.test(entry.token) ? entry.token : null;
    proposals.set(confirmation.executionId, { confirmation, token });
  }
  const events: AssistantStreamEvent[] = [
    { type: 'turn.started', turnId: turn.id, conversationId: turn.conversationId, seq: turn.seq },
  ];
  for (const execution of executions) {
    const card = execution.card ? cardSchema.safeParse(execution.card) : null;
    if (execution.decision !== 'allowed') {
      events.push({
        type: 'tool.denied',
        executionId: execution.id,
        tool: execution.tool,
        decision: execution.decision,
        message:
          (card?.success ? (card.data.message ?? card.data.error?.message) : undefined) ??
          execution.message ??
          execution.errorCode ??
          'The assistant could not use this tool.',
      });
    } else if (card?.success) {
      events.push({
        type: 'tool.completed',
        executionId: execution.id,
        status: execution.status,
        decision: execution.decision,
        card: card.data,
      });
      const proposal =
        execution.status === 'pending_confirmation'
          ? (proposals.get(execution.id) ??
            (execution.confirmation
              ? { confirmation: parseConfirmationView(execution.confirmation), token: null }
              : null))
          : null;
      if (proposal?.confirmation) {
        events.push({
          type: 'confirmation.required',
          confirmation: proposal.confirmation,
          token: proposal.token,
        });
      }
    }
  }
  if (message?.content) events.push({ type: 'text.delta', text: message.content });
  if (turn.status === 'failed') {
    events.push({
      type: 'turn.failed',
      turnId: turn.id,
      code: turn.errorCode ?? 'assistant_provider_error',
      message: 'The assistant could not complete this answer.',
    });
  } else {
    events.push({
      type: 'turn.completed',
      turnId: turn.id,
      status: turn.status === 'cancelled' ? 'cancelled' : 'completed',
      usage: { inputTokens: turn.usage.inputTokens, outputTokens: turn.usage.outputTokens },
      messageId: message?.id ?? '',
    });
  }
  return events;
}

export interface RunTurnInput {
  readonly conversationId: string;
  readonly clientTurnId: string;
  readonly message: string;
  readonly timeZone?: string;
}

export interface RunTurnOptions {
  readonly signal?: AbortSignal;
  readonly onEvent: (event: AssistantStreamEvent) => void;
  /** Injectable wait between JSON recovery attempts (tests). */
  readonly sleep?: (ms: number) => Promise<void>;
  /** Attempts of the JSON recovery while the api still runs the turn (`409`). */
  readonly recoveryAttempts?: number;
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function isEventStream(response: Response): boolean {
  return (response.headers.get('content-type') ?? '').toLowerCase().includes('text/event-stream');
}

function outcomeOf(event: AssistantStreamEvent): TurnOutcome | null {
  if (event.type === 'turn.completed') {
    return event.status === 'cancelled'
      ? { kind: 'cancelled', turnId: event.turnId }
      : { kind: 'completed', turnId: event.turnId, messageId: event.messageId || null };
  }
  if (event.type === 'turn.failed') {
    return { kind: 'failed', turnId: event.turnId, code: event.code, message: event.message };
  }
  return null;
}

async function readJson(response: Response): Promise<TurnResult> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new StreamProtocolError('invalid_response', 'The answer could not be read');
  }
  const value = body as Partial<TurnResult> | null;
  if (!value || typeof value !== 'object' || !value.turn || !Array.isArray(value.executions)) {
    throw new StreamProtocolError('invalid_response', 'The answer could not be read');
  }
  return value as TurnResult;
}

function emitAll(events: readonly AssistantStreamEvent[], onEvent: RunTurnOptions['onEvent']) {
  let outcome: TurnOutcome | null = null;
  for (const event of events) {
    onEvent(event);
    outcome = outcomeOf(event) ?? outcome;
  }
  return outcome;
}

/**
 * Runs one turn. Resolves with its outcome; rejects with an `ApiError` (the api refused the turn:
 * budget, rate limit, disabled, conflict) or the `AbortError` of `signal`. Every event reaches
 * `onEvent` in order. When the stream breaks after `turn.started`, the same `clientTurnId` is
 * POSTed again with `accept: application/json` and the stored turn is replayed as events.
 */
export async function runTurn(input: RunTurnInput, options: RunTurnOptions): Promise<TurnOutcome> {
  const { signal, onEvent } = options;
  const body = {
    clientTurnId: input.clientTurnId,
    message: input.message,
    ...(input.timeZone ? { timeZone: input.timeZone } : {}),
  };
  const call = (accept: string) =>
    openOperationStream(
      'AssistantTurnsController_create_v1',
      { path: { conversationId: input.conversationId }, body },
      { signal, accept },
    );

  const response = await call('text/event-stream, application/json;q=0.9');
  if (!isEventStream(response)) {
    const outcome = emitAll(eventsFromTurnResult(await readJson(response)), onEvent);
    if (!outcome) throw new StreamProtocolError('invalid_response', 'The answer was incomplete');
    return outcome;
  }

  // Assigned inside the parser callback; typed through a holder so control-flow narrowing does
  // not treat it as always null after the loop.
  const state: { outcome: TurnOutcome | null; started: boolean } = {
    outcome: null,
    started: false,
  };
  const parser = new SseParser((raw) => {
    const event = parseStreamEvent(raw);
    if (!event || state.outcome) return;
    if (event.type === 'turn.started') state.started = true;
    onEvent(event);
    state.outcome = outcomeOf(event);
  });
  try {
    if (!response.body) throw new StreamProtocolError('stream_ended', 'The answer was empty');
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    // Not every fetch implementation errors the body when its signal aborts: cancel the reader
    // so a pending read ends at once.
    const onAbort = () => void reader.cancel().catch(() => undefined);
    signal?.addEventListener('abort', onAbort, { once: true });
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done || signal?.aborted) break;
        parser.push(decoder.decode(value, { stream: true }));
        if (state.outcome) break;
      }
      if (!state.outcome && !signal?.aborted) {
        parser.push(decoder.decode());
        parser.end();
      }
    } finally {
      signal?.removeEventListener('abort', onAbort);
      if (state.outcome) void reader.cancel().catch(() => undefined);
      reader.releaseLock();
    }
  } catch (error) {
    if (signal?.aborted || isAbortError(error)) {
      throw signal?.aborted ? new DOMException('The turn was cancelled', 'AbortError') : error;
    }
    if (error instanceof StreamProtocolError && error.code === 'event_too_large') throw error;
    // A broken connection: recover from the stored turn below.
  }
  if (state.outcome) return state.outcome;
  if (signal?.aborted) throw new DOMException('The turn was cancelled', 'AbortError');
  if (!state.started)
    throw new StreamProtocolError('stream_ended', 'The answer ended unexpectedly');
  return recover(call, options);
}

/** JSON replay of a turn whose stream broke (same `clientTurnId`, contracts §35). */
async function recover(
  call: (accept: string) => Promise<Response>,
  options: RunTurnOptions,
): Promise<TurnOutcome> {
  const sleep = options.sleep ?? defaultSleep;
  const attempts = options.recoveryAttempts ?? 6;
  for (let attempt = 0; ; attempt += 1) {
    try {
      const result = await readJson(await call('application/json'));
      // The replay starts with `turn.started` again: the consumer resets the partial text and
      // tools of the broken stream and rebuilds the turn from the stored answer.
      const outcome = emitAll(eventsFromTurnResult(result), options.onEvent);
      if (outcome) return outcome;
      throw new StreamProtocolError('invalid_response', 'The answer was incomplete');
    } catch (error) {
      const inProgress =
        error instanceof ApiError &&
        error.status === 409 &&
        error.code === 'assistant_turn_in_progress';
      if (!inProgress || attempt + 1 >= attempts || options.signal?.aborted) throw error;
      await sleep(Math.min(2000 * (attempt + 1), 8000));
    }
  }
}
