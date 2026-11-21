import { HttpStatus, Inject, Injectable, Logger } from '@nestjs/common';
import {
  type ActionUpdate,
  buildActionUpdates,
  buildSystemPrompt,
  costMicros,
  describeTool,
  LlmError,
  type LlmResponse,
  type LlmToolCall,
  type LlmToolResult,
  META_TOOLS,
  parseMetaToolInput,
  planWindow,
  PROMPT_VERSION,
  type RecapExecution,
  REGISTRY_VERSION,
  renderCatalogueIndex,
  sanitizeText,
} from '@email-gateway/assistant';
import { uuidv7 } from '@email-gateway/common';
import { getCorrelationId } from '@email-gateway/logger';
import { API_CONFIG } from '../../../api-config.token';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../../database/transaction-runner';
import { CodedHttpException } from '../../../http/coded-exception';
import {
  ASSISTANT_TEXT_MAX_CHARS,
  type AssistantConfig,
  CONFIRMATION_REPORT_BATCH,
  DERIVED_TITLE_MAX_CHARS,
  TOOL_CALL_CONCURRENCY,
  TRANSCRIPT_MAX_BYTES,
} from '../assistant.constants';
import {
  assistantTurnInProgress,
  assistantTurnNotFound,
  TURN_FAILURE_CODES,
  TURN_FAILURE_MESSAGES,
  type TurnFailureCode,
} from '../assistant.errors';
import {
  availableTools,
  lookupTool,
  scopeOrganizationPublicId,
  toolAvailability,
} from '../domain/tool-catalog';
import { executionViews, messageView, turnView } from '../domain/views';
import type { CancelResultView, CreateTurnBody, TurnResultView } from '../dto/assistant.schemas';
import {
  type ConversationRow,
  ConversationsRepository,
  type Owner,
  type TurnRow,
} from '../repositories/conversations.repository';
import {
  ConfirmationsRepository,
  type UnreportedConfirmation,
} from '../repositories/confirmations.repository';
import { ExecutionsRepository } from '../repositories/executions.repository';
import { budgetTokens, UsageRepository } from '../repositories/usage.repository';
import { AssistantAvailabilityService } from './assistant-availability.service';
import { AssistantLimitsService } from './assistant-limits.service';
import { AssistantMetrics } from './assistant-metrics';
import { AssistantProviderService } from './assistant-provider.service';
import { ConfirmationViewsService } from './confirmation-views.service';
import { ConversationService, ownerOf } from './conversation.service';
import { LoopbackDispatcher } from './loopback-client';
import type { TurnSink } from './sse-writer';
import { type ExecutionContext, ToolExecutorService } from './tool-executor.service';

const DAY_MS = 86_400_000;
/** User messages and executions read for a recap (D7). */
const RECAP_MESSAGES = 10;
const RECAP_EXECUTIONS = 20;

/** The request facts a turn needs (from the incoming request, never from the model). */
export interface TurnRequest {
  authorization: string;
  clientIp: string | null;
}

/** A turn that passed every check and holds its lock and slot: ready to run. */
export interface PreparedTurn {
  kind: 'run';
  principal: UserPrincipal;
  scope: TenantScope;
  owner: Owner;
  conversation: ConversationRow;
  turn: TurnRow;
  body: CreateTurnBody;
  request: TurnRequest;
  correlationId: string;
  release: () => Promise<void>;
  /**
   * Tokens of this turn's write proposals by confirmation id (step AI-2 D1 step 10): kept in
   * memory for the JSON answer only, never stored, logged or given to the model.
   */
  confirmationTokens: Map<string, string>;
}

/** A retried `clientTurnId` of a finished turn: its stored result is replayed. */
export interface ReplayedTurn {
  kind: 'replay';
  result: TurnResultView;
}

type AbortReason = 'cancelled' | 'deadline';

class TurnFailure extends Error {
  constructor(
    readonly code: TurnFailureCode,
    readonly detail: string | null = null,
  ) {
    super(code);
  }
}

interface Usage {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
}

/** A title from the first user message (whitespace collapsed, controls stripped, capped). */
export function deriveTitle(message: string): string {
  return sanitizeText(message.replace(/\s+/g, ' ').trim(), DERIVED_TITLE_MAX_CHARS);
}

/** Runs `tasks` with at most `limit` in flight; results in input order. */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  task: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await task(items[index]!, index);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()));
  return results;
}

/** One-line result summary of a stored execution (recap; no record content). */
export function executionSummary(row: {
  decision: string;
  status: string;
  httpStatus: number | null;
  errorCode: string | null;
  resultCard: unknown;
}): string {
  if (row.decision !== 'allowed') return `denied ${row.decision}`;
  if (row.status !== 'succeeded') {
    return `error ${row.errorCode ?? row.status}${row.httpStatus ? ` (HTTP ${row.httpStatus})` : ''}`;
  }
  const card = row.resultCard as { kind?: string; rows?: unknown[]; nextCursor?: boolean } | null;
  if (card?.kind === 'table') {
    const count = Array.isArray(card.rows) ? card.rows.length : 0;
    return `ok, ${count} row${count === 1 ? '' : 's'}${card.nextCursor ? ', more available' : ''}`;
  }
  return card ? 'ok, 1 record' : 'ok, content purged';
}

/** Unreported terminal confirmations → the lines of the action updates (step AI-2 D6). */
export function actionUpdatesOf(rows: readonly UnreportedConfirmation[]): ActionUpdate[] {
  return rows.flatMap((row): ActionUpdate[] => {
    if (
      row.status !== 'executed' &&
      row.status !== 'failed' &&
      row.status !== 'cancelled' &&
      row.status !== 'expired'
    ) {
      return [];
    }
    return [
      {
        tool: row.toolName,
        callSeq: row.callSeq,
        status: row.status,
        httpStatus: row.resultHttpStatus,
        error: row.errorCode,
        resultSeq: row.resultSeq,
        resultRowRef: row.resultRowRef,
      },
    ];
  });
}

/**
 * The turn engine of the assistant (design D7, D4, D11, §4.2; ADR-0092, ADR-0094).
 *
 * `prepare` runs every check BEFORE any byte of the answer is written, so refusals are ordinary
 * coded JSON errors: the conversation (own, `404`), the message length (`413`), a retried
 * `clientTurnId` (completed → replay, running → `409 assistant_turn_in_progress`), availability
 * (platform switch, feature, tenant setting, breaker, budgets), the user's per-minute window, the
 * per-process concurrency slot and the conversation's turn lock; then one writer transaction
 * opens the turn (`running` + the user message).
 *
 * `run` streams `turn.started`, builds the context (`assistant-system/1` + the catalogue index of
 * the caller's enabled tools + the context block; the segment's native transcripts replayed
 * verbatim, or a recap when the window overflows), loops model rounds with `describe_tool` /
 * `call_tool` (parallel calls 4 at a time, results in call order) under the caps (rounds, tool
 * calls, output tokens, deadline), honours cancellation (client disconnect, cancel route, a
 * cross-pod flag) and closes the turn in one writer transaction (assistant message ≤ 16 000
 * characters, transcript ≤ 512 KiB, metrics, usage, conversation activity and title), then emits
 * `turn.completed` or `turn.failed`. Logs carry ids and codes only.
 */
@Injectable()
export class TurnEngineService {
  private readonly logger = new Logger(TurnEngineService.name);
  /** Running turns of this process (cancel route, client disconnect). */
  private readonly running = new Map<string, AbortController>();

  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    private readonly conversations: ConversationsRepository,
    private readonly executions: ExecutionsRepository,
    private readonly usage: UsageRepository,
    private readonly conversationService: ConversationService,
    private readonly availability: AssistantAvailabilityService,
    private readonly limits: AssistantLimitsService,
    private readonly provider: AssistantProviderService,
    private readonly executor: ToolExecutorService,
    private readonly loopback: LoopbackDispatcher,
    private readonly runner: TransactionRunner,
    private readonly metrics: AssistantMetrics,
    private readonly confirmations: ConfirmationsRepository,
    private readonly confirmationViews: ConfirmationViewsService,
  ) {}

  now(): Date {
    return new Date();
  }

  // ---- prepare -------------------------------------------------------------------------------

  async prepare(
    principal: UserPrincipal,
    scope: TenantScope,
    conversationPublicId: string,
    body: CreateTurnBody,
    request: TurnRequest,
  ): Promise<PreparedTurn | ReplayedTurn> {
    const owner = ownerOf(principal, scope);
    const conversation = await this.conversationService.load(
      principal,
      scope,
      conversationPublicId,
    );
    if (body.message.length > this.config.ASSISTANT_USER_MESSAGE_MAX_CHARS) {
      throw new CodedHttpException(
        HttpStatus.PAYLOAD_TOO_LARGE,
        'payload_too_large',
        `The message is longer than ${this.config.ASSISTANT_USER_MESSAGE_MAX_CHARS} characters`,
        { limit: this.config.ASSISTANT_USER_MESSAGE_MAX_CHARS },
      );
    }
    const replay = await this.replayIfKnown(principal, owner, conversation, body.clientTurnId);
    if (replay) return replay;

    const now = this.now();
    await this.availability.assertAvailable(scope, now, true);
    await this.limits.consumeUserWindow(principal.userPublicId, now);
    const releaseSlot = this.limits.acquireSlot();
    const turnPublicId = uuidv7();
    let locked = false;
    try {
      locked = await this.limits.acquireLock(conversation.publicId, turnPublicId);
      if (!locked) throw assistantTurnInProgress();
      const correlationId = (getCorrelationId() ?? turnPublicId).slice(0, 128);
      const retention = await this.conversationService.retentionDays(scope);
      const turn = await this.runner.run((tx) =>
        this.conversations.startTurn(
          owner,
          conversation,
          {
            publicId: turnPublicId,
            seq: conversation.turnCount + 1,
            segment: conversation.segment,
            clientTurnId: body.clientTurnId,
            provider: this.provider.providerId,
            model: this.provider.model,
            promptVersion: PROMPT_VERSION,
            registryVersion: REGISTRY_VERSION,
            correlationId,
            startedAt: now,
            userMessagePublicId: uuidv7(),
            userMessage: body.message,
            purgeAfter: new Date(now.getTime() + retention * DAY_MS),
          },
          tx,
        ),
      );
      if (!turn) {
        // A racing retry of the same clientTurnId (or a turn of another pod) got there first.
        const raced = await this.replayIfKnown(principal, owner, conversation, body.clientTurnId);
        if (raced) {
          await this.limits.releaseLock(conversation.publicId, turnPublicId);
          releaseSlot();
          return raced;
        }
        throw assistantTurnInProgress();
      }
      const controller = new AbortController();
      this.running.set(turn.publicId, controller);
      let released = false;
      return {
        kind: 'run',
        principal,
        scope,
        owner,
        conversation,
        turn,
        body,
        request,
        correlationId,
        confirmationTokens: new Map(),
        release: async () => {
          if (released) return;
          released = true;
          this.running.delete(turn.publicId);
          releaseSlot();
          await this.limits
            .releaseLock(conversation.publicId, turnPublicId)
            .catch((err: unknown) =>
              this.logger.warn({ message: 'Turn lock release failed', turnId: turn.publicId, err }),
            );
        },
      };
    } catch (error) {
      if (locked)
        await this.limits.releaseLock(conversation.publicId, turnPublicId).catch(() => undefined);
      releaseSlot();
      throw error;
    }
  }

  private async replayIfKnown(
    principal: UserPrincipal,
    owner: Owner,
    conversation: ConversationRow,
    clientTurnId: string,
  ): Promise<ReplayedTurn | null> {
    const existing = await this.conversations.findTurnByClientId(
      conversation.id,
      owner.scope.organizationId,
      clientTurnId,
    );
    if (!existing) return null;
    if (existing.status === 'running') throw assistantTurnInProgress();
    return {
      kind: 'replay',
      result: await this.result(principal, owner, conversation.publicId, existing),
    };
  }

  /**
   * The JSON answer `{ turn, message, executions, confirmations }` of a stored turn. Tokens come
   * from `tokens` (the turn that just ran in this request); a replay has none (`token: null`).
   */
  async result(
    principal: UserPrincipal,
    owner: Owner,
    conversationPublicId: string,
    turn: TurnRow,
    tokens: ReadonlyMap<string, string> = new Map(),
  ): Promise<TurnResultView> {
    const [messages, all] = await Promise.all([
      this.conversations.turnMessages(owner, turn.id),
      this.executions.forTurns(owner, turn.conversationId, [turn.id]),
    ]);
    const executions = all.filter((e) => e.turnId === turn.id);
    const confirmations = await this.confirmationViews.forExecutions(
      principal,
      owner,
      executions.filter((e) => e.status === 'pending_confirmation').map((e) => e.id),
    );
    const answer = messages.find((m) => m.role === 'assistant') ?? null;
    return {
      turn: turnView(turn, conversationPublicId),
      message: answer ? messageView(answer, turn.publicId) : null,
      executions: executionViews(executions, confirmations),
      confirmations: executions.flatMap((e) => {
        const confirmation = confirmations.get(e.id);
        return confirmation ? [{ confirmation, token: tokens.get(confirmation.id) ?? null }] : [];
      }),
    };
  }

  /** Re-emits a stored turn as `assistant-stream/1` events (SSE replay of a clientTurnId). */
  replayEvents(result: TurnResultView, sink: TurnSink): void {
    sink.emit({
      type: 'turn.started',
      turnId: result.turn.id,
      conversationId: result.turn.conversationId,
      seq: result.turn.seq,
    });
    for (const execution of result.executions) {
      sink.emit({
        type: 'tool.started',
        executionId: execution.id,
        tool: execution.tool,
        title: execution.card?.title ?? execution.tool,
      });
      if (execution.decision !== 'allowed') {
        sink.emit({
          type: 'tool.denied',
          executionId: execution.id,
          tool: execution.tool,
          decision: execution.decision,
          message: execution.errorCode ?? execution.decision,
        });
      } else if (execution.card) {
        sink.emit({
          type: 'tool.completed',
          executionId: execution.id,
          status: execution.status,
          decision: 'allowed',
          card: execution.card,
        });
      }
    }
    if (result.message?.content) sink.emit({ type: 'text.delta', text: result.message.content });
    if (result.turn.status === 'failed') {
      const code = (result.turn.errorCode ?? TURN_FAILURE_CODES.internalError) as TurnFailureCode;
      sink.emit({
        type: 'turn.failed',
        turnId: result.turn.id,
        code,
        message: TURN_FAILURE_MESSAGES[code] ?? TURN_FAILURE_MESSAGES.assistant_internal_error,
      });
    } else {
      sink.emit({
        type: 'turn.completed',
        turnId: result.turn.id,
        status: result.turn.status === 'cancelled' ? 'cancelled' : 'completed',
        usage: {
          inputTokens: result.turn.usage.inputTokens,
          outputTokens: result.turn.usage.outputTokens,
        },
        messageId: result.message?.id ?? '',
      });
    }
  }

  // ---- cancel --------------------------------------------------------------------------------

  /** `POST /assistant/turns/{turnId}/cancel`: the caller's own turn; idempotent. */
  async cancel(
    principal: UserPrincipal,
    scope: TenantScope,
    turnPublicId: string,
  ): Promise<CancelResultView> {
    const turn = await this.conversations.findOwnedTurn(ownerOf(principal, scope), turnPublicId);
    if (!turn) throw assistantTurnNotFound();
    if (turn.status === 'running') {
      await this.limits.requestCancel(turn.publicId);
      this.running.get(turn.publicId)?.abort('cancelled' satisfies AbortReason);
    }
    return { turnId: turn.publicId, status: turn.status };
  }

  /** Aborts a running turn of this process (client disconnect). */
  abort(turnPublicId: string): void {
    this.running.get(turnPublicId)?.abort('cancelled' satisfies AbortReason);
  }

  // ---- run -----------------------------------------------------------------------------------

  /**
   * Runs a prepared turn to its end, emitting events into `sink`. Never throws: every failure
   * becomes `turn.failed` and a stored error code. Releases the lock and the slot.
   */
  async run(prepared: PreparedTurn, sink: TurnSink): Promise<void> {
    const { turn, conversation, principal } = prepared;
    const startedAt = Date.now();
    const controller = this.running.get(turn.publicId) ?? new AbortController();
    const deadline = setTimeout(
      () => controller.abort('deadline' satisfies AbortReason),
      this.config.ASSISTANT_TURN_DEADLINE_MS,
    );
    deadline.unref();
    const signal = controller.signal;
    sink.emit({
      type: 'turn.started',
      turnId: turn.publicId,
      conversationId: conversation.publicId,
      seq: turn.seq,
    });

    const usage: Usage = {
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    };
    const state = {
      text: '',
      rounds: 0,
      toolCalls: 0,
      responseModel: null as string | null,
      appended: [] as unknown[],
      segment: conversation.segment,
      newSegment: false,
      separate: false,
      reported: [] as bigint[],
    };
    let status: 'completed' | 'failed' | 'cancelled' = 'completed';
    let failure: TurnFailure | null = null;
    try {
      await this.loop(prepared, sink, signal, usage, state);
    } catch (error: unknown) {
      const reason = signal.aborted ? (signal.reason as AbortReason) : null;
      if (reason === 'cancelled') status = 'cancelled';
      else {
        status = 'failed';
        failure = this.failureOf(error, reason);
      }
    } finally {
      clearTimeout(deadline);
    }

    const finishedAt = this.now();
    const assistantMessageId = uuidv7();
    try {
      await this.finish(prepared, {
        status,
        failure,
        usage,
        state,
        finishedAt,
        latencyMs: Date.now() - startedAt,
        assistantMessageId,
      });
    } catch (error: unknown) {
      this.logger.error({ message: 'Turn could not be closed', turnId: turn.publicId, err: error });
      status = 'failed';
      failure = new TurnFailure(TURN_FAILURE_CODES.internalError);
    }
    await prepared.release();

    const labels = { provider: this.provider.providerId, model: this.provider.model };
    this.metrics.turns.inc({
      ...labels,
      outcome: failure?.code === TURN_FAILURE_CODES.refused ? 'refused' : status,
    });
    this.metrics.turnSeconds.observe((Date.now() - startedAt) / 1000);
    this.logger.log({
      message: 'Assistant turn finished',
      turnId: turn.publicId,
      conversationId: conversation.publicId,
      status,
      code: failure?.code ?? null,
      rounds: state.rounds,
      toolCalls: state.toolCalls,
      userId: principal.userPublicId,
    });
    if (status === 'failed') {
      const code = failure?.code ?? TURN_FAILURE_CODES.internalError;
      sink.emit({
        type: 'turn.failed',
        turnId: turn.publicId,
        code,
        message:
          code === TURN_FAILURE_CODES.refused && failure?.detail
            ? `${TURN_FAILURE_MESSAGES[code]} (${failure.detail})`
            : TURN_FAILURE_MESSAGES[code],
      });
    } else {
      sink.emit({
        type: 'turn.completed',
        turnId: turn.publicId,
        status,
        usage: { inputTokens: usage.inputTokens, outputTokens: usage.outputTokens },
        messageId: assistantMessageId,
      });
    }
  }

  private failureOf(error: unknown, reason: AbortReason | null): TurnFailure {
    if (error instanceof TurnFailure) return error;
    if (reason === 'deadline') return new TurnFailure(TURN_FAILURE_CODES.turnLimit);
    if (error instanceof LlmError) {
      if (error.reason === 'refusal')
        return new TurnFailure(TURN_FAILURE_CODES.refused, error.category);
      return new TurnFailure(TURN_FAILURE_CODES.providerError);
    }
    this.logger.error({ message: 'Assistant turn failed unexpectedly', err: error });
    return new TurnFailure(TURN_FAILURE_CODES.internalError);
  }

  private async checkCancelled(turnPublicId: string, controller: AbortSignal): Promise<void> {
    if (controller.aborted) throw new TurnFailure(TURN_FAILURE_CODES.turnLimit);
    if (await this.limits.cancelRequested(turnPublicId)) {
      this.abort(turnPublicId);
      throw new TurnFailure(TURN_FAILURE_CODES.turnLimit);
    }
  }

  private async loop(
    prepared: PreparedTurn,
    sink: TurnSink,
    signal: AbortSignal,
    usage: Usage,
    state: {
      text: string;
      rounds: number;
      toolCalls: number;
      responseModel: string | null;
      appended: unknown[];
      segment: number;
      newSegment: boolean;
      separate: boolean;
      reported: bigint[];
    },
  ): Promise<void> {
    const { principal, owner, conversation, turn, body, request, correlationId } = prepared;
    const provider = this.provider.provider();

    // Context (D7): the caller's name, organization and roles through the api itself.
    const me = await this.loopback.send({
      method: 'GET',
      path: '/api/v1/auth/me',
      authorization: request.authorization,
      correlationId: `${correlationId.slice(0, 126)}.0`,
      clientIp: request.clientIp,
      executionId: null,
      signal,
    });
    if (me.kind === 'response' && me.status === 401) {
      throw new TurnFailure(TURN_FAILURE_CODES.sessionExpired);
    }
    if (me.kind === 'aborted') throw new TurnFailure(TURN_FAILURE_CODES.turnLimit);
    const profile = me.kind === 'response' && me.status === 200 ? (me.body as Profile) : null;
    const tools = availableTools(principal);
    const system = buildSystemPrompt({
      organization: principal.override
        ? {
            name: 'Organization under platform override',
            publicId: scopeOrganizationPublicId(principal),
          }
        : {
            name: profile?.organization?.name ?? 'Your organization',
            publicId: principal.organizationPublicId,
          },
      user: { displayName: profile?.user?.displayName ?? 'User' },
      roles: Array.isArray(profile?.roles)
        ? profile.roles.filter((r) => typeof r === 'string')
        : [],
      now: this.now(),
      timeZone: body.timeZone ?? null,
      registryVersion: REGISTRY_VERSION,
      catalogueIndex: renderCatalogueIndex(tools),
    });

    // Window (D7): replay the segment verbatim, or open a new one with a recap.
    const segmentRows = await this.conversations.segmentTranscripts(
      owner,
      conversation.id,
      conversation.segment,
    );
    const segmentTranscript = segmentRows.flatMap((row) => parseTranscript(row.providerTranscript));
    const recapNeeded = segmentTranscript.length > 0;
    // Step AI-2 D6: outcomes of confirmations since the last turn, prefixed to the user entry
    // (server-authored; `ai_chat_messages.content` keeps the user's text only). They are marked
    // reported when this turn completes (its transcript is what the model keeps).
    const unreported = await this.confirmations.unreported(
      owner,
      conversation.id,
      CONFIRMATION_REPORT_BATCH,
    );
    state.reported = unreported.map((row) => row.id);
    const actionUpdates = buildActionUpdates(actionUpdatesOf(unreported));
    const plan = planWindow({
      system: system.text,
      segmentTranscript,
      userMessage: body.message,
      actionUpdates: actionUpdates || null,
      maxTokens: this.config.ASSISTANT_CONTEXT_MAX_TOKENS,
      userEntry: (text) => provider.userEntry(text),
      recap: recapNeeded
        ? await this.recapInput(owner, conversation.id)
        : { userMessages: [], executions: [] },
    });
    if (plan.newSegment) {
      state.newSegment = true;
      state.segment = conversation.segment + 1;
    }
    const transcript = [...plan.transcript];
    state.appended.push(...plan.appended);

    let nextSeq = await this.executions.nextSeq(owner, conversation.id);
    const ctx: ExecutionContext = {
      principal,
      owner,
      conversationId: conversation.id,
      conversationPublicId: conversation.publicId,
      turnId: turn.id,
      turnPublicId: turn.publicId,
      parentExecutionId: null,
      parentExecutionPublicId: null,
      authorization: request.authorization,
      clientIp: request.clientIp,
      correlationBase: correlationId,
      signal,
      allocateSeq: () => nextSeq++,
    };

    const onDelta = (text: string): void => {
      if (text.length === 0) return;
      // Texts of two rounds are separated by a blank line (only when both have text).
      if (state.separate) {
        state.separate = false;
        state.text += '\n\n';
        sink.emit({ type: 'text.delta', text: '\n\n' });
      }
      state.text += text;
      sink.emit({ type: 'text.delta', text });
    };

    let pauses = 0;
    for (;;) {
      await this.checkCancelled(turn.publicId, signal);
      if (state.rounds >= this.config.ASSISTANT_MAX_TOOL_ROUNDS) {
        throw new TurnFailure(TURN_FAILURE_CODES.turnLimit);
      }
      const remaining = this.config.ASSISTANT_MAX_OUTPUT_TOKENS - usage.outputTokens;
      if (remaining <= 0) throw new TurnFailure(TURN_FAILURE_CODES.turnLimit);
      state.separate = state.text.length > 0;
      state.rounds += 1;
      const response: LlmResponse = await this.provider.complete(
        {
          system: system.text,
          transcript: [...transcript],
          tools: META_TOOLS,
          maxOutputTokens: remaining,
        },
        signal,
        onDelta,
      );
      usage.inputTokens += response.usage.inputTokens;
      usage.outputTokens += response.usage.outputTokens;
      usage.cacheReadTokens += response.usage.cacheReadTokens;
      usage.cacheWriteTokens += response.usage.cacheWriteTokens;
      state.responseModel = response.responseModel || state.responseModel;
      transcript.push(...response.appendToTranscript);
      state.appended.push(...response.appendToTranscript);

      if (response.stop === 'refusal') {
        throw new TurnFailure(TURN_FAILURE_CODES.refused, response.refusalCategory ?? null);
      }
      if (response.stop === 'pause_turn') {
        pauses += 1;
        if (pauses > 1) throw new TurnFailure(TURN_FAILURE_CODES.turnLimit);
        continue;
      }
      if (response.stop === 'tool_use' && response.toolCalls.length > 0) {
        if (state.rounds >= this.config.ASSISTANT_MAX_TOOL_ROUNDS) {
          throw new TurnFailure(TURN_FAILURE_CODES.turnLimit);
        }
        await this.checkCancelled(turn.publicId, signal);
        const results = await this.runToolCalls(
          ctx,
          response.toolCalls,
          sink,
          state,
          prepared.confirmationTokens,
        );
        if (signal.aborted) throw new TurnFailure(TURN_FAILURE_CODES.turnLimit);
        if (results.sessionExpired) throw new TurnFailure(TURN_FAILURE_CODES.sessionExpired);
        const entries = provider.toolResultEntries(results.results);
        transcript.push(...entries);
        state.appended.push(...entries);
        continue;
      }
      return;
    }
  }

  private async recapInput(
    owner: Owner,
    conversationId: bigint,
  ): Promise<{ userMessages: string[]; executions: RecapExecution[] }> {
    const [userMessages, rows] = await Promise.all([
      this.conversations.recentUserMessages(owner, conversationId, RECAP_MESSAGES),
      this.executions.recapRows(owner, conversationId, RECAP_EXECUTIONS),
    ]);
    return {
      userMessages,
      executions: rows.map((row) => ({
        refSeq: row.seq,
        tool: row.toolName,
        summary: executionSummary(row),
        validRefs:
          row.resultRefs !== null &&
          typeof row.resultRefs === 'object' &&
          !Array.isArray(row.resultRefs)
            ? Object.keys(row.resultRefs as Record<string, unknown>)
            : [],
      })),
    };
  }

  /** Answers one model response's tool calls (D4, D5): 4 at a time, results in call order. */
  private async runToolCalls(
    ctx: ExecutionContext,
    calls: readonly LlmToolCall[],
    sink: TurnSink,
    state: { toolCalls: number },
    tokens: Map<string, string>,
  ): Promise<{ results: LlmToolResult[]; sessionExpired: boolean }> {
    // Call indexes are assigned in call order before anything runs (the per-turn cap).
    const indexes = calls.map((call) => (call.name === 'call_tool' ? state.toolCalls++ : -1));
    let sessionExpired = false;
    const results = await mapWithConcurrency(calls, TOOL_CALL_CONCURRENCY, async (call, i) => {
      const content = await this.answerCall(ctx, call, indexes[i]!, sink, tokens);
      if (content.sessionExpired) sessionExpired = true;
      return { toolCallId: call.id, content: content.content, isError: content.isError };
    });
    return { results, sessionExpired };
  }

  private async answerCall(
    ctx: ExecutionContext,
    call: LlmToolCall,
    callIndex: number,
    sink: TurnSink,
    tokens: Map<string, string>,
  ): Promise<{ content: string; isError: boolean; sessionExpired: boolean }> {
    const error = (code: string, message: string) => ({
      content: JSON.stringify({ kind: 'tool_result/1', status: 'error', code, message }),
      isError: true,
      sessionExpired: false,
    });
    if (call.name === 'describe_tool') {
      const parsed = parseMetaToolInput('describe_tool', call.input);
      if (!parsed.ok) return error('invalid_meta_tool', 'describe_tool needs { "name": "<tool>" }');
      const found = lookupTool(parsed.name);
      if (found.kind === 'unknown')
        return error('denied_unknown_tool', 'There is no tool with this name.');
      if (found.kind === 'not_applicable') {
        return {
          content: JSON.stringify({
            name: parsed.name,
            available: false,
            unavailableReason: 'not_applicable',
            reason: found.operation.reason,
            portalRoute: found.operation.portalRoute,
          }),
          isError: false,
          sessionExpired: false,
        };
      }
      const availability = toolAvailability(ctx.principal, found.tool);
      return {
        content: JSON.stringify(
          describeTool(
            found.tool,
            availability.available
              ? { available: true }
              : { available: false, reason: availability.reason },
          ),
        ),
        isError: false,
        sessionExpired: false,
      };
    }
    if (call.name !== 'call_tool') {
      return error('invalid_meta_tool', 'Only describe_tool and call_tool exist.');
    }
    const parsed = parseMetaToolInput('call_tool', call.input);
    const input = call.input as { name?: unknown } | null;
    const name =
      parsed.ok && parsed.meta === 'call_tool'
        ? parsed.name
        : typeof input?.name === 'string'
          ? input.name
          : 'invalid';
    const outcome = await this.executor.execute(
      ctx,
      { name, arguments: parsed.ok && parsed.meta === 'call_tool' ? parsed.arguments : null },
      callIndex,
      (started) => sink.emit({ type: 'tool.started', ...started }),
    );
    if (outcome.decision === 'allowed' && outcome.card) {
      sink.emit({
        type: 'tool.completed',
        executionId: outcome.executionId,
        status: outcome.status,
        decision: 'allowed',
        card: outcome.card,
      });
      // Step AI-2 D1 step 10: the confirmation card's data and token, right after the proposal
      // (the browser only; the model's envelope has neither the token nor the digest).
      if (outcome.confirmation) {
        tokens.set(outcome.confirmation.view.id, outcome.confirmation.token);
        sink.emit({
          type: 'confirmation.required',
          confirmation: outcome.confirmation.view,
          token: outcome.confirmation.token,
        });
      }
    } else if (outcome.decision !== 'allowed') {
      sink.emit({
        type: 'tool.denied',
        executionId: outcome.executionId,
        tool: outcome.tool,
        decision: outcome.decision,
        message: outcome.denialMessage ?? outcome.decision,
      });
    }
    return {
      content: JSON.stringify(outcome.envelope),
      isError: outcome.envelope.status !== 'ok',
      sessionExpired: outcome.sessionExpired,
    };
  }

  // ---- finish --------------------------------------------------------------------------------

  private async finish(
    prepared: PreparedTurn,
    f: {
      status: 'completed' | 'failed' | 'cancelled';
      failure: TurnFailure | null;
      usage: Usage;
      state: {
        text: string;
        rounds: number;
        toolCalls: number;
        responseModel: string | null;
        appended: unknown[];
        segment: number;
        reported: bigint[];
      };
      finishedAt: Date;
      latencyMs: number;
      assistantMessageId: string;
    },
  ): Promise<void> {
    const { owner, scope, conversation, turn, body } = prepared;
    const text = f.state.text;
    const content =
      text.length > ASSISTANT_TEXT_MAX_CHARS ? text.slice(0, ASSISTANT_TEXT_MAX_CHARS) : text;
    let transcript: string | null = null;
    let conversationSegment = f.state.segment;
    if (f.status === 'completed') {
      const serialized = JSON.stringify(f.state.appended);
      if (Buffer.byteLength(serialized, 'utf8') <= TRANSCRIPT_MAX_BYTES) transcript = serialized;
      // Too large to replay: the next turn opens a new segment with a recap.
      else conversationSegment = f.state.segment + 1;
    }
    const pricedModel = f.state.responseModel ?? this.provider.model;
    const cost = costMicros(pricedModel, f.usage, this.provider.prices);
    const retention = await this.conversationService.retentionDays(scope);
    await this.runner.run(async (tx) => {
      const closed = await this.conversations.finishTurn(
        owner,
        turn,
        {
          status: f.status,
          segment: f.state.segment,
          conversationSegment,
          responseModel: f.state.responseModel?.slice(0, 128) ?? null,
          rounds: f.state.rounds,
          toolCalls: f.state.toolCalls,
          ...f.usage,
          costMicros: cost === null ? null : BigInt(cost),
          latencyMs: f.latencyMs,
          errorCode: f.failure?.code ?? null,
          providerTranscript: transcript,
          finishedAt: f.finishedAt,
          assistantMessage:
            f.status === 'failed' ? null : { publicId: f.assistantMessageId, content },
        },
        {
          lastTurnAt: f.finishedAt,
          purgeAfter: new Date(f.finishedAt.getTime() + retention * DAY_MS),
          title: conversation.title === null ? deriveTitle(body.message) || null : null,
        },
        tx,
      );
      if (!closed) throw new Error('turn is no longer running');
      // Step AI-2 D6: the action updates this turn's transcript carries are reported.
      if (f.status === 'completed' && f.state.reported.length > 0) {
        await this.confirmations.markReported(owner, f.state.reported, f.finishedAt, tx);
      }
      await this.usage.add(
        scope,
        {
          day: f.finishedAt,
          provider: this.provider.providerId,
          model: this.provider.model,
          inputTokens: f.usage.inputTokens,
          outputTokens: f.usage.outputTokens,
          cacheReadTokens: f.usage.cacheReadTokens,
          cacheWriteTokens: f.usage.cacheWriteTokens,
          costMicros: cost ?? 0,
        },
        tx,
      );
    });
    await this.limits
      .recordTokens(scope.organizationId, budgetTokens(f.usage), f.finishedAt)
      .catch((err: unknown) =>
        this.logger.warn({ message: 'Token counter update failed', turnId: turn.publicId, err }),
      );
  }

  /** The stored turn after `run` (JSON answers). */
  async stored(prepared: PreparedTurn): Promise<TurnResultView> {
    const turn = await this.conversations.findTurn(prepared.owner, prepared.turn.id);
    return this.result(
      prepared.principal,
      prepared.owner,
      prepared.conversation.publicId,
      turn ?? prepared.turn,
      prepared.confirmationTokens,
    );
  }
}

interface Profile {
  user?: { displayName?: string };
  organization?: { name?: string };
  roles?: unknown[];
}

/** A stored native transcript (JSON array); anything else replays as nothing. */
function parseTranscript(value: string | null): unknown[] {
  if (value === null) return [];
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}
