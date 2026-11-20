import { Body, Controller, Get, HttpCode, HttpStatus, Param, Post, Req, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { Request, Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { RateClass } from '../../../rate-limit/rate-class.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ApiAssistantForbidden,
  ApiAssistantGates,
  ApiAssistantResponse,
  ApiAssistantUnavailable,
  ApiConversationIdParam,
  ApiConversationNotFound,
  ApiExecutionIdParam,
  ApiExecutionNotFound,
  ApiTurnIdParam,
  USER_ONLY_RULE,
} from '../api-docs';
import { ASSISTANT_PERMISSIONS as P } from '../assistant.constants';
import { ASSISTANT_ERROR_CODES as C } from '../assistant.errors';
import {
  ASSISTANT_EXAMPLES as X,
  type CancelResultView,
  CancelResultSchema,
  type CreateTurnBody,
  CreateTurnBodySchema,
  ExecutionSchema,
  type ExecutionView,
  PublicIdSchema,
  TurnResultSchema,
} from '../dto/assistant.schemas';
import { ExecutionsService } from '../services/executions.service';
import { NULL_SINK, SseWriter, wantsEventStream } from '../services/sse-writer';
import { type TurnRequest, TurnEngineService } from '../services/turn-engine.service';
import { userOf } from './assistant.controller';

const publicId = new ZodValidationPipe(PublicIdSchema);

/** The turn request's own credential and client address (never from the model, D2). */
function turnRequestOf(req: Request, client: ClientContext): TurnRequest {
  const header = req.headers.authorization;
  return { authorization: typeof header === 'string' ? header : '', clientIp: client.ip };
}

/** An AbortSignal that fires when the client goes away before the answer is complete. */
function disconnectSignal(res: Response): { signal: AbortSignal; dispose: () => void } {
  const controller = new AbortController();
  const onClose = (): void => {
    if (!res.writableFinished) controller.abort();
  };
  res.on('close', onClose);
  return { signal: controller.signal, dispose: () => res.off('close', onClose) };
}

const STREAM_DESCRIPTION =
  'With `accept: text/event-stream` the answer is `assistant-stream/1` (Server-Sent Events: ' +
  '`event:` name + one `data:` JSON line; a `: heartbeat` comment every 15 s): `turn.started ' +
  '{ turnId, conversationId, seq }` (flushed before the first model call), then any ' +
  'interleaving of `text.delta { text }`, `tool.started { executionId, tool, title }`, ' +
  '`tool.completed { executionId, status, decision, card }` and `tool.denied { executionId, ' +
  'tool, decision, message }`, then exactly one of `turn.completed { turnId, status, usage: { ' +
  'inputTokens, outputTokens }, messageId }` or `turn.failed { turnId, code, message }` (codes ' +
  '`assistant_session_expired`, `assistant_turn_limit`, `assistant_refused`, ' +
  '`assistant_provider_error`, `assistant_internal_error`). Headers `cache-control: no-store` ' +
  'and `x-accel-buffering: no`. Otherwise the JSON `{ turn, message, executions }` after the ' +
  'turn ended.';

/** Turns: ask, stream the answer, cancel (step AI-1 D7, §4.1, §4.2). */
@ApiTags('assistant')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'assistant', version: '1' })
export class AssistantTurnsController {
  constructor(private readonly turns: TurnEngineService) {}

  @Post('conversations/:conversationId/turns')
  @RequirePermissions(P.use)
  @RateClass('expensive')
  @HttpCode(HttpStatus.OK)
  @ApiConversationIdParam()
  @ApiOperation({
    summary: 'Ask the AI assistant',
    description:
      'Runs one turn: your `message` (1..ASSISTANT_USER_MESSAGE_MAX_CHARS characters, `413 ' +
      'payload_too_large` beyond) goes to the configured AI provider with the catalogue of the ' +
      'tools you may use; the model may call tools, each one existing `/api/v1` operation ' +
      'executed with YOUR credential through the api’s own pipeline (same permissions, tenant, ' +
      'MFA, rate limits and audit as the portal; only reads in AI-1), recorded and audited ' +
      '(`assistant.tool_executed` / `assistant.tool_denied`). Limits per turn: ' +
      'ASSISTANT_MAX_TOOL_ROUNDS model calls, ASSISTANT_MAX_TOOL_CALLS_PER_TURN tool calls, ' +
      'ASSISTANT_MAX_OUTPUT_TOKENS output tokens, ASSISTANT_TURN_DEADLINE_MS. Refusals before ' +
      'the answer starts are JSON errors: availability (`503 assistant_disabled`, `403 ' +
      'assistant_not_enabled`, `403 assistant_tenant_disabled`, `503 ' +
      'assistant_provider_unavailable`, `429 assistant_budget_exhausted` with `scope`), ' +
      'ASSISTANT_TURNS_PER_USER_PER_MINUTE (`429 rate_limited`), the per-process concurrency ' +
      '(`503 assistant_busy`) and one running turn per conversation (`409 ' +
      'assistant_turn_in_progress`). The same `clientTurnId` again replays a finished turn ' +
      '(`409` while it runs). Rate class `expensive`. ' +
      STREAM_DESCRIPTION +
      USER_ONLY_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(CreateTurnBodySchema, { io: 'input' }),
    examples: { ask: { value: X.turnCreate } },
  })
  @ApiResponse({
    status: 200,
    description: 'The finished turn (JSON) or the event stream (`text/event-stream`)',
    headers: {
      'Cache-Control': {
        description: '`no-store`',
        schema: { type: 'string', enum: ['no-store'] },
      },
    },
    content: {
      'application/json': {
        schema: { ...zodToOpenApi(TurnResultSchema), example: X.turnResult },
      },
      'text/event-stream': {
        schema: {
          type: 'string',
          description: 'assistant-stream/1 events',
          example:
            'event: turn.started\ndata: {"turnId":"…","conversationId":"…","seq":1}\n\n' +
            'event: text.delta\ndata: {"text":"You have 1 active policy."}\n\n' +
            'event: turn.completed\ndata: {"turnId":"…","status":"completed","usage":{"inputTokens":5120,"outputTokens":240},"messageId":"…"}\n\n',
        },
      },
    },
  })
  @ApiConversationNotFound()
  @ApiAssistantGates()
  @ApiCodedError(
    409,
    'Another turn runs in this conversation, or this `clientTurnId` is still running',
    [C.turnInProgress],
  )
  @ApiCodedError(
    413,
    'The message is longer than ASSISTANT_USER_MESSAGE_MAX_CHARS',
    ['payload_too_large'],
    { limit: { type: 'integer' } },
  )
  @ApiCodedError(
    429,
    'Too many turns this minute (`rate_limited`, `scope: route` or a rate-class scope) or the ' +
      'daily token budget is used up (`assistant_budget_exhausted`, `scope: tenant | platform`)',
    ['rate_limited', C.budgetExhausted],
    { scope: { type: 'string' } },
  )
  @ApiAssistantUnavailable(
    [C.disabled, C.providerUnavailable, C.busy],
    'the assistant is off on this platform (`assistant_disabled`), the provider is unavailable ' +
      '(`assistant_provider_unavailable`) or this api process is busy (`assistant_busy`)',
  )
  async create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('conversationId', publicId) conversationId: string,
    @Body(new ZodValidationPipe(CreateTurnBodySchema)) body: CreateTurnBody,
    @Client() client: ClientContext,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    // Every check (and the lock) happens here, before a byte of the answer is written.
    const prepared = await this.turns.prepare(
      userOf(principal),
      scope,
      conversationId,
      body,
      turnRequestOf(req, client),
    );
    const stream = wantsEventStream(req.headers.accept);
    if (prepared.kind === 'replay') {
      if (!stream) {
        res.status(HttpStatus.OK).json(prepared.result);
        return;
      }
      const sse = new SseWriter(res);
      sse.start();
      this.turns.replayEvents(prepared.result, sse);
      sse.end();
      return;
    }
    const onClose = (): void => {
      if (!res.writableFinished) this.turns.abort(prepared.turn.publicId);
    };
    res.on('close', onClose);
    try {
      if (stream) {
        const sse = new SseWriter(res);
        try {
          sse.start();
          await this.turns.run(prepared, sse);
        } finally {
          sse.end();
        }
        return;
      }
      await this.turns.run(prepared, NULL_SINK);
      res.status(HttpStatus.OK).json(await this.turns.stored(prepared));
    } finally {
      res.off('close', onClose);
      await prepared.release();
    }
  }

  @Post('turns/:turnId/cancel')
  @RequirePermissions(P.use)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiTurnIdParam()
  @ApiOperation({
    summary: 'Cancel a running assistant turn',
    description:
      'Stops one of your own running turns: the model call and pending tool calls are aborted ' +
      'and the turn ends `cancelled` with the partial text. Idempotent: a finished turn answers ' +
      'with its status. Another user’s or organization’s turn answers `404`.' +
      USER_ONLY_RULE,
  })
  @ApiAssistantResponse(202, CancelResultSchema, X.cancel, 'Cancellation requested')
  @ApiCodedError(404, 'Unknown turn, or one of another user or organization', [C.turnNotFound])
  @ApiAssistantForbidden()
  @ApiAssistantUnavailable()
  cancel(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('turnId', publicId) turnId: string,
  ): Promise<CancelResultView> {
    return this.turns.cancel(userOf(principal), scope, turnId);
  }
}

/** Stored tool executions and their next pages (step AI-1 §4.1). */
@ApiTags('assistant')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'assistant/executions', version: '1' })
export class AssistantExecutionsController {
  constructor(private readonly executions: ExecutionsService) {}

  @Get(':executionId')
  @RequirePermissions(P.use)
  @ApiExecutionIdParam()
  @ApiOperation({
    summary: 'Get an assistant tool execution',
    description:
      'One tool execution of your own conversations: tool, operation, decision, status, HTTP ' +
      'status, error code and the result card (`assistant-card/1`; null for refused calls and ' +
      'after the content purge).' +
      USER_ONLY_RULE,
  })
  @ApiAssistantResponse(200, ExecutionSchema, X.execution, 'The execution')
  @ApiExecutionNotFound()
  @ApiAssistantForbidden()
  @ApiAssistantUnavailable()
  get(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('executionId', publicId) executionId: string,
  ): Promise<ExecutionView> {
    return this.executions.get(userOf(principal), scope, executionId);
  }

  @Post(':executionId/more')
  @RequirePermissions(P.use)
  @RateClass('expensive')
  @HttpCode(HttpStatus.OK)
  @ApiExecutionIdParam()
  @ApiOperation({
    summary: 'Load the next page of an assistant result',
    description:
      'The next page of a list execution WITHOUT a model call: the same tool with the stored ' +
      'parameters and the stored cursor goes through the same permission pre-filter, schema ' +
      'check and loopback as in a turn, recorded and audited as a new execution whose ' +
      '`parentExecutionId` is this one. `409 assistant_no_more_results` when the result has no ' +
      'next page (or its content was purged); `409 assistant_turn_in_progress` while a turn ' +
      'runs in the conversation. Rate class `expensive`.' +
      USER_ONLY_RULE,
  })
  @ApiAssistantResponse(200, ExecutionSchema, X.execution, 'The new execution with the next page')
  @ApiExecutionNotFound()
  @ApiAssistantGates()
  @ApiCodedError(409, 'No next page, or a turn runs in the conversation', [
    C.noMoreResults,
    C.turnInProgress,
  ])
  @ApiAssistantUnavailable(
    [C.disabled],
    'the assistant is off on this platform (`assistant_disabled`)',
  )
  async more(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('executionId', publicId) executionId: string,
    @Client() client: ClientContext,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ExecutionView> {
    const { signal, dispose } = disconnectSignal(res);
    try {
      return await this.executions.more(
        userOf(principal),
        scope,
        executionId,
        turnRequestOf(req, client),
        signal,
      );
    } finally {
      dispose();
    }
  }
}
