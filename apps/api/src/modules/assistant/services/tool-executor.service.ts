import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  type AssistantCard,
  compileValidator,
  type ConfirmationSpec,
  confirmationSpecOf,
  type ConfirmationView,
  type ExecutionDecision,
  type ExecutionStatus,
  extractNextCursor,
  type OperationTool,
  sanitizeText,
  toCard,
  toPendingCard,
  toPendingEnvelope,
  type ToolResultDenied,
  type ToolResultEnvelope,
  toToolResultEnvelope,
  withCasPlaceholder,
} from '@email-gateway/assistant';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService, scrubMetadata } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { TransactionRunner } from '../../../database/transaction-runner';
import {
  ASSISTANT_AUDIT,
  AUDIT_PARAMS_MAX_BYTES,
  AUDIT_RESOURCE,
  type AssistantConfig,
  CORRELATION_ID_PATTERN,
  PARAMS_REDACTED_MAX_BYTES,
} from '../assistant.constants';
import { sameRequest } from '../domain/confirmation-binding';
import { lookupTool, scopeOrganizationPublicId, toolAvailability } from '../domain/tool-catalog';
import type { ExecutionView } from '../dto/assistant.schemas';
import type { Owner } from '../repositories/conversations.repository';
import { ExecutionsRepository } from '../repositories/executions.repository';
import { AssistantMetrics } from './assistant-metrics';
import { ConfirmationProposer, type OwnFailure } from './confirmation-proposer.service';
import {
  buildLoopbackRequest,
  LoopbackDispatcher,
  type LoopbackResult,
  unsafePathParams,
} from './loopback-client';

/**
 * The tool executor of the assistant (step AI-1 D5, ADR-0091). For each `call_tool`, in order,
 * each refusal a recorded, audited execution with a `decision` the model can explain:
 *
 * 1. per-turn cap (`ASSISTANT_MAX_TOOL_CALLS_PER_TURN`) → `denied_budget`;
 * 2. registry lookup → `denied_unknown_tool`; `not_applicable` → `denied_not_applicable` (reason
 *    and portal page); not enabled → `denied_disabled` (also an enabled write without a
 *    confirmation spec, defence in depth);
 * 3. permission pre-filter (`satisfiesRequirement`, the guard's predicate; `platform:*`-only tools
 *    for platform users only) → `denied_permission`;
 * 4. bindings (`self_organization` = the scope's organization when the model omitted it);
 * 5. refs `@r<seq>.<row>` → the public id stored for that ref in THIS conversation, else
 *    `denied_ref`;
 * 6. Ajv validation of the operation's input schema → `denied_schema` (paths, never values);
 *    for a write, the spec's CAS field is pre-filled with a placeholder when omitted;
 * 7. a READ: the loopback call (D2); `401` ends the turn (`assistant_session_expired`).
 *    A WRITE never runs here (step AI-2 D1, ADR-0093): `ConfirmationProposer` reads the target
 *    and stores a pending confirmation; the execution is `pending_confirmation` and the model
 *    gets the `pending_confirmation` envelope (never the token). The write runs only through
 *    `run()` from the confirm route with the stored request and `Idempotency-Key`;
 * 8. card + minimized envelope (D8), the execution row and the audit row
 *    (`assistant.tool_executed` / `assistant.tool_denied`, D12) in one writer transaction (with
 *    the confirmation row and `assistant.confirmation_requested` for a proposal).
 *
 * Logs carry ids and codes only, never arguments or results.
 */

export interface ExecutionContext {
  principal: UserPrincipal;
  owner: Owner;
  conversationId: bigint;
  conversationPublicId: string;
  turnId: bigint | null;
  turnPublicId: string | null;
  parentExecutionId: bigint | null;
  parentExecutionPublicId: string | null;
  /** The turn request's `authorization` header, verbatim. */
  authorization: string;
  clientIp: string | null;
  /** Correlation id of the turn (or "more") request; the execution's is `<base>.<seq>`. */
  correlationBase: string;
  signal: AbortSignal;
  /** Next conversation-wide execution sequence (callers hold the conversation's turn lock). */
  allocateSeq: () => number;
}

export interface ToolCallRequest {
  name: string;
  /** Parsed arguments, or null when the model sent something that is not a JSON object. */
  arguments: Record<string, unknown> | null;
}

export interface ExecutionStarted {
  executionId: string;
  tool: string;
  title: string;
}

export interface ExecutionOutcome {
  executionId: string;
  seq: number;
  tool: string;
  title: string;
  decision: ExecutionDecision;
  status: ExecutionStatus;
  httpStatus: number | null;
  errorCode: string | null;
  /** What the model gets (`assistant-tool-result/1`). */
  envelope: ToolResultEnvelope;
  /** What the user gets (`assistant-card/1`); null for refused calls. */
  card: AssistantCard | null;
  /** Message of a refused call (stream `tool.denied`). */
  denialMessage: string | null;
  /** The loopback answered 401: the turn ends with `assistant_session_expired`. */
  sessionExpired: boolean;
  view: ExecutionView;
  /** A write proposal: its confirmation and the single-use token (browser only, D1 step 10). */
  confirmation: { view: ConfirmationView; token: string } | null;
}

/** Options of `run()` (step AI-2: the confirmed write). */
export interface RunOptions {
  /**
   * `Idempotency-Key` of the loopback call (the confirmation public id), sent only when the
   * operation declares `required` or `legacy` idempotency. Always a server value.
   */
  idempotencyKey?: string;
  /** The stored request: `run` refuses when the arguments would build any other request. */
  expectedRequest?: { method: string; path: string; body: unknown };
  /** Never aborted by the client (the confirmed write keeps running until its own timeout). */
  signal?: AbortSignal;
  /** Runs inside the transaction of the execution row (the confirmation's outcome + audit). */
  afterPersist?: (
    tx: Prisma.TransactionClient,
    executionRowId: bigint,
    outcome: ExecutionOutcome,
  ) => Promise<void>;
}

/** An answer as the recorder sees it (an API response or an own error). */
interface Answer {
  status: ExecutionStatus;
  httpStatus: number;
  recordedStatus: number | null;
  body: unknown;
  errorCode: string | null;
  errorMessage: string | null;
}

type Base = {
  ctx: ExecutionContext;
  seq: number;
  executionId: string;
  name: string;
  title: string;
};

/** The request of a confirmed write differs from the stored one (never sent). */
export class StoredRequestMismatchError extends Error {
  constructor() {
    super('the stored request of the confirmation does not match its arguments');
  }
}

/** Arguments of the form `@r<seq>.<row>` (D5 step 5). */
export const REF_ARGUMENT = /^@r(\d{1,9})\.(\d{1,5})$/;

const DENIAL_MESSAGES: Record<Exclude<ExecutionDecision, 'allowed'>, string> = {
  denied_budget: 'This turn already used its maximum number of tool calls.',
  denied_unknown_tool: 'There is no tool with this name. Use a name from the catalogue index.',
  denied_not_applicable: 'This operation is not available in chat; it stays in the portal.',
  denied_disabled: 'This tool is not enabled for chat yet; use the portal page.',
  denied_permission: 'You do not have the permission this tool needs.',
  denied_schema: 'The arguments do not match the tool’s input schema.',
  denied_ref: 'A reference (@r<seq>.<row>) does not name a result of this conversation.',
};

const byteLength = (value: unknown): number => Buffer.byteLength(JSON.stringify(value), 'utf8');

/** The execution's correlation id `<base>.<seq>` within `^[A-Za-z0-9._:-]{8,128}$`. */
export function executionCorrelationId(base: string, seq: number): string {
  const suffix = `.${seq}`;
  const safe = CORRELATION_ID_PATTERN.test(base) ? base : 'assistant';
  const id = `${safe.slice(0, 128 - suffix.length)}${suffix}`;
  return id.length >= 8 ? id : `assistant${suffix}`;
}

/**
 * Credential-scrubbed parameters capped at `maxBytes` (the audit pattern drops credential keys
 * at any depth). `exact` = nothing was dropped or truncated, so the parameters can be re-sent.
 */
export function redactParams(
  args: Readonly<Record<string, unknown>>,
  maxBytes: number,
): { value: Prisma.InputJsonValue; exact: boolean } {
  const scrubbed = scrubMetadata(args) ?? {};
  const exact = JSON.stringify(scrubbed) === JSON.stringify(args);
  if (byteLength(scrubbed) <= maxBytes) return { value: scrubbed, exact };
  const keys = Object.keys(args)
    .slice(0, 32)
    .map((k) => sanitizeText(k, 64));
  return { value: { truncated: true, keys }, exact: false };
}

/** Deep-replaces ref arguments; returns the missing refs. */
async function resolveRefs(
  value: unknown,
  lookup: (seq: number, ref: string) => Promise<string | null>,
  missing: string[],
): Promise<unknown> {
  if (typeof value === 'string') {
    const match = REF_ARGUMENT.exec(value);
    if (!match) return value;
    const ref = value.slice(1);
    const resolved = await lookup(Number(match[1]), ref);
    if (resolved === null) {
      missing.push(ref);
      return value;
    }
    return resolved;
  }
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (const item of value) out.push(await resolveRefs(item, lookup, missing));
    return out;
  }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      out[key] = await resolveRefs(item, lookup, missing);
    }
    return out;
  }
  return value;
}

function refTarget(refs: unknown, ref: string): string | null {
  if (refs === null || typeof refs !== 'object' || Array.isArray(refs)) return null;
  const target = (refs as Record<string, unknown>)[ref];
  if (target === null || typeof target !== 'object') return null;
  const publicId = (target as { publicId?: unknown }).publicId;
  return typeof publicId === 'string' && /^[A-Za-z0-9._:@-]{1,128}$/.test(publicId)
    ? publicId
    : null;
}

@Injectable()
export class ToolExecutorService {
  private readonly logger = new Logger(ToolExecutorService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    private readonly executions: ExecutionsRepository,
    private readonly loopback: LoopbackDispatcher,
    private readonly runner: TransactionRunner,
    private readonly audit: AuditService,
    private readonly metrics: AssistantMetrics,
    private readonly proposer: ConfirmationProposer,
  ) {}

  now(): Date {
    return new Date();
  }

  /**
   * Executes one `call_tool` (D5). `callIndex` is the 0-based index of this call in the turn
   * (the per-turn cap); `onStarted` fires once the execution has its id (stream `tool.started`).
   */
  async execute(
    ctx: ExecutionContext,
    call: ToolCallRequest,
    callIndex: number,
    onStarted: (started: ExecutionStarted) => void = () => undefined,
  ): Promise<ExecutionOutcome> {
    const seq = ctx.allocateSeq();
    const executionId = uuidv7();
    const name = sanitizeText(call.name, 96);
    const lookup = lookupTool(call.name);
    const tool = lookup.kind === 'tool' ? lookup.tool : null;
    const title = sanitizeText(
      tool
        ? (tool.display.title ?? tool.summary)
        : lookup.kind === 'not_applicable'
          ? lookup.operation.summary
          : name,
      120,
    );
    onStarted({ executionId, tool: name, title });
    const base = { ctx, seq, executionId, name, title };

    if (callIndex >= this.config.ASSISTANT_MAX_TOOL_CALLS_PER_TURN) {
      return this.deny(base, tool, 'denied_budget', DENIAL_MESSAGES.denied_budget, {});
    }
    if (lookup.kind === 'unknown') {
      return this.deny(base, null, 'denied_unknown_tool', DENIAL_MESSAGES.denied_unknown_tool, {});
    }
    if (lookup.kind === 'not_applicable') {
      const op = lookup.operation;
      const reason = sanitizeText(op.reason, 200);
      return this.deny(
        base,
        {
          operationId: op.operationId,
          method: op.method,
          access: op.access,
          risk: op.risk ?? (op.access === 'read' ? 'read' : 'high'),
          module: op.module,
        },
        'denied_not_applicable',
        `${DENIAL_MESSAGES.denied_not_applicable} Reason: ${reason}.`,
        {},
        op.portalRoute,
      );
    }
    const found = lookup.tool;
    const availability = toolAvailability(ctx.principal, found);
    if (!availability.available && availability.reason === 'disabled') {
      return this.deny(
        base,
        found,
        'denied_disabled',
        DENIAL_MESSAGES.denied_disabled,
        {},
        found.portalRoute,
      );
    }
    if (!availability.available) {
      return this.deny(base, found, 'denied_permission', DENIAL_MESSAGES.denied_permission, {});
    }
    // Step AI-2: an enabled write needs its confirmation spec (the registry check forbids one
    // without; refused like a disabled tool).
    let spec: ConfirmationSpec | undefined;
    if (found.access === 'write') {
      spec = confirmationSpecOf(found.operationId);
      if (!spec) {
        return this.deny(
          base,
          found,
          'denied_disabled',
          DENIAL_MESSAGES.denied_disabled,
          {},
          found.portalRoute,
        );
      }
    }
    if (call.arguments === null) {
      return this.deny(
        base,
        found,
        'denied_schema',
        `${DENIAL_MESSAGES.denied_schema} The arguments must be a JSON object.`,
        {},
      );
    }

    // D5 step 4: bindings (the api enforces the scope again).
    const args: Record<string, unknown> = { ...call.arguments };
    const bindValue =
      ctx.principal.organizationKind === 'customer' || ctx.principal.override
        ? scopeOrganizationPublicId(ctx.principal)
        : null;
    for (const [param, binding] of Object.entries(found.bind)) {
      if (binding === 'self_organization' && args[param] === undefined && bindValue !== null) {
        args[param] = bindValue;
      }
    }

    // D5 step 5: refs of this conversation only.
    const missing: string[] = [];
    const refCache = new Map<number, unknown>();
    const resolved = (await resolveRefs(
      args,
      async (refSeq, ref) => {
        if (!refCache.has(refSeq)) {
          refCache.set(refSeq, await this.executions.refsOf(ctx.owner, ctx.conversationId, refSeq));
        }
        return refTarget(refCache.get(refSeq), ref);
      },
      missing,
    )) as Record<string, unknown>;
    if (missing.length > 0) {
      return this.deny(
        base,
        found,
        'denied_ref',
        `${DENIAL_MESSAGES.denied_ref} Unknown: ${missing.slice(0, 5).join(', ')}.`,
        args,
      );
    }

    // D5 step 6: the operation's own input schema (Ajv 8 strict). A write's CAS field gets a
    // placeholder when omitted (step AI-2 D1); the proposal injects the read's row version.
    const checked = spec ? withCasPlaceholder(resolved, spec) : resolved;
    const validation = compileValidator(found)(checked);
    if (!validation.ok) {
      const issues = validation.issues.map((issue) => `${issue.path} ${issue.message}`).join('; ');
      return this.deny(
        base,
        found,
        'denied_schema',
        `${DENIAL_MESSAGES.denied_schema} ${sanitizeText(issues, 600)}`,
        resolved,
      );
    }
    // A path parameter the schema leaves optional because a binding usually fills it (e.g. `id`
    // of `/organizations/{id}` for customer users) can still be missing (platform users without
    // an override): a schema refusal, never a failed request build.
    const missingPath = found.pathParams.filter(
      (param) => typeof checked[param] !== 'string' && typeof checked[param] !== 'number',
    );
    if (missingPath.length > 0) {
      return this.deny(
        base,
        found,
        'denied_schema',
        `${DENIAL_MESSAGES.denied_schema} Missing path parameter: ${missingPath.join(', ')}.`,
        resolved,
      );
    }

    // `.`/`..`/empty path values would be collapsed by URL resolution into another route than
    // the one recorded, audited and (from AI-2) confirmed: refused like a schema violation.
    const unsafePath = unsafePathParams(found, checked);
    if (unsafePath.length > 0) {
      return this.deny(
        base,
        found,
        'denied_schema',
        `${DENIAL_MESSAGES.denied_schema} Invalid path parameter: ${unsafePath.join(', ')}.`,
        resolved,
      );
    }

    if (spec) return this.propose(base, found, spec, checked);
    return this.run(base, found, resolved);
  }

  /**
   * Step AI-2 D1: a write call becomes a pending confirmation (or a recorded refusal or failure
   * of the proposal). No write request is sent.
   */
  private async propose(
    base: Base,
    tool: OperationTool,
    spec: ConfirmationSpec,
    args: Record<string, unknown>,
  ): Promise<ExecutionOutcome> {
    const { ctx, seq, executionId } = base;
    const correlationId = executionCorrelationId(ctx.correlationBase, seq);
    const started = Date.now();
    const prepared = await this.proposer.prepare({
      ctx,
      tool,
      spec,
      args,
      executionId,
      correlationId,
    });
    const latencyMs = Date.now() - started;
    switch (prepared.kind) {
      case 'denied':
        return this.deny(base, tool, prepared.decision, prepared.message, args);
      case 'failed':
        return this.record(base, tool, args, this.interpret(prepared.result), latencyMs);
      case 'failed_own':
        return this.record(base, tool, args, this.ownFailure(prepared.failure), latencyMs);
      case 'pending':
        break;
    }
    const plan = prepared.plan;
    const card = toPendingCard(executionId, tool);
    const envelope = toPendingEnvelope(tool.name, {
      id: plan.confirmationId,
      risk: plan.risk,
      requiresReauth: plan.requiresReauth,
      expiresAt: plan.expiresAt.toISOString(),
    });
    const confirmation = this.proposer.viewOf(ctx, executionId, tool, plan);
    const outcome: ExecutionOutcome = {
      executionId,
      seq,
      tool: tool.name,
      title: base.title,
      decision: 'allowed',
      status: 'pending_confirmation',
      httpStatus: null,
      errorCode: null,
      envelope,
      card,
      denialMessage: null,
      sessionExpired: false,
      confirmation: { view: confirmation, token: plan.token },
      view: this.viewOf(ctx, {
        executionId,
        seq,
        tool,
        name: tool.name,
        decision: 'allowed',
        status: 'pending_confirmation',
        httpStatus: null,
        errorCode: null,
        card,
        hasMore: false,
        latencyMs,
        confirmation,
      }),
    };
    await this.persist(
      ctx,
      outcome,
      tool,
      {
        correlationId,
        params: redactParams(plan.finalArgs, PARAMS_REDACTED_MAX_BYTES).value,
        args: plan.finalArgs,
        refs: null,
        nextCursor: null,
        latencyMs,
      },
      (tx, rowId) => this.proposer.store(tx, ctx, executionId, rowId, tool, plan, correlationId),
    );
    this.metrics.toolCalls.inc({
      module: tool.module,
      access: tool.access,
      decision: 'allowed',
      outcome: 'pending_confirmation',
    });
    this.metrics.confirmations.inc({ risk: plan.risk, outcome: 'proposed' });
    this.logger.log({
      message: 'Assistant write proposed',
      executionId,
      confirmationId: plan.confirmationId,
      operationId: tool.operationId,
      risk: plan.risk,
    });
    return outcome;
  }

  /**
   * D5 steps 7–8 for validated arguments: the loopback call, card, envelope, execution row and
   * audit. Used by turns (reads), the "more" route and the confirm route (the stored write).
   */
  async run(
    base: Base,
    tool: OperationTool,
    args: Record<string, unknown>,
    options: RunOptions = {},
  ): Promise<ExecutionOutcome> {
    const { ctx, seq, executionId } = base;
    const correlationId = executionCorrelationId(ctx.correlationBase, seq);
    const request = buildLoopbackRequest(tool, args);
    if (options.expectedRequest && !sameRequest(request, options.expectedRequest)) {
      throw new StoredRequestMismatchError();
    }
    const idempotent = tool.idempotency === 'required' || tool.idempotency === 'legacy';
    const started = Date.now();
    const result = await this.loopback.send({
      ...request,
      authorization: ctx.authorization,
      correlationId,
      clientIp: ctx.clientIp,
      executionId,
      signal: options.signal ?? ctx.signal,
      ...(idempotent && options.idempotencyKey !== undefined
        ? { idempotencyKey: options.idempotencyKey }
        : {}),
    });
    const latencyMs = Date.now() - started;
    this.metrics.toolSeconds.observe({ module: tool.module }, latencyMs / 1000);
    return this.record(base, tool, args, this.interpret(result), latencyMs, options.afterPersist);
  }

  /** Card, envelope, execution row and audit of an answer (D5 step 8). */
  private async record(
    base: Base,
    tool: OperationTool,
    args: Record<string, unknown>,
    answer: Answer,
    latencyMs: number,
    afterPersist?: RunOptions['afterPersist'],
  ): Promise<ExecutionOutcome> {
    const { ctx, seq, executionId } = base;
    const correlationId = executionCorrelationId(ctx.correlationBase, seq);
    const params = redactParams(args, PARAMS_REDACTED_MAX_BYTES);
    const { envelope, refs } = toToolResultEnvelope(tool, answer.httpStatus, answer.body, {
      maxRows: this.config.ASSISTANT_TOOL_RESULT_MAX_ROWS,
      maxBytes: this.config.ASSISTANT_TOOL_RESULT_MAX_BYTES,
      refSeq: seq,
    });
    const finalEnvelope: ToolResultEnvelope =
      answer.errorCode !== null && envelope.status === 'error'
        ? { ...envelope, code: answer.errorCode, message: answer.errorMessage ?? envelope.message }
        : envelope;
    const ok = answer.httpStatus >= 200 && answer.httpStatus < 300 && answer.status === 'succeeded';
    const cursor =
      ok && tool.cursor !== null && params.exact ? extractNextCursor(answer.body) : null;
    const nextCursor = cursor !== null && cursor.length <= 2048 ? cursor : null;
    const card = toCard({
      executionId,
      tool,
      httpStatus: answer.httpStatus,
      body: answer.body,
      args,
      refs,
      refSeq: seq,
    });
    if (card.kind === 'table') card.nextCursor = nextCursor !== null;
    const errorCode =
      answer.errorCode ?? (finalEnvelope.status === 'error' ? finalEnvelope.code : null);
    const outcome: ExecutionOutcome = {
      executionId,
      seq,
      tool: tool.name,
      title: base.title,
      decision: 'allowed',
      status: answer.status,
      httpStatus: answer.recordedStatus,
      errorCode,
      envelope: finalEnvelope,
      card,
      denialMessage: null,
      sessionExpired: answer.recordedStatus === 401,
      confirmation: null,
      view: this.viewOf(ctx, {
        executionId,
        seq,
        tool,
        name: tool.name,
        decision: 'allowed',
        status: answer.status,
        httpStatus: answer.recordedStatus,
        errorCode,
        card,
        hasMore: nextCursor !== null,
        latencyMs,
      }),
    };
    await this.persist(
      ctx,
      outcome,
      tool,
      {
        correlationId,
        params: params.value,
        args,
        refs: Object.keys(refs).length > 0 ? (refs as unknown as Prisma.InputJsonValue) : null,
        nextCursor,
        latencyMs,
      },
      afterPersist ? (tx, rowId) => afterPersist(tx, rowId, outcome) : undefined,
    );
    this.metrics.toolCalls.inc({
      module: tool.module,
      access: tool.access,
      decision: 'allowed',
      outcome: answer.status,
    });
    return outcome;
  }

  /** A coded failure of a proposal (definition invalid, row version unreadable, too large). */
  private ownFailure(failure: OwnFailure): Answer {
    return this.ownError(
      'failed',
      failure.httpStatus,
      failure.httpStatus,
      failure.code,
      failure.message,
    );
  }

  /** Loopback result → recorded status, the body the minimizer sees and an own error code. */
  private interpret(result: LoopbackResult): Answer {
    switch (result.kind) {
      case 'response':
        return {
          status: result.status >= 200 && result.status < 300 ? 'succeeded' : 'failed',
          httpStatus: result.status,
          recordedStatus: result.status,
          body: result.body,
          errorCode: null,
          errorMessage: null,
        };
      case 'too_large':
        return this.ownError(
          'failed',
          result.status >= 400 ? result.status : 502,
          result.status,
          'tool_result_too_large',
          'The result is larger than the assistant can read; open the portal page.',
        );
      case 'timeout':
        return this.ownError(
          'timeout',
          504,
          null,
          'tool_timeout',
          'The operation did not answer in time.',
        );
      case 'aborted':
        return this.ownError('failed', 499, null, 'tool_aborted', 'The turn was cancelled.');
      case 'unavailable':
        return this.ownError(
          'failed',
          503,
          null,
          'tool_unavailable',
          'The operation could not be reached.',
        );
    }
  }

  private ownError(
    status: ExecutionStatus,
    httpStatus: number,
    recordedStatus: number | null,
    code: string,
    message: string,
  ): Answer {
    return {
      status,
      httpStatus,
      recordedStatus,
      body: { code, message },
      errorCode: code,
      errorMessage: message,
    };
  }

  private async deny(
    base: Base,
    tool: Pick<OperationTool, 'operationId' | 'method' | 'access' | 'risk' | 'module'> | null,
    decision: Exclude<ExecutionDecision, 'allowed'>,
    message: string,
    args: Record<string, unknown>,
    portalRoute: string | null = null,
  ): Promise<ExecutionOutcome> {
    const { ctx, seq, executionId, name } = base;
    const envelope: ToolResultDenied = {
      kind: 'tool_result/1',
      tool: name,
      status: 'denied',
      decision,
      code: decision,
      message,
      ...(portalRoute ? { portalRoute } : {}),
    };
    const outcome: ExecutionOutcome = {
      executionId,
      seq,
      tool: name,
      title: base.title,
      decision,
      status: 'refused',
      httpStatus: null,
      errorCode: decision,
      envelope,
      card: null,
      denialMessage: message,
      sessionExpired: false,
      confirmation: null,
      view: this.viewOf(ctx, {
        executionId,
        seq,
        tool,
        name,
        decision,
        status: 'refused',
        httpStatus: null,
        errorCode: decision,
        card: null,
        hasMore: false,
        latencyMs: null,
      }),
    };
    await this.persist(ctx, outcome, tool, {
      correlationId: executionCorrelationId(ctx.correlationBase, seq),
      params: redactParams(args, PARAMS_REDACTED_MAX_BYTES).value,
      args,
      refs: null,
      nextCursor: null,
      latencyMs: null,
    });
    this.metrics.toolCalls.inc({
      module: tool?.module ?? 'unknown',
      access: tool?.access ?? 'read',
      decision,
      outcome: 'refused',
    });
    this.logger.log({
      message: 'Assistant tool call refused',
      executionId,
      decision,
      operationId: tool?.operationId ?? null,
    });
    return outcome;
  }

  private viewOf(
    ctx: ExecutionContext,
    v: {
      executionId: string;
      seq: number;
      tool: Pick<OperationTool, 'operationId' | 'access' | 'risk'> | null;
      name: string;
      decision: ExecutionDecision;
      status: ExecutionStatus;
      httpStatus: number | null;
      errorCode: string | null;
      card: AssistantCard | null;
      hasMore: boolean;
      latencyMs: number | null;
      confirmation?: ConfirmationView | null;
    },
  ): ExecutionView {
    return {
      id: v.executionId,
      conversationId: ctx.conversationPublicId,
      turnId: ctx.turnPublicId,
      parentExecutionId: ctx.parentExecutionPublicId,
      seq: v.seq,
      ref: `r${v.seq}`,
      tool: v.name,
      operationId: v.tool?.operationId ?? 'unknown',
      access: v.tool?.access ?? 'read',
      risk: v.tool?.risk ?? 'read',
      decision: v.decision,
      status: v.status,
      httpStatus: v.httpStatus,
      errorCode: v.errorCode,
      hasMore: v.hasMore,
      card: v.card,
      latencyMs: v.latencyMs,
      createdAt: this.now().toISOString(),
      confirmation: v.confirmation ?? null,
    };
  }

  /** The execution row and its audit row, in one writer transaction (D12, I6). */
  private async persist(
    ctx: ExecutionContext,
    outcome: ExecutionOutcome,
    tool: Pick<OperationTool, 'operationId' | 'method' | 'access' | 'risk'> | null,
    extra: {
      correlationId: string;
      params: Prisma.InputJsonValue;
      args: Record<string, unknown>;
      refs: Prisma.InputJsonValue | null;
      nextCursor: string | null;
      latencyMs: number | null;
    },
    also?: (tx: Prisma.TransactionClient, executionRowId: bigint) => Promise<void>,
  ): Promise<void> {
    const resourceRef = resourceRefOf(tool, extra.args);
    const auditParams = redactParams(extra.args, AUDIT_PARAMS_MAX_BYTES).value;
    await this.runner.run(async (tx) => {
      const rowId = await this.executions.create(
        ctx.owner,
        {
          publicId: outcome.executionId,
          conversationId: ctx.conversationId,
          turnId: ctx.turnId,
          parentExecutionId: ctx.parentExecutionId,
          seq: outcome.seq,
          toolName: outcome.tool.slice(0, 96),
          operationId: (tool?.operationId ?? 'unknown').slice(0, 128),
          httpMethod: tool?.method ?? 'GET',
          access: tool?.access ?? 'read',
          risk: tool?.risk ?? 'read',
          decision: outcome.decision,
          status: outcome.status,
          httpStatus: outcome.httpStatus,
          errorCode: outcome.errorCode?.slice(0, 64) ?? null,
          correlationId: extra.correlationId,
          paramsRedacted: extra.params,
          resourceRef,
          resultCard: outcome.card as unknown as Prisma.InputJsonValue | null,
          resultRefs: extra.refs,
          nextCursor: extra.nextCursor,
          latencyMs: extra.latencyMs,
          createdAt: this.now(),
        },
        tx,
      );
      await this.audit.record(
        {
          organizationId: ctx.owner.scope.organizationId,
          actor: this.audit.actorFrom(ctx.principal),
          action:
            outcome.decision === 'allowed'
              ? ASSISTANT_AUDIT.toolExecuted
              : ASSISTANT_AUDIT.toolDenied,
          resourceType: AUDIT_RESOURCE.execution,
          resourceId: outcome.executionId,
          sourceIp: ctx.clientIp,
          metadata: {
            conversationId: ctx.conversationPublicId,
            turnId: ctx.turnPublicId,
            tool: outcome.tool,
            operationId: tool?.operationId ?? null,
            access: tool?.access ?? null,
            risk: tool?.risk ?? null,
            decision: outcome.decision,
            status: outcome.status,
            httpStatus: outcome.httpStatus,
            // `errorCode` would be dropped by the audit credential-key scrub (`…code`): `error`.
            error: outcome.errorCode,
            resourceRef,
            params: auditParams,
            correlationId: extra.correlationId,
          },
        },
        tx,
      );
      if (also) await also(tx, rowId);
    });
  }
}

/** The single resource a call targets: its first path parameter (a public id), else null. */
export function resourceRefOf(
  tool: Pick<OperationTool, 'operationId'> | null,
  args: Readonly<Record<string, unknown>>,
): string | null {
  const pathParams = (tool as Partial<OperationTool> | null)?.pathParams ?? [];
  for (const name of pathParams) {
    const value = args[name];
    if (typeof value === 'string' && /^[A-Za-z0-9._:@-]{1,64}$/.test(value)) return value;
    if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  }
  return null;
}
