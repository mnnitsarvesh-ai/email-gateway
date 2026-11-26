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
  guardRefusal,
  isNativeTool,
  type OperationTool,
  redactToolArguments,
  reportCard,
  reportEnvelope,
  reportQueuedCard,
  reportQueuedEnvelope,
  reportRefs,
  sanitizeText,
  toCard,
  toPendingCard,
  toPendingEnvelope,
  type ToolResultDenied,
  type ToolResultEnvelope,
  toToolResultEnvelope,
  withCasPlaceholder,
  withImpactTokenPlaceholder,
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
  PARAMS_REDACTED_MAX_BYTES,
} from '../assistant.constants';
import { nativeRequestOf, sameRequest } from '../domain/confirmation-binding';
import { executionCorrelationId } from '../domain/correlation';
import { UNKNOWN_PLACEHOLDER_ERROR, unknownPlaceholderMessage } from '../assistant.errors';
import { DENIAL_MESSAGES, refusalMessageOf } from '../domain/denials';
import {
  lookupTool,
  nativeSwitchesOf,
  scopeOrganizationPublicId,
  toolAvailability,
  toolTitleOf,
} from '../domain/tool-catalog';
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
import { NativeToolsService } from './native-tools.service';
import type { GeneratedReport, QueuedReport } from './reports/report-generator.service';

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
 *    for a write, the spec's CAS field is pre-filled with a placeholder when omitted, and so
 *    are a server-filled impact token and `confirm` (step AI-5 D5);
 * 6a. a write's proposal guards that need no read (step AI-3 D3/D10: not the caller's own
 *    account, not the assistant's own feature, not `assistant:configure`) → `denied_guard`
 *    with the guard's fixed message, before any loopback call (not even the precondition read);
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
  /**
   * The organization's display name as the turn read it (`GET /auth/me`; step AI-R: the report
   * header). Absent outside turns.
   */
  organizationName?: string | null;
  /**
   * Step AI-6 D3 (`pseudonymized` turns): replaces the conversation's placeholders in the
   * model's arguments by the real values before bindings, refs and Ajv; an unknown placeholder is
   * refused (`denied_schema`, `assistant_unknown_placeholder`). Absent = arguments as sent.
   */
  demapArguments?: (
    args: Record<string, unknown>,
  ) => { ok: true; value: Record<string, unknown> } | { ok: false; token: string };
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
  /**
   * A confirmed native write (step AI-R D5 step 13): the confirmation row it executes (the
   * delivery's unique `confirmation_id`).
   */
  native?: { confirmationRowId: bigint; confirmationPublicId: string };
}

/** Audit metadata of a refusal: the guard and its facts (codes, a domain, a hash; never values). */
export type DenyExtra = { guard?: string; code?: string } & Record<string, string | undefined>;

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

/** The arguments with the values of `keys` replaced (never stored or audited). */
export function withRedacted(
  args: Record<string, unknown>,
  keys: readonly string[] | undefined,
): Record<string, unknown> {
  if (!keys || keys.length === 0) return args;
  const out = { ...args };
  for (const key of keys) if (key in out) out[key] = '[redacted]';
  return out;
}

/** Arguments of the form `@r<seq>.<row>` (D5 step 5). */
export const REF_ARGUMENT = /^@r(\d{1,9})\.(\d{1,5})$/;

const byteLength = (value: unknown): number => Buffer.byteLength(JSON.stringify(value), 'utf8');

export { executionCorrelationId } from '../domain/correlation';

/** What `redactParams` needs of a tool: its redacted argument paths (step AI-4 D9). */
export type RedactSource = { readonly redactParams?: readonly string[] } | null;

/**
 * The parameters as stored and audited: first every `redactParams` path of the tool replaced by
 * `[redacted]` (step AI-4 D9: e.g. the DLP pattern-test sample and pattern), then the credential
 * scrub (the audit pattern drops credential keys at any depth), capped at `maxBytes`. `exact` =
 * nothing was redacted, dropped or truncated, so the parameters can be re-sent. The loopback
 * request always carries the real arguments; only the stored copy is redacted.
 */
export function redactParams(
  args: Readonly<Record<string, unknown>>,
  maxBytes: number,
  tool: RedactSource,
): { value: Prisma.InputJsonValue; exact: boolean } {
  const paths = tool?.redactParams ?? [];
  const redacted =
    paths.length > 0
      ? redactToolArguments({ redactParams: [...paths] }, args)
      : { args, redacted: false };
  const scrubbed = scrubMetadata(redacted.args) ?? {};
  const exact = !redacted.redacted && JSON.stringify(scrubbed) === JSON.stringify(args);
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
    private readonly native: NativeToolsService,
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
    const title = toolTitleOf(name);
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
    const availability = toolAvailability(ctx.principal, found, nativeSwitchesOf(this.config));
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

    // Step AI-6 D3: placeholders of a pseudonymized turn → the real values (before step 4).
    let modelArgs: Record<string, unknown> = call.arguments;
    if (ctx.demapArguments) {
      const demapped = ctx.demapArguments(call.arguments);
      if (!demapped.ok) {
        return this.deny(
          base,
          found,
          'denied_schema',
          unknownPlaceholderMessage(demapped.token),
          call.arguments,
          null,
          { code: UNKNOWN_PLACEHOLDER_ERROR },
        );
      }
      modelArgs = demapped.value;
    }

    // D5 step 4: bindings (the api enforces the scope again).
    const args: Record<string, unknown> = { ...modelArgs };
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
    // placeholder when omitted (step AI-2 D1); the proposal injects the read's row version. A
    // server-filled impact token (step AI-5 D5) gets its placeholder too (`body.impactToken`,
    // `body.confirm`); the proposal always replaces both with a fresh preview's values.
    const checked = spec
      ? withImpactTokenPlaceholder(withCasPlaceholder(resolved, spec), spec)
      : resolved;
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

    if (spec) {
      // Step AI-3 D10: the before-read proposal guards (I12), before any loopback request.
      const refusal = guardRefusal(
        spec,
        { args: checked, principalUserPublicId: ctx.principal.userPublicId, read: null },
        'before_read',
      );
      if (refusal) {
        return this.deny(base, found, 'denied_guard', refusal.message, resolved, null, {
          guard: refusal.guard,
        });
      }
      return this.propose(base, found, spec, checked);
    }
    // Step AI-R D2: a native read runs its own composition, never the loopback of its path.
    if (isNativeTool(found)) return this.runNativeRead(base, found, resolved);
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
        return this.deny(
          base,
          tool,
          prepared.decision,
          prepared.message,
          withRedacted(args, prepared.redact),
          null,
          {
            ...(prepared.auditExtra ?? {}),
            ...(prepared.guard ? { guard: prepared.guard } : {}),
            ...(prepared.code ? { code: prepared.code } : {}),
          },
        );
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
        params: redactParams(plan.finalArgs, PARAMS_REDACTED_MAX_BYTES, tool).value,
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
    if (isNativeTool(tool)) {
      return tool.access === 'write'
        ? this.runNativeWrite(base, tool, args, options)
        : this.runNativeRead(base, tool, args);
    }
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

  /**
   * Step AI-R D2: `report_generate` through `NativeToolsService` (fixed loopback reads, the
   * renderer, object storage); the report row becomes `available` and is audited in the
   * execution's transaction. Refusals and failures are recorded like any other call.
   */
  private async runNativeRead(
    base: Base,
    tool: OperationTool,
    args: Record<string, unknown>,
  ): Promise<ExecutionOutcome> {
    const { ctx, seq, executionId } = base;
    const started = Date.now();
    const result = await this.native.read(tool, { ctx, executionId, seq, args });
    const latencyMs = Date.now() - started;
    this.metrics.toolSeconds.observe({ module: tool.module }, latencyMs / 1000);
    switch (result.kind) {
      case 'denied':
        return this.deny(
          base,
          tool,
          result.decision,
          result.message,
          withRedacted(args, result.redact),
          null,
          {
            ...(result.auditExtra ?? {}),
            ...(result.guard ? { guard: result.guard } : {}),
            ...(result.code ? { code: result.code } : {}),
          },
        );
      case 'failed':
        return this.record(
          base,
          tool,
          args,
          this.ownError(
            result.status,
            result.httpStatus,
            result.recordedStatus,
            result.code,
            result.message,
          ),
          latencyMs,
        );
      case 'report':
        return this.recordReport(base, tool, args, result, latencyMs);
      case 'queue':
        return this.recordQueued(base, tool, args, result, latencyMs);
    }
  }

  /**
   * Step AI-6 D5: a background report. The execution (`allowed`, `succeeded`, HTTP 202) with the
   * queued card and envelope, `assistant.tool_executed`, and — in the same transaction — the
   * `queued` report, the job, its outbox event and `assistant.report_job_queued`.
   */
  private async recordQueued(
    base: Base,
    tool: OperationTool,
    args: Record<string, unknown>,
    queued: QueuedReport,
    latencyMs: number,
  ): Promise<ExecutionOutcome> {
    const { ctx, seq, executionId } = base;
    const report = {
      reportId: queued.reportId,
      title: queued.title,
      period: queued.period,
      sections: queued.sections,
    };
    const card = reportQueuedCard({ executionId, refSeq: seq, report });
    const envelope = reportQueuedEnvelope({ refSeq: seq, report });
    const refs = reportRefs(seq, queued.reportId);
    const correlationId = executionCorrelationId(ctx.correlationBase, seq);
    const outcome = this.outcomeOf(base, tool, {
      status: 'succeeded',
      httpStatus: 202,
      errorCode: null,
      envelope,
      card,
      hasMore: false,
      latencyMs,
    });
    await this.persist(
      ctx,
      outcome,
      tool,
      {
        correlationId,
        params: redactParams(args, PARAMS_REDACTED_MAX_BYTES, tool).value,
        args,
        refs: refs as unknown as Prisma.InputJsonValue,
        nextCursor: null,
        latencyMs,
      },
      (tx, rowId) => this.native.queueRead(ctx, queued, { rowId, executionId, correlationId }, tx),
    );
    this.countAllowed(tool, 'succeeded');
    return outcome;
  }

  /** The `report` card, envelope and refs of a generated report (D2 steps 10–11). */
  private async recordReport(
    base: Base,
    tool: OperationTool,
    args: Record<string, unknown>,
    generated: GeneratedReport,
    latencyMs: number,
  ): Promise<ExecutionOutcome> {
    const { ctx, seq, executionId } = base;
    const card = reportCard({ executionId, refSeq: seq, report: generated.report });
    const envelope = reportEnvelope({ refSeq: seq, report: generated.report });
    const refs = reportRefs(seq, generated.report.reportId);
    const outcome = this.outcomeOf(base, tool, {
      status: 'succeeded',
      httpStatus: 201,
      errorCode: null,
      envelope,
      card,
      hasMore: false,
      latencyMs,
    });
    await this.persist(
      ctx,
      outcome,
      tool,
      {
        correlationId: executionCorrelationId(ctx.correlationBase, seq),
        params: redactParams(args, PARAMS_REDACTED_MAX_BYTES, tool).value,
        args,
        refs: refs as unknown as Prisma.InputJsonValue,
        nextCursor: null,
        latencyMs,
      },
      (tx, rowId) => this.native.finalizeRead(ctx, generated, rowId, tx),
    );
    this.countAllowed(tool, 'succeeded');
    return outcome;
  }

  /**
   * Step AI-R D5 step 13: a confirmed native write. `NativeToolsService.execute` runs inside the
   * execution's transaction (lock, recount, delivery, outbox, audit), then the execution row, its
   * audit and the confirmation's outcome (`afterPersist`) in the same transaction.
   */
  private async runNativeWrite(
    base: Base,
    tool: OperationTool,
    args: Record<string, unknown>,
    options: RunOptions,
  ): Promise<ExecutionOutcome> {
    const { ctx, seq, executionId } = base;
    const request = nativeRequestOf(tool, args);
    if (options.expectedRequest && !sameRequest(request, options.expectedRequest)) {
      throw new StoredRequestMismatchError();
    }
    if (!options.native) throw new Error('a native write runs only from its confirmation');
    const native = options.native;
    const correlationId = executionCorrelationId(ctx.correlationBase, seq);
    const started = Date.now();
    const params = redactParams(args, PARAMS_REDACTED_MAX_BYTES, tool).value;
    const outcome = await this.runner.run(async (tx) => {
      const result = await this.native.execute(
        tool,
        {
          principal: ctx.principal,
          owner: ctx.owner,
          conversationId: ctx.conversationId,
          clientIp: ctx.clientIp,
        },
        args,
        {
          executionId,
          correlationId,
          confirmationRowId: native.confirmationRowId,
          confirmationPublicId: native.confirmationPublicId,
        },
        tx,
      );
      const latencyMs = Date.now() - started;
      const built =
        result.kind === 'queued'
          ? this.outcomeOf(base, tool, {
              status: 'succeeded',
              httpStatus: result.httpStatus,
              errorCode: null,
              envelope: result.envelope(seq),
              card: result.card(executionId),
              hasMore: false,
              latencyMs,
            })
          : this.assemble(
              base,
              tool,
              args,
              this.ownError(
                result.status,
                result.httpStatus,
                result.recordedStatus,
                result.code,
                result.message,
              ),
              latencyMs,
            ).outcome;
      const rowId = await this.writeRows(tx, ctx, built, tool, {
        correlationId,
        params,
        args,
        refs: null,
        nextCursor: null,
        latencyMs,
      });
      if (options.afterPersist) await options.afterPersist(tx, rowId, built);
      return built;
    });
    this.metrics.toolSeconds.observe({ module: tool.module }, (Date.now() - started) / 1000);
    this.countAllowed(tool, outcome.status);
    return outcome;
  }

  /** An allowed execution's outcome from its parts. */
  private outcomeOf(
    base: Base,
    tool: OperationTool,
    parts: {
      status: ExecutionStatus;
      httpStatus: number | null;
      errorCode: string | null;
      envelope: ToolResultEnvelope;
      card: AssistantCard;
      hasMore: boolean;
      latencyMs: number;
    },
  ): ExecutionOutcome {
    const { ctx, seq, executionId } = base;
    return {
      executionId,
      seq,
      tool: tool.name,
      title: base.title,
      decision: 'allowed',
      status: parts.status,
      httpStatus: parts.httpStatus,
      errorCode: parts.errorCode,
      envelope: parts.envelope,
      card: parts.card,
      denialMessage: null,
      sessionExpired: parts.httpStatus === 401,
      confirmation: null,
      view: this.viewOf(ctx, {
        executionId,
        seq,
        tool,
        name: tool.name,
        decision: 'allowed',
        status: parts.status,
        httpStatus: parts.httpStatus,
        errorCode: parts.errorCode,
        card: parts.card,
        hasMore: parts.hasMore,
        latencyMs: parts.latencyMs,
      }),
    };
  }

  private countAllowed(tool: OperationTool, outcome: ExecutionStatus): void {
    this.metrics.toolCalls.inc({
      module: tool.module,
      access: tool.access,
      decision: 'allowed',
      outcome,
    });
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
    const { ctx } = base;
    const { outcome, extra } = this.assemble(base, tool, args, answer, latencyMs);
    await this.persist(
      ctx,
      outcome,
      tool,
      extra,
      afterPersist ? (tx, rowId) => afterPersist(tx, rowId, outcome) : undefined,
    );
    this.countAllowed(tool, answer.status);
    return outcome;
  }

  /** The outcome and stored extras of an answer (card, minimized envelope, cursor). */
  private assemble(
    base: Base,
    tool: OperationTool,
    args: Record<string, unknown>,
    answer: Answer,
    latencyMs: number,
  ): { outcome: ExecutionOutcome; extra: PersistExtra } {
    const { ctx, seq, executionId } = base;
    const correlationId = executionCorrelationId(ctx.correlationBase, seq);
    const params = redactParams(args, PARAMS_REDACTED_MAX_BYTES, tool);
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
      ...this.outcomeOf(base, tool, {
        status: answer.status,
        httpStatus: answer.recordedStatus,
        errorCode,
        envelope: finalEnvelope,
        card,
        hasMore: nextCursor !== null,
        latencyMs,
      }),
      sessionExpired: answer.recordedStatus === 401,
    };
    return {
      outcome,
      extra: {
        correlationId,
        params: params.value,
        args,
        refs: Object.keys(refs).length > 0 ? (refs as unknown as Prisma.InputJsonValue) : null,
        nextCursor,
        latencyMs,
      },
    };
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
    tool: DeniedTool | null,
    decision: Exclude<ExecutionDecision, 'allowed'>,
    message: string,
    args: Record<string, unknown>,
    portalRoute: string | null = null,
    extra: DenyExtra = {},
  ): Promise<ExecutionOutcome> {
    const { ctx, seq, executionId, name } = base;
    // A specific refusal code (step AI-R: `assistant_report_email_limit`, …), else the decision.
    const { code: specific, ...auditExtra } = extra;
    const code = specific ?? decision;
    const envelope: ToolResultDenied = {
      kind: 'tool_result/1',
      tool: name,
      status: 'denied',
      decision,
      code,
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
      errorCode: code,
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
        errorCode: code,
        card: null,
        hasMore: false,
        latencyMs: null,
      }),
    };
    await this.persist(ctx, outcome, tool, {
      correlationId: executionCorrelationId(ctx.correlationBase, seq),
      params: redactParams(args, PARAMS_REDACTED_MAX_BYTES, tool).value,
      args,
      refs: null,
      nextCursor: null,
      latencyMs: null,
      auditExtra,
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
      title: toolTitleOf(v.name),
      operationId: v.tool?.operationId ?? 'unknown',
      access: v.tool?.access ?? 'read',
      risk: v.tool?.risk ?? 'read',
      decision: v.decision,
      status: v.status,
      httpStatus: v.httpStatus,
      errorCode: v.errorCode,
      message: refusalMessageOf(v.decision, v.tool?.operationId ?? 'unknown', v.errorCode),
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
    tool: StoredTool | null,
    extra: PersistExtra,
    also?: (tx: Prisma.TransactionClient, executionRowId: bigint) => Promise<void>,
  ): Promise<void> {
    await this.runner.run(async (tx) => {
      const rowId = await this.writeRows(tx, ctx, outcome, tool, extra);
      if (also) await also(tx, rowId);
    });
  }

  /** The execution row and `assistant.tool_executed` / `tool_denied` inside `tx`. */
  private async writeRows(
    tx: Prisma.TransactionClient,
    ctx: ExecutionContext,
    outcome: ExecutionOutcome,
    tool: StoredTool | null,
    extra: PersistExtra,
  ): Promise<bigint> {
    const resourceRef = resourceRefOf(tool, extra.args);
    const auditParams = redactParams(extra.args, AUDIT_PARAMS_MAX_BYTES, tool).value;
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
          ...extra.auditExtra,
        },
      },
      tx,
    );
    return rowId;
  }
}

/** The tool facts an execution row and its audit need (a not-applicable operation has no tool). */
type StoredTool = Pick<OperationTool, 'operationId' | 'method' | 'access' | 'risk'> & {
  readonly redactParams?: readonly string[];
};

/** A refused call's tool (with the module for the metric). */
type DeniedTool = StoredTool & Pick<OperationTool, 'module'>;

/** What the execution row stores besides the outcome. */
interface PersistExtra {
  correlationId: string;
  params: Prisma.InputJsonValue;
  args: Record<string, unknown>;
  refs: Prisma.InputJsonValue | null;
  nextCursor: string | null;
  latencyMs: number | null;
  /** Further audit metadata (`guard` of a `denied_guard`, …; keys safe from the scrub). */
  auditExtra?: Record<string, string | undefined>;
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
