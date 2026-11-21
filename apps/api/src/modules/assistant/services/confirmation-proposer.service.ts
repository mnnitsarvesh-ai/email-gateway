import { Inject, Injectable } from '@nestjs/common';
import {
  actionDigest,
  buildEachItem,
  buildSnapshot,
  compileValidator,
  type ConfirmationRisk,
  type ConfirmationSnapshot,
  type ConfirmationSpec,
  type ConfirmationSummary,
  type ConfirmationView,
  type EachSnapshotItem,
  eachReads,
  findTool,
  hashConfirmationToken,
  impactOf,
  newConfirmationToken,
  type OperationTool,
  preconditionArgs,
  readArgPath,
  rowVersionOf,
  sanitizeText,
  stateDigest,
  withInjectedCas,
} from '@email-gateway/assistant';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import {
  ASSISTANT_AUDIT,
  AUDIT_RESOURCE,
  type AssistantConfig,
  CONFIRMATION_PRECONDITIONS_MAX_BYTES,
  CONFIRMATION_REQUEST_MAX_BYTES,
  DEFINITION_VIOLATIONS_MAX,
} from '../assistant.constants';
import { CONFIRMATION_ROW_CODES } from '../assistant.errors';
import {
  confirmationRiskOf,
  digestInputOf,
  type StoredPreconditions,
  type StoredRequest,
} from '../domain/confirmation-binding';
import { scopeOrganizationPublicId } from '../domain/tool-catalog';
import { ConfirmationsRepository } from '../repositories/confirmations.repository';
import { AssistantLimitsService } from './assistant-limits.service';
import { buildLoopbackRequest, LoopbackDispatcher, type LoopbackResult } from './loopback-client';
import type { ExecutionContext } from './tool-executor.service';

/** The request facts of the loopback reads (never from the model). */
export interface ReadCall {
  authorization: string;
  clientIp: string | null;
  correlationId: string;
  signal: AbortSignal;
}

/** The target's state as read before proposing (and again before executing). */
export interface PreconditionState {
  stateDigest: string | null;
  rowVersion: number | null;
  snapshot: ConfirmationSnapshot | null;
  items?: EachSnapshotItem[];
  total?: number;
  action?: string | null;
}

export type PreconditionRead =
  { ok: true; state: PreconditionState } | { ok: false; result: LoopbackResult };

/** A coded failure of the proposal that the executor records like an API error (D1). */
export interface OwnFailure {
  httpStatus: number;
  code: string;
  message: string;
}

/** Everything stored for a pending confirmation (D1 steps 5–9). */
export interface ProposalPlan {
  confirmationId: string;
  token: string;
  tokenHash: string;
  actionDigest: string;
  stateDigest: string | null;
  risk: ConfirmationRisk;
  requiresReauth: boolean;
  reauthFresh: boolean;
  request: StoredRequest;
  preconditions: StoredPreconditions;
  summary: ConfirmationSummary;
  finalArgs: Record<string, unknown>;
  expiresAt: Date;
  createdAt: Date;
}

export type ProposalOutcome =
  | {
      kind: 'denied';
      decision: 'denied_budget' | 'denied_disabled' | 'denied_schema';
      message: string;
    }
  | { kind: 'failed'; result: LoopbackResult }
  | { kind: 'failed_own'; failure: OwnFailure }
  | { kind: 'pending'; plan: ProposalPlan };

export const PENDING_CAP_MESSAGE =
  'Too many actions are waiting for confirmation; confirm or cancel them first.';

const VALIDATE_TOOL = 'policy_tools_validate';

const byteLength = (value: unknown): number => Buffer.byteLength(JSON.stringify(value), 'utf8');

interface Violation {
  path: string;
  code: string;
  message: string;
}

function violationsOf(value: unknown): Violation[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (item === null || typeof item !== 'object') return [];
    const v = item as Record<string, unknown>;
    return typeof v.path === 'string' && typeof v.code === 'string'
      ? [{ path: v.path, code: v.code, message: typeof v.message === 'string' ? v.message : '' }]
      : [];
  });
}

/** The error message of an invalid definition: at most 20 server-authored violations. */
export function definitionInvalidMessage(violations: readonly Violation[]): string {
  const shown = violations
    .slice(0, DEFINITION_VIOLATIONS_MAX)
    .map((v) => sanitizeText(`${v.path} ${v.code}: ${v.message}`, 200));
  const more =
    violations.length > shown.length ? ` (${violations.length - shown.length} more)` : '';
  return sanitizeText(
    `The policy definition is not valid; fix every violation and propose it again. ` +
      `Violations: ${shown.join('; ')}${more}.`,
    5000,
  );
}

/**
 * The proposal half of an assistant write (step AI-2 D1, ADR-0093 amended): for a validated
 * `call_tool` of an enabled write, the pending cap, the definition validation (`POST
 * /policies/validate`), the precondition read(s) through the spec's read tool, the CAS injection,
 * the concrete request, the server-authored impact summary, the token and the digest. Only
 * side-effect-free loopback calls with the user's own credential are sent (`executionId` null):
 * the write itself never runs here. `store` writes the confirmation row and its audit row inside
 * the executor's transaction that records the proposal execution.
 *
 * The precondition read is also the confirm route's re-read (D2 step 12).
 */
@Injectable()
export class ConfirmationProposer {
  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    private readonly confirmations: ConfirmationsRepository,
    private readonly loopback: LoopbackDispatcher,
    private readonly limits: AssistantLimitsService,
    private readonly audit: AuditService,
  ) {}

  now(): Date {
    return new Date();
  }

  /** D1 steps 1–8 for validated arguments (CAS placeholder applied). Nothing is stored. */
  async prepare(input: {
    ctx: ExecutionContext;
    tool: OperationTool;
    spec: ConfirmationSpec;
    args: Record<string, unknown>;
    executionId: string;
    correlationId: string;
  }): Promise<ProposalOutcome> {
    const { ctx, tool, spec, args } = input;
    const risk = confirmationRiskOf(tool);
    if (risk === null) {
      return {
        kind: 'denied',
        decision: 'denied_disabled',
        message: 'This tool is not enabled for chat; use the portal page.',
      };
    }
    const now = this.now();

    // 1. The pending cap of the conversation.
    const pending = await this.confirmations.countLivePending(ctx.owner, ctx.conversationId, now);
    if (pending >= this.config.ASSISTANT_MAX_PENDING_CONFIRMATIONS) {
      return { kind: 'denied', decision: 'denied_budget', message: PENDING_CAP_MESSAGE };
    }
    const call: ReadCall = {
      authorization: ctx.authorization,
      clientIp: ctx.clientIp,
      correlationId: input.correlationId,
      signal: ctx.signal,
    };

    // 3. Definition validation (policies).
    let definitionSha256: string | null = null;
    let ruleCount: number | null = null;
    const definition =
      spec.validateDefinition === undefined
        ? undefined
        : readArgPath(args, spec.validateDefinition);
    if (definition !== undefined) {
      const validated = await this.validateDefinition(call, definition);
      if (validated.kind !== 'valid') return validated;
      definitionSha256 = validated.definitionSha256;
      ruleCount = validated.ruleCount;
    }

    // 4. Precondition read(s).
    let state: PreconditionState = { stateDigest: null, rowVersion: null, snapshot: null };
    if (spec.precondition !== null) {
      const read = await this.readPreconditions(call, spec, args);
      if (!read.ok) return { kind: 'failed', result: read.result };
      state = read.state;
    }

    // 5. CAS injection (server-authoritative) and the schema check of the final arguments.
    let finalArgs = args;
    if (spec.inject) {
      if (state.rowVersion === null) {
        return {
          kind: 'failed_own',
          failure: {
            httpStatus: 502,
            code: CONFIRMATION_ROW_CODES.preconditionUnavailable,
            message: 'The current version of the record could not be read; try again.',
          },
        };
      }
      finalArgs = withInjectedCas(args, spec, state.rowVersion);
      const check = compileValidator(tool)(finalArgs);
      if (!check.ok) {
        return {
          kind: 'denied',
          decision: 'denied_schema',
          message: sanitizeText(
            `The arguments do not match the tool’s input schema. ${check.issues
              .map((issue) => `${issue.path} ${issue.message}`)
              .join('; ')}`,
            600,
          ),
        };
      }
    }

    // 6. The concrete request (path with the query, body).
    const built = buildLoopbackRequest(tool, finalArgs);
    const { body: _body, ...params } = finalArgs;
    const request: StoredRequest = {
      method: built.method,
      path: built.path,
      body: built.body ?? null,
      params,
    };
    if (byteLength(request) > CONFIRMATION_REQUEST_MAX_BYTES) {
      return {
        kind: 'failed_own',
        failure: {
          httpStatus: 413,
          code: 'payload_too_large',
          message: 'The change is too large to confirm in chat; use the portal page.',
        },
      };
    }
    const preconditions: StoredPreconditions = {
      rowVersion: state.rowVersion,
      definitionSha256,
      ruleCount,
      snapshot: state.snapshot,
      ...(state.items
        ? {
            items: state.items,
            total: state.total ?? state.items.length,
            action: state.action ?? null,
          }
        : {}),
    };
    if (byteLength(preconditions) > CONFIRMATION_PRECONDITIONS_MAX_BYTES) {
      return {
        kind: 'failed_own',
        failure: {
          httpStatus: 413,
          code: 'payload_too_large',
          message: 'The change is too large to confirm in chat; use the portal page.',
        },
      };
    }

    // 7. The impact summary (server-authored).
    const summary = impactOf(tool.operationId, {
      args: finalArgs,
      snapshot: state.snapshot,
      items: state.items ?? [],
      validation: definition === undefined ? null : { ruleCount, definitionSha256 },
      request: { method: request.method, path: request.path },
    });

    // 8. Token, digest, re-authentication.
    const confirmationId = uuidv7(now.getTime());
    const token = newConfirmationToken();
    const expiresAt = new Date(
      now.getTime() + this.config.ASSISTANT_CONFIRMATION_TTL_SECONDS * 1000,
    );
    const requiresReauth = risk === 'high';
    const digest = actionDigest(
      digestInputOf({
        confirmationId,
        organizationPublicId: scopeOrganizationPublicId(ctx.principal),
        userPublicId: ctx.principal.userPublicId,
        sessionFamilyId: ctx.principal.sessionId,
        overrideId: ctx.principal.override?.id ?? null,
        conversationId: ctx.conversationPublicId,
        executionId: input.executionId,
        tool: tool.name,
        operationId: tool.operationId,
        risk,
        requiresReauth,
        request,
        stateDigest: state.stateDigest,
        preconditions,
        expiresAt,
      }),
    );
    return {
      kind: 'pending',
      plan: {
        confirmationId,
        token,
        tokenHash: hashConfirmationToken(token),
        actionDigest: digest,
        stateDigest: state.stateDigest,
        risk,
        requiresReauth,
        reauthFresh: requiresReauth && (await this.limits.reauthFresh(ctx.principal.sessionId)),
        request,
        preconditions,
        summary,
        finalArgs,
        expiresAt,
        createdAt: now,
      },
    };
  }

  /** D1 step 3: `POST /policies/validate` with the user's credential. */
  private async validateDefinition(
    call: ReadCall,
    definition: unknown,
  ): Promise<
    | { kind: 'valid'; definitionSha256: string | null; ruleCount: number | null }
    | { kind: 'failed'; result: LoopbackResult }
    | { kind: 'failed_own'; failure: OwnFailure }
  > {
    const validator = findTool(VALIDATE_TOOL);
    if (!validator) return { kind: 'failed', result: { kind: 'unavailable' } };
    const result = await this.loopback.send({
      method: validator.method,
      path: validator.pathTemplate,
      body: { definition },
      authorization: call.authorization,
      correlationId: call.correlationId,
      clientIp: call.clientIp,
      executionId: null,
      signal: call.signal,
    });
    if (result.kind !== 'response' || result.status !== 200) return { kind: 'failed', result };
    const body = (result.body ?? {}) as Record<string, unknown>;
    const violations = [
      ...violationsOf(body.violations),
      ...violationsOf(body.referenceViolations),
    ];
    if (body.valid !== true || violations.length > 0) {
      return {
        kind: 'failed_own',
        failure: {
          httpStatus: 422,
          code: CONFIRMATION_ROW_CODES.definitionInvalid,
          message: definitionInvalidMessage(
            violations.length > 0
              ? violations
              : [{ path: '$', code: 'invalid', message: 'The definition is not valid' }],
          ),
        },
      };
    }
    return {
      kind: 'valid',
      definitionSha256:
        typeof body.definitionSha256 === 'string' && /^[0-9a-f]{64}$/.test(body.definitionSha256)
          ? body.definitionSha256
          : null,
      ruleCount:
        typeof body.ruleCount === 'number' && Number.isSafeInteger(body.ruleCount)
          ? body.ruleCount
          : null,
    };
  }

  /**
   * D1 step 4 / D2 step 12: the precondition read(s) of the spec through enabled read tools
   * (GET, the caller's credential), on the MySQL writer (`readPrimary`): a change committed
   * inside the replica-lag window is never invisible to the proposal or the confirm-time re-read.
   * A non-2xx answer (or a transport failure) is returned as is.
   */
  async readPreconditions(
    call: ReadCall,
    spec: ConfirmationSpec,
    args: Readonly<Record<string, unknown>>,
  ): Promise<PreconditionRead> {
    const precondition = spec.precondition;
    if (precondition === null) {
      return { ok: true, state: { stateDigest: null, rowVersion: null, snapshot: null } };
    }
    if (precondition.kind === 'single') {
      const read = await this.get(call, precondition.tool, preconditionArgs(precondition, args));
      if (!read.ok) return read;
      return {
        ok: true,
        state: {
          stateDigest: stateDigest(read.body, precondition.stateFields),
          rowVersion: rowVersionOf(read.body, precondition),
          snapshot: buildSnapshot(read.body, precondition),
        },
      };
    }
    const plan = eachReads(precondition, args);
    const items: EachSnapshotItem[] = [];
    for (const item of plan.reads) {
      const read = await this.get(call, item.tool, item.args);
      if (!read.ok) return read;
      items.push(buildEachItem(item.id, read.body, precondition));
    }
    return {
      ok: true,
      state: {
        stateDigest: null,
        rowVersion: null,
        snapshot: null,
        items,
        total: plan.total,
        action: plan.action,
      },
    };
  }

  private async get(
    call: ReadCall,
    toolName: string,
    args: Record<string, unknown>,
  ): Promise<{ ok: true; body: unknown } | { ok: false; result: LoopbackResult }> {
    const tool = findTool(toolName);
    if (!tool || !tool.enabled || tool.access !== 'read' || tool.method !== 'GET') {
      return { ok: false, result: { kind: 'unavailable' } };
    }
    let request: ReturnType<typeof buildLoopbackRequest>;
    try {
      request = buildLoopbackRequest(tool, args);
    } catch {
      // A path parameter the write's arguments did not carry: nothing to read.
      return {
        ok: false,
        result: {
          kind: 'response',
          status: 404,
          body: { statusCode: 404, code: 'not_found', message: 'The target was not found' },
        },
      };
    }
    const result = await this.loopback.send({
      method: 'GET',
      path: request.path,
      authorization: call.authorization,
      correlationId: call.correlationId,
      clientIp: call.clientIp,
      executionId: null,
      signal: call.signal,
      // The writer, never a lagging replica: the read guards a confirmed write (step AI-2 review).
      readPrimary: true,
    });
    if (result.kind === 'response' && result.status >= 200 && result.status < 300) {
      return { ok: true, body: result.body };
    }
    return { ok: false, result };
  }

  /** The view of a new proposal (the stream event and the execution view). */
  viewOf(
    ctx: ExecutionContext,
    executionId: string,
    tool: OperationTool,
    plan: ProposalPlan,
  ): ConfirmationView {
    return {
      id: plan.confirmationId,
      executionId,
      resultExecutionId: null,
      conversationId: ctx.conversationPublicId,
      tool: tool.name,
      operationId: tool.operationId,
      risk: plan.risk,
      requiresReauth: plan.requiresReauth,
      reauthFresh: plan.reauthFresh,
      status: 'pending',
      summary: plan.summary,
      actionDigest: plan.actionDigest,
      expiresAt: plan.expiresAt.toISOString(),
      createdAt: plan.createdAt.toISOString(),
      decidedAt: null,
      executedAt: null,
      result: null,
    };
  }

  /**
   * D1 step 9: the confirmation row and `assistant.confirmation_requested`, inside the
   * transaction of the proposal execution (whose row id `executionRowId` is).
   */
  async store(
    tx: Prisma.TransactionClient,
    ctx: ExecutionContext,
    executionId: string,
    executionRowId: bigint,
    tool: OperationTool,
    plan: ProposalPlan,
    correlationId: string,
  ): Promise<void> {
    await this.confirmations.create(
      ctx.owner,
      {
        publicId: plan.confirmationId,
        platformOverrideId: ctx.principal.override?.id ?? null,
        sessionFamilyId: ctx.principal.sessionId,
        conversationId: ctx.conversationId,
        turnId: ctx.turnId,
        executionId: executionRowId,
        toolName: tool.name.slice(0, 96),
        operationId: tool.operationId.slice(0, 128),
        httpMethod: tool.method,
        risk: plan.risk,
        requiresReauth: plan.requiresReauth,
        request: plan.request as unknown as Prisma.InputJsonValue,
        preconditions: plan.preconditions as unknown as Prisma.InputJsonValue,
        summary: plan.summary as unknown as Prisma.InputJsonValue,
        stateDigest: plan.stateDigest,
        actionDigest: plan.actionDigest,
        tokenHash: plan.tokenHash,
        expiresAt: plan.expiresAt,
        correlationId,
        createdAt: plan.createdAt,
      },
      tx,
    );
    await this.audit.record(
      {
        organizationId: ctx.owner.scope.organizationId,
        actor: this.audit.actorFrom(ctx.principal),
        action: ASSISTANT_AUDIT.confirmationRequested,
        resourceType: AUDIT_RESOURCE.confirmation,
        resourceId: plan.confirmationId,
        sourceIp: ctx.clientIp,
        metadata: {
          conversationId: ctx.conversationPublicId,
          executionId,
          resultExecutionId: null,
          tool: tool.name,
          operationId: tool.operationId,
          risk: plan.risk,
          requiresReauth: plan.requiresReauth,
          reauthUsed: false,
          status: 'pending',
          httpStatus: null,
          error: null,
          correlationId,
        },
      },
      tx,
    );
  }
}
