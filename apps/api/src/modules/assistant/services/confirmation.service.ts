import { timingSafeEqual } from 'node:crypto';
import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  actionDigest,
  type ConfirmationRisk,
  type ConfirmationSpec,
  confirmationSpecOf,
  type ConfirmationView,
  effectiveRisk,
  findTool,
  type GuardRefusal,
  guardRefusal,
  isDigestHex,
  type OperationTool,
  tokenMatches,
} from '@email-gateway/assistant';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { getCorrelationId } from '@email-gateway/logger';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../../database/transaction-runner';
import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../../http/coded-exception';
import { ReauthenticationService } from '../../auth/services/reauthentication.service';
import {
  ASSISTANT_AUDIT,
  AUDIT_RESOURCE,
  type AssistantConfig,
  CONFIRMATION_TOKEN_ATTEMPTS,
} from '../assistant.constants';
import {
  ASSISTANT_ERROR_CODES,
  assistantActionNotAllowed,
  assistantReauthFailed,
  assistantReauthRequired,
  assistantTurnInProgress,
  CONFIRMATION_ROW_CODES,
  confirmationDigestMismatch,
  confirmationExpired,
  confirmationNotFound,
  confirmationNotPending,
  confirmationSessionMismatch,
  confirmationStateChanged,
  confirmationTokenInvalid,
  confirmationToolChanged,
  REPORT_GUARD_MESSAGES,
  REPORT_GUARDS,
} from '../assistant.errors';
import {
  argsOfStoredRequest,
  digestInputOf,
  nativeArgsOf,
  parseStoredPreconditions,
  parseStoredRequest,
  type StoredPreconditions,
  type StoredRequest,
} from '../domain/confirmation-binding';
import {
  nativeSwitchesOf,
  scopeOrganizationPublicId,
  toolAvailability,
} from '../domain/tool-catalog';
import { confirmationView } from '../domain/views';
import type {
  CancelConfirmationResultView,
  ConfirmBody,
  ConfirmResultView,
} from '../dto/assistant.schemas';
import {
  type ConfirmationWithRefs,
  ConfirmationsRepository,
} from '../repositories/confirmations.repository';
import type { Owner } from '../repositories/conversations.repository';
import { ExecutionsRepository } from '../repositories/executions.repository';
import { AssistantAvailabilityService } from './assistant-availability.service';
import { NativeToolsService } from './native-tools.service';
import { AssistantLimitsService } from './assistant-limits.service';
import { AssistantMetrics, type ConfirmationOutcome } from './assistant-metrics';
import { ConfirmationProposer, type PreconditionState } from './confirmation-proposer.service';
import { ownerOf } from './conversation.service';
import {
  executionCorrelationId,
  StoredRequestMismatchError,
  ToolExecutorService,
} from './tool-executor.service';
import type { TurnRequest } from './turn-engine.service';

/** Why a confirm was refused (`assistant.confirmation_refused` metadata `reason`). */
type RefusalReason =
  | 'session_mismatch'
  | 'not_pending'
  | 'token_invalid'
  | 'digest_mismatch'
  | 'tool_changed'
  | 'permission'
  | 'unavailable'
  | 'reauth_required'
  | 'reauth_failed'
  | 'turn_in_progress'
  | 'state_changed'
  /** Step AI-3 D10: a proposal guard refused the change. */
  | 'guard';

const hexEquals = (a: string, b: string): boolean =>
  isDigestHex(a) && isDigestHex(b) && timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));

/** A confirmed write's binding, parsed from storage. */
interface Stored {
  request: StoredRequest;
  preconditions: StoredPreconditions;
}

/**
 * Confirm, cancel and read the assistant's write proposals (step AI-2 D2, ADR-0093 amended;
 * invariants I9–I11). The confirm route runs these checks IN ORDER, each refusal audited
 * `assistant.confirmation_refused` (except 404): owner (404) → session family (403) → status
 * (409) → expiry (410, the row expires) → token, constant-time (403; the fifth wrong token
 * cancels) → digest from the body AND recomputed from storage (409; a recomputation mismatch
 * fails the row) → the tool still enabled with the same operation and the caller's permission
 * (409 / 403, the row fails) → availability → re-authentication for high risk (401; the
 * session's window marker skips it) → the conversation lock (409) → the atomic `pending →
 * executing` transition (409) → the precondition re-read on the writer (changed state fails the
 * row, 409) → the write claim (`execution_started_at`; a row the outcome-unknown sweep failed
 * meanwhile is 409 and nothing is sent) → the stored request through `ToolExecutorService.run`
 * with `Idempotency-Key` = the confirmation id → the row `executed` (2xx incl. 202) or `failed`,
 * in the transaction of the result execution (a sweep's outcome unknown is replaced by the real
 * outcome, audited with `reconciledFrom`). Logs and audit rows carry ids and codes only: never the token, the digest
 * input, request bodies, passwords or codes.
 *
 * Step AI-3 (design 30 D10): after the tool check, the effective risk is recomputed from the
 * stored arguments (a difference from the stored risk fails the row, `409 tool_changed`) and the
 * before-read proposal guards are evaluated again with the confirming principal; after the
 * precondition re-read the after-read guards run on the fresh target. A guard refusal fails the
 * row (`assistant_action_not_allowed`), is audited `assistant.confirmation_refused` (`reason:
 * guard`) and answers `403 assistant_action_not_allowed`.
 */
@Injectable()
export class ConfirmationService {
  private readonly logger = new Logger(ConfirmationService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    private readonly confirmations: ConfirmationsRepository,
    private readonly executions: ExecutionsRepository,
    private readonly executor: ToolExecutorService,
    private readonly proposer: ConfirmationProposer,
    private readonly availability: AssistantAvailabilityService,
    private readonly limits: AssistantLimitsService,
    private readonly reauth: ReauthenticationService,
    private readonly runner: TransactionRunner,
    private readonly audit: AuditService,
    private readonly metrics: AssistantMetrics,
    private readonly native: NativeToolsService,
  ) {}

  now(): Date {
    return new Date();
  }

  private async load(
    principal: UserPrincipal,
    scope: TenantScope,
    publicId: string,
  ): Promise<{ owner: Owner; row: ConfirmationWithRefs }> {
    const owner = ownerOf(principal, scope);
    const row = await this.confirmations.findOwned(owner, principal.override?.id ?? null, publicId);
    if (!row) throw confirmationNotFound();
    return { owner, row };
  }

  private async view(
    principal: UserPrincipal,
    row: ConfirmationWithRefs,
    now: Date,
  ): Promise<ConfirmationView> {
    const fresh =
      row.requiresReauth &&
      row.sessionFamilyId === principal.sessionId &&
      (await this.limits.reauthFresh(principal.sessionId));
    return confirmationView(row, now, fresh);
  }

  /** `GET /assistant/confirmations/{id}`: own only, any session; never the token. */
  async get(
    principal: UserPrincipal,
    scope: TenantScope,
    publicId: string,
  ): Promise<ConfirmationView> {
    const { row } = await this.load(principal, scope, publicId);
    return this.view(principal, row, this.now());
  }

  /** `POST …/cancel`: owner + session family; `pending → cancelled`; idempotent. */
  async cancel(
    principal: UserPrincipal,
    scope: TenantScope,
    publicId: string,
    sourceIp: string | null,
  ): Promise<CancelConfirmationResultView> {
    const { owner, row } = await this.load(principal, scope, publicId);
    const now = this.now();
    if (row.sessionFamilyId !== principal.sessionId) {
      await this.refused(principal, scope, row, 'session_mismatch', sourceIp, 'refused_session');
      throw confirmationSessionMismatch();
    }
    if (row.status === 'cancelled') {
      return { confirmation: await this.view(principal, row, now) };
    }
    if (row.status === 'pending' && row.expiresAt.getTime() <= now.getTime()) {
      await this.expire(principal, scope, owner, row, now, sourceIp);
      throw confirmationNotPending('expired');
    }
    if (row.status !== 'pending') {
      await this.refused(principal, scope, row, 'not_pending', sourceIp);
      throw confirmationNotPending(row.status);
    }
    const cancelled = await this.runner.run(async (tx) => {
      if ((await this.confirmations.cancel(owner, row.id, now, tx)) !== 1) return false;
      await this.record(
        principal,
        scope,
        row,
        ASSISTANT_AUDIT.confirmationCancelled,
        sourceIp,
        tx,
        {
          status: 'cancelled',
        },
      );
      return true;
    });
    const current = (await this.confirmations.reload(owner, row.id)) ?? row;
    if (!cancelled && current.status !== 'cancelled') throw confirmationNotPending(current.status);
    if (cancelled) {
      this.metrics.confirmations.inc({ risk: row.risk, outcome: 'cancelled' });
      this.observeDecision(row, now);
    }
    return { confirmation: await this.view(principal, current, now) };
  }

  /** `POST …/confirm` (D2, in order). */
  async confirm(
    principal: UserPrincipal,
    scope: TenantScope,
    publicId: string,
    body: ConfirmBody,
    request: TurnRequest,
  ): Promise<ConfirmResultView> {
    const sourceIp = request.clientIp;
    // 1. Owner (another user's or organization's confirmation is a 404, not audited).
    const { owner, row } = await this.load(principal, scope, publicId);
    const now = this.now();
    // 2. Session family.
    if (row.sessionFamilyId !== principal.sessionId) {
      await this.refused(principal, scope, row, 'session_mismatch', sourceIp, 'refused_session');
      throw confirmationSessionMismatch();
    }
    // 3. Status.
    if (row.status !== 'pending') {
      await this.refused(principal, scope, row, 'not_pending', sourceIp);
      throw confirmationNotPending(row.status);
    }
    // 4. Expiry.
    if (row.expiresAt.getTime() <= now.getTime()) {
      await this.expire(principal, scope, owner, row, now, sourceIp);
      throw confirmationExpired();
    }
    // 5. Token (constant time); the fifth wrong token cancels the confirmation.
    if (!tokenMatches(body.token, row.tokenHash)) {
      const attempts = await this.confirmations.incrementFailedAttempts(owner, row.id);
      await this.refused(principal, scope, row, 'token_invalid', sourceIp, 'refused_token');
      if (attempts >= CONFIRMATION_TOKEN_ATTEMPTS) {
        await this.runner.run(async (tx) => {
          if (
            (await this.confirmations.cancel(
              owner,
              row.id,
              now,
              tx,
              CONFIRMATION_ROW_CODES.tokenLocked,
            )) === 1
          ) {
            await this.record(
              principal,
              scope,
              row,
              ASSISTANT_AUDIT.confirmationCancelled,
              sourceIp,
              tx,
              { status: 'cancelled', error: CONFIRMATION_ROW_CODES.tokenLocked },
            );
          }
        });
        this.metrics.confirmations.inc({ risk: row.risk, outcome: 'cancelled' });
      }
      throw confirmationTokenInvalid();
    }
    // 6. Digest: the card's, and the one recomputed from storage.
    const stored = this.storedOf(row);
    const recomputed = stored ? actionDigest(this.digestInput(principal, row, stored)) : null;
    if (!hexEquals(body.actionDigest, row.actionDigest)) {
      await this.refused(principal, scope, row, 'digest_mismatch', sourceIp, 'refused_digest');
      throw confirmationDigestMismatch();
    }
    if (!stored || recomputed === null || !hexEquals(recomputed, row.actionDigest)) {
      await this.failRow(
        principal,
        scope,
        owner,
        row,
        ASSISTANT_ERROR_CODES.confirmationDigestMismatch,
        sourceIp,
      );
      this.metrics.confirmations.inc({ risk: row.risk, outcome: 'refused_digest' });
      throw confirmationDigestMismatch();
    }
    // 7. The tool is still enabled with the same operation; the caller may still use it.
    const tool = this.toolOf(row, stored.request);
    if (!tool) {
      await this.failRow(
        principal,
        scope,
        owner,
        row,
        ASSISTANT_ERROR_CODES.confirmationToolChanged,
        sourceIp,
      );
      this.metrics.confirmations.inc({ risk: row.risk, outcome: 'failed' });
      throw confirmationToolChanged();
    }
    if (!toolAvailability(principal, tool, nativeSwitchesOf(this.config)).available) {
      await this.failRow(principal, scope, owner, row, 'forbidden', sourceIp);
      this.metrics.confirmations.inc({ risk: row.risk, outcome: 'failed' });
      throw new CodedHttpException(HttpStatus.FORBIDDEN, 'forbidden', 'Forbidden');
    }
    // 7a. Step AI-3 D4/D10: the effective risk of the stored arguments is the stored risk.
    const spec = confirmationSpecOf(tool.operationId)!;
    // Step AI-R D5: a native write's arguments are its stored body (`POST native:<name>`).
    const args =
      spec.native !== undefined
        ? nativeArgsOf(stored.request)
        : argsOfStoredRequest(stored.request);
    if (this.effectiveRiskOf(tool, spec, args) !== row.risk) {
      await this.failRow(
        principal,
        scope,
        owner,
        row,
        ASSISTANT_ERROR_CODES.confirmationToolChanged,
        sourceIp,
      );
      this.metrics.confirmations.inc({ risk: row.risk, outcome: 'failed' });
      throw confirmationToolChanged();
    }
    // 7b. Step AI-3 D3/D10: the before-read proposal guards, with the confirming principal.
    const beforeRead = guardRefusal(
      spec,
      { args, principalUserPublicId: principal.userPublicId, read: null },
      'before_read',
    );
    if (beforeRead) {
      await this.refuseGuard(principal, scope, owner, row, beforeRead, sourceIp);
      throw assistantActionNotAllowed();
    }
    // 8. Availability (platform switch, feature, tenant setting; the budget is not consumed).
    try {
      await this.availability.assertAvailable(scope, now, false);
    } catch (error) {
      await this.refused(principal, scope, row, 'unavailable', sourceIp);
      throw error;
    }
    // 9. Re-authentication (high risk) unless the session's window is open.
    let reauthUsed = false;
    if (row.requiresReauth && !(await this.limits.reauthFresh(principal.sessionId))) {
      if (!body.reauth) {
        await this.refused(principal, scope, row, 'reauth_required', sourceIp, 'reauth_required');
        throw assistantReauthRequired();
      }
      const verified = await this.reauth.verify(principal, {
        password: body.reauth.password,
        ...(body.reauth.totpCode !== undefined && { totpCode: body.reauth.totpCode }),
      });
      if (!verified.ok) {
        await this.refused(principal, scope, row, 'reauth_failed', sourceIp, 'reauth_failed', {
          reauthReason: verified.reason,
        });
        throw assistantReauthFailed(verified.reason);
      }
      await this.limits.markReauthenticated(principal.sessionId);
      reauthUsed = true;
    }
    // 10. The conversation lock (the turn lock, as "more").
    const lock = uuidv7();
    if (!(await this.limits.acquireLock(row.conversationPublicId, lock))) {
      await this.refused(principal, scope, row, 'turn_in_progress', sourceIp);
      throw assistantTurnInProgress();
    }
    try {
      // 11. The atomic transition.
      const decidedAt = this.now();
      if ((await this.confirmations.beginExecuting(owner, row.id, decidedAt, reauthUsed)) !== 1) {
        const current = await this.confirmations.reload(owner, row.id);
        await this.refused(principal, scope, row, 'not_pending', sourceIp);
        throw confirmationNotPending(
          current?.status === 'pending' ? 'expired' : (current?.status ?? 'cancelled'),
        );
      }
      this.observeDecision(row, decidedAt);
      const correlationBase = (getCorrelationId() ?? lock).slice(0, 128);
      // 12. The precondition re-read with the confirm request's credential.
      let target: unknown = null;
      if (spec.precondition !== null) {
        const read = await this.proposer.readPreconditions(
          {
            authorization: request.authorization,
            clientIp: request.clientIp,
            correlationId: executionCorrelationId(correlationBase, 0),
            signal: new AbortController().signal,
          },
          spec,
          args,
        );
        const httpStatus = !read.ok && read.result.kind === 'response' ? read.result.status : null;
        if (!read.ok || !this.sameState(row.stateDigest, stored.preconditions, read.state)) {
          await this.failRow(
            principal,
            scope,
            owner,
            row,
            ASSISTANT_ERROR_CODES.confirmationStateChanged,
            sourceIp,
            httpStatus,
          );
          this.metrics.confirmations.inc({ risk: row.risk, outcome: 'refused_state' });
          throw confirmationStateChanged(read.ok ? null : httpStatus);
        }
        target = read.state.raw ?? null;
      }
      // 12 (native, step AI-R D5): the report state and the recipient class with current data. A
      // recipient no longer allowed refuses (403); any other difference is a changed state (409).
      if (spec.native !== undefined) {
        const state = await this.native.readState(
          tool,
          { principal, owner, conversationId: row.conversationId },
          args,
        );
        if (state.kind === 'refused') {
          await this.refuseGuard(
            principal,
            scope,
            owner,
            row,
            {
              guard: REPORT_GUARDS.recipientNotAllowed,
              message: REPORT_GUARD_MESSAGES.report_recipient_not_allowed,
            },
            sourceIp,
          );
          throw assistantActionNotAllowed();
        }
        if (row.stateDigest === null || !hexEquals(state.stateDigest, row.stateDigest)) {
          await this.failRow(
            principal,
            scope,
            owner,
            row,
            ASSISTANT_ERROR_CODES.confirmationStateChanged,
            sourceIp,
          );
          this.metrics.confirmations.inc({ risk: row.risk, outcome: 'refused_state' });
          throw confirmationStateChanged();
        }
      }
      // 12a. Step AI-3 D10: the after-read proposal guards on the fresh target.
      const afterRead = guardRefusal(
        spec,
        { args, principalUserPublicId: principal.userPublicId, read: target },
        'after_read',
      );
      if (afterRead) {
        await this.refuseGuard(principal, scope, owner, row, afterRead, sourceIp);
        throw assistantActionNotAllowed();
      }
      // 13. Claim the write (`execution_started_at`), then execute the stored request. A row the
      // outcome-unknown sweep failed while the re-read ran loses the claim: nothing is sent.
      if ((await this.confirmations.claimExecution(owner, row.id, this.now())) !== 1) {
        const current = await this.confirmations.reload(owner, row.id);
        await this.refused(principal, scope, row, 'not_pending', sourceIp);
        throw confirmationNotPending(current?.status ?? 'failed');
      }
      let nextSeq = await this.executions.nextSeq(owner, row.conversationId);
      const seq = nextSeq++;
      const resultExecutionId = uuidv7();
      const outcome = await this.runStored(
        row,
        {
          ctx: {
            principal,
            owner,
            conversationId: row.conversationId,
            conversationPublicId: row.conversationPublicId,
            turnId: null,
            turnPublicId: null,
            parentExecutionId: row.executionId,
            parentExecutionPublicId: row.executionPublicId,
            authorization: request.authorization,
            clientIp: request.clientIp,
            correlationBase,
            signal: new AbortController().signal,
            allocateSeq: () => nextSeq++,
          },
          seq,
          executionId: resultExecutionId,
          name: tool.name,
          title: tool.display.title ?? tool.summary,
        },
        tool,
        args,
        {
          idempotencyKey: row.publicId,
          expectedRequest: stored.request,
          native: { confirmationRowId: row.id, confirmationPublicId: row.publicId },
          // 14. The outcome, in the transaction of the result execution.
          afterPersist: async (tx, executionRowId, result) => {
            const ok =
              result.status === 'succeeded' &&
              result.httpStatus !== null &&
              result.httpStatus >= 200 &&
              result.httpStatus < 300;
            const finish = {
              status: ok ? ('executed' as const) : ('failed' as const),
              resultExecutionId: executionRowId,
              resultHttpStatus: result.httpStatus,
              errorCode: ok ? null : result.errorCode,
              executedAt: this.now(),
            };
            let reconciled = false;
            if ((await this.confirmations.finish(owner, row.id, finish, tx)) !== 1) {
              // The sweep marked the row outcome unknown while the write ran: the real outcome
              // replaces it (reported to the model again). Anything else: the row is untouched.
              reconciled =
                (await this.confirmations.reconcileOutcomeUnknown(
                  owner,
                  row.id,
                  CONFIRMATION_ROW_CODES.outcomeUnknown,
                  finish,
                  tx,
                )) === 1;
              if (!reconciled) {
                this.logger.warn({
                  message: 'Assistant confirmation outcome not recorded: the row moved',
                  confirmationId: row.publicId,
                  executionId: resultExecutionId,
                  httpStatus: result.httpStatus,
                });
                return;
              }
            }
            await this.record(
              principal,
              scope,
              row,
              ok ? ASSISTANT_AUDIT.confirmationExecuted : ASSISTANT_AUDIT.confirmationFailed,
              sourceIp,
              tx,
              {
                status: ok ? 'executed' : 'failed',
                resultExecutionId,
                httpStatus: result.httpStatus,
                error: ok ? null : result.errorCode,
                reauthUsed,
                correlationId: executionCorrelationId(correlationBase, seq),
                ...(reconciled && { reconciledFrom: CONFIRMATION_ROW_CODES.outcomeUnknown }),
              },
            );
          },
        },
      );
      const executed = outcome.status === 'succeeded';
      this.metrics.confirmations.inc({ risk: row.risk, outcome: executed ? 'executed' : 'failed' });
      this.logger.log({
        message: 'Assistant confirmation decided',
        confirmationId: row.publicId,
        executionId: resultExecutionId,
        outcome: executed ? 'executed' : 'failed',
        httpStatus: outcome.httpStatus,
        code: outcome.errorCode,
      });
      const current = (await this.confirmations.reload(owner, row.id)) ?? row;
      return {
        confirmation: await this.view(principal, current, this.now()),
        execution: outcome.view,
      };
    } finally {
      await this.limits.releaseLock(row.conversationPublicId, lock);
    }
  }

  // ---- helpers -----------------------------------------------------------------------------

  /**
   * `ToolExecutorService.run` with the stored request; a request the stored arguments would not
   * rebuild exactly (tampered storage) is never sent: the row fails `digest_mismatch`.
   */
  private async runStored(
    row: ConfirmationWithRefs,
    ...args: Parameters<ToolExecutorService['run']>
  ): ReturnType<ToolExecutorService['run']> {
    try {
      return await this.executor.run(...args);
    } catch (error) {
      if (!(error instanceof StoredRequestMismatchError)) throw error;
      const { ctx } = args[0];
      await this.failRow(
        ctx.principal,
        ctx.owner.scope,
        ctx.owner,
        row,
        ASSISTANT_ERROR_CODES.confirmationDigestMismatch,
        ctx.clientIp,
      );
      this.metrics.confirmations.inc({ risk: row.risk, outcome: 'refused_digest' });
      throw confirmationDigestMismatch();
    }
  }

  private storedOf(row: ConfirmationWithRefs): Stored | null {
    const request = parseStoredRequest(row.request);
    const preconditions = parseStoredPreconditions(row.preconditions);
    if (!request || !preconditions) return null;
    if (request.method !== row.httpMethod) return null;
    return { request, preconditions };
  }

  /** The digest input rebuilt from the stored columns and the (owner-checked) caller. */
  private digestInput(principal: UserPrincipal, row: ConfirmationWithRefs, stored: Stored) {
    return digestInputOf({
      confirmationId: row.publicId,
      organizationPublicId: scopeOrganizationPublicId(principal),
      userPublicId: principal.userPublicId,
      sessionFamilyId: row.sessionFamilyId,
      overrideId: row.platformOverrideId,
      conversationId: row.conversationPublicId,
      executionId: row.executionPublicId,
      tool: row.toolName,
      operationId: row.operationId,
      risk: row.risk,
      requiresReauth: row.requiresReauth,
      request: stored.request,
      stateDigest: row.stateDigest,
      preconditions: stored.preconditions,
      expiresAt: row.expiresAt,
    });
  }

  /** The enabled write tool of the row, with the same operation, method and path template. */
  private toolOf(row: ConfirmationWithRefs, request: StoredRequest): OperationTool | null {
    const tool = findTool(row.toolName);
    if (!tool || !tool.enabled || tool.access !== 'write') return null;
    if (tool.operationId !== row.operationId || tool.method !== row.httpMethod) return null;
    if (!confirmationSpecOf(tool.operationId)) return null;
    // The stored path must still be an instance of the tool's template.
    const segments = request.path.split('?')[0]!.split('/');
    const template = tool.pathTemplate.split('/');
    if (segments.length !== template.length) return null;
    const matches = template.every(
      (segment, i) => /^\{[^}]+\}$/.test(segment) || segment === segments[i],
    );
    return matches ? tool : null;
  }

  /** The effective risk of stored arguments, or null when the tool's risk is not confirmable. */
  private effectiveRiskOf(
    tool: OperationTool,
    spec: ConfirmationSpec,
    args: Readonly<Record<string, unknown>>,
  ): ConfirmationRisk | null {
    try {
      return effectiveRisk(tool, spec, args).risk;
    } catch {
      return null;
    }
  }

  /**
   * A proposal guard refused at confirm (step AI-3 D10): the row fails
   * `assistant_action_not_allowed` and the refusal is audited (`reason: guard`, `guard` kind).
   */
  private async refuseGuard(
    principal: UserPrincipal,
    scope: TenantScope,
    owner: Owner,
    row: ConfirmationWithRefs,
    refusal: Pick<GuardRefusal, 'message'> & { guard: string },
    sourceIp: string | null,
  ): Promise<void> {
    await this.failRow(
      principal,
      scope,
      owner,
      row,
      ASSISTANT_ERROR_CODES.actionNotAllowed,
      sourceIp,
    );
    await this.refused(principal, scope, row, 'guard', sourceIp, 'refused_guard', {
      guard: refusal.guard,
    });
  }

  private sameState(
    stateDigest: string | null,
    stored: StoredPreconditions,
    current: PreconditionState,
  ): boolean {
    if (stored.items) {
      const now = current.items ?? [];
      return (
        now.length === stored.items.length &&
        stored.items.every(
          (item, i) => now[i]?.id === item.id && now[i]?.stateDigest === item.stateDigest,
        )
      );
    }
    return current.stateDigest === stateDigest;
  }

  private observeDecision(row: ConfirmationWithRefs, decidedAt: Date): void {
    this.metrics.confirmationSeconds.observe(
      Math.max(0, decidedAt.getTime() - row.createdAt.getTime()) / 1000,
    );
  }

  private async expire(
    principal: UserPrincipal,
    scope: TenantScope,
    owner: Owner,
    row: ConfirmationWithRefs,
    now: Date,
    sourceIp: string | null,
  ): Promise<void> {
    const expired = await this.runner.run(async (tx) => {
      if ((await this.confirmations.expire(owner, row.id, now, tx)) !== 1) return false;
      await this.record(principal, scope, row, ASSISTANT_AUDIT.confirmationExpired, sourceIp, tx, {
        status: 'expired',
      });
      return true;
    });
    if (expired) this.metrics.confirmations.inc({ risk: row.risk, outcome: 'expired' });
  }

  /** The row fails without running the write (audited `assistant.confirmation_failed`). */
  private async failRow(
    principal: UserPrincipal,
    scope: TenantScope,
    owner: Owner,
    row: ConfirmationWithRefs,
    errorCode: string,
    sourceIp: string | null,
    httpStatus: number | null = null,
  ): Promise<void> {
    await this.runner.run(async (tx) => {
      if ((await this.confirmations.fail(owner, row.id, errorCode, this.now(), tx)) !== 1) return;
      await this.record(principal, scope, row, ASSISTANT_AUDIT.confirmationFailed, sourceIp, tx, {
        status: 'failed',
        httpStatus,
        error: errorCode,
      });
    });
    this.logger.warn({
      message: 'Assistant confirmation failed before execution',
      confirmationId: row.publicId,
      code: errorCode,
    });
  }

  /** `assistant.confirmation_refused` with `reason` (the row is unchanged). */
  private async refused(
    principal: UserPrincipal,
    scope: TenantScope,
    row: ConfirmationWithRefs,
    reason: RefusalReason,
    sourceIp: string | null,
    outcome?: ConfirmationOutcome,
    extra: Record<string, string> = {},
  ): Promise<void> {
    await this.record(
      principal,
      scope,
      row,
      ASSISTANT_AUDIT.confirmationRefused,
      sourceIp,
      undefined,
      {
        reason,
        ...extra,
      },
    );
    if (outcome) this.metrics.confirmations.inc({ risk: row.risk, outcome });
    this.logger.log({
      message: 'Assistant confirmation refused',
      confirmationId: row.publicId,
      reason,
    });
  }

  /** An audit row of a confirmation (D11 metadata; keys survive the credential scrub). */
  private async record(
    principal: UserPrincipal,
    scope: TenantScope,
    row: ConfirmationWithRefs,
    action: string,
    sourceIp: string | null,
    tx: Prisma.TransactionClient | undefined,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    await this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action,
        resourceType: AUDIT_RESOURCE.confirmation,
        resourceId: row.publicId,
        sourceIp,
        metadata: {
          conversationId: row.conversationPublicId,
          executionId: row.executionPublicId,
          resultExecutionId: row.resultExecutionPublicId,
          tool: row.toolName,
          operationId: row.operationId,
          risk: row.risk,
          requiresReauth: row.requiresReauth,
          reauthUsed: row.reauthUsed,
          status: row.status,
          httpStatus: row.resultHttpStatus,
          error: row.errorCode,
          correlationId: row.correlationId,
          ...metadata,
        },
      },
      tx,
    );
  }
}
