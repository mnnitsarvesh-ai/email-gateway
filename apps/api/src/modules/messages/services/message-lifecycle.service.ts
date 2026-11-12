import { BadRequestException, HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { EventTypes, messageRescanRequestedV1 } from '@email-gateway/event-contracts';
import { getCorrelationId } from '@email-gateway/logger';
import { QUARANTINE_PERMISSIONS } from '@email-gateway/quarantine';
import {
  decideTransition,
  type LifecycleSnapshot,
  type MessageRef,
  type TransitionActor,
  transitionKeyHash,
  type TransitionOutcome,
  type TransitionRequest,
} from '@email-gateway/message-lifecycle';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  idempotencyKeyHash,
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  IdempotencyRaceError,
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import { formatZodIssues } from '../../../validation/zod-validation.pipe';
import type { ClientContext } from '../../auth/services/session.service';
import {
  API_SERVICE,
  apiTransitionKey,
  AUDIT_ACTIONS,
  decisionConflict,
  type LifecycleOperation,
  OPERATION_NAMES,
  operationTransition,
  outcomeError,
  RESCAN_NOTE,
} from '../domain/lifecycle-operations';
import {
  type LifecycleOperationBody,
  LifecycleOperationBodySchema,
  MessageIdSchema,
  type ReleaseResponse,
  type RescanResponse,
} from '../dto/messages.schemas';
import { ApiLifecycleMetrics, type OperationOutcome } from '../lifecycle-metrics';
import {
  messageNotFound,
  messageStateConflict,
  quarantineRescanForbidden,
  quarantineWorkflowRequired,
} from '../messages.errors';
import { MessageLifecycleRepository } from '../repositories/message-lifecycle.repository';
import { LifecycleGateway } from './lifecycle-gateway';

type Tx = Prisma.TransactionClient;

/** The raw request parts; validated here so every outcome is counted (L10.1 metrics). */
export interface LifecycleOperationInput {
  messageId: unknown;
  idempotencyKey: unknown;
  body: unknown;
}

/** Writer transaction timeout of one operation (no API_TX_TIMEOUT_MS exists, L10.1). */
export const OPERATION_TX_TIMEOUT_MS = 10_000;

const MAX_CORRELATION_ID = 128;
const ACCEPTED = HttpStatus.ACCEPTED;

/** Everything one operation knows once the message is locked and the request validated. */
interface OperationContext {
  operation: LifecycleOperation;
  principal: Principal;
  scope: TenantScope;
  messageId: string;
  ref: MessageRef;
  snapshot: LifecycleSnapshot;
  body: LifecycleOperationBody;
  correlationId: string;
  actor: TransitionActor;
}

type Applied = Extract<TransitionOutcome, { result: 'applied' }>;

interface Effect<P, T> {
  /** Preconditions checked after the state decision and before the transition. */
  prepare(tx: Tx, ctx: OperationContext): Promise<P>;
  /** The stage effects after the applied transition (same transaction). */
  commit(
    tx: Tx,
    ctx: OperationContext,
    outcome: Applied,
    prepared: P,
  ): Promise<{ body: T; eventIds: string[]; audit: Record<string, unknown> }>;
}

const publicIdOf = (principal: Principal): string =>
  principal.kind === 'api_key' ? principal.apiKeyPublicId : principal.userPublicId;

function parseMessageId(raw: unknown): string {
  const parsed = MessageIdSchema.safeParse(raw);
  if (!parsed.success) throw new BadRequestException(['messageId: Invalid UUID']);
  return parsed.data;
}

function parseBody(raw: unknown): LifecycleOperationBody {
  const parsed = LifecycleOperationBodySchema.safeParse(raw);
  if (!parsed.success) throw new BadRequestException(formatZodIssues(parsed.error));
  return parsed.data;
}

function failureOutcome(error: unknown): OperationOutcome | null {
  if (!(error instanceof HttpException)) return null;
  switch (error.getStatus()) {
    case 400:
    case 422:
      return 'invalid_request';
    case 404:
      return 'not_found';
    case 409:
      return 'conflict';
    default:
      return null;
  }
}

/**
 * Administrative rescan and quarantine release (step 3.3 L10), each in one writer transaction:
 * Idempotency-Key lookup → message lock → state decision and preconditions → the transition
 * through `@email-gateway/message-lifecycle` (`recordIgnored: false`) → the stage effects
 * (outbox rows, timeline events) → the audit row → the stored response. The tenant comes from
 * the authenticated scope only; another organization's message is `404 message_not_found`.
 * Conflicts (`409`), `404` and validation errors (`400`) are never stored under the key.
 */
@Injectable()
export class MessageLifecycleService {
  private readonly logger = new Logger(MessageLifecycleService.name);

  constructor(
    private readonly idempotency: IdempotencyService,
    private readonly repository: MessageLifecycleRepository,
    private readonly lifecycle: LifecycleGateway,
    private readonly audit: AuditService,
    private readonly metrics: ApiLifecycleMetrics,
  ) {}

  /**
   * `POST /messages/{messageId}/rescan` (L10.2, edge E19): the message re-enters `scanning`
   * with a new lifecycle round and `mail.message.rescan_requested.v1` is written to the outbox.
   *
   * Step 5.3: the new round supersedes the open quarantine entries and re-decides their
   * recipients, so a clean round delivers held mail. From `quarantined`/`held_for_review` the
   * caller therefore also needs `quarantine:release` (`403 quarantine_rescan_forbidden`); the
   * audit row records how many open entries the rescan supersedes.
   */
  rescan(
    principal: Principal,
    scope: TenantScope,
    input: LifecycleOperationInput,
    client: ClientContext,
  ): Promise<IdempotentResult<RescanResponse>> {
    return this.execute<number, RescanResponse>('rescan', principal, scope, input, client, {
      prepare: async (tx, ctx) => {
        const held =
          ctx.snapshot.state === 'quarantined' || ctx.snapshot.state === 'held_for_review';
        const open = held
          ? await this.repository.openQuarantineEntryCount(tx, ctx.scope, ctx.ref)
          : 0;
        if (held && !ctx.principal.permissions.has(QUARANTINE_PERMISSIONS.release)) {
          throw quarantineRescanForbidden(ctx.snapshot, open);
        }
        return open;
      },
      commit: async (tx, ctx, outcome, openEntries) => {
        const now = new Date();
        const rescanEventId = uuidv7(now.getTime());
        const payload = messageRescanRequestedV1.parse({
          messageId: ctx.ref.id.toString(),
          receivedAt: ctx.ref.receivedAt.toISOString(),
          direction: ctx.snapshot.direction,
          emlS3Key: ctx.snapshot.emlObjectKey,
          lifecycleRound: outcome.round,
          scanKind: 'rescan',
          requestedAt: now.toISOString(),
          requestedBy: ctx.principal.kind,
        });
        await this.repository.insertOutbox(tx, {
          eventId: rescanEventId,
          organizationId: ctx.ref.organizationId,
          eventType: EventTypes.MessageRescanRequested,
          aggregateId: ctx.ref.id.toString(),
          correlationId: ctx.correlationId,
          payload,
        });
        return {
          body: {
            messageId: ctx.messageId,
            state: 'scanning',
            version: outcome.version,
            lifecycleRound: outcome.round,
            rescanEventId,
            note: RESCAN_NOTE,
          },
          eventIds: [outcome.stateEventId, rescanEventId],
          audit: { quarantineEntriesSuperseded: openEntries },
        };
      },
    });
  }

  /**
   * `POST /messages/{messageId}/release` (L10.3; step 5.3 Q30): a `quarantined` or
   * `held_for_review` message is released only through the quarantine workflow, which
   * re-validates every recipient's entry (`POST /quarantine/entries/{entryId}/release`). The route
   * stays and answers `409 quarantine_workflow_required` with the entry count for every such
   * message (entries exist after the quarantine sweeper adopted the 5.2-held messages); other
   * states and stale versions keep their L10.4 conflicts. Nothing is written.
   */
  release(
    principal: Principal,
    scope: TenantScope,
    input: LifecycleOperationInput,
    client: ClientContext,
  ): Promise<IdempotentResult<ReleaseResponse>> {
    return this.execute<never, ReleaseResponse>('release', principal, scope, input, client, {
      prepare: async (tx, ctx) => {
        const entries = await this.repository.quarantineEntryCount(tx, ctx.scope, ctx.ref);
        throw quarantineWorkflowRequired(ctx.snapshot, entries);
      },
      commit: () => Promise.reject(new Error('unreachable: release is refused in prepare')),
    });
  }

  private async execute<P, T>(
    operation: LifecycleOperation,
    principal: Principal,
    scope: TenantScope,
    input: LifecycleOperationInput,
    client: ClientContext,
    effect: Effect<P, T>,
  ): Promise<IdempotentResult<T>> {
    try {
      const messageId = parseMessageId(input.messageId);
      const key = parseIdempotencyKey(input.idempotencyKey);
      const body = parseBody(input.body);
      const name = OPERATION_NAMES[operation];
      const result = await this.idempotency.execute<T>(
        {
          organizationId: scope.organizationId,
          principal: principalKey(principal),
          operation: name,
          key,
          resourceId: messageId,
          fingerprint: requestFingerprint({ operation: name, resourceId: messageId, body }),
        },
        (tx) =>
          this.apply(tx, { operation, principal, scope, messageId, key, body, client }, effect),
        { timeoutMs: OPERATION_TX_TIMEOUT_MS },
      );
      this.metrics.operation(operation, result.replayed ? 'replayed' : 'applied');
      return result;
    } catch (error) {
      const outcome = failureOutcome(error);
      if (outcome !== null) this.metrics.operation(operation, outcome);
      throw error;
    }
  }

  private async apply<P, T>(
    tx: Tx,
    request: {
      operation: LifecycleOperation;
      principal: Principal;
      scope: TenantScope;
      messageId: string;
      key: string;
      body: LifecycleOperationBody;
      client: ClientContext;
    },
    effect: Effect<P, T>,
  ): Promise<{ statusCode: number; body: T }> {
    const { operation, principal, scope, messageId, key, body } = request;
    const identity = await this.repository.findIdentity(tx, scope, messageId);
    if (!identity) throw messageNotFound();
    const ref: MessageRef = {
      id: identity.id,
      receivedAt: identity.receivedAt,
      organizationId: scope.organizationId,
    };
    // The message lock; another organization's partition row is "not found" too.
    const snapshot = await this.lifecycle.lock(tx, ref);
    if (!snapshot) throw messageNotFound();

    const transitionKey = apiTransitionKey(scope.organizationId, operation, key);
    // A concurrent request with the same key applied first (READ COMMITTED: visible now that
    // we hold the lock): roll back and replay its stored response.
    if (await this.repository.hasTransitionKey(tx, ref, transitionKeyHash(transitionKey))) {
      throw new IdempotencyRaceError();
    }

    const actor: TransitionActor = {
      role: 'operator',
      service: API_SERVICE,
      type: principal.kind,
      id: publicIdOf(principal),
    };
    const correlationId = `api:${getCorrelationId() ?? uuidv7()}`.slice(0, MAX_CORRELATION_ID);
    const transition: TransitionRequest = {
      message: ref,
      ...operationTransition(operation, snapshot.state),
      actor,
      transitionKey,
      correlationId,
      expectedVersion: body.expectedVersion,
      recordIgnored: false,
    };
    // The state decision first, so a stale version or a wrong state answers before the
    // operation's own preconditions; the transition below re-decides under the same lock.
    const decision = decideTransition(
      { state: snapshot.state, version: snapshot.version, round: snapshot.round },
      transition,
    );
    if (decision.result !== 'apply') throw decisionConflict(decision, snapshot);
    if (!snapshot.emlObjectKey.startsWith(`org/${scope.organizationId.toString()}/`)) {
      this.logger.error({
        message: 'message EML key is outside the organization prefix; operation refused',
        operation,
        messageId: ref.id.toString(),
        organizationId: scope.organizationId.toString(),
      });
      throw messageStateConflict(snapshot);
    }

    const ctx: OperationContext = {
      operation,
      principal,
      scope,
      messageId,
      ref,
      snapshot,
      body,
      correlationId,
      actor,
    };
    const prepared = await effect.prepare(tx, ctx);
    const outcome = await this.lifecycle.transition(tx, transition);
    if (outcome.result !== 'applied') throw outcomeError(outcome);
    const done = await effect.commit(tx, ctx, outcome, prepared);

    await this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action: AUDIT_ACTIONS[operation],
        resourceType: 'message',
        resourceId: messageId,
        sourceIp: request.client.ip,
        metadata: {
          fromState: outcome.from,
          toState: outcome.to,
          version: outcome.version,
          lifecycleRound: outcome.round,
          reason: body.reason,
          idempotencyKeyHash: idempotencyKeyHash(key),
          eventIds: done.eventIds,
          ...done.audit,
        },
      },
      tx,
    );
    this.logger.log({
      message: 'message lifecycle operation applied',
      operation,
      messageId: ref.id.toString(),
      organizationId: scope.organizationId.toString(),
      from: outcome.from,
      to: outcome.to,
      version: outcome.version,
      round: outcome.round,
    });
    return { statusCode: ACCEPTED, body: done.body };
  }
}
