import { Injectable } from '@nestjs/common';
import { findTool } from '@email-gateway/assistant';
import { uuidv7 } from '@email-gateway/common';
import { getCorrelationId } from '@email-gateway/logger';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  assistantExecutionNotFound,
  assistantNoMoreResults,
  assistantTurnInProgress,
} from '../assistant.errors';
import { executionView } from '../domain/views';
import type { ExecutionView } from '../dto/assistant.schemas';
import {
  type ExecutionWithRefs,
  ExecutionsRepository,
} from '../repositories/executions.repository';
import { AssistantAvailabilityService } from './assistant-availability.service';
import { AssistantLimitsService } from './assistant-limits.service';
import { ConfirmationViewsService } from './confirmation-views.service';
import { ownerOf } from './conversation.service';
import { ToolExecutorService } from './tool-executor.service';
import type { TurnRequest } from './turn-engine.service';

/**
 * Stored tool executions of the caller (design §4.1): `GET` one (own only, card + metadata) and
 * `POST …/more`, the next page of a list execution WITHOUT a model call: the stored (exact)
 * parameters plus the stored next cursor go through the same executor (pre-filter, schema,
 * loopback, card, audit) as a new execution with `parent_execution_id`; `409
 * assistant_no_more_results` when the execution has no next page (or its content was purged).
 */
@Injectable()
export class ExecutionsService {
  constructor(
    private readonly executions: ExecutionsRepository,
    private readonly executor: ToolExecutorService,
    private readonly availability: AssistantAvailabilityService,
    private readonly limits: AssistantLimitsService,
    private readonly confirmationViews: ConfirmationViewsService,
  ) {}

  now(): Date {
    return new Date();
  }

  private async load(
    principal: UserPrincipal,
    scope: TenantScope,
    publicId: string,
  ): Promise<ExecutionWithRefs> {
    const owner = ownerOf(principal, scope);
    const row = await this.executions.findOwned(owner, publicId);
    if (!row) throw assistantExecutionNotFound();
    if (row.parentExecutionId !== null && row.parentPublicId === null) {
      row.parentPublicId = await this.executions.publicIdOf(owner, row.parentExecutionId);
    }
    return row;
  }

  async get(
    principal: UserPrincipal,
    scope: TenantScope,
    publicId: string,
  ): Promise<ExecutionView> {
    const row = await this.load(principal, scope, publicId);
    if (row.status !== 'pending_confirmation') return executionView(row);
    const confirmations = await this.confirmationViews.forExecutions(
      principal,
      ownerOf(principal, scope),
      [row.id],
    );
    return executionView(row, confirmations.get(row.id) ?? null);
  }

  async more(
    principal: UserPrincipal,
    scope: TenantScope,
    publicId: string,
    request: TurnRequest,
    signal: AbortSignal,
  ): Promise<ExecutionView> {
    const owner = ownerOf(principal, scope);
    const parent = await this.load(principal, scope, publicId);
    await this.availability.assertAvailable(scope, this.now(), false);
    const tool = findTool(parent.toolName);
    const params = parent.paramsRedacted;
    if (
      parent.nextCursor === null ||
      !tool ||
      tool.cursor === null ||
      params === null ||
      typeof params !== 'object' ||
      Array.isArray(params)
    ) {
      throw assistantNoMoreResults();
    }
    const token = uuidv7();
    if (!(await this.limits.acquireLock(parent.conversationPublicId, token))) {
      throw assistantTurnInProgress();
    }
    try {
      let nextSeq = await this.executions.nextSeq(owner, parent.conversationId);
      const outcome = await this.executor.execute(
        {
          principal,
          owner,
          conversationId: parent.conversationId,
          conversationPublicId: parent.conversationPublicId,
          turnId: null,
          turnPublicId: null,
          parentExecutionId: parent.id,
          parentExecutionPublicId: parent.publicId,
          authorization: request.authorization,
          clientIp: request.clientIp,
          correlationBase: getCorrelationId() ?? token,
          signal,
          allocateSeq: () => nextSeq++,
        },
        {
          name: tool.name,
          arguments: { ...(params as Record<string, unknown>), cursor: parent.nextCursor },
        },
        0,
      );
      return outcome.view;
    } finally {
      await this.limits.releaseLock(parent.conversationPublicId, token);
    }
  }
}
