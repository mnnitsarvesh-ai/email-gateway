import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Res,
  UseFilters,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CodedExceptionFilter } from '../../../http/coded-exception';
import {
  ApiIdempotencyKey,
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
} from '../../../http/idempotency/idempotency-key';
import type { IdempotentResult } from '../../../http/idempotency/idempotency.service';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import type { Page } from '../../../http/pagination';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiMessageId, messageIdPipe } from '../../deliveries/api-docs';
import { ApiQueryFrom } from '../../organizations/api-docs';
import {
  ApiLifecycleAccepted,
  ApiLifecycleWriteErrors,
  ApiMessageNotFound,
  MESSAGE_READ,
  MESSAGE_RESCAN,
  QUARANTINE_RELEASE,
  RELEASE_CONFLICTS,
  RESCAN_CONFLICTS,
} from '../api-docs';
import {
  type LifecycleHistoryEntry,
  LifecycleHistoryPageSchema,
  type LifecycleHistoryQuery,
  LifecycleHistoryQuerySchema,
  LifecycleOperationBodySchema,
  type LifecycleView,
  LifecycleViewSchema,
  type ReleaseResponse,
  ReleaseResponseSchema,
  type RescanResponse,
  RescanResponseSchema,
} from '../dto/messages.schemas';
import { MessageLifecycleReadService } from '../services/message-lifecycle-read.service';
import { MessageLifecycleService } from '../services/message-lifecycle.service';

/** Sets the replay header and returns the body (the status is the route's 202). */
function reply<T>(res: Response, result: IdempotentResult<T>): T {
  if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
  return result.body;
}

/**
 * Message lifecycle (step 3.3 L10, L12) of the caller's organization: the current state and its
 * history (read replica), the administrative rescan and the quarantine release (writer, with
 * Idempotency-Key). Translation only; the logic is in MessageLifecycleService and
 * MessageLifecycleReadService. Another organization's message is `404 message_not_found`.
 */
@ApiTags('messages')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'messages', version: '1' })
export class MessageLifecycleController {
  constructor(
    private readonly operations: MessageLifecycleService,
    private readonly reads: MessageLifecycleReadService,
  ) {}

  @Get(':messageId/lifecycle')
  @RequirePermissions(MESSAGE_READ)
  @ApiOperation({
    summary: 'Get the lifecycle state of a message',
    description:
      'The lifecycle state (one of the fifteen states of ADR-0025), its reason code, `version` ' +
      '(optimistic concurrency token for rescan and release), `lifecycleRound`, the MIME parse ' +
      'stage, recipient counts by status, the highest delivery sequence and the operations the ' +
      'state allows (`actions`, independent of the caller’s permissions). From the read ' +
      'replica: right after a rescan or release the previous state may still show.',
  })
  @ApiMessageId()
  @ApiOkResponse({ schema: zodToOpenApi(LifecycleViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiMessageNotFound()
  lifecycle(
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
  ): Promise<LifecycleView> {
    return this.reads.lifecycle(scope, messageId);
  }

  @Get(':messageId/lifecycle/history')
  @RequirePermissions(MESSAGE_READ)
  @ApiOperation({
    summary: 'Get the lifecycle history of a message',
    description:
      'Every applied transition, oldest first (by version), cursor-paginated: from and to ' +
      'state, reason code, round, actor (`role`, `type`, `service`, public `id` of an operator) ' +
      'and the causing event. Rows written before step 3.3 show `actor.role = legacy` and are ' +
      'shown as recorded. From the read replica.',
  })
  @ApiMessageId()
  @ApiQueryFrom(LifecycleHistoryQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(LifecycleHistoryPageSchema) })
  @ApiErrors(400, 401, 403)
  @ApiMessageNotFound()
  history(
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
    @Query(new ZodValidationPipe(LifecycleHistoryQuerySchema)) query: LifecycleHistoryQuery,
  ): Promise<Page<LifecycleHistoryEntry>> {
    return this.reads.history(scope, messageId, query);
  }

  @Post(':messageId/rescan')
  @RequirePermissions(MESSAGE_RESCAN)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Request a rescan of a message',
    description:
      'Moves the message to `scanning` with a new lifecycle round (allowed from `scanning`, ' +
      '`scanned`, `scan_failed`, `policy_evaluated`, `quarantined`, `held_for_review`, ' +
      '`expired`) and publishes `mail.message.rescan_requested.v1` to the scan stages: every ' +
      'registered scan engine (step 4.1: Rspamd) scans the new round and the message ends ' +
      '`scanned` or `scan_failed` with that round; results of earlier rounds stay unchanged ' +
      '(`GET /messages/{messageId}/scans`). Audited as `message.rescan_requested`. Requires ' +
      'the Idempotency-Key header.',
  })
  @ApiMessageId()
  @ApiIdempotencyKey()
  @ApiBody({ schema: zodToOpenApi(LifecycleOperationBodySchema, { io: 'input' }) })
  @ApiLifecycleAccepted(RescanResponseSchema, 'Rescan requested (or the stored response replayed)')
  @ApiLifecycleWriteErrors(RESCAN_CONFLICTS)
  async rescan(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId') messageId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RescanResponse> {
    return reply(
      res,
      await this.operations.rescan(principal, scope, { messageId, idempotencyKey, body }, client),
    );
  }

  @Post(':messageId/release')
  @RequirePermissions(QUARANTINE_RELEASE)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Release a quarantined or held message',
    description:
      'Moves a `quarantined` or `held_for_review` message to `approved` with a new lifecycle ' +
      'round and approves its `pending` and `quarantined` recipients for delivery (released ' +
      '`quarantined` recipients become `pending`) ' +
      '(`mail.delivery.approved.v1`, `source: quarantine_release`, `deliverySeq` = highest + 1, ' +
      'at most 1000 recipients per approval); the delivery-worker then delivers it. Messages ' +
      'with per-recipient quarantine entries must go through the quarantine workflow. Audited ' +
      'as `message.quarantine_released`. Requires the Idempotency-Key header.',
  })
  @ApiMessageId()
  @ApiIdempotencyKey()
  @ApiBody({ schema: zodToOpenApi(LifecycleOperationBodySchema, { io: 'input' }) })
  @ApiLifecycleAccepted(ReleaseResponseSchema, 'Released (or the stored response replayed)')
  @ApiLifecycleWriteErrors(RELEASE_CONFLICTS)
  async release(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId') messageId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ReleaseResponse> {
    return reply(
      res,
      await this.operations.release(principal, scope, { messageId, idempotencyKey, body }, client),
    );
  }
}
