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
import { ApiBearerAuth, ApiBody, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequirePermissions,
} from '../../auth-contracts/decorators';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { ApiCodedError, CodedExceptionFilter } from '../../http/coded-exception';
import {
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
} from '../../http/idempotency/idempotency-key';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import { zodToOpenApi } from '../../validation/zod-openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { ApiErrors } from '../auth/api-docs';
import { Client } from '../auth/client-context.decorator';
import type { ClientContext } from '../auth/services/session.service';
import {
  ApiListErrors,
  ApiListQuery,
  ApiOkExample,
  SCAN_BUDGET_RULE,
  TransactionalIdempotency,
} from '../messages/api-docs';
import {
  ApiDeliveryId,
  ApiInProgress,
  ApiKeyedBadRequest,
  ApiKeyedResponse,
  ApiKeyReused,
  ApiMutationBasics,
  ApiNotEnabled,
  ApiReplayId,
  ApiUnavailable,
  ApiWebhookId,
  ApiWebhookNotFound,
  WEBHOOK_MANAGE,
  WEBHOOK_READ,
} from './api-docs';
import { WebhookDeliveriesService } from './services/webhook-deliveries.service';
import { WEBHOOK_OPERATIONS } from './services/webhook-common';
import { WEBHOOK_ERROR_CODES as C } from './webhooks.errors';
import { WebhookRateLimit } from './webhooks-rate-limit';
import {
  CreateReplayBodySchema,
  DELIVERY_LIST_PARAMETERS,
  DeliveryDetailSchema,
  type DeliveryDetailView,
  type DeliveryListQuery,
  DeliveryListQuerySchema,
  type DeliveryPage,
  DeliveryPageSchema,
  DeliveryReplayAcceptedSchema,
  type DeliveryReplayAccepted,
  ReplayAcceptedSchema,
  type ReplayAccepted,
  ReplaySchema,
  type ReplayView,
  WEBHOOK_EXAMPLES,
} from './webhooks.schemas';

/**
 * Delivery history and replays of one webhook (step 6.2 W8, W12, §6.1). Translation only
 * (WebhookDeliveriesService).
 */
@ApiTags('webhooks')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'webhooks/:webhookId', version: '1' })
export class WebhookDeliveriesController {
  constructor(private readonly deliveries: WebhookDeliveriesService) {}

  @Get('deliveries')
  @RequirePermissions(WEBHOOK_READ)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the deliveries of a webhook',
    description:
      'The delivery history of one webhook, newest event first (keyset `(event_occurred_at, ' +
      'id)` over `(subscription_id, event_occurred_at, id)`), within a bounded range of event ' +
      'times (`from`/`to`, default the last 24 h, at most WEBHOOK_HISTORY_MAX_RANGE_DAYS). One ' +
      'row per delivery: the original (`deliverySeq: 0`), each replay and each test ping, with ' +
      'status, attempt counts and the last response code and error code. Kept 2 months. ' +
      SCAN_BUDGET_RULE +
      ' From the read replica.',
  })
  @ApiWebhookId()
  @ApiListQuery(DeliveryListQuerySchema, DELIVERY_LIST_PARAMETERS)
  @ApiOkExample(DeliveryPageSchema, WEBHOOK_EXAMPLES.deliveryPage)
  @ApiListErrors()
  @ApiErrors(401, 403)
  @ApiWebhookNotFound()
  @ApiUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('webhookId') webhookId: string,
    @Query(new ZodValidationPipe(DeliveryListQuerySchema)) query: DeliveryListQuery,
  ): Promise<DeliveryPage> {
    return this.deliveries.list(principal, scope, webhookId, query);
  }

  @Get('deliveries/:deliveryId')
  @RequirePermissions(WEBHOOK_READ)
  @ApiOperation({
    summary: 'Get a delivery with its attempts and event',
    description:
      'One delivery with every attempt (outcome, HTTP status, latency, the first ≤ 512 ' +
      'characters of the response with secrets redacted, Retry-After, error code, number of ' +
      'signatures) and the stored event envelope exactly as it is signed and sent (`null` once ' +
      'its retention ended). Response snippets are untrusted text: never render them as HTML. ' +
      'From the read replica.',
  })
  @ApiWebhookId()
  @ApiDeliveryId()
  @ApiOkExample(DeliveryDetailSchema, WEBHOOK_EXAMPLES.deliveryDetail)
  @ApiErrors(400, 401, 403)
  @ApiCodedError(404, 'Unknown webhook or delivery, or one of another organization', [
    C.notFound,
    C.deliveryNotFound,
  ])
  @ApiUnavailable()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('webhookId') webhookId: string,
    @Param('deliveryId') deliveryId: string,
  ): Promise<DeliveryDetailView> {
    return this.deliveries.get(scope, webhookId, deliveryId);
  }

  @Post('deliveries/:deliveryId/replay')
  @RequirePermissions(WEBHOOK_MANAGE)
  @HttpCode(HttpStatus.ACCEPTED)
  @TransactionalIdempotency(WEBHOOK_OPERATIONS.deliveryReplay)
  @ApiOperation({
    summary: 'Replay one delivery',
    description:
      'Queues a new delivery of the same stored event (same envelope `id` and bytes, a new ' +
      '`EG-Delivery-Id`, new timestamp and signature; `trigger: replay`). The webhook must be ' +
      '`active` (`409 webhook_not_active`); at most WEBHOOK_REPLAY_MAX_PER_DELIVERY replays per ' +
      'event (`409 webhook_replay_limit`); `410 webhook_event_expired` once the stored event ' +
      'is past its retention. Requires the Idempotency-Key header (transactional, rate class ' +
      '`sensitive`). Audited `webhook.delivery_replayed`.',
  })
  @ApiWebhookId()
  @ApiDeliveryId()
  @ApiKeyedResponse(
    202,
    DeliveryReplayAcceptedSchema,
    WEBHOOK_EXAMPLES.deliveryReplayAccepted,
    'Queued (or the stored response of an earlier identical request replayed)',
  )
  @ApiKeyedBadRequest()
  @ApiErrors(401)
  @ApiNotEnabled()
  @ApiUnavailable()
  @ApiCodedError(404, 'Unknown webhook or delivery, or one of another organization', [
    C.notFound,
    C.deliveryNotFound,
  ])
  @ApiInProgress({
    codes: [C.notActive, C.replayLimit],
    description: '`webhook_not_active` (`status`), `webhook_replay_limit` (`limit`)',
  })
  @ApiCodedError(410, 'The stored event is past its retention', [C.eventExpired])
  @ApiKeyReused()
  async replay(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('webhookId') webhookId: string,
    @Param('deliveryId') deliveryId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<DeliveryReplayAccepted> {
    const result = await this.deliveries.replayDelivery(
      principal,
      scope,
      { webhookId, deliveryId, idempotencyKey },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post('replays')
  @RequirePermissions(WEBHOOK_MANAGE)
  @HttpCode(HttpStatus.ACCEPTED)
  @TransactionalIdempotency(WEBHOOK_OPERATIONS.rangeReplay)
  @WebhookRateLimit('range_replay')
  @ApiOperation({
    summary: 'Replay the deliveries of a time range',
    description:
      'Queues a replay of the webhook’s original deliveries whose events occurred in ' +
      '`[from, to)` (at most WEBHOOK_REPLAY_MAX_RANGE_HOURS, 72; `from` within the 2-month ' +
      'retention) with the given `statuses` (default `failed`, `dead`) and `eventTypes`. The ' +
      'delivery worker processes it in batches (at most WEBHOOK_REPLAY_MAX_EVENTS events, then ' +
      '`truncated: true`); poll `GET /webhooks/{webhookId}/replays/{replayId}`. Events that ' +
      'occurred while the webhook was paused or disabled were never recorded for it and cannot ' +
      'be replayed. One queued or running replay per webhook (`409 ' +
      'webhook_replay_in_progress` with `replayId`); the webhook must be `active`. At most ' +
      'WEBHOOK_REPLAY_REQUESTS_PER_HOUR (10) per organization (`429`, `scope: route`). ' +
      'Requires the Idempotency-Key header (transactional, rate class `sensitive`). Audited ' +
      '`webhook.replay_requested`.',
  })
  @ApiWebhookId()
  @ApiBody({
    schema: zodToOpenApi(CreateReplayBodySchema, { io: 'input' }),
    examples: { failedLastNight: { value: WEBHOOK_EXAMPLES.replay } },
  })
  @ApiKeyedResponse(
    202,
    ReplayAcceptedSchema,
    WEBHOOK_EXAMPLES.replayAccepted,
    'Queued (or the stored response of an earlier identical request replayed)',
  )
  @ApiKeyedBadRequest()
  @ApiErrors(401)
  @ApiMutationBasics()
  @ApiInProgress({
    codes: [C.notActive, C.replayInProgress],
    description: '`webhook_not_active` (`status`), `webhook_replay_in_progress` (`replayId`)',
  })
  @ApiKeyReused()
  async createReplay(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('webhookId') webhookId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ReplayAccepted> {
    const result = await this.deliveries.createReplay(
      principal,
      scope,
      { webhookId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get('replays/:replayId')
  @RequirePermissions(WEBHOOK_READ)
  @ApiOperation({
    summary: 'Get a range replay',
    description:
      'Progress of a range replay: `queued`, `running`, `completed` (with `truncated` when ' +
      'WEBHOOK_REPLAY_MAX_EVENTS was reached), `failed` (`errorCode`) or `cancelled`; ' +
      '`matchedCount` original deliveries found and `createdCount` replay deliveries queued. ' +
      'From the read replica.',
  })
  @ApiWebhookId()
  @ApiReplayId()
  @ApiOkExample(ReplaySchema, WEBHOOK_EXAMPLES.replayView)
  @ApiErrors(400, 401, 403)
  @ApiCodedError(404, 'Unknown webhook or replay, or one of another organization', [
    C.notFound,
    C.replayNotFound,
  ])
  @ApiUnavailable()
  getReplay(
    @CurrentScope() scope: TenantScope,
    @Param('webhookId') webhookId: string,
    @Param('replayId') replayId: string,
  ): Promise<ReplayView> {
    return this.deliveries.getReplay(scope, webhookId, replayId);
  }
}
