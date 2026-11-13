import {
  Body,
  Controller,
  Delete,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
  Res,
  UseFilters,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiNoContentResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
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
  IDEMPOTENCY_REQUEST_IN_PROGRESS,
} from '../../http/idempotency/idempotency-key';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import { ReturnsSecret } from '../../rate-limit/rate-class.decorator';
import { zodToOpenApi } from '../../validation/zod-openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { ApiErrors } from '../auth/api-docs';
import { Client } from '../auth/client-context.decorator';
import type { ClientContext } from '../auth/services/session.service';
import {
  ApiListErrors,
  ApiListQuery,
  ApiOkExample,
  TransactionalIdempotency,
} from '../messages/api-docs';
import {
  ApiAcceptedExample,
  ApiInProgress,
  ApiKeyedBadRequest,
  ApiKeyedResponse,
  ApiKeyReused,
  ApiMutationBasics,
  ApiNotEnabled,
  ApiUnavailable,
  ApiUrlRules,
  ApiWebhookId,
  ApiWebhookNotFound,
  REDACTED_REPLAY_RULE,
  WEBHOOK_MANAGE,
  WEBHOOK_READ,
} from './api-docs';
import { RequestHost } from './request-host.decorator';
import { WEBHOOK_OPERATIONS } from './services/webhook-common';
import { WebhooksService } from './services/webhooks.service';
import { WEBHOOK_ERROR_CODES as C } from './webhooks.errors';
import { WebhookRateLimit } from './webhooks-rate-limit';
import {
  CreatedWebhookSchema,
  type CreatedWebhookView,
  CreateWebhookBodySchema,
  EventTypesSchema,
  type EventTypesView,
  RotatedSecretSchema,
  type RotatedSecretView,
  RotateSecretBodySchema,
  TestAcceptedSchema,
  type TestAccepted,
  type UpdateWebhookBody,
  UpdateWebhookBodySchema,
  WEBHOOK_EXAMPLES,
  WEBHOOK_LIST_PARAMETERS,
  type WebhookListQuery,
  WebhookListQuerySchema,
  type WebhookPage,
  WebhookPageSchema,
  WebhookSchema,
  type WebhookView,
} from './webhooks.schemas';

/**
 * Webhook subscriptions of the caller's organization (step 6.2 §6.1, W5–W7; ADR-0057).
 * Translation only (WebhooksService). The static `event-types` route is declared before
 * `{webhookId}`.
 */
@ApiTags('webhooks')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'webhooks', version: '1' })
export class WebhooksController {
  constructor(private readonly webhooks: WebhooksService) {}

  @Get()
  @RequirePermissions(WEBHOOK_READ)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List webhooks',
    description:
      'The webhook subscriptions of your organization, newest first (keyset `id` over ' +
      '`(organization_id, id)`), without `deleted` ones unless `status` asks for them. Never ' +
      'the secret or its ciphertext. Pages follow the v1 list contract (`{ data, nextCursor }`, ' +
      'signed cursor bound to the filters and your organization). From the read replica.',
  })
  @ApiListQuery(WebhookListQuerySchema, WEBHOOK_LIST_PARAMETERS)
  @ApiOkExample(WebhookPageSchema, WEBHOOK_EXAMPLES.page)
  @ApiListErrors()
  @ApiErrors(401, 403)
  @ApiUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(WebhookListQuerySchema)) query: WebhookListQuery,
  ): Promise<WebhookPage> {
    return this.webhooks.list(principal, scope, query);
  }

  @Post()
  @RequirePermissions(WEBHOOK_MANAGE)
  @TransactionalIdempotency(WEBHOOK_OPERATIONS.create)
  @ReturnsSecret({ redactedReplay: true })
  @ApiOperation({
    summary: 'Create a webhook',
    description:
      'Registers an endpoint for the listed event types (1-10 of the catalogue, no wildcard) ' +
      'with optional filters (`directions`, `domainIds` of your domains, `minSeverity`, ' +
      '`verdicts`). The URL must be absolute `https` (≤ 2048, no userinfo or fragment, a port ' +
      'of WEBHOOK_ALLOWED_PORTS) and its host must not be a private, loopback, link-local, ' +
      'metadata or other special-purpose address or one of the platform’s own hosts (`422 ' +
      'webhook_url_not_allowed` with `reason`). DNS is not resolved here: the delivery worker ' +
      'checks every resolved address on every attempt. Needs the plan feature `webhooks` (`403 ' +
      'webhooks_not_enabled`); at most WEBHOOK_MAX_SUBSCRIPTIONS_PER_ORG live subscriptions ' +
      '(`409 webhook_limit_reached`). Returns `201` with the webhook and its signing `secret`. ' +
      REDACTED_REPLAY_RULE +
      ' Audited `webhook.created` (`urlHost` and `urlSha256`, never the URL or the secret).',
  })
  @ApiBody({
    schema: zodToOpenApi(CreateWebhookBodySchema, { io: 'input' }),
    examples: { siem: { value: WEBHOOK_EXAMPLES.create } },
  })
  @ApiKeyedResponse(
    201,
    CreatedWebhookSchema,
    WEBHOOK_EXAMPLES.created,
    'Created; `secret` is shown only here (`null` on a replay)',
  )
  @ApiKeyedBadRequest()
  @ApiErrors(401)
  @ApiNotEnabled()
  @ApiInProgress({
    codes: [C.limitReached],
    description: '`webhook_limit_reached` (`limit`)',
  })
  @ApiUrlRules(true)
  @ApiUnavailable()
  async create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @RequestHost() requestHost: string | null,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<CreatedWebhookView> {
    const result = await this.webhooks.create(
      principal,
      scope,
      { idempotencyKey, body, requestHost },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get('event-types')
  @RequirePermissions(WEBHOOK_READ)
  @ApiOperation({
    summary: 'List the webhook event catalogue',
    description:
      'The ten subscribable event types (payload version 1) and the test-only `webhook.ping`: ' +
      'description, severity rule, the filters that apply and an example envelope. Payloads ' +
      'carry ids, codes, domains and counts only: never a subject, body, attachment, address ' +
      'local part, URL found in mail, S3 key or secret.',
  })
  @ApiOkExample(EventTypesSchema, {
    data: [eventTypeExample()],
    severities: ['info', 'low', 'medium', 'high'],
  })
  @ApiErrors(401, 403)
  eventTypes(): EventTypesView {
    return this.webhooks.eventTypes();
  }

  @Get(':webhookId')
  @RequirePermissions(WEBHOOK_READ)
  @ApiOperation({
    summary: 'Get a webhook',
    description:
      'One webhook of your organization (deleted ones too, with `status: deleted`): its ' +
      'configuration, secret version and rotation overlap, and failure state. Never the ' +
      'secret. From the read replica: right after a change the previous `rowVersion` may show ' +
      'for a moment.',
  })
  @ApiWebhookId()
  @ApiOkExample(WebhookSchema, WEBHOOK_EXAMPLES.item)
  @ApiErrors(400, 401, 403)
  @ApiWebhookNotFound()
  @ApiUnavailable()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('webhookId') webhookId: string,
  ): Promise<WebhookView> {
    return this.webhooks.get(scope, webhookId);
  }

  @Patch(':webhookId')
  @RequirePermissions(WEBHOOK_MANAGE)
  @ApiOperation({
    summary: 'Update a webhook',
    description:
      'Changes any of `name`, `description`, `url`, `eventTypes`, `filters`, `status` ' +
      '(`active`, `paused`, `disabled`) and `maxConcurrency` (null = the worker default), with ' +
      '`expectedRowVersion` (`409 webhook_version_conflict` with `currentRowVersion`). ' +
      '`paused`: no new deliveries are created; pending ones wait, parked (`nextAttemptAt` ' +
      'null) in the same transaction. `disabled`: pending deliveries are cancelled. ' +
      'Re-activation needs the plan feature, resets the failure state (consecutive failures, ' +
      'failing since, disabled reason) and makes parked deliveries due now. URL and filter rules ' +
      'as on create. Changes reach the delivery worker within its cache TTL (≤ 60 s). Audited ' +
      '`webhook.updated` (changed paths; `urlHost` and `urlSha256` when the URL changes; ' +
      '`parkedDeliveries` / `resumedDeliveries` on pause / resume).',
  })
  @ApiWebhookId()
  @ApiBody({
    schema: zodToOpenApi(UpdateWebhookBodySchema, { io: 'input' }),
    examples: { pause: { value: WEBHOOK_EXAMPLES.update } },
  })
  @ApiOkExample(WebhookSchema, { ...WEBHOOK_EXAMPLES.item, status: 'paused', rowVersion: 2 })
  @ApiErrors(400, 401)
  @ApiMutationBasics()
  @ApiCodedError(
    409,
    '`webhook_version_conflict`: `expectedRowVersion` is not the current version ' +
      '(`currentRowVersion`)',
    [C.versionConflict],
    { currentRowVersion: { type: 'integer' } },
  )
  @ApiUrlRules(false)
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('webhookId') webhookId: string,
    @Body(new ZodValidationPipe(UpdateWebhookBodySchema)) body: UpdateWebhookBody,
    @RequestHost() requestHost: string | null,
    @Client() client: ClientContext,
  ): Promise<WebhookView> {
    return this.webhooks.update(principal, scope, webhookId, body, requestHost, client.ip);
  }

  @Delete(':webhookId')
  @RequirePermissions(WEBHOOK_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @TransactionalIdempotency(WEBHOOK_OPERATIONS.delete)
  @ApiOperation({
    summary: 'Delete a webhook',
    description:
      'Soft delete: the webhook gets `status: deleted` and stops receiving events; its pending ' +
      'deliveries are cancelled in the same transaction. The delivery history stays readable ' +
      'until its retention ends; the row is purged after WEBHOOK_DELETED_RETENTION_DAYS. ' +
      'Requires the Idempotency-Key header: repeating the request with the same key answers ' +
      '`204` again (`Idempotency-Replayed: true`); a new key for a deleted webhook is `404`. ' +
      'Audited `webhook.deleted`. Rate class `sensitive`.',
  })
  @ApiWebhookId()
  @ApiNoContentResponse({
    description: 'Deleted (or the stored response of an earlier identical request replayed)',
    headers: {
      [IDEMPOTENCY_REPLAYED_HEADER]: {
        description: '`true` when this is the stored response of an earlier identical request',
        schema: { type: 'string', enum: ['true'] },
      },
    },
  })
  @ApiKeyedBadRequest()
  @ApiErrors(401, 403)
  @ApiWebhookNotFound()
  @ApiCodedError(409, 'A request with this Idempotency-Key is still in progress', [
    IDEMPOTENCY_REQUEST_IN_PROGRESS,
  ])
  @ApiKeyReused()
  @ApiUnavailable()
  async delete(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('webhookId') webhookId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    const result = await this.webhooks.delete(
      principal,
      scope,
      { webhookId, idempotencyKey },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
  }

  @Post(':webhookId/rotate-secret')
  @RequirePermissions(WEBHOOK_MANAGE)
  @HttpCode(HttpStatus.OK)
  @TransactionalIdempotency(WEBHOOK_OPERATIONS.rotate)
  @ReturnsSecret({ redactedReplay: true })
  @ApiOperation({
    summary: 'Rotate a webhook signing secret',
    description:
      'Issues a new signing secret (`secretVersion + 1`). The retiring secret keeps signing ' +
      'for `overlapHours` (0-168, default WEBHOOK_SECRET_OVERLAP_HOURS_DEFAULT = 24; 0 = no ' +
      'overlap): until `previousSecretExpiresAt`, every delivery carries two `v1=` signatures ' +
      '(new secret first), so receivers can switch without dropping events. Rotating again ' +
      'during an overlap retires the then-current secret (only one previous secret exists). ' +
      REDACTED_REPLAY_RULE +
      ' Audited `webhook.secret_rotated` (version and overlap only).',
  })
  @ApiWebhookId()
  @ApiBody({
    schema: zodToOpenApi(RotateSecretBodySchema, { io: 'input' }),
    examples: { dayOverlap: { value: WEBHOOK_EXAMPLES.rotate } },
  })
  @ApiKeyedResponse(
    200,
    RotatedSecretSchema,
    WEBHOOK_EXAMPLES.rotated,
    'Rotated; `secret` is shown only here (`null` on a replay)',
  )
  @ApiKeyedBadRequest()
  @ApiErrors(401, 403)
  @ApiWebhookNotFound()
  @ApiCodedError(409, 'A request with this Idempotency-Key is still in progress', [
    IDEMPOTENCY_REQUEST_IN_PROGRESS,
  ])
  @ApiKeyReused()
  @ApiUnavailable()
  async rotate(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('webhookId') webhookId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RotatedSecretView> {
    const result = await this.webhooks.rotate(
      principal,
      scope,
      { webhookId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post(':webhookId/test')
  @RequirePermissions(WEBHOOK_MANAGE)
  @HttpCode(HttpStatus.ACCEPTED)
  @WebhookRateLimit('test')
  @ApiOperation({
    summary: 'Send a test event to a webhook',
    description:
      'Creates a `webhook.ping` event (`data: { subscriptionId, requestedAt }`) and a delivery ' +
      'with `trigger: test`; the delivery worker signs and sends it like any event. Follow it ' +
      'with `GET /webhooks/{webhookId}/deliveries/{deliveryId}`. The webhook must be `active` ' +
      '(`409 webhook_not_active`) and the plan feature enabled. At most ' +
      'WEBHOOK_TEST_REQUESTS_PER_MINUTE (6) per webhook (`429 rate_limited`, `scope: route`). ' +
      'Audited `webhook.test_requested`.',
  })
  @ApiWebhookId()
  @ApiAcceptedExample(TestAcceptedSchema, WEBHOOK_EXAMPLES.testAccepted, 'Queued for delivery')
  @ApiErrors(400, 401)
  @ApiMutationBasics()
  @ApiCodedError(
    409,
    '`webhook_not_active` (`status`): the webhook is paused or disabled',
    [C.notActive],
    { status: { type: 'string' } },
  )
  test(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('webhookId') webhookId: string,
    @Client() client: ClientContext,
  ): Promise<TestAccepted> {
    return this.webhooks.test(principal, scope, webhookId, client.ip);
  }
}

/** The example of the catalogue route (one entry; the full catalogue is served at runtime). */
function eventTypeExample() {
  return {
    type: 'email.quarantined',
    version: 1,
    description: 'A message was quarantined (by policy or manually) for one or more recipients.',
    severity: 'medium',
    appliesFilters: ['directions', 'domainIds', 'minSeverity'],
    subscribable: true,
    example: WEBHOOK_EXAMPLES.deliveryDetail.event,
  };
}
