import { Controller, Get, Param, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOkResponse, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import { CurrentScope, RequirePermissions } from '../../../auth-contracts/decorators';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import type { Page } from '../../../http/pagination';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { ApiQueryFrom } from '../../organizations/api-docs';
import { ApiMessageId, DELIVERY_READ, DELIVERY_STATUS_DOC, messageIdPipe } from '../api-docs';
import {
  DeliveryEventPageSchema,
  type DeliveryEventsQuery,
  DeliveryEventsQuerySchema,
  type DeliveryEventView,
  type DeliveryListItem,
  DeliveryListPageSchema,
  type ListDeliveriesQuery,
  ListDeliveriesQuerySchema,
  MessageDeliveriesSchema,
  type MessageDeliveriesView,
} from '../dto/deliveries.schemas';
import { DeliveriesService } from '../services/deliveries.service';

/**
 * Per-recipient delivery status (step 2.3 R9, R13) of the caller's organization, from the read
 * replica (a few seconds behind the mail path). Another organization's message is `404`.
 */
@ApiTags('deliveries')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ version: '1' })
export class DeliveriesController {
  constructor(private readonly deliveries: DeliveriesService) {}

  @Get('messages/:messageId/deliveries')
  @RequirePermissions(DELIVERY_READ)
  @ApiOperation({
    summary: 'Get the delivery status of every recipient of a message',
    description:
      'One entry per recipient and delivery (`deliverySeq` 0 = initial delivery), by ' +
      '`rcptSeq`. Statuses: ' +
      DELIVERY_STATUS_DOC +
      ' `dsnGenerated`: the gateway’s MTA sent a DSN to the original sender (never for ' +
      'inbound mail).',
  })
  @ApiMessageId()
  @ApiOkResponse({ schema: zodToOpenApi(MessageDeliveriesSchema) })
  @ApiErrors(400, 401, 403, 404)
  forMessage(
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
  ): Promise<MessageDeliveriesView> {
    return this.deliveries.forMessage(scope, messageId);
  }

  @Get('messages/:messageId/deliveries/events')
  @RequirePermissions(DELIVERY_READ)
  @ApiOperation({
    summary: 'Get the delivery audit trail of a message',
    description:
      'Every status signal of the message’s deliveries, applied or not (stale, conflicting ' +
      'and duplicate-state signals are kept with `applied: false`), oldest first, ' +
      'cursor-paginated; `rcptSeq` limits it to one recipient. Sources: `planner`, ' +
      '`reinjection`, `postfix_log` (the MTA delivery log), `bounce_notice` (DSN copies), ' +
      '`reconciler`.',
  })
  @ApiMessageId()
  @ApiQueryFrom(DeliveryEventsQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(DeliveryEventPageSchema) })
  @ApiErrors(400, 401, 403, 404)
  events(
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
    @Query(new ZodValidationPipe(DeliveryEventsQuerySchema)) query: DeliveryEventsQuery,
  ): Promise<Page<DeliveryEventView>> {
    return this.deliveries.events(scope, messageId, query);
  }

  @Get('deliveries')
  @RequirePermissions(DELIVERY_READ)
  @ApiOperation({
    summary: 'List deliveries',
    description:
      'Deliveries of messages received in `[from, to)` (default the last 24 hours, at most 31 ' +
      'days, else `400`), newest first, keyset-paginated (`cursor`). Filters: `status` (' +
      DELIVERY_STATUS_DOC +
      ') and `direction` (`inbound`, `outbound`, `internal`).',
  })
  @ApiQueryFrom(ListDeliveriesQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(DeliveryListPageSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ListDeliveriesQuerySchema)) query: ListDeliveriesQuery,
  ): Promise<Page<DeliveryListItem>> {
    return this.deliveries.list(scope, query);
  }
}
