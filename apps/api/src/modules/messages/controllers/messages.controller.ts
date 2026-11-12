import { Controller, Get, Param, Query, UseFilters } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError, CodedExceptionFilter } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiMessageId, messageIdPipe } from '../../deliveries/api-docs';
import {
  ApiInconsistentRead,
  ApiListErrors,
  ApiListQuery,
  ApiMessageNotFound,
  ApiOkExample,
  MESSAGE_READ,
  SCAN_BUDGET_RULE,
} from '../api-docs';
import {
  MESSAGE_LIST_PARAMETERS,
  type MessageDetail,
  MessageDetailSchema,
  type MessageListPage,
  MessageListPageSchema,
  type MessageListQuery,
  MessageListQuerySchema,
  type MessageRecipientsPage,
  MessageRecipientsPageSchema,
  type MessageRecipientsQuery,
  MessageRecipientsQuerySchema,
} from '../dto/message-data.schemas';
import { MESSAGE_EXAMPLES } from '../dto/message-data.examples';
import { DOMAIN_NOT_FOUND } from '../messages.errors';
import { MessageDataService } from '../services/message-data.service';

/**
 * Message metadata of the caller's organization (step 6.1 WP2, §3.3): the cursor-based list,
 * the detail and the recipients, from the read replica. Translation only; the logic is in
 * MessageDataService. Another organization's message is `404 message_not_found`.
 */
@ApiTags('messages')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'messages', version: '1' })
export class MessagesController {
  constructor(private readonly messages: MessageDataService) {}

  @Get()
  @RequirePermissions(MESSAGE_READ)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List messages',
    description:
      'Message metadata of your organization received in `[from, to)` (default the last 24 ' +
      'hours, at most API_MESSAGES_MAX_RANGE_DAYS days, default 31), newest first ' +
      '(`sort=-receivedAt`) or oldest first (`sort=receivedAt`), from the read replica (a few ' +
      'seconds behind the writer). Filters: `direction`, `status`, `verdict`, `action` (comma ' +
      'lists), `domainId`, `sender` (exact envelope sender), `headerFrom`, `recipient`, ' +
      '`internetMessageId` (exact values), `riskScore` (`.gte`, `.lte`, `.gt`, `.lt`; 0-1000) ' +
      'and `hasAttachments`. No filter, exactly one `verdict` or only `recipient` read an index ' +
      'in keyset order; every other filter or combination is scan-bounded. ' +
      SCAN_BUDGET_RULE +
      ' A search with `sender`, `headerFrom`, `recipient` or `internetMessageId` is audited ' +
      '(`message.searched`, first page only; the values only as SHA-256). Subjects and ' +
      'addresses are attacker-controlled text; bodies and attachments are never returned.',
  })
  @ApiListQuery(MessageListQuerySchema, MESSAGE_LIST_PARAMETERS)
  @ApiOkExample(MessageListPageSchema, MESSAGE_EXAMPLES.listPage)
  @ApiListErrors()
  @ApiErrors(401, 403)
  @ApiCodedError(404, 'The `domainId` is unknown or belongs to another organization', [
    DOMAIN_NOT_FOUND,
  ])
  @ApiInconsistentRead()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(MessageListQuerySchema)) query: MessageListQuery,
    @Client() client: ClientContext,
  ): Promise<MessageListPage> {
    return this.messages.list(principal, scope, query, client.ip);
  }

  @Get(':messageId')
  @RequirePermissions(MESSAGE_READ)
  @ApiOperation({
    summary: 'Get a message',
    description:
      'The list fields plus `internetMessageId`, `lifecycleRound`, `version` (the optimistic ' +
      'concurrency token of rescan and release), `statusReason`, the SMTP client (`clientIp`, ' +
      '`clientHelo`) and the Postfix queue id, from the read replica. Never the body, the ' +
      'stored object key or attachments content. Not audited (metadata behind `message:read`).',
  })
  @ApiMessageId()
  @ApiOkExample(MessageDetailSchema, MESSAGE_EXAMPLES.detail)
  @ApiErrors(400, 401, 403)
  @ApiMessageNotFound()
  @ApiInconsistentRead()
  detail(
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
  ): Promise<MessageDetail> {
    return this.messages.detail(scope, messageId);
  }

  @Get(':messageId/recipients')
  @RequirePermissions(MESSAGE_READ)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the recipients of a message',
    description:
      'The envelope recipients in RCPT order (keyset `rcptSeq`, v1 cursor bound to the ' +
      'message): address, recipient status, final action, routed direction, the matched user ' +
      '(public id) and the latest delivery (highest delivery sequence: status, final SMTP ' +
      'code, delivery time) or null before planning. From the read replica.',
  })
  @ApiMessageId()
  @ApiListQuery(MessageRecipientsQuerySchema, {
    limit: 'Page size, 1-100 (default 25)',
    cursor: '`nextCursor` of the previous page',
    sort: '`rcptSeq` (the only order)',
  })
  @ApiOkExample(MessageRecipientsPageSchema, MESSAGE_EXAMPLES.recipientsPage)
  @ApiListErrors()
  @ApiErrors(401, 403)
  @ApiMessageNotFound()
  @ApiInconsistentRead()
  recipients(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
    @Query(new ZodValidationPipe(MessageRecipientsQuerySchema)) query: MessageRecipientsQuery,
  ): Promise<MessageRecipientsPage> {
    return this.messages.recipients(principal, scope, messageId, query);
  }
}
