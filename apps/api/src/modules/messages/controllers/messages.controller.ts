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
import {
  DOMAIN_NOT_FOUND,
  MESSAGE_FILTER_FORBIDDEN,
  MESSAGE_SEARCH_TIMEOUT,
  MESSAGE_SEARCH_TOO_BROAD,
} from '../messages.errors';
import { MessageDataService } from '../services/message-data.service';

/**
 * Message metadata of the caller's organization (step 6.1 WP2, §3.3): the cursor-based list
 * (with the step 7.2 search drivers, §2 E1, E2), the detail and the recipients, from the read
 * replica. Translation only; the logic is in
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
    summary: 'List and search messages',
    description:
      'Message metadata of your organization received in `[from, to)` (default the last 24 ' +
      'hours, at most API_MESSAGES_MAX_RANGE_DAYS days, default 31), newest first ' +
      '(`sort=-receivedAt`) or oldest first (`sort=receivedAt`), from the read replica (a few ' +
      'seconds behind the writer). **Search drivers (step 7.2).** The first present filter of ' +
      '`internetMessageId` > `sender` > `headerFrom` > `recipient` > `subject` > ' +
      '`senderDomain` > `recipientDomain` > `subjectPrefix` > `quarantineStatus` > ' +
      '`deliveryStatus` > `verdict` (exactly one value) drives the search: its index is read ' +
      'in time order, so a page with no other filter is exact (no short pages). Every other ' +
      'filter is a residual: with residuals each request examines at most ' +
      'API_LIST_SCAN_BUDGET_ROWS (default 5 000) entries of the driver’s index and may return a ' +
      'short or empty page with a `nextCursor`; with residuals only (no driver) the whole range ' +
      'is scanned that way. A message matched by several recipients, deliveries or quarantine ' +
      'entries is listed once. `subjectPrefix` reads at most API_MESSAGES_SEARCH_MAX_MATCHES ' +
      '(default 5 000) matching messages of the range: more is `422 message_search_too_broad` ' +
      '(type more, use the exact `subject` or narrow the range); a prefix search that takes ' +
      'longer than API_MESSAGES_SEARCH_TIMEOUT_MS is `503 message_search_timeout`. ' +
      '**Filter permissions.** `recipient`, `subject` and `subjectPrefix` require ' +
      '`message:reveal`, ' +
      '`deliveryStatus` requires `delivery:read`, `quarantineStatus` requires `quarantine:read` ' +
      '(`403 message_filter_forbidden` naming the filter and permission, before anything is ' +
      'read). ' +
      SCAN_BUDGET_RULE +
      ' The cursor is also bound to the search driver: after a deploy that changes driver ' +
      'selection an old cursor is `400 cursor_invalid` once; restart the list. A search with ' +
      '`sender`, `headerFrom`, `recipient`, `internetMessageId`, `subject` or `subjectPrefix` ' +
      'is audited (`message.searched`, first page only; values only as SHA-256, subjects ' +
      'normalized first). Subjects and addresses are attacker-controlled text; bodies and ' +
      'attachments are never returned.',
  })
  @ApiListQuery(MessageListQuerySchema, MESSAGE_LIST_PARAMETERS)
  @ApiOkExample(MessageListPageSchema, MESSAGE_EXAMPLES.listPage)
  @ApiListErrors()
  @ApiErrors(401)
  @ApiCodedError(
    403,
    'Missing `message:read` (`forbidden`), or a filter needs a permission you do not hold ' +
      '(`message_filter_forbidden`: `recipient`/`subject`/`subjectPrefix` need ' +
      '`message:reveal`, `deliveryStatus` needs `delivery:read`, `quarantineStatus` needs ' +
      '`quarantine:read`; `filter` and `permission` name it)',
    ['forbidden', MESSAGE_FILTER_FORBIDDEN],
    { filter: { type: 'string' }, permission: { type: 'string' } },
  )
  @ApiCodedError(404, 'The `domainId` is unknown or belongs to another organization', [
    DOMAIN_NOT_FOUND,
  ])
  @ApiCodedError(
    422,
    '`subjectPrefix` matches more than API_MESSAGES_SEARCH_MAX_MATCHES messages of the range ' +
      '(`maxMatches`): type more of the subject, use `subject` or narrow the range',
    [MESSAGE_SEARCH_TOO_BROAD],
    { maxMatches: { type: 'integer' } },
  )
  @ApiCodedError(
    503,
    'The replica returned a row that does not echo the query (`inconsistent_read`, retry), a ' +
      '`subjectPrefix` search exceeded API_MESSAGES_SEARCH_TIMEOUT_MS ' +
      '(`message_search_timeout`), or a dependency is unavailable',
    ['inconsistent_read', MESSAGE_SEARCH_TIMEOUT, 'service_unavailable'],
  )
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
