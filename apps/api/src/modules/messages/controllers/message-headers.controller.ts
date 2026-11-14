import { Controller, Get, Param, UseFilters } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import { CurrentScope, RequirePermissions } from '../../../auth-contracts/decorators';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CodedExceptionFilter } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { ApiErrors } from '../../auth/api-docs';
import { ApiMessageId, messageIdPipe } from '../../deliveries/api-docs';
import { ApiInconsistentRead, ApiMessageNotFound, ApiOkExample, MESSAGE_READ } from '../api-docs';
import { MESSAGE_EXAMPLES } from '../dto/message-data.examples';
import { MessageHeadersSchema, type MessageHeadersView } from '../dto/message-sensitive.schemas';
import { MessageHeadersService } from '../services/message-headers.service';

/**
 * The stored headers of a message (step 7.2 §2 E7, ADR-0062). Translation only; the logic is in
 * MessageHeadersService. Another organization's message is `404 message_not_found`.
 */
@ApiTags('messages')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'messages', version: '1' })
export class MessageHeadersController {
  constructor(private readonly service: MessageHeadersService) {}

  @Get(':messageId/headers')
  @RequirePermissions(MESSAGE_READ)
  @ApiOperation({
    summary: 'Get the stored headers of a message',
    description:
      'The headers the gateway stores for the message (the step 3.1 allow-list: From, Sender, ' +
      'Reply-To, To, Cc, Subject, Message-ID, Date, In-Reply-To, References, Return-Path, ' +
      'Authentication-Results; decoded, at most 2 048 characters each, kept 3 months) in `seq` ' +
      'order, from the read replica. **Safe subset in clear:** From, Sender, Reply-To, ' +
      'Return-Path, Date, Message-ID, In-Reply-To, References and Authentication-Results. ' +
      '**Withheld for every caller** (`value: null`, `masked: true`): To, Cc, Subject and any ' +
      'other name; holders of `message:reveal` read them through the audited ' +
      '`POST /messages/{messageId}/reveal` (`fields: ["headers"]`). `availability`: ' +
      '`available`, `not_parsed` (the MIME parse is missing, still running or failed), ' +
      '`none_stored` (parsed, nothing on the allow-list) or `retention_expired` (the message is ' +
      'older than the 3-month header retention). The full header block stays in the stored ' +
      'message in object storage and is never fetched or returned. Values are attacker-' +
      'controlled text, returned as stored and never interpreted. Not audited.',
  })
  @ApiMessageId()
  @ApiOkExample(MessageHeadersSchema, MESSAGE_EXAMPLES.headers)
  @ApiErrors(400, 401, 403)
  @ApiMessageNotFound()
  @ApiInconsistentRead()
  headers(
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
  ): Promise<MessageHeadersView> {
    return this.service.headers(scope, messageId);
  }
}
