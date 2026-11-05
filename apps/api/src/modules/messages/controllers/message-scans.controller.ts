import { Controller, Get, Param, Query, UseFilters } from '@nestjs/common';
import { ApiBearerAuth, ApiOkResponse, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import { CurrentScope, RequirePermissions } from '../../../auth-contracts/decorators';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CodedExceptionFilter } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { ApiMessageId, messageIdPipe } from '../../deliveries/api-docs';
import { ApiQueryFrom } from '../../organizations/api-docs';
import { ApiMessageNotFound, MESSAGE_READ } from '../api-docs';
import {
  type MessageScansPage,
  MessageScansPageSchema,
  type MessageScansQuery,
  MessageScansQuerySchema,
} from '../dto/message-scans.schemas';
import { MessageScansReadService } from '../services/message-scans-read.service';

/**
 * Security scan results of a message of the caller's organization (step 4.1 S16), from the read
 * replica. Translation only; the logic is in MessageScansReadService.
 */
@ApiTags('messages')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'messages', version: '1' })
export class MessageScansController {
  constructor(private readonly scans: MessageScansReadService) {}

  @Get(':messageId/scans')
  @RequirePermissions(MESSAGE_READ)
  @ApiOperation({
    summary: 'Get the security scan results of a message',
    description:
      'One entry per scan round (`round` = lifecycle round: 0 is the initial scan, each ' +
      'rescan adds one), newest first, cursor-paginated (at most 20 rounds per page): status, ' +
      'aggregate verdict (`clean`, `spam`, `suspicious`, `malicious`, `unknown`, `timeout`, ' +
      '`error`; null while running), reason codes, required engines, the deadline, the ' +
      'SPF/DKIM/DMARC/ARC results and per engine its final result (outcome, score, threshold, ' +
      'action, reason codes, symbols with bounded options, engine and settings versions) and ' +
      'every attempt (failed attempts are retried and listed with their error code). From ' +
      'the read replica: a round that just completed may still show as running. Symbol ' +
      'options can contain addresses or URLs of the message.',
  })
  @ApiMessageId()
  @ApiQueryFrom(MessageScansQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(MessageScansPageSchema) })
  @ApiErrors(400, 401, 403)
  @ApiMessageNotFound()
  scansOf(
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
    @Query(new ZodValidationPipe(MessageScansQuerySchema)) query: MessageScansQuery,
  ): Promise<MessageScansPage> {
    return this.scans.list(scope, messageId, query);
  }
}
