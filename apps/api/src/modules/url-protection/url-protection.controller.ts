import { Controller, Get, Param, Query, UseFilters } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequirePermissions,
} from '../../auth-contracts/decorators';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { CodedExceptionFilter } from '../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { ApiErrors } from '../auth/api-docs';
import { ApiMessageId, messageIdPipe } from '../deliveries/api-docs';
import {
  ApiInconsistentRead,
  ApiListErrors,
  ApiListQuery,
  ApiMessageNotFound,
  ApiOkExample,
  MESSAGE_READ,
  SCAN_BUDGET_RULE,
} from '../messages/api-docs';
import {
  type MessageUrlsPage,
  MessageUrlsPageSchema,
  type MessageUrlsQuery,
  MessageUrlsQuerySchema,
  URL_CLICKS_PARAMETERS,
  URL_EXAMPLES,
  type UrlClicksPage,
  UrlClicksPageSchema,
  type UrlClicksQuery,
  UrlClicksQuerySchema,
} from './url-protection.schemas';
import { UrlProtectionService } from './url-protection.service';

/**
 * URL protection data of the caller's organization (step 6.1 WP2, §3.3), from the read replica.
 * Translation only (UrlProtectionService). The URL engine settings stay at
 * `/scan-settings/url` (no second settings route).
 */
@ApiTags('url-protection')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ version: '1' })
export class UrlProtectionController {
  constructor(private readonly urls: UrlProtectionService) {}

  @Get('messages/:messageId/urls')
  @RequirePermissions(MESSAGE_READ)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the URLs of a message',
    description:
      'The URLs extracted from a message in sequence order (keyset `urlSeq`, v1 cursor bound to ' +
      'the message): the normalized URL fields of the tenant URL view (redirect-form URL, host, ' +
      'Unicode host, registrable domain, host kind, sources, extraction flags; never the shared ' +
      'cache outcomes), the newest scan round’s verdict and reason codes and whether it was ' +
      'rewritten, the rewrite status of the message’s latest rewrite round and the click ' +
      'counts by decision (every round). URLs are attacker-controlled text. From the read ' +
      'replica.',
  })
  @ApiMessageId()
  @ApiListQuery(MessageUrlsQuerySchema, {
    limit: 'Page size, 1-100 (default 25)',
    cursor: '`nextCursor` of the previous page',
    sort: '`urlSeq` (the only order)',
  })
  @ApiOkExample(MessageUrlsPageSchema, URL_EXAMPLES.messagePage)
  @ApiListErrors()
  @ApiErrors(401, 403)
  @ApiMessageNotFound()
  @ApiInconsistentRead()
  ofMessage(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
    @Query(new ZodValidationPipe(MessageUrlsQuerySchema)) query: MessageUrlsQuery,
  ): Promise<MessageUrlsPage> {
    return this.urls.ofMessage(principal, scope, messageId, query);
  }

  @Get('url-protection/clicks')
  @RequirePermissions(MESSAGE_READ)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List URL clicks',
    description:
      'Clicks on rewritten links of your organization’s messages in `[from, to)` (default the ' +
      'last 24 hours, at most 31 days), newest first (keyset `(clickedAt, id)` over ' +
      '`(organization_id, clicked_at)`): click public id, time, decision, verdict and reason ' +
      'codes at click time, message public id and URL sequence with its host and registrable ' +
      'domain, and the stored client network. Never token material or the token key id. ' +
      'Filters `decision`, `verdict` (comma lists) and `messageId` (one of your messages; ' +
      '`404 message_not_found` otherwise) are scan-bounded. ' +
      SCAN_BUDGET_RULE,
  })
  @ApiListQuery(UrlClicksQuerySchema, URL_CLICKS_PARAMETERS)
  @ApiOkExample(UrlClicksPageSchema, URL_EXAMPLES.clicksPage)
  @ApiListErrors()
  @ApiErrors(401, 403)
  @ApiMessageNotFound()
  @ApiInconsistentRead()
  clicks(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(UrlClicksQuerySchema)) query: UrlClicksQuery,
  ): Promise<UrlClicksPage> {
    return this.urls.clicks(principal, scope, query);
  }
}
