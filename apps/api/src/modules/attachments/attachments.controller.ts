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
import { RateClass } from '../../rate-limit/rate-class.decorator';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { ApiErrors } from '../auth/api-docs';
import { Client } from '../auth/client-context.decorator';
import type { ClientContext } from '../auth/services/session.service';
import { ApiMessageId, messageIdPipe } from '../deliveries/api-docs';
import {
  ApiInconsistentRead,
  ApiListErrors,
  ApiListQuery,
  ApiMessageNotFound,
  ApiOkExample,
  MESSAGE_READ,
} from '../messages/api-docs';
import {
  ATTACHMENT_EXAMPLES,
  ATTACHMENT_SEARCH_PARAMETERS,
  type AttachmentSearchPage,
  AttachmentSearchPageSchema,
  type AttachmentSearchQuery,
  AttachmentSearchQuerySchema,
  type MessageAttachmentsPage,
  MessageAttachmentsPageSchema,
  type MessageAttachmentsQuery,
  MessageAttachmentsQuerySchema,
} from './attachments.schemas';
import { AttachmentsService } from './attachments.service';

/**
 * Attachment metadata and verdicts of the caller's organization (step 6.1 WP2, §3.3), from the
 * read replica. Translation only (AttachmentsService). Content is never served and there is no
 * download route: downloads exist only as the single-use grants of the quarantine workflow
 * (`POST /quarantine/entries/{entryId}/download-grants`).
 */
@ApiTags('attachments')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ version: '1' })
export class AttachmentsController {
  constructor(private readonly attachments: AttachmentsService) {}

  @Get('messages/:messageId/attachments')
  @RequirePermissions(MESSAGE_READ)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the attachments of a message',
    description:
      'The attachments (MIME leaves) of a message in part order (keyset `partIndex`, v1 cursor ' +
      'bound to the message): sanitized display filename (attacker-controlled text), declared ' +
      'and detected content type, decoded size, SHA-256, disposition, nesting depth, and the ' +
      'latest scan round’s result as in `GET /messages/{messageId}/scans` (verdict, reason ' +
      'codes, detected type, ClamAV signature, YARA rule names, archive inspection by entry ' +
      'index path, known-hash hit; never the shared cache outcome). Never the content, the ' +
      'original filename or archive entry names. From the read replica.',
  })
  @ApiMessageId()
  @ApiListQuery(MessageAttachmentsQuerySchema, {
    limit: 'Page size, 1-100 (default 25)',
    cursor: '`nextCursor` of the previous page',
    sort: '`partIndex` (the only order)',
  })
  @ApiOkExample(MessageAttachmentsPageSchema, ATTACHMENT_EXAMPLES.messagePage)
  @ApiListErrors()
  @ApiErrors(401, 403)
  @ApiMessageNotFound()
  @ApiInconsistentRead()
  ofMessage(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
    @Query(new ZodValidationPipe(MessageAttachmentsQuerySchema)) query: MessageAttachmentsQuery,
  ): Promise<MessageAttachmentsPage> {
    return this.attachments.ofMessage(principal, scope, messageId, query);
  }

  @Get('attachments')
  @RequirePermissions(MESSAGE_READ)
  @RateClass('expensive')
  @CursorList('v1')
  @ApiOperation({
    summary: 'Search attachments by SHA-256',
    description:
      'Every attachment of your organization with the given decoded-content SHA-256 received ' +
      'in `[from, to)` (default the last 24 hours, at most API_MESSAGES_MAX_RANGE_DAYS days), ' +
      'newest first: message public id, received time, part index, sanitized filename, size, ' +
      'detected type and the latest round’s verdict. Reads the `(organization_id, sha256)` ' +
      'index with partition pruning by `received_at`; pages follow the v1 list contract ' +
      '(`{ data, nextCursor }`, no totals; follow `nextCursor` until null; the signed cursor is ' +
      'bound to the hash, your organization and the first page’s window). Rate class ' +
      '`expensive`. Audited (`attachment.searched`, first page only, the hash only as its ' +
      'SHA-256). Never content and no download.',
  })
  @ApiListQuery(AttachmentSearchQuerySchema, ATTACHMENT_SEARCH_PARAMETERS, ['sha256'])
  @ApiOkExample(AttachmentSearchPageSchema, ATTACHMENT_EXAMPLES.searchPage)
  @ApiListErrors()
  @ApiErrors(401, 403)
  @ApiInconsistentRead()
  search(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(AttachmentSearchQuerySchema)) query: AttachmentSearchQuery,
    @Client() client: ClientContext,
  ): Promise<AttachmentSearchPage> {
    return this.attachments.search(principal, scope, query, client.ip);
  }
}
