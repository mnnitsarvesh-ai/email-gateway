import {
  Body,
  Controller,
  Get,
  Header,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Res,
} from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import type { QuarantinePreview } from '@email-gateway/mail-safety';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError } from '../../../http/coded-exception';
import {
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
} from '../../../http/idempotency/idempotency-key';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { RateClass } from '../../../rate-limit/rate-class.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiListQuery } from '../../messages/api-docs';
import {
  ApiArchiveConflicts,
  ApiArchiveForbidden,
  ApiArchiveMessageNotFound,
  ApiArchiveResponse,
  ApiArchiveUnavailable,
  ApiContentGone,
  ApiIntegrityFailed,
  ApiKeyedErrors,
  ApiMessageIdParam,
  ArchiveIdempotency,
} from '../api-docs';
import { ArchiveRateLimit } from '../archive-rate-limit';
import { ARCHIVE_OPERATIONS, ARCHIVE_PERMISSIONS as P, NO_STORE } from '../archive.constants';
import { ARCHIVE_ERROR_CODES as C } from '../archive.errors';
import {
  ARCHIVE_EXAMPLES as X,
  ARCHIVE_SEARCH_PARAMETERS,
  ArchiveJournalViewSchema,
  type ArchiveJournalView,
  ArchiveMessageDetailSchema,
  type ArchiveMessageDetailView,
  type ArchiveMessagePage,
  ArchiveMessagePageSchema,
  ArchivePreviewSchema,
  type ArchiveRevealBody,
  ArchiveRevealBodySchema,
  ArchiveRevealSchema,
  type ArchiveRevealView,
  type ArchiveSearchQuery,
  ArchiveSearchQuerySchema,
  ArchiveSecurityViewSchema,
  type ArchiveSecurityView,
  DisposeAcceptedSchema,
  type DisposeAccepted,
  type DisposeBody,
  DisposeBodySchema,
  type DownloadGrantBody,
  DownloadGrantBodySchema,
  DownloadGrantSchema,
  type DownloadGrantView,
} from '../dto/archive.schemas';
import { ArchiveDownloadsService } from '../services/archive-downloads.service';
import { ArchiveMessagesService } from '../services/archive-messages.service';
import { ArchiveSearchService } from '../services/archive-search.service';

/** Header of the search freshness (A17). */
export const INDEX_LAG_HEADER = 'X-EG-Index-Lag-Seconds';

const CONTENT_RULE =
  ' The record is re-read on the writer first (a record being disposed is `410 ' +
  'archive_content_unavailable`); the audit row is committed before content is returned.';
const CUSTOMER_ONLY =
  ' Customer-only: refused under a platform override (`403 archive_override_forbidden`). ' +
  'MFA-authenticated users only (`403 mfa_required`; API keys `403 user_required`).';

/**
 * Archived messages (step 8.1 §4.4 #15–#21, #23; A17, A19, ADR-0062). Translation only.
 */
@ApiTags('archive')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'archive/messages', version: '1' })
export class ArchiveMessagesController {
  constructor(
    private readonly search: ArchiveSearchService,
    private readonly messages: ArchiveMessagesService,
    private readonly downloads: ArchiveDownloadsService,
  ) {}

  @Get()
  @RequirePermissions(P.search)
  @CursorList('v1')
  @RateClass('expensive')
  @ApiOperation({
    summary: 'Search archived messages',
    description:
      'Metadata search of your organization’s archive (OpenSearch, through your tenant alias; ' +
      'no bodies, no attachment content). `from` and `to` are required (at most ' +
      'ARCHIVE_SEARCH_MAX_RANGE_DAYS, `400 archive_search_range_invalid`). Filters that would ' +
      'confirm a masked value — `recipient`, `subject`, `custodian` — need `message:reveal`; ' +
      '`holdId` needs `archive:legal_hold` or `ediscovery:manage` (`403 ' +
      'archive_filter_forbidden`, `filter`, before any query). Results are masked for every ' +
      'caller (subjects null, recipients `f***@example.com`; sender side and attachment names ' +
      'in clear); clear values only through the audited reveal. No totals; `nextCursor` (v1, ' +
      '`archive_messages`) is bound to the filters, the range and the sort. The response ' +
      'header `X-EG-Index-Lag-Seconds` gives the age of your oldest change not yet indexed. ' +
      'Search unavailable or not configured: `503 archive_search_unavailable` (detail and ' +
      'content routes keep working). The first page is audited `archive.searched` (filter ' +
      'names and hashes, never values). Rate class `expensive`.',
  })
  @ApiListQuery(ArchiveSearchQuerySchema, ARCHIVE_SEARCH_PARAMETERS, ['from', 'to'])
  @ApiArchiveResponse(200, ArchiveMessagePageSchema, X.messagePage, 'One page of masked results')
  @ApiCodedError(
    400,
    '`validation_failed`, `cursor_invalid`, or `archive_search_range_invalid` (`maxDays`)',
    ['validation_failed', 'cursor_invalid', C.searchRangeInvalid],
    { maxDays: { type: 'integer' } },
  )
  @ApiArchiveForbidden([C.filterForbidden], '`archive_filter_forbidden` (`filter`)')
  @ApiCodedError(404, 'The `holdId` is not an active hold of your organization', [
    C.legalHoldNotFound,
  ])
  @ApiArchiveUnavailable([C.searchUnavailable])
  async list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ArchiveSearchQuerySchema)) query: ArchiveSearchQuery,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ArchiveMessagePage> {
    const result = await this.search.search(principal, scope, query, client.ip);
    res.setHeader(INDEX_LAG_HEADER, String(result.lagSeconds));
    return result.page;
  }

  @Get(':messageId')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get an archived message',
    description:
      'The archive record from MySQL (read replica): masked metadata and parties, capture ' +
      '(sources, category, message state), retention (stored and effective retain-until, ' +
      'expiry action), the legal-hold flag (the matching holds only for holders of ' +
      '`archive:legal_hold` or `ediscovery:manage`), immutability, integrity (original ' +
      'SHA-256, sizes, encryption format, key version) and the linked scan rounds. Audited ' +
      '`archive.message_viewed`.',
  })
  @ApiMessageIdParam()
  @ApiArchiveResponse(200, ArchiveMessageDetailSchema, X.detail, 'The archived message')
  @ApiArchiveForbidden()
  @ApiArchiveMessageNotFound()
  @ApiArchiveUnavailable()
  detail(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId') messageId: string,
    @Client() client: ClientContext,
  ): Promise<ArchiveMessageDetailView> {
    return this.messages.detail(principal, scope, messageId, client.ip);
  }

  @Get(':messageId/journal')
  @RequirePermissions(P.read)
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Get the journal report of an archived message',
    description:
      'The decrypted journal report frozen at capture: envelope recipients (BCC included, ' +
      'masked), message facts (subject masked), the stored headers (the ADR-0062 safe subset ' +
      'in clear; To, Cc, Subject and unknown names `value: null, masked: true`), attachments ' +
      '(names, types, sizes, SHA-256), the parse outcome and deliveries at capture. Audited ' +
      '`archive.journal_viewed`.' +
      CONTENT_RULE,
  })
  @ApiMessageIdParam()
  @ApiArchiveResponse(200, ArchiveJournalViewSchema, X.journal, 'The journal report')
  @ApiArchiveForbidden()
  @ApiArchiveMessageNotFound()
  @ApiContentGone()
  @ApiIntegrityFailed()
  @ApiArchiveUnavailable()
  journal(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId') messageId: string,
    @Client() client: ClientContext,
  ): Promise<ArchiveJournalView> {
    return this.messages.journal(principal, scope, messageId, client.ip);
  }

  @Get(':messageId/security')
  @RequirePermissions(P.read)
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Get the frozen scan results of an archived message',
    description:
      'Every scan round linked at capture (never a rescan), decrypted from its frozen ' +
      'snapshot and mapped exactly like GET /messages/{messageId}/scans (DLP sections only for ' +
      '`dlp:read` holders; DLP evidence, URL click summaries and BEC feedback are live-only and ' +
      'not retained). Audited `archive.security_viewed`.' +
      CONTENT_RULE,
  })
  @ApiMessageIdParam()
  @ApiArchiveResponse(200, ArchiveSecurityViewSchema, X.security, 'The frozen scan rounds')
  @ApiArchiveForbidden()
  @ApiArchiveMessageNotFound()
  @ApiContentGone()
  @ApiIntegrityFailed()
  @ApiArchiveUnavailable()
  security(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId') messageId: string,
    @Client() client: ClientContext,
  ): Promise<ArchiveSecurityView> {
    return this.messages.security(principal, scope, messageId, client.ip);
  }

  @Post(':messageId/reveal')
  @RequirePermissions(P.read, P.reveal)
  @HttpCode(HttpStatus.OK)
  @ArchiveRateLimit('reveal')
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Reveal masked values of an archived message',
    description:
      'The clear subject, envelope recipient addresses (≤ 1 000) and To/Cc/Subject header ' +
      'values (from the journal report) of one archived message. Needs `archive:read` and ' +
      '`message:reveal`. One `archive.revealed` audit row (fields and counts, never values) is ' +
      'committed before the response; if it cannot be written nothing is returned (`503 ' +
      'service_unavailable`). ARCHIVE_REVEAL_PER_MINUTE per caller (`429 rate_limited`, ' +
      '`scope: route`, `RateLimit-*`, `Retry-After`). Not idempotency-stored (the values would ' +
      'be persisted).' +
      CONTENT_RULE,
  })
  @ApiMessageIdParam()
  @ApiBody({
    schema: zodToOpenApi(ArchiveRevealBodySchema, { io: 'input' }),
    examples: { subjectAndHeaders: { value: X.reveal } },
  })
  @ApiArchiveResponse(200, ArchiveRevealSchema, X.revealed, 'The clear values')
  @ApiArchiveForbidden()
  @ApiArchiveMessageNotFound()
  @ApiContentGone()
  @ApiIntegrityFailed()
  @ApiArchiveUnavailable()
  reveal(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId') messageId: string,
    @Body(new ZodValidationPipe(ArchiveRevealBodySchema)) body: ArchiveRevealBody,
    @Client() client: ClientContext,
  ): Promise<ArchiveRevealView> {
    return this.messages.reveal(principal, scope, messageId, body, client.ip);
  }

  @Get(':messageId/preview')
  @RequirePermissions(P.retrieve)
  @UserOnly()
  @RequireMfa()
  @ArchiveRateLimit('preview')
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Preview an archived message (sanitized, DLP-masked)',
    description:
      'JSON text only, never HTML (`preview/1` of the quarantine preview): the stored headers, ' +
      'the decoded text part frozen at capture (else the HTML part converted to text; active ' +
      'content dropped), links listed defanged and not clickable with the latest frozen URL ' +
      'verdicts, attachments with their latest frozen verdicts (never served here), DLP values ' +
      'masked. Needs the tenant switch `access.previewEnabled` (`403 archive_preview_disabled`). ' +
      'The `archive.previewed` audit row is committed before anything is decrypted. ' +
      'ARCHIVE_PREVIEW_PER_MINUTE per caller.' +
      CUSTOMER_ONLY +
      CONTENT_RULE,
  })
  @ApiMessageIdParam()
  @ApiArchiveResponse(200, ArchivePreviewSchema, X.preview, 'The sanitized preview')
  @ApiArchiveForbidden(
    [C.overrideForbidden, C.previewDisabled],
    '`archive_override_forbidden`, `archive_preview_disabled`',
  )
  @ApiArchiveMessageNotFound()
  @ApiContentGone()
  @ApiIntegrityFailed()
  @ApiArchiveUnavailable()
  preview(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId') messageId: string,
    @Client() client: ClientContext,
  ): Promise<QuarantinePreview> {
    return this.messages.preview(principal, scope, messageId, client.ip);
  }

  @Post(':messageId/download-grants')
  @RequirePermissions(P.retrieve)
  @UserOnly()
  @RequireMfa()
  @ArchiveRateLimit('download_grant')
  @HttpCode(HttpStatus.CREATED)
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Grant a single-use download of the original message',
    description:
      'Not offered by default: the tenant switch `access.downloadEnabled` is required (`403 ' +
      'archive_download_disabled`). Fresh re-authorization: your password, and a TOTP code when ' +
      'MFA is enrolled; failures count toward the login lockout (`401 ' +
      'quarantine_reauth_failed`, the step 5.3 code). Malicious records are refused (`409 ' +
      'archive_download_blocked`, `reason: malicious`; use an eDiscovery export with the ' +
      'malicious acknowledgement). The token is bound to your organization, you, the kind and ' +
      'the message and valid ARCHIVE_DOWNLOAD_TOKEN_TTL_SECONDS; download it with GET ' +
      '/archive/downloads/{token}. ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR per user. Audited ' +
      '`archive.download_granted`. Not idempotency-stored (the response carries the token).' +
      CUSTOMER_ONLY,
  })
  @ApiMessageIdParam()
  @ApiBody({
    schema: zodToOpenApi(DownloadGrantBodySchema, { io: 'input' }),
    examples: { reauth: { value: X.grantBody } },
  })
  @ApiArchiveResponse(201, DownloadGrantSchema, X.grant, 'The single-use download token')
  @ApiCodedError(401, 'Re-authorization failed', [C.reauthFailed])
  @ApiArchiveForbidden(
    [C.overrideForbidden, C.downloadDisabled],
    '`archive_override_forbidden`, `archive_download_disabled`',
  )
  @ApiArchiveMessageNotFound()
  @ApiArchiveConflicts([C.downloadBlocked], '`archive_download_blocked` (`reason`)', false, {
    reason: { type: 'string' },
  })
  @ApiContentGone()
  @ApiArchiveUnavailable()
  grant(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId') messageId: string,
    @Body(new ZodValidationPipe(DownloadGrantBodySchema)) body: DownloadGrantBody,
    @Client() client: ClientContext,
  ): Promise<DownloadGrantView> {
    return this.downloads.grantMessage(principal, scope, messageId, body, client);
  }

  @Post(':messageId/dispose')
  @RequirePermissions(P.manage)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.ACCEPTED)
  @ArchiveIdempotency(ARCHIVE_OPERATIONS.dispose)
  @ApiOperation({
    summary: 'Dispose of a reviewed archived message',
    description:
      'Only for a record in `expiry_review` (`409 archive_dispose_not_allowed`, `reason`). ' +
      'Retention and legal holds are re-checked on the writer with the record locked: a live ' +
      'policy that now retains it longer, a running Object Lock or a matching active hold ' +
      'refuse the disposal (`reason: retention | legal_hold`). Otherwise the record is ' +
      'crypto-shredded at once (its data key is destroyed: no copy can be decrypted any more), ' +
      'logged in the disposal log and queued: the archive-worker deletes every object version ' +
      '(also in replica buckets), the index document and the row. `202`. Audited ' +
      '`archive.disposal_requested`. Requires the Idempotency-Key header; rate class ' +
      '`sensitive`. MFA-authenticated users only.',
  })
  @ApiMessageIdParam()
  @ApiBody({
    schema: zodToOpenApi(DisposeBodySchema, { io: 'input' }),
    examples: { reviewed: { value: X.dispose } },
  })
  @ApiArchiveResponse(202, DisposeAcceptedSchema, X.disposed, 'Disposal started', true)
  @ApiKeyedErrors()
  @ApiArchiveForbidden()
  @ApiArchiveMessageNotFound()
  @ApiArchiveConflicts([C.disposeNotAllowed], '`archive_dispose_not_allowed` (`reason`)', true, {
    reason: { type: 'string' },
  })
  @ApiArchiveUnavailable()
  async dispose(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId') messageId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body(new ZodValidationPipe(DisposeBodySchema)) body: DisposeBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<DisposeAccepted> {
    const result = await this.messages.dispose(
      principal,
      scope,
      messageId,
      idempotencyKey,
      body,
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}
