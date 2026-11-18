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
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
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
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ApiArchiveConflicts,
  ApiArchiveForbidden,
  ApiArchiveResponse,
  ApiArchiveUnavailable,
  ArchiveIdempotency,
} from '../../archive/api-docs';
import { ARCHIVE_PERMISSIONS as P } from '../../archive/archive.constants';
import { ARCHIVE_ERROR_CODES as C } from '../../archive/archive.errors';
import { PAGE_PARAMETERS } from '../../archive/dto/archive.schemas';
import { ApiListErrors, ApiListQuery } from '../../messages/api-docs';
import {
  IDEMPOTENCY_KEY_INVALID,
  IDEMPOTENCY_KEY_REQUIRED,
  IDEMPOTENCY_KEY_REUSED,
} from '../../../http/idempotency/idempotency-key';
import {
  type CreateSearchBody,
  CreateSearchBodySchema,
  EDISCOVERY_EXAMPLES as X,
  HitListQuerySchema,
  type HitListQuery,
  type HitPage,
  HitPageSchema,
  type ReviewBody,
  ReviewBodySchema,
  ReviewResultSchema,
  type ReviewResultView,
  SearchListQuerySchema,
  type SearchListQuery,
  type SearchPage,
  SearchPageSchema,
  SearchSchema,
  type SearchView,
} from '../dto/ediscovery.schemas';
import { EDISCOVERY_OPERATIONS } from '../ediscovery.constants';
import { EdiscoverySearchesService } from '../services/ediscovery-searches.service';
import { ApiCaseId, ApiCaseNotFound } from './ediscovery-cases.controller';

const ApiSearchId = (): MethodDecorator =>
  ApiParam({ name: 'searchId', description: 'Case search public id (UUID)', format: 'uuid' });

const ApiSearchNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown case or search, or one of another organization', [
    C.caseNotFound,
    C.searchNotFound,
  ]);

/**
 * eDiscovery case searches, hits and review (step 8.1 §4.4 #33–#37; A17, A18). Translation only.
 */
@ApiTags('ediscovery')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'ediscovery/cases/:caseId/searches', version: '1' })
export class EdiscoverySearchesController {
  constructor(private readonly searches: EdiscoverySearchesService) {}

  @Post()
  @RequirePermissions(P.ediscovery, P.search)
  @HttpCode(HttpStatus.ACCEPTED)
  @ArchiveIdempotency(EDISCOVERY_OPERATIONS.searchCreate, 'expensive')
  @ApiOperation({
    summary: 'Run a case search',
    description:
      'Queues an `archive-search/1` search of an open case (`202`, `status: queued`) for the ' +
      'archive-worker, which pages through your tenant alias to completion (at most ' +
      'ARCHIVE_CASE_SEARCH_MAX_HITS: `truncated`), verifies every hit against MySQL and reports ' +
      'completeness (`indexComplete`, `incompleteReason`): follow it with GET ' +
      '…/searches/{searchId}. `custodians: "case"` uses the case’s custodians (written only by ' +
      'holders of `message:reveal`). Criteria that ' +
      'would confirm a masked value (`recipients`, `subject`, custodian addresses) need ' +
      '`message:reveal` (`403 archive_filter_forbidden`); the range is at most ' +
      'ARCHIVE_CASE_SEARCH_MAX_RANGE_DAYS (`400 archive_search_range_invalid`); at most ' +
      'ARCHIVE_CASE_MAX_ACTIVE_SEARCHES queued or running searches per case (`429 ' +
      'ediscovery_search_limit`). Needs the plan feature `archiving`. Audited ' +
      '`ediscovery.search_requested` (filter names and hash). Requires the Idempotency-Key ' +
      'header; rate class `expensive`.',
  })
  @ApiCaseId()
  @ApiBody({
    schema: zodToOpenApi(CreateSearchBodySchema, { io: 'input' }),
    examples: { custodians: { value: X.searchCreate } },
  })
  @ApiArchiveResponse(202, SearchSchema, X.searchQueued, 'Queued', true)
  @ApiCodedError(
    400,
    '`validation_failed`, `archive_search_range_invalid` (`maxDays`), or the Idempotency-Key ' +
      'header is missing or invalid',
    ['validation_failed', C.searchRangeInvalid, IDEMPOTENCY_KEY_REQUIRED, IDEMPOTENCY_KEY_INVALID],
    { maxDays: { type: 'integer' } },
  )
  @ApiArchiveForbidden(
    [C.notEnabled, C.filterForbidden],
    '`archiving_not_enabled`, `archive_filter_forbidden` (`filter`)',
  )
  @ApiCodedError(404, 'Unknown case, or the `holdId` is not a hold of your organization', [
    C.caseNotFound,
    C.legalHoldNotFound,
  ])
  @ApiArchiveConflicts([C.caseClosed], '`ediscovery_case_closed`', true)
  @ApiCodedError(422, 'The Idempotency-Key was already used for a different request', [
    IDEMPOTENCY_KEY_REUSED,
  ])
  @ApiCodedError(429, 'Too many active searches of the case, or rate limited', [
    C.searchLimit,
    'rate_limited',
  ])
  @ApiArchiveUnavailable()
  async create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('caseId') caseId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body(new ZodValidationPipe(CreateSearchBodySchema)) body: CreateSearchBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<SearchView> {
    const result = await this.searches.create(
      principal,
      scope,
      caseId,
      idempotencyKey,
      body,
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get()
  @RequirePermissions(P.ediscovery)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the searches of a case',
    description:
      'The searches of a case, newest first, with status, hit count and completeness. v1 list ' +
      '(`ediscovery_searches`).',
  })
  @ApiCaseId()
  @ApiListQuery(SearchListQuerySchema, {
    ...PAGE_PARAMETERS,
    status: '`queued`, `running`, `completed`, `failed`; comma list',
    sort: '`-id` (newest first)',
  })
  @ApiArchiveResponse(200, SearchPageSchema, X.searchPage, 'One page of searches')
  @ApiListErrors()
  @ApiArchiveForbidden()
  @ApiCaseNotFound()
  @ApiArchiveUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('caseId') caseId: string,
    @Query(new ZodValidationPipe(SearchListQuerySchema)) query: SearchListQuery,
  ): Promise<SearchPage> {
    return this.searches.list(principal, scope, caseId, query);
  }

  @Get(':searchId')
  @RequirePermissions(P.ediscovery)
  @ApiOperation({
    summary: 'Get a case search',
    description:
      'Status, hit count, `truncated` and the completeness flags: `indexComplete` is true only ' +
      'when the organization’s index had no change older than 60 s when the search completed ' +
      'and every UTC day of the range was verified by the reconciliation; otherwise false with ' +
      '`incompleteReason` (`index_lag`, `unverified_days`, `mismatched_days`): re-run it later.',
  })
  @ApiCaseId()
  @ApiSearchId()
  @ApiArchiveResponse(200, SearchSchema, X.search, 'The search')
  @ApiArchiveForbidden()
  @ApiSearchNotFound()
  @ApiArchiveUnavailable()
  get(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('caseId') caseId: string,
    @Param('searchId') searchId: string,
  ): Promise<SearchView> {
    return this.searches.get(principal, scope, caseId, searchId);
  }

  @Get(':searchId/hits')
  @RequirePermissions(P.ediscovery)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the hits of a case search',
    description:
      'The verified hits, newest first (`reviewTag` filter), each with its review tag and the ' +
      'masked archive record (like GET /archive/messages; `message: null` when the record was ' +
      'disposed since). The first page is audited `ediscovery.hits_viewed`. v1 list ' +
      '(`ediscovery_search_hits`).',
  })
  @ApiCaseId()
  @ApiSearchId()
  @ApiListQuery(HitListQuerySchema, {
    ...PAGE_PARAMETERS,
    reviewTag: '`untagged`, `relevant`, `not_relevant`, `privileged`; comma list',
    sort: '`-id`',
  })
  @ApiArchiveResponse(200, HitPageSchema, X.hits, 'One page of hits')
  @ApiListErrors()
  @ApiArchiveForbidden()
  @ApiSearchNotFound()
  @ApiArchiveUnavailable()
  hits(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('caseId') caseId: string,
    @Param('searchId') searchId: string,
    @Query(new ZodValidationPipe(HitListQuerySchema)) query: HitListQuery,
    @Client() client: ClientContext,
  ): Promise<HitPage> {
    return this.searches.hits(principal, scope, caseId, searchId, query, client.ip);
  }

  @Post(':searchId/review')
  @RequirePermissions(P.ediscovery)
  @UserOnly()
  @HttpCode(HttpStatus.OK)
  @ArchiveIdempotency(EDISCOVERY_OPERATIONS.review)
  @ApiOperation({
    summary: 'Tag hits of a case search',
    description:
      'Sets one review tag (`untagged`, `relevant`, `not_relevant`, `privileged`) on up to ' +
      'ARCHIVE_REVIEW_MAX_ITEMS hits of a completed search (`400 ediscovery_review_limit`, ' +
      '`409 ediscovery_search_not_completed`); ids that are not hits are counted in ' +
      '`notFound`. Exports select hits by tag. Users only (`403 user_required`). Needs the plan ' +
      'feature `archiving`. Audited `ediscovery.review_tagged` (tag, counts and message ids). ' +
      'Requires the Idempotency-Key header; rate class `sensitive`.',
  })
  @ApiCaseId()
  @ApiSearchId()
  @ApiBody({
    schema: zodToOpenApi(ReviewBodySchema, { io: 'input' }),
    examples: { relevant: { value: X.review } },
  })
  @ApiArchiveResponse(200, ReviewResultSchema, X.reviewed, 'Tagged', true)
  @ApiCodedError(
    400,
    '`validation_failed`, `ediscovery_review_limit` (`limit`), or the Idempotency-Key header ' +
      'is missing or invalid',
    ['validation_failed', C.reviewLimit, IDEMPOTENCY_KEY_REQUIRED, IDEMPOTENCY_KEY_INVALID],
    { limit: { type: 'integer' } },
  )
  @ApiCodedError(422, 'The Idempotency-Key was already used for a different request', [
    IDEMPOTENCY_KEY_REUSED,
  ])
  @ApiArchiveForbidden([C.notEnabled], '`archiving_not_enabled`')
  @ApiSearchNotFound()
  @ApiArchiveConflicts(
    [C.searchNotCompleted, C.caseClosed],
    '`ediscovery_search_not_completed` (`status`), `ediscovery_case_closed`',
    true,
    { status: { type: 'string' } },
  )
  @ApiArchiveUnavailable()
  async review(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('caseId') caseId: string,
    @Param('searchId') searchId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body(new ZodValidationPipe(ReviewBodySchema)) body: ReviewBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ReviewResultView> {
    const result = await this.searches.review(
      principal,
      scope,
      caseId,
      searchId,
      idempotencyKey,
      body,
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}
