import { Controller, Get, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CodedForbiddenException } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { RateClass } from '../../../rate-limit/rate-class.decorator';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiListErrors, ApiListQuery } from '../../messages/api-docs';
import {
  ApiInsightsForbidden,
  ApiInsightsResponse,
  ApiInsightsUnavailable,
  USER_ONLY_RULE,
} from '../api-docs';
import {
  INSIGHTS_EXAMPLES as X,
  SEARCH_PARAMETERS,
  type SearchPage,
  SearchPageSchema,
  type SearchQuery,
  SearchQuerySchema,
} from '../dto/insights.schemas';
import { INSIGHTS_PERMISSIONS as P } from '../insights.constants';
import { INSIGHTS_ERROR_CODES as C } from '../insights.errors';
import { AssistantSearchService } from '../services/search.service';

/** The principal of a `@UserOnly()` route (the guard already refused API keys). */
export function userOf(principal: Principal): UserPrincipal {
  if (principal.kind !== 'user') {
    throw new CodedForbiddenException('user_required', 'This operation requires a user');
  }
  return principal;
}

/** `GET /assistant/search` (step AI-6 D4, contracts §35.6). Translation only. */
@ApiTags('assistant')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'assistant', version: '1' })
export class AssistantSearchController {
  constructor(private readonly service: AssistantSearchService) {}

  @Get('search')
  @RequirePermissions(P.use)
  @RateClass('expensive')
  @CursorList('v1')
  @ApiOperation({
    summary: 'Search your assistant conversations',
    description:
      'Finds `q` (2-200 characters after trimming, case- and accent-insensitive, `%` and `_` ' +
      'literal) in the text of your own messages and the assistant’s answers and in the titles ' +
      'of your own conversations (never another user’s, also not for admins; deleted ' +
      'conversations and purged content are never found), newest first. A title match lists ' +
      'the conversation’s first message. Each item has a snippet of at most 160 characters ' +
      'around the first match. The scan covers your ASSISTANT_SEARCH_SCAN_MAX_MESSAGES most ' +
      'recent messages and stops after ASSISTANT_SEARCH_TIMEOUT_MS (`503 ' +
      'assistant_search_timeout`). v1 list (`assistant_search`); rate class `expensive`. From ' +
      'the read replica.' +
      USER_ONLY_RULE,
  })
  @ApiListQuery(SearchQuerySchema, SEARCH_PARAMETERS, ['q'])
  @ApiInsightsResponse(200, SearchPageSchema, X.searchPage, 'One page of matches')
  @ApiListErrors()
  @ApiInsightsForbidden()
  @ApiInsightsUnavailable(
    [C.searchTimeout],
    'the search took longer than ASSISTANT_SEARCH_TIMEOUT_MS (`assistant_search_timeout`)',
  )
  search(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(SearchQuerySchema)) query: SearchQuery,
  ): Promise<SearchPage> {
    return this.service.search(userOf(principal), scope, query);
  }
}
