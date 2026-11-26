import { Body, Controller, Delete, HttpCode, HttpStatus, Param, Put } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ApiFeedbackNotAllowed,
  ApiInsightsForbidden,
  ApiInsightsResponse,
  ApiInsightsUnavailable,
  ApiMessageIdParam,
  ApiMessageNotFound,
  USER_ONLY_RULE,
} from '../api-docs';
import {
  type FeedbackView,
  FeedbackViewSchema,
  INSIGHTS_EXAMPLES as X,
  PublicIdSchema,
  type SetFeedbackBody,
  SetFeedbackBodySchema,
} from '../dto/insights.schemas';
import { INSIGHTS_PERMISSIONS as P } from '../insights.constants';
import { AssistantFeedbackService } from '../services/feedback.service';
import { userOf } from './search.controller';

const messageId = new ZodValidationPipe(PublicIdSchema);

/** Ratings of assistant answers (step AI-6 D2, contracts §35.6). Translation only. */
@ApiTags('assistant')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'assistant/messages', version: '1' })
export class AssistantFeedbackController {
  constructor(private readonly service: AssistantFeedbackService) {}

  @Put(':messageId/feedback')
  @RequirePermissions(P.use)
  @HttpCode(HttpStatus.OK)
  @ApiMessageIdParam()
  @ApiOperation({
    summary: 'Rate an assistant answer',
    description:
      'Sets your rating of one answer of your own conversation: `rating` `up` or `down`, an ' +
      'optional `reason` and an optional `comment` (at most 500 characters; control, bidi and ' +
      'zero-width characters are removed). Replaces an earlier rating of the same answer. Only ' +
      'answers (`assistant` messages) of completed turns can be rated (`409 ' +
      'assistant_feedback_not_allowed`); another user’s or organization’s message, a message ' +
      'of a deleted conversation or one of your own messages answers `404 ' +
      'assistant_message_not_found`. Your rating and comment are visible to your ' +
      'organization’s AI administrators (`assistant:configure`); the comment is deleted with ' +
      'the conversation’s content. Audited `assistant.feedback_recorded` (rating and reason, ' +
      'never the comment).' +
      USER_ONLY_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(SetFeedbackBodySchema, { io: 'input' }),
    examples: { down: { value: X.feedbackSet }, up: { value: { rating: 'up' } } },
  })
  @ApiInsightsResponse(200, FeedbackViewSchema, X.feedback, 'The stored rating')
  @ApiMessageNotFound(
    'Unknown message, one of another user, organization or a deleted conversation, or not an ' +
      'answer',
  )
  @ApiFeedbackNotAllowed()
  @ApiInsightsForbidden()
  @ApiInsightsUnavailable()
  set(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageId) id: string,
    @Body(new ZodValidationPipe(SetFeedbackBodySchema)) body: SetFeedbackBody,
    @Client() client: ClientContext,
  ): Promise<FeedbackView> {
    return this.service.set(userOf(principal), scope, id, body, client.ip);
  }

  @Delete(':messageId/feedback')
  @RequirePermissions(P.use)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiMessageIdParam()
  @ApiOperation({
    summary: 'Remove your rating of an assistant answer',
    description:
      'Deletes your rating (and comment) of one answer of your own conversation. `404 ' +
      'assistant_message_not_found` when the message is not yours or has no rating. Audited ' +
      '`assistant.feedback_removed`.' +
      USER_ONLY_RULE,
  })
  @ApiResponse({ status: 204, description: 'Removed' })
  @ApiMessageNotFound(
    'Unknown message, one of another user, organization or a deleted conversation, or no rating',
  )
  @ApiInsightsForbidden()
  @ApiInsightsUnavailable()
  async remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageId) id: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.service.remove(userOf(principal), scope, id, client.ip);
  }
}
