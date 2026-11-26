import { Controller, Get, Param, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiListErrors, ApiListQuery } from '../../messages/api-docs';
import {
  ApiAdminConversationIdParam,
  ApiAdminConversationNotFound,
  ApiInsightsForbidden,
  ApiInsightsResponse,
  ApiInsightsUnavailable,
  METADATA_ONLY_RULE,
  USER_ONLY_RULE,
} from '../api-docs';
import {
  type AdminFeedbackPage,
  AdminFeedbackPageSchema,
  AUDIT_CONVERSATIONS_PARAMETERS,
  AUDIT_EXECUTIONS_PARAMETERS,
  type AuditConversationDetail,
  AuditConversationDetailSchema,
  type AuditConversationPage,
  AuditConversationPageSchema,
  type AuditConversationsQuery,
  AuditConversationsQuerySchema,
  type AuditExecutionPage,
  AuditExecutionPageSchema,
  type AuditExecutionsQuery,
  AuditExecutionsQuerySchema,
  FEEDBACK_LIST_PARAMETERS,
  type FeedbackListQuery,
  FeedbackListQuerySchema,
  INSIGHTS_EXAMPLES as X,
  PublicIdSchema,
  USAGE_BY_USER_PARAMETERS,
  type UsageByUserQuery,
  UsageByUserQuerySchema,
  type UserUsagePage,
  UserUsagePageSchema,
} from '../dto/insights.schemas';
import { INSIGHTS_PERMISSIONS as P } from '../insights.constants';
import { AssistantAdminService } from '../services/admin.service';
import { AssistantAuditViewService } from '../services/audit-view.service';
import { userOf } from './search.controller';

const conversationId = new ZodValidationPipe(PublicIdSchema);

/** Tenant AI administration reads (step AI-6 D1, D2; `assistant:configure`). Translation only. */
@ApiTags('assistant')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'assistant/admin', version: '1' })
export class AssistantAdminController {
  constructor(private readonly service: AssistantAdminService) {}

  @Get('usage/users')
  @RequirePermissions(P.configure)
  @CursorList('v1')
  @ApiOperation({
    summary: 'Get the AI assistant usage per user and day',
    description:
      'Your organization’s assistant use per UTC day, user and key source (`platform` or ' +
      '`tenant`) between `from` and `to` (YYYY-MM-DD, inclusive, at most 92 days; default the ' +
      'last 30 days), newest day first: turns, input, output, cache read and cache write ' +
      'tokens, total tokens and the **estimated** cost in micro-USD (sum of the priced models; ' +
      '`null` when no price is known). `totals.users` sums the whole window for each user on ' +
      'the page, `totals.overall` the whole window. Users are shown with display name and ' +
      'e-mail (platform operators who worked under an override: public id only). Needs ' +
      '`assistant:configure`. v1 list (`assistant_admin_usage_users`). From the read replica.' +
      USER_ONLY_RULE,
  })
  @ApiListQuery(UsageByUserQuerySchema, USAGE_BY_USER_PARAMETERS)
  @ApiInsightsResponse(200, UserUsagePageSchema, X.usagePage, 'One page of usage rows')
  @ApiListErrors()
  @ApiInsightsForbidden()
  @ApiInsightsUnavailable()
  usageByUser(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(UsageByUserQuerySchema)) query: UsageByUserQuery,
  ): Promise<UserUsagePage> {
    return this.service.usageByUser(userOf(principal), scope, query);
  }

  @Get('feedback')
  @RequirePermissions(P.configure)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the feedback on AI assistant answers',
    description:
      'Ratings of assistant answers in your organization created in `[from, to)` (at most 92 ' +
      'days; default the last 30 days), newest first; filters `rating`, `reason`, `userId`. ' +
      'Each item: rating, reason, the comment the user submitted (null after the content ' +
      'purge), the user, created/updated, conversation and message public ids, the answered ' +
      'turn’s provider, model, prompt version and data-sharing level, and the names of the ' +
      'tools the turn called. Never the conversation’s messages. Needs `assistant:configure`. ' +
      'v1 list (`assistant_admin_feedback`). From the read replica.' +
      USER_ONLY_RULE,
  })
  @ApiListQuery(FeedbackListQuerySchema, FEEDBACK_LIST_PARAMETERS)
  @ApiInsightsResponse(200, AdminFeedbackPageSchema, X.feedbackPage, 'One page of feedback')
  @ApiListErrors()
  @ApiInsightsForbidden()
  @ApiInsightsUnavailable()
  feedback(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(FeedbackListQuerySchema)) query: FeedbackListQuery,
  ): Promise<AdminFeedbackPage> {
    return this.service.feedbackList(userOf(principal), scope, query);
  }
}

/** The metadata-only conversation audit view (step AI-6 D4, I24; `audit:read`). Translation only. */
@ApiTags('assistant')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'assistant/admin', version: '1' })
export class AssistantAdminAuditController {
  constructor(private readonly service: AssistantAuditViewService) {}

  @Get('conversations')
  @RequirePermissions(P.auditRead)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the assistant conversations of your organization (audit)',
    description:
      'Every assistant conversation of your organization (all users, incl. deleted ones and ' +
      'those held by platform operators under an override, flagged `underPlatformOverride`), ' +
      'newest activity first; filters `userId`, `status`, and `from`/`to` on the last turn. ' +
      'Each item: public id, user, status, created, last turn, turn and segment counts, content ' +
      'purged, and totals (tokens, estimated cost, tool calls, denied calls, confirmations by ' +
      'status, reports, ratings up/down). **No title.** Needs `audit:read`. v1 list ' +
      '(`assistant_admin_conversations`). From the read replica.' +
      METADATA_ONLY_RULE +
      USER_ONLY_RULE,
  })
  @ApiListQuery(AuditConversationsQuerySchema, AUDIT_CONVERSATIONS_PARAMETERS)
  @ApiInsightsResponse(
    200,
    AuditConversationPageSchema,
    X.conversationPage,
    'One page of conversation headers',
  )
  @ApiListErrors()
  @ApiInsightsForbidden()
  @ApiInsightsUnavailable()
  conversations(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(AuditConversationsQuerySchema)) query: AuditConversationsQuery,
  ): Promise<AuditConversationPage> {
    return this.service.conversations(userOf(principal), scope, query);
  }

  @Get('conversations/:conversationId')
  @RequirePermissions(P.auditRead)
  @ApiAdminConversationIdParam()
  @ApiOperation({
    summary: 'Get the audit view of an assistant conversation',
    description:
      'The conversation header of the list plus `turns[]` (provider, model, key source, data ' +
      'sharing, fallback, prompt and registry versions, rounds, tool calls, tokens, cost, ' +
      'latency, error code, times), `executions[]` (tool, operation, method, access, risk, ' +
      'decision, status, HTTP status, error code, the redacted parameters as stored, resource, ' +
      'latency, correlation id), `confirmations[]`, `reports[]` (status, period, sections, ' +
      'size, background job, deliveries with the recipient domain only) and `feedback[]` ' +
      '(rating and reason, never the comment); at most 1000 rows each (`truncated`). Another ' +
      'organization’s id answers `404`. Audited `assistant.audit_viewed`. Needs `audit:read`. ' +
      'From the read replica.' +
      METADATA_ONLY_RULE +
      USER_ONLY_RULE,
  })
  @ApiInsightsResponse(
    200,
    AuditConversationDetailSchema,
    X.conversation,
    'The conversation’s metadata',
  )
  @ApiAdminConversationNotFound()
  @ApiInsightsForbidden()
  @ApiInsightsUnavailable()
  conversation(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('conversationId', conversationId) id: string,
    @Client() client: ClientContext,
  ): Promise<AuditConversationDetail> {
    return this.service.conversation(userOf(principal), scope, id, client.ip);
  }

  @Get('executions')
  @RequirePermissions(P.auditRead)
  @CursorList('v1')
  @ApiOperation({
    summary: 'Search the assistant tool executions of your organization (audit)',
    description:
      'Tool executions of every assistant conversation of your organization created in ' +
      '`[from, to)` (at most 92 days; default the last 30 days), newest first; filters ' +
      '`userId`, `conversationId`, `tool`, `module`, `decision`, `status`, `risk`, `access`, ' +
      '`correlationId`. Items as in the conversation audit view, with the conversation and ' +
      'user. No content search across users. Needs `audit:read`. v1 list ' +
      '(`assistant_admin_executions`). From the read replica.' +
      METADATA_ONLY_RULE +
      USER_ONLY_RULE,
  })
  @ApiListQuery(AuditExecutionsQuerySchema, AUDIT_EXECUTIONS_PARAMETERS)
  @ApiInsightsResponse(200, AuditExecutionPageSchema, X.executionPage, 'One page of executions')
  @ApiListErrors()
  @ApiInsightsForbidden()
  @ApiInsightsUnavailable()
  executions(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(AuditExecutionsQuerySchema)) query: AuditExecutionsQuery,
  ): Promise<AuditExecutionPage> {
    return this.service.executions(userOf(principal), scope, query);
  }
}
