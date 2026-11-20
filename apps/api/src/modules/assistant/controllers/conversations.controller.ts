import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
} from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
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
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiListErrors, ApiListQuery } from '../../messages/api-docs';
import {
  ApiAssistantForbidden,
  ApiAssistantGates,
  ApiAssistantResponse,
  ApiAssistantUnavailable,
  ApiConversationIdParam,
  ApiConversationNotFound,
  USER_ONLY_RULE,
} from '../api-docs';
import { ASSISTANT_PERMISSIONS as P } from '../assistant.constants';
import { ASSISTANT_ERROR_CODES as C } from '../assistant.errors';
import {
  ASSISTANT_EXAMPLES as X,
  CONVERSATION_LIST_PARAMETERS,
  type ConversationListQuery,
  ConversationListQuerySchema,
  type ConversationPage,
  ConversationPageSchema,
  ConversationSchema,
  type ConversationView,
  type CreateConversationBody,
  CreateConversationBodySchema,
  MESSAGE_LIST_PARAMETERS,
  type MessageListQuery,
  MessageListQuerySchema,
  type MessagePage,
  MessagePageSchema,
  PublicIdSchema,
  type UpdateConversationBody,
  UpdateConversationBodySchema,
} from '../dto/assistant.schemas';
import { ConversationService } from '../services/conversation.service';
import { userOf } from './assistant.controller';

const conversationId = new ZodValidationPipe(PublicIdSchema);

/** Conversations of the caller (step AI-1 §4.1, D12, Q9, Q11). Translation only. */
@ApiTags('assistant')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'assistant/conversations', version: '1' })
export class AssistantConversationsController {
  constructor(private readonly conversations: ConversationService) {}

  @Get()
  @RequirePermissions(P.use)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List your assistant conversations',
    description:
      'Your own conversations (never another user’s, also not for admins), newest activity ' +
      'first; filters `status` (`active`, `archived`) and `q` (title contains). Deleted ' +
      'conversations are never listed. Under a platform override: the conversations you held ' +
      'in the override’s target organization. v1 list (`assistant_conversations`). From the ' +
      'read replica.' +
      USER_ONLY_RULE,
  })
  @ApiListQuery(ConversationListQuerySchema, CONVERSATION_LIST_PARAMETERS)
  @ApiAssistantResponse(200, ConversationPageSchema, X.conversationPage, 'One page')
  @ApiListErrors()
  @ApiAssistantForbidden()
  @ApiAssistantUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ConversationListQuerySchema)) query: ConversationListQuery,
  ): Promise<ConversationPage> {
    return this.conversations.list(userOf(principal), scope, query);
  }

  @Post()
  @RequirePermissions(P.use)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Start an assistant conversation',
    description:
      'A new, empty conversation (optional `title`; otherwise the first message names it). ' +
      'Needs the assistant available to your organization (`503 assistant_disabled`, `403 ' +
      'assistant_not_enabled`, `403 assistant_tenant_disabled`) and fewer than ' +
      'ASSISTANT_MAX_CONVERSATIONS_PER_USER conversations (`409 ' +
      'assistant_conversation_limit` with `limit`; delete one first). Under a platform ' +
      'override the conversation belongs to the override’s target organization and records ' +
      'the override.' +
      USER_ONLY_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(CreateConversationBodySchema, { io: 'input' }),
    examples: { titled: { value: X.conversationCreate }, untitled: { value: {} } },
  })
  @ApiAssistantResponse(201, ConversationSchema, X.conversation, 'The new conversation')
  @ApiAssistantGates()
  @ApiCodedError(409, 'You have the maximum number of conversations', [C.conversationLimit], {
    limit: { type: 'integer' },
  })
  @ApiAssistantUnavailable(
    [C.disabled],
    'the AI assistant is off on this platform (`assistant_disabled`)',
  )
  create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(CreateConversationBodySchema)) body: CreateConversationBody,
  ): Promise<ConversationView> {
    return this.conversations.create(userOf(principal), scope, body);
  }

  @Get(':conversationId')
  @RequirePermissions(P.use)
  @ApiConversationIdParam()
  @ApiOperation({
    summary: 'Get an assistant conversation',
    description:
      'One of your own conversations: title, status, turn count, last activity, when its ' +
      'content is purged and whether it was. Another user’s or organization’s id answers ' +
      '`404`.' +
      USER_ONLY_RULE,
  })
  @ApiAssistantResponse(200, ConversationSchema, X.conversation, 'The conversation')
  @ApiConversationNotFound()
  @ApiAssistantForbidden()
  @ApiAssistantUnavailable()
  get(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('conversationId', conversationId) id: string,
  ): Promise<ConversationView> {
    return this.conversations.get(userOf(principal), scope, id);
  }

  @Patch(':conversationId')
  @RequirePermissions(P.use)
  @ApiConversationIdParam()
  @ApiOperation({
    summary: 'Rename or archive an assistant conversation',
    description:
      'Changes the `title` and/or the `status` (`active`, `archived`) of one of your own ' +
      'conversations. A new turn makes an archived conversation active again.' +
      USER_ONLY_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(UpdateConversationBodySchema, { io: 'input' }),
    examples: { archive: { value: X.conversationUpdate } },
  })
  @ApiAssistantResponse(200, ConversationSchema, X.conversation, 'The updated conversation')
  @ApiConversationNotFound()
  @ApiAssistantForbidden()
  @ApiAssistantUnavailable()
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('conversationId', conversationId) id: string,
    @Body(new ZodValidationPipe(UpdateConversationBodySchema)) body: UpdateConversationBody,
  ): Promise<ConversationView> {
    return this.conversations.update(userOf(principal), scope, id, body);
  }

  @Delete(':conversationId')
  @RequirePermissions(P.use)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiConversationIdParam()
  @ApiOperation({
    summary: 'Delete an assistant conversation',
    description:
      'Deletes one of your own conversations: it disappears at once and its content (title, ' +
      'messages, transcripts, result cards) is purged immediately; execution metadata stays ' +
      'for ASSISTANT_EXECUTION_RETENTION_DAYS and the audit trail (`assistant.tool_executed`) ' +
      'per audit retention. Audited `assistant.conversation_deleted`.' +
      USER_ONLY_RULE,
  })
  @ApiResponse({ status: 204, description: 'Deleted and purged' })
  @ApiConversationNotFound()
  @ApiAssistantForbidden()
  @ApiAssistantUnavailable()
  async remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('conversationId', conversationId) id: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.conversations.remove(userOf(principal), scope, id, client.ip);
  }
}

/** Messages of a conversation (step AI-1 §4.1). */
@ApiTags('assistant')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'assistant/conversations', version: '1' })
export class AssistantMessagesController {
  constructor(private readonly conversations: ConversationService) {}

  @Get(':conversationId/messages')
  @RequirePermissions(P.use)
  @CursorList('v1')
  @ApiConversationIdParam()
  @ApiOperation({
    summary: 'List the messages of an assistant conversation',
    description:
      'Your messages and the assistant’s answers, oldest first, each with its turn (status, ' +
      'error code) and the turn’s tool executions with their result cards (`assistant-card/1`, ' +
      'masked metadata as the API returned it; null after the content purge). v1 list ' +
      '(`assistant_messages`). From the read replica.' +
      USER_ONLY_RULE,
  })
  @ApiListQuery(MessageListQuerySchema, MESSAGE_LIST_PARAMETERS)
  @ApiAssistantResponse(200, MessagePageSchema, X.messagePage, 'One page of messages')
  @ApiListErrors()
  @ApiConversationNotFound()
  @ApiAssistantForbidden()
  @ApiAssistantUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('conversationId', conversationId) id: string,
    @Query(new ZodValidationPipe(MessageListQuerySchema)) query: MessageListQuery,
  ): Promise<MessagePage> {
    return this.conversations.messages(userOf(principal), scope, id, query);
  }
}
