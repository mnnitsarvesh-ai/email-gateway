import { Body, Controller, Get, HttpCode, HttpStatus, Put, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CodedForbiddenException } from '../../../http/coded-exception';
import { ApiCodedError } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { RateClass } from '../../../rate-limit/rate-class.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ApiAssistantForbidden,
  ApiAssistantResponse,
  ApiAssistantUnavailable,
  USER_ONLY_RULE,
} from '../api-docs';
import { ASSISTANT_PERMISSIONS as P } from '../assistant.constants';
import { ASSISTANT_ERROR_CODES as C } from '../assistant.errors';
import {
  ASSISTANT_EXAMPLES as X,
  type AssistantSettingsView,
  AssistantSettingsSchema,
  type AssistantStatusView,
  AssistantStatusSchema,
  type ToolsView,
  ToolsViewSchema,
  type UpdateAssistantSettingsBody,
  UpdateAssistantSettingsBodySchema,
  type UsageQuery,
  UsageQuerySchema,
  type UsageView,
  UsageViewSchema,
} from '../dto/assistant.schemas';
import { AssistantAvailabilityService } from '../services/assistant-availability.service';
import { AssistantSettingsService } from '../services/assistant-settings.service';
import { AssistantUsageService } from '../services/assistant-usage.service';
import { ConversationService } from '../services/conversation.service';

/** The principal of a `@UserOnly()` route (the guard already refused API keys). */
export function userOf(principal: Principal): UserPrincipal {
  if (principal.kind !== 'user') {
    throw new CodedForbiddenException('user_required', 'This operation requires a user');
  }
  return principal;
}

/**
 * `GET /assistant/status` (step AI-1 §4.1): whether the assistant can answer for the caller now.
 */
@ApiTags('assistant')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'assistant', version: '1' })
export class AssistantStatusController {
  constructor(private readonly availability: AssistantAvailabilityService) {}

  @Get('status')
  @RequirePermissions(P.use)
  @ApiOperation({
    summary: 'Get the AI assistant status',
    description:
      'Whether the AI assistant can answer for you now and, if not, why: `platform_disabled` ' +
      '(ASSISTANT_ENABLED off), `feature_disabled` (organization feature `ai_assistant` off), ' +
      '`tenant_disabled` (your organization has not enabled it with the external-processing ' +
      'acknowledgement), `provider_unavailable` (the provider breaker is open) or ' +
      '`budget_exhausted` (the daily token budget of your organization or of the platform is ' +
      'used up). Also the configured provider and model, the message limit, the turns per ' +
      'minute and today’s token use (UTC day).' +
      USER_ONLY_RULE,
  })
  @ApiAssistantResponse(200, AssistantStatusSchema, X.status, 'The assistant status')
  @ApiAssistantForbidden()
  @ApiAssistantUnavailable()
  get(@CurrentScope() scope: TenantScope): Promise<AssistantStatusView> {
    return this.availability.status(scope);
  }
}

/** `GET` / `PUT /assistant/settings` (step AI-1 D13, §4.1). */
@ApiTags('assistant')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'assistant', version: '1' })
export class AssistantSettingsController {
  constructor(private readonly settings: AssistantSettingsService) {}

  @Get('settings')
  @RequirePermissions(P.configure)
  @ApiOperation({
    summary: 'Get the AI assistant settings',
    description:
      'Your organization’s `assistant-settings/1`: `enabled`, the external-processing ' +
      'acknowledgement (who and when), `dailyTokenBudget` (null = the platform default) and ' +
      'the effective budget, the content `retentionDays` (1-365), `dataSharing` (`metadata`), ' +
      'whether the feature `ai_assistant` is on, and the `rowVersion` to send with PUT (0 ' +
      'before the first save). Needs `assistant:configure`.' +
      USER_ONLY_RULE,
  })
  @ApiAssistantResponse(200, AssistantSettingsSchema, X.settings, 'The assistant settings')
  @ApiAssistantForbidden()
  @ApiAssistantUnavailable()
  get(@CurrentScope() scope: TenantScope): Promise<AssistantSettingsView> {
    return this.settings.get(scope);
  }

  @Put('settings')
  @RequirePermissions(P.configure)
  @RateClass('sensitive')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Update the AI assistant settings',
    description:
      'Replaces `assistant-settings/1` with `expectedRowVersion` (`409 ' +
      'assistant_settings_conflict` with `currentRowVersion`). Enabling needs ' +
      '`externalProcessingAcknowledged: true` (`400 validation_failed`): your users’ messages ' +
      'and the masked metadata of tool results are processed by the platform’s AI provider; the ' +
      'acknowledging user and time are recorded. Enabling also needs the organization feature ' +
      '`ai_assistant`, which a platform operator turns on (`403 assistant_not_enabled`). ' +
      '`dailyTokenBudget` is at most ASSISTANT_TENANT_DAILY_TOKENS_MAX (`400`). Audited ' +
      '`assistant.settings_updated` (changed field names, never values). Needs ' +
      '`assistant:configure`; rate class `sensitive`.' +
      USER_ONLY_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(UpdateAssistantSettingsBodySchema, { io: 'input' }),
    examples: { enable: { value: X.settingsUpdate } },
  })
  @ApiAssistantResponse(200, AssistantSettingsSchema, X.settings, 'The updated settings')
  @ApiAssistantForbidden(
    [C.notEnabled],
    '`assistant_not_enabled` when enabling without the feature `ai_assistant`',
  )
  @ApiCodedError(
    409,
    '`expectedRowVersion` is not the stored version (`currentRowVersion` given)',
    [C.settingsConflict],
    { currentRowVersion: { type: 'integer' } },
  )
  @ApiAssistantUnavailable()
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(UpdateAssistantSettingsBodySchema))
    body: UpdateAssistantSettingsBody,
    @Client() client: ClientContext,
  ): Promise<AssistantSettingsView> {
    return this.settings.update(userOf(principal), scope, body, client.ip);
  }
}

/** `GET /assistant/usage` (step AI-1 §4.1, D11). */
@ApiTags('assistant')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'assistant', version: '1' })
export class AssistantUsageController {
  constructor(private readonly usage: AssistantUsageService) {}

  @Get('usage')
  @RequirePermissions(P.configure)
  @ApiOperation({
    summary: 'Get the AI assistant usage',
    description:
      'Your organization’s assistant use per UTC day, provider and model between `from` and ' +
      '`to` (YYYY-MM-DD, inclusive, at most 92 days; default the last 30 days): turns, input, ' +
      'output, cache read and cache write tokens and the advisory cost in micro-USD (`null` for ' +
      'a model without a price), with totals. Needs `assistant:configure`. From the read replica.' +
      USER_ONLY_RULE,
  })
  @ApiQuery({
    name: 'from',
    required: false,
    description: 'First UTC day (YYYY-MM-DD)',
    schema: { type: 'string', format: 'date' },
  })
  @ApiQuery({
    name: 'to',
    required: false,
    description: 'Last UTC day (YYYY-MM-DD)',
    schema: { type: 'string', format: 'date' },
  })
  @ApiAssistantResponse(200, UsageViewSchema, X.usage, 'Usage per day and model')
  @ApiAssistantForbidden()
  @ApiAssistantUnavailable()
  get(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(UsageQuerySchema)) query: UsageQuery,
  ): Promise<UsageView> {
    return this.usage.get(scope, query);
  }
}

/** `GET /assistant/tools` (step AI-1 D4, §4.1). */
@ApiTags('assistant')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'assistant', version: '1' })
export class AssistantToolsController {
  constructor(private readonly conversations: ConversationService) {}

  @Get('tools')
  @RequirePermissions(P.use)
  @ApiOperation({
    summary: 'List your AI assistant tools',
    description:
      'The tools the assistant may use for you: every enabled tool of the registry (one ' +
      'existing `/api/v1` operation each) whose permission requirement you hold, the ' +
      '`platform:*` tools for platform operators only. `name`, `module`, `title`, `access` and ' +
      '`risk`, with the `registryVersion`. In AI-1 every tool is a read.' +
      USER_ONLY_RULE,
  })
  @ApiAssistantResponse(200, ToolsViewSchema, X.tools, 'Your enabled tools')
  @ApiAssistantForbidden()
  list(@CurrentPrincipal() principal: Principal): ToolsView {
    return this.conversations.tools(userOf(principal));
  }
}
