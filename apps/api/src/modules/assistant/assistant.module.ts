import { type MiddlewareConsumer, Module, type NestModule } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import {
  AssistantSettingsController,
  AssistantStatusController,
  AssistantToolsController,
  AssistantUsageController,
} from './controllers/assistant.controller';
import { AssistantConfirmationsController } from './controllers/confirmations.controller';
import {
  AssistantConversationsController,
  AssistantMessagesController,
} from './controllers/conversations.controller';
import {
  AssistantExecutionsController,
  AssistantTurnsController,
} from './controllers/turns.controller';
import { AssistantSettingsRepository } from './repositories/assistant-settings.repository';
import { ConfirmationsRepository } from './repositories/confirmations.repository';
import { ConversationsRepository } from './repositories/conversations.repository';
import { ExecutionsRepository } from './repositories/executions.repository';
import { UsageRepository } from './repositories/usage.repository';
import { AssistantAvailabilityService } from './services/assistant-availability.service';
import { AssistantLimitsService } from './services/assistant-limits.service';
import { AssistantMetrics } from './services/assistant-metrics';
import {
  AssistantProviderService,
  defaultLlmProviderFactory,
  LLM_PROVIDER_FACTORY,
} from './services/assistant-provider.service';
import { AssistantRetentionService } from './services/assistant-retention.service';
import { AssistantSettingsService } from './services/assistant-settings.service';
import { AssistantUsageService } from './services/assistant-usage.service';
import { ConfirmationService } from './services/confirmation.service';
import { ConfirmationProposer } from './services/confirmation-proposer.service';
import { ConfirmationViewsService } from './services/confirmation-views.service';
import { ConversationService } from './services/conversation.service';
import { ExecutionsService } from './services/executions.service';
import { LoopbackClient, LoopbackDispatcher } from './services/loopback-client';
import { AssistantReadPrimaryMiddleware } from './services/read-primary';
import { ToolExecutorService } from './services/tool-executor.service';
import { TurnEngineService } from './services/turn-engine.service';

/**
 * The AI assistant (step AI-1, docs/plan/steps/28-ai-chat-management.md; ADR-0091–0094,
 * contracts §35): status, settings, usage, the tool catalogue, conversations, messages, turns
 * (JSON or `assistant-stream/1`), cancellation and stored executions with their next pages.
 * Tools are existing `/api/v1` operations executed through the api's own HTTP pipeline with the
 * caller's credential (loopback); the module touches only its own `ai_chat_*` tables (plus the
 * acknowledging user's public id), publishes no message and changes no other module. From step
 * AI-2 (docs/plan/steps/29-ai-chat-confirmations-mail-writes.md) the model may only PROPOSE
 * writes: a write runs only through `POST /assistant/confirmations/{id}/confirm` (ADR-0093
 * amended), whose high-risk re-authentication uses `ReauthenticationService` of `AuthModule`;
 * its precondition reads carry `x-eg-assistant-read-primary` (`AssistantReadPrimaryMiddleware`),
 * so the guarded GET routes read the writer, not a lagging replica.
 */
@Module({
  imports: [AuthModule],
  controllers: [
    AssistantStatusController,
    AssistantSettingsController,
    AssistantUsageController,
    AssistantToolsController,
    AssistantConversationsController,
    AssistantMessagesController,
    AssistantTurnsController,
    AssistantExecutionsController,
    AssistantConfirmationsController,
  ],
  providers: [
    AssistantSettingsRepository,
    ConversationsRepository,
    ExecutionsRepository,
    ConfirmationsRepository,
    UsageRepository,
    AssistantMetrics,
    { provide: LLM_PROVIDER_FACTORY, useValue: defaultLlmProviderFactory },
    AssistantProviderService,
    AssistantLimitsService,
    AssistantAvailabilityService,
    AssistantSettingsService,
    AssistantUsageService,
    ConversationService,
    LoopbackClient,
    { provide: LoopbackDispatcher, useExisting: LoopbackClient },
    ConfirmationProposer,
    ConfirmationViewsService,
    ToolExecutorService,
    ConfirmationService,
    TurnEngineService,
    ExecutionsService,
    AssistantRetentionService,
    AssistantReadPrimaryMiddleware,
  ],
})
export class AssistantModule implements NestModule {
  /**
   * `x-eg-assistant-read-primary` (step AI-2 review): the assistant's precondition reads of a
   * confirmation run on the MySQL writer. Every route, since the reads target other modules.
   */
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(AssistantReadPrimaryMiddleware).forRoutes('*path');
  }
}
