import { Module } from '@nestjs/common';
import {
  AssistantAdminAuditController,
  AssistantAdminController,
} from './controllers/admin.controller';
import { AssistantFeedbackController } from './controllers/feedback.controller';
import { AssistantSearchController } from './controllers/search.controller';
import { InsightsMetrics } from './insights-metrics';
import { AuditRepository } from './repositories/audit.repository';
import { FeedbackRepository } from './repositories/feedback.repository';
import { IdentityRepository } from './repositories/identity.repository';
import { SearchRepository } from './repositories/search.repository';
import { UserUsageRepository } from './repositories/user-usage.repository';
import { AssistantAdminService } from './services/admin.service';
import { AssistantAuditViewService } from './services/audit-view.service';
import { AssistantFeedbackService } from './services/feedback.service';
import { AssistantSearchService } from './services/search.service';

/**
 * AI assistant insights (step AI-6 WP4, docs/plan/steps/34-ai-chat-hardening-operations.md D1,
 * D2, D4, I24; contracts §35.6), beside the assistant module and independent of its providers:
 *
 * - `GET /assistant/search`: the owner's content search over their own messages and titles;
 * - `PUT`/`DELETE /assistant/messages/{messageId}/feedback`: ratings of assistant answers;
 * - `GET /assistant/admin/usage/users` and `/assistant/admin/feedback` (`assistant:configure`);
 * - `GET /assistant/admin/conversations[/{id}]` and `/assistant/admin/executions`
 *   (`audit:read`): the metadata-only audit view.
 *
 * Reads and writes only the `ai_chat_*` tables (plus users' public ids, names and addresses for
 * the admin views). Like the assistant's read routes (conversation list, usage) they answer
 * whatever the platform switch ASSISTANT_ENABLED says: they never call a model or a tool.
 */
@Module({
  controllers: [
    AssistantSearchController,
    AssistantFeedbackController,
    AssistantAdminController,
    AssistantAdminAuditController,
  ],
  providers: [
    InsightsMetrics,
    SearchRepository,
    FeedbackRepository,
    UserUsageRepository,
    AuditRepository,
    IdentityRepository,
    AssistantSearchService,
    AssistantFeedbackService,
    AssistantAdminService,
    AssistantAuditViewService,
  ],
})
export class AssistantInsightsModule {}
