import { Module } from '@nestjs/common';
import { WebhookDeliveriesRepository } from './repositories/webhook-deliveries.repository';
import { WebhookSubscriptionsRepository } from './repositories/webhook-subscriptions.repository';
import { WebhookDeliveriesService } from './services/webhook-deliveries.service';
import { WebhookSecrets } from './services/webhook-secrets';
import { WebhooksService } from './services/webhooks.service';
import { WebhookDeliveriesController } from './webhook-deliveries.controller';
import { WebhooksController } from './webhooks.controller';
import { WebhookRateLimitGuard } from './webhooks-rate-limit';

/**
 * Step 6.2 (docs/plan/steps/19-webhooks-notifications.md W5–W7, W12, §6.1; ADR-0054–0057): the
 * webhook registration API — subscriptions (URL rules, filters, the encrypted signing secret
 * with redacted-replay idempotency, rotation with overlap, soft delete), the event catalogue,
 * the delivery history with attempts, single and range replays and test pings. Delivery itself
 * is the webhook-worker's (it decrypts the secrets this module encrypts). Idempotency, audit,
 * cursors, features, limits and metrics come from the global ApiCommonModule.
 */
@Module({
  controllers: [WebhooksController, WebhookDeliveriesController],
  providers: [
    WebhookSubscriptionsRepository,
    WebhookDeliveriesRepository,
    WebhookSecrets,
    WebhooksService,
    WebhookDeliveriesService,
    WebhookRateLimitGuard,
  ],
})
export class WebhooksModule {}
