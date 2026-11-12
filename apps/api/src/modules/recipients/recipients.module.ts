import { Module } from '@nestjs/common';
import { RecipientSuppressionsController } from './recipient-suppressions.controller';
import { RecipientSuppressionsRepository } from './recipient-suppressions.repository';
import { RecipientSuppressionsService } from './recipient-suppressions.service';

/**
 * Step 6.1 (docs/plan/steps/18-rest-api.md §3.3, WP2): the recipient suppression list
 * (`/recipients/suppressions`, `delivery_suppressions`, enforced by the smtp-adapter on outbound
 * mail). The recipients of one message are served by the messages module
 * (`GET /messages/{messageId}/recipients`). Idempotency, audit, limits, cursors and metrics come
 * from the global ApiCommonModule.
 */
@Module({
  controllers: [RecipientSuppressionsController],
  providers: [RecipientSuppressionsRepository, RecipientSuppressionsService],
})
export class RecipientsModule {}
