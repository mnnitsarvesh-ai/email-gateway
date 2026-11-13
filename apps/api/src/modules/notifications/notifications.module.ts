import { Module } from '@nestjs/common';
import { QuarantineModule } from '../quarantine/quarantine.module';
import { NotificationsController } from './notifications.controller';
import { NotificationsRepository } from './notifications.repository';
import { NotificationsService } from './notifications.service';

/**
 * Step 6.2 (docs/plan/steps/19-webhooks-notifications.md N2, N3, §6.3; ADR-0056): tenant
 * security-alert settings (`notification_settings`) and the personal preference center
 * (`notification_user_preferences` and the quarantine digest opt-out). The alerts themselves
 * are produced by the webhook-worker and sent by the notification-worker.
 */
@Module({
  imports: [QuarantineModule],
  controllers: [NotificationsController],
  providers: [NotificationsRepository, NotificationsService],
})
export class NotificationsModule {}
