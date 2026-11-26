import { Module } from '@nestjs/common';
import { IdempotencyModule } from '../../http/idempotency/idempotency.module';
import { AuthModule } from '../auth/auth.module';
import { IntakeAddressService } from '../journaling/services/intake-address.service';
import { ApiModeController } from './controllers/api-mode.controller';
import { ProtectionModeController } from './controllers/protection-mode.controller';
import { ProviderNotificationsController } from './controllers/provider-notifications.controller';
import { NotificationRateLimitGuard } from './notification-rate-limit.guard';
import { ApiModeRepository } from './repositories/api-mode.repository';
import { ApiModeGuideService } from './services/api-mode-guide.service';
import { ApiModeService } from './services/api-mode.service';
import { ProtectionModeService } from './services/protection-mode.service';
import { ProviderNotificationsService } from './services/provider-notifications.service';

/**
 * API-mode protection (step API-1, docs/plan/steps/35-api-mode-protection.md D1, D2, D10-D12;
 * ADR-0098..0100): the protection modes of the organization and its domains, the API-mode
 * coverage and health views, the per-connection change-feed settings, inventory and resync
 * requests, mailboxes and detections, the setup guide, and the public Graph notification
 * callbacks. The api never calls a provider and never reads message content: the mailbox-worker
 * does the provider work; the api only reads its rows and requests work through them.
 */
@Module({
  imports: [IdempotencyModule, AuthModule],
  controllers: [ProtectionModeController, ApiModeController, ProviderNotificationsController],
  providers: [
    ApiModeRepository,
    ProtectionModeService,
    ApiModeService,
    ApiModeGuideService,
    ProviderNotificationsService,
    NotificationRateLimitGuard,
    IntakeAddressService,
  ],
})
export class ApiModeModule {}
