import { Module } from '@nestjs/common';
import { MessagesModule } from '../messages/messages.module';
import { TenantDataModule } from '../tenant-data/tenant-data.module';
import { UrlProtectionController } from './url-protection.controller';
import { UrlProtectionRepository } from './url-protection.repository';
import { UrlProtectionService } from './url-protection.service';

/**
 * Step 6.1 (docs/plan/steps/18-rest-api.md §3.3, WP2): per-message URLs
 * (`GET /messages/{messageId}/urls`) and URL clicks (`GET /url-protection/clicks`, the
 * click-service's `url_click_events`) from the read replica.
 */
@Module({
  imports: [MessagesModule, TenantDataModule],
  controllers: [UrlProtectionController],
  providers: [UrlProtectionRepository, UrlProtectionService],
})
export class UrlProtectionModule {}
