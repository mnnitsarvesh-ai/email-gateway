import { Module } from '@nestjs/common';
import { MessagesModule } from '../messages/messages.module';
import { TenantDataModule } from '../tenant-data/tenant-data.module';
import { AttachmentsController } from './attachments.controller';
import { AttachmentsRepository } from './attachments.repository';
import { AttachmentsService } from './attachments.service';

/**
 * Step 6.1 (docs/plan/steps/18-rest-api.md §3.3, WP2): attachment metadata and verdicts
 * (`GET /messages/{messageId}/attachments`, `GET /attachments?sha256=`) from the read replica;
 * never content, never a download route.
 */
@Module({
  imports: [MessagesModule, TenantDataModule],
  controllers: [AttachmentsController],
  providers: [AttachmentsRepository, AttachmentsService],
})
export class AttachmentsModule {}
