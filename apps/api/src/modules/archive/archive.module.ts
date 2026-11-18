import { Module } from '@nestjs/common';
import { IdempotencyModule } from '../../http/idempotency/idempotency.module';
import { AuthModule } from '../auth/auth.module';
import { ArchiveRateLimitGuard } from './archive-rate-limit';
import { ArchiveAdminController } from './controllers/archive-admin.controller';
import { ArchiveDownloadsController } from './controllers/archive-downloads.controller';
import { ArchiveMessagesController } from './controllers/archive-messages.controller';
import { ArchiveRetentionController } from './controllers/archive-retention.controller';
import { ArchiveConfigRepository } from './repositories/archive-config.repository';
import { ArchiveGrantsRepository } from './repositories/archive-grants.repository';
import { ArchiveRecordsRepository } from './repositories/archive-records.repository';
import { ArchiveContentService } from './services/archive-content.service';
import { ArchiveDownloadsService } from './services/archive-downloads.service';
import { ArchiveKeysService } from './services/archive-keys.service';
import { ArchiveMessagesService } from './services/archive-messages.service';
import { ArchiveMetrics } from './services/archive-metrics';
import { ArchiveObjectStore } from './services/archive-object-store';
import { ArchiveOperationsService } from './services/archive-operations.service';
import { ArchiveRetentionService } from './services/archive-retention.service';
import { ArchiveSearchClient } from './services/archive-search.client';
import { ArchiveSearchService } from './services/archive-search.service';
import { ArchiveSettingsService } from './services/archive-settings.service';

/**
 * Journaling and compliance archiving, api side (step 8.1,
 * docs/plan/steps/23-journaling-archiving.md §4.4 #1–#23; ADR-0064–0068): archive settings,
 * retention policies, key versions and rotation, status, capture issues, the disposal log, the
 * export signing keys, metadata search through the tenant's OpenSearch alias, detail, journal,
 * frozen scan results, reveal, the sanitized preview, single-use re-authorized downloads and the
 * disposal of reviewed records. The api never writes archive objects or the search index (the
 * archive-worker does); it reads and decrypts. The ediscovery module imports the exported
 * providers (records, content, downloads, search client).
 */
@Module({
  imports: [IdempotencyModule, AuthModule],
  controllers: [
    ArchiveAdminController,
    ArchiveRetentionController,
    ArchiveMessagesController,
    ArchiveDownloadsController,
  ],
  providers: [
    ArchiveMetrics,
    ArchiveRateLimitGuard,
    ArchiveConfigRepository,
    ArchiveRecordsRepository,
    ArchiveGrantsRepository,
    ArchiveObjectStore,
    ArchiveSearchClient,
    ArchiveContentService,
    ArchiveSettingsService,
    ArchiveRetentionService,
    ArchiveKeysService,
    ArchiveOperationsService,
    ArchiveSearchService,
    ArchiveMessagesService,
    ArchiveDownloadsService,
  ],
  exports: [
    ArchiveMetrics,
    ArchiveRateLimitGuard,
    ArchiveConfigRepository,
    ArchiveRecordsRepository,
    ArchiveGrantsRepository,
    ArchiveContentService,
    ArchiveSearchClient,
    ArchiveDownloadsService,
  ],
})
export class ArchiveModule {}
