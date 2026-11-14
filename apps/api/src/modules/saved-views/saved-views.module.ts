import { Module } from '@nestjs/common';
import { SavedViewsController } from './saved-views.controller';
import { SavedViewsRepository } from './saved-views.repository';
import { SavedViewsService } from './saved-views.service';

/**
 * Saved Email Explorer views (step 7.2 §2 E4, ADR-0061): per user, tenant-scoped, on the writer.
 * The shared building blocks (audit, transactions, cursor codec) are global.
 */
@Module({
  controllers: [SavedViewsController],
  providers: [SavedViewsRepository, SavedViewsService],
})
export class SavedViewsModule {}
