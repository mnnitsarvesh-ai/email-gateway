import { Module } from '@nestjs/common';
import { IdempotencyModule } from '../../http/idempotency/idempotency.module';
import { ArchiveModule } from '../archive/archive.module';
import { AuthModule } from '../auth/auth.module';
import { IntakeSourcesController } from './controllers/intake-sources.controller';
import { JournalingController } from './controllers/journaling.controller';
import { JournalingRepository } from './repositories/journaling.repository';
import { IntakeAddressService } from './services/intake-address.service';
import { IntakeGuideService } from './services/intake-guide.service';
import { IntakeSourcesService } from './services/intake-sources.service';
import { JournalingSettingsService } from './services/journaling-settings.service';

/**
 * The Journaling area (step 8.6, docs/plan/steps/27-journal-intake-and-archive-split.md D1, D8,
 * D10, D11; ADR-0087, ADR-0089): the capture half of the archive settings (the same row as
 * /archive/settings), the journaling status, and journal intake sources with their derived
 * addresses (only hashes are stored), wizard, customer guides and attestations. The api never
 * receives intake mail (the smtp-adapter does) and never writes archive objects.
 */
@Module({
  imports: [IdempotencyModule, AuthModule, ArchiveModule],
  controllers: [JournalingController, IntakeSourcesController],
  providers: [
    JournalingRepository,
    IntakeAddressService,
    JournalingSettingsService,
    IntakeSourcesService,
    IntakeGuideService,
  ],
})
export class JournalingModule {}
