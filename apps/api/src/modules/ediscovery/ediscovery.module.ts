import { Module } from '@nestjs/common';
import { IdempotencyModule } from '../../http/idempotency/idempotency.module';
import { ArchiveModule } from '../archive/archive.module';
import { EdiscoveryCasesController } from './controllers/ediscovery-cases.controller';
import { EdiscoveryExportsController } from './controllers/ediscovery-exports.controller';
import { EdiscoverySearchesController } from './controllers/ediscovery-searches.controller';
import { LegalHoldsController } from './controllers/legal-holds.controller';
import { EdiscoveryRepository } from './repositories/ediscovery.repository';
import { EdiscoveryCasesService } from './services/ediscovery-cases.service';
import { EdiscoveryExportsService } from './services/ediscovery-exports.service';
import { EdiscoverySearchesService } from './services/ediscovery-searches.service';
import { LegalHoldsService } from './services/legal-holds.service';

/**
 * Legal holds and eDiscovery (step 8.1, docs/plan/steps/23-journaling-archiving.md §4.4
 * #24–#41; ADR-0067, ADR-0069): organization-wide holds and their release, cases with
 * custodians and case-scoped holds, worker-run case searches with hits and review tags, and
 * bounded signed exports with single-use download grants (through the archive download door).
 * The archive-worker runs the searches and builds the exports; this module records requests and
 * every user decision.
 */
@Module({
  imports: [IdempotencyModule, ArchiveModule],
  controllers: [
    LegalHoldsController,
    EdiscoveryCasesController,
    EdiscoverySearchesController,
    EdiscoveryExportsController,
  ],
  providers: [
    EdiscoveryRepository,
    LegalHoldsService,
    EdiscoveryCasesService,
    EdiscoverySearchesService,
    EdiscoveryExportsService,
  ],
})
export class EdiscoveryModule {}
