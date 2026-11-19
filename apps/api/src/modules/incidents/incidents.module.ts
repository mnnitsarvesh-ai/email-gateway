import { Module } from '@nestjs/common';
import { IdempotencyModule } from '../../http/idempotency/idempotency.module';
import { AuthModule } from '../auth/auth.module';
import { IncidentsController } from './controllers/incidents.controller';
import { IncidentStores } from './incident-stores';
import { IncidentsReadRepository } from './repositories/incidents-read.repository';
import { IncidentMetrics } from './services/incident-metrics';
import { IncidentsService } from './services/incidents.service';

/**
 * Security incidents, api side (step 8.4 §5.2, D24; ADR-0075): the generic, category-aware
 * incident routes over the shared model of `@email-gateway/security-incidents`, the category
 * registry (`account_takeover` first; ATP-4 appends its categories in `incident-categories.ts`)
 * and the transactional stores the ATO module also writes through (`IncidentStores`).
 */
@Module({
  imports: [IdempotencyModule, AuthModule],
  controllers: [IncidentsController],
  providers: [IncidentStores, IncidentsReadRepository, IncidentMetrics, IncidentsService],
  exports: [IncidentStores, IncidentsReadRepository],
})
export class IncidentsModule {}
