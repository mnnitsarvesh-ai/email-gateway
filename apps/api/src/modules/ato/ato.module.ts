import { Module } from '@nestjs/common';
import { IdempotencyModule } from '../../http/idempotency/idempotency.module';
import { AuthModule } from '../auth/auth.module';
import { IncidentsModule } from '../incidents/incidents.module';
import { AtoAccountsController } from './controllers/ato-accounts.controller';
import { AtoIncidentEvidenceController } from './controllers/ato-incident-evidence.controller';
import { AtoOverviewController } from './controllers/ato-overview.controller';
import { AtoResponsesController } from './controllers/ato-responses.controller';
import {
  AtoRestrictionsController,
  AtoRulesController,
  AtoSettingsController,
} from './controllers/ato-settings.controller';
import { AtoAccountVersionRepository } from './repositories/ato-account-version.repository';
import { AtoReadRepository } from './repositories/ato-read.repository';
import { AtoAccessService } from './services/ato-access.service';
import { AtoAccountsService } from './services/ato-accounts.service';
import { AtoEvidenceService } from './services/ato-evidence.service';
import { AtoOverviewService } from './services/ato-overview.service';
import { AtoResponsesService } from './services/ato-responses.service';
import { AtoSettingsService } from './services/ato-settings.service';

/**
 * Account takeover, api side (step 8.4 §5.1, D17; ADR-0070–0075): overview and attention,
 * monitored accounts (detail, protection, signals, auth events, activity, score history,
 * overrides, trusted contexts), the ATO evidence of incidents, response actions (request,
 * approval with separation of duties, rejection, cancellation, rollback), SMTP restrictions,
 * settings and the rule catalogue. Writes go through the `AtoStore` of
 * `@email-gateway/ato-detection` (the `IncidentStores` of the incidents module); reads run on the
 * replica. Detection itself runs in the ato-worker, never here.
 */
@Module({
  imports: [IdempotencyModule, AuthModule, IncidentsModule],
  controllers: [
    AtoOverviewController,
    AtoAccountsController,
    AtoIncidentEvidenceController,
    AtoResponsesController,
    AtoRestrictionsController,
    AtoSettingsController,
    AtoRulesController,
  ],
  providers: [
    AtoReadRepository,
    AtoAccountVersionRepository,
    AtoAccessService,
    AtoOverviewService,
    AtoAccountsService,
    AtoEvidenceService,
    AtoResponsesService,
    AtoSettingsService,
  ],
  exports: [AtoReadRepository, AtoAccessService],
})
export class AtoModule {}
