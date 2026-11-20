import { Module } from '@nestjs/common';
import { IdempotencyModule } from '../../http/idempotency/idempotency.module';
import { AuthModule } from '../auth/auth.module';
import { IncidentsModule } from '../incidents/incidents.module';
import { AtoAccountMailboxController } from './controllers/ato-account-mailbox.controller';
import { AtoAccountsController } from './controllers/ato-accounts.controller';
import { AtoIncidentEvidenceController } from './controllers/ato-incident-evidence.controller';
import { AtoOverviewController } from './controllers/ato-overview.controller';
import { AtoProvidersController } from './controllers/ato-providers.controller';
import { AtoResponsesController } from './controllers/ato-responses.controller';
import {
  AtoRestrictionsController,
  AtoRulesController,
  AtoSettingsController,
} from './controllers/ato-settings.controller';
import { AtoConnectionDirectory } from './providers/connection-directory.provider';
import { AtoAccountVersionRepository } from './repositories/ato-account-version.repository';
import { AtoMailboxItemsRepository } from './repositories/ato-mailbox-items.repository';
import { AtoProvidersRepository } from './repositories/ato-providers.repository';
import { AtoReadRepository } from './repositories/ato-read.repository';
import { AtoAccessService } from './services/ato-access.service';
import { AtoAccountsService } from './services/ato-accounts.service';
import { AtoEvidenceService } from './services/ato-evidence.service';
import { AtoMailboxStateService } from './services/ato-mailbox-state.service';
import { AtoOverviewService } from './services/ato-overview.service';
import { AtoProvidersService } from './services/ato-providers.service';
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
 *
 * Step 8.5 (docs/plan/steps/26-ato-provider-adapters.md §6): identity-provider integrations over
 * step 8.2 connections (bind, settings, pause/resume, probe request, backfill, removal) and the
 * mailbox state of an account with its priority refresh; the 8.2 connections are read through
 * the `connection-directory` binding of `@email-gateway/idp-adapters` (`AtoConnectionDirectory`).
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
    AtoProvidersController,
    AtoAccountMailboxController,
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
    AtoConnectionDirectory,
    AtoProvidersRepository,
    AtoMailboxItemsRepository,
    AtoProvidersService,
    AtoMailboxStateService,
  ],
  exports: [AtoReadRepository, AtoAccessService],
})
export class AtoModule {}
