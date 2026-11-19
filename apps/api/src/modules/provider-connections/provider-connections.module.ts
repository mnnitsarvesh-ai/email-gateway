import { Module } from '@nestjs/common';
import { DomainDestinationsModule } from '../domain-destinations/domain-destinations.module';
import {
  ProviderAttestationsController,
  ProviderCatalogController,
  ProviderConnectionsController,
  ProviderDomainsController,
  ProviderHealthController,
} from './controllers/provider-connections.controller';
import { ProviderGrantsController } from './controllers/provider-grants.controller';
import {
  ProviderGuideController,
  ProviderMailFlowController,
  ProviderValidationsController,
} from './controllers/provider-mail-flow.controller';
import { ProviderRateLimitGuard } from './provider-connections-rate-limit';
import { ProviderConnectionsRepository } from './repositories/provider-connections.repository';
import { ProviderGrantsRepository } from './repositories/provider-grants.repository';
import { ProviderRunsRepository } from './repositories/provider-runs.repository';
import { ProviderConnectionsService } from './services/provider-connections.service';
import { ProviderGrantsService } from './services/provider-grants.service';
import { ProviderGuideService } from './services/provider-guide.service';
import { ProviderMailFlowService } from './services/provider-mail-flow.service';
import { ProviderValidationService } from './services/provider-validation.service';

/**
 * Step 8.2 (docs/plan/steps/25-m365-google-connectors.md §5; ADR-0076–ADR-0081): Microsoft 365 and
 * Google Workspace connections — the catalogue, connections, grants with admin consent and
 * encrypted customer credentials (the api encrypts and never decrypts), linked domains, the
 * computed setup wizard with preview → impact token → apply for every gateway-side mail-flow
 * change, attestations, validation runs with single-use probe addresses, health and the
 * customer-specific setup guides. The api never calls Microsoft or Google: provider traffic,
 * verification, validation and health checks run in the integration-worker. Idempotency, audit,
 * cursors and limits come from the global ApiCommonModule.
 */
@Module({
  imports: [DomainDestinationsModule],
  controllers: [
    ProviderCatalogController,
    ProviderConnectionsController,
    ProviderGrantsController,
    ProviderDomainsController,
    ProviderMailFlowController,
    ProviderAttestationsController,
    ProviderValidationsController,
    ProviderHealthController,
    ProviderGuideController,
  ],
  providers: [
    ProviderConnectionsRepository,
    ProviderGrantsRepository,
    ProviderRunsRepository,
    ProviderConnectionsService,
    ProviderGrantsService,
    ProviderMailFlowService,
    ProviderValidationService,
    ProviderGuideService,
    ProviderRateLimitGuard,
  ],
})
export class ProviderConnectionsModule {}
