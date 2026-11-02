import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { OrganizationConfigurationController } from './controllers/organization-configuration.controller';
import { OrganizationDeletionController } from './controllers/organization-deletion.controller';
import { OrganizationsController } from './controllers/organizations.controller';
import { OrganizationUsageRepository } from './organization-usage.repository';
import { OrganizationsRepository } from './organizations.repository';
import { OrganizationDeletionService } from './services/organization-deletion.service';
import { OrganizationEntitlementsService } from './services/organization-entitlements.service';
import { OrganizationSettingsService } from './services/organization-settings.service';
import { OrganizationUsageService } from './services/organization-usage.service';
import { OrganizationsService } from './services/organizations.service';

/**
 * Organizations (§4.3, D12): the platform catalog (create, plan, status, entitlements, deletion
 * workflow) and the own-organization views of members (read, name, settings, usage). Uses the
 * auth module for session revocation, invitations and cache invalidation; the shared building
 * blocks (audit, transactions, API_CONFIG) are global.
 */
@Module({
  imports: [AuthModule],
  controllers: [
    OrganizationsController,
    OrganizationConfigurationController,
    OrganizationDeletionController,
  ],
  providers: [
    OrganizationsRepository,
    OrganizationUsageRepository,
    OrganizationsService,
    OrganizationSettingsService,
    OrganizationEntitlementsService,
    OrganizationUsageService,
    OrganizationDeletionService,
  ],
})
export class OrganizationsModule {}
