import { Module } from '@nestjs/common';
import { OrganizationsModule } from '../organizations/organizations.module';
import { ReportsModule } from '../reports/reports.module';
import { BillingController } from './billing.controller';
import { BillingRepository } from './billing.repository';
import { BillingService } from './billing.service';

/**
 * Step 6.1 (docs/plan/steps/18-rest-api.md §3.3, D12): the plan, entitlements and metered usage
 * (`/billing/plan`, `/billing/usage`); no prices or invoices exist. Reuses the organization
 * repository (entitlements) and the report aggregates, cache and timeout of ReportsModule.
 */
@Module({
  imports: [OrganizationsModule, ReportsModule],
  controllers: [BillingController],
  providers: [BillingRepository, BillingService],
})
export class BillingModule {}
