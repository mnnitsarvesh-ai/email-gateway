import { Module } from '@nestjs/common';
import { OrganizationsModule } from '../organizations/organizations.module';
import { UsageController } from './usage.controller';
import { UsageService } from './usage.service';

/**
 * Step 6.1 (docs/plan/steps/18-rest-api.md §3.3, D12): the caller's organization usage
 * (`GET /usage`) through OrganizationUsageService (exported by OrganizationsModule).
 */
@Module({
  imports: [OrganizationsModule],
  controllers: [UsageController],
  providers: [UsageService],
})
export class UsageModule {}
