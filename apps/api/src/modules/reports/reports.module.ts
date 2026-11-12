import { Module } from '@nestjs/common';
import { ReportExecutor } from './report-executor';
import { ReportMetrics } from './report-metrics';
import { ReportsController } from './reports.controller';
import { ReportsRepository } from './reports.repository';
import { ReportsService } from './reports.service';

/**
 * Step 6.1 (docs/plan/steps/18-rest-api.md §3.3, D12): traffic, threat and URL-click reports
 * computed on the replica (`/reports/*`). Exports the aggregate repository and the cached,
 * timed executor for the billing usage (same covering index, cache and timeout rules).
 */
@Module({
  controllers: [ReportsController],
  providers: [ReportsRepository, ReportExecutor, ReportMetrics, ReportsService],
  exports: [ReportsRepository, ReportExecutor],
})
export class ReportsModule {}
