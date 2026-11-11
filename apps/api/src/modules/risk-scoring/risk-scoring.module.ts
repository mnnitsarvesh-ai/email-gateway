import { Module } from '@nestjs/common';
import { RiskDryRunController } from './controllers/risk-dry-run.controller';
import { RiskProfilesController } from './controllers/risk-profiles.controller';
import { RiskDryRunRepository } from './repositories/risk-dry-run.repository';
import { RiskProfilesRepository } from './repositories/risk-profiles.repository';
import { RiskDryRunService } from './services/risk-dry-run.service';
import { RiskProfilesService } from './services/risk-profiles.service';
import { RiskAuditor, RiskMetrics, RiskWriter } from './services/risk-writer';

/**
 * Risk scoring (step 5.1 R10, R15, docs/plan/steps/15-risk-scoring.md; ADR-0041, ADR-0042): the
 * platform profile with its bounds and signal map, the organization's versioned profile
 * (drafts, immutable published versions, activation, rollback and reset; audited) and the
 * no-write dry-run of a stored round. Scores are computed and stored by the email-worker at
 * round completion; the `risk` section of the scan results is served by MessagesModule
 * (`GET /messages/{messageId}/scans`). 5.1 recommends and never enforces. Audit, transactions,
 * metrics and the database clients are global.
 */
@Module({
  controllers: [RiskProfilesController, RiskDryRunController],
  providers: [
    RiskWriter,
    RiskAuditor,
    RiskMetrics,
    RiskProfilesRepository,
    RiskDryRunRepository,
    RiskProfilesService,
    RiskDryRunService,
  ],
})
export class RiskScoringModule {}
