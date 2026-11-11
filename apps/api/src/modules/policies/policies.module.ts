import { Module } from '@nestjs/common';
import { PolicyManagementController } from './controllers/policy-management.controller';
import { PolicyMessagesController } from './controllers/policy-messages.controller';
import { PolicySettingsController } from './controllers/policy-settings.controller';
import { PolicyToolsController } from './controllers/policy-tools.controller';
import { PoliciesManagementRepository } from './repositories/policies-management.repository';
import { PolicyExecutionsRepository } from './repositories/policy-executions.repository';
import { PolicyFactsRepository } from './repositories/policy-facts.repository';
import { PoliciesService } from './services/policies.service';
import { PolicyEvaluationService } from './services/policy-evaluation.service';
import { PolicyHistoryService } from './services/policy-history.service';
import { PolicyAuditor, PolicyMetrics, PolicyWriter } from './services/policy-writer';

/**
 * Policy engine management (step 5.2 P11, P12, P16, P17, P22, P23,
 * docs/plan/steps/16-policy-engine.md; ADR-0043, ADR-0045): tenant policies with versioned,
 * immutable published definitions, activation and rollback, enable/disable/delete, settings, the
 * catalog, tests with synthetic facts, the no-write dry-run of a stored round, the execution
 * history and the evaluations of a message. Evaluation itself runs in the policy-engine; every
 * change that affects it increments the organization's generation and applies to the next
 * evaluation. PolicyToolsController is listed first so its static `/policies/*` routes are
 * matched before `/policies/{policyId}`. The writer, auditor and metrics are exported for the
 * directory module.
 */
@Module({
  controllers: [
    PolicyToolsController,
    PolicyManagementController,
    PolicySettingsController,
    PolicyMessagesController,
  ],
  providers: [
    PolicyWriter,
    PolicyAuditor,
    PolicyMetrics,
    PoliciesManagementRepository,
    PolicyFactsRepository,
    PolicyExecutionsRepository,
    PoliciesService,
    PolicyEvaluationService,
    PolicyHistoryService,
  ],
  exports: [
    PolicyWriter,
    PolicyAuditor,
    PolicyMetrics,
    PoliciesManagementRepository,
    PolicyExecutionsRepository,
  ],
})
export class PoliciesModule {}
