import { Module } from '@nestjs/common';
import { DlpComplianceController } from './controllers/dlp-compliance.controller';
import { DlpDictionariesController } from './controllers/dlp-dictionaries.controller';
import {
  DlpEvidenceController,
  DlpMessageEvidenceController,
} from './controllers/dlp-evidence.controller';
import { DlpExceptionsController } from './controllers/dlp-exceptions.controller';
import { DlpIncidentsController } from './controllers/dlp-incidents.controller';
import { DlpPatternsController } from './controllers/dlp-patterns.controller';
import { DlpPoliciesController } from './controllers/dlp-policies.controller';
import { DlpConfigRepository } from './repositories/dlp-config.repository';
import { DlpResultsRepository } from './repositories/dlp-results.repository';
import { DlpComplianceService } from './services/dlp-compliance.service';
import { DlpDictionariesService } from './services/dlp-dictionaries.service';
import { DlpEvidenceStore } from './services/dlp-evidence-store';
import { DlpEvidenceService } from './services/dlp-evidence.service';
import { DlpExceptionsService } from './services/dlp-exceptions.service';
import { DlpIncidentsService } from './services/dlp-incidents.service';
import { DlpPatternsService } from './services/dlp-patterns.service';
import { DlpPoliciesService } from './services/dlp-policies.service';
import { DlpAuditor } from './services/dlp-views';
import { DlpMetrics, DlpWriter } from './services/dlp-writer';

/**
 * Data loss prevention tenant data and evidence (step 4.5 D8, D9, D11, D12, D14, D16, D17, D21,
 * docs/plan/steps/13-dlp.md): policies and rules, exceptions, custom patterns and the pattern
 * test, keyword dictionaries, the Aadhaar compliance basis, incidents, the audited evidence
 * door and the evidence purge. The `dlp` engine settings are served by ScansModule
 * (`/scan-settings/dlp`) and the `dlp` section of the scan results by MessagesModule
 * (`GET /messages/{messageId}/scans`). Audit, transactions, metrics, S3 and the database
 * clients are global.
 */
@Module({
  controllers: [
    DlpPoliciesController,
    DlpExceptionsController,
    DlpPatternsController,
    DlpDictionariesController,
    DlpComplianceController,
    DlpIncidentsController,
    DlpMessageEvidenceController,
    DlpEvidenceController,
  ],
  providers: [
    DlpWriter,
    DlpMetrics,
    DlpAuditor,
    DlpConfigRepository,
    DlpResultsRepository,
    DlpEvidenceStore,
    DlpPoliciesService,
    DlpExceptionsService,
    DlpPatternsService,
    DlpDictionariesService,
    DlpComplianceService,
    DlpIncidentsService,
    DlpEvidenceService,
  ],
})
export class DlpModule {}
