import { Module } from '@nestjs/common';
import { AttachmentRescansController } from './controllers/attachment-rescans.controller';
import { ScanSettingsController } from './controllers/scan-settings.controller';
import { ScanTrainingController } from './controllers/scan-training.controller';
import { ThreatHashesController } from './controllers/threat-hashes.controller';
import { ThreatIndicatorsController } from './controllers/threat-indicators.controller';
import { AttachmentRescansRepository } from './repositories/attachment-rescans.repository';
import { ScanSettingsRepository } from './repositories/scan-settings.repository';
import { ScanTrainingRepository } from './repositories/scan-training.repository';
import { ThreatHashesRepository } from './repositories/threat-hashes.repository';
import { ThreatIndicatorsRepository } from './repositories/threat-indicators.repository';
import { AttachmentRescansService } from './services/attachment-rescans.service';
import { EmlStore } from './services/eml-store';
import { RspamdController } from './services/rspamd-controller';
import { ScanSettingsService } from './services/scan-settings.service';
import { ScanTrainingService } from './services/scan-training.service';
import { ThreatHashesService } from './services/threat-hashes.service';
import { ThreatIndicatorsService } from './services/threat-indicators.service';

/**
 * Security scanning control plane (step 4.1 S8, S13, S16, docs/plan/steps/09-rspamd.md): the
 * per-organization scan settings (tenant routes, writer with version compare-and-set, audited)
 * and the platform training of the shared Rspamd classifiers (Bayes, fuzzy); step 4.2: the
 * platform known-threat hash catalog (A16, A17) and bulk attachment rescan jobs (A13); step 4.3:
 * the platform threat-indicator catalog (U16) and the `url` engine settings (U13). The scan results
 * of a message are read through MessagesModule (`GET /messages/{messageId}/scans`). Audit,
 * transactions, S3 and the database clients are global.
 */
@Module({
  controllers: [
    ScanSettingsController,
    ScanTrainingController,
    ThreatHashesController,
    ThreatIndicatorsController,
    AttachmentRescansController,
  ],
  providers: [
    ThreatHashesRepository,
    ThreatHashesService,
    ThreatIndicatorsRepository,
    ThreatIndicatorsService,
    AttachmentRescansRepository,
    AttachmentRescansService,
    ScanSettingsRepository,
    ScanSettingsService,
    ScanTrainingRepository,
    ScanTrainingService,
    EmlStore,
    RspamdController,
  ],
})
export class ScansModule {}
