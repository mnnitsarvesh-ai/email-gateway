import { Module } from '@nestjs/common';
import { ScanSettingsController } from './controllers/scan-settings.controller';
import { ScanTrainingController } from './controllers/scan-training.controller';
import { ScanSettingsRepository } from './repositories/scan-settings.repository';
import { ScanTrainingRepository } from './repositories/scan-training.repository';
import { EmlStore } from './services/eml-store';
import { RspamdController } from './services/rspamd-controller';
import { ScanSettingsService } from './services/scan-settings.service';
import { ScanTrainingService } from './services/scan-training.service';

/**
 * Security scanning control plane (step 4.1 S8, S13, S16, docs/plan/steps/09-rspamd.md): the
 * per-organization scan settings (tenant routes, writer with version compare-and-set, audited)
 * and the platform training of the shared Rspamd classifiers (Bayes, fuzzy). The scan results
 * of a message are read through MessagesModule (`GET /messages/{messageId}/scans`). Audit,
 * transactions, S3 and the database clients are global.
 */
@Module({
  controllers: [ScanSettingsController, ScanTrainingController],
  providers: [
    ScanSettingsRepository,
    ScanSettingsService,
    ScanTrainingRepository,
    ScanTrainingService,
    EmlStore,
    RspamdController,
  ],
})
export class ScansModule {}
