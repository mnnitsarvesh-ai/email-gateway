import { Module } from '@nestjs/common';
import { BecExecutivesController } from './controllers/bec-executives.controller';
import {
  BecFeedbackController,
  BecMessageFeedbackController,
} from './controllers/bec-feedback.controller';
import { BecTrustedSendersController } from './controllers/bec-trusted-senders.controller';
import { BecVendorsController } from './controllers/bec-vendors.controller';
import { BecFeedbackRepository } from './repositories/bec-feedback.repository';
import { BecProfilesRepository } from './repositories/bec-profiles.repository';
import { BecFeedbackService } from './services/bec-feedback.service';
import { BecProfilesService } from './services/bec-profiles.service';
import { BecTrustedSendersService } from './services/bec-trusted-senders.service';
import { BecMetrics, BecWriter } from './services/bec-writer';

/**
 * Phishing and BEC tenant data (step 4.4 B7, B11, B12, B18, docs/plan/steps/12-phishing-bec.md):
 * executive and vendor profiles, trusted senders, analyst feedback with bounded suppressions,
 * the retraining export and the communication-history purge. The `bec` engine settings are
 * served by ScansModule (`/scan-settings/bec`) and the `bec` section of the scan results by
 * MessagesModule (`GET /messages/{messageId}/scans`). Audit, transactions, metrics and the
 * database clients are global.
 */
@Module({
  controllers: [
    BecExecutivesController,
    BecVendorsController,
    BecTrustedSendersController,
    BecFeedbackController,
    BecMessageFeedbackController,
  ],
  providers: [
    BecWriter,
    BecMetrics,
    BecProfilesRepository,
    BecFeedbackRepository,
    BecProfilesService,
    BecTrustedSendersService,
    BecFeedbackService,
  ],
})
export class BecModule {}
