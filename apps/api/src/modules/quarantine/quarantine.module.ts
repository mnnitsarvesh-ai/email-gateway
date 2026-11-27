import { Module } from '@nestjs/common';
import { IdempotencyModule } from '../../http/idempotency/idempotency.module';
import { AuthModule } from '../auth/auth.module';
import { MessagesModule } from '../messages/messages.module';
import { PoliciesModule } from '../policies/policies.module';
import { QuarantineApprovalsController } from './controllers/quarantine-approvals.controller';
import { QuarantineEntriesController } from './controllers/quarantine-entries.controller';
import { QuarantineSelfController } from './controllers/quarantine-self.controller';
import { QuarantineToolsController } from './controllers/quarantine-tools.controller';
import { QuarantineRateLimitGuard } from './quarantine-rate-limit';
import { RemediationActionWriter } from '../api-mode/repositories/remediation-action-writer';
import { QuarantineFactsRepository } from './repositories/quarantine-facts.repository';
import { QuarantineMailboxRepository } from './repositories/quarantine-mailbox.repository';
import { QuarantineReadRepository } from './repositories/quarantine-read.repository';
import { QuarantineWriteRepository } from './repositories/quarantine-write.repository';
import { QuarantineApprovalsService } from './services/quarantine-approvals.service';
import { QuarantineBulkService } from './services/quarantine-bulk.service';
import { QuarantineContext } from './services/quarantine-context';
import { QuarantineDispositionService } from './services/quarantine-disposition.service';
import { QuarantineDownloadService } from './services/quarantine-download.service';
import { QuarantineEntryOps } from './services/quarantine-entry-ops';
import { QuarantineMailboxOps } from './services/quarantine-mailbox-ops';
import { QuarantineMetrics } from './services/quarantine-metrics';
import { QuarantineObjectStore } from './services/quarantine-object-store';
import { QuarantinePrecheckService } from './services/quarantine-precheck.service';
import { QuarantinePreviewService } from './services/quarantine-preview.service';
import { QuarantineQueryService } from './services/quarantine-query.service';
import { QuarantineReleaseService } from './services/quarantine-release.service';
import { QuarantineSettingsService } from './services/quarantine-settings.service';
import { QuarantineWriter } from './services/quarantine-writer';

/**
 * Quarantine (step 5.3, docs/plan/steps/17-quarantine.md Q7, Q9–Q18, Q21, Q24, Q26, Q30;
 * ADR-0046–0048): the tenant-scoped quarantine API — search, detail, history, the sanitized
 * preview, the download door, release with re-validation, approvals with separation of duties,
 * end-user self-service, reject, delete under retention and legal hold, manual quarantine, bulk
 * actions and settings. The release executor, the sweeper and the notifications run in the
 * policy-engine (`quarantine` role) and the notification-worker; this module writes the requests
 * (release logs, approval requests, outbox events) and every user-facing decision. The
 * controllers with static paths are listed before the `entries/{entryId}` ones. Step API-2 R10
 * (ADR-0102): mailbox-located entries (API-mode copies held in the recipient's mailbox) branch
 * on `location`: release = a `restore_inbox` action row for the mailbox-worker.
 */
@Module({
  imports: [IdempotencyModule, MessagesModule, PoliciesModule, AuthModule],
  controllers: [
    QuarantineToolsController,
    QuarantineSelfController,
    QuarantineApprovalsController,
    QuarantineEntriesController,
  ],
  providers: [
    QuarantineMetrics,
    QuarantineWriter,
    QuarantineRateLimitGuard,
    QuarantineReadRepository,
    QuarantineWriteRepository,
    QuarantineFactsRepository,
    QuarantineObjectStore,
    QuarantineContext,
    QuarantineEntryOps,
    QuarantinePrecheckService,
    QuarantineQueryService,
    QuarantinePreviewService,
    QuarantineDownloadService,
    QuarantineReleaseService,
    QuarantineDispositionService,
    QuarantineApprovalsService,
    QuarantineBulkService,
    QuarantineSettingsService,
    // Step API-2 R10 (ADR-0102): the mailbox-located branch and the action rows it queues.
    QuarantineMailboxRepository,
    QuarantineMailboxOps,
    RemediationActionWriter,
  ],
  // Step 6.2 N3: the notification preference center checks `digest.allowOptOut` of the same
  // effective settings before writing `quarantine_user_preferences.digest_opt_out`. Step API-2
  // R12: the API-mode restore releases a mailbox-located entry through the release service (in
  // its own transaction, audited refusals via the writer) and queues action rows with the writer.
  exports: [QuarantineContext, QuarantineReleaseService, QuarantineWriter, RemediationActionWriter],
})
export class QuarantineModule {}
