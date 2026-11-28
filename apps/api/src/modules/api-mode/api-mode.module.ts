import { Module } from '@nestjs/common';
import { IdempotencyModule } from '../../http/idempotency/idempotency.module';
import { AuthModule } from '../auth/auth.module';
import { QuarantineModule } from '../quarantine/quarantine.module';
import { IntakeAddressService } from '../journaling/services/intake-address.service';
import { ApiModeController } from './controllers/api-mode.controller';
import { ApiModeClawbackController } from './controllers/api-mode-clawback.controller';
import { ApiModeReportsController } from './controllers/api-mode-reports.controller';
import { ApiModeSettingsController } from './controllers/api-mode-settings.controller';
import { ApiModeRemediationController } from './controllers/api-mode-remediation.controller';
import { ApiModeOnboardingController } from './controllers/api-mode-onboarding.controller';
import { ApiModeOnboardingRepository } from './repositories/api-mode-onboarding.repository';
import { ApiModeOnboardingService } from './services/api-mode-onboarding.service';
import { DomainOwnershipReader } from '../domains/services/domain-ownership-reader';
import { ProviderVerificationsRepository } from '../domains/repositories/provider-verifications.repository';
import { BoundConnectionsReader } from '../provider-connections/repositories/bound-connections.repository';
import { ProtectionModeController } from './controllers/protection-mode.controller';
import { ProviderNotificationsController } from './controllers/provider-notifications.controller';
import { NotificationRateLimitGuard } from './notification-rate-limit.guard';
import { ApiClawbackRepository } from './repositories/api-clawback.repository';
import { ApiModeRepository } from './repositories/api-mode.repository';
import { ApiRemediationRepository } from './repositories/api-remediation.repository';
import { ApiModeGuideService } from './services/api-mode-guide.service';
import { ApiModeService } from './services/api-mode.service';
import { ClawbackService } from './services/clawback.service';
import { OrgSettingsService } from './services/org-settings.service';
import { ProtectionModeService } from './services/protection-mode.service';
import { ProviderNotificationsService } from './services/provider-notifications.service';
import { ReportsService } from './services/reports.service';
import { RemediationActionsService } from './services/remediation-actions.service';
import { RemediationPolicyService } from './services/remediation-policy.service';

/**
 * API-mode protection (step API-1, docs/plan/steps/35-api-mode-protection.md D1, D2, D10-D12;
 * ADR-0098..0100): the protection modes of the organization and its domains, the API-mode
 * coverage and health views, the per-connection change-feed settings, inventory and resync
 * requests, mailboxes and detections, the setup guide, and the public Graph notification
 * callbacks. The api never calls a provider and never reads message content: the mailbox-worker
 * does the provider work; the api only reads its rows and requests work through them. Step API-2
 * (docs/plan/steps/36-api-mode-remediation.md R12, R13; ADR-0101): the remediation policy, the
 * remediation history and the manual remediate / restore / retry requests (action rows the
 * mailbox-worker executes; a restore of a quarantined copy goes through the quarantine release).
 * Step API-3 (docs/plan/steps/37-api-mode-clawback-reporting.md C14; ADR-0103, ADR-0104):
 * clawbacks (admin search and purge with the second-approver rule, cancel, bulk restore), user
 * reports (triage, clawback from a report, report mailboxes) and the organization's API-mode
 * settings; the mailbox-worker materializes and executes them. Step API-4
 * (docs/plan/steps/38-api-mode-parity-onboarding.md A10, A12, B6, B8; ADR-0105..0107): protection
 * by mode, the domain onboarding state, the per-domain mailbox scope, detect-mode policy fields of
 * detections, `policyMapping` and the detect-only period of remediation policies.
 */
@Module({
  imports: [IdempotencyModule, AuthModule, QuarantineModule],
  controllers: [
    ProtectionModeController,
    ApiModeController,
    ApiModeRemediationController,
    ApiModeClawbackController,
    ApiModeReportsController,
    ApiModeSettingsController,
    ApiModeOnboardingController,
    ProviderNotificationsController,
  ],
  providers: [
    ApiModeRepository,
    ApiRemediationRepository,
    ApiClawbackRepository,
    OrgSettingsService,
    ClawbackService,
    ReportsService,
    RemediationPolicyService,
    RemediationActionsService,
    ProtectionModeService,
    ApiModeService,
    ApiModeGuideService,
    ProviderNotificationsService,
    NotificationRateLimitGuard,
    IntakeAddressService,
    // Step API-4 (A10, B6, B8): onboarding reads, the scope write and the ownership block (the
    // domains module's reader with its two repositories).
    ApiModeOnboardingRepository,
    ApiModeOnboardingService,
    DomainOwnershipReader,
    ProviderVerificationsRepository,
    BoundConnectionsReader,
  ],
})
export class ApiModeModule {}
