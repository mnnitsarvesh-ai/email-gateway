import { Module } from '@nestjs/common';
import { DnsModule } from '../../dns/dns.module';
import { DomainDnsController } from './controllers/domain-dns.controller';
import { DomainRecipientsController } from './controllers/domain-recipients.controller';
import { DomainsController } from './controllers/domains.controller';
import { DomainDnsChecker } from './engine/domain-dns-checker';
import { DkimKeysRepository } from './repositories/dkim-keys.repository';
import { DkimSigningRepository } from './repositories/dkim-signing.repository';
import { DnsRecordsRepository } from './repositories/dns-records.repository';
import { DomainJobsRepository } from './repositories/domain-jobs.repository';
import { DomainOutboxRepository } from './repositories/domain-outbox.repository';
import { DomainOwnershipRepository } from './repositories/domain-ownership.repository';
import { DomainsRepository } from './repositories/domains.repository';
import { MxObservationsRepository } from './repositories/mx-observations.repository';
import { RecipientsRepository } from './repositories/recipients.repository';
import { VerificationsRepository } from './repositories/verifications.repository';
import { DkimRotationService } from './services/dkim-rotation.service';
import { DkimSigningPublisher } from './services/dkim-signing-publisher.service';
import { DomainCheckScheduler } from './services/domain-check-scheduler.service';
import { DomainConfigurationService } from './services/domain-configuration.service';
import { DomainEventsService } from './services/domain-events.service';
import {
  DomainVerificationService,
  domainScheduleJitterProvider,
} from './services/domain-verification.service';
import { DomainsService } from './services/domains.service';
import { DomainOwnershipReader } from './services/domain-ownership-reader';
import { DomainProviderOwnershipService } from './services/domain-provider-ownership.service';
import { ProviderVerificationsRepository } from './repositories/provider-verifications.repository';
import { BoundConnectionsReader } from '../provider-connections/repositories/bound-connections.repository';
import { RecipientValidationService } from './services/recipient-validation.service';
import { DkimKeyStore } from './signing/dkim-key-store';
import { RedisDkimStore } from './signing/redis-dkim-store';

/**
 * Domain onboarding (step 2.1): lifecycle, ownership verification, DNS checks, DKIM keys and
 * rotation, the background check scheduler and the `/domains` API. Step 2.2 adds inbound
 * recipient validation (D3) and the DKIM signing publisher that feeds redis-dkim (D12). Uses
 * the DNS module (ADR-0017) and the global building blocks (audit, transactions, KV,
 * SecretBox, limits). Step API-4 (B3, ADR-0107) adds ownership through the bound provider tenant
 * (the request route, the scheduler's application of the integration-worker's answers and the
 * `ownership` block of the views; the provider-connections module's bound-connection reader is
 * provided here, a module import would be circular).
 */
@Module({
  imports: [DnsModule],
  controllers: [DomainsController, DomainDnsController, DomainRecipientsController],
  providers: [
    // Repositories (the only Prisma users of this module).
    DomainsRepository,
    DnsRecordsRepository,
    VerificationsRepository,
    DkimKeysRepository,
    MxObservationsRepository,
    DomainOwnershipRepository,
    DomainJobsRepository,
    DomainOutboxRepository,
    RecipientsRepository,
    DkimSigningRepository,
    // Step API-4 (B3): provider ownership rows and the bound-connection reader of 8.2.
    ProviderVerificationsRepository,
    BoundConnectionsReader,
    { provide: DkimKeyStore, useClass: RedisDkimStore },
    // Engine and services.
    DomainDnsChecker,
    domainScheduleJitterProvider,
    DomainEventsService,
    DomainConfigurationService,
    DomainVerificationService,
    DkimRotationService,
    DomainsService,
    DomainOwnershipReader,
    DomainProviderOwnershipService,
    DomainCheckScheduler,
    RecipientValidationService,
    DkimSigningPublisher,
  ],
  exports: [
    // Step 2.3: the destinations module writes domain.routing.changed.v1 with it.
    DomainOutboxRepository,
    DomainCheckScheduler,
    DomainVerificationService,
    DkimRotationService,
    DkimSigningPublisher,
  ],
})
export class DomainsModule {}
