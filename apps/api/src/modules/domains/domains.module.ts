import { Module } from '@nestjs/common';
import { DnsModule } from '../../dns/dns.module';
import { DomainDnsController } from './controllers/domain-dns.controller';
import { DomainsController } from './controllers/domains.controller';
import { DomainDnsChecker } from './engine/domain-dns-checker';
import { DkimKeysRepository } from './repositories/dkim-keys.repository';
import { DnsRecordsRepository } from './repositories/dns-records.repository';
import { DomainJobsRepository } from './repositories/domain-jobs.repository';
import { DomainOutboxRepository } from './repositories/domain-outbox.repository';
import { DomainOwnershipRepository } from './repositories/domain-ownership.repository';
import { DomainsRepository } from './repositories/domains.repository';
import { MxObservationsRepository } from './repositories/mx-observations.repository';
import { VerificationsRepository } from './repositories/verifications.repository';
import { DkimRotationService } from './services/dkim-rotation.service';
import { DomainCheckScheduler } from './services/domain-check-scheduler.service';
import { DomainConfigurationService } from './services/domain-configuration.service';
import { DomainEventsService } from './services/domain-events.service';
import {
  DomainVerificationService,
  domainScheduleJitterProvider,
} from './services/domain-verification.service';
import { DomainsService } from './services/domains.service';

/**
 * Domain onboarding (step 2.1): lifecycle, ownership verification, DNS checks, DKIM keys and
 * rotation, the background check scheduler and the `/domains` API. Uses the DNS module
 * (ADR-0017) and the global building blocks (audit, transactions, KV, SecretBox, limits).
 */
@Module({
  imports: [DnsModule],
  controllers: [DomainsController, DomainDnsController],
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
    // Engine and services.
    DomainDnsChecker,
    domainScheduleJitterProvider,
    DomainEventsService,
    DomainConfigurationService,
    DomainVerificationService,
    DkimRotationService,
    DomainsService,
    DomainCheckScheduler,
  ],
  exports: [DomainCheckScheduler, DomainVerificationService, DkimRotationService],
})
export class DomainsModule {}
