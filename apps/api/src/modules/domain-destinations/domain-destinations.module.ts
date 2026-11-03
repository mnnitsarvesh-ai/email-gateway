import { Module } from '@nestjs/common';
import { DomainsModule } from '../domains/domains.module';
import { DestinationProvidersController } from './controllers/destination-providers.controller';
import { DomainDestinationsController } from './controllers/domain-destinations.controller';
import { DomainDestinationsRepository } from './repositories/domain-destinations.repository';
import { DomainDestinationsService } from './services/domain-destinations.service';

/**
 * Destination servers of a domain (step 2.3 R2, R3, R13): provider presets, the tenant's
 * inbound destinations (`domain_mail_servers`, role `inbound_destination`) and their safety
 * rules. The smtp-adapter answers Postfix's transport and TLS maps from the same rows and
 * re-validates them. Uses the domains module's outbox repository and the global building
 * blocks (audit, transactions).
 */
@Module({
  imports: [DomainsModule],
  controllers: [DestinationProvidersController, DomainDestinationsController],
  providers: [DomainDestinationsRepository, DomainDestinationsService],
})
export class DomainDestinationsModule {}
