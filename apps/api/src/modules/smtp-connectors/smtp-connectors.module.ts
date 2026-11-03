import { Module } from '@nestjs/common';
import { SmtpConnectorsController } from './controllers/smtp-connectors.controller';
import { SmtpConnectorsRepository } from './repositories/smtp-connectors.repository';
import { SmtpConnectorsService } from './services/smtp-connectors.service';

/**
 * Outbound SMTP connectors (step 2.2 D10, §4.1): SASL credentials, source networks and client
 * certificates that let a tenant's servers relay through `postfix-outbound`. The smtp-adapter
 * reads the same tables (writer) to authorize sessions; this module only manages them. Uses the
 * global building blocks (audit, transactions, password hasher, organization lock).
 */
@Module({
  controllers: [SmtpConnectorsController],
  providers: [SmtpConnectorsRepository, SmtpConnectorsService],
})
export class SmtpConnectorsModule {}
