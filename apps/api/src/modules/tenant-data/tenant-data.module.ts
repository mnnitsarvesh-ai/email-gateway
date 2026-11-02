import { Module } from '@nestjs/common';
import { DomainsRepository } from './domains.repository';
import { MessagesRepository } from './messages.repository';
import { PoliciesRepository } from './policies.repository';
import { QuarantineRepository } from './quarantine.repository';

/**
 * Read-only, tenant-scoped repositories (D9, §10) for later steps (domains in 2.1, policies,
 * messages and quarantine afterwards). No controllers: they establish the scoping rule (every
 * query takes a `TenantScope` first) and are covered by the isolation tests.
 */
@Module({
  providers: [DomainsRepository, PoliciesRepository, MessagesRepository, QuarantineRepository],
  exports: [DomainsRepository, PoliciesRepository, MessagesRepository, QuarantineRepository],
})
export class TenantDataModule {}
