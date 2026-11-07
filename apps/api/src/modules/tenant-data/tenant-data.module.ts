import { Module } from '@nestjs/common';
import { BecTenantDataRepository } from './bec-tenant-data.repository';
import { DomainsRepository } from './domains.repository';
import { MessagesRepository } from './messages.repository';
import { PoliciesRepository } from './policies.repository';
import { QuarantineRepository } from './quarantine.repository';

/**
 * Read-only, tenant-scoped repositories (D9, §10) for later steps (domains in 2.1, policies,
 * messages and quarantine afterwards). No controllers: they establish the scoping rule (every
 * query takes a `TenantScope` first) and are covered by the isolation tests. Step 4.4:
 * BecTenantDataRepository deletes an organization's BEC rows for the organization purge.
 */
@Module({
  providers: [
    DomainsRepository,
    PoliciesRepository,
    MessagesRepository,
    QuarantineRepository,
    BecTenantDataRepository,
  ],
  exports: [
    DomainsRepository,
    PoliciesRepository,
    MessagesRepository,
    QuarantineRepository,
    BecTenantDataRepository,
  ],
})
export class TenantDataModule {}
