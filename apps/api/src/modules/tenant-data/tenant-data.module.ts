import { Module } from '@nestjs/common';
import { DlpEvidenceStore } from '../dlp/services/dlp-evidence-store';
import { BecTenantDataRepository } from './bec-tenant-data.repository';
import { DlpTenantDataRepository } from './dlp-tenant-data.repository';
import { DomainsRepository } from './domains.repository';
import { MessagesRepository } from './messages.repository';
import { PoliciesRepository } from './policies.repository';
import { PolicyTenantDataRepository } from './policy-tenant-data.repository';
import { QuarantineRepository } from './quarantine.repository';
import { RiskTenantDataRepository } from './risk-tenant-data.repository';

/**
 * Read-only, tenant-scoped repositories (D9, §10) for later steps (domains in 2.1, policies,
 * messages and quarantine afterwards). No controllers: they establish the scoping rule (every
 * query takes a `TenantScope` first) and are covered by the isolation tests. Step 4.4:
 * BecTenantDataRepository deletes an organization's BEC rows for the organization purge; step
 * 4.5: DlpTenantDataRepository its DLP rows and evidence objects; step 5.1:
 * RiskTenantDataRepository its risk scores and risk scoring profiles; step 5.2:
 * PolicyTenantDataRepository its policy evaluations, policies, settings and departments.
 */
@Module({
  providers: [
    DomainsRepository,
    PoliciesRepository,
    MessagesRepository,
    QuarantineRepository,
    BecTenantDataRepository,
    DlpEvidenceStore,
    DlpTenantDataRepository,
    RiskTenantDataRepository,
    PolicyTenantDataRepository,
  ],
  exports: [
    DomainsRepository,
    PoliciesRepository,
    MessagesRepository,
    QuarantineRepository,
    BecTenantDataRepository,
    DlpTenantDataRepository,
    RiskTenantDataRepository,
    PolicyTenantDataRepository,
  ],
})
export class TenantDataModule {}
