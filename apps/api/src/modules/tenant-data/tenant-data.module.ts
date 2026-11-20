import { Module } from '@nestjs/common';
import { ArchiveRecordsRepository } from '../archive/repositories/archive-records.repository';
import { DlpEvidenceStore } from '../dlp/services/dlp-evidence-store';
import { ArchiveTenantDataRepository } from './archive-tenant-data.repository';
import { AtoProviderTenantDataRepository } from './ato-provider-tenant-data.repository';
import { BecTenantDataRepository } from './bec-tenant-data.repository';
import { DlpTenantDataRepository } from './dlp-tenant-data.repository';
import { DomainsRepository } from './domains.repository';
import { JournalIntakeTenantDataRepository } from './journal-intake-tenant-data.repository';
import { MessagesRepository } from './messages.repository';
import { PoliciesRepository } from './policies.repository';
import { PolicyTenantDataRepository } from './policy-tenant-data.repository';
import { ProviderTenantDataRepository } from './provider-tenant-data.repository';
import { QuarantineRepository } from './quarantine.repository';
import { QuarantineTenantDataRepository } from './quarantine-tenant-data.repository';
import { RiskTenantDataRepository } from './risk-tenant-data.repository';

/**
 * Read-only, tenant-scoped repositories (D9, §10) for later steps (domains in 2.1, policies,
 * messages and quarantine afterwards). No controllers: they establish the scoping rule (every
 * query takes a `TenantScope` first) and are covered by the isolation tests. Step 4.4:
 * BecTenantDataRepository deletes an organization's BEC rows for the organization purge; step
 * 4.5: DlpTenantDataRepository its DLP rows and evidence objects; step 5.1:
 * RiskTenantDataRepository its risk scores and risk scoring profiles; step 5.2:
 * PolicyTenantDataRepository its policy evaluations, policies, settings and departments; step
 * 5.3: QuarantineTenantDataRepository its quarantine tables (refused under an active legal hold);
 * step 8.1: ArchiveTenantDataRepository its archive (disposal decisions, then the archive and
 * eDiscovery rows and the tenant keys; refused under an active hold or running retention); step
 * 8.2: ProviderTenantDataRepository its Microsoft 365 / Google Workspace connection rows (purge
 * order of §3.3) and their tenant data export (never credential material); step 8.5:
 * AtoProviderTenantDataRepository its ATO identity-provider rows (mailbox items, stream rows,
 * account identities, integrations) and their export (never a token or an address); step 8.6:
 * JournalIntakeTenantDataRepository its journal intake counters, intake messages and sources
 * (before the provider connections, which the sources reference).
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
    QuarantineTenantDataRepository,
    ArchiveRecordsRepository,
    ArchiveTenantDataRepository,
    ProviderTenantDataRepository,
    AtoProviderTenantDataRepository,
    JournalIntakeTenantDataRepository,
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
    QuarantineTenantDataRepository,
    ArchiveTenantDataRepository,
    ProviderTenantDataRepository,
    AtoProviderTenantDataRepository,
    JournalIntakeTenantDataRepository,
  ],
})
export class TenantDataModule {}
