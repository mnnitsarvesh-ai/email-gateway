import { type DynamicModule, Module } from '@nestjs/common';
import {
  CorrelationModule,
  DatabaseModule,
  HealthModule,
  MetricsModule,
  PrismaReadService,
  PrismaService,
  RedisModule,
  RedisService,
  S3Module,
  S3Service,
} from '@email-gateway/common';
import { ApiCommonModule } from './api-common.module';
import { HttpConventionsModule } from './http/http-conventions.module';
import { API_CONFIG } from './api-config.token';
import type { ApiConfig } from './config';
import { MetaModule } from './meta/meta.module';
import { ApiKeysModule } from './modules/api-keys/api-keys.module';
import { AttachmentsModule } from './modules/attachments/attachments.module';
import { AuditLogsModule } from './modules/audit-logs/audit-logs.module';
import { AuthModule } from './modules/auth/auth.module';
import { BecModule } from './modules/bec/bec.module';
import { BillingModule } from './modules/billing/billing.module';
import { DeadLettersModule } from './modules/dead-letters/dead-letters.module';
import { DlpModule } from './modules/dlp/dlp.module';
import { DeliveriesModule } from './modules/deliveries/deliveries.module';
import { DomainDestinationsModule } from './modules/domain-destinations/domain-destinations.module';
import { DomainsModule } from './modules/domains/domains.module';
import { LoginAuditModule } from './modules/login-audit/login-audit.module';
import { MessagesModule } from './modules/messages/messages.module';
import { OrganizationsModule } from './modules/organizations/organizations.module';
import { RiskScoringModule } from './modules/risk-scoring/risk-scoring.module';
import { PoliciesModule } from './modules/policies/policies.module';
import { QuarantineModule } from './modules/quarantine/quarantine.module';
import { RecipientsModule } from './modules/recipients/recipients.module';
import { ReportsModule } from './modules/reports/reports.module';
import { DirectoryModule } from './modules/directory/directory.module';
import { RolesModule } from './modules/roles/roles.module';
import { ScansModule } from './modules/scans/scans.module';
import { SmtpConnectorsModule } from './modules/smtp-connectors/smtp-connectors.module';
import { TenantDataModule } from './modules/tenant-data/tenant-data.module';
import { ThreatIntelligenceModule } from './modules/threat-intelligence/threat-intelligence.module';
import { UrlProtectionModule } from './modules/url-protection/url-protection.module';
import { UsageModule } from './modules/usage/usage.module';
import { UsersModule } from './modules/users/users.module';

export const SERVICE_NAME = 'api';

@Module({})
export class AppModule {
  static forRoot(config: Readonly<ApiConfig>): DynamicModule {
    return {
      module: AppModule,
      global: true,
      imports: [
        CorrelationModule,
        // Step 6.1 D1, D2, D16: request id + Cache-Control and HTTP metrics middleware (after the
        // correlation middleware: same distance, import order) and the global ApiExceptionFilter.
        HttpConventionsModule,
        DatabaseModule.forRoot({
          url: config.DATABASE_URL,
          read: {
            url: config.DATABASE_READ_URL,
            maxLagSeconds: config.DATABASE_READ_MAX_LAG_SECONDS,
            lagCheckIntervalMs: config.DATABASE_READ_LAG_CHECK_INTERVAL_MS,
          },
        }),
        RedisModule.forRoot({ url: config.REDIS_URL }),
        S3Module.forRoot(config),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, PrismaReadService, RedisService, S3Service],
        }),
        // Prometheus series of the api (GET /metrics, outside the /api prefix; step 3.2 §5.3).
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        ApiCommonModule,
        // Registers the global AuthGuard → PermissionsGuard and the override audit interceptor.
        AuthModule,
        MetaModule,
        UsersModule,
        RolesModule,
        ApiKeysModule,
        LoginAuditModule,
        TenantDataModule,
        OrganizationsModule,
        DomainsModule,
        SmtpConnectorsModule,
        // Step 2.3: destination servers and per-recipient delivery status.
        DomainDestinationsModule,
        DeliveriesModule,
        // Step 3.3 L10/L12: message lifecycle reads, rescan and quarantine release.
        MessagesModule,
        // Step 3.2 Q9: dead-letter view and audited replay (platform).
        DeadLettersModule,
        // Step 4.1 S8, S13, S16: scan settings (tenant) and classifier training (platform).
        ScansModule,
        // Step 4.4 B18: BEC profiles, trusted senders, feedback, export and history purge.
        BecModule,
        // Step 4.5: DLP tenant data, incidents and the audited evidence door.
        DlpModule,
        // Step 5.1: risk scoring profiles (versioned, audited) and the no-write dry-run.
        RiskScoringModule,
        // Step 5.2: policies (versioned, audited), settings, test, dry-run, history; departments.
        PoliciesModule,
        DirectoryModule,
        // Step 5.3: quarantine search, preview, downloads, release, approvals, self-service.
        QuarantineModule,
        // Step 6.1: the new REST resources (filled by WP2 and WP3).
        RecipientsModule,
        AttachmentsModule,
        UrlProtectionModule,
        AuditLogsModule,
        ReportsModule,
        UsageModule,
        BillingModule,
        ThreatIntelligenceModule,
      ],
      providers: [{ provide: API_CONFIG, useValue: config }],
      exports: [API_CONFIG],
    };
  }
}
