import { Module } from '@nestjs/common';
import { OrganizationsModule } from '../organizations/organizations.module';
import { AuditLogsController } from './audit-logs.controller';
import { AuditLogsRepository } from './audit-logs.repository';
import { AuditLogsService } from './audit-logs.service';
import { PlatformAuditLogsController } from './platform-audit-logs.controller';

/**
 * Step 6.1 (docs/plan/steps/18-rest-api.md §3.3): the audit log read API (`GET /audit/logs`,
 * `GET /platform/audit/logs`) on the replica. The platform search resolves its target
 * organization through OrganizationsRepository.
 */
@Module({
  imports: [OrganizationsModule],
  controllers: [AuditLogsController, PlatformAuditLogsController],
  providers: [AuditLogsRepository, AuditLogsService],
})
export class AuditLogsModule {}
