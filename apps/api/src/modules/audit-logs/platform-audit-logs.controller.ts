import { Controller, Get, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../auth-contracts/decorators';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME } from '../../http/openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { Client } from '../auth/client-context.decorator';
import type { ClientContext } from '../auth/services/session.service';
import { ApiCodedError, ApiOkExample, ApiReadErrors } from '../reports/api-docs';
import { ApiAuditQuery } from './api-docs';
import { AUDIT_SEARCH_DESCRIPTION } from './audit-logs.controller';
import {
  AUDIT_LOG_PAGE_EXAMPLE,
  type AuditLogPage,
  AuditLogPageSchema,
  type PlatformAuditLogsQuery,
  PlatformAuditLogsQuerySchema,
} from './audit-logs.schemas';
import { ORGANIZATION_NOT_FOUND_CODE, AuditLogsService } from './audit-logs.service';
import { AUDIT_READ, PLATFORM_OPERATIONS } from './domain/platform-audit-access';

/** `GET /platform/audit/logs` (step 6.1 §3.3, D7): audit search across organizations. */
@ApiTags('platform')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@Controller({ path: 'platform/audit/logs', version: '1' })
export class PlatformAuditLogsController {
  constructor(private readonly auditLogs: AuditLogsService) {}

  @Get()
  @RequirePermissions(PLATFORM_OPERATIONS, AUDIT_READ)
  @UserOnly()
  @RequireMfa()
  @CursorList('v1')
  @ApiOperation({
    summary: 'Search any organization’s audit log (platform)',
    description:
      'For users of the platform organization only (API keys, override sessions and customer ' +
      'users are refused), in an MFA session. Exactly one target: `organizationId` (any ' +
      'organization, `404 organization_not_found` when unknown) or `scope=platform` (rows ' +
      'without an organization). ' +
      AUDIT_SEARCH_DESCRIPTION +
      ' The first page of each search is audited as `platform.audit_searched` in the searched ' +
      'organization’s trail (platform rows for `scope=platform`).',
  })
  @ApiAuditQuery(true)
  @ApiOkExample(AuditLogPageSchema, AUDIT_LOG_PAGE_EXAMPLE)
  @ApiReadErrors({ extra400: ['cursor_invalid'] })
  @ApiCodedError(
    403,
    ['forbidden', 'mfa_required', 'user_required'],
    'Not a platform user, an API key, an override session, or no MFA',
  )
  @ApiCodedError(404, [ORGANIZATION_NOT_FOUND_CODE], 'Unknown organization')
  search(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(PlatformAuditLogsQuerySchema)) query: PlatformAuditLogsQuery,
    @Client() client: ClientContext,
  ): Promise<AuditLogPage> {
    return this.auditLogs.searchPlatform(principal, scope, query, client);
  }
}
