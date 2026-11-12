import { Controller, Get, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequirePermissions,
} from '../../auth-contracts/decorators';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { Client } from '../auth/client-context.decorator';
import type { ClientContext } from '../auth/services/session.service';
import { ApiOkExample, ApiReadErrors } from '../reports/api-docs';
import { ApiAuditQuery } from './api-docs';
import {
  AUDIT_LOG_PAGE_EXAMPLE,
  type AuditLogPage,
  AuditLogPageSchema,
  type AuditLogsQuery,
  AuditLogsQuerySchema,
} from './audit-logs.schemas';
import { AuditLogsService } from './audit-logs.service';
import { AUDIT_READ } from './domain/platform-audit-access';

export const AUDIT_SEARCH_DESCRIPTION =
  'Window `[from, to)` default the last 7 days, at most `API_AUDIT_MAX_RANGE_DAYS`. Keyset ' +
  '`(createdAt, id)` in the `sort` direction (`-createdAt` default), read from the replica. ' +
  'Filters: `action` (exact) or `actionPrefix`, `resourceType`, `resourceId`, `actorType`, ' +
  '`actorId`; with any filter a page scans at most `API_LIST_SCAN_BUDGET_ROWS` entries and may ' +
  'be short (even empty) while `nextCursor` is non-null: follow `nextCursor` until it is null. ' +
  'Cursors are signed and bound to the caller, filters, sort and first window ' +
  '(`400 cursor_invalid` otherwise).';

/** `GET /audit/logs` (step 6.1 §3.3): the organization's audit trail. */
@ApiTags('audit')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'audit/logs', version: '1' })
export class AuditLogsController {
  constructor(private readonly auditLogs: AuditLogsService) {}

  @Get()
  @RequirePermissions(AUDIT_READ)
  @CursorList('v1')
  @ApiOperation({
    summary: 'Search the audit log',
    description:
      'Audit rows of the caller’s organization (mutations, audited reads, platform override ' +
      'requests into it). ' +
      AUDIT_SEARCH_DESCRIPTION +
      ' The first page of each search is itself audited (`audit.searched`: filter names, ' +
      'filter hash, row count).',
  })
  @ApiAuditQuery(false)
  @ApiOkExample(AuditLogPageSchema, AUDIT_LOG_PAGE_EXAMPLE)
  @ApiReadErrors({ extra400: ['cursor_invalid'] })
  search(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(AuditLogsQuerySchema)) query: AuditLogsQuery,
    @Client() client: ClientContext,
  ): Promise<AuditLogPage> {
    return this.auditLogs.search(principal, scope, query, client);
  }
}
