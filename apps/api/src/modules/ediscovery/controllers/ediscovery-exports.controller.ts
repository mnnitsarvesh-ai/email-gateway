import {
  Body,
  Controller,
  Get,
  Header,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Res,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError } from '../../../http/coded-exception';
import {
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
} from '../../../http/idempotency/idempotency-key';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ApiArchiveConflicts,
  ApiArchiveForbidden,
  ApiArchiveResponse,
  ApiArchiveUnavailable,
  ApiArchiveUnprocessable,
  ApiKeyedErrors,
  ArchiveIdempotency,
} from '../../archive/api-docs';
import { ArchiveRateLimit } from '../../archive/archive-rate-limit';
import { ARCHIVE_PERMISSIONS as P, NO_STORE } from '../../archive/archive.constants';
import { ARCHIVE_ERROR_CODES as C } from '../../archive/archive.errors';
import {
  type DownloadGrantBody,
  DownloadGrantBodySchema,
  DownloadGrantSchema,
  type DownloadGrantView,
  PAGE_PARAMETERS,
} from '../../archive/dto/archive.schemas';
import { ApiListErrors, ApiListQuery } from '../../messages/api-docs';
import {
  type CreateExportBody,
  CreateExportBodySchema,
  EDISCOVERY_EXAMPLES as X,
  ExportListQuerySchema,
  type ExportListQuery,
  type ExportPage,
  ExportPageSchema,
  ExportSchema,
  type ExportView,
} from '../dto/ediscovery.schemas';
import { EDISCOVERY_OPERATIONS } from '../ediscovery.constants';
import { EdiscoveryExportsService } from '../services/ediscovery-exports.service';
import { ApiCaseId, ApiCaseNotFound } from './ediscovery-cases.controller';

const ApiExportId = (): MethodDecorator =>
  ApiParam({ name: 'exportId', description: 'Export public id (UUID)', format: 'uuid' });

const ApiExportNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown case or export, or one of another organization', [
    C.caseNotFound,
    C.exportNotFound,
  ]);

/**
 * eDiscovery exports and their download grants (step 8.1 §4.4 #38–#41; A18). Translation only.
 */
@ApiTags('ediscovery')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'ediscovery/cases/:caseId/exports', version: '1' })
export class EdiscoveryExportsController {
  constructor(private readonly exports: EdiscoveryExportsService) {}

  @Post()
  @RequirePermissions(P.ediscovery, P.export)
  @HttpCode(HttpStatus.ACCEPTED)
  @ArchiveIdempotency(EDISCOVERY_OPERATIONS.exportCreate, 'expensive')
  @ApiOperation({
    summary: 'Export the hits of a case search',
    description:
      'Queues an export (`202`, `status: queued`) of the hits of a completed search ' +
      '(`409 ediscovery_search_not_completed`) with the given review tags (default every tag ' +
      'except `not_relevant`). The archive-worker builds a ZIP of the decrypted original ' +
      'messages (`messages/<receivedAt>_<messageId>.eml`, plaintext SHA-256 re-verified), ' +
      '`manifest.json` (`archive-export-manifest/1`), `manifest.sig` (Ed25519, keys at GET ' +
      '/archive/export-signing-keys) and `README.txt`, encrypted at rest, available for ' +
      'ARCHIVE_EXPORT_TTL_HOURS. Bounded by ARCHIVE_EXPORT_MAX_ITEMS and ' +
      'ARCHIVE_EXPORT_MAX_BYTES (`422 ediscovery_export_too_large`, checked here on the live ' +
      'records and again by the worker). A selection with malicious records needs ' +
      '`acknowledgeMalicious: true` (`409 ediscovery_export_malicious_ack_required`; they go ' +
      'under `malicious/` with a warning). Needs the plan feature `archiving`. Audited ' +
      '`ediscovery.export_requested`. Requires the Idempotency-Key header; rate class ' +
      '`expensive`.',
  })
  @ApiCaseId()
  @ApiBody({
    schema: zodToOpenApi(CreateExportBodySchema, { io: 'input' }),
    examples: { relevant: { value: X.exportCreate } },
  })
  @ApiArchiveResponse(202, ExportSchema, X.exportQueued, 'Queued', true)
  @ApiKeyedErrors()
  @ApiArchiveForbidden([C.notEnabled], '`archiving_not_enabled`')
  @ApiCodedError(404, 'Unknown case or search, or one of another organization', [
    C.caseNotFound,
    C.searchNotFound,
  ])
  @ApiArchiveConflicts(
    [C.searchNotCompleted, C.caseClosed, C.exportMaliciousAckRequired],
    '`ediscovery_search_not_completed`, `ediscovery_case_closed`, ' +
      '`ediscovery_export_malicious_ack_required` (`maliciousCount`)',
    true,
    { maliciousCount: { type: 'integer' }, status: { type: 'string' } },
  )
  @ApiArchiveUnprocessable(
    [C.exportTooLarge],
    '`ediscovery_export_too_large` (`limit`, `unit`)',
    true,
    {
      limit: { type: 'integer' },
      unit: { type: 'string' },
    },
  )
  @ApiArchiveUnavailable()
  async create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('caseId') caseId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body(new ZodValidationPipe(CreateExportBodySchema)) body: CreateExportBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ExportView> {
    const result = await this.exports.create(
      principal,
      scope,
      caseId,
      idempotencyKey,
      body,
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get()
  @RequirePermissions(P.ediscovery)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the exports of a case',
    description:
      'The exports of a case, newest first, with status, counts, hashes and expiry. v1 list ' +
      '(`ediscovery_exports`).',
  })
  @ApiCaseId()
  @ApiListQuery(ExportListQuerySchema, {
    ...PAGE_PARAMETERS,
    status: '`queued`, `building`, `completed`, `failed`, `expired`; comma list',
    sort: '`-id` (newest first)',
  })
  @ApiArchiveResponse(200, ExportPageSchema, X.exportPage, 'One page of exports')
  @ApiListErrors()
  @ApiArchiveForbidden()
  @ApiCaseNotFound()
  @ApiArchiveUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('caseId') caseId: string,
    @Query(new ZodValidationPipe(ExportListQuerySchema)) query: ExportListQuery,
  ): Promise<ExportPage> {
    return this.exports.list(principal, scope, caseId, query);
  }

  @Get(':exportId')
  @RequirePermissions(P.ediscovery)
  @ApiOperation({
    summary: 'Get an export',
    description:
      'Status (`queued`, `building`, `completed`, `failed`, `expired`), item and malicious ' +
      'counts, package size and SHA-256 (of the ZIP as downloaded), manifest SHA-256, signing ' +
      'key id and expiry.',
  })
  @ApiCaseId()
  @ApiExportId()
  @ApiArchiveResponse(200, ExportSchema, X.export, 'The export')
  @ApiArchiveForbidden()
  @ApiExportNotFound()
  @ApiArchiveUnavailable()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('caseId') caseId: string,
    @Param('exportId') exportId: string,
  ): Promise<ExportView> {
    return this.exports.get(scope, caseId, exportId);
  }

  @Post(':exportId/download-grants')
  @RequirePermissions(P.ediscovery, P.export)
  @UserOnly()
  @RequireMfa()
  @ArchiveRateLimit('download_grant')
  @HttpCode(HttpStatus.CREATED)
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Grant a single-use download of an export',
    description:
      'For a `completed` export (`409 ediscovery_export_not_ready`, `410 ' +
      'ediscovery_export_expired`). Fresh re-authorization: your password, and a TOTP code ' +
      'when MFA is enrolled (`401 quarantine_reauth_failed`). The token is bound to your ' +
      'organization, you and the export, valid ARCHIVE_DOWNLOAD_TOKEN_TTL_SECONDS; download ' +
      'it with GET /archive/downloads/{token}. ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR per user ' +
      '(shared with message grants). Audited `ediscovery.download_granted`. Customer-only: ' +
      'refused under a platform override (`403 archive_override_forbidden`). MFA-authenticated ' +
      'users only. Not idempotency-stored (the response carries the token).',
  })
  @ApiCaseId()
  @ApiExportId()
  @ApiBody({
    schema: zodToOpenApi(DownloadGrantBodySchema, { io: 'input' }),
    examples: { reauth: { value: { password: 'EXAMPLE-PASSWORD', totpCode: '123456' } } },
  })
  @ApiArchiveResponse(201, DownloadGrantSchema, X.grant, 'The single-use download token')
  @ApiCodedError(401, 'Re-authorization failed', [C.reauthFailed])
  @ApiArchiveForbidden([C.overrideForbidden], '`archive_override_forbidden`')
  @ApiExportNotFound()
  @ApiArchiveConflicts([C.exportNotReady], '`ediscovery_export_not_ready` (`status`)', false, {
    status: { type: 'string' },
  })
  @ApiCodedError(410, 'The export has expired', [C.exportExpired])
  @ApiArchiveUnavailable()
  grant(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('caseId') caseId: string,
    @Param('exportId') exportId: string,
    @Body(new ZodValidationPipe(DownloadGrantBodySchema)) body: DownloadGrantBody,
    @Client() client: ClientContext,
  ): Promise<DownloadGrantView> {
    return this.exports.grant(principal, scope, caseId, exportId, body, client);
  }
}
