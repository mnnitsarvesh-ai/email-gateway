import {
  Body,
  Controller,
  Get,
  Header,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Put,
  Query,
  Res,
  StreamableFile,
} from '@nestjs/common';
import { ApiBody, ApiOkResponse, ApiOperation, ApiParam, ApiProduces } from '@nestjs/swagger';
import type { Response } from 'express';
import type { BulkResult } from '@email-gateway/quarantine';
import {
  CurrentPrincipal,
  CurrentScope,
  RequireAnyPermission,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError, CodedHttpException } from '../../../http/coded-exception';
import { ApiIdempotencyKey } from '../../../http/idempotency/idempotency-key';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import { CurrentUser } from '../../auth/current-user.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  IdempotencyKey,
  ApiInconsistent,
  ApiQueryOf,
  NO_STORE_HEADER,
  QuarantineController,
  releaseIdPipe,
} from '../api-docs';
import {
  BulkBodySchema,
  BulkResponseSchema,
  CatalogResponseSchema,
  type CatalogResponse,
  ReleaseDetailSchema,
  type ReleaseDetail,
  SettingsResponseSchema,
  type SettingsResponse,
  SettingsUpdateBodySchema,
  type SettingsUpdateBody,
  SummaryQuerySchema,
  type SummaryQuery,
  SummaryResponseSchema,
  type SummaryResponse,
} from '../dto/quarantine.schemas';
import { NO_STORE, Q, SETTINGS_MANAGE } from '../quarantine.constants';
import { QuarantineRateLimit } from '../quarantine-rate-limit';
import { QuarantineBulkService } from '../services/quarantine-bulk.service';
import { QuarantineDownloadService } from '../services/quarantine-download.service';
import { QuarantineQueryService } from '../services/quarantine-query.service';
import { QuarantineSettingsService } from '../services/quarantine-settings.service';
import { reply } from './quarantine-entries.controller';

/** Token path parameter: the `qdl1.<payload>.<mac>` grammar, bounded. */
const TOKEN = /^qdl1\.[A-Za-z0-9_-]{1,900}\.[A-Za-z0-9_-]{43}$/;

/**
 * Organization-level quarantine routes (step 5.3 Q12, Q18, Q24, Q26): the catalog, the bounded
 * summary, settings, bulk actions, release lookups and the download door. Translation only.
 */
@QuarantineController()
@Controller({ path: 'quarantine', version: '1' })
export class QuarantineToolsController {
  constructor(
    private readonly queries: QuarantineQueryService,
    private readonly settings: QuarantineSettingsService,
    private readonly bulkActions: QuarantineBulkService,
    private readonly downloads: QuarantineDownloadService,
  ) {}

  @Get('catalog')
  @RequireAnyPermission(Q.read, Q.self)
  @ApiOperation({
    summary: 'Quarantine catalog',
    description:
      'Enums (states, kinds, origins, reasons, engines, levels, release modes and statuses, ' +
      'approval kinds, statuses and reasons, entry and bulk actions), the error codes with ' +
      'their HTTP status, the platform limits and the organization’s effective self-service ' +
      'switches (for the portal).',
  })
  @ApiOkResponse({ schema: zodToOpenApi(CatalogResponseSchema) })
  @ApiErrors(401, 403)
  catalog(@CurrentScope() scope: TenantScope): Promise<CatalogResponse> {
    return this.queries.catalog(scope);
  }

  @Get('summary')
  @RequirePermissions(Q.read)
  @ApiOperation({
    summary: 'Count entries by state',
    description:
      'Counts of entries by state quarantined in a required bounded range (`to - from` ≤ ' +
      'QUARANTINE_SEARCH_MAX_RANGE_DAYS) and the number of pending approval requests. Read ' +
      'replica.',
  })
  @ApiQueryOf(SummaryQuerySchema, ['from', 'to'])
  @ApiOkResponse({ schema: zodToOpenApi(SummaryResponseSchema) })
  @ApiErrors(400, 401, 403)
  @ApiCodedError(400, 'Invalid range', ['quarantine_search_range_invalid'])
  summary(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(SummaryQuerySchema)) query: SummaryQuery,
  ): Promise<SummaryResponse> {
    return this.queries.summary(scope, query);
  }

  @Get('settings')
  @RequirePermissions(Q.read)
  @ApiOperation({
    summary: 'Get the quarantine settings',
    description:
      'The effective settings (stored document over the defaults, with the hold period and ' +
      'digest schedule of the organization settings), the stored document, whether it is ' +
      'invalid (defaults apply), the bounds and `rowVersion` (0 without a stored row).',
  })
  @ApiOkResponse({ schema: zodToOpenApi(SettingsResponseSchema) })
  @ApiErrors(401, 403)
  getSettings(@CurrentScope() scope: TenantScope): Promise<SettingsResponse> {
    return this.settings.get(scope);
  }

  @Put('settings')
  @RequirePermissions(SETTINGS_MANAGE)
  @ApiOperation({
    summary: 'Replace the quarantine settings',
    description:
      'The whole settings document (every key optional; unknown keys refused) with the ' +
      '`rowVersion` read before (`409 quarantine_settings_conflict` when it changed; 0 creates ' +
      'the row). Invalid documents: `400 quarantine_settings_invalid` with the violations by ' +
      'path. Changes apply to entries created afterwards (expiry is fixed at creation). ' +
      'Audited as `quarantine.settings_updated` with the changed paths.',
  })
  @ApiBody({ schema: zodToOpenApi(SettingsUpdateBodySchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(SettingsResponseSchema) })
  @ApiErrors(400, 401, 403)
  @ApiCodedError(400, 'Invalid settings', ['quarantine_settings_invalid'])
  @ApiCodedError(409, 'Settings changed since rowVersion', ['quarantine_settings_conflict'])
  @ApiInconsistent()
  putSettings(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(SettingsUpdateBodySchema)) body: SettingsUpdateBody,
    @Client() client: ClientContext,
  ): Promise<SettingsResponse> {
    return this.settings.put(principal, scope, body, client);
  }

  @Post('bulk')
  @RequireAnyPermission(Q.release, Q.reject, Q.delete, Q.approve)
  @QuarantineRateLimit('bulk')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Release, reject, delete, approve or deny many entries',
    description:
      '1 to QUARANTINE_BULK_MAX_ITEMS unique ids (entry ids; approval request ids for approve ' +
      'and deny) per request (`400 quarantine_bulk_limit`), QUARANTINE_BULK_MAX_ITEMS_PER_' +
      'MINUTE items per organization and minute (`429 quarantine_bulk_rate_limited` with ' +
      '`Retry-After`), QUARANTINE_BULK_REQUESTS_PER_MINUTE requests per caller. The action’s ' +
      'own permission is required (`quarantine:release`, `:reject`, `:delete`, `:approve`); ' +
      'approve and deny also need an MFA-authenticated user. Each item runs the single-item ' +
      'operation in its own transaction (same re-validation, separation of duties and audit), ' +
      'sequentially until QUARANTINE_BULK_DEADLINE_MS (the rest `skipped`, code `deadline`). ' +
      'Partial failure is reported per item. The whole response is stored under the ' +
      'Idempotency-Key. Audited as `quarantine.bulk` plus the per-item rows.',
  })
  @ApiIdempotencyKey()
  @ApiBody({ schema: zodToOpenApi(BulkBodySchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(BulkResponseSchema) })
  @ApiErrors(400, 401, 403, 422, 429)
  @ApiCodedError(400, 'Bulk request limits', ['quarantine_bulk_limit'])
  @ApiCodedError(429, 'Bulk item rate per organization', ['quarantine_bulk_rate_limited'])
  async bulk(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @IdempotencyKey() key: string,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<BulkResult> {
    try {
      return reply(res, await this.bulkActions.bulk(principal, scope, key, body, client));
    } catch (error) {
      if (error instanceof CodedHttpException && error.code === 'quarantine_bulk_rate_limited') {
        const retry = error.details.retryAfterSeconds;
        res.setHeader('Retry-After', typeof retry === 'number' ? String(retry) : '60');
      }
      throw error;
    }
  }

  @Get('releases/:releaseId')
  @RequirePermissions(Q.read)
  @ApiOperation({
    summary: 'Get a release',
    description:
      'The release log of a queued release: status (pending until the executor ran: ' +
      'dispatched, approval_required, rescan_required, refused, message_busy …), mode, ' +
      'requester, the re-validation summary (the executor’s, else the api’s pre-check), the ' +
      'delivered object and the entries. Read replica.',
  })
  @ApiParam({ name: 'releaseId', format: 'uuid' })
  @ApiOkResponse({ schema: zodToOpenApi(ReleaseDetailSchema) })
  @ApiErrors(400, 401, 403)
  @ApiCodedError(404, 'Release not found (also another organization’s)', [
    'quarantine_release_not_found',
  ])
  release(
    @CurrentScope() scope: TenantScope,
    @Param('releaseId', releaseIdPipe) releaseId: string,
  ): Promise<ReleaseDetail> {
    return this.queries.release(scope, releaseId);
  }

  @Get('downloads/:token')
  @RequirePermissions(Q.download)
  @UserOnly()
  @QuarantineRateLimit('download')
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Download through a single-use grant',
    description:
      'The token of POST …/download-grants, by the same user in the same organization, once, ' +
      'before it expires (`404 quarantine_download_token_invalid`, `410 ' +
      'quarantine_download_token_used`). The malware gating runs again; the audit row ' +
      '`quarantine.downloaded` is committed before the bytes are streamed with ' +
      '`Content-Type: application/octet-stream`, `Content-Disposition: attachment; ' +
      'filename="<name>.eml.bin|.bin"`, `X-Content-Type-Options: nosniff`, `Cache-Control: ' +
      "no-store` and `Content-Security-Policy: sandbox; default-src 'none'`. Never an S3 URL.",
  })
  @ApiParam({ name: 'token', description: 'qdl1.<payload>.<mac>' })
  @ApiProduces('application/octet-stream')
  @ApiOkResponse({
    description: 'The object bytes',
    schema: { type: 'string', format: 'binary' },
    headers: NO_STORE_HEADER,
  })
  @ApiErrors(401, 403, 429)
  @ApiCodedError(404, 'Unknown, expired or foreign token', ['quarantine_download_token_invalid'])
  @ApiCodedError(410, 'Token used, or content purged', [
    'quarantine_download_token_used',
    'quarantine_content_purged',
  ])
  @ApiCodedError(409, 'Blocked by the malware gating', ['quarantine_download_blocked'])
  async download(
    @CurrentUser() principal: UserPrincipal,
    @CurrentScope() scope: TenantScope,
    @Param('token') token: string,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<StreamableFile> {
    if (typeof token !== 'string' || !TOKEN.test(token)) {
      throw new CodedHttpException(
        HttpStatus.NOT_FOUND,
        'quarantine_download_token_invalid',
        'Download token not found or expired',
      );
    }
    const file = await this.downloads.download(principal, scope, token, client);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "sandbox; default-src 'none'");
    return new StreamableFile(file.body, {
      type: 'application/octet-stream',
      disposition: `attachment; filename="${file.filename}"`,
      length: file.sizeBytes,
    });
  }
}
