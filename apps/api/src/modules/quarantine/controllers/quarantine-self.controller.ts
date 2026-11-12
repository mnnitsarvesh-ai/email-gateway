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
} from '@nestjs/common';
import { ApiAcceptedResponse, ApiBody, ApiOkResponse, ApiOperation } from '@nestjs/swagger';
import type { Response } from 'express';
import type { QuarantinePreview } from '@email-gateway/mail-safety';
import type {
  Page,
  QuarantineEntryDetail,
  QuarantineEntrySummary,
} from '@email-gateway/quarantine';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError } from '../../../http/coded-exception';
import { ApiIdempotencyKey } from '../../../http/idempotency/idempotency-key';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ApiConflicts,
  IdempotencyKey,
  ApiEntryId,
  ApiEntryNotFound,
  ApiForbiddenCodes,
  ApiInconsistent,
  ApiQueryOf,
  entryIdPipe,
  NO_STORE_HEADER,
  QuarantineController,
  RELEASE_CONFLICTS,
} from '../api-docs';
import {
  EntryDetailSchema,
  EntryPageSchema,
  PreferencesBodySchema,
  type PreferencesBody,
  PreferencesResponseSchema,
  type PreferencesResponse,
  PreviewSchema,
  ReasonBodySchema,
  type ReasonBody,
  ReleaseBodySchema,
  type ReleaseBody,
  ReleaseOutcomeSchema,
  type ReleaseOutcome,
  type SelfSearchQuery,
  SelfSearchQuerySchema,
} from '../dto/quarantine.schemas';
import { NO_STORE, Q } from '../quarantine.constants';
import { QuarantineRateLimit } from '../quarantine-rate-limit';
import { QuarantinePreviewService } from '../services/quarantine-preview.service';
import { QuarantineQueryService } from '../services/quarantine-query.service';
import { QuarantineReleaseService } from '../services/quarantine-release.service';
import { QuarantineSettingsService } from '../services/quarantine-settings.service';
import { reply } from './quarantine-entries.controller';

const SELF_NOTE =
  ' Mailbox users (`quarantine:self`) with a verified email only: API keys and platform ' +
  'overrides are refused (`403`); the scope is the organization and the caller’s own address ' +
  '(another address’s entry is `404`).';

/**
 * End-user self-service (step 5.3 Q15; ADR-0047) under `/quarantine/me`: the caller's own
 * entries, preview, self-release, release requests and digest preferences. Translation only.
 */
@QuarantineController()
@Controller({ path: 'quarantine/me', version: '1' })
export class QuarantineSelfController {
  constructor(
    private readonly queries: QuarantineQueryService,
    private readonly releases: QuarantineReleaseService,
    private readonly previews: QuarantinePreviewService,
    private readonly settings: QuarantineSettingsService,
  ) {}

  @Get('entries')
  @RequirePermissions(Q.self)
  @UserOnly()
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Search my quarantined mail',
    description:
      'The caller’s own entries (recipient = the caller’s verified email), newest first, over ' +
      'a required bounded range, filtered by state and reason; subjects included. Empty when ' +
      'the organization disabled end-user access (`endUser.enabled`).' +
      SELF_NOTE,
  })
  @ApiQueryOf(SelfSearchQuerySchema, ['from', 'to'])
  @ApiOkResponse({ schema: zodToOpenApi(EntryPageSchema), headers: NO_STORE_HEADER })
  @ApiErrors(400, 401, 403)
  @ApiCodedError(400, 'Invalid range or cursor', [
    'quarantine_search_range_invalid',
    'quarantine_cursor_invalid',
  ])
  search(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(SelfSearchQuerySchema)) query: SelfSearchQuery,
    @Client() client: ClientContext,
  ): Promise<Page<QuarantineEntrySummary>> {
    return this.queries.selfSearch(principal, scope, query, client);
  }

  @Get('entries/:entryId')
  @RequirePermissions(Q.self)
  @UserOnly()
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Get one of my quarantined messages',
    description:
      'The entry with the actions the caller may take (`preview`, `release`, ' +
      '`request_release`). Audited as `quarantine.entry_viewed`.' +
      SELF_NOTE,
  })
  @ApiEntryId()
  @ApiOkResponse({ schema: zodToOpenApi(EntryDetailSchema), headers: NO_STORE_HEADER })
  @ApiErrors(400, 401, 403)
  @ApiEntryNotFound()
  detail(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('entryId', entryIdPipe) entryId: string,
    @Client() client: ClientContext,
  ): Promise<QuarantineEntryDetail> {
    return this.queries.selfDetail(principal, scope, entryId, client);
  }

  @Get('entries/:entryId/preview')
  @RequirePermissions(Q.self)
  @UserOnly()
  @QuarantineRateLimit('preview')
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Preview one of my quarantined messages',
    description:
      'The sanitized, DLP-masked JSON preview (as GET /quarantine/entries/{entryId}/preview), ' +
      'when the organization allows it (`endUser.preview`) and the entry has no hard block and ' +
      'is not malware or phishing (`403 quarantine_preview_not_allowed`). Downloads are never ' +
      'offered to end users.' +
      SELF_NOTE,
  })
  @ApiEntryId()
  @ApiOkResponse({ schema: zodToOpenApi(PreviewSchema), headers: NO_STORE_HEADER })
  @ApiErrors(400, 401, 403, 429)
  @ApiForbiddenCodes(['quarantine_preview_not_allowed'])
  @ApiEntryNotFound()
  @ApiCodedError(410, 'The message content was purged', ['quarantine_content_purged'])
  preview(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('entryId', entryIdPipe) entryId: string,
    @Client() client: ClientContext,
  ): Promise<QuarantinePreview> {
    return this.previews.selfPreview(principal, scope, entryId, client);
  }

  @Post('entries/:entryId/release')
  @RequirePermissions(Q.self)
  @UserOnly()
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Release one of my quarantined messages',
    description:
      'Self-release when the organization allows it (`endUser.selfRelease`): the entry’s ' +
      'reason is in `endUser.selfReleaseReasons` (spam, bulk, policy), its risk level at most ' +
      '`endUser.selfReleaseMaxLevel`, no approval reason (hard block, engine failure, DLP, ' +
      'policy reject) and fresh verdicts; otherwise `403 quarantine_self_release_not_allowed` ' +
      'with the cause. Queued for the release executor, which re-validates. Audited as ' +
      '`quarantine.self_released`. Requires the Idempotency-Key header.' +
      SELF_NOTE,
  })
  @ApiEntryId()
  @ApiIdempotencyKey()
  @ApiBody({ schema: zodToOpenApi(ReleaseBodySchema, { io: 'input' }) })
  @ApiAcceptedResponse({ schema: zodToOpenApi(ReleaseOutcomeSchema) })
  @ApiErrors(400, 401, 403, 422)
  @ApiForbiddenCodes(['quarantine_self_release_not_allowed'])
  @ApiEntryNotFound()
  @ApiConflicts(RELEASE_CONFLICTS)
  @ApiInconsistent()
  async release(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('entryId', entryIdPipe) entryId: string,
    @IdempotencyKey() key: string,
    @Body(new ZodValidationPipe(ReleaseBodySchema)) body: ReleaseBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ReleaseOutcome> {
    return reply(
      res,
      await this.releases.selfRelease({ principal, scope, entryId, key, body, client }),
    );
  }

  @Post('entries/:entryId/request-release')
  @RequirePermissions(Q.self)
  @UserOnly()
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Ask an administrator to release one of my messages',
    description:
      'A `release_request` approval request (when `endUser.requestRelease`); an administrator ' +
      'other than the caller decides. Audited as `quarantine.approval_requested`. Requires the ' +
      'Idempotency-Key header.' +
      SELF_NOTE,
  })
  @ApiEntryId()
  @ApiIdempotencyKey()
  @ApiBody({ schema: zodToOpenApi(ReasonBodySchema, { io: 'input' }) })
  @ApiAcceptedResponse({ schema: zodToOpenApi(ReleaseOutcomeSchema) })
  @ApiErrors(400, 401, 403, 422)
  @ApiForbiddenCodes(['quarantine_self_release_not_allowed'])
  @ApiEntryNotFound()
  @ApiConflicts(['quarantine_state_conflict', 'quarantine_hard_block_release_disabled'])
  @ApiInconsistent()
  async requestRelease(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('entryId', entryIdPipe) entryId: string,
    @IdempotencyKey() key: string,
    @Body(new ZodValidationPipe(ReasonBodySchema)) body: ReasonBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ReleaseOutcome> {
    return reply(
      res,
      await this.releases.selfRequestRelease({ principal, scope, entryId, key, body, client }),
    );
  }

  @Get('preferences')
  @RequirePermissions(Q.self)
  @UserOnly()
  @ApiOperation({
    summary: 'Get my quarantine digest preference',
    description:
      'Whether the caller opted out of the digest, and whether opting out is allowed.' + SELF_NOTE,
  })
  @ApiOkResponse({ schema: zodToOpenApi(PreferencesResponseSchema) })
  @ApiErrors(401, 403)
  preferences(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
  ): Promise<PreferencesResponse> {
    return this.settings.preferences(principal, scope);
  }

  @Put('preferences')
  @RequirePermissions(Q.self)
  @UserOnly()
  @ApiOperation({
    summary: 'Set my quarantine digest preference',
    description:
      'Opting out needs the organization’s `digest.allowOptOut` (`400 ' +
      'quarantine_settings_invalid`). Idempotent (PUT). Audited as ' +
      '`quarantine.preferences_updated`.' +
      SELF_NOTE,
  })
  @ApiBody({ schema: zodToOpenApi(PreferencesBodySchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(PreferencesResponseSchema) })
  @ApiErrors(400, 401, 403)
  @ApiCodedError(400, 'Opting out is not allowed', ['quarantine_settings_invalid'])
  putPreferences(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(PreferencesBodySchema)) body: PreferencesBody,
    @Client() client: ClientContext,
  ): Promise<PreferencesResponse> {
    return this.settings.putPreferences(principal, scope, body, client);
  }
}
