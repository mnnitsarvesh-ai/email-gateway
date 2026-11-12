import {
  Body,
  Controller,
  Get,
  Header,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Res,
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiBody,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
} from '@nestjs/swagger';
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
  CursorList,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError } from '../../../http/coded-exception';
import { IDEMPOTENCY_REPLAYED_HEADER } from '../../../http/idempotency/idempotency-key';
import type { IdempotentResult } from '../../../http/idempotency/idempotency.service';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import { CurrentUser } from '../../auth/current-user.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ApiConflicts,
  IdempotencyKey,
  ApiEntryId,
  ApiEntryNotFound,
  ApiForbiddenCodes,
  ApiInconsistent,
  ApiQueryOf,
  ENTRY_WRITE_CONFLICTS,
  entryIdPipe,
  NO_STORE_HEADER,
  QuarantineController,
  RELEASE_CONFLICTS,
} from '../api-docs';
import {
  DeleteBodySchema,
  type DeleteBody,
  DownloadGrantBodySchema,
  type DownloadGrantBody,
  DownloadGrantResponseSchema,
  type DownloadGrantResponse,
  EntryDetailSchema,
  EntryPageSchema,
  type EntrySearchQuery,
  EntrySearchQuerySchema,
  EntryStateResponseSchema,
  type EntryStateResponse,
  HistoryResponseSchema,
  type HistoryResponse,
  ManualQuarantineBodySchema,
  type ManualQuarantineBody,
  ManualQuarantineResponseSchema,
  type ManualQuarantineResponse,
  PreviewSchema,
  ReasonBodySchema,
  type ReasonBody,
  RejectBodySchema,
  type RejectBody,
  ReleaseBodySchema,
  type ReleaseBody,
  ReleaseOutcomeSchema,
  type ReleaseOutcome,
} from '../dto/quarantine.schemas';
import { NO_STORE, Q, QUARANTINE_OPERATIONS } from '../quarantine.constants';
import { TransactionalIdempotency } from '../../messages/api-docs';
import { QuarantineRateLimit } from '../quarantine-rate-limit';
import { QuarantineDispositionService } from '../services/quarantine-disposition.service';
import { QuarantineDownloadService } from '../services/quarantine-download.service';
import { QuarantinePreviewService } from '../services/quarantine-preview.service';
import { QuarantineQueryService } from '../services/quarantine-query.service';
import { QuarantineReleaseService } from '../services/quarantine-release.service';

export function reply<T>(res: Response, result: IdempotentResult<T>): T {
  if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
  res.status(result.statusCode);
  return result.body;
}

const searchQueryPipe = new ZodValidationPipe(EntrySearchQuerySchema);

/**
 * Quarantine entries of the caller's organization (step 5.3 Q7, Q9–Q13, Q16, Q17, Q26):
 * search, manual quarantine, detail, history, preview, download grants, release, release
 * requests, reject and delete. Translation only; the tenant comes from the authenticated scope,
 * another organization's entry is `404 quarantine_entry_not_found`.
 */
@QuarantineController()
@Controller({ path: 'quarantine/entries', version: '1' })
export class QuarantineEntriesController {
  constructor(
    private readonly queries: QuarantineQueryService,
    private readonly releases: QuarantineReleaseService,
    private readonly disposition: QuarantineDispositionService,
    private readonly previews: QuarantinePreviewService,
    private readonly downloads: QuarantineDownloadService,
  ) {}

  @Get()
  @CursorList('v0')
  @RequirePermissions(Q.read)
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Search quarantine entries',
    description:
      'Keyset-paginated search (newest `quarantinedAt` first) over a required, bounded range ' +
      '(`to - from` ≤ QUARANTINE_SEARCH_MAX_RANGE_DAYS) with optional filters: state, kind, ' +
      'direction, reason, riskLevel or minRiskLevel, primaryEngine, decisive policyId/ruleId, ' +
      'exact envelope sender (`sender`, index-backed) or header From (`headerFrom`), ' +
      'senderDomain, exact recipient, hasAttachments, ' +
      'hasHardBlock, messageId. No free-text or subject search. The cursor is bound to the ' +
      'filters (`400 quarantine_cursor_invalid` with other filters). `subject` is returned only ' +
      'to holders of `quarantine:preview`. Read replica: an entry just created may be missing ' +
      'for the replication lag. Audited as `quarantine.searched` (filter hash and count only).',
  })
  @ApiQueryOf(EntrySearchQuerySchema, ['from', 'to'])
  @ApiOkResponse({ schema: zodToOpenApi(EntryPageSchema), headers: NO_STORE_HEADER })
  @ApiErrors(400, 401, 403)
  @ApiCodedError(400, 'Invalid range or cursor', [
    'quarantine_search_range_invalid',
    'quarantine_cursor_invalid',
  ])
  search(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(searchQueryPipe) query: EntrySearchQuery,
    @Client() client: ClientContext,
  ): Promise<Page<QuarantineEntrySummary>> {
    return this.queries.search(principal, scope, query, client);
  }

  @Post()
  @TransactionalIdempotency(QUARANTINE_OPERATIONS.manual)
  @RequirePermissions(Q.manage)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Quarantine a message manually',
    description:
      'A `held_for_review` message: the selected pending review entries become quarantine ' +
      'entries (`held`, their policy_review requests cancelled; E16 when no review entry ' +
      'remains). A `rejected` message whose policy rejected or discarded it, received within ' +
      'QUARANTINE_MANUAL_FROM_REJECT_MAX_DAYS and whose EML still exists: E29 → `quarantined` ' +
      '(same round) and one `manual` entry per selected recipient (`409 ' +
      'quarantine_manual_not_allowed` otherwise). Any other state: `409 ' +
      'quarantine_state_conflict` (no clawback of delivered mail). Audited as ' +
      '`quarantine.manual_quarantined`. Requires the Idempotency-Key header.',
  })
  @ApiBody({ schema: zodToOpenApi(ManualQuarantineBodySchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(ManualQuarantineResponseSchema) })
  @ApiErrors(400, 401, 403, 422)
  @ApiEntryNotFound()
  @ApiConflicts(['quarantine_state_conflict', 'quarantine_manual_not_allowed'])
  @ApiInconsistent()
  async manual(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @IdempotencyKey() key: string,
    @Body(new ZodValidationPipe(ManualQuarantineBodySchema)) body: ManualQuarantineBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ManualQuarantineResponse> {
    return reply(res, await this.disposition.manual({ principal, scope, key, body, client }));
  }

  @Get(':entryId')
  @RequirePermissions(Q.read)
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Get a quarantine entry',
    description:
      'The entry with its explanation lines, floor reasons, reason codes, decisive rule, ' +
      'release attempts, `allowedActions` for the caller (advisory; every route re-checks) and ' +
      '`contentAvailable`. `subject` only with `quarantine:preview`. Read replica; each call ' +
      'writes a `view` action and the audit row `quarantine.entry_viewed`.',
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
    return this.queries.detail(principal, scope, entryId, client);
  }

  @Get(':entryId/history')
  @RequirePermissions(Q.read)
  @ApiOperation({
    summary: 'Get the history of a quarantine entry',
    description:
      'The entry’s `quarantine_actions` (oldest first, at most 500: action, actor type and ' +
      'public id, result, time, the operator-typed reason of user and API-key actions) and its ' +
      'release attempts. Read replica.',
  })
  @ApiEntryId()
  @ApiOkResponse({ schema: zodToOpenApi(HistoryResponseSchema) })
  @ApiErrors(400, 401, 403)
  @ApiEntryNotFound()
  history(
    @CurrentScope() scope: TenantScope,
    @Param('entryId', entryIdPipe) entryId: string,
  ): Promise<HistoryResponse> {
    return this.queries.history(scope, entryId);
  }

  @Get(':entryId/preview')
  @RequirePermissions(Q.preview)
  @QuarantineRateLimit('preview')
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Preview a quarantined message (sanitized, DLP-masked)',
    description:
      'JSON text only, never HTML: allow-listed headers, the decoded text part (else the HTML ' +
      'part converted to text: scripts, styles, frames, forms, SVG, images and comments ' +
      'dropped), read with a bounded Range GET (QUARANTINE_PREVIEW_MAX_BODY_BYTES; the raw EML ' +
      'is never parsed); links listed defanged and not clickable; attachments listed with their ' +
      'latest-round verdicts (never served here); DLP values masked (cards first 6 + last 4). ' +
      'The `preview` action and the audit row `quarantine.previewed` are committed before any ' +
      'part is read; a failure afterwards adds `quarantine.preview_failed`. A deleted entry ' +
      'whose objects were purged is `410 quarantine_content_purged`. QUARANTINE_PREVIEW_RATE_' +
      'PER_MINUTE per caller; `Cache-Control: no-store`.',
  })
  @ApiEntryId()
  @ApiOkResponse({ schema: zodToOpenApi(PreviewSchema), headers: NO_STORE_HEADER })
  @ApiErrors(400, 401, 403, 429)
  @ApiEntryNotFound()
  @ApiCodedError(410, 'The message content was purged', ['quarantine_content_purged'])
  @ApiConflicts(['quarantine_preview_unavailable'])
  preview(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('entryId', entryIdPipe) entryId: string,
    @Client() client: ClientContext,
  ): Promise<QuarantinePreview> {
    return this.previews.preview(principal, scope, entryId, client);
  }

  @Post(':entryId/download-grants')
  @RequirePermissions(Q.download)
  @UserOnly()
  @RequireMfa()
  @QuarantineRateLimit('download_grant')
  @HttpCode(HttpStatus.CREATED)
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Grant a single-use download of the EML or an attachment',
    description:
      'Not offered by default: the tenant setting `download.enabled` and `quarantine:download` ' +
      'are both required (`403 quarantine_download_disabled`). Fresh re-authorization: the ' +
      'caller’s password, and a TOTP code when MFA is enrolled; failures count toward the ' +
      'login lockout (`401 quarantine_reauth_failed`). Malware gating: refused with `409 ' +
      'quarantine_download_blocked` when the entry or message has a hard block, the latest ' +
      'verdict is malware or phishing, the attachment is not `clean` (or, for the EML, any ' +
      'attachment is not clean or any URL malicious). The token is bound to the organization, ' +
      'the user and the entry and valid QUARANTINE_DOWNLOAD_TOKEN_TTL_SECONDS. MFA-' +
      'authenticated users only; QUARANTINE_DOWNLOAD_GRANTS_PER_HOUR per user. Audited as ' +
      '`quarantine.download_granted` / `quarantine.download_refused`.',
  })
  @ApiEntryId()
  @ApiBody({ schema: zodToOpenApi(DownloadGrantBodySchema, { io: 'input' }) })
  @ApiCreatedResponse({
    schema: zodToOpenApi(DownloadGrantResponseSchema),
    headers: NO_STORE_HEADER,
  })
  @ApiErrors(400, 401, 403, 429)
  @ApiCodedError(401, 'Re-authorization failed', ['quarantine_reauth_failed'])
  @ApiForbiddenCodes(['quarantine_download_disabled'])
  @ApiEntryNotFound()
  @ApiConflicts(['quarantine_download_blocked', 'quarantine_state_conflict'])
  @ApiCodedError(410, 'The message content was purged', ['quarantine_content_purged'])
  @ApiInconsistent()
  grant(
    @CurrentUser() principal: UserPrincipal,
    @CurrentScope() scope: TenantScope,
    @Param('entryId', entryIdPipe) entryId: string,
    @Body(new ZodValidationPipe(DownloadGrantBodySchema)) body: DownloadGrantBody,
    @Client() client: ClientContext,
  ): Promise<DownloadGrantResponse> {
    return this.downloads.grant(principal, scope, entryId, body, client);
  }

  @Post(':entryId/release')
  @TransactionalIdempotency(QUARANTINE_OPERATIONS.release)
  @RequirePermissions(Q.release)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Release a held entry (re-validated)',
    description:
      'For a `held` entry: an advisory pre-check on replica facts (the latest completed scan ' +
      'round re-evaluated with the current published policy for this recipient, staleness of ' +
      'verdicts and signatures). Outcomes: stale verdicts on a rescannable message → `409 ' +
      'quarantine_rescan_required` (rescan with POST /messages/{messageId}/rescan); approval ' +
      'reasons (hard block, engine failure, DLP hold, current policy reject, review, …) → `202 ' +
      'approval_requested` (a release_approval request; a second authorized user decides); ' +
      'otherwise `202 queued` (the release executor re-validates authoritatively and delivers). ' +
      'Audited as `quarantine.release_requested` (refusals `quarantine.release_refused`). ' +
      'Requires the Idempotency-Key header.',
  })
  @ApiEntryId()
  @ApiBody({ schema: zodToOpenApi(ReleaseBodySchema, { io: 'input' }) })
  @ApiAcceptedResponse({ schema: zodToOpenApi(ReleaseOutcomeSchema) })
  @ApiErrors(400, 401, 403, 422)
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
      await this.releases.release({ principal, scope, entryId, key, body, client }),
    );
  }

  @Post(':entryId/request-release')
  @TransactionalIdempotency(QUARANTINE_OPERATIONS.requestRelease)
  @RequirePermissions(Q.requestRelease)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Request the release of a held entry',
    description:
      'Creates a `release_request` approval request (the pre-check’s approval reasons stored) ' +
      'and moves the entry to `pending_approval`; approvers are notified when ' +
      '`alerts.approvalRequests` is on. Audited as `quarantine.approval_requested`. Requires the ' +
      'Idempotency-Key header.',
  })
  @ApiEntryId()
  @ApiBody({ schema: zodToOpenApi(ReasonBodySchema, { io: 'input' }) })
  @ApiAcceptedResponse({ schema: zodToOpenApi(ReleaseOutcomeSchema) })
  @ApiErrors(400, 401, 403, 422)
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
      await this.releases.requestRelease({ principal, scope, entryId, key, body, client }),
    );
  }

  @Post(':entryId/reject')
  @TransactionalIdempotency(QUARANTINE_OPERATIONS.reject)
  @RequirePermissions(Q.reject)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Reject a quarantine entry',
    description:
      'A `held` or `pending_approval` entry → `rejected` (a pending request is cancelled), its ' +
      'recipient `discarded`; when no other entry of the message is live and no recipient is ' +
      'pending, deferred or delivered, the message moves to `rejected` (E17/E18). A sender ' +
      'notice is sent only for outbound/internal entries (`notifySender`, default ' +
      '`notices.senderOnReject`), never for inbound mail. Object disposal follows the delete ' +
      'rules (legal hold and retention keep the object). Audited as `quarantine.rejected`. ' +
      'Requires the Idempotency-Key header.',
  })
  @ApiEntryId()
  @ApiBody({ schema: zodToOpenApi(RejectBodySchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(EntryStateResponseSchema) })
  @ApiErrors(400, 401, 403, 422)
  @ApiEntryNotFound()
  @ApiConflicts(ENTRY_WRITE_CONFLICTS)
  @ApiInconsistent()
  async reject(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('entryId', entryIdPipe) entryId: string,
    @IdempotencyKey() key: string,
    @Body(new ZodValidationPipe(RejectBodySchema)) body: RejectBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<EntryStateResponse> {
    return reply(
      res,
      await this.disposition.reject({ principal, scope, entryId, key, body, client }),
    );
  }

  @Post(':entryId/delete')
  @TransactionalIdempotency(QUARANTINE_OPERATIONS.delete)
  @RequirePermissions(Q.delete)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Delete a quarantine entry (retention and legal hold apply)',
    description:
      'A `held`, `pending_approval`, `rejected` or `expired` entry → `deleted`. Refused with ' +
      '`409 quarantine_legal_hold` while an active legal hold matches the message (criteria ' +
      'this release cannot read match everything) and `409 quarantine_retention_active` while ' +
      'archive retention applies. Otherwise the object purge is scheduled: purged by the ' +
      'quarantine sweeper when every entry of the message is final and not released and no ' +
      'recipient still needs it, else retained (`archive_pending`, `shared`). Audited as ' +
      '`quarantine.deleted` / `quarantine.delete_refused`. Requires the Idempotency-Key header.',
  })
  @ApiEntryId()
  @ApiBody({ schema: zodToOpenApi(DeleteBodySchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(EntryStateResponseSchema) })
  @ApiErrors(400, 401, 403, 422)
  @ApiEntryNotFound()
  @ApiConflicts([...ENTRY_WRITE_CONFLICTS, 'quarantine_legal_hold', 'quarantine_retention_active'])
  @ApiInconsistent()
  async delete(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('entryId', entryIdPipe) entryId: string,
    @IdempotencyKey() key: string,
    @Body(new ZodValidationPipe(DeleteBodySchema)) body: DeleteBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<EntryStateResponse> {
    return reply(
      res,
      await this.disposition.delete({ principal, scope, entryId, key, body, client }),
    );
  }
}
