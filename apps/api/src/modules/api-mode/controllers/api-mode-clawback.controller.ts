import {
  Body,
  Controller,
  Get,
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
  RequirePermissions,
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
import { ApiListErrors, ApiListQuery } from '../../messages/api-docs';
import {
  ApiBadId,
  ApiDetectionNotFound,
  ApiKeyedErrors,
  ApiModeConflicts,
  ApiModeForbidden,
  ApiModeIdempotency,
  ApiModeResponse,
  ApiModeUnavailable,
  ApiModeUnprocessable,
  KEYED_RULE,
} from '../api-docs';
import {
  API_MODE_OPERATIONS,
  API_MODE_PERMISSIONS as P,
  QUARANTINE_RELEASE_PERMISSION,
} from '../api-mode.constants';
import { API_MODE_ERROR_CODES as C } from '../api-mode.errors';
import {
  CLAWBACK_EXAMPLES as X,
  CLAWBACK_LIST_PARAMETERS,
  CLAWBACK_TARGET_PARAMETERS,
  ClawbackCreatedSchema,
  type ClawbackCreatedView,
  ClawbackDetailSchema,
  type ClawbackDetailView,
  type ClawbackListQuery,
  ClawbackListQuerySchema,
  type ClawbackPage,
  ClawbackPageSchema,
  ClawbackSchema,
  type ClawbackTargetListQuery,
  ClawbackTargetListQuerySchema,
  type ClawbackTargetPage,
  ClawbackTargetPageSchema,
  type ClawbackView,
  CreateClawbackBodySchema,
  DecisionBodySchema,
  ReasonBodySchema,
  SubmitClawbackBodySchema,
  SubmitClawbackResponseSchema,
  type SubmitClawbackResponseView,
} from '../dto/api-mode-clawback.schemas';
import { ClawbackService } from '../services/clawback.service';

const ApiClawbackIdParam = (): MethodDecorator =>
  ApiParam({ name: 'clawbackId', description: 'Clawback public id (UUID)', format: 'uuid' });

const ApiClawbackNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown clawback, or one of another organization', [C.clawbackNotFound]);

const STATE_CONFLICT_DETAILS = {
  status: { type: 'string' },
  currentRowVersion: { type: 'integer' },
} as const;

const APPROVAL_RULES =
  ' The approver is a user (API keys: `403 api_mode_purge_approval_forbidden` reason ' +
  '`api_key`) holding `remediation:purge` who is neither the requester nor the submitter ' +
  '(reason `requester`); the request must be pending and not expired (`409 ' +
  'api_mode_purge_approval_not_pending`, reason `not_pending` or `expired`). CAS: ' +
  '`expectedRowVersion` (`409 api_mode_clawback_state_conflict` with `currentRowVersion`).';

const NEVER_CONTENT =
  ' Never returns message content: hashes are truncated, sender addresses and subject keys are ' +
  'untrusted data.';

/**
 * API-mode clawbacks: search and purge (step API-3 C2-C7, C14 #1-#10,
 * docs/plan/steps/37-api-mode-clawback-reporting.md; ADR-0103). An admin search (criteria or a
 * seed detection with its campaign expansion) is materialized by the mailbox-worker into a frozen
 * hit list; submit purges it through the API-2 remediation actions (second approver above the
 * organization's threshold of distinct mailboxes; hard delete portal-only with the platform
 * setting); cancel and bulk restore. Reads need `remediation:read`; every write
 * `remediation:purge` (restore also `quarantine:release`). Translation only: the service owns the
 * rules, the rows and the audit.
 */
@ApiTags('api-mode')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'api-mode', version: '1' })
export class ApiModeClawbackController {
  constructor(private readonly clawbacks: ClawbackService) {}

  @Post('clawbacks')
  @RequirePermissions(P.purge)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiModeIdempotency(API_MODE_OPERATIONS.clawbackCreate)
  @ApiOperation({
    summary: 'Search API-mode mailbox copies (create a clawback)',
    description:
      '`{ criteria: { messageId?, attachmentSha256?, url?, urlSha256?, sender?, subject?, from, ' +
      'to }, seedDetectionId?, expand?: { attachments?, urls?, senderSubjectHours? }, ' +
      'directions?, reason }`. Searches the recorded copies of your organization (never a live ' +
      'provider search; report mailboxes excluded): keys combine with OR; the Message-ID is ' +
      'hashed as the dedupe hash, the subject normalized to the explorer’s subject key (sender + ' +
      'subject together, window ≤ 7 days unless from a campaign seed), a URL reduced to its ' +
      'identity hash; the window spans at most 31 days within the 6-month copy retention. A ' +
      'seed detection alone searches its Message-ID; `expand` adds its attachment and URL ' +
      'hashes and its sender + subject within ± `senderSubjectHours` (a campaign). The ' +
      'mailbox-worker materializes the hit list (`searching` → `ready`, `no_match` or ' +
      '`too_broad` above 20 000 copies); preview it with the targets list, then submit. Invalid ' +
      'criteria → `422 api_mode_clawback_criteria_invalid` (`codes`). Audited ' +
      '`api_mode.clawback_created` (key counts, never the keys). Needs `remediation:purge`.' +
      KEYED_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(CreateClawbackBodySchema, { io: 'input' }),
    examples: { messageId: { value: X.create }, campaign: { value: X.createSeeded } },
  })
  @ApiModeResponse(202, ClawbackCreatedSchema, X.created, 'Searching', true)
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiDetectionNotFound()
  @ApiModeConflicts([], 'The same key is still running', true)
  @ApiModeUnprocessable(
    [C.clawbackCriteriaInvalid],
    '`api_mode_clawback_criteria_invalid` (`codes`)',
    true,
    { codes: { type: 'string' } },
  )
  @ApiModeUnavailable()
  async create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ClawbackCreatedView> {
    const result = await this.clawbacks.create(
      principal,
      scope,
      { idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get('clawbacks')
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List API-mode clawbacks',
    description:
      'Clawbacks (automatic late-verdict and threat-intelligence signals, campaigns, report and ' +
      'admin searches), newest first: trigger, status, decision mode and action, target and ' +
      'mailbox counts, the approval block (required, status, reasons, expiry) and the restore ' +
      'block. Filters `status`, `trigger`, `approvalStatus`, `from`/`to` (at most 93 days; ' +
      'default the last 30). v1 list (`api_clawbacks`). From the read replica. Needs ' +
      '`remediation:read`.',
  })
  @ApiListQuery(ClawbackListQuerySchema, CLAWBACK_LIST_PARAMETERS)
  @ApiModeResponse(200, ClawbackPageSchema, X.clawbackPage, 'One page of clawbacks')
  @ApiListErrors()
  @ApiModeForbidden()
  @ApiModeUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ClawbackListQuerySchema)) query: ClawbackListQuery,
  ): Promise<ClawbackPage> {
    return this.clawbacks.list(principal, scope, query);
  }

  @Get('clawbacks/:clawbackId')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get an API-mode clawback',
    description:
      'One clawback with its criteria (hashes truncated; the sender and subject key of a sender ' +
      '+ subject search), the signal facts the policy decides on, the counts, the approval ' +
      '(requester, submitter, the second person, reasons, expiry), the restore block and hints ' +
      '(`canSubmit`, `canApprove`, `canCancel`, `canRestore` for the caller). Needs ' +
      '`remediation:read`.' +
      NEVER_CONTENT,
  })
  @ApiClawbackIdParam()
  @ApiModeResponse(200, ClawbackDetailSchema, X.clawbackDetail, 'The clawback')
  @ApiBadId()
  @ApiModeForbidden()
  @ApiClawbackNotFound()
  @ApiModeUnavailable()
  detail(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('clawbackId') clawbackId: string,
  ): Promise<ClawbackDetailView> {
    return this.clawbacks.detail(principal, scope, clawbackId);
  }

  @Get('clawbacks/:clawbackId/targets')
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the targets of an API-mode clawback',
    description:
      'The frozen hit list (one row per matched copy, in materialization order): mailbox, ' +
      'detection, receipt time, the keys that matched, the copy’s remediation state, the target ' +
      'status, planned action, skip or result code, the mailbox action and the restore state. ' +
      'Without `remediation:purge` the mailbox address is masked and the header From and ' +
      'subject are withheld (`null`); with it they are shown as untrusted mail data. Filters ' +
      '`status`, `restoreStatus`, `mailboxId`. v1 list bound to the clawback. Needs ' +
      '`remediation:read`.',
  })
  @ApiClawbackIdParam()
  @ApiListQuery(ClawbackTargetListQuerySchema, CLAWBACK_TARGET_PARAMETERS)
  @ApiModeResponse(200, ClawbackTargetPageSchema, X.targetPage, 'One page of targets')
  @ApiListErrors()
  @ApiModeForbidden()
  @ApiClawbackNotFound()
  @ApiModeUnavailable()
  targets(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('clawbackId') clawbackId: string,
    @Query(new ZodValidationPipe(ClawbackTargetListQuerySchema)) query: ClawbackTargetListQuery,
  ): Promise<ClawbackTargetPage> {
    return this.clawbacks.targets(principal, scope, clawbackId, query);
  }

  @Post('clawbacks/:clawbackId/submit')
  @RequirePermissions(P.purge)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiModeIdempotency(API_MODE_OPERATIONS.clawbackSubmit)
  @ApiOperation({
    summary: 'Submit an API-mode clawback (purge)',
    description:
      '`{ mode: policy, verdict?, level? } | { mode: explicit, action: move_quarantine | ' +
      'move_junk | soft_delete }` with `reason` and `expectedRowVersion`, from `ready` or ' +
      '`review_required`. `policy` re-decides every target through your remediation policy with ' +
      'the chosen facts (detect-only and pause respected); `explicit` applies the action. A ' +
      'purge whose eligible targets span more than the organization’s approval threshold of ' +
      'distinct mailboxes (default 50), or an automatic clawback held at its cap, waits for a ' +
      'second approver (`pending_approval`, expires after 72 h; alert `api_mode_purge_approval`); ' +
      'otherwise it is `queued` and the mailbox-worker queues the remediation actions. A wrong ' +
      'state or version → `409 api_mode_clawback_state_conflict` (`status`, `currentRowVersion`). ' +
      'Audited `api_mode.clawback_submitted` (+ `api_mode.clawback_approval_requested`). Needs ' +
      '`remediation:purge`.' +
      KEYED_RULE,
  })
  @ApiClawbackIdParam()
  @ApiBody({
    schema: zodToOpenApi(SubmitClawbackBodySchema, { io: 'input' }),
    examples: { policy: { value: X.submitPolicy }, explicit: { value: X.submitExplicit } },
  })
  @ApiModeResponse(
    202,
    SubmitClawbackResponseSchema,
    X.submitted,
    'Queued or pending approval',
    true,
  )
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiClawbackNotFound()
  @ApiModeConflicts(
    [C.clawbackStateConflict],
    '`api_mode_clawback_state_conflict` (`status`, `currentRowVersion`)',
    true,
    STATE_CONFLICT_DETAILS,
  )
  @ApiModeUnavailable()
  async submit(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('clawbackId') clawbackId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<SubmitClawbackResponseView> {
    const result = await this.clawbacks.submit(
      principal,
      scope,
      { id: clawbackId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post('clawbacks/:clawbackId/submit-hard-delete')
  @RequirePermissions(P.purge)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiModeIdempotency(API_MODE_OPERATIONS.clawbackSubmitHardDelete)
  @ApiOperation({
    summary: 'Submit an API-mode clawback as a hard delete (portal only)',
    description:
      '`{ reason, expectedRowVersion }`, from `ready` or `review_required`. Permanently deletes ' +
      'the eligible copies (irreversible on Microsoft 365; Trash on Google Workspace). Only when ' +
      'the platform setting allows hard delete (else `422 api_mode_hard_delete_disabled`) and ' +
      'always with a second approver (`pending_approval`, reason `hard_delete`; alert severity ' +
      '`high`). Portal only: never an assistant tool. Audited `api_mode.clawback_submitted` and ' +
      '`api_mode.clawback_approval_requested`. Needs `remediation:purge`.' +
      KEYED_RULE,
  })
  @ApiClawbackIdParam()
  @ApiBody({
    schema: zodToOpenApi(DecisionBodySchema, { io: 'input' }),
    examples: { hardDelete: { value: X.hardDelete } },
  })
  @ApiModeResponse(
    202,
    SubmitClawbackResponseSchema,
    { ...X.submitted, approvalReasons: ['hard_delete'] },
    'Pending approval',
    true,
  )
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiClawbackNotFound()
  @ApiModeConflicts(
    [C.clawbackStateConflict],
    '`api_mode_clawback_state_conflict` (`status`, `currentRowVersion`)',
    true,
    STATE_CONFLICT_DETAILS,
  )
  @ApiModeUnprocessable([C.hardDeleteDisabled], '`api_mode_hard_delete_disabled`', true)
  @ApiModeUnavailable()
  async submitHardDelete(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('clawbackId') clawbackId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<SubmitClawbackResponseView> {
    const result = await this.clawbacks.submitHardDelete(
      principal,
      scope,
      { id: clawbackId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post('clawbacks/:clawbackId/approve')
  @RequirePermissions(P.purge)
  @HttpCode(HttpStatus.OK)
  @ApiModeIdempotency(API_MODE_OPERATIONS.clawbackApprove)
  @ApiOperation({
    summary: 'Approve a pending API-mode purge',
    description:
      '`{ reason, expectedRowVersion }`: the second person approves; the clawback is `queued`.' +
      APPROVAL_RULES +
      ' Stores the approver and the hash of their permission set. Audited ' +
      '`api_mode.clawback_approved`. Needs `remediation:purge`.' +
      KEYED_RULE,
  })
  @ApiClawbackIdParam()
  @ApiBody({
    schema: zodToOpenApi(DecisionBodySchema, { io: 'input' }),
    examples: { approve: { value: X.decision } },
  })
  @ApiModeResponse(200, ClawbackSchema, X.approved, 'Approved (queued)', true)
  @ApiKeyedErrors()
  @ApiModeForbidden([C.purgeApprovalForbidden], '`api_mode_purge_approval_forbidden` (`reason`)')
  @ApiClawbackNotFound()
  @ApiModeConflicts(
    [C.purgeApprovalNotPending, C.clawbackStateConflict],
    '`api_mode_purge_approval_not_pending` (`reason`), `api_mode_clawback_state_conflict`',
    true,
    { ...STATE_CONFLICT_DETAILS, reason: { type: 'string' } },
  )
  @ApiModeUnavailable()
  async approve(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('clawbackId') clawbackId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ClawbackView> {
    const result = await this.clawbacks.approve(
      principal,
      scope,
      { id: clawbackId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post('clawbacks/:clawbackId/deny')
  @RequirePermissions(P.purge)
  @HttpCode(HttpStatus.OK)
  @ApiModeIdempotency(API_MODE_OPERATIONS.clawbackDeny)
  @ApiOperation({
    summary: 'Deny a pending API-mode purge',
    description:
      '`{ reason, expectedRowVersion }`: the second person denies; the clawback is `denied` and ' +
      'nothing is removed.' +
      APPROVAL_RULES +
      ' Audited `api_mode.clawback_denied`. Needs `remediation:purge`.' +
      KEYED_RULE,
  })
  @ApiClawbackIdParam()
  @ApiBody({
    schema: zodToOpenApi(DecisionBodySchema, { io: 'input' }),
    examples: { deny: { value: X.decision } },
  })
  @ApiModeResponse(
    200,
    ClawbackSchema,
    { ...X.clawback, status: 'denied', approval: { ...X.clawback.approval, status: 'denied' } },
    'Denied',
    true,
  )
  @ApiKeyedErrors()
  @ApiModeForbidden([C.purgeApprovalForbidden], '`api_mode_purge_approval_forbidden` (`reason`)')
  @ApiClawbackNotFound()
  @ApiModeConflicts(
    [C.purgeApprovalNotPending, C.clawbackStateConflict],
    '`api_mode_purge_approval_not_pending` (`reason`), `api_mode_clawback_state_conflict`',
    true,
    { ...STATE_CONFLICT_DETAILS, reason: { type: 'string' } },
  )
  @ApiModeUnavailable()
  async deny(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('clawbackId') clawbackId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ClawbackView> {
    const result = await this.clawbacks.deny(
      principal,
      scope,
      { id: clawbackId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post('clawbacks/:clawbackId/cancel')
  @RequirePermissions(P.purge)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiModeIdempotency(API_MODE_OPERATIONS.clawbackCancel)
  @ApiOperation({
    summary: 'Cancel an API-mode clawback',
    description:
      '`{ reason }`. `ready`, `review_required` and `pending_approval` are cancelled at once ' +
      '(a pending approval request is cancelled with it); `queued` and `running` clawbacks get ' +
      'a cancel request: the mailbox-worker cancels every pending mailbox action of the ' +
      'clawback and lets running ones finish (a repeated cancel changes nothing). Anything else ' +
      '→ `409 api_mode_clawback_not_cancellable` (`status`). Audited ' +
      '`api_mode.clawback_cancelled`. Needs `remediation:purge`.' +
      KEYED_RULE,
  })
  @ApiClawbackIdParam()
  @ApiBody({
    schema: zodToOpenApi(ReasonBodySchema, { io: 'input' }),
    examples: { cancel: { value: X.cancel } },
  })
  @ApiModeResponse(
    202,
    ClawbackSchema,
    {
      ...X.clawback,
      status: 'cancelled',
      approval: { ...X.clawback.approval, status: 'cancelled' },
    },
    'Cancelled or cancel requested',
    true,
  )
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiClawbackNotFound()
  @ApiModeConflicts(
    [C.clawbackNotCancellable, C.clawbackStateConflict],
    '`api_mode_clawback_not_cancellable` (`status`)',
    true,
    STATE_CONFLICT_DETAILS,
  )
  @ApiModeUnavailable()
  async cancel(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('clawbackId') clawbackId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ClawbackView> {
    const result = await this.clawbacks.cancel(
      principal,
      scope,
      { id: clawbackId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post('clawbacks/:clawbackId/restore')
  @RequirePermissions(P.purge, QUARANTINE_RELEASE_PERMISSION)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiModeIdempotency(API_MODE_OPERATIONS.clawbackRestore)
  @ApiOperation({
    summary: 'Restore an API-mode clawback (bulk restore)',
    description:
      '`{ reason }` on a `completed`, `completed_with_errors` or `cancelled` clawback with ' +
      'succeeded targets: the mailbox-worker restores them where the provider allows it (a tag ' +
      'is removed; quarantine-folder, Junk and soft-delete moves go back to the Inbox through ' +
      'the quarantine release check of their mailbox entry; entries needing an approval and hard ' +
      'deletes are skipped with a code). Anything else → `409 api_mode_clawback_not_restorable` ' +
      '(`status`, `restoreStatus`). Audited `api_mode.clawback_restore_requested`. Needs ' +
      '`remediation:purge` and `quarantine:release`.' +
      KEYED_RULE,
  })
  @ApiClawbackIdParam()
  @ApiBody({
    schema: zodToOpenApi(ReasonBodySchema, { io: 'input' }),
    examples: { restore: { value: X.restore } },
  })
  @ApiModeResponse(
    202,
    ClawbackSchema,
    {
      ...X.clawback,
      status: 'completed',
      restore: { ...X.clawback.restore, status: 'requested' },
    },
    'Restore requested',
    true,
  )
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiClawbackNotFound()
  @ApiModeConflicts(
    [C.clawbackNotRestorable, C.clawbackStateConflict],
    '`api_mode_clawback_not_restorable` (`status`, `restoreStatus`)',
    true,
    { status: { type: 'string' }, restoreStatus: { type: 'string' } },
  )
  @ApiModeUnavailable()
  async restore(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('clawbackId') clawbackId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ClawbackView> {
    const result = await this.clawbacks.restore(
      principal,
      scope,
      { id: clawbackId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}
