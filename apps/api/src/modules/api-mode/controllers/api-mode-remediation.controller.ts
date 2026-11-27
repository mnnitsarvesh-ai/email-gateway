import {
  Body,
  Controller,
  Delete,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Put,
  Query,
  Res,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiNoContentResponse,
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
  ApiDetectionIdParam,
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
import { API_MODE_OPERATIONS, API_MODE_PERMISSIONS as P } from '../api-mode.constants';
import { API_MODE_ERROR_CODES as C } from '../api-mode.errors';
import {
  PutRemediationPolicyBodySchema,
  REMEDIATION_EXAMPLES as X,
  REMEDIATION_LIST_PARAMETERS,
  RemediateBodySchema,
  RemediationDetailSchema,
  type RemediationDetailView,
  type RemediationListQuery,
  RemediationListQuerySchema,
  type RemediationPage,
  RemediationPageSchema,
  RemediationPolicyChangeSchema,
  type RemediationPolicyChangeView,
  RemediationPolicyViewSchema,
  type RemediationPolicyView,
  RemediationRequestSchema,
  type RemediationRequestView,
  RemediationSchema,
  type RemediationView,
  RestoreBodySchema,
  RestoreResponseSchema,
  type RestoreResponseView,
} from '../dto/api-mode-remediation.schemas';
import { RemediationActionsService } from '../services/remediation-actions.service';
import { RemediationPolicyService } from '../services/remediation-policy.service';

const ApiRemediationIdParam = (): MethodDecorator =>
  ApiParam({
    name: 'remediationId',
    description: 'Remediation (mailbox action) public id (UUID)',
    format: 'uuid',
  });

const ApiDomainIdParam = (): MethodDecorator =>
  ApiParam({ name: 'domainId', description: 'Domain public id (UUID)', format: 'uuid' });

const ApiRemediationNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown remediation, or one of another organization', [
    C.remediationNotFound,
  ]);

const ApiDomainNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown or deleted domain, or one of another organization', [
    C.domainNotFound,
  ]);

const POLICY_RULES =
  ' The document is `api-remediation-policy/1` (strict; 1-16 rules, first match wins; a rule ' +
  'matches when the verdict is listed and every present bound holds: `minLevel`/`maxLevel`, ' +
  '`hardBlock`, `minScore`); invalid → `400 validation_failed` with the document paths. A ' +
  '`hard_delete` rule while the platform setting is off → `422 api_mode_hard_delete_disabled` ' +
  '(`ruleIds`). CAS: `expectedRowVersion` is the version read (null when no row exists: the ' +
  'PUT creates it); a mismatch → `409 api_mode_remediation_policy_conflict` with ' +
  '`currentRowVersion`. Audited `api_mode.remediation_policy_updated` (scope, from/to mode and ' +
  'SHA-256, reason). Needs `remediation:write`.';

const NEVER_PROVIDER_IDS =
  ' Never returns provider message ids (`providerRefs` shows the container and the counts only) ' +
  'or message content.';

/**
 * API-mode remediation (step API-2 R2, R12, R13, docs/plan/steps/36-api-mode-remediation.md;
 * ADR-0101, ADR-0102): the remediation policy of the organization with per-domain overrides, the
 * remediation history, and the manual requests — retry of a failed action, remediate a
 * detection, restore it (a quarantined copy is restored through the quarantine release). Reads
 * need `remediation:read`, writes `remediation:write`. Translation only: the services own the
 * rules, the action rows and the audit rows.
 */
@ApiTags('api-mode')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'api-mode', version: '1' })
export class ApiModeRemediationController {
  constructor(
    private readonly policies: RemediationPolicyService,
    private readonly remediations: RemediationActionsService,
  ) {}

  @Get('remediation-policy')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get the API-mode remediation policy',
    description:
      'The organization policy (`source: platform_default` with the P1 default when no row ' +
      'exists: high-confidence malware and phishing to the quarantine folder, other malware, ' +
      'phishing, suspicious and BEC tagged, nothing hard-deleted), the per-domain overrides, the ' +
      'presets (P1, detect-only start, strict) and whether the platform allows hard delete. ' +
      'Needs `remediation:read`.',
  })
  @ApiModeResponse(200, RemediationPolicyViewSchema, X.policy, 'The policy')
  @ApiModeForbidden()
  @ApiModeUnavailable()
  getPolicy(@CurrentScope() scope: TenantScope): Promise<RemediationPolicyView> {
    return this.policies.get(scope);
  }

  @Put('remediation-policy')
  @RequirePermissions(P.write)
  @HttpCode(HttpStatus.OK)
  @ApiModeIdempotency(API_MODE_OPERATIONS.policyPut)
  @ApiOperation({
    summary: 'Set the organization’s API-mode remediation policy',
    description:
      '`{ mode: detect_only | enforce, document, reason, expectedRowVersion }`. `detect_only` ' +
      'records what would have happened (simulated) without touching mailboxes.' +
      POLICY_RULES +
      KEYED_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(PutRemediationPolicyBodySchema, { io: 'input' }),
    examples: { detectOnlyStart: { value: X.policyPut } },
  })
  @ApiModeResponse(200, RemediationPolicyChangeSchema, X.policyChange, 'The stored policy', true)
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiModeConflicts(
    [C.remediationPolicyConflict],
    '`api_mode_remediation_policy_conflict` (`currentRowVersion`)',
    true,
    { currentRowVersion: { type: 'integer' } },
  )
  @ApiModeUnprocessable(
    [C.hardDeleteDisabled],
    '`api_mode_hard_delete_disabled` (`ruleIds`)',
    true,
    {
      ruleIds: { type: 'string' },
    },
  )
  @ApiModeUnavailable()
  async putPolicy(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RemediationPolicyChangeView> {
    const result = await this.policies.putOrganization(
      principal,
      scope,
      { idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Put('remediation-policy/domains/:domainId')
  @RequirePermissions(P.write)
  @HttpCode(HttpStatus.OK)
  @ApiModeIdempotency(API_MODE_OPERATIONS.domainPolicyPut)
  @ApiOperation({
    summary: 'Set a domain’s API-mode remediation policy override',
    description:
      'The same body as the organization policy; the override applies to the mailboxes of the ' +
      'domain (one of your organization’s non-deleted domains, else `404 domain_not_found`).' +
      POLICY_RULES +
      KEYED_RULE,
  })
  @ApiDomainIdParam()
  @ApiBody({
    schema: zodToOpenApi(PutRemediationPolicyBodySchema, { io: 'input' }),
    examples: { domainOverride: { value: { ...X.policyPut, mode: 'enforce' } } },
  })
  @ApiModeResponse(
    200,
    RemediationPolicyChangeSchema,
    X.domainPolicyChange,
    'The stored override',
    true,
  )
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiDomainNotFound()
  @ApiModeConflicts(
    [C.remediationPolicyConflict],
    '`api_mode_remediation_policy_conflict` (`currentRowVersion`)',
    true,
    { currentRowVersion: { type: 'integer' } },
  )
  @ApiModeUnprocessable(
    [C.hardDeleteDisabled],
    '`api_mode_hard_delete_disabled` (`ruleIds`)',
    true,
    {
      ruleIds: { type: 'string' },
    },
  )
  @ApiModeUnavailable()
  async putDomainPolicy(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('domainId') domainId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RemediationPolicyChangeView> {
    const result = await this.policies.putDomain(
      principal,
      scope,
      { domainId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Delete('remediation-policy/domains/:domainId')
  @RequirePermissions(P.write)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiModeIdempotency(API_MODE_OPERATIONS.domainPolicyDelete)
  @ApiOperation({
    summary: 'Remove a domain’s API-mode remediation policy override',
    description:
      'The domain inherits the organization policy again. `204` (also when it had no override: ' +
      'nothing changes and no audit row is written). Audited ' +
      '`api_mode.remediation_policy_updated` (`to: null`). Needs `remediation:write`.' +
      KEYED_RULE,
  })
  @ApiDomainIdParam()
  @ApiNoContentResponse({
    description: 'Removed (or the stored response of an earlier identical request replayed)',
    headers: {
      [IDEMPOTENCY_REPLAYED_HEADER]: {
        description: '`true` when this is the stored response of an earlier identical request',
        schema: { type: 'string', enum: ['true'] },
      },
    },
  })
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiDomainNotFound()
  @ApiModeConflicts([], 'The same key is still running', true)
  @ApiModeUnavailable()
  async deleteDomainPolicy(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('domainId') domainId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    const result = await this.policies.deleteDomain(
      principal,
      scope,
      { domainId, idempotencyKey },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
  }

  @Get('remediations')
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List API-mode remediations',
    description:
      'Mailbox actions (remediations and reversals), newest first: action, trigger (`policy`, ' +
      '`admin`, `release`, `end_user`, `system`), status, reason or failure code, attempts, the ' +
      'mailbox, connection, detection and quarantine entry, creation and completion times and ' +
      'the latency. Filters `status`, `action`, `trigger`, `mailboxId`, `connectionId`, ' +
      '`detectionId`, `from`/`to` (at most 31 days; default the last 7). v1 list ' +
      '(`api_remediation_actions`). From the read replica. Needs `remediation:read`.' +
      NEVER_PROVIDER_IDS,
  })
  @ApiListQuery(RemediationListQuerySchema, REMEDIATION_LIST_PARAMETERS)
  @ApiModeResponse(200, RemediationPageSchema, X.remediationPage, 'One page of remediations')
  @ApiListErrors()
  @ApiModeForbidden()
  @ApiModeUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(RemediationListQuerySchema)) query: RemediationListQuery,
  ): Promise<RemediationPage> {
    return this.remediations.list(principal, scope, query);
  }

  @Get('remediations/:remediationId')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get an API-mode remediation',
    description:
      'One mailbox action with its decision record (`api-remediation-decision/1`: policy scope, ' +
      'id, version and SHA-256, mode, rule, the verdict inputs; or `{ requestedAction, reason }` ' +
      'of a manual request), the requester, the reversal links and the quarantine release of a ' +
      'release restore. Needs `remediation:read`.' +
      NEVER_PROVIDER_IDS,
  })
  @ApiRemediationIdParam()
  @ApiModeResponse(200, RemediationDetailSchema, X.remediationDetail, 'The remediation')
  @ApiBadId()
  @ApiModeForbidden()
  @ApiRemediationNotFound()
  @ApiModeUnavailable()
  detail(
    @CurrentScope() scope: TenantScope,
    @Param('remediationId') remediationId: string,
  ): Promise<RemediationDetailView> {
    return this.remediations.detail(scope, remediationId);
  }

  @Post('remediations/:remediationId/retry')
  @RequirePermissions(P.write)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiModeIdempotency(API_MODE_OPERATIONS.remediationRetry)
  @ApiOperation({
    summary: 'Retry a failed API-mode remediation',
    description:
      'A `failed` action goes back to `pending` (due now, attempts reset); anything else → `409 ' +
      'api_mode_remediation_not_retryable` (`cause`: its status, or `use_quarantine_release` ' +
      'for the restore of a quarantine entry, which is released again through the quarantine, ' +
      'or `stale_generation` for an action of an older remediation generation: the detection ' +
      'was restored since). ' +
      'Another queued or running action of the same detection → `409 ' +
      'api_mode_remediation_in_progress`. Audited `api_mode.remediation_retry_requested`. Needs ' +
      '`remediation:write`.' +
      KEYED_RULE,
  })
  @ApiRemediationIdParam()
  @ApiModeResponse(202, RemediationSchema, X.retried, 'Queued again', true)
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiRemediationNotFound()
  @ApiModeConflicts(
    [C.remediationNotRetryable, C.remediationInProgress],
    '`api_mode_remediation_not_retryable` (`cause`), `api_mode_remediation_in_progress`',
    true,
    { cause: { type: 'string' } },
  )
  @ApiModeUnavailable()
  async retry(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('remediationId') remediationId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RemediationView> {
    const result = await this.remediations.retry(
      principal,
      scope,
      { id: remediationId, idempotencyKey },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post('detections/:detectionId/remediate')
  @RequirePermissions(P.write)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiModeIdempotency(API_MODE_OPERATIONS.remediate)
  @ApiOperation({
    summary: 'Remediate an API-mode detection',
    description:
      '`{ action: move_quarantine | move_junk | tag | soft_delete, reason }` queues the mailbox ' +
      'action for the mailbox-worker (`pending`, executed within seconds; a quarantine-folder, ' +
      'Junk or soft-delete move creates a mailbox-located quarantine entry). Any verdict (an ' +
      'admin decision; also hybrid copies the inline path already decided); the copy must be ' +
      '`scanned` or `scan_failed` (`409 api_mode_detection_not_remediable`), the mailbox-access ' +
      'grant active (`409 api_mode_mailbox_access_required`), no action of the detection queued ' +
      'or running (`409 api_mode_remediation_in_progress`) and the action not already in effect ' +
      '(`409 api_mode_remediation_already_applied`). `hard_delete` is never manual (`422 ' +
      'api_mode_hard_delete_not_manual`). Audited `api_mode.remediation_requested`. Needs ' +
      '`remediation:write`.' +
      KEYED_RULE,
  })
  @ApiDetectionIdParam()
  @ApiBody({
    schema: zodToOpenApi(RemediateBodySchema, { io: 'input' }),
    examples: { quarantine: { value: X.remediate } },
  })
  @ApiModeResponse(202, RemediationRequestSchema, X.remediationRequest, 'Queued', true)
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiDetectionNotFound()
  @ApiModeConflicts(
    [
      C.detectionNotRemediable,
      C.mailboxAccessRequired,
      C.remediationInProgress,
      C.remediationAlreadyApplied,
    ],
    '`api_mode_detection_not_remediable`, `api_mode_mailbox_access_required`, ' +
      '`api_mode_remediation_in_progress`, `api_mode_remediation_already_applied`',
    true,
    { status: { type: 'string' }, action: { type: 'string' } },
  )
  @ApiModeUnprocessable([C.hardDeleteNotManual], '`api_mode_hard_delete_not_manual`', true)
  @ApiModeUnavailable()
  async remediate(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('detectionId') detectionId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RemediationRequestView> {
    const result = await this.remediations.remediate(
      principal,
      scope,
      { id: detectionId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post('detections/:detectionId/restore')
  @RequirePermissions(P.write)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiModeIdempotency(API_MODE_OPERATIONS.restore)
  @ApiOperation({
    summary: 'Restore a remediated API-mode detection',
    description:
      '`{ reason }`. A tag is removed (`via: mailbox_action`, a `remove_tag` action). A ' +
      'quarantine-folder, Junk or soft-delete remediation is restored to the Inbox through the ' +
      'quarantine release of its mailbox-located entry (`via: quarantine_release`; the caller ' +
      'also needs `quarantine:release`, else `403 quarantine_permission_required`; the ' +
      'quarantine’s rules apply: a hard block needs a second approver (`outcome: ' +
      'approval_requested`) or is refused by tenant setting, and its codes are returned). A hard ' +
      'delete cannot be undone (`409 api_mode_restore_not_possible`); nothing in effect → `409 ' +
      'api_mode_nothing_to_restore`. Audited `api_mode.restore_requested` (plus the quarantine ' +
      'audit rows of a release). Needs `remediation:write`.' +
      KEYED_RULE,
  })
  @ApiDetectionIdParam()
  @ApiBody({
    schema: zodToOpenApi(RestoreBodySchema, { io: 'input' }),
    examples: { restore: { value: X.restore } },
  })
  @ApiModeResponse(
    202,
    RestoreResponseSchema,
    X.restoreResponse,
    'Queued or approval requested',
    true,
  )
  @ApiKeyedErrors()
  @ApiModeForbidden([C.quarantinePermissionRequired], '`quarantine_permission_required`')
  @ApiDetectionNotFound()
  @ApiModeConflicts(
    [
      C.nothingToRestore,
      C.restoreNotPossible,
      C.remediationInProgress,
      'quarantine_state_conflict',
      'quarantine_version_conflict',
      'quarantine_hard_block_release_disabled',
    ],
    '`api_mode_nothing_to_restore`, `api_mode_restore_not_possible` (`cause`), ' +
      '`api_mode_remediation_in_progress`, the quarantine state conflicts',
    true,
    { cause: { type: 'string' }, remediationState: { type: 'string' } },
  )
  @ApiModeUnavailable()
  async restore(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('detectionId') detectionId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RestoreResponseView> {
    const result = await this.remediations.restore(
      principal,
      scope,
      { id: detectionId, idempotencyKey, body },
      client,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}
