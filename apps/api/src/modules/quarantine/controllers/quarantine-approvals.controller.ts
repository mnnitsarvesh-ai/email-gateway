import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Res,
} from '@nestjs/common';
import { ApiAcceptedResponse, ApiBody, ApiOkResponse, ApiOperation } from '@nestjs/swagger';
import type { Response } from 'express';
import type { Page, QuarantineApprovalView } from '@email-gateway/quarantine';
import {
  CurrentPrincipal,
  CurrentScope,
  RequireAnyPermission,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiIdempotencyKey } from '../../../http/idempotency/idempotency-key';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ApiApprovalId,
  ApiApprovalNotFound,
  ApiConflicts,
  IdempotencyKey,
  ApiForbiddenCodes,
  ApiInconsistent,
  ApiQueryOf,
  approvalIdPipe,
  QuarantineController,
} from '../api-docs';
import {
  ApprovalDecisionResponseSchema,
  type ApprovalDecisionResponse,
  type ApprovalListQuery,
  ApprovalListQuerySchema,
  ApprovalPageSchema,
  ApprovalViewSchema,
  ReasonBodySchema,
  type ReasonBody,
} from '../dto/quarantine.schemas';
import { Q } from '../quarantine.constants';
import { QuarantineApprovalsService } from '../services/quarantine-approvals.service';
import { QuarantineQueryService } from '../services/quarantine-query.service';
import { reply } from './quarantine-entries.controller';

const DECISION_CONFLICTS = [
  'quarantine_approval_not_pending',
  'quarantine_state_conflict',
  'quarantine_version_conflict',
] as const;

/**
 * Quarantine approval requests (step 5.3 Q14; ADR-0047): list, detail, approve, deny, cancel.
 * Separation of duties is enforced in QuarantineApprovalsService. Translation only.
 */
@QuarantineController()
@Controller({ path: 'quarantine/approvals', version: '1' })
export class QuarantineApprovalsController {
  constructor(
    private readonly queries: QuarantineQueryService,
    private readonly approvals: QuarantineApprovalsService,
  ) {}

  @Get()
  @RequirePermissions(Q.read)
  @ApiOperation({
    summary: 'List approval requests',
    description:
      'Policy reviews (`policy_review`), releases that need approval (`release_approval`) and ' +
      'release requests (`release_request`), newest first, filtered by status, kind and ' +
      'request time, keyset-paginated. Read replica.',
  })
  @ApiQueryOf(ApprovalListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(ApprovalPageSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ApprovalListQuerySchema)) query: ApprovalListQuery,
  ): Promise<Page<QuarantineApprovalView>> {
    return this.queries.approvals(scope, query);
  }

  @Get(':approvalId')
  @RequirePermissions(Q.read)
  @ApiOperation({ summary: 'Get an approval request', description: 'Read replica.' })
  @ApiApprovalId()
  @ApiOkResponse({ schema: zodToOpenApi(ApprovalViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiApprovalNotFound()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('approvalId', approvalIdPipe) approvalId: string,
  ): Promise<QuarantineApprovalView> {
    return this.queries.approval(scope, approvalId);
  }

  @Post(':approvalId/approve')
  @RequirePermissions(Q.approve)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Approve a request (second person)',
    description:
      'Separation of duties: the approver is an MFA-authenticated user holding ' +
      '`quarantine:approve`, never the requester and never the entry’s recipient (by user or ' +
      'verified address) (`403 quarantine_approval_forbidden` with the reason). The request ' +
      'must be pending and unexpired (`409 quarantine_approval_not_pending`). The pre-check is ' +
      're-run: stale verdicts → `409 quarantine_rescan_required`; otherwise the request is ' +
      '`approved` with the approved reasons (the request’s ∪ the current ones), the entry ' +
      '`releasing` and the release queued; the executor re-validates and needs a new approval ' +
      'for reasons that appear later. Audited as `quarantine.approval_approved`. Requires the ' +
      'Idempotency-Key header.',
  })
  @ApiApprovalId()
  @ApiIdempotencyKey()
  @ApiBody({ schema: zodToOpenApi(ReasonBodySchema, { io: 'input' }) })
  @ApiAcceptedResponse({ schema: zodToOpenApi(ApprovalDecisionResponseSchema) })
  @ApiErrors(400, 401, 403, 422)
  @ApiForbiddenCodes(['quarantine_approval_forbidden'])
  @ApiApprovalNotFound()
  @ApiConflicts([
    ...DECISION_CONFLICTS,
    'quarantine_rescan_required',
    'quarantine_hard_block_release_disabled',
  ])
  @ApiInconsistent()
  async approve(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('approvalId', approvalIdPipe) approvalId: string,
    @IdempotencyKey() key: string,
    @Body(new ZodValidationPipe(ReasonBodySchema)) body: ReasonBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApprovalDecisionResponse> {
    return reply(
      res,
      await this.approvals.approve({ principal, scope, approvalId, key, body, client }),
    );
  }

  @Post(':approvalId/deny')
  @RequirePermissions(Q.approve)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Deny a request',
    description:
      'Same separation of duties as approve. A `policy_review` denial rejects the entry (its ' +
      'recipient discarded, E17/E18 when it was the last live entry); a release request or ' +
      'release approval returns the entry to `held`. Audited as `quarantine.approval_denied`. ' +
      'Requires the Idempotency-Key header.',
  })
  @ApiApprovalId()
  @ApiIdempotencyKey()
  @ApiBody({ schema: zodToOpenApi(ReasonBodySchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(ApprovalDecisionResponseSchema) })
  @ApiErrors(400, 401, 403, 422)
  @ApiForbiddenCodes(['quarantine_approval_forbidden'])
  @ApiApprovalNotFound()
  @ApiConflicts(DECISION_CONFLICTS)
  @ApiInconsistent()
  async deny(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('approvalId', approvalIdPipe) approvalId: string,
    @IdempotencyKey() key: string,
    @Body(new ZodValidationPipe(ReasonBodySchema)) body: ReasonBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApprovalDecisionResponse> {
    return reply(
      res,
      await this.approvals.deny({ principal, scope, approvalId, key, body, client }),
    );
  }

  @Post(':approvalId/cancel')
  @RequireAnyPermission(Q.approve, Q.release, Q.requestRelease, Q.self)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Cancel a request',
    description:
      'By the requester (user or API key) or a holder of `quarantine:approve`; the entry ' +
      'returns to `held`. A `policy_review` cannot be cancelled (`409`). Audited as ' +
      '`quarantine.approval_cancelled`. Requires the Idempotency-Key header.',
  })
  @ApiApprovalId()
  @ApiIdempotencyKey()
  @ApiBody({ schema: zodToOpenApi(ReasonBodySchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(ApprovalDecisionResponseSchema) })
  @ApiErrors(400, 401, 403, 422)
  @ApiApprovalNotFound()
  @ApiConflicts(DECISION_CONFLICTS)
  @ApiInconsistent()
  async cancel(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('approvalId', approvalIdPipe) approvalId: string,
    @IdempotencyKey() key: string,
    @Body(new ZodValidationPipe(ReasonBodySchema)) body: ReasonBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApprovalDecisionResponse> {
    return reply(
      res,
      await this.approvals.cancel({ principal, scope, approvalId, key, body, client }),
    );
  }
}
