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
import { ApiBearerAuth, ApiBody, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
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
import { ApiListErrors, ApiListQuery, TransactionalIdempotency } from '../../messages/api-docs';
import {
  ApiAtoForbidden,
  ApiAtoKeyedErrors,
  ApiAtoResponse,
  ApiAtoUnavailable,
  ApiIncidentIdParam,
  ApiResponseIdParam,
  ApiResponseNotFound,
  FEATURE_OFF_READ,
  MUTATION_RULE,
} from '../api-docs';
import { ATO_OPERATIONS as O, ATO_PERMISSIONS as P } from '../ato.constants';
import { ATO_ERROR_CODES as C } from '../ato.errors';
import { ATO_EXAMPLES as X } from '../dto/ato.examples';
import {
  type ApproveBody,
  ApproveBodySchema,
  type CancelBody,
  CancelBodySchema,
  PAGE_PARAMETERS,
  type ReasonBody,
  ReasonBodySchema,
  type RequestResponseBody,
  RequestResponseBodySchema,
  ResponseDetailSchema,
  type ResponseDetailView,
  type ResponseListQuery,
  ResponseListQuerySchema,
  type ResponsePage,
  ResponsePageSchema,
} from '../dto/ato.schemas';
import { AtoResponsesService } from '../services/ato-responses.service';

const MFA_RULE =
  ' Users with an MFA session only (`403 mfa_required`; API keys `403 user_required`).';
const STATE_CODES = [C.responseState, C.responseExpired];

/**
 * Response actions (step 8.4 §5.1 #16–#22, D13, ADR-0072). Translation only: the ATO store
 * enforces the catalogue, the state machine, the four-eyes rule and the approval window.
 */
@ApiTags('ato')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'ato', version: '1' })
export class AtoResponsesController {
  constructor(private readonly responses: AtoResponsesService) {}

  private static replay<T>(res: Response, result: { replayed: boolean; body: T }): T {
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post('incidents/:incidentId/responses')
  @RequirePermissions(P.respond)
  @HttpCode(HttpStatus.CREATED)
  @TransactionalIdempotency(O.responseRequest)
  @ApiOperation({
    summary: 'Request a response on an account takeover incident',
    description:
      'Requests an action of the response catalogue for the incident’s account. Gateway ' +
      'actions: `alert_tenant_admins`, `notify_soc`, `escalate_investigation` (low impact: ' +
      'executed now), `restrict_smtp_sending` (mailbox or connector scope) and `block_smtp_auth` ' +
      '(connector, or connector + `cidr` at medium impact) — high/medium impact waits for an ' +
      'approval (`pending_approval`, expires after ATO_APPROVAL_TTL_HOURS) by another user with ' +
      '`ato:respond` and MFA; `durationMinutes` (15-10080) and `mode` (`reject` default, ' +
      '`defer`) apply to restrictions. `record_manual_action` records what an analyst did ' +
      'elsewhere (`description`; status `attested`, never "succeeded"). Identity-provider ' +
      'actions (`revoke_sessions`, `require_mfa`, …) are `unsupported` until an adapter exists ' +
      '(step 8.5). One active action per incident, type and target (`409 ato_response_active` ' +
      'with `responseId`). Users and API keys (an API key may request, never approve or roll ' +
      'back). Audited `ato.response_requested` / `ato.response_attested`. `404 ' +
      'incident_not_found` unless the id is an `account_takeover` incident.' +
      MUTATION_RULE,
  })
  @ApiIncidentIdParam()
  @ApiBody({
    schema: zodToOpenApi(RequestResponseBodySchema, { io: 'input' }),
    examples: { restrict: { value: X.requestResponse } },
  })
  @ApiAtoResponse(201, ResponseDetailSchema, X.responseDetail, 'The response action', true)
  @ApiAtoKeyedErrors([C.responseActive], [C.responseInvalid])
  @ApiCodedError(404, 'Unknown incident or not an `account_takeover` incident', [
    C.incidentNotFound,
  ])
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async request(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('incidentId') incidentId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(RequestResponseBodySchema)) body: RequestResponseBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ResponseDetailView> {
    return AtoResponsesController.replay(
      res,
      await this.responses.request(principal, scope, incidentId, key, body, client.ip),
    );
  }

  @Get('responses')
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List response actions',
    description:
      'Response actions newest first: type, provider, impact, status, target, requester, ' +
      'approver, times, provider status and result code, and what the caller may do ' +
      '(`canDecide`, `canRollback`). Filters `status` and `actionType` (lists), `incidentId`, ' +
      '`accountId`.' +
      FEATURE_OFF_READ,
  })
  @ApiListQuery(ResponseListQuerySchema, {
    ...PAGE_PARAMETERS,
    sort: '`-createdAt`',
    status: 'Statuses (comma list), e.g. `pending_approval`',
    actionType: 'Action types (comma list)',
    incidentId: 'Incident public id',
    accountId: 'Account public id',
  })
  @ApiAtoResponse(200, ResponsePageSchema, X.responsePage, 'One page of response actions')
  @ApiListErrors()
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ResponseListQuerySchema)) query: ResponseListQuery,
  ): Promise<ResponsePage> {
    return this.responses.list(principal, scope, query);
  }

  @Get('responses/:responseId')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get a response action',
    description:
      'The action with its attempts and the SMTP restriction it applied.' + FEATURE_OFF_READ,
  })
  @ApiResponseIdParam()
  @ApiAtoResponse(200, ResponseDetailSchema, X.responseDetail, 'The response action')
  @ApiCodedError(400, 'The id is not a UUID (`validation_failed`)', ['validation_failed'])
  @ApiResponseNotFound()
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  get(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('responseId') responseId: string,
  ): Promise<ResponseDetailView> {
    return this.responses.detail(principal, scope, responseId);
  }

  @Post('responses/:responseId/approve')
  @RequirePermissions(P.respond)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @TransactionalIdempotency(O.responseApprove)
  @ApiOperation({
    summary: 'Approve a response action',
    description:
      'Approves a `pending_approval` action (`409 ato_response_state` otherwise; `409 ' +
      'ato_response_expired` after the approval window). Never by the user who requested it, ' +
      'nor, for a request made with an API key, by the user who created that key (`403 ' +
      'ato_approval_self`). Gateway actions execute in the same transaction (a restriction ' +
      'is enforced by every SMTP adapter within SMTP_ATO_RESTRICTION_CACHE_SECONDS); provider ' +
      'actions are queued for the ato-worker (`unsupported` without an adapter). Audited ' +
      '`ato.response_approved`.' +
      MFA_RULE +
      MUTATION_RULE,
  })
  @ApiResponseIdParam()
  @ApiBody({
    schema: zodToOpenApi(ApproveBodySchema, { io: 'input' }),
    examples: { approve: { value: X.approve } },
  })
  @ApiAtoResponse(200, ResponseDetailSchema, X.responseDetail, 'The decided action', true)
  @ApiAtoKeyedErrors(STATE_CODES)
  @ApiResponseNotFound()
  @ApiAtoForbidden([C.approvalSelf, C.approverInvalid], true)
  @ApiAtoUnavailable()
  async approve(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('responseId') responseId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(ApproveBodySchema)) body: ApproveBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ResponseDetailView> {
    return AtoResponsesController.replay(
      res,
      await this.responses.approve(principal, scope, responseId, key, body, client.ip),
    );
  }

  @Post('responses/:responseId/reject')
  @RequirePermissions(P.respond)
  @UserOnly()
  @HttpCode(HttpStatus.OK)
  @TransactionalIdempotency(O.responseReject)
  @ApiOperation({
    summary: 'Reject a response action',
    description:
      'Rejects a `pending_approval` action with a reason (10-1000 characters); never by its ' +
      'requester nor the creator of the requesting API key (`403 ato_approval_self`). Audited `ato.response_rejected`. Users only.' +
      MUTATION_RULE,
  })
  @ApiResponseIdParam()
  @ApiBody({
    schema: zodToOpenApi(ReasonBodySchema, { io: 'input' }),
    examples: { reject: { value: X.reject } },
  })
  @ApiAtoResponse(200, ResponseDetailSchema, X.responseDetail, 'The rejected action', true)
  @ApiAtoKeyedErrors(STATE_CODES)
  @ApiResponseNotFound()
  @ApiAtoForbidden([C.approvalSelf, C.approverInvalid], true)
  @ApiAtoUnavailable()
  async reject(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('responseId') responseId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(ReasonBodySchema)) body: ReasonBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ResponseDetailView> {
    return AtoResponsesController.replay(
      res,
      await this.responses.reject(principal, scope, responseId, key, body, client.ip),
    );
  }

  @Post('responses/:responseId/cancel')
  @RequirePermissions(P.respond)
  @HttpCode(HttpStatus.OK)
  @TransactionalIdempotency(O.responseCancel)
  @ApiOperation({
    summary: 'Cancel a pending response action',
    description:
      'Cancels a `pending_approval` action (`409 ato_response_state` otherwise). Users and API ' +
      'keys. Audited `ato.response_cancelled`.' +
      MUTATION_RULE,
  })
  @ApiResponseIdParam()
  @ApiBody({
    schema: zodToOpenApi(CancelBodySchema, { io: 'input' }),
    examples: { cancel: { value: X.cancel } },
  })
  @ApiAtoResponse(200, ResponseDetailSchema, X.responseDetail, 'The cancelled action', true)
  @ApiAtoKeyedErrors(STATE_CODES)
  @ApiResponseNotFound()
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async cancel(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('responseId') responseId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(CancelBodySchema)) body: CancelBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ResponseDetailView> {
    return AtoResponsesController.replay(
      res,
      await this.responses.cancel(principal, scope, responseId, key, body, client.ip),
    );
  }

  @Post('responses/:responseId/rollback')
  @RequirePermissions(P.respond)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @TransactionalIdempotency(O.responseRollback)
  @ApiOperation({
    summary: 'Roll back a response action',
    description:
      'Rolls back a `succeeded` action whose type supports it (`422 ato_rollback_unsupported` ' +
      'otherwise): an SMTP restriction is lifted in the same transaction (`rolled_back`); a ' +
      'provider action gets `rollback_requested` (step 8.5). Reason 10-1000 characters. Audited ' +
      '`ato.response_rollback_requested` / `ato.response_rolled_back`.' +
      MFA_RULE +
      MUTATION_RULE,
  })
  @ApiResponseIdParam()
  @ApiBody({
    schema: zodToOpenApi(ReasonBodySchema, { io: 'input' }),
    examples: { rollback: { value: X.rollback } },
  })
  @ApiAtoResponse(200, ResponseDetailSchema, X.responseDetail, 'The rolled-back action', true)
  @ApiAtoKeyedErrors(STATE_CODES, [C.rollbackUnsupported])
  @ApiResponseNotFound()
  @ApiAtoForbidden([C.approverInvalid], true)
  @ApiAtoUnavailable()
  async rollback(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('responseId') responseId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(ReasonBodySchema)) body: ReasonBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ResponseDetailView> {
    return AtoResponsesController.replay(
      res,
      await this.responses.rollback(principal, scope, responseId, key, body, client.ip),
    );
  }
}
