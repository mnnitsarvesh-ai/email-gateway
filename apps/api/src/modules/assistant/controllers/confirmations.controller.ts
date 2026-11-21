import { Body, Controller, Get, HttpCode, HttpStatus, Param, Post, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { RateClass } from '../../../rate-limit/rate-class.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ApiAssistantForbidden,
  ApiAssistantResponse,
  ApiAssistantUnavailable,
  ApiConfirmationIdParam,
  ApiConfirmationNotFound,
  USER_ONLY_RULE,
} from '../api-docs';
import { ASSISTANT_PERMISSIONS as P } from '../assistant.constants';
import { ASSISTANT_ERROR_CODES as C } from '../assistant.errors';
import {
  ASSISTANT_EXAMPLES as X,
  CancelConfirmationResultSchema,
  type CancelConfirmationResultView,
  type ConfirmBody,
  ConfirmBodySchema,
  ConfirmationSchema,
  type ConfirmationViewDto,
  ConfirmResultSchema,
  type ConfirmResultView,
  PublicIdSchema,
} from '../dto/assistant.schemas';
import { ConfirmationService } from '../services/confirmation.service';
import { userOf } from './assistant.controller';

const publicId = new ZodValidationPipe(PublicIdSchema);

const BINDING_RULE =
  ' A confirmation belongs to the user, organization (and platform override) and sign-in ' +
  'session that the assistant proposed it in; another user’s or organization’s answers `404`.';

/**
 * Confirmations of the assistant's write proposals (step AI-2 D2, §4.1; ADR-0093 amended).
 * Translation only: every check lives in `ConfirmationService`. The routes are tagged
 * `assistant`, so the registry classifies them `not_applicable`: the model can never call them.
 */
@ApiTags('assistant')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'assistant/confirmations', version: '1' })
export class AssistantConfirmationsController {
  constructor(private readonly confirmations: ConfirmationService) {}

  @Get(':confirmationId')
  @RequirePermissions(P.use)
  @ApiConfirmationIdParam()
  @ApiOperation({
    summary: 'Get an assistant confirmation',
    description:
      'One of your own write proposals: tool, risk, status, the server-authored summary ' +
      '(`assistant-confirmation/1`) the confirmation card shows, `actionDigest`, expiry and, ' +
      'after confirm, the result. Never the token (it exists only in the answer of the turn ' +
      'that proposed it). A `pending` confirmation past `expiresAt` shows as `expired`.' +
      BINDING_RULE +
      USER_ONLY_RULE,
  })
  @ApiAssistantResponse(200, ConfirmationSchema, X.confirmation, 'The confirmation')
  @ApiConfirmationNotFound()
  @ApiAssistantForbidden()
  @ApiAssistantUnavailable()
  get(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('confirmationId', publicId) confirmationId: string,
  ): Promise<ConfirmationViewDto> {
    return this.confirmations.get(userOf(principal), scope, confirmationId);
  }

  @Post(':confirmationId/confirm')
  @RequirePermissions(P.use)
  @RateClass('sensitive')
  @HttpCode(HttpStatus.OK)
  @ApiConfirmationIdParam()
  @ApiOperation({
    summary: 'Confirm an action the assistant proposed',
    description:
      'Runs the stored request of a pending proposal, exactly as the card showed it, through ' +
      'the api’s own pipeline with YOUR credential (permissions, tenant, MFA, rate limits, ' +
      'validation, CAS, approvals and audit apply as in the portal) with `Idempotency-Key` = ' +
      'the confirmation id where the operation takes one. Send the single-use `token` of the ' +
      '`confirmation.required` event (or the turn’s `confirmations[]`) and the `actionDigest` ' +
      'the card showed; high-risk actions also need `reauth` (`password`, and `totpCode` with ' +
      'MFA) unless this session re-authenticated an assistant confirmation within ' +
      'ASSISTANT_REAUTH_WINDOW_SECONDS. Checks in order: own confirmation (`404`), same ' +
      'sign-in session (`403 assistant_confirmation_session_mismatch`), still pending (`409 ' +
      'assistant_confirmation_not_pending` with `status`), not expired (`410 ' +
      'assistant_confirmation_expired`), the token (`403 assistant_confirmation_token_invalid`; ' +
      'the fifth wrong token cancels the confirmation), the digest (`409 ' +
      'assistant_confirmation_digest_mismatch`), the tool still enabled (`409 ' +
      'assistant_confirmation_tool_changed`) and permitted (`403 forbidden`), the assistant ' +
      'available, re-authentication (`401 assistant_reauth_required`, `401 ' +
      'assistant_reauth_failed` with `reason`; failures count toward the login lockout), no ' +
      'turn running in the conversation (`409 assistant_turn_in_progress`), then the target is ' +
      'read again and any change since the proposal refuses (`409 ' +
      'assistant_confirmation_state_changed`). A write the operation itself refuses is a `200` ' +
      'with `confirmation.status = failed` and the execution’s error card; `202` approval ' +
      'answers are `executed`. The assistant learns the outcome at the start of its next turn. ' +
      'Rate class `sensitive`.' +
      BINDING_RULE +
      USER_ONLY_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(ConfirmBodySchema, { io: 'input' }),
    examples: {
      confirm: { value: X.confirm },
      highRisk: { summary: 'High risk with re-authentication', value: X.confirmHighRisk },
    },
  })
  @ApiAssistantResponse(
    200,
    ConfirmResultSchema,
    X.confirmResult,
    'The confirmation (`executed` or `failed`) and the execution of the write',
  )
  @ApiCodedError(
    401,
    'Re-authentication needed (`assistant_reauth_required`) or failed ' +
      '(`assistant_reauth_failed`, `reason`: `password`, `totp`, `totp_required`, `locked`, ' +
      '`inactive`)',
    [C.reauthRequired, C.reauthFailed],
    {
      reason: {
        type: 'string',
        enum: ['password', 'totp', 'totp_required', 'locked', 'inactive'],
      },
    },
  )
  @ApiConfirmationNotFound()
  @ApiAssistantForbidden(
    [C.notEnabled, C.tenantDisabled, C.confirmationSessionMismatch, C.confirmationTokenInvalid],
    'the organization feature `ai_assistant` is off (`assistant_not_enabled`), the ' +
      'organization turned the assistant off (`assistant_tenant_disabled`), another sign-in ' +
      'session (`assistant_confirmation_session_mismatch`) or a wrong token ' +
      '(`assistant_confirmation_token_invalid`)',
  )
  @ApiCodedError(
    409,
    'No longer pending (`assistant_confirmation_not_pending`, `status`), a digest that does ' +
      'not match the proposal (`assistant_confirmation_digest_mismatch`), the operation is no ' +
      'longer available (`assistant_confirmation_tool_changed`), the target changed since the ' +
      'proposal (`assistant_confirmation_state_changed`, `httpStatus` when the re-read failed) ' +
      'or a turn runs in the conversation (`assistant_turn_in_progress`)',
    [
      C.confirmationNotPending,
      C.confirmationDigestMismatch,
      C.confirmationToolChanged,
      C.confirmationStateChanged,
      C.turnInProgress,
    ],
    { status: { type: 'string' }, httpStatus: { type: 'integer' } },
  )
  @ApiCodedError(410, 'The confirmation expired (ASSISTANT_CONFIRMATION_TTL_SECONDS)', [
    C.confirmationExpired,
  ])
  @ApiCodedError(
    429,
    'Too many requests of the `sensitive` rate class (`rate_limited`)',
    ['rate_limited'],
    { scope: { type: 'string' } },
  )
  @ApiAssistantUnavailable(
    [C.disabled],
    'the assistant is off on this platform (`assistant_disabled`)',
  )
  confirm(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('confirmationId', publicId) confirmationId: string,
    @Body(new ZodValidationPipe(ConfirmBodySchema)) body: ConfirmBody,
    @Client() client: ClientContext,
    @Req() req: Request,
  ): Promise<ConfirmResultView> {
    const header = req.headers.authorization;
    return this.confirmations.confirm(userOf(principal), scope, confirmationId, body, {
      authorization: typeof header === 'string' ? header : '',
      clientIp: client.ip,
    });
  }

  @Post(':confirmationId/cancel')
  @RequirePermissions(P.use)
  @RateClass('sensitive')
  @HttpCode(HttpStatus.OK)
  @ApiConfirmationIdParam()
  @ApiOperation({
    summary: 'Cancel an action the assistant proposed',
    description:
      'Cancels one of your own pending proposals from the same sign-in session (no token ' +
      'needed, so it also works after a page reload); nothing runs. Idempotent: an already ' +
      'cancelled confirmation answers unchanged; any other state answers `409 ' +
      'assistant_confirmation_not_pending` with `status`. The assistant learns about it at the ' +
      'start of its next turn. Rate class `sensitive`.' +
      BINDING_RULE +
      USER_ONLY_RULE,
  })
  @ApiAssistantResponse(
    200,
    CancelConfirmationResultSchema,
    X.cancelConfirmation,
    'The cancelled confirmation',
  )
  @ApiConfirmationNotFound()
  @ApiAssistantForbidden(
    [C.confirmationSessionMismatch],
    'another sign-in session (`assistant_confirmation_session_mismatch`)',
  )
  @ApiCodedError(
    409,
    'Already executed, failed, expired or executing',
    [C.confirmationNotPending],
    { status: { type: 'string' } },
  )
  @ApiCodedError(
    429,
    'Too many requests of the `sensitive` rate class (`rate_limited`)',
    ['rate_limited'],
    { scope: { type: 'string' } },
  )
  @ApiAssistantUnavailable()
  cancel(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('confirmationId', publicId) confirmationId: string,
    @Client() client: ClientContext,
  ): Promise<CancelConfirmationResultView> {
    return this.confirmations.cancel(userOf(principal), scope, confirmationId, client.ip);
  }
}
