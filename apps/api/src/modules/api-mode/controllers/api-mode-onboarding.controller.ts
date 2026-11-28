import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Put,
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
  DomainOnboardingSchema,
  type DomainOnboardingResponse,
  DomainScopeChangeSchema,
  type DomainScopeChangeView,
  DomainScopeSchema,
  type DomainScopeView,
  ONBOARDING_EXAMPLES as X,
  PROTECTION_COVERAGE_PARAMETERS,
  type ProtectionCoverageQuery,
  ProtectionCoverageQuerySchema,
  ProtectionCoverageSchema,
  type ProtectionCoverageView,
  PutDomainScopeBodySchema,
} from '../dto/api-mode-onboarding.schemas';
import { ApiModeOnboardingService } from '../services/api-mode-onboarding.service';

const ApiDomainNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown domain, or one of another organization', [C.domainNotFound]);

const ApiDomainIdParam = (): MethodDecorator =>
  ApiParam({ name: 'domainId', description: 'Domain public id (UUID)', format: 'uuid' });

/**
 * API-mode onboarding (step API-4 A10, B6, B8; ADR-0107;
 * docs/plan/steps/38-api-mode-parity-onboarding.md): protection by mode, the server-computed
 * onboarding state of an api/hybrid domain (the wizard's steps and the live first-copy check) and
 * the domain's mailbox scope. Translation only: the service owns the rules and the audit row.
 */
@ApiTags('api-mode')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'api-mode', version: '1' })
export class ApiModeOnboardingController {
  constructor(private readonly onboarding: ApiModeOnboardingService) {}

  @Get('protection-coverage')
  @RequirePermissions(P.domainRead)
  @CursorList('v1')
  @ApiOperation({
    summary: 'Protection by mode: what each mode covers and each domain’s coverage',
    description:
      'The static capability matrix of the inline, api and hybrid modes (`capabilities`: ' +
      '`pre_delivery_blocking`, `hold_for_review`, `post_delivery_removal`, ' +
      '`retroactive_clawback`, `internal_mail`, `outbound_dlp_enforce`, `outbound_dlp_detect`, ' +
      '`tenant_policies`, `url_rewriting`, `message_tagging`, `user_reports`, ' +
      '`alerts_webhooks`), the domains per effective mode and one page of the organization’s ' +
      'domains (newest first) with their actual coverage: the inline facts (inbound, outbound, MX ' +
      'at the gateway), the API facts (connection health and mailbox access, journal and feed ' +
      'intake, scope, in-scope / covered / gap mailboxes, remediation source and mode with the ' +
      'detect-only end, policy evaluation, last copy) and the gap codes (`inline_mx_not_at_gateway`, ' +
      '`inline_not_active`, `api_no_connection`, `api_no_mailbox_access`, `api_no_intake`, ' +
      '`api_coverage_gaps`, `api_mx_points_to_gateway`, `api_detect_only`, ' +
      '`api_policy_evaluation_off`). Counts only, never an address. Filter `effectiveMode`. v1 ' +
      'list (`protection_coverage`). From the read replica. Needs `domain:read`.',
  })
  @ApiListQuery(ProtectionCoverageQuerySchema, PROTECTION_COVERAGE_PARAMETERS)
  @ApiModeResponse(200, ProtectionCoverageSchema, X.coverage, 'The coverage page')
  @ApiListErrors()
  @ApiModeForbidden()
  @ApiModeUnavailable()
  protectionCoverage(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ProtectionCoverageQuerySchema)) query: ProtectionCoverageQuery,
  ): Promise<ProtectionCoverageView> {
    return this.onboarding.coverage(principal, scope, query);
  }

  @Get('domains/:domainId/onboarding')
  @RequirePermissions(P.domainRead)
  @ApiOperation({
    summary: 'Get the API-mode onboarding state of a domain',
    description:
      'Computed from server state only (never from clicks): the wizard steps `ownership`, ' +
      '`connect`, `intake`, `mailboxes`, `action`, `review` with their status (`not_started`, ' +
      '`in_progress`, `done`, `blocked`, `skipped` — all skipped for an inline domain), blocker ' +
      'and next-action codes; ownership (method, the provider check, whether one is available), ' +
      'the linked connection (bound, grants), intake (journal sources, feeds), scope counts, the ' +
      'threat action (source, mode, preset, detect-only period) and the live first-copy check ' +
      '(`waiting` / `received` with the copy’s verdict, lag, source, policy and remediation ' +
      'state; after API_MODE_FIRST_COPY_HINT_AFTER_MINUTES of waiting the troubleshooting hints ' +
      '`domain_not_active`, `mode_not_api`, `connection_missing`, `connection_not_bound`, ' +
      '`mailbox_access_missing`, `journal_source_missing`, `journal_source_unverified`, ' +
      '`journal_source_silent`, `journal_seen_no_domain_recipient`, `feeds_disabled`, ' +
      '`feeds_initializing`, `no_mailboxes_in_scope`, `connection_throttled`, `copies_failing`, ' +
      '`send_test_message`). The wizard polls it every 5 s. From the read replica. Needs ' +
      '`domain:read`.',
  })
  @ApiModeResponse(200, DomainOnboardingSchema, X.onboarding, 'The onboarding state')
  @ApiDomainIdParam()
  @ApiBadId()
  @ApiModeForbidden()
  @ApiDomainNotFound()
  @ApiModeUnavailable()
  domainOnboarding(
    @CurrentScope() scope: TenantScope,
    @Param('domainId') domainId: string,
  ): Promise<DomainOnboardingResponse> {
    return this.onboarding.onboarding(scope, domainId);
  }

  @Get('domains/:domainId/scope')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get the mailbox scope of an API-mode domain',
    description:
      'Which mailboxes of the domain API mode protects: `all` (default), policy-directory ' +
      '`departments` (with their names and member counts; names are operator text) or selected ' +
      '`mailboxes`; the selected count, the in-scope and excluded counts of the last ' +
      'evaluation, whether a change waits for the mailbox-worker, and the CAS `rowVersion`. ' +
      'Excluded mailboxes keep their copies recorded but get no remediation, feed or clawback. ' +
      'Needs `remediation:read`.',
  })
  @ApiModeResponse(200, DomainScopeSchema, X.scope, 'The scope')
  @ApiDomainIdParam()
  @ApiBadId()
  @ApiModeForbidden()
  @ApiDomainNotFound()
  @ApiModeUnavailable()
  getScope(
    @CurrentScope() scope: TenantScope,
    @Param('domainId') domainId: string,
  ): Promise<DomainScopeView> {
    return this.onboarding.getScope(scope, domainId);
  }

  @Put('domains/:domainId/scope')
  @RequirePermissions(P.write)
  @HttpCode(HttpStatus.OK)
  @ApiModeIdempotency(API_MODE_OPERATIONS.scopePut)
  @ApiOperation({
    summary: 'Set the mailbox scope of an API-mode domain',
    description:
      '`{ scope: api-mode-scope/1, mailboxIds? (kind mailboxes only, required there, ≤ 5 000 ' +
      'mailboxes of this domain), reason, expectedRowVersion }` replaces the scope: the domain ' +
      'must be effective `api` or `hybrid` (`409 api_mode_scope_domain_not_api`), departments ' +
      'must be the organization’s (`422 api_mode_scope_department_invalid`), mailboxes the ' +
      'domain’s (`422 api_mode_scope_mailbox_invalid`); CAS on `expectedRowVersion` (null = ' +
      'create; mismatch `409 api_mode_scope_conflict` with `currentRowVersion`). The selection ' +
      'is cleared and set in the same transaction and the mailbox-worker re-evaluates the ' +
      'domain’s mailboxes on its next tick (new mailboxes of a `departments` scope stay ' +
      'protected until evaluated). Narrowing the scope removes protection: audited ' +
      '`api_mode.scope_updated` `{ domainId, from, to, departments, mailboxes, reason }`. Needs ' +
      '`remediation:write`.' +
      KEYED_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(PutDomainScopeBodySchema, { io: 'input' }),
    examples: { mailboxes: { value: X.putScope } },
  })
  @ApiModeResponse(200, DomainScopeChangeSchema, X.scopeChange, 'The stored scope', true)
  @ApiDomainIdParam()
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiDomainNotFound()
  @ApiModeConflicts(
    [C.scopeDomainNotApi, C.scopeConflict],
    '`api_mode_scope_domain_not_api` (`effectiveMode`), `api_mode_scope_conflict` ' +
      '(`currentRowVersion`)',
    true,
    { currentRowVersion: { type: 'integer' } },
  )
  @ApiModeUnprocessable(
    [C.scopeDepartmentInvalid, C.scopeMailboxInvalid],
    '`api_mode_scope_department_invalid` (`departmentIds`), `api_mode_scope_mailbox_invalid` ' +
      '(`invalid`)',
    true,
  )
  @ApiModeUnavailable()
  async putScope(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('domainId') domainId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<DomainScopeChangeView> {
    const result = await this.onboarding.putScope(
      principal,
      scope,
      { domainId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}
