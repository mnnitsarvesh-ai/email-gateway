import {
  Body,
  Controller,
  Delete,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
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
  ApiQuery,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
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
  ApiListErrors,
  ApiListQuery,
  SCAN_BUDGET_RULE,
  TransactionalIdempotency,
} from '../../messages/api-docs';
import {
  ApiAccountIdParam,
  ApiAccountNotFound,
  ApiAtoForbidden,
  ApiAtoKeyedErrors,
  ApiAtoResponse,
  ApiAtoUnavailable,
  ApiContextIdParam,
  FEATURE_OFF_READ,
  MUTATION_RULE,
} from '../api-docs';
import { ATO_OPERATIONS as O, ATO_PERMISSIONS as P } from '../ato.constants';
import { ATO_ERROR_CODES as C } from '../ato.errors';
import { ATO_EXAMPLES as X } from '../dto/ato.examples';
import {
  AccountDetailSchema,
  type AccountDetailView,
  type AccountListQuery,
  AccountListQuerySchema,
  type AccountPage,
  AccountPageSchema,
  type ActivityQuery,
  ActivityQuerySchema,
  ActivitySchema,
  type ActivityView,
  type AddTrustedContextBody,
  AddTrustedContextBodySchema,
  type AuthEventListQuery,
  AuthEventListQuerySchema,
  type AuthEventPage,
  AuthEventPageSchema,
  type ClearOverrideBody,
  ClearOverrideBodySchema,
  PAGE_PARAMETERS,
  type ScoreHistoryQuery,
  ScoreHistoryQuerySchema,
  type ScorePage,
  ScorePageSchema,
  type SetOverrideBody,
  SetOverrideBodySchema,
  type SignalListQuery,
  SignalListQuerySchema,
  type SignalPage,
  SignalPageSchema,
  TrustedContextSchema,
  type UpdateAccountBody,
  UpdateAccountBodySchema,
} from '../dto/ato.schemas';
import { AtoAccountsService } from '../services/ato-accounts.service';

const RANGE = {
  from: 'Start of the range (ISO 8601 with offset, inclusive)',
  to: 'End of the range (exclusive; default now)',
};

/**
 * Monitored accounts (step 8.4 §5.1 #3–#13): list, detail, protection, signals, auth events,
 * activity, score history, overrides and trusted contexts. Translation only (services own the
 * rules; the ATO store writes and audits).
 */
@ApiTags('ato')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'ato/accounts', version: '1' })
export class AtoAccountsController {
  constructor(private readonly accounts: AtoAccountsService) {}

  private static replay<T>(res: Response, result: { replayed: boolean; body: T }): T {
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get()
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List monitored accounts',
    description:
      'Mailboxes, gateway users and SMTP connectors monitored for account takeover, with their ' +
      'risk score and level, active incident and override. Filters: `kind` and `level` (lists), ' +
      '`minScore`, `hasActiveIncident`, `protected`, `domainId`, `q` (address prefix, at least ' +
      '2 characters). Sorts: `-riskScore` (default), `-lastSignalAt` (accounts that had a ' +
      'signal), `address` (accounts with an address). ' +
      SCAN_BUDGET_RULE +
      FEATURE_OFF_READ,
  })
  @ApiListQuery(AccountListQuerySchema, {
    ...PAGE_PARAMETERS,
    sort: '`-riskScore` (default), `-lastSignalAt` or `address`',
    kind: '`mailbox`, `gateway_user`, `smtp_connector` (comma list)',
    level: '`low`, `medium`, `high`, `critical` (comma list)',
    minScore: 'Minimum risk score (0-100)',
    hasActiveIncident: '`true` or `false`',
    protected: '`true` or `false`',
    domainId: 'Domain public id',
    q: 'Address prefix (case-insensitive, at least 2 characters)',
  })
  @ApiAtoResponse(200, AccountPageSchema, X.accountPage, 'One page of accounts')
  @ApiListErrors()
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(AccountListQuerySchema)) query: AccountListQuery,
  ): Promise<AccountPage> {
    return this.accounts.list(principal, scope, query);
  }

  @Get(':accountId')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get a monitored account',
    description:
      'The account (address, user display name or connector name), score and level with the ' +
      'explanation (rendered and structured), override, protection, active restrictions, active ' +
      'incident, baseline summary (top prefixes, countries, ASNs and devices with counts, hour ' +
      'histograms, volume statistics, maturity), trusted contexts, linked accounts (same ' +
      'address, other kinds), provider identities (8.5) and the worker capabilities. ' +
      '`rowVersion` is the version for `PATCH`.' +
      FEATURE_OFF_READ,
  })
  @ApiAccountIdParam()
  @ApiAtoResponse(200, AccountDetailSchema, X.accountDetail, 'The account')
  @ApiCodedError(400, 'The account id is not a UUID (`validation_failed`)', ['validation_failed'])
  @ApiAccountNotFound()
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('accountId') accountId: string,
  ): Promise<AccountDetailView> {
    return this.accounts.detail(scope, accountId);
  }

  @Patch(':accountId')
  @RequirePermissions(P.manage)
  @UserOnly()
  @HttpCode(HttpStatus.OK)
  @TransactionalIdempotency(O.accountUpdate)
  @ApiOperation({
    summary: 'Protect or unprotect a monitored account',
    description:
      'Sets `protected` (a protected account is never acted on automatically; recommendations ' +
      'stay) with a reason, compare-and-set on `expectedRowVersion` (`409 ato_account_conflict` ' +
      'with `currentRowVersion`). Audited `ato.account_protected` / `ato.account_unprotected`. ' +
      'Users only.' +
      MUTATION_RULE,
  })
  @ApiAccountIdParam()
  @ApiBody({
    schema: zodToOpenApi(UpdateAccountBodySchema, { io: 'input' }),
    examples: { protect: { value: X.updateAccount } },
  })
  @ApiAtoResponse(200, AccountDetailSchema, X.accountDetail, 'The updated account', true)
  @ApiAtoKeyedErrors([C.accountConflict])
  @ApiAccountNotFound()
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('accountId') accountId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(UpdateAccountBodySchema)) body: UpdateAccountBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AccountDetailView> {
    return AtoAccountsController.replay(
      res,
      await this.accounts.update(principal, scope, accountId, key, body, client.ip),
    );
  }

  @Get(':accountId/signals')
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the risk signals of an account',
    description:
      'Signals newest first with their rule title, category, strength, weight, status, ' +
      'occurrences, rendered explanation and allow-listed evidence. Range `from`/`to` (default ' +
      'the last 30 days, at most 400); filters `category`, `status`, `strength` (lists). ' +
      SCAN_BUDGET_RULE +
      FEATURE_OFF_READ,
  })
  @ApiAccountIdParam()
  @ApiListQuery(SignalListQuerySchema, {
    ...PAGE_PARAMETERS,
    ...RANGE,
    sort: '`-detectedAt`',
    category: 'Signal categories (comma list)',
    status: '`active`, `dismissed`, `informational` (comma list)',
    strength: '`weak`, `moderate`, `strong` (comma list)',
  })
  @ApiAtoResponse(200, SignalPageSchema, X.signalPage, 'One page of signals')
  @ApiListErrors()
  @ApiAccountNotFound()
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  signals(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('accountId') accountId: string,
    @Query(new ZodValidationPipe(SignalListQuerySchema)) query: SignalListQuery,
  ): Promise<SignalPage> {
    return this.accounts.signals(principal, scope, accountId, query);
  }

  @Get(':accountId/auth-events')
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the authentication events of an account',
    description:
      'Portal, MFA, SMTP and identity-provider authentication events newest first: outcome, ' +
      'failure code, IP address and prefix, coarse geolocation (when GeoIP is configured), ASN, ' +
      'anonymizer flags, IP reputation, device label and attempt count (successful SMTP ' +
      'authentications are aggregated per connector, IP and hour). Never a password, token or ' +
      'attempted username. Range `from`/`to` (default the last 7 days, at most 90); filters ' +
      '`outcome`, `source` (lists), `ip`, `country`. The first page of each request is audited ' +
      '(`ato.auth_events.viewed`: the account, range and filter names; no IP addresses). ' +
      SCAN_BUDGET_RULE +
      FEATURE_OFF_READ,
  })
  @ApiAccountIdParam()
  @ApiListQuery(AuthEventListQuerySchema, {
    ...PAGE_PARAMETERS,
    ...RANGE,
    sort: '`-occurredAt`',
    outcome: 'Outcomes (comma list)',
    source: '`portal_login`, `portal_mfa`, `smtp_auth`, `idp_sign_in` (comma list)',
    ip: 'Exact IP address',
    country: 'ISO 3166-1 alpha-2 country code',
  })
  @ApiAtoResponse(200, AuthEventPageSchema, X.authEventPage, 'One page of authentication events')
  @ApiListErrors()
  @ApiAccountNotFound()
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  authEvents(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('accountId') accountId: string,
    @Query(new ZodValidationPipe(AuthEventListQuerySchema)) query: AuthEventListQuery,
    @Client() client: ClientContext,
  ): Promise<AuthEventPage> {
    return this.accounts.authEvents(principal, scope, accountId, query, client.ip);
  }

  @Get(':accountId/activity')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get the daily activity of an account',
    description:
      'Daily activity rows of `from`/`to` (default the last 30 days, at most 180): ' +
      'authentication successes and failures, outbound messages, recipients (internal and ' +
      'external counts), attachments, findings, the busiest hour, the top recipient domains ' +
      '(domains only) and content counts.' +
      FEATURE_OFF_READ,
  })
  @ApiAccountIdParam()
  @ApiQuery({
    name: 'from',
    required: false,
    description: RANGE.from,
    schema: { type: 'string', format: 'date-time' },
  })
  @ApiQuery({
    name: 'to',
    required: false,
    description: RANGE.to,
    schema: { type: 'string', format: 'date-time' },
  })
  @ApiAtoResponse(200, ActivitySchema, X.activity, 'The daily activity')
  @ApiCodedError(400, 'Invalid range or parameter (`validation_failed`)', ['validation_failed'])
  @ApiAccountNotFound()
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  activity(
    @CurrentScope() scope: TenantScope,
    @Param('accountId') accountId: string,
    @Query(new ZodValidationPipe(ActivityQuerySchema)) query: ActivityQuery,
  ): Promise<ActivityView> {
    return this.accounts.activity(scope, accountId, query);
  }

  @Get(':accountId/score-history')
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the risk score history of an account',
    description:
      'Score changes newest first with the previous score and level, the trigger (signal, ' +
      'decay, override, dismissal, settings, feedback) and the stored explanation. Range ' +
      '`from`/`to` (default the last 30 days, at most 400).' +
      FEATURE_OFF_READ,
  })
  @ApiAccountIdParam()
  @ApiListQuery(ScoreHistoryQuerySchema, { ...PAGE_PARAMETERS, ...RANGE, sort: '`-computedAt`' })
  @ApiAtoResponse(200, ScorePageSchema, X.scorePage, 'One page of score points')
  @ApiListErrors()
  @ApiAccountNotFound()
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  scoreHistory(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('accountId') accountId: string,
    @Query(new ZodValidationPipe(ScoreHistoryQuerySchema)) query: ScoreHistoryQuery,
  ): Promise<ScorePage> {
    return this.accounts.scoreHistory(principal, scope, accountId, query);
  }

  @Put(':accountId/override')
  @RequirePermissions(P.manage)
  @UserOnly()
  @HttpCode(HttpStatus.OK)
  @TransactionalIdempotency(O.overrideSet)
  @ApiOperation({
    summary: 'Set an analyst override on an account',
    description:
      '`benign` (the score is held below the medium band until a strong signal arrives after ' +
      'the override, which contradicts it; automation never acts on the account) or ' +
      '`compromised` (the score is at least 90) with a ' +
      'reason (10-1000 characters) for `expiresInHours` (1-720). Replaces an active override and ' +
      'rescores the account in the same transaction. Audited `ato.override_set`. Users only.' +
      MUTATION_RULE,
  })
  @ApiAccountIdParam()
  @ApiBody({
    schema: zodToOpenApi(SetOverrideBodySchema, { io: 'input' }),
    examples: { benign: { value: X.setOverride } },
  })
  @ApiAtoResponse(200, AccountDetailSchema, X.accountDetail, 'The rescored account', true)
  @ApiAtoKeyedErrors([], [C.overrideInvalid])
  @ApiAccountNotFound()
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async setOverride(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('accountId') accountId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(SetOverrideBodySchema)) body: SetOverrideBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AccountDetailView> {
    return AtoAccountsController.replay(
      res,
      await this.accounts.setOverride(principal, scope, accountId, key, body, client.ip),
    );
  }

  @Post(':accountId/override/clear')
  @RequirePermissions(P.manage)
  @UserOnly()
  @HttpCode(HttpStatus.OK)
  @TransactionalIdempotency(O.overrideClear)
  @ApiOperation({
    summary: 'Clear the analyst override of an account',
    description:
      'Clears the active override (`404 ato_override_not_found` without one) with a reason and ' +
      'rescores the account. Audited `ato.override_cleared`. Users only.' +
      MUTATION_RULE,
  })
  @ApiAccountIdParam()
  @ApiBody({
    schema: zodToOpenApi(ClearOverrideBodySchema, { io: 'input' }),
    examples: { clear: { value: X.clearOverride } },
  })
  @ApiAtoResponse(200, AccountDetailSchema, X.accountDetail, 'The rescored account', true)
  @ApiAtoKeyedErrors()
  @ApiCodedError(404, 'Unknown account, or the account has no active override', [
    C.accountNotFound,
    C.overrideNotFound,
  ])
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async clearOverride(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('accountId') accountId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(ClearOverrideBodySchema)) body: ClearOverrideBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AccountDetailView> {
    return AtoAccountsController.replay(
      res,
      await this.accounts.clearOverride(principal, scope, accountId, key, body, client.ip),
    );
  }

  @Post(':accountId/trusted-contexts')
  @RequirePermissions(P.manage)
  @UserOnly()
  @HttpCode(HttpStatus.CREATED)
  @TransactionalIdempotency(O.trustedContextAdd)
  @ApiOperation({
    summary: 'Add a trusted context to an account',
    description:
      'A context the rules treat as known for this account: `ip_cidr` (IPv4 /8 or longer, IPv6 ' +
      '/32 or longer), `asn`, `country` (ISO alpha-2) or `device` (16-hex device hash), with a ' +
      'reason and `expiresInDays` (1-365). An existing context of the same kind and value is ' +
      'renewed. `422 ato_trusted_context_invalid` for an invalid value. Audited ' +
      '`ato.trusted_context_added`. Users only.' +
      MUTATION_RULE,
  })
  @ApiAccountIdParam()
  @ApiBody({
    schema: zodToOpenApi(AddTrustedContextBodySchema, { io: 'input' }),
    examples: { office: { value: X.addTrustedContext } },
  })
  @ApiAtoResponse(201, TrustedContextSchema, X.trustedContext, 'The trusted context', true)
  @ApiAtoKeyedErrors([], [C.trustedContextInvalid])
  @ApiAccountNotFound()
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async addTrustedContext(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('accountId') accountId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(AddTrustedContextBodySchema)) body: AddTrustedContextBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AccountDetailView['trustedContexts'][number]> {
    return AtoAccountsController.replay(
      res,
      await this.accounts.addTrustedContext(principal, scope, accountId, key, body, client.ip),
    );
  }

  @Delete(':accountId/trusted-contexts/:contextId')
  @RequirePermissions(P.manage)
  @UserOnly()
  @HttpCode(HttpStatus.NO_CONTENT)
  @TransactionalIdempotency(O.trustedContextRemove)
  @ApiOperation({
    summary: 'Remove a trusted context from an account',
    description:
      'Deletes the context (the audit log keeps the trail: `ato.trusted_context_removed`). Users ' +
      'only.' +
      MUTATION_RULE,
  })
  @ApiAccountIdParam()
  @ApiContextIdParam()
  @ApiNoContentResponse({
    description: 'Removed (or the stored response of an earlier identical request replayed)',
  })
  @ApiAtoKeyedErrors()
  @ApiCodedError(404, 'Unknown account or trusted context (or one of another account)', [
    C.accountNotFound,
    C.trustedContextNotFound,
  ])
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async removeTrustedContext(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('accountId') accountId: string,
    @Param('contextId') contextId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    AtoAccountsController.replay(
      res,
      await this.accounts.removeTrustedContext(
        principal,
        scope,
        accountId,
        contextId,
        key,
        client.ip,
      ),
    );
  }
}
