import { ApiQueryFrom } from '../../organizations/api-docs';
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
  Query,
  Res,
} from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
} from '../../../http/idempotency/idempotency-key';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { TransactionalIdempotency } from '../../messages/api-docs';
import {
  ApiAtoForbidden,
  ApiAtoKeyedErrors,
  ApiAtoUnavailable,
  FEATURE_OFF_READ,
} from '../api-docs';
import {
  ApiIntegrationIdParam,
  ApiProviderConnectionNotFound,
  ApiProviderNotFound,
  ApiProviderResponse,
  ATO_PROVIDER_EXAMPLES as X,
  PROVIDER_MUTATION_RULE,
  withSettingsDoc,
} from '../ato-providers.api-docs';
import { ATO_OPERATIONS as O, ATO_PERMISSIONS as P } from '../ato.constants';
import { ATO_ERROR_CODES as C } from '../ato.errors';
import {
  type BackfillBody,
  BackfillBodySchema,
  type CreateProviderBody,
  CreateProviderBodySchema,
  ProviderConnectionsSchema,
  type ProviderConnectionsView,
  ProviderDetailSchema,
  type ProviderDetailView,
  ProviderHealthCheckSchema,
  type ProviderHealthCheckView,
  type ProviderListQuery,
  ProviderListQuerySchema,
  ProviderListSchema,
  type ProviderListView,
  type ProviderReasonBody,
  ProviderReasonBodySchema,
  ProviderRequirementsSchema,
  type ProviderRequirementsView,
  type UpdateProviderBody,
  UpdateProviderBodySchema,
} from '../dto/ato-providers.schemas';
import { AtoProvidersService } from '../services/ato-providers.service';

const MFA_RULE =
  ' Users with an MFA session only (`403 mfa_required`; API keys `403 user_required`).';
const USER_RULE = ' Users only (API keys `403 user_required`).';

/**
 * Identity-provider integrations (step 8.5 §6 #1–#11, D4, D6, D8, D10; ADR-0082–0084): bind a
 * Microsoft 365 or Google Workspace connection of step 8.2 to account takeover detection,
 * configure, pause, resume, probe, backfill and remove it. Translation only: the service decides
 * eligibility, limits, settings, CAS and the effects on stream rows and provider actions.
 */
@ApiTags('ato')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'ato/providers', version: '1' })
export class AtoProvidersController {
  constructor(private readonly providers: AtoProvidersService) {}

  private static replay<T>(res: Response, result: { replayed: boolean; body: T }): T {
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get()
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'List identity-provider integrations',
    description:
      'The Microsoft Entra ID / Microsoft 365 and Google Workspace integrations of your ' +
      'organization (not disabled; `includeDisabled=true` adds the 50 most recently removed): ' +
      'provider, the bound connection, status, health (`stale` when the last probe is older ' +
      'than 3 × the probe interval), a stream summary (enabled, available, failing, ' +
      'backfilling, largest lag) and the available streams and actions, plus the limit ' +
      'ATO_IDP_MAX_INTEGRATIONS_PER_ORG and its use. No cursor (a handful of rows).' +
      FEATURE_OFF_READ,
  })
  @ApiQueryFrom(ProviderListQuerySchema)
  @ApiProviderResponse(200, ProviderListSchema, X.list, 'The integrations')
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ProviderListQuerySchema)) query: ProviderListQuery,
  ): Promise<ProviderListView> {
    return this.providers.list(scope, query);
  }

  @Get('requirements')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get the identity-provider permission requirements',
    description:
      'For Microsoft and Google: the six least-privilege permission profiles (one app or ' +
      'service account each, consented through the provider connection’s grant routes), the ' +
      'permissions or scopes each stream and action needs, stream roles (primary, companion, ' +
      'unsupported), provider retention (the backfill bound), licences and notes. Static ' +
      'catalogue; the probe proves what is actually granted.',
  })
  @ApiProviderResponse(200, ProviderRequirementsSchema, X.requirements, 'The requirements')
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  requirements(): ProviderRequirementsView {
    return this.providers.requirements();
  }

  @Get('connections')
  @RequirePermissions(P.configure)
  @ApiOperation({
    summary: 'List provider connections that can be bound',
    description:
      'The Microsoft 365 and Google Workspace connections of your organization (step 8.2) ' +
      'with their eligibility for account takeover detection: `eligible`, `already_bound` ' +
      '(with `integrationId`), `wrong_provider` or `inactive` with the reasons ' +
      '(`connection_inactive`, `telemetry_grant_missing`, `telemetry_grant_inactive`), the ' +
      'number of provider-verified linked domains and, per ATO permission profile, the ' +
      'required, observed, missing and excess permissions. Empty while ATO is not enabled.',
  })
  @ApiProviderResponse(200, ProviderConnectionsSchema, X.connections, 'The connections')
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  connections(@CurrentScope() scope: TenantScope): Promise<ProviderConnectionsView> {
    return this.providers.connections(scope);
  }

  @Post()
  @RequirePermissions(P.configure)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.CREATED)
  @TransactionalIdempotency(O.providerCreate)
  @ApiOperation({
    summary: 'Bind a provider connection to account takeover detection',
    description:
      'Creates the identity-provider integration of a step 8.2 connection (`connectionId`) ' +
      'with optional `settings` (`ato-idp-binding/1`; defaults otherwise): the connection must ' +
      'be active with an active telemetry grant (`409 ato_provider_connection_ineligible` with ' +
      '`reasons`), not already bound (`409 ato_provider_already_bound` with `integrationId`), ' +
      'its provider directory not monitored by another integration (`409 ' +
      'ato_provider_directory_in_use`; the other organization is never named) and the ' +
      'organization below ATO_IDP_MAX_INTEGRATIONS_PER_ORG (`409 ato_provider_limit_reached`). ' +
      'Creates one stream row per stream (backfilling the last `backfillDays` days where the ' +
      'provider keeps them) and schedules the first probe now. A connection removed earlier is ' +
      'bound again under its previous id. Audited `ato.provider.bound`.' +
      MFA_RULE +
      PROVIDER_MUTATION_RULE,
  })
  @ApiBody({
    schema: withSettingsDoc(CreateProviderBodySchema),
    examples: { bind: { value: X.createBody } },
  })
  @ApiProviderResponse(201, ProviderDetailSchema, X.detail, 'The new integration', true)
  @ApiAtoKeyedErrors(
    [
      C.providerConnectionIneligible,
      C.providerAlreadyBound,
      C.providerDirectoryInUse,
      C.providerLimitReached,
    ],
    [],
    [C.providerSettingsInvalid],
  )
  @ApiProviderConnectionNotFound()
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(CreateProviderBodySchema)) body: CreateProviderBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ProviderDetailView> {
    return AtoProvidersController.replay(
      res,
      await this.providers.create(principal, scope, key, body, client.ip),
    );
  }

  @Get(':integrationId')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get an identity-provider integration',
    description:
      'The full view: the bound connection, settings with `rowVersion` (send with PATCH), ' +
      'health (status, last and next probe, the probe’s grants with missing permissions), every ' +
      'stream (role, enabled, status, availability, capability, watermark and lag, last ' +
      'attempt/success/event/error, failures, throttling, backfill, totals), every action ' +
      '(enabled, capability, rollback, confirmation, required configuration), required, ' +
      'granted and missing permissions per profile, and the directory domain count.' +
      FEATURE_OFF_READ,
  })
  @ApiIntegrationIdParam()
  @ApiProviderResponse(200, ProviderDetailSchema, X.detail, 'The integration')
  @ApiProviderNotFound()
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('integrationId') integrationId: string,
  ): Promise<ProviderDetailView> {
    return this.providers.get(scope, integrationId);
  }

  @Patch(':integrationId')
  @RequirePermissions(P.configure)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @TransactionalIdempotency(O.providerUpdate)
  @ApiOperation({
    summary: 'Update the settings of an identity-provider integration',
    description:
      'Replaces the `ato-idp-binding/1` settings (the full document) with `rowVersion` (`409 ' +
      'ato_provider_conflict` with `currentRowVersion`). Validated as a whole (`400 ' +
      'ato_provider_settings_invalid` with the failing paths: a companion stream needs its ' +
      'primary, `groupId` only for Microsoft, `orgUnitPath` only for Google, `backfillDays` ≤ ' +
      'ATO_IDP_BACKFILL_MAX_DAYS). Enabling a stream schedules it now. Audited ' +
      '`ato.provider.updated` with the changed paths. A removed integration answers `409 ' +
      'ato_provider_disabled`.' +
      MFA_RULE +
      PROVIDER_MUTATION_RULE,
  })
  @ApiIntegrationIdParam()
  @ApiBody({
    schema: withSettingsDoc(UpdateProviderBodySchema),
    examples: { update: { value: X.updateBody } },
  })
  @ApiProviderResponse(200, ProviderDetailSchema, X.detail, 'The updated integration', true)
  @ApiAtoKeyedErrors([C.providerConflict, C.providerDisabled], [], [C.providerSettingsInvalid])
  @ApiProviderNotFound()
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('integrationId') integrationId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(UpdateProviderBodySchema)) body: UpdateProviderBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ProviderDetailView> {
    return AtoProvidersController.replay(
      res,
      await this.providers.update(principal, scope, integrationId, key, body, client.ip),
    );
  }

  @Post(':integrationId/pause')
  @RequirePermissions(P.configure)
  @UserOnly()
  @HttpCode(HttpStatus.OK)
  @TransactionalIdempotency(O.providerPause)
  @ApiOperation({
    summary: 'Pause an identity-provider integration',
    description:
      'Stops every poll, probe and provider action of the integration (`status: paused`, ' +
      '`pausedReason: user`) until it is resumed; `reason` is audited ' +
      '(`ato.provider.paused`). Idempotent. A removed integration answers `409 ' +
      'ato_provider_disabled`.' +
      USER_RULE +
      PROVIDER_MUTATION_RULE,
  })
  @ApiIntegrationIdParam()
  @ApiBody({
    schema: zodToOpenApi(ProviderReasonBodySchema, { io: 'input' }),
    examples: { pause: { value: X.pauseBody } },
  })
  @ApiProviderResponse(200, ProviderDetailSchema, X.detail, 'The paused integration', true)
  @ApiAtoKeyedErrors([C.providerDisabled])
  @ApiProviderNotFound()
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async pause(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('integrationId') integrationId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(ProviderReasonBodySchema)) body: ProviderReasonBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ProviderDetailView> {
    return AtoProvidersController.replay(
      res,
      await this.providers.pause(principal, scope, integrationId, key, body, client.ip),
    );
  }

  @Post(':integrationId/resume')
  @RequirePermissions(P.configure)
  @UserOnly()
  @HttpCode(HttpStatus.OK)
  @TransactionalIdempotency(O.providerResume)
  @ApiOperation({
    summary: 'Resume an identity-provider integration',
    description:
      'Returns a paused (or failed) integration to `active` with its polls and a probe ' +
      'scheduled now; `409 ato_provider_connection_inactive` while the step 8.2 connection or ' +
      'its telemetry grant is not active. Idempotent. Audited `ato.provider.resumed`. No body.' +
      USER_RULE +
      PROVIDER_MUTATION_RULE,
  })
  @ApiIntegrationIdParam()
  @ApiProviderResponse(200, ProviderDetailSchema, X.detail, 'The resumed integration', true)
  @ApiAtoKeyedErrors([C.providerConnectionInactive, C.providerDisabled])
  @ApiProviderNotFound()
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async resume(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('integrationId') integrationId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ProviderDetailView> {
    return AtoProvidersController.replay(
      res,
      await this.providers.resume(principal, scope, integrationId, key, {}, client.ip),
    );
  }

  @Post(':integrationId/health-check')
  @RequirePermissions(P.configure)
  @HttpCode(HttpStatus.ACCEPTED)
  @TransactionalIdempotency(O.providerHealthCheck)
  @ApiOperation({
    summary: 'Request a probe of an identity-provider integration',
    description:
      'Schedules the read-only probe (connection, tokens per grant, one cheap read per stream, ' +
      'action prerequisites) for the ato-worker’s next tick and answers `202` with the current ' +
      'health. Audited `ato.provider.health_check_requested`. Users and API keys. No body.' +
      PROVIDER_MUTATION_RULE,
  })
  @ApiIntegrationIdParam()
  @ApiProviderResponse(
    202,
    ProviderHealthCheckSchema,
    X.healthCheck,
    'The probe is scheduled; the current health',
    true,
  )
  @ApiAtoKeyedErrors([C.providerDisabled])
  @ApiProviderNotFound()
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async healthCheck(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('integrationId') integrationId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ProviderHealthCheckView> {
    return AtoProvidersController.replay(
      res,
      await this.providers.healthCheck(principal, scope, integrationId, key, {}, client.ip),
    );
  }

  @Post(':integrationId/backfill')
  @RequirePermissions(P.configure)
  @UserOnly()
  @HttpCode(HttpStatus.ACCEPTED)
  @TransactionalIdempotency(O.providerBackfill)
  @ApiOperation({
    summary: 'Backfill provider telemetry of an integration',
    description:
      'Re-reads the enabled primary streams (or `streams`) from `from` (within ' +
      'ATO_IDP_BACKFILL_MAX_DAYS, clamped per stream to what the provider keeps; snapshot ' +
      'streams have no backfill). Backfilled events build history and baselines but never open ' +
      'incidents, propose responses or notify (historical mode). `202` with the integration; ' +
      '`409 ato_provider_backfill_active` while a stream is still backfilling; `422 ' +
      'ato_provider_backfill_range_invalid` with `reason` (`range`, `stream_not_backfillable`, ' +
      '`stream_disabled`, `no_stream`). Audited `ato.provider.backfill_requested`.' +
      USER_RULE +
      PROVIDER_MUTATION_RULE,
  })
  @ApiIntegrationIdParam()
  @ApiBody({
    schema: zodToOpenApi(BackfillBodySchema, { io: 'input' }),
    examples: { week: { value: X.backfillBody } },
  })
  @ApiProviderResponse(202, ProviderDetailSchema, X.detail, 'The backfill is scheduled', true)
  @ApiAtoKeyedErrors(
    [C.providerBackfillActive, C.providerDisabled],
    [C.providerBackfillRangeInvalid],
  )
  @ApiProviderNotFound()
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async backfill(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('integrationId') integrationId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(BackfillBodySchema)) body: BackfillBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ProviderDetailView> {
    return AtoProvidersController.replay(
      res,
      await this.providers.backfill(principal, scope, integrationId, key, body, client.ip),
    );
  }

  @Delete(':integrationId')
  @RequirePermissions(P.configure)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @TransactionalIdempotency(O.providerRemove)
  @ApiOperation({
    summary: 'Remove an identity-provider integration',
    description:
      'Disables the integration (`status: disabled`, `disabledReason: user`): every poll, ' +
      'probe and provider action stops; provider actions still in flight end `failed` with ' +
      '`integration_disabled`. Signals, authentication events and actions stay; stream rows ' +
      'and mailbox state are deleted by the worker after 30 days. The step 8.2 connection is ' +
      'not changed. `reason` is audited (`ato.provider.unbound`). Idempotent.' +
      MFA_RULE +
      PROVIDER_MUTATION_RULE,
  })
  @ApiIntegrationIdParam()
  @ApiBody({
    schema: zodToOpenApi(ProviderReasonBodySchema, { io: 'input' }),
    examples: { remove: { value: X.removeBody } },
  })
  @ApiProviderResponse(200, ProviderDetailSchema, X.detail, 'The removed integration', true)
  @ApiAtoKeyedErrors()
  @ApiProviderNotFound()
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('integrationId') integrationId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(ProviderReasonBodySchema)) body: ProviderReasonBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ProviderDetailView> {
    return AtoProvidersController.replay(
      res,
      await this.providers.remove(principal, scope, integrationId, key, body, client.ip),
    );
  }
}
