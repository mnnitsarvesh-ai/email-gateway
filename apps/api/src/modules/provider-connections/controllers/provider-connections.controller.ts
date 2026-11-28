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
  UseFilters,
} from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { RateClass } from '../../../rate-limit/rate-class.decorator';
import { ApiCodedError, CodedExceptionFilter } from '../../../http/coded-exception';
import {
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
} from '../../../http/idempotency/idempotency-key';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiListErrors, ApiListQuery, ApiOkExample } from '../../messages/api-docs';
import {
  ApiConnectionBasics,
  ApiConnectionId,
  ApiConnectionNotFound,
  ApiKeyedBadRequest,
  ApiKeyedConflict,
  ApiKeyedResponse,
  ApiKeyedUnprocessable,
  ApiUnavailable,
  KEYED_RULE,
  ProviderIdempotency,
} from '../api-docs';
import {
  type AttestationsView,
  AttestationBodySchema,
  type CatalogView,
  CatalogSchema,
  type ConnectionDetailView,
  ConnectionDetailSchema,
  CONNECTION_LIST_PARAMETERS,
  type ConnectionListQuery,
  ConnectionListQuerySchema,
  type ConnectionPage,
  ConnectionPageSchema,
  AttestationsSchema,
  CreateConnectionBodySchema,
  DisconnectBodySchema,
  type DisconnectedView,
  DisconnectedSchema,
  HealthCheckAcceptedSchema,
  type HealthCheckAccepted,
  HealthSchema,
  type HealthView,
  type LinkedDomainList,
  LinkedDomainListSchema,
  PROVIDER_EXAMPLES,
  ReplaceDomainsBodySchema,
  type UpdateConnectionBody,
  UpdateConnectionBodySchema,
  WizardSchema,
  type WizardView,
} from '../dto/provider-connections.schemas';
import {
  CONNECTOR_MANAGE,
  INTEGRATION_MANAGE,
  INTEGRATION_READ,
  PROVIDER_OPERATIONS,
} from '../provider-connections.constants';
import { PROVIDER_ERROR_CODES as C } from '../provider-connections.errors';
import { ProviderRateLimit } from '../provider-connections-rate-limit';
import { ProviderConnectionsService } from '../services/provider-connections.service';
import { ProviderMailFlowService } from '../services/provider-mail-flow.service';

/**
 * The provider catalogue (step 8.2 §5.2 #1): what can be connected on this deployment. Translation
 * only (ProviderConnectionsService).
 */
@ApiTags('provider-connections')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'provider-integrations', version: '1' })
export class ProviderCatalogController {
  constructor(private readonly connections: ProviderConnectionsService) {}

  @Get('catalog')
  @RequirePermissions(INTEGRATION_READ)
  @ApiOperation({
    summary: 'Get the Microsoft 365 / Google Workspace catalogue',
    description:
      'The providers, their read-only permission profiles (key, version, permissions, the ' +
      'authentication methods and which of them this deployment offers: platform methods need ' +
      'the operator’s app or service account), the attestation codes of each provider’s guide, ' +
      'the probe domain, the gateway values used by the setup guides and the active provider ' +
      'egress range set per provider. Never a secret.',
  })
  @ApiOkExample(CatalogSchema, {
    providers: [
      {
        provider: 'microsoft_365',
        displayName: 'Microsoft 365',
        profiles: [
          {
            key: 'm365.mail_flow',
            version: 1,
            purpose: 'mail_flow',
            title: 'Microsoft 365 mail flow (read-only)',
            description:
              'Reads your tenant id and name and the verification state of your domains.',
            permissions: ['Organization.Read.All', 'Domain.Read.All'],
            readOnly: true,
            authMethods: ['platform_app', 'customer_app_secret'],
            availableAuthMethods: ['platform_app', 'customer_app_secret'],
          },
        ],
        attestations: [
          {
            code: 'm365.inbound_connector_created',
            phase: 'inbound',
            statement: 'The inbound partner connector exists.',
            requiredFor: 'inbound',
          },
        ],
        egressSet: {
          version: 1,
          publishedAt: '2026-06-01T00:00:00.000Z',
          importedAt: '2026-11-18T07:12:00.000Z',
          rangeCount: 8,
        },
      },
    ],
    probeDomain: 'probe.mail-gateway.example',
    gateway: {
      mxHosts: ['mx1.gateway.example'],
      egressNetworks: ['192.0.2.10/32'],
      relayHosts: ['out.gateway.example'],
      relayTlsName: 'out.gateway.example',
      spfInclude: '_spf.gateway.example',
    },
  })
  @ApiErrors(401, 403)
  @ApiUnavailable()
  get(): Promise<CatalogView> {
    return this.connections.catalog();
  }
}

/**
 * Microsoft 365 / Google Workspace connections of the caller's organization (step 8.2 §5.2 #2–7).
 * Translation only (ProviderConnectionsService, ProviderMailFlowService).
 */
@ApiTags('provider-connections')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'provider-connections', version: '1' })
export class ProviderConnectionsController {
  constructor(
    private readonly connections: ProviderConnectionsService,
    private readonly mailFlow: ProviderMailFlowService,
  ) {}

  @Get()
  @RequirePermissions(INTEGRATION_READ)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List provider connections',
    description:
      'Your organization’s Microsoft 365 / Google Workspace connections, newest first, with ' +
      'status, tenant name, outbound mode, internal routing, health and the number of linked ' +
      'domains. Pages follow the v1 list contract (signed cursor bound to the filters and your ' +
      'organization). From the read replica.',
  })
  @ApiListQuery(ConnectionListQuerySchema, CONNECTION_LIST_PARAMETERS)
  @ApiOkExample(ConnectionPageSchema, PROVIDER_EXAMPLES.page)
  @ApiListErrors()
  @ApiErrors(401, 403)
  @ApiUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ConnectionListQuerySchema)) query: ConnectionListQuery,
  ): Promise<ConnectionPage> {
    return this.connections.list(principal, scope, query);
  }

  @Post()
  @RequirePermissions(INTEGRATION_MANAGE)
  @ProviderIdempotency(PROVIDER_OPERATIONS.create, null)
  @ApiOperation({
    summary: 'Create a provider connection',
    description:
      '`{ provider, displayName }` → a `draft` connection; grant access next (`POST ' +
      '…/grants`). At most PROVIDER_MAX_CONNECTIONS_PER_ORG live connections (`409 ' +
      'connection_limit`); the name is unique in your organization (`409 ' +
      'connection_name_exists`). Audited `integration.connection_created`.' +
      KEYED_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(CreateConnectionBodySchema, { io: 'input' }),
    examples: { m365: { value: PROVIDER_EXAMPLES.create } },
  })
  @ApiKeyedResponse(201, ConnectionDetailSchema, PROVIDER_EXAMPLES.created, 'Created')
  @ApiKeyedBadRequest()
  @ApiErrors(401, 403)
  @ApiKeyedConflict(
    [C.connectionLimit, C.connectionNameExists],
    '`connection_limit`, `connection_name_exists`',
  )
  @ApiKeyedUnprocessable()
  @ApiUnavailable()
  async create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ConnectionDetailView> {
    const result = await this.connections.create(
      principal,
      scope,
      { idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get(':id')
  @RequirePermissions(INTEGRATION_READ)
  @ApiOperation({
    summary: 'Get a provider connection',
    description:
      'The connection with its grants (status, method, client id, the masked delegated ' +
      'administrator, the 12-character credential fingerprint, credential dates, missing and ' +
      'excess permissions, last error code — never a credential), linked domains, the relay ' +
      'connector id, the relay proof policy, attestations, health and `rowVersion`. From the ' +
      'read replica.',
  })
  @ApiConnectionId()
  @ApiOkExample(ConnectionDetailSchema, PROVIDER_EXAMPLES.detail)
  @ApiErrors(400, 401, 403)
  @ApiConnectionBasics()
  get(@CurrentScope() scope: TenantScope, @Param('id') id: string): Promise<ConnectionDetailView> {
    return this.connections.get(scope, id);
  }

  @Patch(':id')
  @RequirePermissions(INTEGRATION_MANAGE)
  @ApiOperation({
    summary: 'Rename a provider connection',
    description:
      '`{ displayName, rowVersion }` only (`409 connection_version_conflict` with ' +
      '`currentRowVersion`); mail-flow fields change through preview → apply. Audited ' +
      '`integration.connection_updated`.',
  })
  @ApiConnectionId()
  @ApiBody({
    schema: zodToOpenApi(UpdateConnectionBodySchema, { io: 'input' }),
    examples: { rename: { value: PROVIDER_EXAMPLES.update } },
  })
  @ApiOkExample(ConnectionDetailSchema, { ...PROVIDER_EXAMPLES.detail, rowVersion: 8 })
  @ApiErrors(400, 401, 403)
  @ApiConnectionBasics()
  @ApiCodedError(
    409,
    '`connection_version_conflict` (`currentRowVersion`), `connection_name_exists`, ' +
      '`connection_disabled`',
    [C.connectionVersionConflict, C.connectionNameExists, C.connectionDisabled],
    { currentRowVersion: { type: 'integer' } },
  )
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Body(new ZodValidationPipe(UpdateConnectionBodySchema)) body: UpdateConnectionBody,
    @Client() client: ClientContext,
  ): Promise<ConnectionDetailView> {
    return this.connections.update(principal, scope, id, body, client.ip);
  }

  @Delete(':id')
  @RequirePermissions(INTEGRATION_MANAGE, CONNECTOR_MANAGE)
  @HttpCode(HttpStatus.OK)
  @ProviderIdempotency(PROVIDER_OPERATIONS.disconnect)
  @RateClass('sensitive')
  @ApiOperation({
    summary: 'Disconnect a provider connection',
    description:
      '`{ impactToken, confirm: true }` with the token of `POST …/mail-flow/preview { change: { ' +
      'kind: "disable" } }`. In one writer transaction: grants revoked and their credentials ' +
      'wiped, the relay connector disabled (kept for history), outbound and internal routing ' +
      'off, status `disabled`, the tenant binding released. Inbound destinations are KEPT ' +
      '(removing them would break inbound mail; change them on the domain’s destinations ' +
      'page). Returns the provider-side cleanup steps. `409 impact_changed` when the connection ' +
      'changed since the preview. Audited `integration.connection_disconnected`.' +
      KEYED_RULE,
  })
  @ApiConnectionId()
  @ApiBody({
    schema: zodToOpenApi(DisconnectBodySchema, { io: 'input' }),
    examples: { disconnect: { value: PROVIDER_EXAMPLES.disconnect } },
  })
  @ApiKeyedResponse(200, DisconnectedSchema, PROVIDER_EXAMPLES.disconnected, 'Disconnected')
  @ApiKeyedBadRequest()
  @ApiErrors(401, 403)
  @ApiConnectionBasics()
  @ApiKeyedConflict(
    [C.impactChanged, C.connectionDisabled, C.connectionVersionConflict],
    '`impact_changed` (preview again), `connection_disabled`',
  )
  @ApiKeyedUnprocessable()
  async disconnect(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<DisconnectedView> {
    const result = await this.mailFlow.disconnect(
      principal,
      scope,
      { id, idempotencyKey, body },
      client,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get(':id/wizard')
  @RequirePermissions(INTEGRATION_READ)
  @ApiOperation({
    summary: 'Get the setup wizard of a connection',
    description:
      'The six steps (`connect`, `domains`, `inbound`, `outbound`, `validate`, `activate`) with ' +
      'their status (`not_started`, `in_progress`, `done`, `blocked`, `skipped`), blocker codes ' +
      'and the next action, computed from the stored rows (never a stored pointer, ADR-0080).',
  })
  @ApiConnectionId()
  @ApiOkExample(WizardSchema, PROVIDER_EXAMPLES.wizard)
  @ApiErrors(400, 401, 403)
  @ApiConnectionBasics()
  wizard(@CurrentScope() scope: TenantScope, @Param('id') id: string): Promise<WizardView> {
    return this.connections.wizard(scope, id);
  }
}

/** Linked gateway domains of a connection (step 8.2 §5.2 #13, #14; D4). */
@ApiTags('provider-connections')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'provider-connections/:id/domains', version: '1' })
export class ProviderDomainsController {
  constructor(private readonly connections: ProviderConnectionsService) {}

  @Get()
  @RequirePermissions(INTEGRATION_READ)
  @ApiOperation({
    summary: 'List the linked domains of a connection',
    description:
      'Name, gateway status, provider verification (evidence: gateway ownership stays TXT ' +
      'verification), the tenant’s MX target (Microsoft 365), the provider of the current ' +
      'destinations, when inbound was applied and the stored MX/SPF/DKIM record statuses.',
  })
  @ApiConnectionId()
  @ApiOkExample(LinkedDomainListSchema, PROVIDER_EXAMPLES.domains)
  @ApiErrors(400, 401, 403)
  @ApiConnectionBasics()
  list(@CurrentScope() scope: TenantScope, @Param('id') id: string): Promise<LinkedDomainList> {
    return this.connections.domains(scope, id);
  }

  @Put()
  @RequirePermissions(INTEGRATION_MANAGE)
  @HttpCode(HttpStatus.OK)
  @ProviderIdempotency(PROVIDER_OPERATIONS.domainsReplace, null)
  @ApiOperation({
    summary: 'Replace the linked domains of a connection',
    description:
      '`{ domainIds }` replaces the set (≤ PROVIDER_MAX_DOMAINS_PER_CONNECTION). Each domain must ' +
      'be yours (`404 domain_not_in_organization`), `verified` or `active` at the gateway ' +
      '(step API-4 B4; `pending_verification` → `422 domain_not_verified`) and not linked to another connection (`409 ' +
      'domain_linked_elsewhere`); unlinking needs outbound off (`409 outbound_active`). The ' +
      'integration-worker checks the new domains in the provider tenant on its next health run ' +
      '(requested now). Audited `integration.domains_linked`.' +
      KEYED_RULE,
  })
  @ApiConnectionId()
  @ApiBody({
    schema: zodToOpenApi(ReplaceDomainsBodySchema, { io: 'input' }),
    examples: { one: { value: PROVIDER_EXAMPLES.replaceDomains } },
  })
  @ApiKeyedResponse(200, LinkedDomainListSchema, PROVIDER_EXAMPLES.domains, 'The linked domains')
  @ApiKeyedBadRequest()
  @ApiErrors(401, 403)
  @ApiConnectionNotFound([C.domainNotInOrganization])
  @ApiUnavailable()
  @ApiKeyedConflict(
    [C.domainLinkedElsewhere, C.outboundActive, C.connectionDisabled, C.connectionVersionConflict],
    '`domain_linked_elsewhere` (`domainId`), `outbound_active`, `connection_disabled`',
  )
  @ApiKeyedUnprocessable([C.domainNotVerified], '`domain_not_verified` (`domainId`)')
  async replace(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LinkedDomainList> {
    const result = await this.connections.replaceDomains(
      principal,
      scope,
      { id, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}

/** Attestations of customer-side steps (step 8.2 §5.2 #18; D13). */
@ApiTags('provider-connections')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'provider-connections/:id/attestations', version: '1' })
export class ProviderAttestationsController {
  constructor(private readonly connections: ProviderConnectionsService) {}

  @Post()
  @RequirePermissions(INTEGRATION_MANAGE)
  @HttpCode(HttpStatus.OK)
  @ProviderIdempotency(PROVIDER_OPERATIONS.attestationRecord, null)
  @ApiOperation({
    summary: 'Record an attestation of a customer-side step',
    description:
      '`{ code, attested }` with a code of the provider’s setup guide (`422 ' +
      'attestation_unknown`); `false` withdraws it. Attestations are statements by your ' +
      'administrator, not proofs (the gateway cannot observe customer-side configuration). ' +
      'Attesting `m365.internal_routing_rules_updated` during a route-token rotation switches to ' +
      'the new token. Audited `integration.attestation_recorded`.' +
      KEYED_RULE,
  })
  @ApiConnectionId()
  @ApiBody({
    schema: zodToOpenApi(AttestationBodySchema, { io: 'input' }),
    examples: { inbound: { value: PROVIDER_EXAMPLES.attestation } },
  })
  @ApiKeyedResponse(200, AttestationsSchema, PROVIDER_EXAMPLES.attestations, 'Recorded')
  @ApiKeyedBadRequest()
  @ApiErrors(401, 403)
  @ApiConnectionBasics()
  @ApiKeyedConflict([C.connectionDisabled, C.connectionVersionConflict], '`connection_disabled`')
  @ApiKeyedUnprocessable([C.attestationUnknown], '`attestation_unknown`')
  async record(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AttestationsView> {
    const result = await this.connections.recordAttestation(
      principal,
      scope,
      { id, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}

/** Health of a connection (step 8.2 §5.2 #22, #23; D11). */
@ApiTags('provider-connections')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'provider-connections/:id/health', version: '1' })
export class ProviderHealthController {
  constructor(private readonly connections: ProviderConnectionsService) {}

  @Get()
  @RequirePermissions(INTEGRATION_READ)
  @ApiOperation({
    summary: 'Get the health of a connection',
    description:
      'The status (worst failing check), the latest result of every check (code, title, ' +
      'subject, status, severity, bounded non-secret evidence) and the last 20 transitions. ' +
      'Health never changes mail flow automatically.',
  })
  @ApiConnectionId()
  @ApiOkExample(HealthSchema, PROVIDER_EXAMPLES.health)
  @ApiErrors(400, 401, 403)
  @ApiConnectionBasics()
  get(@CurrentScope() scope: TenantScope, @Param('id') id: string): Promise<HealthView> {
    return this.connections.health(scope, id);
  }

  @Post('check')
  @RequirePermissions(INTEGRATION_MANAGE)
  @HttpCode(HttpStatus.ACCEPTED)
  @ProviderIdempotency(PROVIDER_OPERATIONS.healthCheck, null)
  @ProviderRateLimit('health_check')
  @ApiOperation({
    summary: 'Check the health of a connection now',
    description:
      'Asks the integration-worker to run the periodic checks now (`next_health_check_at = ' +
      'now`); `202`. At most 6 per connection per hour (`429 rate_limited`, `scope: route`). ' +
      'Audited `integration.health_check_requested`.' +
      KEYED_RULE,
  })
  @ApiConnectionId()
  @ApiKeyedResponse(202, HealthCheckAcceptedSchema, PROVIDER_EXAMPLES.healthCheck, 'Requested')
  @ApiKeyedBadRequest()
  @ApiErrors(401, 403)
  @ApiConnectionBasics()
  @ApiKeyedConflict([C.connectionDisabled, C.connectionVersionConflict], '`connection_disabled`')
  @ApiKeyedUnprocessable()
  async checkNow(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<HealthCheckAccepted> {
    const result = await this.connections.checkNow(
      principal,
      scope,
      { id, idempotencyKey },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}
