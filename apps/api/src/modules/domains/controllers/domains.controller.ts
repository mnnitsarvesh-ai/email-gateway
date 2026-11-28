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
  UseInterceptors,
} from '@nestjs/common';
import type { Response } from 'express';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import {
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
} from '../../../http/idempotency/idempotency-key';
import { ArchiveIdempotency } from '../../archive/api-docs';
import { PROVIDER_CHECK_OPERATION } from '../domains.constants';
import { DOMAIN_PROVIDER_ERROR_CODES } from '../domains.errors';
import { DomainProviderOwnershipService } from '../services/domain-provider-ownership.service';
import { RetryAfterInterceptor } from './retry-after.interceptor';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import type { Page } from '../../../http/pagination';
import { RateLimit } from '../../../rate-limit/rate-limit.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiCodedError } from '../../../http/coded-exception';
import { ApiErrors } from '../../auth/api-docs';
import { PROVIDER_ERROR_CODES } from '../../provider-connections/provider-connections.errors';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiQueryFrom } from '../../organizations/api-docs';
import { ApiDomainId, DOMAIN_MANAGE, DOMAIN_READ, domainIdPipe } from '../api-docs';
import {
  type CreatedDomain,
  CreatedDomainSchema,
  type CreateDomainInput,
  CreateDomainSchema,
  type DomainDetail,
  DomainDetailSchema,
  DomainPageSchema,
  type DomainStatusChangeInput,
  DomainStatusChangeSchema,
  type DomainSummary,
  type ListDomainsQuery,
  ListDomainsQuerySchema,
  PROVIDER_CHECK_EXAMPLES,
  ProviderOwnershipCheckBodySchema,
  type ProviderOwnershipCheckResponse,
  ProviderOwnershipCheckResponseSchema,
} from '../dto/domains.schemas';
import { DomainsService } from '../services/domains.service';
import { MAIL_FILTERING_NOT_ENABLED } from '../domains.errors';
import { API_MODE_ERROR_CODES } from '../../api-mode/api-mode.errors';

/** The keyed-mutation rule of the provider ownership check (step API-4). */
const PROVIDER_CHECK_KEYED_RULE =
  ' Requires the Idempotency-Key header (transactional: the request, its audit row and the ' +
  'stored response commit together; a repeat with the same key returns the stored response with ' +
  '`Idempotency-Replayed: true`); rate class `sensitive`.';

/** Domains of the caller's organization (§4). The tenant always comes from the credential. */
@ApiTags('domains')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'domains', version: '1' })
export class DomainsController {
  constructor(
    private readonly domains: DomainsService,
    private readonly providerOwnership: DomainProviderOwnershipService,
  ) {}

  @Post()
  @RequirePermissions(DOMAIN_MANAGE)
  @RateLimit({ bucket: 'domains-create', limit: 60, windowSeconds: 60, by: 'principal' })
  @ApiOperation({
    summary: 'Add a domain',
    description:
      'Normalizes the name (IDN → punycode, lower case, one trailing dot ignored), enforces ' +
      '`max_domains`, and creates the ownership challenge, a DKIM key (RSA 2048, plus Ed25519 ' +
      'on request) and the DNS records to publish. `409` when the organization already has the ' +
      'name or another organization owns it. The first check runs about a minute later. At ' +
      'most 60 per caller per minute (`429` with `Retry-After`). The platform probe domain ' +
      '(`PROVIDER_PROBE_DOMAIN`, step 8.2), the journal intake domain (`JOURNAL_INTAKE_DOMAIN`, ' +
      'step 8.6) and names under them are `422 domain_reserved`. Step 8.6: an archive-only ' +
      'organization (`serviceProfile: archive_only`) gets the domain with inbound mail flow off; ' +
      '`inboundEnabled: true` is refused there (`403 mail_filtering_not_enabled`). Step API-1 ' +
      '(ADR-0098): optional `protectionMode` (`inline`, `api`, `hybrid`; absent = inherit the ' +
      'organization’s mode); `api` and `hybrid` need the plan feature `api_mode_protection` (`403 ' +
      'api_mode_not_enabled`); a domain whose effective mode is `api` is created with inbound ' +
      'mail flow off, and `protectionMode: api` with `inboundEnabled: true` is `422 ' +
      'protection_mode_inbound_conflict`.',
  })
  @ApiBody({ schema: zodToOpenApi(CreateDomainSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(CreatedDomainSchema) })
  @ApiErrors(400, 401, 409, 429, 503)
  @ApiCodedError(
    422,
    '`domain_reserved`: the platform probe domain (step 8.2), the journal intake domain (step ' +
      '8.6) or a name under them; `protection_mode_inbound_conflict` (step API-1)',
    [PROVIDER_ERROR_CODES.domainReserved, API_MODE_ERROR_CODES.inboundConflict],
  )
  @ApiCodedError(
    403,
    'Missing permission (`forbidden`), or `inboundEnabled: true` for an archive-only ' +
      'organization (`mail_filtering_not_enabled`, step 8.6), or `api`/`hybrid` without the ' +
      'plan feature `api_mode_protection` (`api_mode_not_enabled`, step API-1)',
    ['forbidden', MAIL_FILTERING_NOT_ENABLED, API_MODE_ERROR_CODES.notEnabled],
  )
  create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(CreateDomainSchema)) body: CreateDomainInput,
    @Client() client: ClientContext,
  ): Promise<CreatedDomain> {
    return this.domains.create(principal, scope, body, client);
  }

  @Get()
  @CursorList('v0')
  @RequirePermissions(DOMAIN_READ)
  @ApiOperation({
    summary: 'List domains',
    description: 'Non-deleted domains, newest first, cursor-paginated, from the read replica.',
  })
  @ApiQueryFrom(ListDomainsQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(DomainPageSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ListDomainsQuerySchema)) query: ListDomainsQuery,
  ): Promise<Page<DomainSummary>> {
    return this.domains.list(scope, query);
  }

  @Get(':id')
  @RequirePermissions(DOMAIN_READ)
  @ApiOperation({ summary: 'Get a domain', description: 'Verification state and DKIM keys.' })
  @ApiDomainId()
  @ApiOkResponse({ schema: zodToOpenApi(DomainDetailSchema) })
  @ApiErrors(400, 401, 403, 404)
  get(
    @CurrentScope() scope: TenantScope,
    @Param('id', domainIdPipe) id: string,
  ): Promise<DomainDetail> {
    return this.domains.get(scope, id);
  }

  @Patch(':id/status')
  @RequirePermissions(DOMAIN_MANAGE)
  @ApiOperation({
    summary: 'Activate, suspend or resume a domain',
    description:
      '`verified → active`, `active → suspended` (reason required), `suspended → active`. ' +
      'Activation needs verified ownership only, so the gateway can be activated before the MX ' +
      'records are switched. Any other transition is `409`.',
  })
  @ApiDomainId()
  @ApiBody({ schema: zodToOpenApi(DomainStatusChangeSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(DomainDetailSchema) })
  @ApiErrors(400, 401, 403, 404, 409)
  changeStatus(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', domainIdPipe) id: string,
    @Body(new ZodValidationPipe(DomainStatusChangeSchema)) body: DomainStatusChangeInput,
    @Client() client: ClientContext,
  ): Promise<DomainDetail> {
    return this.domains.changeStatus(principal, scope, id, body, client);
  }

  @Post(':domainId/ownership/provider-check')
  @RequirePermissions(DOMAIN_MANAGE)
  @HttpCode(HttpStatus.ACCEPTED)
  @UseInterceptors(RetryAfterInterceptor)
  @ArchiveIdempotency(PROVIDER_CHECK_OPERATION)
  @ApiOperation({
    summary: 'Verify ownership through the bound provider tenant',
    description:
      'Step API-4 (ADR-0107): requests an ownership check of a domain waiting for verification ' +
      'through the organization’s **bound** Microsoft 365 / Google Workspace connection (tenant ' +
      'verified, not disabled, active `*.mail_flow` grant). `{ connectionId? }` picks the ' +
      'connection (optional when exactly one qualifies or the previous check used one that still ' +
      'does; else `409 domain_provider_connection_unavailable` with `reason`). A `failed` domain ' +
      'is restarted first exactly as `POST /domains/{id}/verify`; a name owned by another ' +
      'organization is `409`; a domain that is not waiting is `409 domain_not_pending`; an ' +
      'unknown connection is `404 connection_not_found`. A pending provider check of the domain ' +
      'with the same connection is reused. The integration-worker asks the provider (verified ' +
      'for e-mail only); the domain scheduler then applies the answer through the same ' +
      'first-to-verify-wins transaction as a TXT check (`ownership_method = provider_tenant`, ' +
      'audit `domain.verified` with `{ method, connectionId }`); any other answer fails the ' +
      'check only (the domain stays pending, TXT still works); no answer within ' +
      'DOMAIN_PROVIDER_CHECK_TTL_MINUTES expires it. Provider-proven domains never prove a ' +
      'tenant binding. Audited `domain.provider_verification_requested`. At most ' +
      'DOMAIN_PROVIDER_CHECKS_PER_HOUR per organization per hour (`429` with `Retry-After`).' +
      PROVIDER_CHECK_KEYED_RULE,
  })
  @ApiParam({ name: 'domainId', description: 'Domain public id (UUID)', format: 'uuid' })
  @ApiBody({
    schema: zodToOpenApi(ProviderOwnershipCheckBodySchema, { io: 'input' }),
    examples: { bound: { value: PROVIDER_CHECK_EXAMPLES.body } },
  })
  @ApiResponse({
    status: 202,
    description: 'The pending provider check',
    content: {
      'application/json': {
        schema: zodToOpenApi(ProviderOwnershipCheckResponseSchema),
        example: PROVIDER_CHECK_EXAMPLES.response,
      },
    },
  })
  @ApiErrors(400, 401, 404, 429, 503)
  @ApiCodedError(403, 'Missing permission (`forbidden`)', ['forbidden'])
  @ApiCodedError(
    409,
    '`domain_provider_connection_unavailable` (`reason`: `none`, `not_capable`, ' +
      '`connection_required` with `candidates`), `domain_not_pending` (`status`), the name is ' +
      'owned by another organization, or an Idempotency-Key conflict',
    [
      DOMAIN_PROVIDER_ERROR_CODES.connectionUnavailable,
      DOMAIN_PROVIDER_ERROR_CODES.notPending,
      'idempotency_key_conflict',
      'idempotency_key_in_progress',
    ],
  )
  @ApiCodedError(422, 'Idempotency-Key reused with a different request', ['idempotency_key_reused'])
  async providerOwnershipCheck(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('domainId', domainIdPipe) domainId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ProviderOwnershipCheckResponse> {
    const result = await this.providerOwnership.request(
      principal,
      scope,
      domainId,
      { idempotencyKey, body },
      client,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Delete(':id')
  @RequirePermissions(DOMAIN_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete a domain',
    description:
      'Soft delete: the name is freed, checks stop and every DKIM key is revoked. An active ' +
      'domain must be suspended first (`409`).',
  })
  @ApiDomainId()
  @ApiNoContentResponse({ description: 'Deleted' })
  @ApiErrors(400, 401, 403, 404, 409)
  remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', domainIdPipe) id: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    return this.domains.remove(principal, scope, id, client);
  }
}
