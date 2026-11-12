import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
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
import { ApiErrors } from '../../auth/api-docs';
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
} from '../dto/domains.schemas';
import { DomainsService } from '../services/domains.service';

/** Domains of the caller's organization (§4). The tenant always comes from the credential. */
@ApiTags('domains')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'domains', version: '1' })
export class DomainsController {
  constructor(private readonly domains: DomainsService) {}

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
      'most 60 per caller per minute (`429` with `Retry-After`).',
  })
  @ApiBody({ schema: zodToOpenApi(CreateDomainSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(CreatedDomainSchema) })
  @ApiErrors(400, 401, 403, 409, 429, 503)
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
