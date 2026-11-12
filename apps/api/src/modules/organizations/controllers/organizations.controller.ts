import { Body, Controller, Get, Param, Patch, Post, Put, Query } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import { LegacyIdempotent } from '../../../legacy-idempotency/legacy-idempotent';
import {
  CursorList,
  RequireAnyPermission,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import type { Page } from '../../../http/pagination';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import { CurrentUser } from '../../auth/current-user.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiOrganizationId, ApiQueryFrom } from '../api-docs';
import {
  ORGANIZATION_MANAGE,
  ORGANIZATION_READ,
  type OrganizationAccess,
  PLATFORM_ORGANIZATIONS,
} from '../domain/organization-access';
import {
  CreatedOrganizationResponseSchema,
  type CreateOrganizationInput,
  CreateOrganizationSchema,
  type ListOrganizationsQuery,
  ListOrganizationsQuerySchema,
  OrganizationPageResponseSchema,
  OrganizationResponseSchema,
  type StatusChangeInput,
  StatusChangeSchema,
  UpdateOrganizationDocSchema,
  type UpdateOrganizationInput,
  UpdateOrganizationSchema,
  type UsageQuery,
  UsageQuerySchema,
  UsageResponseSchema,
  UuidParamSchema,
} from '../dto/organizations.schemas';
import { OrgAccess } from '../organization-access.decorator';
import type { OrganizationResponse } from '../organization.mapper';
import {
  OrganizationUsageService,
  type UsageResponse,
} from '../services/organization-usage.service';
import {
  type CreatedOrganizationResponse,
  OrganizationsService,
} from '../services/organizations.service';

const idPipe = new ZodValidationPipe(UuidParamSchema);

/** Organization catalog and own-organization views (§4.3, D12). */
@ApiTags('organizations')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@Controller({ path: 'organizations', version: '1' })
export class OrganizationsController {
  constructor(
    private readonly organizations: OrganizationsService,
    private readonly usage: OrganizationUsageService,
  ) {}

  @Post()
  @RequirePermissions(PLATFORM_ORGANIZATIONS)
  @UserOnly()
  @ApiOperation({
    summary: 'Create a customer organization',
    description:
      'Platform catalog function. Materializes settings, the plan limits and features, the ' +
      'deployment row and optionally invites an initial administrator (organization_admin).',
  })
  @ApiBody({ schema: zodToOpenApi(CreateOrganizationSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(CreatedOrganizationResponseSchema) })
  @ApiErrors(400, 401, 403, 409)
  create(
    @CurrentUser() principal: UserPrincipal,
    @OrgAccess() access: OrganizationAccess,
    @Body(new ZodValidationPipe(CreateOrganizationSchema)) body: CreateOrganizationInput,
    @Client() client: ClientContext,
  ): Promise<CreatedOrganizationResponse> {
    return this.organizations.create(principal, access, body, client);
  }

  @Get()
  @CursorList('v0')
  @RequireAnyPermission(ORGANIZATION_READ, PLATFORM_ORGANIZATIONS)
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({
    summary: 'List organizations',
    description:
      'With platform:organizations: every organization (deleted ones only with status=deleted). ' +
      'Otherwise only the caller’s own organization. Served from the read replica.',
  })
  @ApiQueryFrom(ListOrganizationsQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(OrganizationPageResponseSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @OrgAccess() access: OrganizationAccess,
    @Query(new ZodValidationPipe(ListOrganizationsQuerySchema)) query: ListOrganizationsQuery,
  ): Promise<Page<OrganizationResponse>> {
    return this.organizations.list(access, query);
  }

  @Get(':id')
  @RequireAnyPermission(ORGANIZATION_READ, PLATFORM_ORGANIZATIONS)
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({ summary: 'Get an organization' })
  @ApiOrganizationId()
  @ApiOkResponse({ schema: zodToOpenApi(OrganizationResponseSchema) })
  @ApiErrors(400, 401, 403, 404)
  get(
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
  ): Promise<OrganizationResponse> {
    return this.organizations.get(access, id);
  }

  @Put(':id')
  @RequireAnyPermission(ORGANIZATION_MANAGE, PLATFORM_ORGANIZATIONS)
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({
    summary: 'Update an organization',
    description:
      'Name (own organization with organization:manage, or platform). planCode requires ' +
      'platform:organizations; a plan change re-materializes plan-sourced limits and features ' +
      'and keeps overrides. slug, kind, deploymentMode and dataRegion are immutable (400).',
  })
  @ApiOrganizationId()
  @ApiBody({ schema: zodToOpenApi(UpdateOrganizationDocSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(OrganizationResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 409)
  update(
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
    @Body(new ZodValidationPipe(UpdateOrganizationSchema)) body: UpdateOrganizationInput,
    @Client() client: ClientContext,
  ): Promise<OrganizationResponse> {
    return this.organizations.update(access, id, body, client);
  }

  @Patch(':id/status')
  @LegacyIdempotent({
    operation: 'organization.status_change',
    legacy: true,
    publicFields: ['code'],
  })
  @RequirePermissions(PLATFORM_ORGANIZATIONS)
  @UserOnly()
  @ApiOperation({
    summary: 'Suspend or reactivate an organization',
    description:
      'Only active ↔ suspended; the platform organization cannot be suspended. Suspension ' +
      'revokes every session of the organization and stops its API keys immediately.',
  })
  @ApiOrganizationId()
  @ApiBody({ schema: zodToOpenApi(StatusChangeSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(OrganizationResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 409)
  changeStatus(
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
    @Body(new ZodValidationPipe(StatusChangeSchema)) body: StatusChangeInput,
    @Client() client: ClientContext,
  ): Promise<OrganizationResponse> {
    return this.organizations.changeStatus(access, id, body, client);
  }

  @Get(':id/usage')
  @RequireAnyPermission(ORGANIZATION_READ, PLATFORM_ORGANIZATIONS)
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({
    summary: 'Organization usage',
    description:
      'Counts of users, domains, messages (by direction, in the period, and today in UTC), ' +
      'active quarantine items, API keys and sessions, and the limits with their current use. ' +
      'Period: default the last 30 days, at most 31 days. Served from the read replica.',
  })
  @ApiOrganizationId()
  @ApiQueryFrom(UsageQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(UsageResponseSchema) })
  @ApiErrors(400, 401, 403, 404)
  getUsage(
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
    @Query(new ZodValidationPipe(UsageQuerySchema)) query: UsageQuery,
  ): Promise<UsageResponse> {
    return this.usage.get(access, id, query);
  }
}
