import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Put,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
  UserOnly,
} from '../../auth-contracts/decorators';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import { zodToOpenApi } from '../../validation/zod-openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { ApiErrors } from '../auth/api-docs';
import { Client } from '../auth/client-context.decorator';
import type { ClientContext } from '../auth/services/session.service';
import {
  type CreateRoleRequest,
  CreateRoleRequestSchema,
  PermissionListResponseSchema,
  type PermissionView,
  RoleKeySchema,
  RoleListResponseSchema,
  RoleResponseSchema,
  type RoleView,
  type UpdateRoleRequest,
  UpdateRoleRequestSchema,
} from './roles.schemas';
import { RolesService } from './roles.service';

/** The permission catalog (§4.2). */
@ApiTags('roles')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'permissions', version: '1' })
export class PermissionsController {
  constructor(private readonly roles: RolesService) {}

  @Get()
  @RequirePermissions('role:read')
  @ApiOperation({
    summary: 'List the permission catalog',
    description:
      '`platform:*` permissions are listed only for users of the platform organization (not ' +
      'under an override).',
  })
  @ApiOkResponse({ schema: zodToOpenApi(PermissionListResponseSchema) })
  @ApiErrors(401, 403, 503)
  async list(@CurrentPrincipal() principal: Principal): Promise<{ data: PermissionView[] }> {
    return { data: await this.roles.listPermissions(principal) };
  }
}

/** System and custom roles (D8, §4.2). Roles are addressed by key. */
@ApiTags('roles')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@Controller({ path: 'roles', version: '1' })
export class RolesController {
  constructor(private readonly roles: RolesService) {}

  @Get()
  @RequirePermissions('role:read')
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({
    summary: 'List roles',
    description:
      'System roles (platform roles only in the platform organization) and the custom roles of ' +
      'the organization, each with its permission keys. Read from the replica.',
  })
  @ApiOkResponse({ schema: zodToOpenApi(RoleListResponseSchema) })
  @ApiErrors(401, 403, 503)
  async list(@CurrentScope() scope: TenantScope): Promise<{ data: RoleView[] }> {
    return { data: await this.roles.list(scope) };
  }

  @Get(':key')
  @RequirePermissions('role:read')
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({ summary: 'Get a role by key' })
  @ApiParam({ name: 'key', example: 'organization_admin' })
  @ApiOkResponse({ schema: zodToOpenApi(RoleResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 503)
  get(
    @CurrentScope() scope: TenantScope,
    @Param('key', new ZodValidationPipe(RoleKeySchema)) key: string,
  ): Promise<RoleView> {
    return this.roles.get(scope, key);
  }

  @Post()
  @RequirePermissions('role:manage')
  @UserOnly()
  @ApiOperation({
    summary: 'Create a custom role',
    description:
      'Tenant permissions only, and only permissions the caller holds (no escalation). ' +
      'System role keys are reserved (`409`).',
  })
  @ApiBody({ schema: zodToOpenApi(CreateRoleRequestSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(RoleResponseSchema) })
  @ApiErrors(400, 401, 403, 409, 503)
  create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(CreateRoleRequestSchema)) body: CreateRoleRequest,
    @Client() client: ClientContext,
  ): Promise<RoleView> {
    return this.roles.create(principal, scope, body, client);
  }

  @Put(':key')
  @RequirePermissions('role:manage')
  @UserOnly()
  @ApiOperation({
    summary: 'Replace a custom role',
    description:
      'System roles are read-only (`409`). The caller must hold every old and new permission. ' +
      'Removing `user:manage` from the last administrators is a `409`.',
  })
  @ApiParam({ name: 'key' })
  @ApiBody({ schema: zodToOpenApi(UpdateRoleRequestSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(RoleResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 409, 503)
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('key', new ZodValidationPipe(RoleKeySchema)) key: string,
    @Body(new ZodValidationPipe(UpdateRoleRequestSchema)) body: UpdateRoleRequest,
    @Client() client: ClientContext,
  ): Promise<RoleView> {
    return this.roles.update(principal, scope, key, body, client);
  }

  @Delete(':key')
  @RequirePermissions('role:manage')
  @UserOnly()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete a custom role (`409` while assigned or for system roles)' })
  @ApiParam({ name: 'key' })
  @ApiNoContentResponse({ description: 'Role deleted' })
  @ApiErrors(400, 401, 403, 404, 409, 503)
  async remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('key', new ZodValidationPipe(RoleKeySchema)) key: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.roles.remove(principal, scope, key, client);
  }
}
