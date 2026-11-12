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
  ApiBody,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
} from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiQueryFrom } from '../../organizations/api-docs';
import {
  ApiDepartmentConflict,
  ApiDepartmentId,
  ApiDepartmentNotFound,
  ApiDirectoryInconsistentRead,
  ApiMemberId,
  ApiMemberInvalid,
  ApiMemberNotFound,
  DepartmentsController as DepartmentsApi,
  departmentIdPipe,
  memberIdPipe,
  USER_MANAGE,
  USER_READ,
} from '../api-docs';
import {
  DEPARTMENT_CONFLICT,
  DEPARTMENT_IN_USE,
  DEPARTMENT_LIMIT_REACHED,
  DEPARTMENT_MEMBER_EXISTS,
  DEPARTMENT_MEMBER_LIMIT_REACHED,
  DEPARTMENT_NAME_TAKEN,
} from '../directory.errors';
import {
  type DepartmentCreate,
  DepartmentCreateSchema,
  type DepartmentDeleteQuery,
  DepartmentDeleteQuerySchema,
  type DepartmentListQuery,
  DepartmentListQuerySchema,
  type DepartmentPage,
  DepartmentPageSchema,
  DepartmentSchema,
  type DepartmentUpdate,
  DepartmentUpdateDocSchema,
  DepartmentUpdateSchema,
  type DepartmentView,
  type MemberCreate,
  MemberCreateSchema,
  type MemberListQuery,
  MemberListQuerySchema,
  type MemberPage,
  MemberPageSchema,
  MemberSchema,
  type MemberView,
} from '../dto/directory.schemas';
import { DepartmentsService } from '../services/departments.service';

const LIVE_NOTE =
  'Membership is live directory data: a change applies to the next policy evaluation without ' +
  'a publish (the resolved memberships are part of the hashed evaluation input).';

/** Tenant departments and members (step 5.2 P5, P22). Translation only. */
@DepartmentsApi()
@Controller({ path: 'departments', version: '1' })
export class DepartmentsController {
  constructor(private readonly departments: DepartmentsService) {}

  @Get()
  @CursorList('v0')
  @RequirePermissions(USER_READ)
  @ApiOperation({
    summary: 'List departments',
    description: 'Newest first, cursor-paginated, with member counts. From the read replica.',
  })
  @ApiQueryFrom(DepartmentListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(DepartmentPageSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(DepartmentListQuerySchema)) query: DepartmentListQuery,
  ): Promise<DepartmentPage> {
    return this.departments.list(scope, query);
  }

  @Post()
  @RequirePermissions(USER_MANAGE)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a department',
    description:
      'A department policies can reference by its public id (`sender.department`, ' +
      '`recipient.department`). Names are unique per organization; at most ' +
      'DEPARTMENT_MAX_PER_ORG. Audited as `department.created`.',
  })
  @ApiBody({ schema: zodToOpenApi(DepartmentCreateSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(DepartmentSchema) })
  @ApiErrors(400, 401, 403)
  @ApiDepartmentConflict([DEPARTMENT_NAME_TAKEN, DEPARTMENT_LIMIT_REACHED])
  @ApiDirectoryInconsistentRead()
  create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(DepartmentCreateSchema)) body: DepartmentCreate,
    @Client() client: ClientContext,
  ): Promise<DepartmentView> {
    return this.departments.create(principal, scope, body, client);
  }

  @Get(':departmentId')
  @RequirePermissions(USER_READ)
  @ApiOperation({ summary: 'Get a department', description: 'From the read replica.' })
  @ApiDepartmentId()
  @ApiOkResponse({ schema: zodToOpenApi(DepartmentSchema) })
  @ApiErrors(400, 401, 403)
  @ApiDepartmentNotFound()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('departmentId', departmentIdPipe) departmentId: string,
  ): Promise<DepartmentView> {
    return this.departments.get(scope, departmentId);
  }

  @Patch(':departmentId')
  @RequirePermissions(USER_MANAGE)
  @ApiOperation({
    summary: 'Rename or describe a department',
    description:
      'At `expectedRowVersion` (`409 department_conflict`). Audited as `department.updated`.',
  })
  @ApiDepartmentId()
  @ApiBody({ schema: zodToOpenApi(DepartmentUpdateDocSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(DepartmentSchema) })
  @ApiErrors(400, 401, 403)
  @ApiDepartmentNotFound()
  @ApiDepartmentConflict([DEPARTMENT_CONFLICT, DEPARTMENT_NAME_TAKEN])
  @ApiDirectoryInconsistentRead()
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('departmentId', departmentIdPipe) departmentId: string,
    @Body(new ZodValidationPipe(DepartmentUpdateSchema)) body: DepartmentUpdate,
    @Client() client: ClientContext,
  ): Promise<DepartmentView> {
    return this.departments.update(principal, scope, departmentId, body, client);
  }

  @Delete(':departmentId')
  @RequirePermissions(USER_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete a department',
    description:
      'Deletes the department and its members, optionally only at `?expectedRowVersion=`; ' +
      'refused while an active version of an active policy references it ' +
      '(`409 department_in_use`). Audited as `department.deleted`.',
  })
  @ApiDepartmentId()
  @ApiQueryFrom(DepartmentDeleteQuerySchema)
  @ApiNoContentResponse({ description: 'Deleted' })
  @ApiErrors(400, 401, 403)
  @ApiDepartmentNotFound()
  @ApiDepartmentConflict([DEPARTMENT_CONFLICT, DEPARTMENT_IN_USE])
  @ApiDirectoryInconsistentRead()
  async remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('departmentId', departmentIdPipe) departmentId: string,
    @Query(new ZodValidationPipe(DepartmentDeleteQuerySchema)) query: DepartmentDeleteQuery,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.departments.remove(principal, scope, departmentId, query.expectedRowVersion, client);
  }

  @Get(':departmentId/members')
  @CursorList('v0')
  @RequirePermissions(USER_READ)
  @ApiOperation({
    summary: 'List the members of a department',
    description: `Newest first, cursor-paginated. From the read replica. ${LIVE_NOTE}`,
  })
  @ApiDepartmentId()
  @ApiQueryFrom(MemberListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(MemberPageSchema) })
  @ApiErrors(400, 401, 403)
  @ApiDepartmentNotFound()
  listMembers(
    @CurrentScope() scope: TenantScope,
    @Param('departmentId', departmentIdPipe) departmentId: string,
    @Query(new ZodValidationPipe(MemberListQuerySchema)) query: MemberListQuery,
  ): Promise<MemberPage> {
    return this.departments.listMembers(scope, departmentId, query);
  }

  @Post(':departmentId/members')
  @RequirePermissions(USER_MANAGE)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Add a member to a department',
    description:
      'Exactly one of `address` (normalized: lower case, NFC, punycode domain; must be in an ' +
      'active domain of the organization, else `400 member_address_not_tenant`) or `userId` (a ' +
      'user of the organization, else `400 member_user_not_tenant`; matches the user’s email ' +
      'while the user is active). At most DEPARTMENT_MAX_MEMBERS. Audited as ' +
      `\`department.member_added\` (ids only). ${LIVE_NOTE}`,
  })
  @ApiDepartmentId()
  @ApiBody({ schema: zodToOpenApi(MemberCreateSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(MemberSchema) })
  @ApiErrors(401, 403)
  @ApiMemberInvalid()
  @ApiDepartmentNotFound()
  @ApiDepartmentConflict([DEPARTMENT_MEMBER_EXISTS, DEPARTMENT_MEMBER_LIMIT_REACHED])
  @ApiDirectoryInconsistentRead()
  addMember(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('departmentId', departmentIdPipe) departmentId: string,
    @Body(new ZodValidationPipe(MemberCreateSchema)) body: MemberCreate,
    @Client() client: ClientContext,
  ): Promise<MemberView> {
    return this.departments.addMember(principal, scope, departmentId, body, client);
  }

  @Delete(':departmentId/members/:memberId')
  @RequirePermissions(USER_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Remove a member from a department',
    description: `Audited as \`department.member_removed\`. ${LIVE_NOTE}`,
  })
  @ApiDepartmentId()
  @ApiMemberId()
  @ApiNoContentResponse({ description: 'Removed' })
  @ApiErrors(400, 401, 403)
  @ApiMemberNotFound()
  @ApiDirectoryInconsistentRead()
  async removeMember(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('departmentId', departmentIdPipe) departmentId: string,
    @Param('memberId', memberIdPipe) memberId: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.departments.removeMember(principal, scope, departmentId, memberId, client);
  }
}
