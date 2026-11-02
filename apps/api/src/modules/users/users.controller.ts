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
  Put,
  Query,
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../auth-contracts/decorators';
import type { Principal, UserPrincipal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import type { Page } from '../../http/pagination';
import { zodToOpenApi } from '../../validation/zod-openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { ApiErrors } from '../auth/api-docs';
import { Client } from '../auth/client-context.decorator';
import { CurrentUser } from '../auth/current-user.decorator';
import { SessionListResponseSchema } from '../auth/dto/auth.schemas';
import type { ClientContext, SessionView } from '../auth/services/session.service';
import {
  InvitationResentResponseSchema,
  type InviteUserRequest,
  InviteUserRequestSchema,
  type UpdateUserRequest,
  UpdateUserRequestSchema,
  UserIdParamSchema,
  type UserListQuery,
  UserListQuerySchema,
  UserListResponseSchema,
  UserResponseSchema,
  type UserRolesRequest,
  UserRolesRequestSchema,
  type UserStatusRequest,
  UserStatusRequestSchema,
  type UserView,
} from './users.schemas';
import { UsersService } from './users.service';

const idPipe = new ZodValidationPipe(UserIdParamSchema);

/** Users of the caller's organization (D11, §4.2). Users are addressed by public id. */
@ApiTags('users')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@Controller({ path: 'users', version: '1' })
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get()
  @RequirePermissions('user:read')
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({
    summary: 'List users',
    description: 'Newest first, cursor-paginated, read from the replica (may lag briefly).',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    schema: { type: 'integer', minimum: 1, maximum: 100 },
  })
  @ApiQuery({ name: 'cursor', required: false, schema: { type: 'string' } })
  @ApiQuery({
    name: 'status',
    required: false,
    schema: { type: 'string', enum: ['invited', 'active', 'disabled', 'locked'] },
  })
  @ApiQuery({ name: 'q', required: false, description: 'Email or display-name prefix' })
  @ApiQuery({ name: 'role', required: false, description: 'Role key' })
  @ApiOkResponse({ schema: zodToOpenApi(UserListResponseSchema) })
  @ApiErrors(400, 401, 403, 503)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(UserListQuerySchema)) query: UserListQuery,
  ): Promise<Page<UserView>> {
    return this.users.list(scope, query);
  }

  @Post('invitations')
  @RequirePermissions('user:manage')
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({
    summary: 'Invite a user',
    description:
      'Creates the user (or re-invites a deleted one) with the given roles and emails an ' +
      'invitation link. Enforces the `max_users` limit, the escalation rule and platform-role ' +
      'restrictions. Refused under a platform override (`403`): the access would outlive it.',
  })
  @ApiBody({ schema: zodToOpenApi(InviteUserRequestSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(UserResponseSchema) })
  @ApiErrors(400, 401, 403, 409, 503)
  invite(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(InviteUserRequestSchema)) body: InviteUserRequest,
    @Client() client: ClientContext,
  ): Promise<UserView> {
    return this.users.invite(principal, scope, body, client);
  }

  @Get(':id')
  @RequirePermissions('user:read')
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({ summary: 'Get a user' })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiOkResponse({ schema: zodToOpenApi(UserResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 503)
  get(@CurrentScope() scope: TenantScope, @Param('id', idPipe) id: string): Promise<UserView> {
    return this.users.get(scope, id);
  }

  @Post(':id/invitation')
  @RequirePermissions('user:manage')
  @ApiSecurity(API_KEY_SCHEME)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Resend the invitation (invited users only; earlier links stop working)',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiAcceptedResponse({ schema: zodToOpenApi(InvitationResentResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 409, 503)
  resendInvitation(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', idPipe) id: string,
    @Client() client: ClientContext,
  ): Promise<{ expiresAt: string }> {
    return this.users.resendInvitation(principal, scope, id, client);
  }

  @Patch(':id')
  @RequirePermissions('user:manage')
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({
    summary: 'Update display name and/or email',
    description:
      'An email change clears the verification and sends a verification link to the new ' +
      'address (an invited user gets a new invitation instead); password-reset links go to ' +
      'it only once verified. Email changes need a user session (API keys get `403`) and are ' +
      'refused under a platform override. Duplicate email → `409`. Like every action on ' +
      'another user, the caller must hold every permission of the target’s roles (`403`).',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiBody({ schema: zodToOpenApi(UpdateUserRequestSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(UserResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 409, 503)
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', idPipe) id: string,
    @Body(new ZodValidationPipe(UpdateUserRequestSchema)) body: UpdateUserRequest,
    @Client() client: ClientContext,
  ): Promise<UserView> {
    return this.users.updateProfile(principal, scope, id, body, client);
  }

  @Patch(':id/status')
  @RequirePermissions('user:manage')
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({
    summary: 'Activate, disable or unlock a user',
    description:
      '`active → disabled` and `invited → disabled` (cancels the invitation) revoke sessions; ' +
      '`disabled → active`; a locked account `→ active` clears the lockout. Users cannot ' +
      'disable themselves; the last active administrator cannot be disabled (`409`). The ' +
      'caller must hold every permission of the target’s roles (`403`).',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiBody({ schema: zodToOpenApi(UserStatusRequestSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(UserResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 409, 503)
  changeStatus(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', idPipe) id: string,
    @Body(new ZodValidationPipe(UserStatusRequestSchema)) body: UserStatusRequest,
    @Client() client: ClientContext,
  ): Promise<UserView> {
    return this.users.changeStatus(principal, scope, id, body, client);
  }

  @Put(':id/roles')
  @RequirePermissions('user:manage')
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({
    summary: 'Replace the roles of a user',
    description:
      'The caller must hold every permission of the target’s current roles and of each added ' +
      'role; platform roles only in the platform organization; the last active administrator ' +
      'keeps `user:manage`; refused under a platform override (`403`).',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiBody({ schema: zodToOpenApi(UserRolesRequestSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(UserResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 409, 503)
  replaceRoles(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', idPipe) id: string,
    @Body(new ZodValidationPipe(UserRolesRequestSchema)) body: UserRolesRequest,
    @Client() client: ClientContext,
  ): Promise<UserView> {
    return this.users.replaceRoles(principal, scope, id, body.roleKeys, client);
  }

  @Delete(':id')
  @RequirePermissions('user:manage')
  @ApiSecurity(API_KEY_SCHEME)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete a user (soft delete; sessions revoked)' })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiNoContentResponse({ description: 'User deleted' })
  @ApiErrors(400, 401, 403, 404, 409, 503)
  async remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', idPipe) id: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.users.remove(principal, scope, id, client);
  }

  @Post(':id/mfa/reset')
  @RequirePermissions('user:manage')
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: "Reset a user's MFA",
    description:
      'Clears the TOTP secret and recovery codes and revokes the user’s sessions. Requires an ' +
      'MFA-authenticated session; not for your own account.',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiNoContentResponse({ description: 'MFA reset' })
  @ApiErrors(400, 401, 403, 404, 409, 503)
  async resetMfa(
    @CurrentUser() principal: UserPrincipal,
    @CurrentScope() scope: TenantScope,
    @Param('id', idPipe) id: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.users.resetMfa(principal, scope, id, client);
  }

  @Get(':id/sessions')
  @RequirePermissions('session:manage')
  @ApiOperation({
    summary: "List a user's live sessions",
    description: 'Read from the replica; a just-created session may appear after a short delay.',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiOkResponse({ schema: zodToOpenApi(SessionListResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 503)
  async listSessions(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', idPipe) id: string,
  ): Promise<{ data: SessionView[] }> {
    return { data: await this.users.listSessions(principal, scope, id) };
  }

  @Delete(':id/sessions')
  @RequirePermissions('session:manage')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: "Revoke all of a user's sessions" })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiNoContentResponse({ description: 'Sessions revoked' })
  @ApiErrors(400, 401, 403, 404, 503)
  async revokeAllSessions(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', idPipe) id: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.users.revokeAllSessions(principal, scope, id, client);
  }

  @Delete(':id/sessions/:sessionId')
  @RequirePermissions('session:manage')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: "Revoke one of a user's sessions" })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiParam({ name: 'sessionId', format: 'uuid' })
  @ApiNoContentResponse({ description: 'Session revoked' })
  @ApiErrors(400, 401, 403, 404, 503)
  async revokeSession(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', idPipe) id: string,
    @Param('sessionId', idPipe) sessionId: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.users.revokeSession(principal, scope, id, sessionId, client);
  }
}
