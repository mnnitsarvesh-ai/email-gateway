import { Body, Controller, Get, HttpCode, HttpStatus, Param, Post } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { RequireMfa, RequirePermissions, UserOnly } from '../../../auth-contracts/decorators';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import { CurrentUser } from '../../auth/current-user.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiOrganizationId } from '../api-docs';
import { type OrganizationAccess, PLATFORM_ORGANIZATIONS } from '../domain/organization-access';
import {
  type DeletionCancelInput,
  DeletionCancelSchema,
  type DeletionConfirmInput,
  DeletionConfirmSchema,
  type DeletionRequestInput,
  DeletionRequestSchema,
  DeletionStateResponseSchema,
  UuidParamSchema,
} from '../dto/organizations.schemas';
import { OrgAccess } from '../organization-access.decorator';
import type { DeletionStateResponse } from '../organization.mapper';
import { OrganizationDeletionService } from '../services/organization-deletion.service';

const idPipe = new ZodValidationPipe(UuidParamSchema);

/**
 * Organization deletion workflow (D12): request → four-eyes confirmation → cancellable until
 * `purge_after`. Platform users only; the state-changing steps need an MFA session.
 */
@ApiTags('organizations')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@RequirePermissions(PLATFORM_ORGANIZATIONS)
@Controller({ path: 'organizations/:id/deletion', version: '1' })
export class OrganizationDeletionController {
  constructor(private readonly deletion: OrganizationDeletionService) {}

  @Get()
  @ApiOperation({ summary: 'Deletion request state' })
  @ApiOrganizationId()
  @ApiOkResponse({ schema: zodToOpenApi(DeletionStateResponseSchema) })
  @ApiErrors(400, 401, 403, 404)
  get(
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
  ): Promise<DeletionStateResponse> {
    return this.deletion.get(access, id);
  }

  @Post()
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Request deletion (step 1)',
    description:
      'The organization must be suspended, confirmSlug must equal its slug and no legal hold ' +
      'may be active. Another platform user must confirm within ' +
      'ORG_DELETION_CONFIRM_WINDOW_HOURS.',
  })
  @ApiOrganizationId()
  @ApiBody({ schema: zodToOpenApi(DeletionRequestSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(DeletionStateResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 409)
  request(
    @CurrentUser() principal: UserPrincipal,
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
    @Body(new ZodValidationPipe(DeletionRequestSchema)) body: DeletionRequestInput,
    @Client() client: ClientContext,
  ): Promise<DeletionStateResponse> {
    return this.deletion.request(principal, access, id, body, client);
  }

  @Post('confirm')
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Confirm deletion (step 2, four-eyes)',
    description:
      'By a different platform user than the requester (403 otherwise), within the ' +
      'confirmation window (409 otherwise). Marks the organization deleted, sets purge_after, ' +
      'revokes every session and API key.',
  })
  @ApiOrganizationId()
  @ApiBody({ schema: zodToOpenApi(DeletionConfirmSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(DeletionStateResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 409)
  confirm(
    @CurrentUser() principal: UserPrincipal,
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
    @Body(new ZodValidationPipe(DeletionConfirmSchema)) body: DeletionConfirmInput,
    @Client() client: ClientContext,
  ): Promise<DeletionStateResponse> {
    return this.deletion.confirm(principal, access, id, body, client);
  }

  @Post('cancel')
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Cancel deletion',
    description:
      'From pending_deletion, or from deleted while now < purge_after. The organization ' +
      'returns to suspended; reactivation is a separate status change.',
  })
  @ApiOrganizationId()
  @ApiBody({ schema: zodToOpenApi(DeletionCancelSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(DeletionStateResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 409)
  cancel(
    @CurrentUser() principal: UserPrincipal,
    @OrgAccess() access: OrganizationAccess,
    @Param('id', idPipe) id: string,
    @Body(new ZodValidationPipe(DeletionCancelSchema)) body: DeletionCancelInput,
    @Client() client: ClientContext,
  ): Promise<DeletionStateResponse> {
    return this.deletion.cancel(principal, access, id, body, client);
  }
}
