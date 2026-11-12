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
  ApiBecId,
  ApiExecutiveConflict,
  ApiExecutiveNotFound,
  ApiInconsistentRead,
  ApiVersionOnlyConflict,
  BEC_APPLY_NOTE,
  BEC_MANAGE,
  BEC_READ,
  becIdPipe,
} from '../api-docs';
import {
  type BecDeleteQuery,
  BecDeleteQuerySchema,
  type BecExecutiveCreate,
  BecExecutiveCreateSchema,
  type BecExecutivePage,
  BecExecutivePageSchema,
  type BecExecutiveUpdate,
  BecExecutiveUpdateSchema,
  type BecExecutiveView,
  BecExecutiveViewSchema,
  type BecProfileListQuery,
  BecProfileListQuerySchema,
} from '../dto/bec.schemas';
import { BecProfilesService } from '../services/bec-profiles.service';
import { BecController } from './bec-common';

/**
 * Executive profiles of the caller's organization (step 4.4 B5, B6 X1–X3, B18): the names the
 * BEC engine protects against display-name impersonation. Translation only; the logic is in
 * BecProfilesService.
 */
@BecController()
@Controller({ path: 'bec/executives', version: '1' })
export class BecExecutivesController {
  constructor(private readonly profiles: BecProfilesService) {}

  @Get()
  @CursorList('v0')
  @RequirePermissions(BEC_READ)
  @ApiOperation({
    summary: 'List the executive profiles',
    description:
      'Newest first, cursor-paginated, optionally only enabled or disabled profiles. From the ' +
      'read replica: a profile created a moment ago may not be listed yet.',
  })
  @ApiQueryFrom(BecProfileListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(BecExecutivePageSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(BecProfileListQuerySchema)) query: BecProfileListQuery,
  ): Promise<BecExecutivePage> {
    return this.profiles.listExecutives(scope, query);
  }

  @Get(':id')
  @RequirePermissions(BEC_READ)
  @ApiOperation({ summary: 'Get an executive profile', description: 'From the read replica.' })
  @ApiBecId('Executive profile public id')
  @ApiOkResponse({ schema: zodToOpenApi(BecExecutiveViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiExecutiveNotFound()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('id', becIdPipe) id: string,
  ): Promise<BecExecutiveView> {
    return this.profiles.getExecutive(scope, id);
  }

  @Post()
  @RequirePermissions(BEC_MANAGE)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create an executive profile',
    description:
      'The display name (2–128 characters) is normalized (NFKC, invisible characters removed, ' +
      'case folded, punctuation removed) and must be unique in the organization (`409 ' +
      'executive_exists`); aliases (≤ 10) and known addresses (≤ 20, normalized, lower case) ' +
      'are optional. At most BEC_MAX_EXECUTIVES profiles (`409 bec_limit_reached`). Audited ' +
      `as \`bec_executive.created\`. ${BEC_APPLY_NOTE}`,
  })
  @ApiBody({ schema: zodToOpenApi(BecExecutiveCreateSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(BecExecutiveViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiExecutiveConflict()
  @ApiInconsistentRead()
  create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(BecExecutiveCreateSchema)) body: BecExecutiveCreate,
    @Client() client: ClientContext,
  ): Promise<BecExecutiveView> {
    return this.profiles.createExecutive(principal, scope, body, client);
  }

  @Patch(':id')
  @RequirePermissions(BEC_MANAGE)
  @ApiOperation({
    summary: 'Update an executive profile',
    description:
      'Changes the given fields; `version` must be the current version (`409 ' +
      'version_conflict`). Audited as `bec_executive.updated` with the profile before and ' +
      `after. ${BEC_APPLY_NOTE}`,
  })
  @ApiBecId('Executive profile public id')
  @ApiBody({ schema: zodToOpenApi(BecExecutiveUpdateSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(BecExecutiveViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiExecutiveNotFound()
  @ApiExecutiveConflict()
  @ApiInconsistentRead()
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', becIdPipe) id: string,
    @Body(new ZodValidationPipe(BecExecutiveUpdateSchema)) body: BecExecutiveUpdate,
    @Client() client: ClientContext,
  ): Promise<BecExecutiveView> {
    return this.profiles.updateExecutive(principal, scope, id, body, client);
  }

  @Delete(':id')
  @RequirePermissions(BEC_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete an executive profile',
    description:
      'Optionally only at `?version=`. Audited as `bec_executive.deleted` with the profile as ' +
      `it was. ${BEC_APPLY_NOTE}`,
  })
  @ApiBecId('Executive profile public id')
  @ApiQueryFrom(BecDeleteQuerySchema)
  @ApiNoContentResponse({ description: 'Deleted' })
  @ApiErrors(400, 401, 403)
  @ApiExecutiveNotFound()
  @ApiVersionOnlyConflict()
  @ApiInconsistentRead()
  async remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', becIdPipe) id: string,
    @Query(new ZodValidationPipe(BecDeleteQuerySchema)) query: BecDeleteQuery,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.profiles.deleteExecutive(principal, scope, id, query.version, client);
  }
}
