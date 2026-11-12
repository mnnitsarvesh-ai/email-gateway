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
  ApiDlpId,
  ApiExceptionConflict,
  ApiExceptionNotFound,
  ApiInconsistentRead,
  ApiReferenceInvalid,
  ApiVersionConflict,
  DLP_APPLY_NOTE,
  DLP_MANAGE,
  DLP_READ,
  DlpController,
  dlpIdPipe,
} from '../api-docs';
import {
  type DlpDeleteQuery,
  DlpDeleteQuerySchema,
  type DlpExceptionCreate,
  DlpExceptionCreateSchema,
  type DlpExceptionListQuery,
  DlpExceptionListQuerySchema,
  type DlpExceptionPage,
  DlpExceptionPageSchema,
  type DlpExceptionUpdate,
  DlpExceptionUpdateSchema,
  type DlpExceptionView,
  DlpExceptionViewSchema,
} from '../dto/dlp.schemas';
import { DlpExceptionsService } from '../services/dlp-exceptions.service';

/** DLP exceptions (step 4.5 D12, D21). Translation only; the logic is in DlpExceptionsService. */
@DlpController()
@Controller({ path: 'dlp/exceptions', version: '1' })
export class DlpExceptionsController {
  constructor(private readonly exceptions: DlpExceptionsService) {}

  @Get()
  @CursorList('v0')
  @RequirePermissions(DLP_READ)
  @ApiOperation({
    summary: 'List the DLP exceptions',
    description:
      'Newest first, cursor-paginated, optionally one `scope` and only active or inactive ' +
      'entries; expired entries are listed with `expired: true` (never applied). From the ' +
      'read replica.',
  })
  @ApiQueryFrom(DlpExceptionListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(DlpExceptionPageSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(DlpExceptionListQuerySchema)) query: DlpExceptionListQuery,
  ): Promise<DlpExceptionPage> {
    return this.exceptions.list(scope, query);
  }

  @Post()
  @RequirePermissions(DLP_MANAGE)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Add a DLP exception',
    description:
      'A sender or recipient address (normalized) or domain (ASCII; public suffixes and IP ' +
      'literals refused), optionally for one policy or rule of the organization (`400 ' +
      'dlp_reference_invalid` otherwise) and only some detectors or categories, with a ' +
      'required reason and a required expiry (future, at most DLP_EXCEPTION_MAX_DAYS ahead). A ' +
      'sender exception removes findings from the targeted rules; a recipient exception ' +
      'removes recipients from their recipient sets; applied exceptions are recorded in the ' +
      'result. Sender exceptions match the envelope sender (MAIL FROM), which is not bound to an ' +
      'authenticated user: anyone who can submit through the organization’s connector, or any ' +
      'inbound sender, can set it, so prefer recipient or domain exceptions where possible. ' +
      'Unique per (scope, value, target) (`409 dlp_exception_exists`), at most ' +
      'DLP_EXCEPTIONS_MAX_PER_TENANT (`409 dlp_limit_reached`). Audited as ' +
      `\`dlp_exception.created\`. ${DLP_APPLY_NOTE}`,
  })
  @ApiBody({ schema: zodToOpenApi(DlpExceptionCreateSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(DlpExceptionViewSchema) })
  @ApiErrors(401, 403)
  @ApiReferenceInvalid()
  @ApiExceptionConflict()
  @ApiInconsistentRead()
  create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(DlpExceptionCreateSchema)) body: DlpExceptionCreate,
    @Client() client: ClientContext,
  ): Promise<DlpExceptionView> {
    return this.exceptions.create(principal, scope, body, client);
  }

  @Patch(':id')
  @RequirePermissions(DLP_MANAGE)
  @ApiOperation({
    summary: 'Update a DLP exception’s reason, expiry, filters or state',
    description:
      'Scope, value and target are fixed (delete and add instead). `version` must be the ' +
      'current version (`409 version_conflict`). Audited as `dlp_exception.updated` with the ' +
      `entry before and after. ${DLP_APPLY_NOTE}`,
  })
  @ApiDlpId('id', 'Exception public id')
  @ApiBody({ schema: zodToOpenApi(DlpExceptionUpdateSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(DlpExceptionViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiExceptionNotFound()
  @ApiVersionConflict()
  @ApiInconsistentRead()
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', dlpIdPipe) id: string,
    @Body(new ZodValidationPipe(DlpExceptionUpdateSchema)) body: DlpExceptionUpdate,
    @Client() client: ClientContext,
  ): Promise<DlpExceptionView> {
    return this.exceptions.update(principal, scope, id, body, client);
  }

  @Delete(':id')
  @RequirePermissions(DLP_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Remove a DLP exception',
    description: `Optionally only at \`?version=\`. Audited as \`dlp_exception.deleted\` with the entry as it was. ${DLP_APPLY_NOTE}`,
  })
  @ApiDlpId('id', 'Exception public id')
  @ApiQueryFrom(DlpDeleteQuerySchema)
  @ApiNoContentResponse({ description: 'Removed' })
  @ApiErrors(400, 401, 403)
  @ApiExceptionNotFound()
  @ApiVersionConflict()
  @ApiInconsistentRead()
  async remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', dlpIdPipe) id: string,
    @Query(new ZodValidationPipe(DlpDeleteQuerySchema)) query: DlpDeleteQuery,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.exceptions.remove(principal, scope, id, query.version, client);
  }
}
