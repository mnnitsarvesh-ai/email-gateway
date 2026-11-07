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
  ApiInconsistentRead,
  ApiTrustedDomainFreemail,
  ApiTrustedSenderConflict,
  ApiTrustedSenderNotFound,
  ApiVersionOnlyConflict,
  BEC_APPLY_NOTE,
  BEC_MANAGE,
  BEC_READ,
  becIdPipe,
} from '../api-docs';
import {
  type BecDeleteQuery,
  BecDeleteQuerySchema,
  type BecTrustedSenderCreate,
  BecTrustedSenderCreateSchema,
  type BecTrustedSenderListQuery,
  BecTrustedSenderListQuerySchema,
  type BecTrustedSenderPage,
  BecTrustedSenderPageSchema,
  type BecTrustedSenderUpdate,
  BecTrustedSenderUpdateSchema,
  type BecTrustedSenderView,
  BecTrustedSenderViewSchema,
} from '../dto/bec.schemas';
import { BecTrustedSendersService } from '../services/bec-trusted-senders.service';
import { BecController } from './bec-common';

/**
 * Trusted senders of the caller's organization (step 4.4 B7, B18). Translation only; the logic
 * is in BecTrustedSendersService.
 */
@BecController()
@Controller({ path: 'bec/trusted-senders', version: '1' })
export class BecTrustedSendersController {
  constructor(private readonly trusted: BecTrustedSendersService) {}

  @Get()
  @RequirePermissions(BEC_READ)
  @ApiOperation({
    summary: 'List the trusted senders',
    description:
      'Newest first, cursor-paginated, optionally one `kind`; expired entries are listed with ' +
      '`expired: true` (no longer applied). From the read replica.',
  })
  @ApiQueryFrom(BecTrustedSenderListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(BecTrustedSenderPageSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(BecTrustedSenderListQuerySchema)) query: BecTrustedSenderListQuery,
  ): Promise<BecTrustedSenderPage> {
    return this.trusted.list(scope, query);
  }

  @Post()
  @RequirePermissions(BEC_MANAGE)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Add a trusted sender',
    description:
      'An exact address (normalized, lower case) or a registrable domain (normalized to ' +
      'ASCII; subdomains and public suffixes refused with 400, free-mail domains with `422 ' +
      'trusted_domain_freemail`), a reason and an optional expiry (future, at most 365 days ' +
      'ahead). Trust applies only when the message authenticates as the From domain; it never ' +
      'neutralizes authentication, lookalike, executive impersonation or link findings. Unique ' +
      'per (kind, value) (`409 trusted_sender_exists`); at most BEC_MAX_TRUSTED_SENDERS (`409 ' +
      `bec_limit_reached\`). Audited as \`bec_trusted_sender.created\`. ${BEC_APPLY_NOTE}`,
  })
  @ApiBody({ schema: zodToOpenApi(BecTrustedSenderCreateSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(BecTrustedSenderViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiTrustedSenderConflict()
  @ApiTrustedDomainFreemail()
  @ApiInconsistentRead()
  create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(BecTrustedSenderCreateSchema)) body: BecTrustedSenderCreate,
    @Client() client: ClientContext,
  ): Promise<BecTrustedSenderView> {
    return this.trusted.create(principal, scope, body, client);
  }

  @Patch(':id')
  @RequirePermissions(BEC_MANAGE)
  @ApiOperation({
    summary: 'Update a trusted sender’s reason or expiry',
    description:
      '`version` must be the current version (`409 version_conflict`). Audited as ' +
      `\`bec_trusted_sender.updated\` with the entry before and after. ${BEC_APPLY_NOTE}`,
  })
  @ApiBecId('Trusted sender public id')
  @ApiBody({ schema: zodToOpenApi(BecTrustedSenderUpdateSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(BecTrustedSenderViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiTrustedSenderNotFound()
  @ApiVersionOnlyConflict()
  @ApiInconsistentRead()
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', becIdPipe) id: string,
    @Body(new ZodValidationPipe(BecTrustedSenderUpdateSchema)) body: BecTrustedSenderUpdate,
    @Client() client: ClientContext,
  ): Promise<BecTrustedSenderView> {
    return this.trusted.update(principal, scope, id, body, client);
  }

  @Delete(':id')
  @RequirePermissions(BEC_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Remove a trusted sender',
    description:
      'Optionally only at `?version=`. Audited as `bec_trusted_sender.deleted` with the entry ' +
      `as it was. ${BEC_APPLY_NOTE}`,
  })
  @ApiBecId('Trusted sender public id')
  @ApiQueryFrom(BecDeleteQuerySchema)
  @ApiNoContentResponse({ description: 'Removed' })
  @ApiErrors(400, 401, 403)
  @ApiTrustedSenderNotFound()
  @ApiVersionOnlyConflict()
  @ApiInconsistentRead()
  async remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', becIdPipe) id: string,
    @Query(new ZodValidationPipe(BecDeleteQuerySchema)) query: BecDeleteQuery,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.trusted.remove(principal, scope, id, query.version, client);
  }
}
