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
  ApiVendorConflict,
  ApiVendorDomainFreemail,
  ApiVendorNotFound,
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
  type BecVendorCreate,
  BecVendorCreateSchema,
  type BecVendorPage,
  BecVendorPageSchema,
  type BecVendorUpdate,
  BecVendorUpdateSchema,
  type BecVendorView,
  BecVendorViewSchema,
  type BecProfileListQuery,
  BecProfileListQuerySchema,
} from '../dto/bec.schemas';
import { BecProfilesService } from '../services/bec-profiles.service';
import { BecController } from './bec-common';

/**
 * Vendor profiles of the caller's organization (step 4.4 B5, B6 V1–V4, L2, B18): the suppliers
 * whose names and domains the BEC engine protects against impersonation, lookalikes and
 * payment-change fraud. Translation only; the logic is in
 * BecProfilesService.
 */
@BecController()
@Controller({ path: 'bec/vendors', version: '1' })
export class BecVendorsController {
  constructor(private readonly profiles: BecProfilesService) {}

  @Get()
  @RequirePermissions(BEC_READ)
  @ApiOperation({
    summary: 'List the vendor profiles',
    description:
      'Newest first, cursor-paginated, optionally only enabled or disabled profiles. From the ' +
      'read replica: a profile created a moment ago may not be listed yet.',
  })
  @ApiQueryFrom(BecProfileListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(BecVendorPageSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(BecProfileListQuerySchema)) query: BecProfileListQuery,
  ): Promise<BecVendorPage> {
    return this.profiles.listVendors(scope, query);
  }

  @Get(':id')
  @RequirePermissions(BEC_READ)
  @ApiOperation({ summary: 'Get a vendor profile', description: 'From the read replica.' })
  @ApiBecId('Vendor profile public id')
  @ApiOkResponse({ schema: zodToOpenApi(BecVendorViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiVendorNotFound()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('id', becIdPipe) id: string,
  ): Promise<BecVendorView> {
    return this.profiles.getVendor(scope, id);
  }

  @Post()
  @RequirePermissions(BEC_MANAGE)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a vendor profile',
    description:
      'The name (2–128 characters) is normalized like a display name and must be unique in ' +
      'the organization (`409 vendor_exists`); 1–20 domains, normalized to ASCII registrable ' +
      'domains (public suffixes refused with 400, free-mail domains with `422 ' +
      'vendor_domain_freemail`); aliases (≤ 10), known sender addresses (≤ 50) and ' +
      '`paymentChangeSensitive` (default true) are optional. At most BEC_MAX_VENDORS profiles ' +
      '(`409 bec_limit_reached`). Audited as `bec_vendor.created`. ' +
      BEC_APPLY_NOTE,
  })
  @ApiBody({ schema: zodToOpenApi(BecVendorCreateSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(BecVendorViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiVendorConflict()
  @ApiVendorDomainFreemail()
  @ApiInconsistentRead()
  create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(BecVendorCreateSchema)) body: BecVendorCreate,
    @Client() client: ClientContext,
  ): Promise<BecVendorView> {
    return this.profiles.createVendor(principal, scope, body, client);
  }

  @Patch(':id')
  @RequirePermissions(BEC_MANAGE)
  @ApiOperation({
    summary: 'Update a vendor profile',
    description:
      'Changes the given fields; `version` must be the current version (`409 ' +
      'version_conflict`). Audited as `bec_vendor.updated` with the profile before and ' +
      `after. ${BEC_APPLY_NOTE}`,
  })
  @ApiBecId('Vendor profile public id')
  @ApiBody({ schema: zodToOpenApi(BecVendorUpdateSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(BecVendorViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiVendorNotFound()
  @ApiVendorConflict()
  @ApiVendorDomainFreemail()
  @ApiInconsistentRead()
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', becIdPipe) id: string,
    @Body(new ZodValidationPipe(BecVendorUpdateSchema)) body: BecVendorUpdate,
    @Client() client: ClientContext,
  ): Promise<BecVendorView> {
    return this.profiles.updateVendor(principal, scope, id, body, client);
  }

  @Delete(':id')
  @RequirePermissions(BEC_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete a vendor profile',
    description:
      'Optionally only at `?version=`. Audited as `bec_vendor.deleted` with the profile as ' +
      `it was. ${BEC_APPLY_NOTE}`,
  })
  @ApiBecId('Vendor profile public id')
  @ApiQueryFrom(BecDeleteQuerySchema)
  @ApiNoContentResponse({ description: 'Deleted' })
  @ApiErrors(400, 401, 403)
  @ApiVendorNotFound()
  @ApiVersionOnlyConflict()
  @ApiInconsistentRead()
  async remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', becIdPipe) id: string,
    @Query(new ZodValidationPipe(BecDeleteQuerySchema)) query: BecDeleteQuery,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.profiles.deleteVendor(principal, scope, id, query.version, client);
  }
}
