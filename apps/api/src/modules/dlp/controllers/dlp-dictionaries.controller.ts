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
  ApiDictionaryConflict,
  ApiDictionaryInvalid,
  ApiDictionaryNotFound,
  ApiDlpId,
  ApiInconsistentRead,
  DLP_APPLY_NOTE,
  DLP_MANAGE,
  DLP_READ,
  DlpController,
  dlpIdPipe,
} from '../api-docs';
import {
  type DlpDeleteQuery,
  DlpDeleteQuerySchema,
  type DlpDictionaryCreate,
  DlpDictionaryCreateSchema,
  type DlpDictionaryDetail,
  DlpDictionaryDetailSchema,
  type DlpDictionaryPage,
  DlpDictionaryPageSchema,
  type DlpDictionaryUpdate,
  DlpDictionaryUpdateSchema,
  type DlpListQuery,
  DlpListQuerySchema,
} from '../dto/dlp.schemas';
import { DlpDictionariesService } from '../services/dlp-dictionaries.service';

/** Tenant keyword dictionaries (step 4.5 D8, D21). Translation only. */
@DlpController()
@Controller({ path: 'dlp/dictionaries', version: '1' })
export class DlpDictionariesController {
  constructor(private readonly dictionaries: DlpDictionariesService) {}

  @Get()
  @CursorList('v0')
  @RequirePermissions(DLP_READ)
  @ApiOperation({
    summary: 'List the keyword dictionaries',
    description:
      'Newest first, cursor-paginated, optionally only enabled or disabled; the term count ' +
      'only (terms with `GET /{id}`). From the read replica.',
  })
  @ApiQueryFrom(DlpListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(DlpDictionaryPageSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(DlpListQuerySchema)) query: DlpListQuery,
  ): Promise<DlpDictionaryPage> {
    return this.dictionaries.list(scope, query);
  }

  @Get(':id')
  @RequirePermissions(DLP_READ)
  @ApiOperation({
    summary: 'Get a keyword dictionary with its terms',
    description:
      'Terms are tenant configuration (possibly confidential names): shown to dlp:read ' +
      'holders only, never in the scans read API. From the read replica.',
  })
  @ApiDlpId('id', 'Dictionary public id')
  @ApiOkResponse({ schema: zodToOpenApi(DlpDictionaryDetailSchema) })
  @ApiErrors(400, 401, 403)
  @ApiDictionaryNotFound()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('id', dlpIdPipe) id: string,
  ): Promise<DlpDictionaryDetail> {
    return this.dictionaries.get(scope, id);
  }

  @Post()
  @RequirePermissions(DLP_MANAGE)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a keyword dictionary',
    description:
      'Terms are matched as token phrases on the normalized text (case, NFKC forms, zero-width ' +
      'characters and Latin confusables do not hide a term). Unique name per organization ' +
      '(`409 dlp_dictionary_exists`), at most DLP_DICTIONARIES_MAX_PER_TENANT (`409 ' +
      'dlp_limit_reached`). Audited as `dlp_dictionary.created` with the term count (never ' +
      `the terms). ${DLP_APPLY_NOTE}`,
  })
  @ApiBody({ schema: zodToOpenApi(DlpDictionaryCreateSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(DlpDictionaryDetailSchema) })
  @ApiErrors(401, 403)
  @ApiDictionaryInvalid()
  @ApiDictionaryConflict()
  @ApiInconsistentRead()
  create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(DlpDictionaryCreateSchema)) body: DlpDictionaryCreate,
    @Client() client: ClientContext,
  ): Promise<DlpDictionaryDetail> {
    return this.dictionaries.create(principal, scope, body, client);
  }

  @Patch(':id')
  @RequirePermissions(DLP_MANAGE)
  @ApiOperation({
    summary: 'Update a keyword dictionary',
    description:
      '`version` must be the current version (`409 version_conflict`); `terms` replaces the ' +
      'list. Audited as `dlp_dictionary.updated` with the entry before and after (term counts ' +
      `only). ${DLP_APPLY_NOTE}`,
  })
  @ApiDlpId('id', 'Dictionary public id')
  @ApiBody({ schema: zodToOpenApi(DlpDictionaryUpdateSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(DlpDictionaryDetailSchema) })
  @ApiErrors(401, 403)
  @ApiDictionaryInvalid()
  @ApiDictionaryNotFound()
  @ApiDictionaryConflict()
  @ApiInconsistentRead()
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', dlpIdPipe) id: string,
    @Body(new ZodValidationPipe(DlpDictionaryUpdateSchema)) body: DlpDictionaryUpdate,
    @Client() client: ClientContext,
  ): Promise<DlpDictionaryDetail> {
    return this.dictionaries.update(principal, scope, id, body, client);
  }

  @Delete(':id')
  @RequirePermissions(DLP_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete a keyword dictionary',
    description:
      'Optionally only at `?version=`. Refused while a rule selects it (`409 ' +
      `dlp_dictionary_in_use\`). Audited as \`dlp_dictionary.deleted\`. ${DLP_APPLY_NOTE}`,
  })
  @ApiDlpId('id', 'Dictionary public id')
  @ApiQueryFrom(DlpDeleteQuerySchema)
  @ApiNoContentResponse({ description: 'Deleted' })
  @ApiErrors(400, 401, 403)
  @ApiDictionaryNotFound()
  @ApiDictionaryConflict()
  @ApiInconsistentRead()
  async remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', dlpIdPipe) id: string,
    @Query(new ZodValidationPipe(DlpDeleteQuerySchema)) query: DlpDeleteQuery,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.dictionaries.remove(principal, scope, id, query.version, client);
  }
}
