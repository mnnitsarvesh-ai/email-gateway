import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
} from '@nestjs/common';
import {
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
import type { ClientContext } from '../auth/services/session.service';
import {
  ApiKeyIdParamSchema,
  type ApiKeyListQuery,
  ApiKeyListQuerySchema,
  ApiKeyListResponseSchema,
  type ApiKeyView,
  type CreateApiKeyRequest,
  CreateApiKeyRequestSchema,
  CreatedApiKeyResponseSchema,
  type CreatedApiKeyView,
} from './api-keys.schemas';
import { ApiKeysService } from './api-keys.service';

/** API keys of the caller's organization (D11, §4.2). Secrets are shown once, at creation. */
@ApiTags('api-keys')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@Controller({ path: 'api-keys', version: '1' })
export class ApiKeysController {
  constructor(private readonly keys: ApiKeysService) {}

  @Get()
  @RequirePermissions('apikey:read')
  @ApiSecurity(API_KEY_SCHEME)
  @ApiOperation({
    summary: 'List API keys',
    description: 'Never returns keys or hashes. Newest first, read from the replica.',
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    schema: { type: 'integer', minimum: 1, maximum: 100 },
  })
  @ApiQuery({ name: 'cursor', required: false, schema: { type: 'string' } })
  @ApiOkResponse({ schema: zodToOpenApi(ApiKeyListResponseSchema) })
  @ApiErrors(400, 401, 403, 503)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ApiKeyListQuerySchema)) query: ApiKeyListQuery,
  ): Promise<Page<ApiKeyView>> {
    return this.keys.list(scope, query);
  }

  @Post()
  @RequirePermissions('apikey:manage')
  @UserOnly()
  @ApiOperation({
    summary: 'Create an API key',
    description:
      'Requires the `api_access` feature (`403` otherwise). Scopes: tenant permissions the ' +
      'caller holds, never `apikey:manage`, `role:manage` or `session:manage`. The key is in ' +
      'the response once and cannot be retrieved later.',
  })
  @ApiBody({ schema: zodToOpenApi(CreateApiKeyRequestSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(CreatedApiKeyResponseSchema) })
  @ApiErrors(400, 401, 403, 503)
  create(
    @CurrentUser() principal: UserPrincipal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(CreateApiKeyRequestSchema)) body: CreateApiKeyRequest,
    @Client() client: ClientContext,
  ): Promise<CreatedApiKeyView> {
    return this.keys.create(principal, scope, body, client);
  }

  @Delete(':id')
  @RequirePermissions('apikey:manage')
  @UserOnly()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Revoke an API key (idempotent)' })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiNoContentResponse({ description: 'Revoked; the key stops working immediately' })
  @ApiErrors(400, 401, 403, 404, 503)
  async revoke(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', new ZodValidationPipe(ApiKeyIdParamSchema)) id: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.keys.revoke(principal, scope, id, client);
  }
}
