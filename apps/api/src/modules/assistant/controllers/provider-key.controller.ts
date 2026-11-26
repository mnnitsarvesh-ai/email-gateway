import { Body, Controller, Delete, HttpCode, HttpStatus, Post, Put, Query } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { RateClass } from '../../../rate-limit/rate-class.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ApiAssistantForbidden,
  ApiAssistantResponse,
  ApiAssistantUnavailable,
  USER_ONLY_RULE,
} from '../api-docs';
import { ASSISTANT_PERMISSIONS as P } from '../assistant.constants';
import { ASSISTANT_ERROR_CODES as C } from '../assistant.errors';
import {
  ASSISTANT_EXAMPLES as X,
  type RemoveProviderKeyQuery,
  RemoveProviderKeyQuerySchema,
  type SetProviderKeyBody,
  SetProviderKeyBodySchema,
  type TenantKeyView,
  TenantKeyViewSchema,
} from '../dto/assistant.schemas';
import { TenantKeyService } from '../services/tenant-key.service';
import { userOf } from './assistant.controller';

const KEY_RULE =
  ' The key is write-only: it is verified with the provider, stored encrypted with a dedicated ' +
  'key and never returned, logged, audited or sent to the model; responses carry its ' +
  'fingerprint (first 16 hex characters of its SHA-256) and status only. Needs ' +
  '`assistant:configure` and an MFA session; rate class `sensitive`.';

const CONFLICT = (): MethodDecorator =>
  ApiCodedError(
    409,
    '`expectedRowVersion` is not the stored settings version (`currentRowVersion` given)',
    [C.settingsConflict],
    { currentRowVersion: { type: 'integer' } },
  );

/**
 * The organization's own provider key (step AI-6 D7, PO Q8, ADR-0097, contracts §35.6):
 * `PUT|DELETE /assistant/settings/provider-key` and `POST /assistant/settings/provider-key/validate`.
 * Thin: `TenantKeyService` probes, encrypts, stores and audits.
 */
@ApiTags('assistant')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'assistant/settings/provider-key', version: '1' })
export class AssistantProviderKeyController {
  constructor(private readonly keys: TenantKeyService) {}

  @Put()
  @RequirePermissions(P.configure)
  @RequireMfa()
  @RateClass('sensitive')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Set your organization’s AI provider key',
    description:
      'Stores your organization’s own API key for the AI provider (only when the platform ' +
      'offers it: `403 assistant_tenant_keys_disabled`), for one of the offered providers and ' +
      'models (`tenantKeysOffered` of GET /assistant/settings; else `400 validation_failed`). ' +
      'The key is first checked with the provider without generating tokens: a refusal ' +
      '(401/403 or an unknown model) answers `422 assistant_tenant_key_rejected`, an ' +
      'unreachable provider `502 assistant_tenant_key_unverified`; nothing is stored then. A ' +
      'stored key replaces the previous one and bumps the settings `rowVersion` (CAS ' +
      '`expectedRowVersion`). Turns use it once `useTenantKey` is set in the settings. Audited ' +
      '`assistant.provider_key_set` (provider, model, fingerprint).' +
      KEY_RULE +
      USER_ONLY_RULE,
  })
  @ApiBody({ schema: zodToOpenApi(SetProviderKeyBodySchema, { io: 'input' }) })
  @ApiAssistantResponse(200, TenantKeyViewSchema, X.tenantKey, 'The stored key (never the key)')
  @ApiAssistantForbidden(
    [C.tenantKeysDisabled, 'mfa_required'],
    'an MFA session is needed (`mfa_required`), the platform does not offer organization keys ' +
      '(`assistant_tenant_keys_disabled`)',
  )
  @ApiCodedError(422, 'The provider refused the key for this model', [C.tenantKeyRejected])
  @ApiCodedError(502, 'The key could not be verified with the provider', [C.tenantKeyUnverified])
  @CONFLICT()
  @ApiAssistantUnavailable()
  set(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(SetProviderKeyBodySchema)) body: SetProviderKeyBody,
    @Client() client: ClientContext,
  ): Promise<TenantKeyView> {
    return this.keys.set(userOf(principal), scope, body, client.ip);
  }

  @Delete()
  @RequirePermissions(P.configure)
  @RequireMfa()
  @RateClass('sensitive')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Remove your organization’s AI provider key',
    description:
      'Deletes the stored key and turns `useTenantKey` off (turns use the platform’s ' +
      'providers again); bumps the settings `rowVersion` (CAS `expectedRowVersion` query ' +
      'parameter). `404 assistant_tenant_key_not_found` when none is stored. Audited ' +
      '`assistant.provider_key_removed`. Needs `assistant:configure` and an MFA session; rate ' +
      'class `sensitive`.' +
      USER_ONLY_RULE,
  })
  @ApiQuery({
    name: 'expectedRowVersion',
    required: true,
    description: '`rowVersion` of the settings you read (compare-and-set)',
    schema: zodToOpenApi(RemoveProviderKeyQuerySchema.shape.expectedRowVersion, { io: 'input' }),
  })
  @ApiResponse({ status: 204, description: 'Removed' })
  @ApiAssistantForbidden(['mfa_required'], 'an MFA session is needed (`mfa_required`)')
  @ApiCodedError(404, 'No key is stored', [C.tenantKeyNotFound])
  @CONFLICT()
  @ApiAssistantUnavailable()
  async remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(RemoveProviderKeyQuerySchema)) query: RemoveProviderKeyQuery,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.keys.remove(userOf(principal), scope, query.expectedRowVersion, client.ip);
  }

  @Post('validate')
  @RequirePermissions(P.configure)
  @RequireMfa()
  @RateClass('sensitive')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Re-check your organization’s AI provider key',
    description:
      'Checks the stored key with the provider again (no tokens generated) and records the ' +
      'outcome: `status` `valid`, `invalid` (refused; turns stop using it) or `unverified` ' +
      '(the provider could not be reached), with `lastValidatedAt` and `lastErrorCode`. Only ' +
      'the status changes. `403 assistant_tenant_keys_disabled` when the platform does not ' +
      'offer organization keys, `404 assistant_tenant_key_not_found` when none is stored. ' +
      'Audited `assistant.provider_key_validated`.' +
      KEY_RULE +
      USER_ONLY_RULE,
  })
  @ApiAssistantResponse(200, TenantKeyViewSchema, X.tenantKey, 'The key with its new status')
  @ApiAssistantForbidden(
    [C.tenantKeysDisabled, 'mfa_required'],
    'an MFA session is needed (`mfa_required`), the platform does not offer organization keys ' +
      '(`assistant_tenant_keys_disabled`)',
  )
  @ApiCodedError(404, 'No key is stored', [C.tenantKeyNotFound])
  @ApiAssistantUnavailable()
  validate(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Client() client: ClientContext,
  ): Promise<TenantKeyView> {
    return this.keys.validate(userOf(principal), scope, client.ip);
  }
}
