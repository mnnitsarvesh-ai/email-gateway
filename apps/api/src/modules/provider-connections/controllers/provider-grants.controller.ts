import {
  Body,
  Controller,
  Delete,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Put,
  Res,
  UseFilters,
} from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError, CodedExceptionFilter } from '../../../http/coded-exception';
import {
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
} from '../../../http/idempotency/idempotency-key';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { RateClass, ReturnsSecret } from '../../../rate-limit/rate-class.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ApiConnectionId,
  ApiConnectionNotFound,
  ApiKeyedBadRequest,
  ApiKeyedConflict,
  ApiKeyedResponse,
  ApiKeyedUnprocessable,
  ApiProfileParam,
  ApiUnavailable,
  KEYED_RULE,
  ProviderIdempotency,
  REDACTED_REPLAY_RULE,
} from '../api-docs';
import {
  CompleteConsentBodySchema,
  type ConsentCompletedView,
  ConsentCompletedSchema,
  CreateGrantBodySchema,
  type CreatedGrantView,
  CreatedGrantSchema,
  type GrantView,
  GrantSchema,
  PROVIDER_EXAMPLES,
  type RevokedGrantView,
  RevokedGrantSchema,
  SetCredentialsBodySchema,
  VerifyGrantBodySchema,
} from '../dto/provider-connections.schemas';
import { INTEGRATION_MANAGE, PROVIDER_OPERATIONS } from '../provider-connections.constants';
import { PROVIDER_ERROR_CODES as C } from '../provider-connections.errors';
import { ProviderGrantsService } from '../services/provider-grants.service';

const GRANT_CONFLICTS = [C.connectionDisabled, C.connectionVersionConflict];

/**
 * Grants of a connection (step 8.2 §5.2 #8–12; D2, D3, D5; ADR-0076, ADR-0077). Translation only
 * (ProviderGrantsService). The static `consent/complete` route is declared before `{id}` routes.
 */
@ApiTags('provider-connections')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'provider-connections', version: '1' })
export class ProviderGrantsController {
  constructor(private readonly grants: ProviderGrantsService) {}

  @Post('consent/complete')
  @RequirePermissions(INTEGRATION_MANAGE)
  @HttpCode(HttpStatus.OK)
  @ProviderIdempotency(PROVIDER_OPERATIONS.consentComplete)
  @RateClass('sensitive')
  @ApiOperation({
    summary: 'Complete a Microsoft admin consent',
    description:
      'Posted by the portal’s consent callback page with the values of the redirect in the ' +
      'JSON body (never as query parameters): `{ state, tenant, adminConsent }` or `{ state, ' +
      'error, errorDescription }`. The state is single-use, expires after ' +
      'PROVIDER_CONSENT_STATE_TTL_SECONDS and is bound to your organization, your user and the ' +
      'grant (`404 consent_state_invalid` otherwise; API keys `403 user_principal_required`). ' +
      'The tenant of the redirect is only a claim: the integration-worker verifies it with a ' +
      'token for that tenant (grant `verifying`, then `active`) and binds the connection to it ' +
      'only when a linked, TXT-verified domain of your organization is verified in that tenant ' +
      '(until then the connection shows no tenant id or name). A declined consent ' +
      'sets the grant `error` (`consent_declined`). Returns the connection id for the redirect. ' +
      'Audited `integration.grant_consented` (≤ 256 sanitized characters of a provider error ' +
      'description; never the state). Rate class `sensitive`.' +
      KEYED_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(CompleteConsentBodySchema, { io: 'input' }),
    examples: { consented: { value: PROVIDER_EXAMPLES.completeConsent } },
  })
  @ApiKeyedResponse(200, ConsentCompletedSchema, PROVIDER_EXAMPLES.consentCompleted, 'Recorded')
  @ApiKeyedBadRequest()
  @ApiErrors(401)
  @ApiCodedError(403, 'Missing permission, or an API key (`user_principal_required`)', [
    'forbidden',
    C.userPrincipalRequired,
  ])
  @ApiCodedError(404, '`consent_state_invalid`: unknown, expired, used or another user’s state', [
    C.consentStateInvalid,
  ])
  @ApiKeyedConflict(GRANT_CONFLICTS, '`connection_disabled`')
  @ApiKeyedUnprocessable([C.credentialInvalid], '`credential_invalid` (`field: tenant`)')
  @ApiUnavailable()
  async completeConsent(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ConsentCompletedView> {
    const result = await this.grants.completeConsent(
      principal,
      scope,
      { idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post(':id/grants')
  @RequirePermissions(INTEGRATION_MANAGE)
  @ProviderIdempotency(PROVIDER_OPERATIONS.grantCreate)
  @ReturnsSecret({ redactedReplay: true })
  @ApiOperation({
    summary: 'Grant read-only access to the provider tenant',
    description:
      '`{ profile, authMethod }` → a `pending_consent` grant (one per profile: `409 ' +
      'grant_exists`; a revoked grant is reused). `platform_app` (Microsoft 365, user sessions ' +
      'only): `consent.consentUrl`, the admin-consent URL of the operator’s read-only app with a ' +
      'single-use state (10 minutes; only its SHA-256 is stored). `platform_service_account` ' +
      '(Google): `delegation` with the client id and scopes to authorize under domain-wide ' +
      'delegation, then `POST …/grants/{profile}/verify { subjectEmail }`. Customer methods: ' +
      'upload the credential next (`PUT …/grants/{profile}/credentials`). Platform methods need ' +
      'the operator’s app (`422 auth_method_unavailable`); the method must belong to the ' +
      'profile and provider (`422 auth_method_not_allowed`). Audited `integration.grant_created`.' +
      REDACTED_REPLAY_RULE('consent.consentUrl') +
      KEYED_RULE,
  })
  @ApiConnectionId()
  @ApiBody({
    schema: zodToOpenApi(CreateGrantBodySchema, { io: 'input' }),
    examples: { platformApp: { value: PROVIDER_EXAMPLES.createGrant } },
  })
  @ApiKeyedResponse(
    201,
    CreatedGrantSchema,
    PROVIDER_EXAMPLES.createdGrant,
    'Created; `consent.consentUrl` is shown only here (`null` on a replay)',
  )
  @ApiKeyedBadRequest()
  @ApiErrors(401)
  @ApiCodedError(403, 'Missing permission, or an API key with `platform_app`', [
    'forbidden',
    C.userPrincipalRequired,
  ])
  @ApiConnectionNotFound()
  @ApiUnavailable()
  @ApiKeyedConflict(
    [C.grantExists, ...GRANT_CONFLICTS],
    '`grant_exists` (`status`), `connection_disabled`',
  )
  @ApiKeyedUnprocessable(
    [C.authMethodUnavailable, C.authMethodNotAllowed],
    '`auth_method_unavailable`, `auth_method_not_allowed` (`authMethod`)',
  )
  async create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<CreatedGrantView> {
    const result = await this.grants.create(
      principal,
      scope,
      { id, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Put(':id/grants/:profile/credentials')
  @RequirePermissions(INTEGRATION_MANAGE)
  @HttpCode(HttpStatus.OK)
  @ProviderIdempotency(PROVIDER_OPERATIONS.credentialsSet)
  @RateClass('sensitive')
  @ApiOperation({
    summary: 'Upload the credential of a customer-owned app or service account',
    description:
      'Customer methods only (`422 auth_method_not_allowed`). Microsoft 365 ' +
      '(`customer_app_secret`): `{ tenantId, clientId, clientSecret, expiresAt? }`; Google ' +
      '(`customer_service_account`): `{ serviceAccountKey, subjectEmail }` (unknown key fields ' +
      'are dropped; `token_uri` must be the platform’s Google token URL; RSA ≥ 2048 bits). The ' +
      'credential is validated (`422 credential_invalid` naming the field, never the value), ' +
      'encrypted with AES-256-GCM under the dedicated provider key bound to this grant and ' +
      'version (ADR-0077), never returned, logged or audited; the response shows only a ' +
      '12-character fingerprint and dates. The grant goes `verifying` (the integration-worker ' +
      'verifies it). Redacted replay (ADR-0057): the stored response never contains the ' +
      'credential and the request fingerprint is an HMAC of it. Audited ' +
      '`integration.grant_credentials_set`. Rate class `sensitive`.' +
      KEYED_RULE,
  })
  @ApiConnectionId()
  @ApiProfileParam()
  @ApiBody({
    schema: zodToOpenApi(SetCredentialsBodySchema, { io: 'input' }),
    examples: {
      microsoft365: { value: PROVIDER_EXAMPLES.setM365Credentials },
      googleWorkspace: { value: PROVIDER_EXAMPLES.setGoogleCredentials },
    },
  })
  @ApiKeyedResponse(200, GrantSchema, PROVIDER_EXAMPLES.grantWithCredential, 'Stored, verifying')
  @ApiKeyedBadRequest()
  @ApiErrors(401, 403)
  @ApiConnectionNotFound([C.grantNotFound])
  @ApiUnavailable()
  @ApiKeyedConflict(GRANT_CONFLICTS, '`connection_disabled`')
  @ApiKeyedUnprocessable(
    [C.credentialInvalid, C.authMethodNotAllowed],
    '`credential_invalid` (`field`), `auth_method_not_allowed`',
  )
  async setCredentials(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Param('profile') profile: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<GrantView> {
    const result = await this.grants.setCredentials(
      principal,
      scope,
      { id, profile, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post(':id/grants/:profile/verify')
  @RequirePermissions(INTEGRATION_MANAGE)
  @HttpCode(HttpStatus.OK)
  @ProviderIdempotency(PROVIDER_OPERATIONS.grantVerify)
  @RateClass('sensitive')
  @ApiOperation({
    summary: 'Verify a grant again',
    description:
      'Asks the integration-worker to verify the grant (`verifying`): token acquisition for the ' +
      'tenant, tenant identity and granted permissions. Google platform service account: ' +
      '`{ subjectEmail }` (the delegated administrator) is required the first time (it confirms ' +
      'the delegation). A customer grant needs its credential, a Microsoft platform grant its ' +
      'consent (`422 credential_invalid`). Audited `integration.grant_consented` (delegation ' +
      'confirmed) or `integration.grant_verification_requested`.' +
      KEYED_RULE,
  })
  @ApiConnectionId()
  @ApiProfileParam()
  @ApiBody({
    schema: zodToOpenApi(VerifyGrantBodySchema, { io: 'input' }),
    examples: { delegation: { value: PROVIDER_EXAMPLES.verify } },
  })
  @ApiKeyedResponse(
    200,
    GrantSchema,
    { ...PROVIDER_EXAMPLES.createdGrant.grant, status: 'verifying' },
    'Verification requested',
  )
  @ApiKeyedBadRequest()
  @ApiErrors(401, 403)
  @ApiConnectionNotFound([C.grantNotFound])
  @ApiUnavailable()
  @ApiKeyedConflict(GRANT_CONFLICTS, '`connection_disabled`')
  @ApiKeyedUnprocessable(
    [C.credentialInvalid, C.authMethodNotAllowed],
    '`credential_invalid` (`field`), `auth_method_not_allowed`',
  )
  async verify(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Param('profile') profile: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<GrantView> {
    const result = await this.grants.verify(
      principal,
      scope,
      { id, profile, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Delete(':id/grants/:profile')
  @RequirePermissions(INTEGRATION_MANAGE)
  @HttpCode(HttpStatus.OK)
  @ProviderIdempotency(PROVIDER_OPERATIONS.grantRevoke)
  @RateClass('sensitive')
  @ApiOperation({
    summary: 'Revoke a grant',
    description:
      'The grant becomes `revoked` and its credential ciphertext is wiped; open consent states ' +
      'are closed; a connection without a live grant releases its tenant binding. Refused while ' +
      'outbound routing is on (`409 outbound_active`: turn it off first). The gateway cannot ' +
      'revoke consent at the provider (it holds no write permission): the response lists the ' +
      'provider-side removal steps. Audited `integration.grant_revoked`.' +
      KEYED_RULE,
  })
  @ApiConnectionId()
  @ApiProfileParam()
  @ApiKeyedResponse(200, RevokedGrantSchema, PROVIDER_EXAMPLES.revoked, 'Revoked')
  @ApiKeyedBadRequest()
  @ApiErrors(401, 403)
  @ApiConnectionNotFound([C.grantNotFound])
  @ApiUnavailable()
  @ApiKeyedConflict(
    [C.outboundActive, ...GRANT_CONFLICTS],
    '`outbound_active`, `connection_disabled`',
  )
  @ApiKeyedUnprocessable()
  async revoke(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Param('profile') profile: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RevokedGrantView> {
    const result = await this.grants.revoke(
      principal,
      scope,
      { id, profile, idempotencyKey },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}
