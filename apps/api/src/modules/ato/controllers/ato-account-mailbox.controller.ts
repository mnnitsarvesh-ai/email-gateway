import { Controller, Get, Headers, HttpCode, HttpStatus, Param, Post, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
} from '../../../http/idempotency/idempotency-key';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { TransactionalIdempotency } from '../../messages/api-docs';
import {
  ApiAccountIdParam,
  ApiAccountNotFound,
  ApiAtoForbidden,
  ApiAtoKeyedErrors,
  ApiAtoUnavailable,
} from '../api-docs';
import {
  ApiProviderResponse,
  ATO_PROVIDER_EXAMPLES as X,
  PROVIDER_MUTATION_RULE,
} from '../ato-providers.api-docs';
import { ATO_OPERATIONS as O, ATO_PERMISSIONS as P } from '../ato.constants';
import { ATO_ERROR_CODES as C } from '../ato.errors';
import {
  MailboxRefreshSchema,
  type MailboxRefreshView,
  MailboxStateSchema,
  type MailboxStateView,
} from '../dto/ato-providers.schemas';
import { AtoMailboxStateService } from '../services/ato-mailbox-state.service';

/**
 * The mailbox state of a monitored account (step 8.5 §6 #12–#13, D8.3): forwarding, inbox rules,
 * delegates and mailbox permissions as the identity-provider integrations observed them, and the
 * priority refresh. Translation only.
 */
@ApiTags('ato')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'ato/accounts', version: '1' })
export class AtoAccountMailboxController {
  constructor(private readonly mailbox: AtoMailboxStateService) {}

  @Get(':accountId/mailbox-state')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get the mailbox state of a monitored account',
    description:
      'Forwarding, inbox rules (Graph message rules, Gmail filters), delegates, mailbox ' +
      'permissions and send-as rights the identity-provider integrations observed for the ' +
      'account: present items and items removed in the last 30 days (≤ 500; `truncated`) with ' +
      'kind, state, target **domain** (never the address), trait codes (never the rule ' +
      'keywords), enabled, source (snapshot or audit), provider and integration; the account’s ' +
      'provider identities with their directory status and refresh request; each integration’s ' +
      'last mailbox sweep. `404 ato_account_not_found` for an unknown or foreign account or ' +
      'while ATO is not enabled.',
  })
  @ApiAccountIdParam()
  @ApiProviderResponse(200, MailboxStateSchema, X.mailboxState, 'The mailbox state')
  @ApiAccountNotFound()
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('accountId') accountId: string,
  ): Promise<MailboxStateView> {
    return this.mailbox.get(scope, accountId);
  }

  @Post(':accountId/mailbox-state/refresh')
  @RequirePermissions(P.manage)
  @HttpCode(HttpStatus.ACCEPTED)
  @TransactionalIdempotency(O.mailboxRefresh)
  @ApiOperation({
    summary: 'Request a priority refresh of the mailbox state',
    description:
      'Flags the account’s identities whose integration supports a priority refresh (active, ' +
      'its mailbox-state stream enabled and available); the ato-worker reads their mailbox ' +
      'settings first in its next poll. `202`; `409 ato_provider_refresh_unavailable` when no ' +
      'identity qualifies. Audited `ato.mailbox_state.refresh_requested`. Users and API keys. ' +
      'No body.' +
      PROVIDER_MUTATION_RULE,
  })
  @ApiAccountIdParam()
  @ApiProviderResponse(
    202,
    MailboxRefreshSchema,
    X.mailboxRefresh,
    'The refresh is requested',
    true,
  )
  @ApiAtoKeyedErrors([C.providerRefreshUnavailable])
  @ApiAccountNotFound()
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async refresh(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('accountId') accountId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<MailboxRefreshView> {
    const result = await this.mailbox.refresh(principal, scope, accountId, key, {}, client.ip);
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}
