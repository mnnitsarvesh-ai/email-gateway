import { Body, Controller, Get, Headers, HttpCode, HttpStatus, Put, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
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
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ApiKeyedErrors,
  ApiModeConflicts,
  ApiModeForbidden,
  ApiModeIdempotency,
  ApiModeResponse,
  ApiModeUnavailable,
  KEYED_RULE,
} from '../api-docs';
import { API_MODE_OPERATIONS, API_MODE_PERMISSIONS as P } from '../api-mode.constants';
import { API_MODE_ERROR_CODES as C } from '../api-mode.errors';
import {
  CLAWBACK_EXAMPLES as X,
  OrgSettingsChangeSchema,
  type OrgSettingsChangeView,
  OrgSettingsViewSchema,
  type OrgSettingsView,
  PutOrgSettingsBodySchema,
} from '../dto/api-mode-clawback.schemas';
import { OrgSettingsService } from '../services/org-settings.service';

/**
 * The organization's API-mode settings (step API-3 §3.1, C14 #18, #19,
 * docs/plan/steps/37-api-mode-clawback-reporting.md): internal mail, automatic clawback mode and
 * cap, the purge approval threshold, the clawback lookback, the threat-intelligence confidence and
 * reporter feedback. Read with `remediation:read`, replaced with `remediation:write` (CAS).
 * Translation only.
 */
@ApiTags('api-mode')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'api-mode', version: '1' })
export class ApiModeSettingsController {
  constructor(private readonly settings: OrgSettingsService) {}

  @Get('settings')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get the organization’s API-mode settings',
    description:
      'The effective settings (`source: defaults` when no row exists): internal-mail recording ' +
      'and remediation, automatic clawback (`enforce`, `review`, `off`) and its cap of eligible ' +
      'mailboxes, the purge approval threshold of distinct mailboxes (P2), the clawback ' +
      'lookback, the threat-intelligence confidence floor and the reporter acknowledgement and ' +
      'result e-mails; the defaults, the bounds and the platform facts (`hardDeleteAvailable`, ' +
      'the longest search window, the approval TTL, the most report mailboxes). Needs ' +
      '`remediation:read`.',
  })
  @ApiModeResponse(200, OrgSettingsViewSchema, X.settings, 'The settings')
  @ApiModeForbidden()
  @ApiModeUnavailable()
  get(@CurrentScope() scope: TenantScope): Promise<OrgSettingsView> {
    return this.settings.get(scope);
  }

  @Put('settings')
  @RequirePermissions(P.write)
  @HttpCode(HttpStatus.OK)
  @ApiModeIdempotency(API_MODE_OPERATIONS.orgSettingsPut)
  @ApiOperation({
    summary: 'Set the organization’s API-mode settings',
    description:
      '`{ internalMailEnabled, autoClawback, autoMaxMailboxes (1-20000), purgeApprovalMailboxes ' +
      '(1-10000), clawbackLookbackDays (1-60), tiMinConfidence (50-100), reportAckEnabled, ' +
      'reportFeedbackEnabled, reason, expectedRowVersion }` replaces all values. CAS: ' +
      '`expectedRowVersion` is the version read (null when no row exists: the PUT creates it); ' +
      'a mismatch → `409 api_mode_settings_conflict` (`currentRowVersion`). Audited ' +
      '`api_mode.settings_org_updated` with the changed values before and after. Needs ' +
      '`remediation:write`.' +
      KEYED_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(PutOrgSettingsBodySchema, { io: 'input' }),
    examples: { review: { value: X.putSettings } },
  })
  @ApiModeResponse(200, OrgSettingsChangeSchema, X.settingsChange, 'The stored settings', true)
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiModeConflicts(
    [C.settingsConflict],
    '`api_mode_settings_conflict` (`currentRowVersion`)',
    true,
    { currentRowVersion: { type: 'integer' } },
  )
  @ApiModeUnavailable()
  async put(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<OrgSettingsChangeView> {
    const result = await this.settings.put(principal, scope, { idempotencyKey, body }, client.ip);
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}
