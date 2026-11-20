import { Body, Controller, Get, Headers, HttpCode, HttpStatus, Put, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  RequireAnyPermission,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError } from '../../../http/coded-exception';
import {
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
} from '../../../http/idempotency/idempotency-key';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ARCHIVE_ERROR_CODES as A } from '../../archive/archive.errors';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ApiJournalConflicts,
  ApiJournalForbidden,
  ApiJournalResponse,
  ApiJournalUnavailable,
  ApiJournalUnprocessable,
  ApiKeyedErrors,
  JournalIdempotency,
  MFA_RULE,
} from '../api-docs';
import {
  JOURNALING_EXAMPLES as X,
  type JournalingSettingsView,
  JournalingSettingsViewSchema,
  JournalingStatusSchema,
  type JournalingStatusView,
  type UpdateJournalingSettingsBody,
  UpdateJournalingSettingsBodySchema,
} from '../dto/journaling.schemas';
import { JOURNAL_OPERATIONS, JOURNAL_PERMISSIONS as P } from '../journaling.constants';
import { JournalingSettingsService } from '../services/journaling-settings.service';

/**
 * The Journaling area (step 8.6 D11, ADR-0089): the capture half of the archive settings and
 * the journaling status. Translation only (services own the rules).
 */
@ApiTags('journaling')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'journaling', version: '1' })
export class JournalingController {
  constructor(private readonly settings: JournalingSettingsService) {}

  @Get('settings')
  @RequireAnyPermission(P.read, P.archiveRead)
  @ApiOperation({
    summary: 'Get the journaling settings',
    description:
      'The journaling (capture) half of your organization’s archive settings: whether ' +
      'journaling is enabled, entitled (`archiving`) and journal intake entitled ' +
      '(`journal_intake`) and available on this platform, when it was enabled, the effective ' +
      'directions, included outcomes, scope, policy-rule archiving and intake scanning, the ' +
      '`generation` and the `rowVersion` shared with GET /archive/settings (send it with PUT). ' +
      'Needs `journal:read` or `archive:read`. From the read replica.',
  })
  @ApiJournalResponse(200, JournalingSettingsViewSchema, X.settings, 'The journaling settings')
  @ApiJournalForbidden()
  @ApiJournalUnavailable()
  get(@CurrentScope() scope: TenantScope): Promise<JournalingSettingsView> {
    return this.settings.get(scope);
  }

  @Put('settings')
  @RequirePermissions(P.manage)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @JournalIdempotency(JOURNAL_OPERATIONS.settingsUpdate)
  @ApiOperation({
    summary: 'Update the journaling settings',
    description:
      'Changes `enabled` and/or the journaling sections of `archive-settings/1` ' +
      '(`directions`, `include`, `scope`, `policyArchive`, `intake.scanEnabled`) of the SAME ' +
      'settings row as PUT /archive/settings, with `expectedRowVersion` (`409 ' +
      'archive_settings_conflict` with `currentRowVersion`). The given sections replace the ' +
      'stored journaling sections; the Archive-area settings (immutability, default retention, ' +
      'access) are never changed here. The 8.1 rules apply: enabling needs the plan feature ' +
      '`archiving` (`403 archiving_not_enabled`) and a live default retention policy (`422 ' +
      'archive_default_retention_required`); scope ids must be your organization’s (`422 ' +
      'archive_scope_reference_invalid`, `path`). `intake.scanEnabled` applies to journal ' +
      'intake messages received afterwards. Audited `archive.settings_updated` with `area: ' +
      'journaling` (changed paths, never values). Requires `journal:manage` and the ' +
      'Idempotency-Key header; rate class `sensitive`.' +
      MFA_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(UpdateJournalingSettingsBodySchema, { io: 'input' }),
    examples: { scanIntake: { value: X.settingsUpdate } },
  })
  @ApiJournalResponse(200, JournalingSettingsViewSchema, X.settings, 'The updated settings', true)
  @ApiKeyedErrors()
  @ApiJournalForbidden(
    [A.notEnabled],
    '`archiving_not_enabled` when enabling without the plan feature',
  )
  @ApiJournalConflicts(
    [A.settingsConflict],
    '`archive_settings_conflict` (`currentRowVersion`)',
    true,
    { currentRowVersion: { type: 'integer' } },
  )
  @ApiJournalUnprocessable(
    [A.defaultRetentionRequired, A.scopeReferenceInvalid],
    '`archive_default_retention_required`, `archive_scope_reference_invalid` (`path`)',
    true,
    { path: { type: 'string' } },
  )
  @ApiJournalUnavailable()
  async update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body(new ZodValidationPipe(UpdateJournalingSettingsBodySchema))
    body: UpdateJournalingSettingsBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<JournalingSettingsView> {
    const result = await this.settings.update(principal, scope, idempotencyKey, body, client.ip);
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get('status')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get the journaling status',
    description:
      'Capture backlog of your organization (capture intents by status, oldest pending), ' +
      'journal intake sources by status and by health (sources that are not disabled), and ' +
      'today’s intake counters (UTC day, summed over the sources; flushed by the gateway every ' +
      'JOURNAL_INTAKE_COUNTER_FLUSH_SECONDS). From the read replica.',
  })
  @ApiJournalResponse(200, JournalingStatusSchema, X.status, 'The journaling status')
  @ApiJournalForbidden()
  @ApiCodedError(503, 'An inconsistent read or a dependency is unavailable', [
    'inconsistent_read',
    'service_unavailable',
  ])
  status(@CurrentScope() scope: TenantScope): Promise<JournalingStatusView> {
    return this.settings.status(scope);
  }
}
