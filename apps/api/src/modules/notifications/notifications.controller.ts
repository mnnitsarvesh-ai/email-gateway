import { Body, Controller, Get, Put, UseFilters } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import {
  AuthenticatedOnly,
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
  UserOnly,
} from '../../auth-contracts/decorators';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { ApiCodedError, CodedExceptionFilter } from '../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import { zodToOpenApi } from '../../validation/zod-openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { ApiErrors } from '../auth/api-docs';
import { Client } from '../auth/client-context.decorator';
import type { ClientContext } from '../auth/services/session.service';
import { ApiOkExample } from '../messages/api-docs';
import { NOTIFICATION_ERROR_CODES as C } from './notifications.errors';
import {
  NOTIFICATION_EXAMPLES,
  type PreferencesBody,
  PreferencesBodySchema,
  type PreferencesResponse,
  PreferencesResponseSchema,
  type SettingsResponse,
  SettingsResponseSchema,
  SettingsUpdateBodySchema,
} from './notifications.schemas';
import { NotificationsService } from './notifications.service';

/** Permissions of the tenant settings routes (seed catalog). */
export const ORGANIZATION_READ = 'organization:read';
export const SETTINGS_MANAGE = 'settings:manage';

const ApiUnavailable = (): MethodDecorator =>
  ApiCodedError(
    503,
    'The database returned a row that does not echo the query (`inconsistent_read`, retry) or ' +
      'a dependency is unavailable',
    [C.inconsistentRead, 'service_unavailable'],
  );

/**
 * Security-alert settings of the organization and the caller's own notification preferences
 * (step 6.2 N3, §6.1). Translation only (NotificationsService).
 */
@ApiTags('notifications')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'notifications', version: '1' })
export class NotificationsController {
  constructor(private readonly notifications: NotificationsService) {}

  @Get('settings')
  @RequirePermissions(ORGANIZATION_READ)
  @ApiOperation({
    summary: 'Get the security-alert settings',
    description:
      'The effective settings of the three security alerts (threat detected: enabled, minimum ' +
      'severity `medium`/`high`, throttle window; DNS record failures and webhook disabled: ' +
      'enabled, throttle window; whether `organization_settings.notification_email` also ' +
      'receives them), the stored document, the defaults, the bounds and `rowVersion` (0 while ' +
      'nothing is stored). Alerts go to active, verified users holding the kind’s permission ' +
      '(`quarantine:approve`, `domain:manage`, `webhook:manage`) who did not opt out; one ' +
      'alert per organization, kind, scope and window at most. From the read replica.',
  })
  @ApiOkExample(SettingsResponseSchema, NOTIFICATION_EXAMPLES.settings)
  @ApiErrors(401, 403)
  @ApiUnavailable()
  settings(@CurrentScope() scope: TenantScope): Promise<SettingsResponse> {
    return this.notifications.settings(scope);
  }

  @Put('settings')
  @RequirePermissions(SETTINGS_MANAGE)
  @ApiOperation({
    summary: 'Replace the security-alert settings',
    description:
      'Replaces the whole settings document (every key optional; `{}` restores the defaults) ' +
      'with `expectedRowVersion` (`409 notification_settings_conflict` with ' +
      '`currentRowVersion`; 0 when nothing is stored yet). Bounds: threat throttle 15-1440 ' +
      'minutes, DNS and webhook throttles 60-10080 minutes; unknown keys or values out of bounds ' +
      'are `400 notification_settings_invalid` with `violations` (paths and rules). Takes ' +
      'effect within the delivery worker’s cache TTL. Audited `notification.settings_updated` ' +
      '(changed paths only).',
  })
  @ApiBody({
    schema: zodToOpenApi(SettingsUpdateBodySchema, { io: 'input' }),
    examples: { tighter: { value: NOTIFICATION_EXAMPLES.settingsUpdate } },
  })
  @ApiOkExample(SettingsResponseSchema, NOTIFICATION_EXAMPLES.settings)
  @ApiCodedError(
    400,
    '`validation_failed` (the body is not `{ settings, expectedRowVersion }`) or ' +
      '`notification_settings_invalid` (`violations`: `{ path, message }`)',
    ['validation_failed', C.settingsInvalid],
    {
      violations: {
        type: 'array',
        items: {
          type: 'object',
          properties: { path: { type: 'string' }, message: { type: 'string' } },
        },
      },
    },
  )
  @ApiErrors(401, 403)
  @ApiCodedError(409, '`expectedRowVersion` is not the current version', [C.settingsConflict], {
    currentRowVersion: { type: 'integer' },
  })
  @ApiUnavailable()
  putSettings(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body() body: unknown,
    @Client() client: ClientContext,
  ): Promise<SettingsResponse> {
    return this.notifications.putSettings(principal, scope, body, client);
  }

  @Get('preferences')
  @AuthenticatedOnly()
  @UserOnly()
  @ApiOperation({
    summary: 'Get my notification preferences',
    description:
      'The notification kinds you opted out of (security alerts, policy alerts, quarantine ' +
      'admin alerts and approval requests), your quarantine digest opt-out (the same setting as ' +
      '`/quarantine/me/preferences`) and whether the organization allows it. Users who are ' +
      'members of the organization only: API keys and platform overrides get `403`.',
  })
  @ApiOkExample(PreferencesResponseSchema, NOTIFICATION_EXAMPLES.preferences)
  @ApiErrors(401, 403)
  @ApiUnavailable()
  preferences(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
  ): Promise<PreferencesResponse> {
    return this.notifications.preferences(principal, scope);
  }

  @Put('preferences')
  @AuthenticatedOnly()
  @UserOnly()
  @ApiOperation({
    summary: 'Replace my notification preferences',
    description:
      'Sets the kinds you opt out of (`optOut`, unique) and the quarantine digest opt-out ' +
      '(opting out needs the organization’s `digest.allowOptOut`, `400` otherwise). Decisions ' +
      'on your own release requests and sender notices are not optional. Idempotent (PUT). ' +
      'Audited `notification.preferences_updated`.',
  })
  @ApiBody({
    schema: zodToOpenApi(PreferencesBodySchema, { io: 'input' }),
    examples: { quieter: { value: NOTIFICATION_EXAMPLES.preferencesUpdate } },
  })
  @ApiOkExample(PreferencesResponseSchema, NOTIFICATION_EXAMPLES.preferences)
  @ApiErrors(400, 401, 403)
  @ApiUnavailable()
  putPreferences(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(PreferencesBodySchema)) body: PreferencesBody,
    @Client() client: ClientContext,
  ): Promise<PreferencesResponse> {
    return this.notifications.putPreferences(principal, scope, body, client);
  }
}
