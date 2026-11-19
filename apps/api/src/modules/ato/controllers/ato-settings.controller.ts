import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Put,
  Query,
  Res,
} from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import { atoSettingsSchema } from '@email-gateway/ato-detection';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
} from '../../../http/idempotency/idempotency-key';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiListErrors, ApiListQuery, TransactionalIdempotency } from '../../messages/api-docs';
import {
  ApiAtoForbidden,
  ApiAtoKeyedErrors,
  ApiAtoResponse,
  ApiAtoUnavailable,
  FEATURE_OFF_READ,
  MUTATION_RULE,
} from '../api-docs';
import { ATO_OPERATIONS as O, ATO_PERMISSIONS as P } from '../ato.constants';
import { ATO_ERROR_CODES as C } from '../ato.errors';
import { ATO_EXAMPLES as X } from '../dto/ato.examples';
import {
  PAGE_PARAMETERS,
  type RestrictionListQuery,
  RestrictionListQuerySchema,
  type RestrictionPage,
  RestrictionPageSchema,
  RulesViewSchema,
  type RulesView,
  SettingsViewSchema,
  type SettingsView,
  type UpdateSettingsBody,
  UpdateSettingsBodySchema,
} from '../dto/ato.schemas';
import { AtoSettingsService } from '../services/ato-settings.service';

/** OpenAPI body of `PUT /ato/settings`: the envelope with the documented `ato-settings/1`. */
const settingsBodyDoc = (() => {
  const envelope = zodToOpenApi(UpdateSettingsBodySchema, { io: 'input' }) as {
    properties?: Record<string, unknown>;
  };
  return {
    ...envelope,
    properties: {
      ...(envelope.properties ?? {}),
      settings: {
        ...zodToOpenApi(atoSettingsSchema, { io: 'input' }),
        description:
          '`ato-settings/1` (strict; every key optional, `{}` = defaults; see the bounds in the ' +
          'GET response). Validated as a whole: `400 ato_settings_invalid` lists the failing paths.',
      },
    },
  };
})();

/** ATO settings (step 8.4 §5.1 #24, #25). Translation only. */
@ApiTags('ato')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'ato', version: '1' })
export class AtoSettingsController {
  constructor(private readonly settings: AtoSettingsService) {}

  @Get('settings')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get the account takeover settings',
    description:
      'Whether ATO is enabled for your organization (`featureEnabled`), the stored and effective ' +
      '`ato-settings/1` (mode, learning period, scoring bands and gates, rules, IP reputation, ' +
      'baselines, geography, notifications, automation, restrictions), `version` and ' +
      '`rowVersion` (send with PUT; 0 before the first change), the bounds, the worker ' +
      'capabilities (`unknown` when the worker has not reported for 15 minutes), the gateway ' +
      'sources with their last event time, the identity providers (available in step 8.5) and ' +
      'whether an active tenant policy uses `ato.*` fields (`policy.atoFieldsInUse`).',
  })
  @ApiAtoResponse(200, SettingsViewSchema, X.settings, 'The settings')
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  get(@CurrentScope() scope: TenantScope): Promise<SettingsView> {
    return this.settings.get(scope);
  }

  @Put('settings')
  @RequirePermissions(P.configure)
  @UserOnly()
  @HttpCode(HttpStatus.OK)
  @TransactionalIdempotency(O.settingsUpdate)
  @ApiOperation({
    summary: 'Update the account takeover settings',
    description:
      'Replaces the stored settings document with `settings` (the explicit values; defaults ' +
      'apply to everything else) with `expectedRowVersion` (`409 ato_settings_conflict` with ' +
      '`currentRowVersion`). Validated strictly, including the cross-field rules (ordered bands, ' +
      'thresholds, CIDRs, SOC e-mails, automation only for catalogue types with `automatic` for ' +
      'medium/high impact only at `minLevel` high or critical, rule parameters): `400 ' +
      'ato_settings_invalid` with `issues[]` (`path`, `message`; never values). Each change ' +
      'creates a new `version` and an audit row `ato.settings_updated` with the changed paths. ' +
      'The ato-worker applies changes within ATO_SETTINGS_CACHE_SECONDS. Users only.' +
      MUTATION_RULE,
  })
  @ApiBody({ schema: settingsBodyDoc, examples: { monitor: { value: X.updateSettings } } })
  @ApiAtoResponse(200, SettingsViewSchema, X.settings, 'The updated settings', true)
  @ApiAtoKeyedErrors([C.settingsConflict], [], [C.settingsInvalid])
  @ApiAtoForbidden([], true)
  @ApiAtoUnavailable()
  async update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(UpdateSettingsBodySchema)) body: UpdateSettingsBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<SettingsView> {
    const result = await this.settings.update(principal, scope, key, body, client.ip);
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}

/** SMTP restrictions (step 8.4 §5.1 #23). Translation only. */
@ApiTags('ato')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'ato', version: '1' })
export class AtoRestrictionsController {
  constructor(private readonly settings: AtoSettingsService) {}

  @Get('restrictions')
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List SMTP restrictions',
    description:
      'Sending restrictions (`send_block`: mailbox or connector) and authentication blocks ' +
      '(`auth_block`: connector or connector + IP range) applied by responses, newest first: ' +
      'mode, status, expiry, the response that applied them and how they ended. Filters ' +
      '`status` (default `active`), `kind`, `scope` (lists).' +
      FEATURE_OFF_READ,
  })
  @ApiListQuery(RestrictionListQuerySchema, {
    ...PAGE_PARAMETERS,
    sort: '`-createdAt`',
    status: '`active` (default), `lifted`, `expired` (comma list)',
    kind: '`send_block`, `auth_block` (comma list)',
    scope: '`mailbox`, `connector`, `connector_ip` (comma list)',
  })
  @ApiAtoResponse(200, RestrictionPageSchema, X.restrictionPage, 'One page of restrictions')
  @ApiListErrors()
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(RestrictionListQuerySchema)) query: RestrictionListQuery,
  ): Promise<RestrictionPage> {
    return this.settings.restrictions(principal, scope, query);
  }
}

/** The rule catalogue (step 8.4 §5.1 #26). Translation only. */
@ApiTags('ato')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'ato', version: '1' })
export class AtoRulesController {
  constructor(private readonly settings: AtoSettingsService) {}

  @Get('rules')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'List the account takeover rules',
    description:
      'The `ato-rules/1` catalogue: code, title, category, strength, account kinds, sources, ' +
      'default weight, the effective state of your settings (enabled, weight, parameters), the ' +
      'parameter bounds, the capabilities a rule needs and its availability (`false` with the ' +
      'missing capabilities when, for example, no GeoIP database is configured; ' +
      '`capabilities_unknown` while the worker has not reported).',
  })
  @ApiAtoResponse(200, RulesViewSchema, X.rules, 'The rule catalogue')
  @ApiAtoForbidden()
  @ApiAtoUnavailable()
  list(@CurrentScope() scope: TenantScope): Promise<RulesView> {
    return this.settings.rules(scope);
  }
}
