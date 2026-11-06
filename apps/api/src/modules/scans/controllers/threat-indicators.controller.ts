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
  UseFilters,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiTags,
} from '@nestjs/swagger';
import { RequireMfa, RequirePermissions, UserOnly } from '../../../auth-contracts/decorators';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { CodedExceptionFilter } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { RateLimit } from '../../../rate-limit/rate-limit.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import { CurrentUser } from '../../auth/current-user.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiQueryFrom } from '../../organizations/api-docs';
import {
  ApiIndicatorExists,
  ApiThreatIndicatorNotFound,
  PLATFORM_THREAT_INTEL_MANAGE,
} from '../api-docs';
import {
  type ThreatIndicatorCreate,
  ThreatIndicatorCreateSchema,
  type ThreatIndicatorDeleteQuery,
  ThreatIndicatorDeleteQuerySchema,
  ThreatIndicatorIdSchema,
  type ThreatIndicatorListQuery,
  ThreatIndicatorListQuerySchema,
  type ThreatIndicatorPage,
  ThreatIndicatorPageSchema,
  type ThreatIndicatorView,
  ThreatIndicatorViewSchema,
} from '../dto/threat-indicators.schemas';
import { ThreatIndicatorsService } from '../services/threat-indicators.service';

const idPipe = new ZodValidationPipe(ThreatIndicatorIdSchema);

/**
 * The platform threat-indicator catalog (step 4.3 U16): URLs, domains and IP addresses the URL
 * engine and the click-service treat as malicious (`high`/`critical`) or suspicious
 * (`low`/`medium`), platform-wide and never cached. Platform users only (no API keys, no override
 * tokens), MFA, `platform:threat_intel_manage`, 60 calls per caller per minute. Translation only;
 * the logic is in ThreatIndicatorsService.
 */
@ApiTags('platform')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@UseFilters(CodedExceptionFilter)
@RateLimit({ bucket: 'threat-indicators', limit: 60, windowSeconds: 60, by: 'principal' })
@Controller({ path: 'platform/threat-indicators', version: '1' })
export class ThreatIndicatorsController {
  constructor(private readonly indicators: ThreatIndicatorsService) {}

  @Get()
  @RequirePermissions(PLATFORM_THREAT_INTEL_MANAGE)
  @RequireMfa()
  @ApiOperation({
    summary: 'List the platform threat indicators (URLs, domains, IPs)',
    description:
      'The platform catalog the URL engine and the click-service consult on every scan and ' +
      'click (never cached), newest first, cursor-paginated, optionally one `type`, one ' +
      '`source` (`analyst`, `feed:<name>`) or one `value` (normalized like a new indicator; ' +
      'requires `type`). From the read replica: an indicator added a moment ago may not be ' +
      'listed yet. 60 calls per caller per minute (shared by the catalog routes).',
  })
  @ApiQueryFrom(ThreatIndicatorListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(ThreatIndicatorPageSchema) })
  @ApiErrors(400, 401, 403, 429)
  list(
    @CurrentUser() principal: UserPrincipal,
    @Query(new ZodValidationPipe(ThreatIndicatorListQuerySchema)) query: ThreatIndicatorListQuery,
  ): Promise<ThreatIndicatorPage> {
    return this.indicators.list(principal, query);
  }

  @Post()
  @RequirePermissions(PLATFORM_THREAT_INTEL_MANAGE)
  @RequireMfa()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Add a platform threat indicator',
    description:
      'Adds a URL, domain or IP address with its severity, category, the reason and an ' +
      'optional future `expiresAt`. The value is normalized by `@email-gateway/url-security`: ' +
      'a URL in its identity form (no userinfo, no fragment; matched exactly), a domain as ' +
      'lower-case ASCII (IDN as A-labels; matches the host and every subdomain; a public ' +
      'suffix is refused), an IP address canonical. `source` is `analyst`, the caller is ' +
      'recorded. Applies to the next scan and the next click of every organization: ' +
      '`high`/`critical` → `malicious` (`url.feed_malicious`), `low`/`medium` → `suspicious` ' +
      '(`url.feed_suspicious`). Audited as `threat_indicator.added`. `409 indicator_exists` ' +
      'when the normalized value is listed already.',
  })
  @ApiBody({ schema: zodToOpenApi(ThreatIndicatorCreateSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(ThreatIndicatorViewSchema) })
  @ApiErrors(400, 401, 403, 429)
  @ApiIndicatorExists()
  add(
    @CurrentUser() principal: UserPrincipal,
    @Body(new ZodValidationPipe(ThreatIndicatorCreateSchema)) body: ThreatIndicatorCreate,
    @Client() client: ClientContext,
  ): Promise<ThreatIndicatorView> {
    return this.indicators.add(principal, body, client);
  }

  @Delete(':id')
  @RequirePermissions(PLATFORM_THREAT_INTEL_MANAGE)
  @RequireMfa()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Remove a platform threat indicator',
    description:
      'Deletes the indicator (the next scan and click no longer match it). `reason` is ' +
      'required. Audited as `threat_indicator.removed` with the indicator as it was ' +
      '(before-image).',
  })
  @ApiParam({ name: 'id', description: 'Indicator id (decimal, from the list)' })
  @ApiQueryFrom(ThreatIndicatorDeleteQuerySchema)
  @ApiNoContentResponse({ description: 'Removed' })
  @ApiErrors(400, 401, 403, 429)
  @ApiThreatIndicatorNotFound()
  async remove(
    @CurrentUser() principal: UserPrincipal,
    @Param('id', idPipe) id: string,
    @Query(new ZodValidationPipe(ThreatIndicatorDeleteQuerySchema))
    query: ThreatIndicatorDeleteQuery,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.indicators.remove(principal, BigInt(id), query.reason, client);
  }
}
