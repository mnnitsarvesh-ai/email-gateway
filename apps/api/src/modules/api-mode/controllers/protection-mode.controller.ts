import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Put,
  Res,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  RequireAnyPermission,
  RequirePermissions,
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
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ORGANIZATION_MANAGE,
  ORGANIZATION_READ,
  type OrganizationAccess,
  PLATFORM_ORGANIZATIONS,
} from '../../organizations/domain/organization-access';
import { OrgAccess } from '../../organizations/organization-access.decorator';
import {
  ApiBadId,
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
  API_MODE_EXAMPLES as X,
  DomainModeChangeSchema,
  type DomainModeChangeView,
  OrganizationModeChangeSchema,
  type OrganizationModeChangeView,
  OrganizationProtectionModeSchema,
  type OrganizationProtectionModeView,
  PutDomainModeBodySchema,
  PutOrganizationModeBodySchema,
} from '../dto/api-mode.schemas';
import { ProtectionModeService } from '../services/protection-mode.service';

const MODE_RULES =
  ' `api` and `hybrid` need the plan feature `api_mode_protection` (`403 api_mode_not_enabled`); ' +
  '`inline` is always allowed. A change that makes a domain’s effective mode `api` is refused ' +
  'while its latest MX observation points to the gateway (`409 ' +
  'protection_mode_mx_points_to_gateway`, `details.domains` with at most 20 `{ id, name }`; ' +
  'choose `hybrid` or move the MX records first). The mode never changes inline mail flow ' +
  '(inbound/outbound switches, destinations, connectors). The same value again answers `200` ' +
  'with `changed: false` and no audit row.';

const MX_CONFLICT_DETAILS = { domains: { type: 'array' } };

/**
 * Protection modes of the organization and its domains (step API-1 D1, D2; ADR-0098). The base
 * paths are the organization and domain resources (`/organizations/{id}/protection-mode`,
 * `/domains/{domainId}/protection-mode`); the routes belong to the API-mode area. Translation
 * only: the service owns the rules, the locks and the audit rows.
 */
@ApiTags('api-mode')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ version: '1' })
export class ProtectionModeController {
  constructor(private readonly modes: ProtectionModeService) {}

  @Get('organizations/:id/protection-mode')
  @RequireAnyPermission(ORGANIZATION_READ, PLATFORM_ORGANIZATIONS)
  @ApiOperation({
    summary: 'Get the protection mode of an organization',
    description:
      'The organization’s protection mode (`inline`, `api`, `hybrid`: the default of every ' +
      'domain without its own mode), when it changed, whether the plan entitles API mode, ' +
      'whether API mode is active (entitled and at least one domain effective `api`/`hybrid`) ' +
      'and the non-deleted domains per effective mode. Your own organization (`404 ' +
      'organization_not_found` otherwise; platform staff with `platform:organizations` any). ' +
      'Needs `organization:read`.',
  })
  @ApiParam({ name: 'id', description: 'Organization public id (UUID)', format: 'uuid' })
  @ApiModeResponse(200, OrganizationProtectionModeSchema, X.organizationMode, 'The mode')
  @ApiBadId()
  @ApiModeForbidden()
  @ApiCodedError(404, 'Not your organization, or unknown', [C.organizationNotFound])
  @ApiModeUnavailable()
  getOrganization(
    @OrgAccess() access: OrganizationAccess,
    @Param('id') id: string,
  ): Promise<OrganizationProtectionModeView> {
    return this.modes.getOrganization(access, id);
  }

  @Put('organizations/:id/protection-mode')
  @RequireAnyPermission(ORGANIZATION_MANAGE, PLATFORM_ORGANIZATIONS)
  @HttpCode(HttpStatus.OK)
  @ApiModeIdempotency(API_MODE_OPERATIONS.organizationMode)
  @ApiOperation({
    summary: 'Change the protection mode of an organization',
    description:
      '`{ mode, reason }`: the new default mode of every domain without its own mode (inheriting ' +
      'domains change their effective mode; the response reports how many inherit). The MX check ' +
      'runs over every inheriting domain that would become effective `api`; any conflict refuses ' +
      'the whole change.' +
      MODE_RULES +
      ' Audited `organization.protection_mode_changed` `{ from, to, reason, inheritingDomains, ' +
      'effectiveApiDomains }`. Needs `organization:manage`.' +
      KEYED_RULE,
  })
  @ApiParam({ name: 'id', description: 'Organization public id (UUID)', format: 'uuid' })
  @ApiBody({
    schema: zodToOpenApi(PutOrganizationModeBodySchema, { io: 'input' }),
    examples: { hybrid: { value: X.organizationModeUpdate } },
  })
  @ApiModeResponse(200, OrganizationModeChangeSchema, X.organizationModeChange, 'Changed', true)
  @ApiKeyedErrors()
  @ApiModeForbidden([C.notEnabled], '`api_mode_not_enabled`')
  @ApiCodedError(404, 'Not your organization, or unknown', [C.organizationNotFound])
  @ApiModeConflicts(
    [C.mxPointsToGateway],
    '`protection_mode_mx_points_to_gateway` (`domains`)',
    true,
    MX_CONFLICT_DETAILS,
  )
  @ApiModeUnavailable()
  async putOrganization(
    @OrgAccess() access: OrganizationAccess,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<OrganizationModeChangeView> {
    const result = await this.modes.putOrganization(
      access,
      scope,
      { id, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Put('domains/:domainId/protection-mode')
  @RequirePermissions(P.domainManage)
  @HttpCode(HttpStatus.OK)
  @ApiModeIdempotency(API_MODE_OPERATIONS.domainMode)
  @ApiOperation({
    summary: 'Change the protection mode of a domain',
    description:
      '`{ mode, reason }` with `mode` `inline`, `api`, `hybrid` or `inherit` (clears the ' +
      'domain’s own mode: it follows the organization’s).' +
      MODE_RULES +
      ' Audited `domain.protection_mode_changed` `{ fromConfigured, toConfigured, ' +
      'fromEffective, toEffective, reason }`. Needs `domain:manage`.' +
      KEYED_RULE,
  })
  @ApiParam({ name: 'domainId', description: 'Domain public id (UUID)', format: 'uuid' })
  @ApiBody({
    schema: zodToOpenApi(PutDomainModeBodySchema, { io: 'input' }),
    examples: { api: { value: X.domainModeUpdate } },
  })
  @ApiModeResponse(200, DomainModeChangeSchema, X.domainModeChange, 'Changed', true)
  @ApiKeyedErrors()
  @ApiModeForbidden([C.notEnabled], '`api_mode_not_enabled`')
  @ApiCodedError(404, 'Unknown domain, or one of another organization', [C.domainNotFound])
  @ApiModeConflicts(
    [C.mxPointsToGateway],
    '`protection_mode_mx_points_to_gateway` (`domains`)',
    true,
    MX_CONFLICT_DETAILS,
  )
  @ApiModeUnavailable()
  async putDomain(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('domainId') domainId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<DomainModeChangeView> {
    const result = await this.modes.putDomain(
      principal,
      scope,
      { id: domainId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}
