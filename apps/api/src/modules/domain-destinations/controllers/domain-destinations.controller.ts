import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Put,
  UseFilters,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { RateLimit } from '../../../rate-limit/rate-limit.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiDomainId, DOMAIN_READ, domainIdPipe } from '../../domains/api-docs';
import { ApiDestinationRefusal } from '../api-docs';
import { DESTINATIONS_WRITE_LIMIT, DOMAIN_ROUTING_MANAGE } from '../domain-destinations.constants';
import { DestinationRefusalFilter } from '../domain-destinations.errors';
import {
  DomainDestinationsSchema,
  type DomainDestinationsView,
  type PutDestinationsInput,
  PutDestinationsSchema,
} from '../dto/domain-destinations.schemas';
import { DomainDestinationsService } from '../services/domain-destinations.service';

const WRITE_LIMIT = {
  bucket: 'domain-destinations-write',
  ...DESTINATIONS_WRITE_LIMIT,
  by: 'principal',
} as const;

/**
 * Where a domain's inbound and internal mail is delivered (step 2.3 R2, R13): the tenant's
 * own servers or a provider preset. The tenant always comes from the credential.
 */
@ApiTags('domains')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(DestinationRefusalFilter)
@Controller({ path: 'domains', version: '1' })
export class DomainDestinationsController {
  constructor(private readonly destinations: DomainDestinationsService) {}

  @Get(':id/destinations')
  @RequirePermissions(DOMAIN_READ)
  @ApiOperation({
    summary: 'Get the destination servers of a domain',
    description:
      'Inbound destinations only, in delivery order (priority, then insertion order); the ' +
      'gateway fails over in this order. From the read replica (a few seconds behind a change).',
  })
  @ApiDomainId()
  @ApiOkResponse({ schema: zodToOpenApi(DomainDestinationsSchema) })
  @ApiErrors(400, 401, 403, 404)
  get(
    @CurrentScope() scope: TenantScope,
    @Param('id', domainIdPipe) id: string,
  ): Promise<DomainDestinationsView> {
    return this.destinations.get(scope, id);
  }

  @Put(':id/destinations')
  @RequirePermissions(DOMAIN_ROUTING_MANAGE)
  @RateLimit(WRITE_LIMIT)
  @ApiOperation({
    summary: 'Replace the destination servers of a domain',
    description:
      'Atomically replaces every destination. `{ provider: microsoft_365, host }` (one host ' +
      'of the preset’s patterns), `{ provider: google_workspace }` (the preset’s servers) or ' +
      '`{ provider: custom, servers: [...] }` (1..`ROUTING_MAX_DESTINATIONS_PER_DOMAIN`, ' +
      'defaults port 25, priority 10, `opportunistic`). Presets force their port and verified ' +
      'TLS. Refused hosts are `422` with a stable `reason`; a deleted domain is `409`. The ' +
      'change reaches the mail path within seconds (`domain.routing.changed.v1`). Needs ' +
      '`domain:routing_manage`; at most 30 changes per caller per minute (`429`).',
  })
  @ApiDomainId()
  @ApiBody({ schema: zodToOpenApi(PutDestinationsSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(DomainDestinationsSchema) })
  @ApiErrors(400, 401, 403, 404, 409, 429)
  @ApiDestinationRefusal()
  replace(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', domainIdPipe) id: string,
    @Body(new ZodValidationPipe(PutDestinationsSchema)) body: PutDestinationsInput,
    @Client() client: ClientContext,
  ): Promise<DomainDestinationsView> {
    return this.destinations.replace(principal, scope, id, body, client);
  }

  @Delete(':id/destinations')
  @RequirePermissions(DOMAIN_ROUTING_MANAGE)
  @RateLimit(WRITE_LIMIT)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Remove the destination servers of a domain',
    description:
      'Removes every destination: mail for the domain is then held (deferred, ' +
      '`no_destination`) until destinations are set again or the queue lifetime expires. A ' +
      'deleted domain is `409`.',
  })
  @ApiDomainId()
  @ApiNoContentResponse({ description: 'Removed' })
  @ApiErrors(400, 401, 403, 404, 409, 429)
  remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', domainIdPipe) id: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    return this.destinations.remove(principal, scope, id, client);
  }
}
