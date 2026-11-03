import { Controller, Get } from '@nestjs/common';
import { ApiBearerAuth, ApiOkResponse, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import { RequirePermissions } from '../../../auth-contracts/decorators';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ApiErrors } from '../../auth/api-docs';
import { DOMAIN_READ } from '../../domains/api-docs';
import {
  type DestinationProviderList,
  DestinationProviderListSchema,
} from '../dto/domain-destinations.schemas';
import { DomainDestinationsService } from '../services/domain-destinations.service';

/** Destination provider presets (step 2.3 R2): platform configuration data, read-only. */
@ApiTags('domains')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'destination-providers', version: '1' })
export class DestinationProvidersController {
  constructor(private readonly destinations: DomainDestinationsService) {}

  @Get()
  @RequirePermissions(DOMAIN_READ)
  @ApiOperation({
    summary: 'List the destination provider presets',
    description:
      'Microsoft 365 and Google Workspace presets for `PUT /domains/{id}/destinations`: host ' +
      'patterns, the forced port and TLS mode (`verify`), the certificate names checked, the ' +
      'maximum number of servers and the preset servers. See docs/domains/destination-servers.md ' +
      'for the customer-side setup.',
  })
  @ApiOkResponse({ schema: zodToOpenApi(DestinationProviderListSchema) })
  @ApiErrors(401, 403)
  list(): Promise<DestinationProviderList> {
    return this.destinations.providers();
  }
}
