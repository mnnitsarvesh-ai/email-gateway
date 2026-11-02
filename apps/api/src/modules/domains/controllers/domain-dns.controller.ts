import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  UseInterceptors,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
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
import {
  ApiDomainId,
  DOMAIN_DKIM_ROTATE,
  DOMAIN_MANAGE,
  DOMAIN_READ,
  domainIdPipe,
} from '../api-docs';
import {
  type DnsRecordsResponse,
  DnsRecordsResponseSchema,
  type DomainStatusView,
  DomainStatusViewSchema,
  OptionalRotateDkimSchema,
  type RotateDkimInput,
  type RotateDkimResponse,
  RotateDkimResponseSchema,
  RotateDkimSchema,
} from '../dto/domains.schemas';
import { DkimRotationService } from '../services/dkim-rotation.service';
import { DomainVerificationService } from '../services/domain-verification.service';
import { DomainsService } from '../services/domains.service';
import { RetryAfterInterceptor } from './retry-after.interceptor';

/** Verification, DNS records, status and DKIM rotation of a domain (§4). */
@ApiTags('domains')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'domains', version: '1' })
export class DomainDnsController {
  constructor(
    private readonly domains: DomainsService,
    private readonly verification: DomainVerificationService,
    private readonly rotation: DkimRotationService,
  ) {}

  @Post(':id/verify')
  @RequirePermissions(DOMAIN_MANAGE)
  @RateLimit({ bucket: 'domains-verify', limit: 30, windowSeconds: 60, by: 'ip' })
  @UseInterceptors(RetryAfterInterceptor)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Check the DNS records now',
    description:
      'Runs a fresh check (DNS cache bypassed) and returns the status view. A failed domain ' +
      'restarts verification first. DNS failures (timeouts, SERVFAIL) are not errors: the ' +
      'result is `200` with `lastOutcome: indeterminate` and the retry scheduled; the status ' +
      'never changes because of them. At most 6 per domain per minute (`429` with ' +
      '`Retry-After`); `409` while another check of the domain is running.',
  })
  @ApiDomainId()
  @ApiOkResponse({ schema: zodToOpenApi(DomainStatusViewSchema) })
  @ApiErrors(400, 401, 403, 404, 409, 429, 503)
  verify(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', domainIdPipe) id: string,
    @Client() client: ClientContext,
  ): Promise<DomainStatusView> {
    return this.verification.verifyNow(principal, scope, id, client);
  }

  @Get(':id/dns-records')
  @RequirePermissions(DOMAIN_READ)
  @ApiOperation({
    summary: 'DNS records to publish',
    description:
      'Every record with its requirement (activation, inbound, outbound, recommended), the ' +
      'value to publish, the last check result and instructions; `cleanup` lists TXT records ' +
      'of DKIM selectors retired in the last 30 days that can be deleted.',
  })
  @ApiDomainId()
  @ApiOkResponse({ schema: zodToOpenApi(DnsRecordsResponseSchema) })
  @ApiErrors(400, 401, 403, 404)
  dnsRecords(
    @CurrentScope() scope: TenantScope,
    @Param('id', domainIdPipe) id: string,
  ): Promise<DnsRecordsResponse> {
    return this.domains.dnsRecords(scope, id);
  }

  @Get(':id/status')
  @RequirePermissions(DOMAIN_READ)
  @ApiOperation({
    summary: 'Verification and configuration status',
    description:
      'Stored state only (no DNS lookups): readiness for activation, mail-flow readiness and a ' +
      'summary per check (ownership, MX with propagation, SPF, DKIM, DMARC).',
  })
  @ApiDomainId()
  @ApiOkResponse({ schema: zodToOpenApi(DomainStatusViewSchema) })
  @ApiErrors(400, 401, 403, 404)
  status(
    @CurrentScope() scope: TenantScope,
    @Param('id', domainIdPipe) id: string,
  ): Promise<DomainStatusView> {
    return this.verification.statusView(scope, id);
  }

  @Post(':id/dkim/rotate')
  @RequirePermissions(DOMAIN_DKIM_ROTATE)
  @RateLimit({ bucket: 'domains-dkim-rotate', limit: 30, windowSeconds: 60, by: 'principal' })
  @UseInterceptors(RetryAfterInterceptor)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Rotate a DKIM key',
    description:
      'Creates a new pending key of the algorithm (default rsa_2048) whose TXT record must be ' +
      'published; once it validates, it becomes active and the previous key keeps signing ' +
      'verification valid for the overlap period, then is retired. `409` when a rotation of ' +
      'that algorithm is already in progress. At most 10 per domain per 24 hours and 30 per ' +
      'caller per minute (`429` with `Retry-After`).',
  })
  @ApiDomainId()
  @ApiBody({ required: false, schema: zodToOpenApi(RotateDkimSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(RotateDkimResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 409, 429, 503)
  rotate(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', domainIdPipe) id: string,
    @Body(new ZodValidationPipe(OptionalRotateDkimSchema)) body: RotateDkimInput,
    @Client() client: ClientContext,
  ): Promise<RotateDkimResponse> {
    return this.rotation.rotate(principal, scope, id, body, client);
  }
}
