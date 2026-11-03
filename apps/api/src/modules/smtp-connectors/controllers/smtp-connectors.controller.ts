import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
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
import type { Page } from '../../../http/pagination';
import { RateLimit } from '../../../rate-limit/rate-limit.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiQueryFrom } from '../../organizations/api-docs';
import {
  ApiConnectorId,
  CONNECTOR_MANAGE,
  CONNECTOR_READ,
  connectorIdPipe,
  SHARED_IP_WARNING,
} from '../api-docs';
import {
  ConnectorPageSchema,
  ConnectorSchema,
  type ConnectorView,
  type CreateConnectorInput,
  CreateConnectorSchema,
  type CreatedConnector,
  CreatedConnectorSchema,
  type ListConnectorsQuery,
  ListConnectorsQuerySchema,
  type RotatedSecret,
  RotatedSecretSchema,
  type UpdateConnectorInput,
  UpdateConnectorSchema,
} from '../dto/smtp-connectors.schemas';
import { SmtpConnectorsService } from '../services/smtp-connectors.service';

/**
 * Outbound SMTP connectors of the caller's organization (step 2.2 §4.1, D10). The tenant
 * always comes from the credential; responses never contain a secret hash.
 */
@ApiTags('smtp-connectors')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'smtp-connectors', version: '1' })
export class SmtpConnectorsController {
  constructor(private readonly connectors: SmtpConnectorsService) {}

  @Post()
  @RequirePermissions(CONNECTOR_MANAGE)
  @RateLimit({ bucket: 'smtp-connectors-create', limit: 20, windowSeconds: 60, by: 'principal' })
  @ApiOperation({
    summary: 'Create an outbound SMTP connector',
    description:
      'One authentication method per connector. `sasl`: SMTP AUTH on port 587 after STARTTLS; ' +
      'the username (`egc-…`) and a random password are generated and returned **once** in ' +
      '`credentials` (only an Argon2id hash is stored; rotate it if it is lost). `source_ip`: ' +
      '1–20 networks (IPv4 ≥ /16, IPv6 ≥ /48) on the port 25 relay listener; networks must be ' +
      'publicly routable (private, loopback, link-local, shared, documentation, multicast and ' +
      'reserved ranges are `400` unless the deployment sets ' +
      '`SMTP_CONNECTOR_ALLOW_NON_PUBLIC_NETWORKS`) and may not ' +
      'overlap any network of any connector (`409 Network overlaps an existing connector ' +
      'network`). `client_certificate`: the SHA-256 fingerprint of the client certificate ' +
      'presented on port 25 (globally unique, `409`), optionally restricted to networks. ' +
      '`requireTls` (default true) only applies to `source_ip`; the other types always need ' +
      `TLS. At most \`SMTP_CONNECTORS_MAX_PER_ORGANIZATION\` (default 50) per organization (\`409\`). ` +
      'At most 20 per caller per minute (`429`).\n\n' +
      SHARED_IP_WARNING,
  })
  @ApiBody({ schema: zodToOpenApi(CreateConnectorSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(CreatedConnectorSchema) })
  @ApiErrors(400, 401, 403, 409, 429, 503)
  create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(CreateConnectorSchema)) body: CreateConnectorInput,
    @Client() client: ClientContext,
  ): Promise<CreatedConnector> {
    return this.connectors.create(principal, scope, body, client);
  }

  @Get()
  @RequirePermissions(CONNECTOR_READ)
  @ApiOperation({
    summary: 'List SMTP connectors',
    description: 'Newest first, cursor-paginated, from the read replica. Never secrets.',
  })
  @ApiQueryFrom(ListConnectorsQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(ConnectorPageSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ListConnectorsQuerySchema)) query: ListConnectorsQuery,
  ): Promise<Page<ConnectorView>> {
    return this.connectors.list(scope, query);
  }

  @Get(':id')
  @RequirePermissions(CONNECTOR_READ)
  @ApiOperation({ summary: 'Get an SMTP connector', description: 'Never secrets.' })
  @ApiConnectorId()
  @ApiOkResponse({ schema: zodToOpenApi(ConnectorSchema) })
  @ApiErrors(400, 401, 403, 404)
  get(
    @CurrentScope() scope: TenantScope,
    @Param('id', connectorIdPipe) id: string,
  ): Promise<ConnectorView> {
    return this.connectors.get(scope, id);
  }

  @Patch(':id')
  @RequirePermissions(CONNECTOR_MANAGE)
  @ApiOperation({
    summary: 'Update an SMTP connector',
    description:
      'Rename, enable/disable (`status`), change `requireTls` (source_ip only) or replace the ' +
      'networks atomically (same rules as on create, `409` on overlap). A disabled connector ' +
      'authorizes nothing; the change reaches the mail path within the adapter cache TTL ' +
      '(about 30 s).\n\n' +
      SHARED_IP_WARNING,
  })
  @ApiConnectorId()
  @ApiBody({ schema: zodToOpenApi(UpdateConnectorSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(ConnectorSchema) })
  @ApiErrors(400, 401, 403, 404, 409, 503)
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', connectorIdPipe) id: string,
    @Body(new ZodValidationPipe(UpdateConnectorSchema)) body: UpdateConnectorInput,
    @Client() client: ClientContext,
  ): Promise<ConnectorView> {
    return this.connectors.update(principal, scope, id, body, client);
  }

  @Post(':id/rotate-secret')
  @RequirePermissions(CONNECTOR_MANAGE)
  @RateLimit({ bucket: 'smtp-connectors-rotate', limit: 10, windowSeconds: 60, by: 'principal' })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Rotate the SASL password of a connector',
    description:
      '`sasl` connectors only (`409` otherwise). Returns a new password **once**; the previous ' +
      'password stops working immediately. At most 10 per caller per minute (`429`).',
  })
  @ApiConnectorId()
  @ApiOkResponse({ schema: zodToOpenApi(RotatedSecretSchema) })
  @ApiErrors(400, 401, 403, 404, 409, 429)
  rotateSecret(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', connectorIdPipe) id: string,
    @Client() client: ClientContext,
  ): Promise<RotatedSecret> {
    return this.connectors.rotateSecret(principal, scope, id, client);
  }

  @Delete(':id')
  @RequirePermissions(CONNECTOR_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete an SMTP connector',
    description: 'Hard delete; its networks are removed with it and free for other connectors.',
  })
  @ApiConnectorId()
  @ApiNoContentResponse({ description: 'Deleted' })
  @ApiErrors(400, 401, 403, 404)
  remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', connectorIdPipe) id: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    return this.connectors.remove(principal, scope, id, client);
  }
}
