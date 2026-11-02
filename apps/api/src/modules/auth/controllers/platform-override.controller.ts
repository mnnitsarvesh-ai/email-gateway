import { Body, Controller, Delete, HttpCode, HttpStatus, Param, Post } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOperation,
  ApiParam,
  ApiTags,
} from '@nestjs/swagger';
import type { z } from 'zod';
import {
  AuthenticatedOnly,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../api-docs';
import { Client } from '../client-context.decorator';
import { CurrentUser } from '../current-user.decorator';
import {
  OverrideResponseSchema,
  OverrideStartRequestSchema,
  UuidParamSchema,
} from '../dto/auth.schemas';
import {
  OVERRIDE_PERMISSION,
  type OverrideResponse,
  PlatformOverrideService,
} from '../services/platform-override.service';
import type { ClientContext } from '../services/session.service';

/** Audited platform override into one customer organization (D9). */
@ApiTags('platform')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'platform/overrides', version: '1' })
export class PlatformOverrideController {
  constructor(private readonly overrides: PlatformOverrideService) {}

  @Post()
  @RequirePermissions(OVERRIDE_PERMISSION)
  @RequireMfa()
  @ApiOperation({
    summary: 'Start an override into a customer organization',
    description:
      'Platform users with `platform:tenant_override` and an MFA session. Returns a ' +
      'non-refreshable access token scoped to the target organization with tenant permissions ' +
      'only; every request made with it is audited.',
  })
  @ApiBody({ schema: zodToOpenApi(OverrideStartRequestSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(OverrideResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 503)
  start(
    @CurrentUser() principal: UserPrincipal,
    @Body(new ZodValidationPipe(OverrideStartRequestSchema))
    body: z.output<typeof OverrideStartRequestSchema>,
    @Client() client: ClientContext,
  ): Promise<OverrideResponse> {
    return this.overrides.start(principal, body, client);
  }

  @Delete(':overrideId')
  @AuthenticatedOnly()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'End an own override (normal or override token)' })
  @ApiParam({ name: 'overrideId', format: 'uuid' })
  @ApiNoContentResponse({ description: 'Override ended; its token stops working' })
  @ApiErrors(400, 401, 403, 404, 503)
  async end(
    @CurrentUser() principal: UserPrincipal,
    @Param('overrideId', new ZodValidationPipe(UuidParamSchema)) overrideId: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.overrides.end(principal, overrideId, client);
  }
}
