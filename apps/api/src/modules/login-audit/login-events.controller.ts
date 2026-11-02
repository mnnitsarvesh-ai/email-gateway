import { Controller, Get, Query } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOkResponse,
  ApiOperation,
  ApiQuery,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import { CurrentScope, RequirePermissions } from '../../auth-contracts/decorators';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import type { Page } from '../../http/pagination';
import { zodToOpenApi } from '../../validation/zod-openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { ApiErrors } from '../auth/api-docs';
import {
  LOGIN_OUTCOMES,
  LoginEventListResponseSchema,
  type LoginEventsQuery,
  LoginEventsQuerySchema,
  type LoginEventView,
} from './login-events.schemas';
import { LoginEventsService } from './login-events.service';

/** Login attempts of the caller's organization (§4.2). The general audit log comes with step 6.1. */
@ApiTags('audit')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'audit/login-events', version: '1' })
export class LoginEventsController {
  constructor(private readonly events: LoginEventsService) {}

  @Get()
  @RequirePermissions('audit:read')
  @ApiOperation({
    summary: 'List login events',
    description:
      'Newest first, cursor-paginated, read from the replica. Window `[from, to)` defaults to ' +
      'the last 7 days and spans at most 90 days.',
  })
  @ApiQuery({ name: 'from', required: false, schema: { type: 'string', format: 'date-time' } })
  @ApiQuery({ name: 'to', required: false, schema: { type: 'string', format: 'date-time' } })
  @ApiQuery({
    name: 'outcome',
    required: false,
    schema: { type: 'string', enum: [...LOGIN_OUTCOMES] },
  })
  @ApiQuery({ name: 'userId', required: false, schema: { type: 'string', format: 'uuid' } })
  @ApiQuery({
    name: 'limit',
    required: false,
    schema: { type: 'integer', minimum: 1, maximum: 100 },
  })
  @ApiQuery({ name: 'cursor', required: false, schema: { type: 'string' } })
  @ApiOkResponse({ schema: zodToOpenApi(LoginEventListResponseSchema) })
  @ApiErrors(400, 401, 403, 503)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(LoginEventsQuerySchema)) query: LoginEventsQuery,
  ): Promise<Page<LoginEventView>> {
    return this.events.list(scope, query);
  }
}
