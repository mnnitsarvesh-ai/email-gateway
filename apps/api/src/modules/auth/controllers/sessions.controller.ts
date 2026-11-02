import {
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiTags,
} from '@nestjs/swagger';
import {
  AllowDuringMfaEnrollment,
  AuthenticatedOnly,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { scopeFromPrincipal } from '../../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../api-docs';
import { Client } from '../client-context.decorator';
import { CurrentUser } from '../current-user.decorator';
import { SessionListResponseSchema, UuidParamSchema } from '../dto/auth.schemas';
import {
  type ClientContext,
  SessionService,
  type SessionView,
  toSessionView,
} from '../services/session.service';

/** The caller's own sessions (§4.1). Administrators use `/users/{id}/sessions` (WP4). */
@ApiTags('sessions')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@AuthenticatedOnly()
@UserOnly()
@Controller({ path: 'auth/sessions', version: '1' })
export class SessionsController {
  constructor(private readonly sessions: SessionService) {}

  @Get()
  @AllowDuringMfaEnrollment()
  @ApiOperation({
    summary: 'List own live sessions',
    description: 'Read from the replica; a just-created session may appear after a short delay.',
  })
  @ApiOkResponse({ schema: zodToOpenApi(SessionListResponseSchema) })
  @ApiErrors(401, 403, 503)
  async list(@CurrentUser() principal: UserPrincipal): Promise<{ data: SessionView[] }> {
    // Own sessions live in the home organization, also while an override scopes elsewhere.
    const home = scopeFromPrincipal({ ...principal, override: undefined });
    const rows = await this.sessions.listLiveForUser(home, principal.userId);
    return { data: rows.map((row) => toSessionView(row, principal.sessionId)) };
  }

  @Delete(':sessionId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Revoke one own session' })
  @ApiParam({ name: 'sessionId', format: 'uuid' })
  @ApiNoContentResponse({ description: 'Session revoked' })
  @ApiErrors(400, 401, 403, 404, 503)
  async revoke(
    @CurrentUser() principal: UserPrincipal,
    @Param('sessionId', new ZodValidationPipe(UuidParamSchema)) sessionId: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    if (!(await this.sessions.revokeOwnSession(principal, sessionId, client))) {
      throw new NotFoundException('Session not found');
    }
  }
}
