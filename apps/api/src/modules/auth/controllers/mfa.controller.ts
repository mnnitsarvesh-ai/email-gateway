import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import type { z } from 'zod';
import { ReturnsSecret } from '../../../rate-limit/rate-class.decorator';
import {
  AllowDuringMfaEnrollment,
  AuthenticatedOnly,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { RateLimit } from '../../../rate-limit/rate-limit.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../api-docs';
import { Client } from '../client-context.decorator';
import { CurrentUser } from '../current-user.decorator';
import {
  MfaDisableRequestSchema,
  RecoveryCodesResponseSchema,
  TotpCodeRequestSchema,
  TotpSetupResponseSchema,
} from '../dto/auth.schemas';
import { MfaService } from '../services/mfa.service';
import type { ClientContext } from '../services/session.service';

/** Self-service TOTP enrollment and recovery codes (D7). */
@ApiTags('mfa')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@AuthenticatedOnly()
@UserOnly()
@Controller({ path: 'auth/mfa', version: '1' })
export class MfaController {
  constructor(private readonly mfa: MfaService) {}

  @Post('totp/setup')
  @ReturnsSecret()
  @AllowDuringMfaEnrollment()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Start TOTP enrollment',
    description: 'Stores a new pending secret and returns it once with its otpauth:// URI.',
  })
  @ApiOkResponse({ schema: zodToOpenApi(TotpSetupResponseSchema) })
  @ApiErrors(401, 403, 409, 503)
  setup(
    @CurrentUser() principal: UserPrincipal,
  ): Promise<z.output<typeof TotpSetupResponseSchema>> {
    return this.mfa.setup(principal);
  }

  @Post('totp/enable')
  @AllowDuringMfaEnrollment()
  @RateLimit({ bucket: 'auth-mfa-enable', limit: 10, windowSeconds: 900, by: 'ip' })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Confirm TOTP enrollment with a code',
    description:
      'Enables MFA, returns 10 single-use recovery codes (shown once), marks the current ' +
      'session MFA-authenticated and revokes every other session.',
  })
  @ApiBody({ schema: zodToOpenApi(TotpCodeRequestSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(RecoveryCodesResponseSchema) })
  @ApiErrors(400, 401, 403, 409, 429, 503)
  enable(
    @CurrentUser() principal: UserPrincipal,
    @Body(new ZodValidationPipe(TotpCodeRequestSchema))
    body: z.output<typeof TotpCodeRequestSchema>,
    @Client() client: ClientContext,
  ): Promise<z.output<typeof RecoveryCodesResponseSchema>> {
    return this.mfa.enable(principal, body.code, client);
  }

  @Post('totp/disable')
  @RateLimit({ bucket: 'auth-mfa-disable', limit: 10, windowSeconds: 900, by: 'ip' })
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Turn MFA off (password and code required)',
    description: '`409` while the organization requires MFA.',
  })
  @ApiBody({ schema: zodToOpenApi(MfaDisableRequestSchema, { io: 'input' }) })
  @ApiNoContentResponse({ description: 'MFA disabled' })
  @ApiErrors(400, 401, 403, 409, 429, 503)
  async disable(
    @CurrentUser() principal: UserPrincipal,
    @Body(new ZodValidationPipe(MfaDisableRequestSchema))
    body: z.output<typeof MfaDisableRequestSchema>,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.mfa.disable(principal, body, client);
  }

  @Post('recovery-codes')
  @ReturnsSecret()
  @RateLimit({ bucket: 'auth-recovery-codes', limit: 10, windowSeconds: 900, by: 'ip' })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Replace all recovery codes (TOTP code required)' })
  @ApiBody({ schema: zodToOpenApi(TotpCodeRequestSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(RecoveryCodesResponseSchema) })
  @ApiErrors(400, 401, 403, 409, 429, 503)
  regenerate(
    @CurrentUser() principal: UserPrincipal,
    @Body(new ZodValidationPipe(TotpCodeRequestSchema))
    body: z.output<typeof TotpCodeRequestSchema>,
    @Client() client: ClientContext,
  ): Promise<z.output<typeof RecoveryCodesResponseSchema>> {
    return this.mfa.regenerateRecoveryCodes(principal, body.code, client);
  }
}
