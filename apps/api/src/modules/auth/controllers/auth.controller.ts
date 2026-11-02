import { Body, Controller, Get, HttpCode, HttpStatus, Post } from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiBearerAuth,
  ApiBody,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import type { z } from 'zod';
import {
  AllowDuringMfaEnrollment,
  AuthenticatedOnly,
  Public,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { RateLimit } from '../../../rate-limit/rate-limit.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../api-docs';
import { RevokeReason } from '../auth.constants';
import { Client } from '../client-context.decorator';
import { CurrentUser } from '../current-user.decorator';
import {
  InvitationAcceptRequestSchema,
  InvitationDetailsResponseSchema,
  LoginRequestSchema,
  LoginResponseSchema,
  MeResponseSchema,
  MfaVerifyRequestSchema,
  PasswordChangeRequestSchema,
  PasswordForgotRequestSchema,
  PasswordResetRequestSchema,
  RefreshRequestSchema,
  TokenRequestSchema,
  TokenResponseSchema,
} from '../dto/auth.schemas';
import {
  AuthenticationService,
  type LoginResult,
  type MeResponse,
} from '../services/authentication.service';
import { EmailVerificationService } from '../services/email-verification.service';
import { type InvitationDetails, InvitationService } from '../services/invitation.service';
import { PasswordService } from '../services/password.service';
import {
  type ClientContext,
  SessionService,
  type TokenResponse,
} from '../services/session.service';

const input = (schema: z.ZodType) => ({ schema: zodToOpenApi(schema, { io: 'input' }) });
const output = (schema: z.ZodType) => ({ schema: zodToOpenApi(schema) });
const FIFTEEN_MINUTES = 900;

/** Login, tokens, password and email self-service, invitation acceptance (§4.1). */
@ApiTags('auth')
@Controller({ path: 'auth', version: '1' })
export class AuthController {
  constructor(
    private readonly authentication: AuthenticationService,
    private readonly sessions: SessionService,
    private readonly passwords: PasswordService,
    private readonly emailVerification: EmailVerificationService,
    private readonly invitations: InvitationService,
  ) {}

  @Post('login')
  @Public()
  @RateLimit({ bucket: 'auth-login', limit: 20, windowSeconds: 60, by: 'ip' })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Log in with email and password',
    description:
      'Returns the token response, or an MFA challenge when the user has MFA. `organization` ' +
      '(slug) selects the account when the email exists in several organizations. Every ' +
      'failure is `401 Invalid credentials`.',
  })
  @ApiBody(input(LoginRequestSchema))
  @ApiOkResponse(output(LoginResponseSchema))
  @ApiErrors(400, 401, 429, 503)
  login(
    @Body(new ZodValidationPipe(LoginRequestSchema)) body: z.output<typeof LoginRequestSchema>,
    @Client() client: ClientContext,
  ): Promise<LoginResult> {
    return this.authentication.login(body, client);
  }

  @Post('mfa/verify')
  @Public()
  @RateLimit({ bucket: 'auth-mfa-verify', limit: 20, windowSeconds: 60, by: 'ip' })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Complete an MFA login',
    description:
      'Exactly one of `code` (TOTP) or `recoveryCode`. At most 5 attempts per challenge.',
  })
  @ApiBody(input(MfaVerifyRequestSchema))
  @ApiOkResponse(output(TokenResponseSchema))
  @ApiErrors(400, 401, 429, 503)
  verifyMfa(
    @Body(new ZodValidationPipe(MfaVerifyRequestSchema))
    body: z.output<typeof MfaVerifyRequestSchema>,
    @Client() client: ClientContext,
  ): Promise<TokenResponse> {
    return this.authentication.verifyMfa(body, client);
  }

  @Post('refresh')
  @Public()
  @RateLimit({ bucket: 'auth-refresh', limit: 60, windowSeconds: 60, by: 'ip' })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Rotate the refresh token',
    description:
      'Returns new tokens; the presented refresh token is spent. Presenting a spent token ' +
      'revokes the whole session (reuse detection). Clients must serialize refreshes.',
  })
  @ApiBody(input(RefreshRequestSchema))
  @ApiOkResponse(output(TokenResponseSchema))
  @ApiErrors(400, 401, 429, 503)
  refresh(
    @Body(new ZodValidationPipe(RefreshRequestSchema)) body: z.output<typeof RefreshRequestSchema>,
    @Client() client: ClientContext,
  ): Promise<TokenResponse> {
    return this.sessions.rotate(body.refreshToken, client);
  }

  @Post('logout')
  @AuthenticatedOnly()
  @UserOnly()
  @AllowDuringMfaEnrollment()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiBearerAuth(ACCESS_TOKEN_SCHEME)
  @ApiOperation({ summary: 'Revoke the current session' })
  @ApiNoContentResponse({ description: 'Session revoked; its access tokens stop working now' })
  @ApiErrors(401, 403, 503)
  async logout(@CurrentUser() principal: UserPrincipal): Promise<void> {
    await this.authentication.logout(principal);
  }

  @Post('logout-all')
  @AuthenticatedOnly()
  @UserOnly()
  @AllowDuringMfaEnrollment()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiBearerAuth(ACCESS_TOKEN_SCHEME)
  @ApiOperation({ summary: 'Revoke all own sessions, including the current one' })
  @ApiNoContentResponse({ description: 'All sessions revoked' })
  @ApiErrors(401, 403, 503)
  async logoutAll(
    @CurrentUser() principal: UserPrincipal,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.sessions.revokeAllForUserAudited(principal, RevokeReason.logoutAll, client);
  }

  @Get('me')
  @AuthenticatedOnly()
  @UserOnly()
  @AllowDuringMfaEnrollment()
  @ApiBearerAuth(ACCESS_TOKEN_SCHEME)
  @ApiOperation({ summary: 'The current user, organization, roles and effective permissions' })
  @ApiOkResponse(output(MeResponseSchema))
  @ApiErrors(401, 403, 503)
  me(@CurrentUser() principal: UserPrincipal): Promise<MeResponse> {
    return this.authentication.me(principal);
  }

  @Post('password/forgot')
  @Public()
  @RateLimit({ bucket: 'auth-forgot-ip', limit: 5, windowSeconds: FIFTEEN_MINUTES, by: 'ip' })
  @RateLimit({
    bucket: 'auth-forgot-email',
    limit: 3,
    windowSeconds: 3600,
    by: 'body',
    bodyField: 'email',
  })
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Request a password reset link',
    description:
      'Always `202`, whether or not an account matched. Only active accounts whose email is ' +
      'verified receive a link (an address changed by an administrator must be confirmed ' +
      'first). Links expire after 30 minutes.',
  })
  @ApiBody(input(PasswordForgotRequestSchema))
  @ApiAcceptedResponse({ description: 'Accepted' })
  @ApiErrors(400, 429, 503)
  forgotPassword(
    @Body(new ZodValidationPipe(PasswordForgotRequestSchema))
    body: z.output<typeof PasswordForgotRequestSchema>,
    @Client() client: ClientContext,
  ): void {
    this.passwords.requestReset(body, client);
  }

  @Post('password/reset')
  @Public()
  @RateLimit({ bucket: 'auth-reset', limit: 20, windowSeconds: FIFTEEN_MINUTES, by: 'ip' })
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Set a new password with a reset token; signs out everywhere' })
  @ApiBody(input(PasswordResetRequestSchema))
  @ApiNoContentResponse({ description: 'Password changed, all sessions revoked' })
  @ApiErrors(400, 429, 503)
  async resetPassword(
    @Body(new ZodValidationPipe(PasswordResetRequestSchema))
    body: z.output<typeof PasswordResetRequestSchema>,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.passwords.reset(body, client);
  }

  @Post('password/change')
  @AuthenticatedOnly()
  @UserOnly()
  @RateLimit({
    bucket: 'auth-password-change',
    limit: 10,
    windowSeconds: FIFTEEN_MINUTES,
    by: 'ip',
  })
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiBearerAuth(ACCESS_TOKEN_SCHEME)
  @ApiOperation({ summary: 'Change the own password; other sessions are revoked' })
  @ApiBody(input(PasswordChangeRequestSchema))
  @ApiNoContentResponse({ description: 'Password changed' })
  @ApiErrors(400, 401, 403, 429, 503)
  async changePassword(
    @CurrentUser() principal: UserPrincipal,
    @Body(new ZodValidationPipe(PasswordChangeRequestSchema))
    body: z.output<typeof PasswordChangeRequestSchema>,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.passwords.change(principal, body, client);
  }

  @Post('email/verification')
  @AuthenticatedOnly()
  @UserOnly()
  @RateLimit({ bucket: 'auth-email-verification', limit: 10, windowSeconds: 3600, by: 'ip' })
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiBearerAuth(ACCESS_TOKEN_SCHEME)
  @ApiOperation({
    summary: 'Send a verification link to the own email address (if unverified)',
    description: 'At most 3 per hour per user.',
  })
  @ApiAcceptedResponse({ description: 'Accepted' })
  @ApiErrors(401, 403, 429, 503)
  async sendVerification(@CurrentUser() principal: UserPrincipal): Promise<void> {
    await this.emailVerification.resend(principal.userId);
  }

  @Post('email/verify')
  @Public()
  @RateLimit({ bucket: 'auth-email-verify', limit: 20, windowSeconds: FIFTEEN_MINUTES, by: 'ip' })
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Confirm an email address with a verification token' })
  @ApiBody(input(TokenRequestSchema))
  @ApiNoContentResponse({ description: 'Email verified' })
  @ApiErrors(400, 429, 503)
  async verifyEmail(
    @Body(new ZodValidationPipe(TokenRequestSchema)) body: z.output<typeof TokenRequestSchema>,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.emailVerification.verify(body.token, client);
  }

  @Post('invitations/inspect')
  @Public()
  @RateLimit({
    bucket: 'auth-invitation-inspect',
    limit: 20,
    windowSeconds: FIFTEEN_MINUTES,
    by: 'ip',
  })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Show what an invitation token is for (does not consume it)' })
  @ApiBody(input(TokenRequestSchema))
  @ApiOkResponse(output(InvitationDetailsResponseSchema))
  @ApiErrors(400, 429, 503)
  inspectInvitation(
    @Body(new ZodValidationPipe(TokenRequestSchema)) body: z.output<typeof TokenRequestSchema>,
  ): Promise<InvitationDetails> {
    return this.invitations.inspect(body.token);
  }

  @Post('invitations/accept')
  @Public()
  @RateLimit({
    bucket: 'auth-invitation-accept',
    limit: 20,
    windowSeconds: FIFTEEN_MINUTES,
    by: 'ip',
  })
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Accept an invitation: set the password and activate the account' })
  @ApiBody(input(InvitationAcceptRequestSchema))
  @ApiNoContentResponse({ description: 'Account active, email verified' })
  @ApiErrors(400, 429, 503)
  async acceptInvitation(
    @Body(new ZodValidationPipe(InvitationAcceptRequestSchema))
    body: z.output<typeof InvitationAcceptRequestSchema>,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.invitations.accept(body, client);
  }
}
