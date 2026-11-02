import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { ApiConfig } from '../../../config';
import { PasswordHasher } from '../../../crypto/password-hasher';
import { checkPasswordPolicy } from '../../../crypto/password-policy';
import { TransactionRunner } from '../../../database/transaction-runner';
import { EmailSender } from '../../../email/email-sender';
import { buildPortalLink, passwordResetEmail } from '../../../email/templates';
import { INVALID_TOKEN, RevokeReason } from '../auth.constants';
import { OrganizationsAuthRepository } from '../repositories/organizations-auth.repository';
import { UsersAuthRepository } from '../repositories/users-auth.repository';
import { LoginThrottleService } from './login-throttle.service';
import { PrincipalCacheService } from './principal-cache.service';
import { type ClientContext, isUsable, SessionService } from './session.service';
import { UserTokenService } from './user-token.service';

export type PasswordConfig = Pick<
  ApiConfig,
  'AUTH_PASSWORD_RESET_TTL_SECONDS' | 'PORTAL_PUBLIC_URL'
>;

/** Throws `400` with the policy reasons (never the password). */
export function assertPasswordPolicy(password: string, email: string, field: string): void {
  const reasons = checkPasswordPolicy(password, { email });
  if (reasons.length > 0) {
    throw new BadRequestException(reasons.map((reason) => `${field}: ${reason}`));
  }
}

/** Forgot / reset / change password (§4.1). */
@Injectable()
export class PasswordService {
  private readonly logger = new Logger(PasswordService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: PasswordConfig,
    private readonly users: UsersAuthRepository,
    private readonly organizations: OrganizationsAuthRepository,
    private readonly passwords: PasswordHasher,
    private readonly userTokens: UserTokenService,
    private readonly transactions: TransactionRunner,
    private readonly sessions: SessionService,
    private readonly throttle: LoginThrottleService,
    private readonly audit: AuditService,
    private readonly principalCache: PrincipalCacheService,
    private readonly emailSender: EmailSender,
  ) {}

  /**
   * `POST /auth/password/forgot`: always `202`. The work runs after the response is decided, so
   * neither the answer nor its timing reveals whether any account matched. Every active account
   * with the email (in the slug's organization, if given) receives its own reset link.
   */
  requestReset(input: { email: string; organization?: string }, context: ClientContext): void {
    void this.sendResetLinks(input, context).catch((err: unknown) =>
      this.logger.error({ message: 'Password reset request failed', err }),
    );
  }

  /** Exposed for tests; callers use `requestReset`. */
  async sendResetLinks(
    input: { email: string; organization?: string },
    context: ClientContext,
  ): Promise<number> {
    const email = input.email.trim().toLowerCase();
    let organizationId: bigint | undefined;
    if (input.organization !== undefined) {
      const org = await this.organizations.findBySlug(input.organization.trim().toLowerCase());
      if (!org) return 0;
      organizationId = org.id;
    }
    const accounts = await this.users.findActiveAccountsByEmail(email, organizationId);
    for (const user of accounts) {
      const issued = await this.transactions.run((tx) =>
        this.userTokens.issue(tx, {
          userId: user.id,
          organizationId: user.organizationId,
          purpose: 'password_reset',
          ttlSeconds: this.config.AUTH_PASSWORD_RESET_TTL_SECONDS,
          createdIp: context.ip,
        }),
      );
      try {
        await this.emailSender.send(
          passwordResetEmail({
            to: user.email,
            link: buildPortalLink('reset-password', issued.token, this.config.PORTAL_PUBLIC_URL),
            expiresAt: issued.expiresAt,
          }),
        );
      } catch (err) {
        this.logger.error({ message: 'Password reset email not delivered', err });
      }
    }
    return accounts.length;
  }

  /** `POST /auth/password/reset`: single-use token; signs the user out everywhere. */
  async reset(
    input: { token: string; newPassword: string },
    context: ClientContext,
  ): Promise<void> {
    const row = await this.userTokens.find(input.token, 'password_reset');
    const user = row ? await this.users.findById(row.userId) : null;
    if (!row || !user || !isUsable(user)) throw new BadRequestException(INVALID_TOKEN);
    assertPasswordPolicy(input.newPassword, user.email, 'newPassword');
    const hash = await this.passwords.hash(input.newPassword);
    await this.transactions.run(async (tx) => {
      if (!(await this.userTokens.consume(tx, row))) throw new BadRequestException(INVALID_TOKEN);
      await this.users.setPassword(tx, user.id, hash, new Date());
      await this.audit.record(
        {
          organizationId: user.organizationId,
          actor: { type: 'user', id: user.publicId },
          action: 'auth.password_reset',
          resourceType: 'user',
          resourceId: user.publicId,
          sourceIp: context.ip,
        },
        tx,
      );
    });
    await this.sessions.revokeAllForUser(user.id, RevokeReason.passwordReset);
    await this.throttle.clearForUser(user.id);
    await this.principalCache.invalidateUserByPublicId(user.publicId);
  }

  /** `POST /auth/password/change`: requires the current password; keeps the current session. */
  async change(
    principal: UserPrincipal,
    input: { currentPassword: string; newPassword: string },
    context: ClientContext,
  ): Promise<void> {
    const user = await this.users.findById(principal.userId);
    if (!user || user.deletedAt) throw new NotFoundException('User not found');
    if (!(await this.passwords.verify(user.passwordHash, input.currentPassword))) {
      throw new ForbiddenException('Current password is incorrect');
    }
    assertPasswordPolicy(input.newPassword, user.email, 'newPassword');
    const hash = await this.passwords.hash(input.newPassword);
    await this.transactions.run(async (tx) => {
      await this.users.setPassword(tx, user.id, hash, new Date());
      await this.audit.record(
        {
          organizationId: user.organizationId,
          actor: this.audit.actorFrom(principal),
          action: 'auth.password_changed',
          resourceType: 'user',
          resourceId: user.publicId,
          sourceIp: context.ip,
        },
        tx,
      );
    });
    await this.sessions.revokeAllForUser(user.id, RevokeReason.passwordChanged, {
      exceptSessionId: principal.sessionId,
    });
  }
}
