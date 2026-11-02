import { BadRequestException, Inject, Injectable, Logger } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { ApiConfig } from '../../../config';
import { PasswordHasher } from '../../../crypto/password-hasher';
import { TransactionRunner } from '../../../database/transaction-runner';
import { EmailSender } from '../../../email/email-sender';
import { buildPortalLink, invitationEmail } from '../../../email/templates';
import { INVALID_TOKEN } from '../auth.constants';
import type { UserTokenRow } from '../repositories/user-tokens.repository';
import { type AuthUserRecord, UsersAuthRepository } from '../repositories/users-auth.repository';
import { assertPasswordPolicy } from './password.service';
import { PrincipalCacheService } from './principal-cache.service';
import type { ClientContext } from './session.service';
import { type IssuedUserToken, UserTokenService } from './user-token.service';

export type InvitationConfig = Pick<ApiConfig, 'AUTH_INVITATION_TTL_SECONDS' | 'PORTAL_PUBLIC_URL'>;

export interface InvitationEmailInput {
  email: string;
  displayName: string;
  organizationName: string;
  token: string;
  expiresAt: Date;
}

export interface InvitationDetails {
  email: string;
  organizationName: string;
  expiresAt: string;
}

/**
 * Invitation tokens (D11) and their acceptance (§4.1). Identity administration (WP4) creates the
 * invited user and calls `createToken` inside its transaction and `sendInvitation` after commit.
 */
@Injectable()
export class InvitationService {
  private readonly logger = new Logger(InvitationService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: InvitationConfig,
    private readonly users: UsersAuthRepository,
    private readonly userTokens: UserTokenService,
    private readonly passwords: PasswordHasher,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
    private readonly principalCache: PrincipalCacheService,
    private readonly emailSender: EmailSender,
  ) {}

  /** Issues the invitation token (retiring earlier ones) inside the caller's transaction. */
  createToken(
    tx: Prisma.TransactionClient,
    input: { userId: bigint; organizationId: bigint; createdByUserId: bigint | null },
  ): Promise<IssuedUserToken> {
    return this.userTokens.issue(tx, {
      userId: input.userId,
      organizationId: input.organizationId,
      purpose: 'invitation',
      ttlSeconds: this.config.AUTH_INVITATION_TTL_SECONDS,
      createdByUserId: input.createdByUserId,
    });
  }

  /** The acceptance link (`#token=` fragment) for a raw invitation token. */
  link(token: string): string {
    return buildPortalLink('accept-invitation', token, this.config.PORTAL_PUBLIC_URL);
  }

  /**
   * Sends the invitation email. Call after the transaction commits. A delivery failure is
   * logged (without the token) and reported as `false`; nothing is rolled back.
   */
  async sendInvitation(input: InvitationEmailInput): Promise<boolean> {
    try {
      await this.emailSender.send(
        invitationEmail({
          to: input.email,
          displayName: input.displayName,
          organizationName: input.organizationName,
          link: this.link(input.token),
          expiresAt: input.expiresAt,
        }),
      );
      return true;
    } catch (err) {
      this.logger.error({ message: 'Invitation email not delivered', err });
      return false;
    }
  }

  /** `POST /auth/invitations/inspect`: does not consume the token. */
  async inspect(token: string): Promise<InvitationDetails> {
    const { row, user } = await this.resolve(token);
    return {
      email: user.email,
      organizationName: user.organization.name,
      expiresAt: row.expiresAt.toISOString(),
    };
  }

  /**
   * `POST /auth/invitations/accept`: the user must still be invited and the organization
   * active. Sets the password, activates the user and marks the email verified.
   */
  async accept(
    input: { token: string; password: string; displayName?: string },
    context: ClientContext,
  ): Promise<void> {
    const { row, user } = await this.resolve(input.token);
    assertPasswordPolicy(input.password, user.email, 'password');
    const passwordHash = await this.passwords.hash(input.password);
    await this.transactions.run(async (tx) => {
      if (!(await this.userTokens.consume(tx, row))) throw new BadRequestException(INVALID_TOKEN);
      const activated = await this.users.activateInvitedUser(tx, user.id, {
        passwordHash,
        now: new Date(),
        ...(input.displayName !== undefined && { displayName: input.displayName }),
      });
      if (!activated) throw new BadRequestException(INVALID_TOKEN);
      await this.audit.record(
        {
          organizationId: user.organizationId,
          actor: { type: 'user', id: user.publicId },
          action: 'user.invitation_accepted',
          resourceType: 'user',
          resourceId: user.publicId,
          sourceIp: context.ip,
        },
        tx,
      );
    });
    await this.principalCache.invalidateUserByPublicId(user.publicId);
  }

  private async resolve(token: string): Promise<{ row: UserTokenRow; user: AuthUserRecord }> {
    const row = await this.userTokens.find(token, 'invitation');
    const user = row ? await this.users.findById(row.userId) : null;
    if (
      !row ||
      !user ||
      user.status !== 'invited' ||
      user.deletedAt !== null ||
      user.organization.status !== 'active' ||
      user.organization.deletedAt !== null
    ) {
      throw new BadRequestException(INVALID_TOKEN);
    }
    return { row, user };
  }
}
