import {
  BadRequestException,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  Logger,
} from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { ApiConfig } from '../../../config';
import { TransactionRunner } from '../../../database/transaction-runner';
import { EmailSender } from '../../../email/email-sender';
import { buildPortalLink, emailVerificationEmail } from '../../../email/templates';
import { KeyValueStore } from '../../../kv/key-value-store';
import {
  EMAIL_VERIFICATION_RESEND_LIMIT,
  EMAIL_VERIFICATION_RESEND_WINDOW_SECONDS,
  INVALID_TOKEN,
  kvKeys,
} from '../auth.constants';
import { UsersAuthRepository } from '../repositories/users-auth.repository';
import { failClosed } from './kv-fail-closed';
import type { ClientContext } from './session.service';
import { UserTokenService } from './user-token.service';

export type EmailVerificationConfig = Pick<
  ApiConfig,
  'AUTH_EMAIL_VERIFICATION_TTL_SECONDS' | 'PORTAL_PUBLIC_URL'
>;

/** Email address verification (§4.1). */
@Injectable()
export class EmailVerificationService {
  private readonly logger = new Logger(EmailVerificationService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: EmailVerificationConfig,
    private readonly users: UsersAuthRepository,
    private readonly userTokens: UserTokenService,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
    private readonly emailSender: EmailSender,
    private readonly kv: KeyValueStore,
  ) {}

  /**
   * Issues a verification token for the user's current email and sends the link (after the
   * token commits). No-op for verified, deleted or unknown users. Returns whether an email was
   * handed to the transport. Used by the self-service resend and by email changes (WP4).
   */
  async issueAndSend(userId: bigint): Promise<boolean> {
    const user = await this.users.findById(userId);
    if (!user || user.deletedAt !== null || user.emailVerifiedAt !== null) return false;
    const issued = await this.transactions.run((tx) =>
      this.userTokens.issue(tx, {
        userId: user.id,
        organizationId: user.organizationId,
        purpose: 'email_verification',
        ttlSeconds: this.config.AUTH_EMAIL_VERIFICATION_TTL_SECONDS,
      }),
    );
    try {
      await this.emailSender.send(
        emailVerificationEmail({
          to: user.email,
          link: buildPortalLink('verify-email', issued.token, this.config.PORTAL_PUBLIC_URL),
          expiresAt: issued.expiresAt,
        }),
      );
      return true;
    } catch (err) {
      this.logger.error({ message: 'Verification email not delivered', err });
      return false;
    }
  }

  /** `POST /auth/email/verification`: at most 3 per hour per user (D6). */
  async resend(userId: bigint): Promise<void> {
    const count = await failClosed(this.logger, 'email-verification-limit', () =>
      this.kv.incrWithTtl(
        kvKeys.emailVerificationResend(userId),
        EMAIL_VERIFICATION_RESEND_WINDOW_SECONDS,
      ),
    );
    if (count > EMAIL_VERIFICATION_RESEND_LIMIT) {
      throw new HttpException('Too many requests', HttpStatus.TOO_MANY_REQUESTS);
    }
    await this.issueAndSend(userId);
  }

  /** `POST /auth/email/verify`. */
  async verify(token: string, context: ClientContext): Promise<void> {
    const row = await this.userTokens.find(token, 'email_verification');
    const user = row ? await this.users.findById(row.userId) : null;
    if (!row || !user || user.deletedAt !== null) throw new BadRequestException(INVALID_TOKEN);
    await this.transactions.run(async (tx) => {
      if (!(await this.userTokens.consume(tx, row))) throw new BadRequestException(INVALID_TOKEN);
      await this.users.markEmailVerified(tx, user.id, new Date());
      await this.audit.record(
        {
          organizationId: user.organizationId,
          actor: { type: 'user', id: user.publicId },
          action: 'auth.email_verified',
          resourceType: 'user',
          resourceId: user.publicId,
          sourceIp: context.ip,
        },
        tx,
      );
    });
  }
}
