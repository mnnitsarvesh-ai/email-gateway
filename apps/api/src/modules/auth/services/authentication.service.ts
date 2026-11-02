import {
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { PasswordHasher } from '../../../crypto/password-hasher';
import { INVALID_CREDENTIALS, type LoginFailureReason, RevokeReason } from '../auth.constants';
import type { LoginAuditEntry } from '../repositories/login-audit.repository';
import { OrganizationsAuthRepository } from '../repositories/organizations-auth.repository';
import { type AuthUserRecord, UsersAuthRepository } from '../repositories/users-auth.repository';
import { LoginAuditService } from './login-audit.service';
import { LoginThrottleService } from './login-throttle.service';
import { MfaService, type SecondFactor } from './mfa.service';
import { type ClientContext, SessionService, type TokenResponse } from './session.service';

export interface LoginInput {
  email: string;
  password: string;
  /** Organization slug; only selects the account, never the tenant context. */
  organization?: string;
}

export interface MfaChallengeResponse {
  mfaRequired: true;
  mfaToken: string;
  expiresIn: number;
}

export type LoginResult = TokenResponse | MfaChallengeResponse;

export interface MeResponse {
  user: { id: string; email: string; displayName: string; status: string };
  organization: { id: string; slug: string; name: string; kind: 'customer' | 'platform' };
  roles: string[];
  permissions: string[];
  mfaEnabled: boolean;
  emailVerified: boolean;
  mfaEnrollmentRequired: boolean;
  session: { id: string; mfaAuthenticated: boolean };
  override: { id: string; reason: string; organizationId: string; expiresAt: string } | null;
}

function invalidCredentials(): UnauthorizedException {
  return new UnauthorizedException(INVALID_CREDENTIALS);
}

/**
 * Password login and MFA verification (D6, D7). Every path writes exactly one
 * `login_audit_logs` row, and every rejection is the same `401 Invalid credentials` (except
 * the per-IP block, `429`), so responses never reveal whether an account exists.
 */
@Injectable()
export class AuthenticationService {
  constructor(
    private readonly users: UsersAuthRepository,
    private readonly organizations: OrganizationsAuthRepository,
    private readonly passwords: PasswordHasher,
    private readonly throttle: LoginThrottleService,
    private readonly loginAudit: LoginAuditService,
    private readonly sessions: SessionService,
    private readonly mfa: MfaService,
  ) {}

  async login(input: LoginInput, context: ClientContext): Promise<LoginResult> {
    const email = input.email.trim().toLowerCase();
    const ip = context.ip ?? 'unknown';
    const audit = (
      partial: Pick<LoginAuditEntry, 'outcome' | 'failureReason'> &
        Partial<Pick<LoginAuditEntry, 'organizationId' | 'userId'>>,
    ) =>
      this.loginAudit.record({
        organizationId: partial.organizationId ?? null,
        userId: partial.userId ?? null,
        emailAttempted: email,
        outcome: partial.outcome,
        failureReason: partial.failureReason,
        ipAddress: context.ip,
        userAgent: context.userAgent,
      });

    // 2. Per-IP failure block.
    if (await this.throttle.isIpBlocked(ip)) {
      await audit({ outcome: 'rate_limited', failureReason: 'ip_blocked' });
      throw new HttpException('Too many requests', HttpStatus.TOO_MANY_REQUESTS);
    }

    // 3. Resolve the account: (organization, email); without a slug only an unambiguous email.
    let slugOrganizationId: bigint | null = null;
    let user: AuthUserRecord | undefined;
    if (input.organization !== undefined) {
      const org = await this.organizations.findBySlug(input.organization.trim().toLowerCase());
      if (org) {
        slugOrganizationId = org.id;
        [user] = await this.users.findLoginCandidates(email, org.id, 1);
      }
    } else {
      const candidates = await this.users.findLoginCandidates(email, undefined, 2);
      if (candidates.length === 1) user = candidates[0];
    }
    if (!user) {
      await this.passwords.verifyDummy(input.password);
      await this.throttle.recordIpFailure(ip);
      await audit({
        outcome: 'failure',
        failureReason: 'unknown_account',
        organizationId: slugOrganizationId,
      });
      throw invalidCredentials();
    }
    const ids = { organizationId: user.organizationId, userId: user.id };

    // 4. Locked account: same answer and timing as a wrong password; no real verification.
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      await this.passwords.verifyDummy(input.password);
      await this.throttle.recordIpFailure(ip);
      await audit({ ...ids, outcome: 'locked', failureReason: 'account_locked' });
      throw invalidCredentials();
    }

    // 5. Password.
    if (user.passwordHash === null) {
      await this.passwords.verifyDummy(input.password);
      await this.throttle.recordIpFailure(ip);
      await audit({ ...ids, outcome: 'failure', failureReason: 'not_activated' });
      throw invalidCredentials();
    }
    if (!(await this.passwords.verify(user.passwordHash, input.password))) {
      const { lockedUntil } = await this.throttle.recordAccountFailure(user.id);
      await this.throttle.recordIpFailure(ip);
      await audit(
        lockedUntil
          ? { ...ids, outcome: 'locked', failureReason: 'lockout_started' }
          : { ...ids, outcome: 'failure', failureReason: 'invalid_password' },
      );
      throw invalidCredentials();
    }

    // 6. Account and organization state.
    const inactive = this.inactiveReason(user);
    if (inactive) {
      await audit({ ...ids, outcome: 'failure', failureReason: inactive });
      throw invalidCredentials();
    }

    // 7. Upgrade the hash when the parameters changed; MFA challenge.
    if (this.passwords.needsRehash(user.passwordHash)) {
      const rehashed = await this.passwords.hash(input.password);
      await this.users.updatePasswordHashIfUnchanged(user.id, user.passwordHash, rehashed);
    }
    if (user.mfaEnabled) {
      const challenge = await this.mfa.createChallenge(user, context.ip);
      await audit({ ...ids, outcome: 'mfa_required', failureReason: null });
      return { mfaRequired: true, ...challenge };
    }

    // 8. Success.
    return this.completeLogin(user, context, false, () =>
      audit({ ...ids, outcome: 'success', failureReason: null }),
    );
  }

  /** `POST /auth/mfa/verify` (D7): second step of a login. */
  async verifyMfa(
    input: { mfaToken: string } & SecondFactor,
    context: ClientContext,
  ): Promise<TokenResponse> {
    const ip = context.ip ?? 'unknown';
    const audit = (
      user: AuthUserRecord | null,
      outcome: LoginAuditEntry['outcome'],
      failureReason: LoginFailureReason | null,
    ) =>
      this.loginAudit.record({
        organizationId: user?.organizationId ?? null,
        userId: user?.id ?? null,
        emailAttempted: user?.email ?? '',
        outcome,
        failureReason,
        ipAddress: context.ip,
        userAgent: context.userAgent,
      });

    const challenge = await this.mfa.readChallenge(input.mfaToken);
    const user = challenge ? await this.users.findById(challenge.userId) : null;
    if (!challenge || !user) {
      await this.throttle.recordIpFailure(ip);
      await audit(user, 'mfa_failure', 'invalid_challenge');
      throw invalidCredentials();
    }
    const inactive = this.inactiveReason(user);
    if (inactive) {
      await this.mfa.completeChallenge(input.mfaToken);
      await audit(user, 'failure', inactive);
      throw invalidCredentials();
    }
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      await this.mfa.completeChallenge(input.mfaToken);
      await audit(user, 'locked', 'account_locked');
      throw invalidCredentials();
    }

    const ok = await this.mfa.verifySecondFactor(user, input);
    if (!ok) {
      const exhausted = await this.mfa.failChallengeAttempt(input.mfaToken);
      const { lockedUntil } = await this.throttle.recordAccountFailure(user.id);
      await this.throttle.recordIpFailure(ip);
      if (lockedUntil) {
        await this.mfa.completeChallenge(input.mfaToken);
        await audit(user, 'locked', 'lockout_started');
      } else {
        await audit(user, 'mfa_failure', exhausted ? 'mfa_attempts_exceeded' : 'invalid_mfa_code');
      }
      throw invalidCredentials();
    }
    // Single use even under concurrency: only the request that deletes the challenge proceeds.
    if (!(await this.mfa.completeChallenge(input.mfaToken))) {
      await audit(user, 'mfa_failure', 'invalid_challenge');
      throw invalidCredentials();
    }
    return this.completeLogin(user, context, true, () => audit(user, 'success', null));
  }

  async logout(principal: UserPrincipal): Promise<void> {
    await this.sessions.revokeSession(principal.userId, principal.sessionId, RevokeReason.logout);
  }

  async me(principal: UserPrincipal): Promise<MeResponse> {
    const user = await this.users.findById(principal.userId);
    if (!user) throw new NotFoundException('User not found');
    const roles = await this.users.roleKeys(user.id);
    return {
      user: {
        id: user.publicId,
        email: user.email,
        displayName: user.displayName,
        status: user.status,
      },
      organization: {
        id: user.organization.publicId,
        slug: user.organization.slug,
        name: user.organization.name,
        kind: user.organization.kind,
      },
      roles,
      permissions: [...principal.permissions].sort(),
      mfaEnabled: user.mfaEnabled,
      emailVerified: user.emailVerifiedAt !== null,
      mfaEnrollmentRequired: principal.mfaEnrollmentRequired,
      session: { id: principal.sessionId, mfaAuthenticated: principal.mfaAuthenticated },
      override: principal.override
        ? {
            id: principal.override.id,
            reason: principal.override.reason,
            organizationId: principal.override.targetOrganizationPublicId,
            expiresAt: principal.override.expiresAt.toISOString(),
          }
        : null,
    };
  }

  private inactiveReason(user: AuthUserRecord): LoginFailureReason | null {
    if (user.status !== 'active' || user.deletedAt !== null) return 'user_disabled';
    if (user.organization.status !== 'active' || user.organization.deletedAt !== null) {
      return 'org_inactive';
    }
    return null;
  }

  private async completeLogin(
    user: AuthUserRecord,
    context: ClientContext,
    mfaAuthenticated: boolean,
    writeAudit: () => Promise<void>,
  ): Promise<TokenResponse> {
    await this.throttle.clearAccountFailures(user.id);
    await this.users.recordSuccessfulLogin(user.id, new Date());
    const response = await this.sessions.start(user, context, { mfaAuthenticated });
    await writeAudit();
    return response;
  }
}
