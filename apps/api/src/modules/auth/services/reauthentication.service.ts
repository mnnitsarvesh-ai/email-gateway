import { Injectable } from '@nestjs/common';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { PasswordHasher } from '../../../crypto/password-hasher';
import { UsersAuthRepository } from '../repositories/users-auth.repository';
import { LoginThrottleService } from './login-throttle.service';
import { MfaService } from './mfa.service';
import { isUsable } from './session.service';

export type ReauthenticationResult =
  | { ok: true }
  | { ok: false; reason: 'locked' | 'inactive' | 'password' | 'totp_required' | 'totp' };

/**
 * Fresh re-authorization of a signed-in user for a sensitive operation (step 5.3 Q12: the
 * quarantine download grant): the password, and a TOTP code when the user has MFA enrolled.
 * Failures count toward the login lockout exactly like a failed login (D6: the account failure
 * counter, progressive lockout mirrored to `users.locked_until`); a locked account fails without
 * checking anything. A success clears the failure window (as a successful login does). The
 * password and the code are never logged or stored.
 */
@Injectable()
export class ReauthenticationService {
  constructor(
    private readonly users: UsersAuthRepository,
    private readonly passwords: PasswordHasher,
    private readonly mfa: MfaService,
    private readonly throttle: LoginThrottleService,
  ) {}

  async verify(
    principal: UserPrincipal,
    input: { password: string; totpCode?: string },
    now: Date = new Date(),
  ): Promise<ReauthenticationResult> {
    const user = await this.users.findById(principal.userId);
    if (user === null || !isUsable(user)) return { ok: false, reason: 'inactive' };
    if (user.lockedUntil !== null && user.lockedUntil.getTime() > now.getTime()) {
      return { ok: false, reason: 'locked' };
    }
    if (!(await this.passwords.verify(user.passwordHash, input.password))) {
      await this.throttle.recordAccountFailure(user.id, now);
      return { ok: false, reason: 'password' };
    }
    if (user.mfaEnabled) {
      if (input.totpCode === undefined) {
        await this.throttle.recordAccountFailure(user.id, now);
        return { ok: false, reason: 'totp_required' };
      }
      if (!(await this.mfa.verifyTotpCode(user, input.totpCode))) {
        await this.throttle.recordAccountFailure(user.id, now);
        return { ok: false, reason: 'totp' };
      }
    }
    await this.throttle.clearAccountFailures(user.id);
    return { ok: true };
  }
}
