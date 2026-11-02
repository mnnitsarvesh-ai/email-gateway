import { Inject, Injectable, Logger } from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import type { ApiConfig } from '../../../config';
import { KeyValueStore } from '../../../kv/key-value-store';
import { kvKeys, LOCKOUT_HISTORY_TTL_SECONDS } from '../auth.constants';
import { UsersAuthRepository } from '../repositories/users-auth.repository';
import { failClosed } from './kv-fail-closed';

export type LoginThrottleConfig = Pick<
  ApiConfig,
  | 'AUTH_LOGIN_MAX_ACCOUNT_FAILURES'
  | 'AUTH_LOGIN_MAX_IP_FAILURES'
  | 'AUTH_LOGIN_FAILURE_WINDOW_SECONDS'
  | 'AUTH_LOCKOUT_BASE_SECONDS'
  | 'AUTH_LOCKOUT_MAX_SECONDS'
>;

export interface AccountFailureResult {
  /** Set when this failure started a lockout. */
  lockedUntil: Date | null;
}

/** Lockout duration after `previousLockouts` lockouts within 24 h: base × 2^n, capped. */
export function lockoutSeconds(
  previousLockouts: number,
  config: Pick<LoginThrottleConfig, 'AUTH_LOCKOUT_BASE_SECONDS' | 'AUTH_LOCKOUT_MAX_SECONDS'>,
): number {
  const exponent = Math.min(Math.max(previousLockouts, 0), 30);
  return Math.min(
    config.AUTH_LOCKOUT_BASE_SECONDS * 2 ** exponent,
    config.AUTH_LOCKOUT_MAX_SECONDS,
  );
}

/**
 * Brute-force protection (D6): failure counters per client IP and per account in the key-value
 * store, progressive account lockout mirrored to `users.locked_until` and
 * `users.failed_login_count` (the database stays the source of truth for the lock).
 */
@Injectable()
export class LoginThrottleService {
  private readonly logger = new Logger(LoginThrottleService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: LoginThrottleConfig,
    private readonly kv: KeyValueStore,
    private readonly users: UsersAuthRepository,
  ) {}

  async isIpBlocked(ip: string): Promise<boolean> {
    const value = await failClosed(this.logger, 'ip-check', () =>
      this.kv.get(kvKeys.ipFailures(ip)),
    );
    return Number(value ?? 0) >= this.config.AUTH_LOGIN_MAX_IP_FAILURES;
  }

  async recordIpFailure(ip: string): Promise<void> {
    await failClosed(this.logger, 'ip-failure', () =>
      this.kv.incrWithTtl(kvKeys.ipFailures(ip), this.config.AUTH_LOGIN_FAILURE_WINDOW_SECONDS),
    );
  }

  /**
   * Counts a wrong password or MFA code. At AUTH_LOGIN_MAX_ACCOUNT_FAILURES within the window the
   * account is locked for base × 2^n seconds (n = lockouts in the last 24 h, capped at
   * AUTH_LOCKOUT_MAX_SECONDS) and the counter restarts.
   */
  async recordAccountFailure(
    userId: bigint,
    now: Date = new Date(),
  ): Promise<AccountFailureResult> {
    const failures = await failClosed(this.logger, 'account-failure', () =>
      this.kv.incrWithTtl(
        kvKeys.accountFailures(userId),
        this.config.AUTH_LOGIN_FAILURE_WINDOW_SECONDS,
      ),
    );
    let lockedUntil: Date | null = null;
    if (failures >= this.config.AUTH_LOGIN_MAX_ACCOUNT_FAILURES) {
      const lockouts = await failClosed(this.logger, 'lockout', async () => {
        const n = await this.kv.incrWithTtl(kvKeys.lockouts(userId), LOCKOUT_HISTORY_TTL_SECONDS);
        await this.kv.del(kvKeys.accountFailures(userId));
        return n;
      });
      lockedUntil = new Date(now.getTime() + lockoutSeconds(lockouts - 1, this.config) * 1000);
    }
    await this.users.recordFailedLogin(userId, lockedUntil);
    return { lockedUntil };
  }

  /** Successful login: the failure window restarts (lockout history is kept for 24 h). */
  async clearAccountFailures(userId: bigint): Promise<void> {
    await failClosed(this.logger, 'account-clear', () =>
      this.kv.del(kvKeys.accountFailures(userId)),
    );
  }

  /**
   * Administrative unlock (D6): clears both account counters in the store and the mirrored
   * `locked_until` / `failed_login_count`. Call after the status change has committed.
   */
  async clearForUser(userId: bigint): Promise<void> {
    await failClosed(this.logger, 'account-unlock', () =>
      this.kv.del(kvKeys.accountFailures(userId), kvKeys.lockouts(userId)),
    );
    await this.users.clearLockout(userId);
  }
}
