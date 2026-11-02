import { Logger, ServiceUnavailableException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryKeyValueStore } from '../../../../test/support/in-memory-key-value-store';
import type { UsersAuthRepository } from '../repositories/users-auth.repository';
import { lockoutSeconds, LoginThrottleService } from './login-throttle.service';

const config = {
  AUTH_LOGIN_MAX_ACCOUNT_FAILURES: 5,
  AUTH_LOGIN_MAX_IP_FAILURES: 3,
  AUTH_LOGIN_FAILURE_WINDOW_SECONDS: 900,
  AUTH_LOCKOUT_BASE_SECONDS: 900,
  AUTH_LOCKOUT_MAX_SECONDS: 3600,
};

describe('lockoutSeconds', () => {
  it('doubles per previous lockout and caps at the maximum', () => {
    expect([0, 1, 2, 3, 10].map((n) => lockoutSeconds(n, config))).toEqual([
      900, 1800, 3600, 3600, 3600,
    ]);
    expect(
      lockoutSeconds(100, { AUTH_LOCKOUT_BASE_SECONDS: 1, AUTH_LOCKOUT_MAX_SECONDS: 86400 }),
    ).toBe(86400);
  });
});

describe('LoginThrottleService', () => {
  let kv: InMemoryKeyValueStore;
  let users: {
    recordFailedLogin: ReturnType<typeof vi.fn>;
    clearLockout: ReturnType<typeof vi.fn>;
  };
  let throttle: LoginThrottleService;
  const now = new Date('2026-11-02T10:00:00Z');

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(now);
    kv = new InMemoryKeyValueStore();
    users = { recordFailedLogin: vi.fn(), clearLockout: vi.fn() };
    throttle = new LoginThrottleService(config, kv, users as unknown as UsersAuthRepository);
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('blocks an IP at the failure threshold within the window', async () => {
    for (let i = 0; i < 2; i += 1) await throttle.recordIpFailure('198.51.100.7');
    expect(await throttle.isIpBlocked('198.51.100.7')).toBe(false);
    await throttle.recordIpFailure('198.51.100.7');
    expect(await throttle.isIpBlocked('198.51.100.7')).toBe(true);
    expect(await throttle.isIpBlocked('198.51.100.8')).toBe(false);
    vi.advanceTimersByTime(900_000);
    expect(await throttle.isIpBlocked('198.51.100.7')).toBe(false);
  });

  it('locks on the 5th failure, mirrors it to the database and restarts the counter', async () => {
    for (let i = 1; i <= 4; i += 1) {
      expect(await throttle.recordAccountFailure(7n, now)).toEqual({ lockedUntil: null });
    }
    const { lockedUntil } = await throttle.recordAccountFailure(7n, now);
    expect(lockedUntil?.toISOString()).toBe('2026-11-02T10:15:00.000Z');
    expect(users.recordFailedLogin).toHaveBeenCalledTimes(5);
    expect(users.recordFailedLogin).toHaveBeenLastCalledWith(7n, lockedUntil);
    expect(await kv.get('auth:fail:acct:7')).toBeNull();
    expect(await kv.get('auth:lockouts:7')).toBe('1');
  });

  it('doubles the lockout for repeated lockouts within 24 h, up to the cap', async () => {
    const lockouts: Array<number | null> = [];
    for (let round = 0; round < 4; round += 1) {
      let result = { lockedUntil: null as Date | null };
      for (let i = 0; i < 5; i += 1) result = await throttle.recordAccountFailure(9n, now);
      lockouts.push(result.lockedUntil && (result.lockedUntil.getTime() - now.getTime()) / 1000);
    }
    expect(lockouts).toEqual([900, 1800, 3600, 3600]);
  });

  it('forgets the failures outside the window', async () => {
    for (let i = 0; i < 4; i += 1) await throttle.recordAccountFailure(3n, now);
    vi.advanceTimersByTime(901_000);
    expect((await throttle.recordAccountFailure(3n, now)).lockedUntil).toBeNull();
  });

  it('clearForUser removes both account counters and the database lock', async () => {
    for (let i = 0; i < 5; i += 1) await throttle.recordAccountFailure(4n, now);
    await throttle.recordAccountFailure(4n, now);
    await throttle.clearForUser(4n);
    expect(await kv.get('auth:fail:acct:4')).toBeNull();
    expect(await kv.get('auth:lockouts:4')).toBeNull();
    expect(users.clearLockout).toHaveBeenCalledWith(4n);
  });

  it('fails closed with 503 when the store is unavailable', async () => {
    kv.failing = true;
    await expect(throttle.isIpBlocked('198.51.100.1')).rejects.toThrow(ServiceUnavailableException);
    await expect(throttle.recordAccountFailure(1n)).rejects.toThrow(ServiceUnavailableException);
    expect(users.recordFailedLogin).not.toHaveBeenCalled();
  });
});
