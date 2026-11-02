import { randomBytes, randomUUID } from 'node:crypto';
import { ConflictException, ForbiddenException, Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryKeyValueStore } from '../../../../test/support/in-memory-key-value-store';
import type { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { PasswordHasher } from '../../../crypto/password-hasher';
import { SecretBox } from '../../../crypto/secret-box';
import { TokenHasher } from '../../../crypto/tokens';
import { generateTotpSecret, totpCode, totpStep } from '../../../crypto/totp';
import type { TransactionRunner } from '../../../database/transaction-runner';
import type { RecoveryCodesRepository } from '../repositories/recovery-codes.repository';
import type { AuthUserRecord, UsersAuthRepository } from '../repositories/users-auth.repository';
import { mfaAad, MfaService } from './mfa.service';
import type { PrincipalCacheService } from './principal-cache.service';
import type { SessionService } from './session.service';

const hex = () => randomBytes(32).toString('hex');

function authUser(overrides: Partial<AuthUserRecord> = {}): AuthUserRecord {
  return {
    id: 10n,
    publicId: randomUUID(),
    organizationId: 2n,
    email: 'alice@example.test',
    displayName: 'Alice',
    status: 'active',
    passwordHash: '$argon2id$hash',
    mfaEnabled: false,
    mfaSecretCiphertext: null,
    mfaLastUsedStep: null,
    emailVerifiedAt: null,
    lockedUntil: null,
    deletedAt: null,
    organization: {
      id: 2n,
      publicId: randomUUID(),
      slug: 'acme',
      name: 'Acme',
      kind: 'customer',
      status: 'active',
      deletedAt: null,
      mfaRequired: false,
    },
    ...overrides,
  };
}

/** Fake users repository holding one mutable user with the conditional-update semantics. */
class FakeUsers {
  constructor(public user: AuthUserRecord) {}
  findById = vi.fn(() => Promise.resolve({ ...this.user }));
  setPendingMfaSecret = vi.fn((_id: bigint, ciphertext: string) => {
    if (this.user.mfaEnabled) return Promise.resolve(false);
    this.user.mfaSecretCiphertext = ciphertext;
    return Promise.resolve(true);
  });
  enableMfa = vi.fn((_tx: unknown, _id: bigint, step: number) => {
    if (this.user.mfaEnabled || !this.user.mfaSecretCiphertext) return Promise.resolve(false);
    Object.assign(this.user, { mfaEnabled: true, mfaLastUsedStep: BigInt(step) });
    return Promise.resolve(true);
  });
  disableMfa = vi.fn(() => {
    Object.assign(this.user, {
      mfaEnabled: false,
      mfaSecretCiphertext: null,
      mfaLastUsedStep: null,
    });
    return Promise.resolve();
  });
  advanceMfaStep = vi.fn((_id: bigint, step: number) => {
    const last = this.user.mfaLastUsedStep;
    if (last !== null && last >= BigInt(step)) return Promise.resolve(false);
    this.user.mfaLastUsedStep = BigInt(step);
    return Promise.resolve(true);
  });
  replaceMfaCiphertext = vi.fn((_id: bigint, previous: string, next: string) => {
    if (this.user.mfaSecretCiphertext === previous) this.user.mfaSecretCiphertext = next;
    return Promise.resolve();
  });
}

class FakeRecoveryCodes {
  codes = new Map<string, Date | null>();
  replaceAll = vi.fn((_tx: unknown, _user: unknown, hashes: string[]) => {
    this.codes = new Map(hashes.map((h) => [h, null]));
    return Promise.resolve();
  });
  deleteAll = vi.fn(() => {
    this.codes.clear();
    return Promise.resolve();
  });
  use = vi.fn((_id: bigint, hash: string, now: Date) => {
    if (!this.codes.has(hash) || this.codes.get(hash) !== null) return Promise.resolve(false);
    this.codes.set(hash, now);
    return Promise.resolve(true);
  });
}

describe('MfaService', () => {
  const dataKey = hex();
  let box: SecretBox;
  let users: FakeUsers;
  let codes: FakeRecoveryCodes;
  let kv: InMemoryKeyValueStore;
  let sessions: {
    markMfaAuthenticated: ReturnType<typeof vi.fn>;
    revokeAllForUser: ReturnType<typeof vi.fn>;
  };
  let audit: { record: ReturnType<typeof vi.fn>; actorFrom: ReturnType<typeof vi.fn> };
  let passwordOk: boolean;
  let service: MfaService;
  let principal: UserPrincipal;

  const build = (secretBox: SecretBox) =>
    new MfaService(
      { AUTH_MFA_ISSUER: 'EmailSecurityGateway' },
      users as unknown as UsersAuthRepository,
      codes as unknown as RecoveryCodesRepository,
      secretBox,
      new TokenHasher({ AUTH_TOKEN_PEPPER: hex() }),
      { verify: () => Promise.resolve(passwordOk) } as unknown as PasswordHasher,
      kv,
      { run: (fn: (tx: object) => Promise<unknown>) => fn({}) } as unknown as TransactionRunner,
      sessions as unknown as SessionService,
      audit as unknown as AuditService,
      { invalidateUserByPublicId: vi.fn() } as unknown as PrincipalCacheService,
    );

  beforeEach(() => {
    box = new SecretBox({ DATA_ENCRYPTION_KEY: dataKey });
    users = new FakeUsers(authUser());
    codes = new FakeRecoveryCodes();
    kv = new InMemoryKeyValueStore();
    sessions = { markMfaAuthenticated: vi.fn(), revokeAllForUser: vi.fn() };
    audit = { record: vi.fn(), actorFrom: vi.fn(() => ({ type: 'user', id: 'u' })) };
    passwordOk = true;
    service = build(box);
    principal = {
      kind: 'user',
      userId: 10n,
      userPublicId: users.user.publicId,
      organizationId: 2n,
      organizationPublicId: users.user.organization.publicId,
      organizationKind: 'customer',
      sessionId: randomUUID(),
      mfaAuthenticated: false,
      mfaEnrollmentRequired: false,
      permissions: new Set(),
    };
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => vi.restoreAllMocks());

  const code = (secret: string, offset = 0) => totpCode(secret, totpStep(Date.now()) + offset);

  describe('login challenge', () => {
    it('stores the challenge under the token hash only, single use', async () => {
      const { mfaToken, expiresIn } = await service.createChallenge(users.user, '198.51.100.1');
      expect(expiresIn).toBe(300);
      expect([...kv.entries.keys()].join()).not.toContain(mfaToken);
      expect(await service.readChallenge(mfaToken)).toEqual({
        userId: 10n,
        organizationId: 2n,
        ip: '198.51.100.1',
      });
      expect(await service.completeChallenge(mfaToken)).toBe(true);
      expect(await service.completeChallenge(mfaToken)).toBe(false);
      expect(await service.readChallenge(mfaToken)).toBeNull();
    });

    it('deletes the challenge on the 5th failed attempt', async () => {
      const { mfaToken } = await service.createChallenge(users.user, null);
      for (let i = 1; i <= 4; i += 1)
        expect(await service.failChallengeAttempt(mfaToken)).toBe(false);
      expect(await service.failChallengeAttempt(mfaToken)).toBe(true);
      expect(await service.readChallenge(mfaToken)).toBeNull();
    });

    it('rejects malformed tokens without a lookup', async () => {
      expect(await service.readChallenge('not-a-token')).toBeNull();
      expect(await service.readChallenge(42)).toBeNull();
    });
  });

  describe('TOTP verification', () => {
    let secret: string;
    beforeEach(() => {
      secret = generateTotpSecret();
      Object.assign(users.user, {
        mfaEnabled: true,
        mfaSecretCiphertext: box.encrypt(secret, mfaAad(10n)),
      });
    });

    it('accepts a valid code once (replay protection)', async () => {
      const c = code(secret);
      expect(await service.verifySecondFactor(users.user, { code: c })).toBe(true);
      expect(await service.verifySecondFactor({ ...users.user }, { code: c })).toBe(false);
      expect(await service.verifySecondFactor({ ...users.user }, { code: code(secret, 1) })).toBe(
        true,
      );
    });

    it('rejects wrong codes, other users’ ciphertexts and users without MFA', async () => {
      expect(
        await service.verifySecondFactor(users.user, {
          code: '000000' === code(secret) ? '111111' : '000000',
        }),
      ).toBe(false);
      const other = authUser({
        id: 11n,
        mfaEnabled: true,
        mfaSecretCiphertext: users.user.mfaSecretCiphertext,
      });
      expect(await service.verifyTotpCode(other, code(secret))).toBe(false);
      expect(
        await service.verifySecondFactor(
          { ...users.user, mfaEnabled: false },
          { code: code(secret) },
        ),
      ).toBe(false);
    });

    it('re-encrypts a secret that only the previous key can open', async () => {
      const newKey = hex();
      const rotated = build(
        new SecretBox({ DATA_ENCRYPTION_KEY: newKey, DATA_ENCRYPTION_KEY_PREVIOUS: dataKey }),
      );
      const before = users.user.mfaSecretCiphertext!;
      expect(await rotated.verifyTotpCode({ ...users.user }, code(secret))).toBe(true);
      expect(users.user.mfaSecretCiphertext).not.toBe(before);
      expect(
        new SecretBox({ DATA_ENCRYPTION_KEY: newKey }).decrypt(
          users.user.mfaSecretCiphertext!,
          mfaAad(10n),
        ).plaintext,
      ).toBe(secret);
    });
  });

  describe('enrollment', () => {
    it('setup → enable issues 10 recovery codes, marks the session and revokes the others', async () => {
      const { secret, otpauthUri } = await service.setup(principal);
      expect(otpauthUri).toContain(
        'otpauth://totp/EmailSecurityGateway:alice%40example.test?secret=',
      );
      await expect(
        service.enable(principal, '12345', { ip: null, userAgent: null }),
      ).rejects.toThrow(ForbiddenException);
      const { recoveryCodes } = await service.enable(principal, code(secret), {
        ip: null,
        userAgent: null,
      });
      expect(recoveryCodes).toHaveLength(10);
      expect(new Set(recoveryCodes).size).toBe(10);
      expect(users.user.mfaEnabled).toBe(true);
      expect(sessions.markMfaAuthenticated).toHaveBeenCalledWith({}, 10n, principal.sessionId);
      expect(sessions.revokeAllForUser).toHaveBeenCalledWith(10n, 'mfa_enabled', {
        exceptSessionId: principal.sessionId,
      });
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'auth.mfa_enabled' }),
        {},
      );
      // Recovery codes are stored as HMACs and work once.
      expect([...codes.codes.keys()].some((h) => recoveryCodes.includes(h))).toBe(false);
      expect(
        await service.verifySecondFactor(users.user, { recoveryCode: recoveryCodes[3]! }),
      ).toBe(true);
      expect(
        await service.verifySecondFactor(users.user, { recoveryCode: recoveryCodes[3]! }),
      ).toBe(false);
      await expect(service.setup(principal)).rejects.toThrow(ConflictException);
    });

    it('enable without setup is a conflict', async () => {
      await expect(
        service.enable(principal, '123456', { ip: null, userAgent: null }),
      ).rejects.toThrow(ConflictException);
    });

    it('disable needs the password and a code, and is refused when the organization requires MFA', async () => {
      const { secret } = await service.setup(principal);
      await service.enable(principal, code(secret), { ip: null, userAgent: null });
      passwordOk = false;
      await expect(
        service.disable(
          principal,
          { password: 'x', code: code(secret, 1) },
          { ip: null, userAgent: null },
        ),
      ).rejects.toThrow(ForbiddenException);
      passwordOk = true;
      users.user.organization.mfaRequired = true;
      await expect(
        service.disable(
          principal,
          { password: 'x', code: code(secret, 1) },
          { ip: null, userAgent: null },
        ),
      ).rejects.toThrow(ConflictException);
      users.user.organization.mfaRequired = false;
      await service.disable(
        principal,
        { password: 'x', code: code(secret, 1) },
        { ip: null, userAgent: null },
      );
      expect(users.user).toMatchObject({ mfaEnabled: false, mfaSecretCiphertext: null });
      expect(codes.codes.size).toBe(0);
    });

    it('regenerates recovery codes after a TOTP check', async () => {
      const { secret } = await service.setup(principal);
      const first = await service.enable(principal, code(secret), { ip: null, userAgent: null });
      const second = await service.regenerateRecoveryCodes(principal, code(secret, 1), {
        ip: null,
        userAgent: null,
      });
      expect(second.recoveryCodes).not.toEqual(first.recoveryCodes);
      expect(
        await service.verifySecondFactor(users.user, { recoveryCode: first.recoveryCodes[0]! }),
      ).toBe(false);
      await expect(
        service.regenerateRecoveryCodes(principal, code(secret, 1), { ip: null, userAgent: null }),
      ).rejects.toThrow(ForbiddenException);
    });
  });
});
