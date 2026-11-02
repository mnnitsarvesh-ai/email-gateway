import {
  ConflictException,
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
import { SecretBox, SecretBoxError } from '../../../crypto/secret-box';
import {
  generateOpaqueToken,
  generateRecoveryCodes,
  isOpaqueToken,
  normalizeRecoveryCode,
  sha256Hex,
  TokenHasher,
} from '../../../crypto/tokens';
import { generateTotpSecret, otpauthUri, verifyTotp } from '../../../crypto/totp';
import { TransactionRunner } from '../../../database/transaction-runner';
import { KeyValueStore } from '../../../kv/key-value-store';
import {
  kvKeys,
  MFA_CHALLENGE_MAX_ATTEMPTS,
  MFA_CHALLENGE_TTL_SECONDS,
  RevokeReason,
} from '../auth.constants';
import { RecoveryCodesRepository } from '../repositories/recovery-codes.repository';
import { type AuthUserRecord, UsersAuthRepository } from '../repositories/users-auth.repository';
import { failClosed } from './kv-fail-closed';
import { PrincipalCacheService } from './principal-cache.service';
import { type ClientContext, SessionService } from './session.service';

export type MfaConfig = Pick<ApiConfig, 'AUTH_MFA_ISSUER'>;

/** The pending second step of a password login (D7), stored in the key-value store. */
export interface MfaChallenge {
  userId: bigint;
  organizationId: bigint;
  ip: string | null;
}

export interface SecondFactor {
  code?: string;
  recoveryCode?: string;
}

const RECOVERY_CODE_COUNT = 10;

/** AAD binding an MFA secret ciphertext to its user row (D4). */
export const mfaAad = (userId: bigint): string => `mfa:user:${userId}`;

/**
 * TOTP MFA (D7): login challenges, verification with replay protection, recovery codes and
 * self-service enrollment. Secrets are AES-256-GCM encrypted (SecretBox); recovery codes are
 * stored as peppered HMACs.
 */
@Injectable()
export class MfaService {
  private readonly logger = new Logger(MfaService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: MfaConfig,
    private readonly users: UsersAuthRepository,
    private readonly recoveryCodes: RecoveryCodesRepository,
    private readonly secretBox: SecretBox,
    private readonly hasher: TokenHasher,
    private readonly passwords: PasswordHasher,
    private readonly kv: KeyValueStore,
    private readonly transactions: TransactionRunner,
    private readonly sessions: SessionService,
    private readonly audit: AuditService,
    private readonly principalCache: PrincipalCacheService,
  ) {}

  // ---- Login challenge -------------------------------------------------------------------

  async createChallenge(
    user: AuthUserRecord,
    ip: string | null,
  ): Promise<{ mfaToken: string; expiresIn: number }> {
    const mfaToken = generateOpaqueToken('egt');
    const value = JSON.stringify({
      userId: user.id.toString(),
      organizationId: user.organizationId.toString(),
      ip,
    });
    await failClosed(this.logger, 'mfa-challenge', () =>
      this.kv.set(kvKeys.mfaChallenge(sha256Hex(mfaToken)), value, MFA_CHALLENGE_TTL_SECONDS),
    );
    return { mfaToken, expiresIn: MFA_CHALLENGE_TTL_SECONDS };
  }

  /** The challenge behind an `mfaToken`, or null when unknown or expired. */
  async readChallenge(mfaToken: unknown): Promise<MfaChallenge | null> {
    if (!isOpaqueToken(mfaToken, 'egt')) return null;
    const raw = await failClosed(this.logger, 'mfa-challenge', () =>
      this.kv.get(kvKeys.mfaChallenge(sha256Hex(mfaToken))),
    );
    if (raw === null) return null;
    try {
      const parsed = JSON.parse(raw) as {
        userId: string;
        organizationId: string;
        ip: string | null;
      };
      return {
        userId: BigInt(parsed.userId),
        organizationId: BigInt(parsed.organizationId),
        ip: parsed.ip,
      };
    } catch {
      return null;
    }
  }

  /** Counts a failed attempt; the 5th failure deletes the challenge. Returns true if deleted. */
  async failChallengeAttempt(mfaToken: string): Promise<boolean> {
    const hash = sha256Hex(mfaToken);
    return failClosed(this.logger, 'mfa-attempt', async () => {
      const attempts = await this.kv.incrWithTtl(
        kvKeys.mfaAttempts(hash),
        MFA_CHALLENGE_TTL_SECONDS,
      );
      if (attempts < MFA_CHALLENGE_MAX_ATTEMPTS) return false;
      await this.kv.del(kvKeys.mfaChallenge(hash), kvKeys.mfaAttempts(hash));
      return true;
    });
  }

  /** Single use: deletes the challenge; false if it was already gone (concurrent success). */
  async completeChallenge(mfaToken: string): Promise<boolean> {
    const hash = sha256Hex(mfaToken);
    const deleted = await failClosed(this.logger, 'mfa-complete', () =>
      this.kv.del(kvKeys.mfaChallenge(hash), kvKeys.mfaAttempts(hash)),
    );
    return deleted > 0;
  }

  // ---- Verification ----------------------------------------------------------------------

  /** Exactly one of `code` / `recoveryCode` (validated by the request schema). */
  async verifySecondFactor(user: AuthUserRecord, factor: SecondFactor): Promise<boolean> {
    if (!user.mfaEnabled) return false;
    if (factor.recoveryCode !== undefined) return this.useRecoveryCode(user, factor.recoveryCode);
    if (factor.code !== undefined) return this.verifyTotpCode(user, factor.code);
    return false;
  }

  /**
   * Checks a TOTP code against the user's secret (±1 step) and records the step with a
   * conditional update, so a code is accepted at most once (replay protection, D4). Secrets
   * encrypted with the previous key are re-encrypted with the current one.
   */
  async verifyTotpCode(user: AuthUserRecord, code: string): Promise<boolean> {
    const secret = this.decryptSecret(user);
    if (secret === null) return false;
    const result = verifyTotp(secret.plaintext, code, { afterStep: user.mfaLastUsedStep });
    if (!result.ok) return false;
    if (!(await this.users.advanceMfaStep(user.id, result.step))) return false;
    if (secret.usedPreviousKey && user.mfaSecretCiphertext) {
      const reencrypted = this.secretBox.encrypt(secret.plaintext, mfaAad(user.id));
      await this.users.replaceMfaCiphertext(user.id, user.mfaSecretCiphertext, reencrypted);
    }
    return true;
  }

  async useRecoveryCode(user: AuthUserRecord, input: string): Promise<boolean> {
    const normalized = normalizeRecoveryCode(input);
    if (normalized === null) return false;
    return this.recoveryCodes.use(user.id, this.hasher.hmacHex(normalized), new Date());
  }

  // ---- Enrollment (self-service) ---------------------------------------------------------

  /** `POST /auth/mfa/totp/setup`: a new pending secret while MFA is off (`409` otherwise). */
  async setup(principal: UserPrincipal): Promise<{ secret: string; otpauthUri: string }> {
    const user = await this.requireUser(principal);
    if (user.mfaEnabled) throw new ConflictException('MFA is already enabled');
    const secret = generateTotpSecret();
    const stored = await this.users.setPendingMfaSecret(
      user.id,
      this.secretBox.encrypt(secret, mfaAad(user.id)),
    );
    if (!stored) throw new ConflictException('MFA is already enabled');
    return {
      secret,
      otpauthUri: otpauthUri({ issuer: this.config.AUTH_MFA_ISSUER, account: user.email, secret }),
    };
  }

  /**
   * `POST /auth/mfa/totp/enable`: verifies the pending secret, enables MFA, issues recovery
   * codes, marks the current session MFA-authenticated and revokes every other session.
   */
  async enable(
    principal: UserPrincipal,
    code: string,
    context: ClientContext,
  ): Promise<{ recoveryCodes: string[] }> {
    const user = await this.requireUser(principal);
    if (user.mfaEnabled) throw new ConflictException('MFA is already enabled');
    const secret = this.decryptSecret(user);
    if (secret === null) throw new ConflictException('Start MFA setup first');
    const check = verifyTotp(secret.plaintext, code);
    if (!check.ok) throw new ForbiddenException('Invalid verification code');

    const codes = generateRecoveryCodes(RECOVERY_CODE_COUNT);
    await this.transactions.run(async (tx) => {
      if (!(await this.users.enableMfa(tx, user.id, check.step))) {
        throw new ConflictException('MFA is already enabled');
      }
      await this.recoveryCodes.replaceAll(tx, user, this.hashCodes(codes));
      await this.sessions.markMfaAuthenticated(tx, user.id, principal.sessionId);
      await this.audit.record(
        {
          organizationId: user.organizationId,
          actor: this.audit.actorFrom(principal),
          action: 'auth.mfa_enabled',
          resourceType: 'user',
          resourceId: user.publicId,
          sourceIp: context.ip,
        },
        tx,
      );
    });
    await this.sessions.revokeAllForUser(user.id, RevokeReason.mfaEnabled, {
      exceptSessionId: principal.sessionId,
    });
    await this.principalCache.invalidateUserByPublicId(user.publicId);
    return { recoveryCodes: codes };
  }

  /** `POST /auth/mfa/totp/disable` (`409` while the organization requires MFA). */
  async disable(
    principal: UserPrincipal,
    input: { password: string; code: string },
    context: ClientContext,
  ): Promise<void> {
    const user = await this.requireUser(principal);
    if (!user.mfaEnabled) throw new ConflictException('MFA is not enabled');
    if (user.organization.mfaRequired) {
      throw new ConflictException('Your organization requires MFA');
    }
    const passwordOk = await this.passwords.verify(user.passwordHash, input.password);
    const codeOk = passwordOk && (await this.verifyTotpCode(user, input.code));
    if (!passwordOk || !codeOk) throw new ForbiddenException('Invalid password or code');
    await this.transactions.run(async (tx) => {
      await this.users.disableMfa(tx, user.id);
      await this.recoveryCodes.deleteAll(tx, user.id);
      await this.audit.record(
        {
          organizationId: user.organizationId,
          actor: this.audit.actorFrom(principal),
          action: 'auth.mfa_disabled',
          resourceType: 'user',
          resourceId: user.publicId,
          sourceIp: context.ip,
        },
        tx,
      );
    });
    await this.principalCache.invalidateUserByPublicId(user.publicId);
  }

  /** `POST /auth/mfa/recovery-codes`: replaces all recovery codes after a TOTP check. */
  async regenerateRecoveryCodes(
    principal: UserPrincipal,
    code: string,
    context: ClientContext,
  ): Promise<{ recoveryCodes: string[] }> {
    const user = await this.requireUser(principal);
    if (!user.mfaEnabled) throw new ConflictException('MFA is not enabled');
    if (!(await this.verifyTotpCode(user, code))) {
      throw new ForbiddenException('Invalid verification code');
    }
    const codes = generateRecoveryCodes(RECOVERY_CODE_COUNT);
    await this.transactions.run(async (tx) => {
      await this.recoveryCodes.replaceAll(tx, user, this.hashCodes(codes));
      await this.audit.record(
        {
          organizationId: user.organizationId,
          actor: this.audit.actorFrom(principal),
          action: 'auth.recovery_codes_regenerated',
          resourceType: 'user',
          resourceId: user.publicId,
          sourceIp: context.ip,
        },
        tx,
      );
    });
    return { recoveryCodes: codes };
  }

  private hashCodes(codes: readonly string[]): string[] {
    return codes.map((c) => this.hasher.hmacHex(normalizeRecoveryCode(c)!));
  }

  private decryptSecret(
    user: AuthUserRecord,
  ): { plaintext: string; usedPreviousKey: boolean } | null {
    if (!user.mfaSecretCiphertext) return null;
    try {
      return this.secretBox.decrypt(user.mfaSecretCiphertext, mfaAad(user.id));
    } catch (err) {
      if (err instanceof SecretBoxError) {
        this.logger.error({ message: 'Stored MFA secret could not be decrypted' });
        return null;
      }
      throw err;
    }
  }

  private async requireUser(principal: UserPrincipal): Promise<AuthUserRecord> {
    const user = await this.users.findById(principal.userId);
    if (!user || user.deletedAt) throw new NotFoundException('User not found');
    return user;
  }
}
