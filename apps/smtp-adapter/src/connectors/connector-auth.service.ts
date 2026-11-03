import { Inject, Injectable } from '@nestjs/common';
import { PrismaService, RedisService } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import { verify as argon2Verify } from 'argon2';
import { createHmac, randomBytes } from 'node:crypto';
import { ADAPTER_CONFIG, ADAPTER_LOGGER, type SmtpAdapterConfig } from '../config';
import { FixedWindowLimiter } from '../rate-limit/fixed-window-limiter';
import { cacheKeys } from '../tenancy/cache-keys';

/**
 * - `ok`: credentials valid, connector and organization active.
 * - `fail`: wrong or unknown credentials, or connector/organization not active.
 * - `temp`: database, Redis or hash failure (Postfix answers 454 4.7.0).
 * - `throttled`: too many failures from this client IP (also a temporary failure).
 */
export type AuthResult =
  | { result: 'ok'; connectorId: bigint; organizationId: bigint }
  | { result: 'fail' | 'temp' | 'throttled' };

export type ConnectorAuthConfig = Pick<
  SmtpAdapterConfig,
  | 'SMTP_AUTH_MAX_FAILURES_PER_IP'
  | 'SMTP_AUTH_FAILURE_WINDOW_SECONDS'
  | 'SMTP_AUTH_VERIFY_CACHE_SECONDS'
>;

/** Upper bound of the process-local verification cache. */
const MAX_VERIFY_CACHE_ENTRIES = 10_000;

/** Verification function (argon2 in production; injectable for tests). */
export type PasswordVerifier = (hash: string, secret: string) => Promise<boolean>;
export const PASSWORD_VERIFIER = Symbol('PASSWORD_VERIFIER');
export const argon2PasswordVerifier: PasswordVerifier = (hash, secret) =>
  argon2Verify(hash, secret);

/**
 * SASL credential check of `sasl` connectors (step 2.2 D10), used by the Dovecot auth server.
 *
 * Per AUTH: the per-IP failure counter (`sa:authfail:{ip}`) is checked first; then the connector
 * is read from the writer by its unique username (status and organization status on every
 * AUTH), and the secret is verified against the Argon2id PHC hash. Successful verifications are
 * cached in process memory for SMTP_AUTH_VERIFY_CACHE_SECONDS under
 * HMAC-SHA256(per-process random key, username NUL secret NUL connector updated_at), so a
 * rotated secret or a changed connector never hits a stale entry and the secret itself is never
 * kept. Failures increment the IP counter. Secrets are never logged.
 */
@Injectable()
export class ConnectorAuthService {
  private readonly logger: Logger;
  private readonly cacheKey = randomBytes(32);
  /** HMAC → expiry (epoch ms). Insertion order = age, for eviction. */
  private readonly verified = new Map<string, number>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly limiter: FixedWindowLimiter,
    @Inject(ADAPTER_CONFIG) private readonly config: ConnectorAuthConfig,
    @Inject(ADAPTER_LOGGER) logger: Logger,
    @Inject(PASSWORD_VERIFIER) private readonly verifyPassword: PasswordVerifier,
  ) {
    this.logger = logger.child({ component: 'connector-auth' });
  }

  async authenticate(username: string, secret: string, clientIp: string): Promise<AuthResult> {
    const failureKey = cacheKeys.authFailures(clientIp || 'unknown');
    try {
      const failures = Number((await this.redis.client.get(failureKey)) ?? '0');
      if (failures >= this.config.SMTP_AUTH_MAX_FAILURES_PER_IP) return { result: 'throttled' };
    } catch (err) {
      this.logger.error({ err }, 'auth failure counter unavailable; temporary failure');
      return { result: 'temp' };
    }

    let connector;
    try {
      connector = await this.prisma.smtpConnector.findUnique({
        where: { saslUsername: username },
        select: {
          id: true,
          organizationId: true,
          authType: true,
          status: true,
          secretHash: true,
          updatedAt: true,
          organization: { select: { status: true } },
        },
      });
    } catch (err) {
      this.logger.error({ err }, 'connector lookup failed; temporary failure');
      return { result: 'temp' };
    }

    if (
      connector &&
      connector.authType === 'sasl' &&
      connector.status === 'active' &&
      connector.organization.status === 'active' &&
      connector.secretHash
    ) {
      const cacheKey = this.verifyCacheKey(username, secret, connector.updatedAt);
      if (this.isCached(cacheKey)) {
        return {
          result: 'ok',
          connectorId: connector.id,
          organizationId: connector.organizationId,
        };
      }
      let valid: boolean;
      try {
        valid = await this.verifyPassword(connector.secretHash, secret);
      } catch (err) {
        this.logger.error(
          { err, connectorId: String(connector.id) },
          'secret hash could not be verified; temporary failure',
        );
        return { result: 'temp' };
      }
      if (valid) {
        this.remember(cacheKey);
        return {
          result: 'ok',
          connectorId: connector.id,
          organizationId: connector.organizationId,
        };
      }
    }

    await this.countFailure(failureKey);
    return { result: 'fail' };
  }

  private async countFailure(key: string): Promise<void> {
    try {
      await this.limiter.increment(key, this.config.SMTP_AUTH_FAILURE_WINDOW_SECONDS * 1000);
    } catch (err) {
      // The credentials were wrong either way; the next AUTH sees Redis down and answers temp.
      this.logger.warn({ err }, 'auth failure not counted');
    }
  }

  private verifyCacheKey(username: string, secret: string, updatedAt: Date): string {
    return createHmac('sha256', this.cacheKey)
      .update(`${username}\0${secret}\0${updatedAt.toISOString()}`)
      .digest('base64url');
  }

  private isCached(key: string): boolean {
    const expiresAt = this.verified.get(key);
    if (expiresAt === undefined) return false;
    if (expiresAt > Date.now()) return true;
    this.verified.delete(key);
    return false;
  }

  private remember(key: string): void {
    const ttlMs = this.config.SMTP_AUTH_VERIFY_CACHE_SECONDS * 1000;
    if (ttlMs === 0) return;
    if (this.verified.size >= MAX_VERIFY_CACHE_ENTRIES) {
      const oldest = this.verified.keys().next();
      if (!oldest.done) this.verified.delete(oldest.value);
    }
    this.verified.set(key, Date.now() + ttlMs);
  }
}
