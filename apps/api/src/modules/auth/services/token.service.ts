import { randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { errors, jwtVerify, SignJWT, type JWTPayload } from 'jose';
import { API_CONFIG } from '../../../api-config.token';
import type { ApiConfig } from '../../../config';

export type TokenServiceConfig = Pick<
  ApiConfig,
  | 'AUTH_JWT_SECRET'
  | 'AUTH_JWT_PREVIOUS_SECRET'
  | 'AUTH_JWT_ISSUER'
  | 'AUTH_JWT_AUDIENCE'
  | 'AUTH_ACCESS_TOKEN_TTL_SECONDS'
>;

export type AuthMethod = 'pwd' | 'otp';

/** Verified access-token claims (D4). */
export interface AccessTokenClaims {
  /** User public id. */
  sub: string;
  /** Home organization public id. */
  org: string;
  /** Session (refresh family) id. */
  sid: string;
  typ: 'access';
  amr: AuthMethod[];
  jti: string;
  iat: number;
  exp: number;
  mfa_enroll?: true;
  /** Platform override id. */
  ovr?: string;
}

export interface AccessTokenInput {
  userPublicId: string;
  organizationPublicId: string;
  sessionId: string;
  amr: readonly AuthMethod[];
  mfaEnrollmentRequired?: boolean;
  overrideId?: string;
  /** Override tokens expire with the override; others after AUTH_ACCESS_TOKEN_TTL_SECONDS. */
  expiresAt?: Date;
}

export interface IssuedAccessToken {
  token: string;
  expiresAt: Date;
  /** Seconds until expiry. */
  expiresIn: number;
}

export const JWT_ALGORITHM = 'HS256';
export const CLOCK_TOLERANCE_SECONDS = 30;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isClaims(payload: JWTPayload): payload is JWTPayload & AccessTokenClaims {
  const p = payload as Record<string, unknown>;
  return (
    p.typ === 'access' &&
    typeof p.sub === 'string' &&
    UUID.test(p.sub) &&
    typeof p.org === 'string' &&
    UUID.test(p.org) &&
    typeof p.sid === 'string' &&
    UUID.test(p.sid) &&
    typeof p.jti === 'string' &&
    typeof p.iat === 'number' &&
    typeof p.exp === 'number' &&
    Array.isArray(p.amr) &&
    p.amr.length > 0 &&
    p.amr.every((m) => m === 'pwd' || m === 'otp') &&
    (p.mfa_enroll === undefined || p.mfa_enroll === true) &&
    (p.ovr === undefined || (typeof p.ovr === 'string' && UUID.test(p.ovr)))
  );
}

/**
 * Access tokens (D4): HS256 JWTs signed with AUTH_JWT_SECRET (`kid: current`). Verification pins
 * the algorithm, issuer and audience, allows 30 s of clock skew and also accepts
 * AUTH_JWT_PREVIOUS_SECRET while the secret is being rotated.
 */
@Injectable()
export class TokenService {
  private readonly current: Uint8Array;
  private readonly previous: Uint8Array | undefined;

  constructor(@Inject(API_CONFIG) private readonly config: TokenServiceConfig) {
    const encoder = new TextEncoder();
    this.current = encoder.encode(config.AUTH_JWT_SECRET);
    this.previous = config.AUTH_JWT_PREVIOUS_SECRET
      ? encoder.encode(config.AUTH_JWT_PREVIOUS_SECRET)
      : undefined;
  }

  get accessTokenTtlSeconds(): number {
    return this.config.AUTH_ACCESS_TOKEN_TTL_SECONDS;
  }

  async issue(input: AccessTokenInput, now: Date = new Date()): Promise<IssuedAccessToken> {
    const iat = Math.floor(now.getTime() / 1000);
    const exp = input.expiresAt
      ? Math.floor(input.expiresAt.getTime() / 1000)
      : iat + this.config.AUTH_ACCESS_TOKEN_TTL_SECONDS;
    const payload: Record<string, unknown> = {
      org: input.organizationPublicId,
      sid: input.sessionId,
      typ: 'access',
      amr: [...input.amr],
      ...(input.mfaEnrollmentRequired && { mfa_enroll: true }),
      ...(input.overrideId && { ovr: input.overrideId }),
    };
    const token = await new SignJWT(payload)
      .setProtectedHeader({ alg: JWT_ALGORITHM, kid: 'current', typ: 'JWT' })
      .setIssuer(this.config.AUTH_JWT_ISSUER)
      .setAudience(this.config.AUTH_JWT_AUDIENCE)
      .setSubject(input.userPublicId)
      .setJti(randomUUID())
      .setIssuedAt(iat)
      .setExpirationTime(exp)
      .sign(this.current);
    return { token, expiresAt: new Date(exp * 1000), expiresIn: Math.max(0, exp - iat) };
  }

  /** The verified claims, or null for anything that is not a valid access token of ours. */
  async verify(token: string, now: Date = new Date()): Promise<AccessTokenClaims | null> {
    if (typeof token !== 'string' || token.length > 4096 || token.split('.').length !== 3) {
      return null;
    }
    const keys = this.previous ? [this.current, this.previous] : [this.current];
    for (const key of keys) {
      try {
        const { payload } = await jwtVerify(token, key, {
          algorithms: [JWT_ALGORITHM],
          issuer: this.config.AUTH_JWT_ISSUER,
          audience: this.config.AUTH_JWT_AUDIENCE,
          clockTolerance: CLOCK_TOLERANCE_SECONDS,
          currentDate: now,
          requiredClaims: ['exp', 'iat', 'sub', 'jti'],
        });
        return isClaims(payload) ? payload : null;
      } catch (err) {
        // Only a signature mismatch may be retried with the previous key.
        if (!(err instanceof errors.JWSSignatureVerificationFailed)) return null;
      }
    }
    return null;
  }
}
