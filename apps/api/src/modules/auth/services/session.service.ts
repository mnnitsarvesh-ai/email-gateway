import { randomUUID } from 'node:crypto';
import { Inject, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService, SYSTEM_ACTOR } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { generateOpaqueToken, isOpaqueToken, sha256Hex } from '../../../crypto/tokens';
import { TransactionRunner } from '../../../database/transaction-runner';
import { KeyValueStore } from '../../../kv/key-value-store';
import { kvKeys, RevokeReason } from '../auth.constants';
import { SessionsRepository, type SessionRow } from '../repositories/sessions.repository';
import { type AuthUserRecord, UsersAuthRepository } from '../repositories/users-auth.repository';
import { failClosed } from './kv-fail-closed';
import { type AuthMethod, TokenService } from './token.service';

export type SessionConfig = Pick<
  ApiConfig,
  | 'AUTH_REFRESH_TOKEN_TTL_SECONDS'
  | 'AUTH_SESSION_MAX_AGE_SECONDS'
  | 'AUTH_ACCESS_TOKEN_TTL_SECONDS'
>;

/** Where a request came from (stored on session rows, audit rows and login audit rows). */
export interface ClientContext {
  ip: string | null;
  userAgent: string | null;
}

/** The token response of login, MFA verification and refresh (§4.1). */
export interface TokenResponse {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  refreshToken: string;
  refreshTokenExpiresAt: string;
  sessionId: string;
  mfaEnrollmentRequired: boolean;
  user: { id: string; email: string; displayName: string };
  organization: { id: string; slug: string; name: string; kind: 'customer' | 'platform' };
}

/** A live session as shown to its owner or an administrator. */
export interface SessionView {
  id: string;
  current: boolean;
  authenticatedAt: string;
  lastUsedAt: string | null;
  expiresAt: string;
  ipAddress: string | null;
  userAgent: string | null;
  mfaAuthenticated: boolean;
}

export function toSessionView(row: SessionRow, currentSessionId?: string): SessionView {
  return {
    id: row.familyId,
    current: row.familyId === currentSessionId,
    authenticatedAt: row.authenticatedAt.toISOString(),
    lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
    expiresAt: (row.expiresAt < row.absoluteExpiresAt
      ? row.expiresAt
      : row.absoluteExpiresAt
    ).toISOString(),
    ipAddress: row.ipAddress,
    userAgent: row.userAgent,
    mfaAuthenticated: row.mfaAuthenticated,
  };
}

const MAX_USER_AGENT = 512;

type RotationOutcome =
  | { kind: 'invalid' }
  | { kind: 'reuse'; familyId: string }
  | {
      kind: 'rotated';
      user: AuthUserRecord;
      familyId: string;
      mfaAuthenticated: boolean;
      refreshToken: string;
      refreshTokenExpiresAt: Date;
    };

/**
 * Sessions are refresh-token families (D5). Every refresh rotates the token; presenting a
 * rotated token revokes the whole family (reuse detection). Revocation writes deny-list entries
 * for the session ids so access tokens stop working immediately.
 */
@Injectable()
export class SessionService {
  private readonly logger = new Logger(SessionService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: SessionConfig,
    private readonly sessions: SessionsRepository,
    private readonly users: UsersAuthRepository,
    private readonly transactions: TransactionRunner,
    private readonly kv: KeyValueStore,
    private readonly tokens: TokenService,
    private readonly audit: AuditService,
  ) {}

  /** Starts a session for an authenticated user and returns the token response. */
  async start(
    user: AuthUserRecord,
    context: ClientContext,
    options: { mfaAuthenticated: boolean },
  ): Promise<TokenResponse> {
    const now = new Date();
    const refreshToken = generateOpaqueToken('egr');
    const familyId = randomUUID();
    const absoluteExpiresAt = new Date(
      now.getTime() + this.config.AUTH_SESSION_MAX_AGE_SECONDS * 1000,
    );
    const expiresAt = this.idleExpiry(now, absoluteExpiresAt);
    await this.sessions.create({
      organizationId: user.organizationId,
      userId: user.id,
      refreshTokenHash: sha256Hex(refreshToken),
      familyId,
      ipAddress: context.ip,
      userAgent: context.userAgent?.slice(0, MAX_USER_AGENT) ?? null,
      lastUsedAt: now,
      authenticatedAt: now,
      expiresAt,
      absoluteExpiresAt,
      mfaAuthenticated: options.mfaAuthenticated,
    });
    return this.tokenResponse(user, familyId, options.mfaAuthenticated, refreshToken, expiresAt);
  }

  /**
   * `POST /auth/refresh` (D5): one writer transaction. Reuse of a rotated token (or losing a
   * concurrent rotation) revokes the family, deny-lists it and is audited; every failure is `401`.
   */
  async rotate(refreshToken: string, context: ClientContext): Promise<TokenResponse> {
    if (!isOpaqueToken(refreshToken, 'egr')) throw new UnauthorizedException();
    const hash = sha256Hex(refreshToken);
    const now = new Date();

    const outcome = await this.transactions.run<RotationOutcome>(async (tx) => {
      const row = await this.sessions.findByTokenHash(hash, tx);
      if (!row) return { kind: 'invalid' };
      if (row.revokedAt) {
        return row.revokedReason === RevokeReason.rotated
          ? this.revokeReusedFamily(tx, row, context, now)
          : { kind: 'invalid' };
      }
      if (row.expiresAt <= now || row.absoluteExpiresAt <= now) return { kind: 'invalid' };
      const user = await this.users.findById(row.userId, tx);
      if (!user || !isUsable(user)) return { kind: 'invalid' };
      if (!(await this.sessions.markRotated(tx, row.id, now))) {
        // Another request rotated this token first: treat it as reuse (clients serialize).
        return this.revokeReusedFamily(tx, row, context, now);
      }
      const next = generateOpaqueToken('egr');
      const expiresAt = this.idleExpiry(now, row.absoluteExpiresAt);
      await this.sessions.create(
        {
          organizationId: row.organizationId,
          userId: row.userId,
          refreshTokenHash: sha256Hex(next),
          familyId: row.familyId,
          ipAddress: context.ip,
          userAgent: context.userAgent?.slice(0, MAX_USER_AGENT) ?? null,
          lastUsedAt: now,
          authenticatedAt: row.authenticatedAt,
          expiresAt,
          absoluteExpiresAt: row.absoluteExpiresAt,
          mfaAuthenticated: row.mfaAuthenticated,
        },
        tx,
      );
      return {
        kind: 'rotated',
        user,
        familyId: row.familyId,
        mfaAuthenticated: row.mfaAuthenticated,
        refreshToken: next,
        refreshTokenExpiresAt: expiresAt,
      };
    });

    if (outcome.kind === 'reuse') {
      this.logger.warn({ message: 'Refresh token reuse detected; session revoked' });
      await this.denyList([outcome.familyId]);
      throw new UnauthorizedException();
    }
    if (outcome.kind === 'invalid') throw new UnauthorizedException();
    return this.tokenResponse(
      outcome.user,
      outcome.familyId,
      outcome.mfaAuthenticated,
      outcome.refreshToken,
      outcome.refreshTokenExpiresAt,
    );
  }

  /** Revokes one session of the user. False when the user has no such live session. */
  async revokeSession(userId: bigint, sessionId: string, reason: RevokeReason): Promise<boolean> {
    const now = new Date();
    const row = await this.sessions.findLiveRow(userId, sessionId, now);
    if (!row) return false;
    await this.sessions.revokeFamilies([sessionId], reason, now);
    await this.denyList([sessionId]);
    return true;
  }

  /** Revokes every live session of the user, optionally keeping the caller's own. */
  async revokeAllForUser(
    userId: bigint,
    reason: RevokeReason,
    opts: { exceptSessionId?: string } = {},
  ): Promise<number> {
    const now = new Date();
    const families = (await this.sessions.liveFamilyIds({ userId }, now)).filter(
      (id) => id !== opts.exceptSessionId,
    );
    await this.sessions.revokeFamilies(families, reason, now);
    await this.denyList(families);
    return families.length;
  }

  /** `POST /auth/logout-all`: every own session, audited as `session.revoked_all`. */
  async revokeAllForUserAudited(
    principal: UserPrincipal,
    reason: RevokeReason,
    context: ClientContext,
  ): Promise<number> {
    const count = await this.revokeAllForUser(principal.userId, reason);
    await this.audit.record({
      organizationId: principal.organizationId,
      actor: this.audit.actorFrom(principal),
      action: 'session.revoked_all',
      resourceType: 'user',
      resourceId: principal.userPublicId,
      sourceIp: context.ip,
      metadata: { reason, sessions: count },
    });
    return count;
  }

  /** `DELETE /auth/sessions/{id}`: one own session, audited as `session.revoked`. */
  async revokeOwnSession(
    principal: UserPrincipal,
    sessionId: string,
    context: ClientContext,
  ): Promise<boolean> {
    const revoked = await this.revokeSession(principal.userId, sessionId, RevokeReason.userRevoked);
    if (revoked) {
      await this.audit.record({
        organizationId: principal.organizationId,
        actor: this.audit.actorFrom(principal),
        action: 'session.revoked',
        resourceType: 'session',
        resourceId: sessionId,
        sourceIp: context.ip,
        metadata: { reason: RevokeReason.userRevoked, sessionId },
      });
    }
    return revoked;
  }

  /** Revokes every live session of every user of the organization (suspension, deletion). */
  async revokeAllForOrganization(organizationId: bigint, reason: RevokeReason): Promise<number> {
    const now = new Date();
    const families = await this.sessions.liveFamilyIds({ organizationId }, now);
    await this.sessions.revokeFamilies(families, reason, now);
    await this.denyList(families);
    return families.length;
  }

  /** Live sessions of a user within the scope's organization (reader; may lag briefly). */
  async listLiveForUser(scope: TenantScope, userId: bigint): Promise<SessionRow[]> {
    return this.sessions.listLive(scope, userId, new Date());
  }

  /** Marks the caller's session as MFA-authenticated (MFA enrollment, D7). */
  async markMfaAuthenticated(
    tx: Prisma.TransactionClient,
    userId: bigint,
    sessionId: string,
  ): Promise<void> {
    await this.sessions.markFamilyMfaAuthenticated(tx, userId, sessionId);
  }

  /** True when the session still has a live row. */
  isLive(sessionId: string): Promise<boolean> {
    return this.sessions.isFamilyLive(sessionId, new Date());
  }

  /** True when the session id is deny-listed. */
  isRevoked(sessionId: string): Promise<boolean> {
    return this.kv.exists(kvKeys.revokedSession(sessionId));
  }

  private async revokeReusedFamily(
    tx: Prisma.TransactionClient,
    row: SessionRow,
    context: ClientContext,
    now: Date,
  ): Promise<RotationOutcome> {
    await this.sessions.revokeFamilies([row.familyId], RevokeReason.reuseDetected, now, tx);
    await this.audit.record(
      {
        organizationId: row.organizationId,
        actor: SYSTEM_ACTOR,
        action: 'auth.refresh_token_reused',
        resourceType: 'session',
        resourceId: row.familyId,
        sourceIp: context.ip,
        metadata: { sessionId: row.familyId, ipAddress: context.ip },
      },
      tx,
    );
    return { kind: 'reuse', familyId: row.familyId };
  }

  private async denyList(familyIds: readonly string[]): Promise<void> {
    if (familyIds.length === 0) return;
    const ttl = this.config.AUTH_ACCESS_TOKEN_TTL_SECONDS + 60;
    await failClosed(this.logger, 'session-deny-list', async () => {
      for (const id of familyIds) await this.kv.set(kvKeys.revokedSession(id), '1', ttl);
    });
  }

  private idleExpiry(now: Date, absoluteExpiresAt: Date): Date {
    const idle = new Date(now.getTime() + this.config.AUTH_REFRESH_TOKEN_TTL_SECONDS * 1000);
    return idle < absoluteExpiresAt ? idle : absoluteExpiresAt;
  }

  private async tokenResponse(
    user: AuthUserRecord,
    sessionId: string,
    mfaAuthenticated: boolean,
    refreshToken: string,
    refreshTokenExpiresAt: Date,
  ): Promise<TokenResponse> {
    const mfaEnrollmentRequired = user.organization.mfaRequired && !user.mfaEnabled;
    const amr: AuthMethod[] = mfaAuthenticated ? ['pwd', 'otp'] : ['pwd'];
    const access = await this.tokens.issue({
      userPublicId: user.publicId,
      organizationPublicId: user.organization.publicId,
      sessionId,
      amr,
      mfaEnrollmentRequired,
    });
    return {
      accessToken: access.token,
      tokenType: 'Bearer',
      expiresIn: access.expiresIn,
      refreshToken,
      refreshTokenExpiresAt: refreshTokenExpiresAt.toISOString(),
      sessionId,
      mfaEnrollmentRequired,
      user: { id: user.publicId, email: user.email, displayName: user.displayName },
      organization: {
        id: user.organization.publicId,
        slug: user.organization.slug,
        name: user.organization.name,
        kind: user.organization.kind,
      },
    };
  }
}

/** Active, not deleted, in an active organization. */
export function isUsable(user: AuthUserRecord): boolean {
  return (
    user.status === 'active' &&
    user.deletedAt === null &&
    user.organization.status === 'active' &&
    user.organization.deletedAt === null
  );
}
