import { randomBytes, randomUUID } from 'node:crypto';
import { Logger, UnauthorizedException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryKeyValueStore } from '../../../../test/support/in-memory-key-value-store';
import type { AuditService } from '../../../audit/audit.service';
import { sha256Hex } from '../../../crypto/tokens';
import type { TransactionRunner } from '../../../database/transaction-runner';
import type {
  NewSessionRow,
  SessionRow,
  SessionsRepository,
} from '../repositories/sessions.repository';
import type { AuthUserRecord, UsersAuthRepository } from '../repositories/users-auth.repository';
import { SessionService } from './session.service';
import { TokenService } from './token.service';

type Row = SessionRow & { refreshTokenHash: string };

/** In-memory `user_sessions` with the repository's semantics. */
class FakeSessions {
  rows: Row[] = [];
  private nextId = 1n;
  private live = (r: Row, now: Date) =>
    !r.revokedAt && r.expiresAt > now && r.absoluteExpiresAt > now;

  create(data: NewSessionRow): Promise<SessionRow> {
    const row: Row = {
      ...data,
      id: this.nextId++,
      revokedAt: null,
      revokedReason: null,
      createdAt: new Date(),
    };
    this.rows.push(row);
    return Promise.resolve(row);
  }
  findByTokenHash(hash: string): Promise<SessionRow | null> {
    return Promise.resolve(this.rows.find((r) => r.refreshTokenHash === hash) ?? null);
  }
  markRotated(_tx: unknown, id: bigint, now: Date): Promise<boolean> {
    const row = this.rows.find((r) => r.id === id && !r.revokedAt);
    if (row) Object.assign(row, { revokedAt: now, revokedReason: 'rotated' });
    return Promise.resolve(!!row);
  }
  revokeFamilies(familyIds: readonly string[], reason: string, now: Date): Promise<number> {
    const rows = this.rows.filter((r) => familyIds.includes(r.familyId) && !r.revokedAt);
    for (const r of rows) Object.assign(r, { revokedAt: now, revokedReason: reason });
    return Promise.resolve(rows.length);
  }
  liveFamilyIds(
    filter: { userId?: bigint; organizationId?: bigint },
    now: Date,
  ): Promise<string[]> {
    const ids = this.rows
      .filter((r) => this.live(r, now))
      .filter(
        (r) =>
          (filter.userId === undefined || r.userId === filter.userId) &&
          (filter.organizationId === undefined || r.organizationId === filter.organizationId),
      )
      .map((r) => r.familyId);
    return Promise.resolve([...new Set(ids)]);
  }
  findLiveRow(userId: bigint, familyId: string, now: Date): Promise<SessionRow | null> {
    return Promise.resolve(
      this.rows.find((r) => r.userId === userId && r.familyId === familyId && this.live(r, now)) ??
        null,
    );
  }
  isFamilyLive(familyId: string, now: Date): Promise<boolean> {
    return Promise.resolve(this.rows.some((r) => r.familyId === familyId && this.live(r, now)));
  }
}

function authUser(overrides: Partial<AuthUserRecord> = {}): AuthUserRecord {
  return {
    id: 10n,
    publicId: randomUUID(),
    organizationId: 2n,
    email: 'alice@example.test',
    displayName: 'Alice',
    status: 'active',
    passwordHash: null,
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

const config = {
  AUTH_REFRESH_TOKEN_TTL_SECONDS: 3600,
  AUTH_SESSION_MAX_AGE_SECONDS: 7200,
  AUTH_ACCESS_TOKEN_TTL_SECONDS: 600,
};
const context = { ip: '198.51.100.9', userAgent: 'vitest' };

describe('SessionService', () => {
  let sessions: FakeSessions;
  let kv: InMemoryKeyValueStore;
  let user: AuthUserRecord;
  let audit: { record: ReturnType<typeof vi.fn> };
  let tokens: TokenService;
  let service: SessionService;

  beforeEach(() => {
    sessions = new FakeSessions();
    kv = new InMemoryKeyValueStore();
    user = authUser();
    audit = { record: vi.fn().mockResolvedValue(undefined) };
    tokens = new TokenService({
      AUTH_JWT_SECRET: randomBytes(32).toString('hex'),
      AUTH_JWT_ISSUER: 'iss',
      AUTH_JWT_AUDIENCE: 'aud',
      AUTH_ACCESS_TOKEN_TTL_SECONDS: 600,
    });
    const users = { findById: vi.fn(() => Promise.resolve(user)) };
    const transactions = { run: (fn: (tx: object) => Promise<unknown>) => fn({}) };
    service = new SessionService(
      config,
      sessions as unknown as SessionsRepository,
      users as unknown as UsersAuthRepository,
      transactions as unknown as TransactionRunner,
      kv,
      tokens,
      audit as unknown as AuditService,
    );
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
  });
  afterEach(() => vi.restoreAllMocks());

  it('starts a session family with idle and absolute expiry', async () => {
    const res = await service.start(user, context, { mfaAuthenticated: false });
    expect(res).toMatchObject({
      tokenType: 'Bearer',
      expiresIn: 600,
      mfaEnrollmentRequired: false,
    });
    const [row] = sessions.rows;
    expect(row).toMatchObject({
      familyId: res.sessionId,
      refreshTokenHash: sha256Hex(res.refreshToken),
    });
    expect(row!.absoluteExpiresAt.getTime() - row!.authenticatedAt.getTime()).toBe(7_200_000);
    expect(row!.expiresAt.getTime() - row!.authenticatedAt.getTime()).toBe(3_600_000);
    expect(await tokens.verify(res.accessToken)).toMatchObject({
      sid: res.sessionId,
      amr: ['pwd'],
    });
  });

  it('flags MFA enrollment when the organization requires MFA', async () => {
    user = authUser({ organization: { ...user.organization, mfaRequired: true } });
    const res = await service.start(user, context, { mfaAuthenticated: false });
    expect(res.mfaEnrollmentRequired).toBe(true);
    expect(await tokens.verify(res.accessToken)).toMatchObject({ mfa_enroll: true });
  });

  it('rotates: the old row is spent, the new row keeps the family and MFA state', async () => {
    const first = await service.start(user, context, { mfaAuthenticated: true });
    const second = await service.rotate(first.refreshToken, context);
    expect(second.sessionId).toBe(first.sessionId);
    expect(second.refreshToken).not.toBe(first.refreshToken);
    expect(sessions.rows.map((r) => r.revokedReason)).toEqual(['rotated', null]);
    expect(sessions.rows[1]!.authenticatedAt).toEqual(sessions.rows[0]!.authenticatedAt);
    expect(await tokens.verify(second.accessToken)).toMatchObject({ amr: ['pwd', 'otp'] });
  });

  it('never extends a family past its absolute expiry', async () => {
    const first = await service.start(user, context, { mfaAuthenticated: false });
    sessions.rows[0]!.absoluteExpiresAt = new Date(Date.now() + 60_000);
    await service.rotate(first.refreshToken, context);
    expect(sessions.rows[1]!.expiresAt).toEqual(sessions.rows[0]!.absoluteExpiresAt);
  });

  it('detects reuse: the family is revoked, deny-listed and audited', async () => {
    const first = await service.start(user, context, { mfaAuthenticated: false });
    const second = await service.rotate(first.refreshToken, context);
    await expect(service.rotate(first.refreshToken, context)).rejects.toThrow(
      UnauthorizedException,
    );
    expect(sessions.rows.every((r) => r.revokedAt)).toBe(true);
    expect(sessions.rows[1]!.revokedReason).toBe('reuse_detected');
    expect(await service.isRevoked(first.sessionId)).toBe(true);
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'auth.refresh_token_reused',
        resourceId: first.sessionId,
        organizationId: 2n,
      }),
      expect.anything(),
    );
    await expect(service.rotate(second.refreshToken, context)).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('treats losing a concurrent rotation as reuse', async () => {
    const first = await service.start(user, context, { mfaAuthenticated: false });
    vi.spyOn(sessions, 'markRotated').mockResolvedValueOnce(false);
    await expect(service.rotate(first.refreshToken, context)).rejects.toThrow(
      UnauthorizedException,
    );
    expect(sessions.rows[0]!.revokedReason).toBe('reuse_detected');
    expect(audit.record).toHaveBeenCalledTimes(1);
  });

  it('rejects unknown, malformed, expired, otherwise revoked tokens and inactive users without revoking', async () => {
    await expect(service.rotate('egr_unknown', context)).rejects.toThrow(UnauthorizedException);
    await expect(service.rotate(`egr_${'A'.repeat(43)}`, context)).rejects.toThrow(
      UnauthorizedException,
    );

    const expired = await service.start(user, context, { mfaAuthenticated: false });
    sessions.rows.at(-1)!.expiresAt = new Date(Date.now() - 1000);
    await expect(service.rotate(expired.refreshToken, context)).rejects.toThrow(
      UnauthorizedException,
    );

    const loggedOut = await service.start(user, context, { mfaAuthenticated: false });
    await service.revokeSession(user.id, loggedOut.sessionId, 'logout');
    await expect(service.rotate(loggedOut.refreshToken, context)).rejects.toThrow(
      UnauthorizedException,
    );

    const suspended = await service.start(user, context, { mfaAuthenticated: false });
    user = authUser({ organization: { ...user.organization, status: 'suspended' } });
    await expect(service.rotate(suspended.refreshToken, context)).rejects.toThrow(
      UnauthorizedException,
    );
    expect(sessions.rows.at(-1)!.revokedAt).toBeNull();
    expect(audit.record).not.toHaveBeenCalled();
  });

  it('revokes all sessions of a user except the current one, deny-listing each', async () => {
    const a = await service.start(user, context, { mfaAuthenticated: false });
    const b = await service.start(user, context, { mfaAuthenticated: false });
    const c = await service.start(user, context, { mfaAuthenticated: false });
    expect(
      await service.revokeAllForUser(user.id, 'password_changed', { exceptSessionId: a.sessionId }),
    ).toBe(2);
    expect(await service.isRevoked(a.sessionId)).toBe(false);
    expect(await service.isRevoked(b.sessionId)).toBe(true);
    expect(await service.isRevoked(c.sessionId)).toBe(true);
    expect(await kv.ttl(`auth:revoked:${b.sessionId}`)).toBe(660);
  });

  it('revokes every session of an organization', async () => {
    await service.start(user, context, { mfaAuthenticated: false });
    await service.start(authUser({ id: 11n }), context, { mfaAuthenticated: false });
    await service.start(authUser({ id: 12n, organizationId: 3n }), context, {
      mfaAuthenticated: false,
    });
    expect(await service.revokeAllForOrganization(2n, 'organization_suspended')).toBe(2);
  });

  it('revokeSession is false for another user’s or an unknown session', async () => {
    const a = await service.start(user, context, { mfaAuthenticated: false });
    expect(await service.revokeSession(99n, a.sessionId, 'user_revoked')).toBe(false);
    expect(await service.revokeSession(user.id, randomUUID(), 'user_revoked')).toBe(false);
    expect(await service.revokeSession(user.id, a.sessionId, 'user_revoked')).toBe(true);
  });
});
