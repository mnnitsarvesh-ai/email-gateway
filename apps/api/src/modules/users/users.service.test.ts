import { ConflictException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { SYSTEM_ROLES, TENANT_PERMISSIONS } from '@email-gateway/database';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../audit/audit.service';
import type { ApiKeyPrincipal, UserPrincipal } from '../../auth-contracts/principal';
import { systemScope } from '../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../database/transaction-runner';
import type { OrganizationLimitsService } from '../../tenancy/organization-limits.service';
import type { EmailVerificationService } from '../auth/services/email-verification.service';
import type { InvitationService } from '../auth/services/invitation.service';
import type { LoginThrottleService } from '../auth/services/login-throttle.service';
import type { PrincipalCacheService } from '../auth/services/principal-cache.service';
import type { SessionService } from '../auth/services/session.service';
import type { RoleRecord } from '../roles/roles.repository';
import type { RolesService } from '../roles/roles.service';
import type { UserRecord, UsersRepository } from './users.repository';
import { changedRoles, planStatusChange, toUserView, UsersService } from './users.service';

const scope = systemScope(7n);
const client = { ip: '203.0.113.7', userAgent: null };
const now = new Date('2026-11-02T10:00:00Z');
const later = new Date(now.getTime() + 60_000);
const earlier = new Date(now.getTime() - 60_000);
const TARGET_ID = '0190a0b0-0000-7000-8000-0000000000aa';

function roleRecord(key: string, id: bigint): RoleRecord {
  const def = SYSTEM_ROLES.find((r) => r.key === key)!;
  return {
    id,
    organizationId: null,
    key,
    name: def.name,
    description: null,
    isSystem: true,
    permissions: [...def.permissions],
    createdAt: now,
    updatedAt: now,
  };
}
const ROLES = {
  organization_admin: roleRecord('organization_admin', 3n),
  domain_admin: roleRecord('domain_admin', 4n),
  read_only_user: roleRecord('read_only_user', 8n),
};

function userRecord(overrides: Partial<UserRecord> = {}): UserRecord {
  return {
    id: 50n,
    publicId: TARGET_ID,
    organizationId: 7n,
    email: 'target@example.test',
    displayName: 'Target',
    status: 'active',
    statusReason: null,
    hasPassword: true,
    mfaEnabled: false,
    emailVerifiedAt: now,
    lockedUntil: null,
    lastLoginAt: null,
    deletedAt: null,
    createdAt: now,
    updatedAt: now,
    roles: [{ id: 8n, key: 'read_only_user', name: 'Read-only User' }],
    ...overrides,
  };
}

function actor(permissions: Iterable<string>, userId = 1n): UserPrincipal {
  return {
    kind: 'user',
    userId,
    userPublicId: '0190a0b0-0000-7000-8000-000000000001',
    organizationId: 7n,
    organizationPublicId: '0190a0b0-0000-7000-8000-000000000007',
    organizationKind: 'customer',
    sessionId: '3f0e8c1a-2b3c-4d5e-8f90-a1b2c3d4e5f6',
    mfaAuthenticated: true,
    mfaEnrollmentRequired: false,
    permissions: new Set(permissions),
  };
}
const admin = actor(TENANT_PERMISSIONS);

function setup(target: UserRecord | null = userRecord()) {
  const events: string[] = [];
  const users = {
    list: vi.fn(() => Promise.resolve([])),
    findByPublicId: vi.fn(() => Promise.resolve(target)),
    findAnyByEmail: vi.fn(() => Promise.resolve(null)),
    countNonDeleted: vi.fn(() => Promise.resolve(3)),
    createInvited: vi.fn(() => Promise.resolve({ id: 60n, publicId: TARGET_ID })),
    reinstateAsInvited: vi.fn(() => Promise.resolve({ id: 61n, publicId: TARGET_ID })),
    replaceRoles: vi.fn(() => Promise.resolve()),
    updateProfile: vi.fn(() => Promise.resolve('updated')),
    setStatus: vi.fn(() => Promise.resolve()),
    softDelete: vi.fn(() => Promise.resolve(true)),
    resetMfa: vi.fn(() => Promise.resolve()),
    consumeTokens: vi.fn(() => Promise.resolve(1)),
    organizationName: vi.fn(() => Promise.resolve('Acme')),
  };
  const roles = {
    resolveForAssignment: vi.fn((_tx: unknown, _s: unknown, keys: readonly string[]) =>
      Promise.resolve(keys.map((k) => ROLES[k as keyof typeof ROLES])),
    ),
    findByKeys: vi.fn((_tx: unknown, _s: unknown, keys: readonly string[]) =>
      Promise.resolve(keys.map((k) => ROLES[k as keyof typeof ROLES])),
    ),
    countActiveAdministrators: vi.fn(() => Promise.resolve(2)),
  };
  const transactions = {
    run: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => {
      events.push('tx:begin');
      const result = await fn({});
      events.push('tx:commit');
      return result;
    }),
  };
  const limits = {
    lockOrganization: vi.fn(() => Promise.resolve()),
    assertWithinLimit: vi.fn(() => Promise.resolve()),
  };
  const audit = {
    record: vi.fn(() => Promise.resolve()),
    actorFrom: vi.fn(() => ({ type: 'user', id: 'actor' })),
  };
  const invitations = {
    createToken: vi.fn(() => Promise.resolve({ token: 'egt_x', expiresAt: later })),
    sendInvitation: vi.fn(() => {
      events.push('email:invitation');
      return Promise.resolve(true);
    }),
  };
  const emailVerification = { issueAndSend: vi.fn(() => Promise.resolve(true)) };
  const sessions = {
    revokeAllForUser: vi.fn(() => {
      events.push('sessions:revoked');
      return Promise.resolve(1);
    }),
    revokeSession: vi.fn(() => Promise.resolve(true)),
    listLiveForUser: vi.fn(() => Promise.resolve([])),
  };
  const cache = {
    invalidateUser: vi.fn(() => {
      events.push('cache:user');
      return Promise.resolve();
    }),
  };
  const throttle = { clearForUser: vi.fn(() => Promise.resolve()) };
  const service = new UsersService(
    users as unknown as UsersRepository,
    roles as unknown as RolesService,
    transactions as unknown as TransactionRunner,
    limits as unknown as OrganizationLimitsService,
    audit as unknown as AuditService,
    invitations as unknown as InvitationService,
    emailVerification as unknown as EmailVerificationService,
    sessions as unknown as SessionService,
    cache as unknown as PrincipalCacheService,
    throttle as unknown as LoginThrottleService,
  );
  return {
    service,
    users,
    roles,
    limits,
    audit,
    invitations,
    emailVerification,
    sessions,
    cache,
    throttle,
    events,
  };
}

describe('toUserView', () => {
  it('maps public fields only and hides an expired lock', () => {
    const view = toUserView(userRecord({ lockedUntil: earlier }), now);
    expect(view).toEqual({
      id: TARGET_ID,
      email: 'target@example.test',
      displayName: 'Target',
      status: 'active',
      statusReason: null,
      roles: [{ key: 'read_only_user', name: 'Read-only User' }],
      mfaEnabled: false,
      emailVerified: true,
      lockedUntil: null,
      lastLoginAt: null,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
    });
    expect(toUserView(userRecord({ lockedUntil: later }), now).lockedUntil).toBe(
      later.toISOString(),
    );
  });
});

describe('planStatusChange', () => {
  it.each([
    ['active', null, 'disabled', { status: 'disabled', revokeSessions: true }],
    ['locked', null, 'disabled', { status: 'disabled', revokeSessions: true }],
    ['invited', null, 'disabled', { status: 'disabled', cancelInvitation: true }],
    ['disabled', null, 'active', { status: 'active', clearLockout: true }],
    ['locked', null, 'active', { status: 'active', clearLockout: true }],
    ['active', later, 'active', { status: 'active', clearLockout: true }],
  ] as const)('%s (locked until %s) → %s', (status, lockedUntil, target, expected) => {
    expect(planStatusChange({ status, lockedUntil, hasPassword: true }, target, now)).toMatchObject(
      expected,
    );
  });

  it.each([
    ['disabled', null, 'disabled', true],
    ['active', null, 'active', true],
    ['active', earlier, 'active', true],
    ['invited', null, 'active', false],
    ['disabled', null, 'active', false],
  ] as const)('%s (locked until %s) → %s is a conflict', (status, lockedUntil, target, pw) => {
    expect(() => planStatusChange({ status, lockedUntil, hasPassword: pw }, target, now)).toThrow(
      ConflictException,
    );
  });
});

describe('changedRoles', () => {
  it('returns added and removed roles only', () => {
    const changed = changedRoles(
      [{ key: 'read_only_user' }, { key: 'domain_admin' }],
      [ROLES.read_only_user, ROLES.organization_admin],
      [ROLES.read_only_user, ROLES.domain_admin],
    );
    expect(changed.map((r) => r.key).sort()).toEqual(['domain_admin', 'organization_admin']);
  });
});

describe('invitations', () => {
  const body = { email: 'new@example.test', displayName: 'New', roleKeys: ['read_only_user'] };

  it('creates the user in one transaction and emails after commit', async () => {
    const t = setup();
    await t.service.invite(admin, scope, body, client);
    expect(t.limits.lockOrganization).toHaveBeenCalledWith(expect.anything(), 7n);
    expect(t.limits.assertWithinLimit).toHaveBeenCalledWith(expect.anything(), 7n, 'max_users', 3);
    expect(t.users.replaceRoles).toHaveBeenCalledWith(expect.anything(), scope, 60n, [8n], 1n);
    expect(t.invitations.createToken).toHaveBeenCalledWith(expect.anything(), {
      userId: 60n,
      organizationId: 7n,
      createdByUserId: 1n,
    });
    expect(t.events).toEqual(['tx:begin', 'tx:commit', 'email:invitation']);
    expect(t.audit.record).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'user.invited', metadata: expect.anything() }),
      expect.anything(),
    );
  });

  it('refuses an existing email (409) but reinstates a deleted user', async () => {
    const t = setup();
    t.users.findAnyByEmail.mockResolvedValueOnce({ id: 61n, deletedAt: null } as never);
    await expect(t.service.invite(admin, scope, body, client)).rejects.toThrow(ConflictException);

    t.users.findAnyByEmail.mockResolvedValueOnce({ id: 61n, deletedAt: earlier } as never);
    await t.service.invite(admin, scope, body, client);
    expect(t.users.reinstateAsInvited).toHaveBeenCalled();
    expect(t.users.createInvited).not.toHaveBeenCalled();
    expect(t.cache.invalidateUser).toHaveBeenCalledWith(61n);
  });

  it('refuses roles the actor cannot grant and sends nothing', async () => {
    const t = setup();
    const domainAdmin = actor([...ROLES.domain_admin.permissions, 'user:manage']);
    await expect(
      t.service.invite(domainAdmin, scope, { ...body, roleKeys: ['organization_admin'] }, client),
    ).rejects.toThrow(ForbiddenException);
    expect(t.invitations.sendInvitation).not.toHaveBeenCalled();
  });

  it('records no granting user for API keys', async () => {
    const t = setup();
    const key: ApiKeyPrincipal = {
      kind: 'api_key',
      apiKeyId: 9n,
      apiKeyPublicId: 'k',
      organizationId: 7n,
      organizationPublicId: 'o',
      permissions: new Set(['user:manage', ...ROLES.read_only_user.permissions]),
    };
    await t.service.invite(key, scope, body, client);
    expect(t.users.replaceRoles).toHaveBeenCalledWith(expect.anything(), scope, 60n, [8n], null);
  });
});

describe('status, roles and deletion', () => {
  let t: ReturnType<typeof setup>;
  beforeEach(() => {
    t = setup();
  });

  it('disabling revokes sessions and invalidates the cache after commit', async () => {
    await t.service.changeStatus(
      admin,
      scope,
      TARGET_ID,
      { status: 'disabled', reason: 'x' },
      client,
    );
    expect(t.events).toEqual(['tx:begin', 'tx:commit', 'sessions:revoked', 'cache:user']);
    expect(t.users.setStatus).toHaveBeenCalledWith(expect.anything(), scope, 50n, {
      status: 'disabled',
      reason: 'x',
      now: expect.any(Date),
      clearLockout: false,
    });
  });

  it('unlocking clears the lockout counters', async () => {
    t.users.findByPublicId.mockResolvedValue(
      userRecord({ lockedUntil: new Date(Date.now() + 1e6) }),
    );
    await t.service.changeStatus(admin, scope, TARGET_ID, { status: 'active' }, client);
    expect(t.throttle.clearForUser).toHaveBeenCalledWith(50n);
    expect(t.sessions.revokeAllForUser).not.toHaveBeenCalled();
  });

  it('cancelling an invitation consumes its tokens', async () => {
    t.users.findByPublicId.mockResolvedValue(userRecord({ status: 'invited', hasPassword: false }));
    await t.service.changeStatus(
      admin,
      scope,
      TARGET_ID,
      { status: 'disabled', reason: 'x' },
      client,
    );
    expect(t.users.consumeTokens).toHaveBeenCalledWith(
      expect.anything(),
      scope,
      50n,
      ['invitation'],
      expect.any(Date),
    );
  });

  it('refuses self-suspension and self-deletion', async () => {
    const self = actor(TENANT_PERMISSIONS, 50n);
    await expect(
      t.service.changeStatus(self, scope, TARGET_ID, { status: 'disabled', reason: 'x' }, client),
    ).rejects.toThrow(/own account/);
    await expect(t.service.remove(self, scope, TARGET_ID, client)).rejects.toThrow(/own account/);
  });

  it('refuses changes that remove the last administrator and has no side effects', async () => {
    t.roles.countActiveAdministrators.mockResolvedValueOnce(1).mockResolvedValueOnce(0);
    await expect(
      t.service.changeStatus(admin, scope, TARGET_ID, { status: 'disabled', reason: 'x' }, client),
    ).rejects.toThrow(/at least one active administrator/);
    expect(t.sessions.revokeAllForUser).not.toHaveBeenCalled();

    t.roles.countActiveAdministrators.mockResolvedValueOnce(1).mockResolvedValueOnce(0);
    await expect(
      t.service.replaceRoles(admin, scope, TARGET_ID, ['read_only_user'], client),
    ).rejects.toThrow(ConflictException);

    t.roles.countActiveAdministrators.mockResolvedValueOnce(1).mockResolvedValueOnce(0);
    await expect(t.service.remove(admin, scope, TARGET_ID, client)).rejects.toThrow(
      ConflictException,
    );
  });

  it('applies the escalation rule to removed roles as well as added ones', async () => {
    t.users.findByPublicId.mockResolvedValue(
      userRecord({ roles: [{ id: 3n, key: 'organization_admin', name: 'Organization Admin' }] }),
    );
    const limited = actor([...ROLES.domain_admin.permissions, 'user:manage']);
    await expect(
      t.service.replaceRoles(limited, scope, TARGET_ID, ['read_only_user'], client),
    ).rejects.toThrow(ForbiddenException);
    expect(t.users.replaceRoles).not.toHaveBeenCalled();
  });

  it('answers 404 for users outside the scope', async () => {
    t.users.findByPublicId.mockResolvedValue(null);
    await expect(t.service.get(scope, TARGET_ID)).rejects.toThrow(NotFoundException);
    await expect(t.service.remove(admin, scope, TARGET_ID, client)).rejects.toThrow(
      NotFoundException,
    );
    await expect(t.service.listSessions(admin, scope, TARGET_ID)).rejects.toThrow(
      NotFoundException,
    );
  });

  it('soft-deletes, consumes tokens and revokes sessions after commit', async () => {
    await t.service.remove(admin, scope, TARGET_ID, client);
    expect(t.users.softDelete).toHaveBeenCalled();
    expect(t.events).toEqual(['tx:begin', 'tx:commit', 'sessions:revoked', 'cache:user']);
  });
});

describe('profile and MFA', () => {
  it('an email change sends a verification link after commit; a duplicate is 409', async () => {
    const t = setup();
    await t.service.updateProfile(admin, scope, TARGET_ID, { email: 'n@example.test' }, client);
    expect(t.emailVerification.issueAndSend).toHaveBeenCalledWith(50n);

    t.users.updateProfile.mockResolvedValueOnce('email_taken');
    await expect(
      t.service.updateProfile(admin, scope, TARGET_ID, { email: 'dup@example.test' }, client),
    ).rejects.toThrow(ConflictException);
  });

  it('an invited user gets a new invitation at the new address instead', async () => {
    const t = setup(userRecord({ status: 'invited', hasPassword: false, emailVerifiedAt: null }));
    await t.service.updateProfile(admin, scope, TARGET_ID, { email: 'n@example.test' }, client);
    expect(t.invitations.sendInvitation).toHaveBeenCalledWith(
      expect.objectContaining({ email: 'n@example.test', token: 'egt_x' }),
    );
    expect(t.emailVerification.issueAndSend).not.toHaveBeenCalled();
  });

  it('resets MFA of another user and revokes their sessions; not for oneself', async () => {
    const t = setup(userRecord({ mfaEnabled: true }));
    await t.service.resetMfa(admin, scope, TARGET_ID, client);
    expect(t.users.resetMfa).toHaveBeenCalledWith(expect.anything(), scope, 50n);
    expect(t.sessions.revokeAllForUser).toHaveBeenCalledWith(50n, 'mfa_reset');
    await expect(
      t.service.resetMfa(actor(TENANT_PERMISSIONS, 50n), scope, TARGET_ID, client),
    ).rejects.toThrow(ConflictException);
  });

  it('revoking an unknown session is 404', async () => {
    const t = setup();
    t.sessions.revokeSession.mockResolvedValueOnce(false);
    await expect(
      t.service.revokeSession(
        admin,
        scope,
        TARGET_ID,
        'e2a9d2b4-0000-4000-8000-000000000000',
        client,
      ),
    ).rejects.toThrow(NotFoundException);
  });
});

describe('target-side no escalation and the platform override (D8, D9)', () => {
  const adminTarget = () =>
    userRecord({ roles: [{ id: 3n, key: 'organization_admin', name: 'Organization Admin' }] });
  const userManager = actor(['user:read', 'user:manage']);

  it.each([
    [
      'email change',
      (t: ReturnType<typeof setup>) =>
        t.service.updateProfile(userManager, scope, TARGET_ID, { email: 'x@evil.test' }, client),
    ],
    [
      'display-name change',
      (t: ReturnType<typeof setup>) =>
        t.service.updateProfile(userManager, scope, TARGET_ID, { displayName: 'Renamed' }, client),
    ],
    [
      'disable',
      (t: ReturnType<typeof setup>) =>
        t.service.changeStatus(userManager, scope, TARGET_ID, { status: 'disabled' }, client),
    ],
    [
      'delete',
      (t: ReturnType<typeof setup>) => t.service.remove(userManager, scope, TARGET_ID, client),
    ],
    [
      'MFA reset',
      (t: ReturnType<typeof setup>) => t.service.resetMfa(userManager, scope, TARGET_ID, client),
    ],
    [
      'role change',
      (t: ReturnType<typeof setup>) =>
        t.service.replaceRoles(userManager, scope, TARGET_ID, ['organization_admin'], client),
    ],
    [
      'invitation resend',
      (t: ReturnType<typeof setup>) =>
        t.service.resendInvitation(userManager, scope, TARGET_ID, client),
    ],
    [
      'session revocation',
      (t: ReturnType<typeof setup>) =>
        t.service.revokeAllSessions(userManager, scope, TARGET_ID, client),
    ],
  ])('refuses a %s on a user with permissions the actor lacks (403)', async (_name, act) => {
    const t = setup(adminTarget());
    await expect(act(t)).rejects.toThrow(ForbiddenException);
    expect(t.users.updateProfile).not.toHaveBeenCalled();
    expect(t.users.setStatus).not.toHaveBeenCalled();
    expect(t.users.softDelete).not.toHaveBeenCalled();
    expect(t.users.resetMfa).not.toHaveBeenCalled();
    expect(t.users.replaceRoles).not.toHaveBeenCalled();
    expect(t.invitations.createToken).not.toHaveBeenCalled();
    expect(t.sessions.revokeAllForUser).not.toHaveBeenCalled();
  });

  it('allows managing a user whose permissions the actor holds', async () => {
    const t = setup();
    const manager = actor(['user:manage', ...ROLES.read_only_user.permissions]);
    await t.service.updateProfile(manager, scope, TARGET_ID, { displayName: 'Renamed' }, client);
    expect(t.users.updateProfile).toHaveBeenCalled();
  });

  it('refuses email changes by API keys, even for manageable users', async () => {
    const t = setup();
    const key: ApiKeyPrincipal = {
      kind: 'api_key',
      apiKeyId: 9n,
      apiKeyPublicId: 'k',
      organizationId: 7n,
      organizationPublicId: 'o',
      permissions: new Set(TENANT_PERMISSIONS),
    };
    await expect(
      t.service.updateProfile(key, scope, TARGET_ID, { email: 'x@evil.test' }, client),
    ).rejects.toThrow('Email changes require a user session');
    await t.service.updateProfile(key, scope, TARGET_ID, { displayName: 'Renamed' }, client);
    expect(t.users.updateProfile).toHaveBeenCalledTimes(1);
  });

  it('refuses actions that create standing access under a platform override', async () => {
    const t = setup();
    const operator: UserPrincipal = {
      ...actor(TENANT_PERMISSIONS, 99n),
      override: {
        id: 'ovr',
        reason: 'Support ticket 1234',
        targetOrganizationId: 7n,
        targetOrganizationPublicId: 'o',
        expiresAt: later,
      },
    };
    const body = { email: 'new@example.test', displayName: 'New', roleKeys: ['read_only_user'] };
    await expect(t.service.invite(operator, scope, body, client)).rejects.toThrow(
      ForbiddenException,
    );
    await expect(
      t.service.replaceRoles(operator, scope, TARGET_ID, ['read_only_user'], client),
    ).rejects.toThrow(ForbiddenException);
    await expect(t.service.resendInvitation(operator, scope, TARGET_ID, client)).rejects.toThrow(
      ForbiddenException,
    );
    await expect(
      t.service.updateProfile(operator, scope, TARGET_ID, { email: 'x@evil.test' }, client),
    ).rejects.toThrow(ForbiddenException);
    expect(t.users.createInvited).not.toHaveBeenCalled();
    expect(t.users.replaceRoles).not.toHaveBeenCalled();
    expect(t.users.updateProfile).not.toHaveBeenCalled();
    // Operational support stays possible: a display-name fix and a status change.
    await t.service.updateProfile(operator, scope, TARGET_ID, { displayName: 'Fixed' }, client);
    await t.service.changeStatus(operator, scope, TARGET_ID, { status: 'disabled' }, client);
    expect(t.users.setStatus).toHaveBeenCalled();
  });
});
