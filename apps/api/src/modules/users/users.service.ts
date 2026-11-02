import {
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import type { Prisma, UserStatus } from '@email-gateway/database';
import { AuditService } from '../../audit/audit.service';
import type { Principal, UserPrincipal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { TransactionRunner } from '../../database/transaction-runner';
import { type Page, type PageQuery, pageWindow, toPage } from '../../http/pagination';
import { OrganizationLimitsService } from '../../tenancy/organization-limits.service';
import { RevokeReason } from '../auth/auth.constants';
import { EmailVerificationService } from '../auth/services/email-verification.service';
import { InvitationService } from '../auth/services/invitation.service';
import { LoginThrottleService } from '../auth/services/login-throttle.service';
import { PrincipalCacheService } from '../auth/services/principal-cache.service';
import {
  type ClientContext,
  SessionService,
  type SessionView,
  toSessionView,
} from '../auth/services/session.service';
import type { IssuedUserToken } from '../auth/services/user-token.service';
import {
  assertCanManageUser,
  assertNoEscalation,
  violatesLastAdministrator,
} from '../roles/role-rules';
import type { RoleRecord } from '../roles/roles.repository';
import { RolesService } from '../roles/roles.service';
import { type UserListFilter, type UserRecord, UsersRepository } from './users.repository';
import type {
  InviteUserRequest,
  UpdateUserRequest,
  UserStatusRequest,
  UserView,
} from './users.schemas';

export const LAST_ADMIN_MESSAGE = 'The organization must keep at least one active administrator';

export function toUserView(user: UserRecord, now: Date = new Date()): UserView {
  return {
    id: user.publicId,
    email: user.email,
    displayName: user.displayName,
    status: user.status,
    statusReason: user.statusReason,
    roles: user.roles.map((r) => ({ key: r.key, name: r.name })),
    mfaEnabled: user.mfaEnabled,
    emailVerified: user.emailVerifiedAt !== null,
    lockedUntil: user.lockedUntil && user.lockedUntil > now ? user.lockedUntil.toISOString() : null,
    lastLoginAt: user.lastLoginAt?.toISOString() ?? null,
    createdAt: user.createdAt.toISOString(),
    updatedAt: user.updatedAt.toISOString(),
  };
}

export interface StatusChangePlan {
  status: UserStatus;
  /** Clears `locked_until`, `failed_login_count` and the throttle counters. */
  clearLockout: boolean;
  /** Invited → disabled cancels the outstanding invitation. */
  cancelInvitation: boolean;
  revokeSessions: boolean;
}

/**
 * The allowed status transitions (D11): active/locked → disabled, invited → disabled (cancels
 * the invitation), disabled → active (only for users who completed their invitation), and
 * unlock: a locked account (`status = locked` or `locked_until > now`) → active. Anything else
 * is a `409`.
 */
export function planStatusChange(
  user: Pick<UserRecord, 'status' | 'hasPassword' | 'lockedUntil'>,
  target: 'active' | 'disabled',
  now: Date,
): StatusChangePlan {
  const lockedOut = user.lockedUntil !== null && user.lockedUntil > now;
  if (target === 'disabled') {
    if (user.status === 'disabled') throw new ConflictException('User is already disabled');
    return {
      status: 'disabled',
      clearLockout: false,
      cancelInvitation: user.status === 'invited',
      revokeSessions: true,
    };
  }
  switch (user.status) {
    case 'invited':
      throw new ConflictException('User has not accepted the invitation yet');
    case 'disabled':
      if (!user.hasPassword) {
        throw new ConflictException(
          'User never completed the invitation; delete and invite them again',
        );
      }
      break;
    case 'active':
      if (!lockedOut) throw new ConflictException('User is already active');
      break;
    case 'locked':
      break;
  }
  return { status: 'active', clearLockout: true, cancelInvitation: false, revokeSessions: false };
}

/** Roles whose assignment changes: added and removed (the escalation rule applies to both). */
export function changedRoles(
  current: readonly { key: string }[],
  next: readonly RoleRecord[],
  currentRecords: readonly RoleRecord[],
): RoleRecord[] {
  const currentKeys = new Set(current.map((r) => r.key));
  const nextKeys = new Set(next.map((r) => r.key));
  return [
    ...next.filter((r) => !currentKeys.has(r.key)),
    ...currentRecords.filter((r) => !nextKeys.has(r.key)),
  ];
}

const isSelf = (principal: Principal, user: UserRecord): boolean =>
  principal.kind === 'user' && principal.userId === user.id;

const actorUserId = (principal: Principal): bigint | null =>
  principal.kind === 'user' ? principal.userId : null;

/**
 * Actions that create standing access to the organization (D9): refused under a platform
 * override, because the access would outlive the time-boxed override (like API keys).
 */
export function assertNotUnderOverride(principal: Principal, action: string): void {
  if (principal.kind === 'user' && principal.override) {
    throw new ForbiddenException(`${action} is not allowed under a platform override`);
  }
}

type AfterCommit = () => Promise<unknown>;

/**
 * Identity administration (D11, §4.2): invitations, profile, status, roles, deletion, MFA reset
 * and sessions of the users of the scope organization. Changes run in one writer transaction
 * with the organization row locked (limits and the last-administrator rule are exact); emails,
 * session revocation and cache invalidation happen after commit.
 */
@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(
    private readonly users: UsersRepository,
    private readonly roles: RolesService,
    private readonly transactions: TransactionRunner,
    private readonly limits: OrganizationLimitsService,
    private readonly audit: AuditService,
    private readonly invitations: InvitationService,
    private readonly emailVerification: EmailVerificationService,
    private readonly sessions: SessionService,
    private readonly principalCache: PrincipalCacheService,
    private readonly throttle: LoginThrottleService,
  ) {}

  async list(
    scope: TenantScope,
    query: PageQuery & UserListFilter,
    now: Date = new Date(),
  ): Promise<Page<UserView>> {
    const rows = await this.users.list(
      scope,
      {
        ...(query.status && { status: query.status }),
        ...(query.q && { q: query.q }),
        ...(query.role && { role: query.role }),
      },
      pageWindow(query),
    );
    return toPage(rows, query.limit, (row) => toUserView(row, now));
  }

  async get(scope: TenantScope, publicId: string): Promise<UserView> {
    return toUserView(await this.require(scope, publicId));
  }

  /** `POST /users/invitations` (D11). */
  async invite(
    principal: Principal,
    scope: TenantScope,
    body: InviteUserRequest,
    client: ClientContext,
  ): Promise<UserView> {
    assertNotUnderOverride(principal, 'Inviting users');
    const now = new Date();
    const result = await this.transactions.run(async (tx) => {
      await this.limits.lockOrganization(tx, scope.organizationId);
      const existing = await this.users.findAnyByEmail(tx, scope, body.email);
      if (existing && existing.deletedAt === null) {
        throw new ConflictException('A user with this email already exists');
      }
      const roles = await this.roles.resolveForAssignment(tx, scope, body.roleKeys);
      assertNoEscalation(principal.permissions, roles);
      const count = await this.users.countNonDeleted(tx, scope);
      await this.limits.assertWithinLimit(tx, scope.organizationId, 'max_users', count);

      const user = existing
        ? await this.users.reinstateAsInvited(tx, scope, existing.id, {
            displayName: body.displayName,
            now,
          })
        : await this.users.createInvited(tx, scope, {
            email: body.email,
            displayName: body.displayName,
            now,
          });
      if (existing) {
        await this.users.consumeTokens(
          tx,
          scope,
          user.id,
          ['invitation', 'password_reset', 'email_verification'],
          now,
        );
      }
      await this.users.replaceRoles(
        tx,
        scope,
        user.id,
        roles.map((r) => r.id),
        actorUserId(principal),
      );
      const token = await this.invitations.createToken(tx, {
        userId: user.id,
        organizationId: scope.organizationId,
        createdByUserId: actorUserId(principal),
      });
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: 'user.invited',
          resourceType: 'user',
          resourceId: user.publicId,
          sourceIp: client.ip,
          metadata: { roles: roles.map((r) => r.key).sort(), reinstated: existing !== null },
        },
        tx,
      );
      return { user, token, reinstated: existing !== null };
    });

    if (result.reinstated) await this.principalCache.invalidateUser(result.user.id);
    await this.sendInvitation(scope, body.email, body.displayName, result.token);
    return toUserView(await this.require(scope, result.user.publicId));
  }

  /** `POST /users/{id}/invitation`: a new link for an invited user (earlier links stop working). */
  async resendInvitation(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    client: ClientContext,
  ): Promise<{ expiresAt: string }> {
    assertNotUnderOverride(principal, 'Resending invitations');
    const { user, token } = await this.transactions.run(async (tx) => {
      const user = await this.requireIn(tx, scope, publicId);
      await this.assertCanManage(tx, principal, scope, user);
      if (user.status !== 'invited') {
        throw new ConflictException('Only invited users can receive an invitation');
      }
      const token = await this.invitations.createToken(tx, {
        userId: user.id,
        organizationId: scope.organizationId,
        createdByUserId: actorUserId(principal),
      });
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: 'user.invitation_resent',
          resourceType: 'user',
          resourceId: user.publicId,
          sourceIp: client.ip,
        },
        tx,
      );
      return { user, token };
    });
    await this.sendInvitation(scope, user.email, user.displayName, token);
    return { expiresAt: token.expiresAt.toISOString() };
  }

  /**
   * `PATCH /users/{id}`. An email change clears the verification and sends a verification
   * link to the new address; for an invited user it replaces the invitation instead (the old
   * link was sent to the old address).
   */
  async updateProfile(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    body: UpdateUserRequest,
    client: ClientContext,
  ): Promise<UserView> {
    const now = new Date();
    const outcome = await this.transactions.run(async (tx) => {
      const user = await this.requireIn(tx, scope, publicId);
      const emailChanged = body.email !== undefined && body.email !== user.email;
      const nameChanged = body.displayName !== undefined && body.displayName !== user.displayName;
      if (!emailChanged && !nameChanged) return { user, emailChanged, invitation: null };
      await this.assertCanManage(tx, principal, scope, user);
      if (emailChanged) {
        // The email is the account-recovery channel: only a person may move it, never a key,
        // and never under a platform override (it would hand out standing access, D9).
        if (principal.kind !== 'user') {
          throw new ForbiddenException('Email changes require a user session');
        }
        assertNotUnderOverride(principal, 'Changing a user email');
      }
      const result = await this.users.updateProfile(tx, scope, user.id, {
        ...(nameChanged && { displayName: body.displayName }),
        ...(emailChanged && { email: body.email }),
      });
      if (result === 'not_found') throw new NotFoundException('User not found');
      if (result === 'email_taken') {
        throw new ConflictException('A user with this email already exists');
      }
      let invitation: IssuedUserToken | null = null;
      if (emailChanged) {
        await this.users.consumeTokens(
          tx,
          scope,
          user.id,
          ['email_verification', 'password_reset'],
          now,
        );
        if (user.status === 'invited') {
          invitation = await this.invitations.createToken(tx, {
            userId: user.id,
            organizationId: scope.organizationId,
            createdByUserId: actorUserId(principal),
          });
        }
      }
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: 'user.updated',
          resourceType: 'user',
          resourceId: user.publicId,
          sourceIp: client.ip,
          metadata: {
            fields: [...(nameChanged ? ['displayName'] : []), ...(emailChanged ? ['email'] : [])],
          },
        },
        tx,
      );
      return { user, emailChanged, invitation };
    });

    if (outcome.emailChanged && body.email !== undefined) {
      if (outcome.invitation) {
        await this.sendInvitation(
          scope,
          body.email,
          body.displayName ?? outcome.user.displayName,
          outcome.invitation,
        );
      } else {
        await this.emailVerification.issueAndSend(outcome.user.id);
      }
    }
    return toUserView(await this.require(scope, publicId));
  }

  /** `PATCH /users/{id}/status` (D11). */
  async changeStatus(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    body: UserStatusRequest,
    client: ClientContext,
  ): Promise<UserView> {
    const now = new Date();
    const { user, plan } = await this.withAdministratorGuard(scope, async (tx) => {
      const user = await this.requireIn(tx, scope, publicId);
      await this.assertCanManage(tx, principal, scope, user);
      const plan = planStatusChange(user, body.status, now);
      if (plan.status === 'disabled' && isSelf(principal, user)) {
        throw new ConflictException('You cannot disable your own account');
      }
      await this.users.setStatus(tx, scope, user.id, {
        status: plan.status,
        reason: body.reason ?? null,
        now,
        clearLockout: plan.clearLockout,
      });
      if (plan.cancelInvitation) {
        await this.users.consumeTokens(tx, scope, user.id, ['invitation'], now);
      }
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: 'user.status_changed',
          resourceType: 'user',
          resourceId: user.publicId,
          sourceIp: client.ip,
          metadata: {
            from: user.status,
            to: plan.status,
            reason: body.reason ?? null,
            unlocked: plan.clearLockout,
            invitationCancelled: plan.cancelInvitation,
          },
        },
        tx,
      );
      return { user, plan };
    });

    await this.afterCommit([
      ...(plan.revokeSessions
        ? [() => this.sessions.revokeAllForUser(user.id, RevokeReason.userDisabled)]
        : []),
      ...(plan.clearLockout ? [() => this.throttle.clearForUser(user.id)] : []),
      () => this.principalCache.invalidateUser(user.id),
    ]);
    return toUserView(await this.require(scope, publicId));
  }

  /** `PUT /users/{id}/roles`: replaces the role set (escalation, platform, last-admin rules). */
  async replaceRoles(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    roleKeys: readonly string[],
    client: ClientContext,
  ): Promise<UserView> {
    assertNotUnderOverride(principal, 'Changing user roles');
    const user = await this.withAdministratorGuard(scope, async (tx) => {
      const user = await this.requireIn(tx, scope, publicId);
      const next = await this.roles.resolveForAssignment(tx, scope, roleKeys);
      const current = await this.roles.findByKeys(
        tx,
        scope,
        user.roles.map((r) => r.key),
      );
      assertCanManageUser(principal.permissions, current);
      assertNoEscalation(principal.permissions, changedRoles(user.roles, next, current));
      await this.users.replaceRoles(
        tx,
        scope,
        user.id,
        next.map((r) => r.id),
        actorUserId(principal),
      );
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: 'user.roles_changed',
          resourceType: 'user',
          resourceId: user.publicId,
          sourceIp: client.ip,
          metadata: {
            from: user.roles.map((r) => r.key).sort(),
            to: next.map((r) => r.key).sort(),
          },
        },
        tx,
      );
      return user;
    });
    await this.afterCommit([() => this.principalCache.invalidateUser(user.id)]);
    return toUserView(await this.require(scope, publicId));
  }

  /** `DELETE /users/{id}`: soft delete, outstanding tokens consumed, sessions revoked. */
  async remove(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    client: ClientContext,
  ): Promise<void> {
    const now = new Date();
    const user = await this.withAdministratorGuard(scope, async (tx) => {
      const user = await this.requireIn(tx, scope, publicId);
      if (isSelf(principal, user))
        throw new ConflictException('You cannot delete your own account');
      await this.assertCanManage(tx, principal, scope, user);
      if (!(await this.users.softDelete(tx, scope, user.id, now))) {
        throw new NotFoundException('User not found');
      }
      await this.users.consumeTokens(
        tx,
        scope,
        user.id,
        ['invitation', 'password_reset', 'email_verification'],
        now,
      );
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: 'user.deleted',
          resourceType: 'user',
          resourceId: user.publicId,
          sourceIp: client.ip,
          metadata: { status: user.status, roles: user.roles.map((r) => r.key).sort() },
        },
        tx,
      );
      return user;
    });
    await this.afterCommit([
      () => this.sessions.revokeAllForUser(user.id, RevokeReason.userDeleted),
      () => this.principalCache.invalidateUser(user.id),
    ]);
  }

  /** `POST /users/{id}/mfa/reset` (D7): clears MFA and recovery codes, revokes sessions. */
  async resetMfa(
    principal: UserPrincipal,
    scope: TenantScope,
    publicId: string,
    client: ClientContext,
  ): Promise<void> {
    const user = await this.transactions.run(async (tx) => {
      const user = await this.requireIn(tx, scope, publicId);
      if (isSelf(principal, user)) {
        throw new ConflictException('Use the MFA self-service endpoints for your own account');
      }
      await this.assertCanManage(tx, principal, scope, user);
      await this.users.resetMfa(tx, scope, user.id);
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: 'user.mfa_reset',
          resourceType: 'user',
          resourceId: user.publicId,
          sourceIp: client.ip,
          metadata: { mfaWasEnabled: user.mfaEnabled },
        },
        tx,
      );
      return user;
    });
    await this.afterCommit([
      () => this.sessions.revokeAllForUser(user.id, RevokeReason.mfaReset),
      () => this.principalCache.invalidateUser(user.id),
    ]);
  }

  /** `GET /users/{id}/sessions`: live sessions (replica; may lag briefly). */
  async listSessions(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
  ): Promise<SessionView[]> {
    const user = await this.require(scope, publicId);
    const rows = await this.sessions.listLiveForUser(scope, user.id);
    const current = principal.kind === 'user' ? principal.sessionId : undefined;
    return rows.map((row) => toSessionView(row, current));
  }

  /** `DELETE /users/{id}/sessions`. */
  async revokeAllSessions(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    client: ClientContext,
  ): Promise<void> {
    const user = await this.requireManageable(principal, scope, publicId);
    const count = await this.sessions.revokeAllForUser(user.id, RevokeReason.adminRevoked);
    await this.audit.record({
      organizationId: scope.organizationId,
      actor: this.audit.actorFrom(principal),
      action: 'session.revoked_all',
      resourceType: 'user',
      resourceId: user.publicId,
      sourceIp: client.ip,
      metadata: { reason: RevokeReason.adminRevoked, sessions: count },
    });
  }

  /** `DELETE /users/{id}/sessions/{sessionId}`: `404` unless it is a live session of the user. */
  async revokeSession(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    sessionId: string,
    client: ClientContext,
  ): Promise<void> {
    const user = await this.requireManageable(principal, scope, publicId);
    if (!(await this.sessions.revokeSession(user.id, sessionId, RevokeReason.adminRevoked))) {
      throw new NotFoundException('Session not found');
    }
    await this.audit.record({
      organizationId: scope.organizationId,
      actor: this.audit.actorFrom(principal),
      action: 'session.revoked',
      resourceType: 'session',
      resourceId: sessionId,
      sourceIp: client.ip,
      metadata: { reason: RevokeReason.adminRevoked, sessionId, userId: user.publicId },
    });
  }

  /**
   * Runs a change with the organization row locked and refuses it (`409`) when it would leave
   * an organization that had an active administrator without one (D8).
   */
  private async withAdministratorGuard<T>(
    scope: TenantScope,
    change: (tx: Prisma.TransactionClient) => Promise<T>,
  ): Promise<T> {
    return this.transactions.run(async (tx) => {
      await this.limits.lockOrganization(tx, scope.organizationId);
      const before = await this.roles.countActiveAdministrators(tx, scope);
      const result = await change(tx);
      const after = await this.roles.countActiveAdministrators(tx, scope);
      if (violatesLastAdministrator(before, after)) throw new ConflictException(LAST_ADMIN_MESSAGE);
      return result;
    });
  }

  /** Post-commit effects: each runs even if an earlier one fails; the first error is rethrown. */
  private async afterCommit(effects: AfterCommit[]): Promise<void> {
    let failure: Error | undefined;
    for (const effect of effects) {
      try {
        await effect();
      } catch (err) {
        this.logger.error({ message: 'Post-commit effect failed', err });
        failure ??= err instanceof Error ? err : new Error('Post-commit effect failed');
      }
    }
    if (failure !== undefined) throw failure;
  }

  private async sendInvitation(
    scope: TenantScope,
    email: string,
    displayName: string,
    token: IssuedUserToken,
  ): Promise<void> {
    await this.invitations.sendInvitation({
      email,
      displayName,
      organizationName: await this.users.organizationName(scope),
      token: token.token,
      expiresAt: token.expiresAt,
    });
  }

  /** Target-side no escalation (D8): `403` unless the principal holds all the user's roles. */
  private async assertCanManage(
    tx: Prisma.TransactionClient,
    principal: Principal,
    scope: TenantScope,
    user: UserRecord,
  ): Promise<void> {
    if (isSelf(principal, user)) return;
    const roles = await this.roles.findByKeys(
      tx,
      scope,
      user.roles.map((r) => r.key),
    );
    assertCanManageUser(principal.permissions, roles);
  }

  /** The user (from the writer) after the target-side escalation check. */
  private async requireManageable(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
  ): Promise<UserRecord> {
    return this.transactions.run(async (tx) => {
      const user = await this.requireIn(tx, scope, publicId);
      await this.assertCanManage(tx, principal, scope, user);
      return user;
    });
  }

  private async require(scope: TenantScope, publicId: string): Promise<UserRecord> {
    const user = await this.users.findByPublicId(scope, publicId);
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  private async requireIn(
    tx: Prisma.TransactionClient,
    scope: TenantScope,
    publicId: string,
  ): Promise<UserRecord> {
    const user = await this.users.findByPublicId(scope, publicId, tx);
    if (!user) throw new NotFoundException('User not found');
    return user;
  }
}
