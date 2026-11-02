import { Injectable } from '@nestjs/common';
import { PLATFORM_ORGANIZATION_SLUG } from '@email-gateway/database';
import { AuditService, SYSTEM_ACTOR } from '../../../audit/audit.service';
import { TransactionRunner } from '../../../database/transaction-runner';
import { BootstrapRepository } from '../repositories/bootstrap.repository';
import { OrganizationsAuthRepository } from '../repositories/organizations-auth.repository';
import { InvitationService } from './invitation.service';
import { PrincipalCacheService } from './principal-cache.service';

export const BOOTSTRAP_ROLE_KEY = 'super_admin';

/** A refusal with an operator-facing message (never contains secrets). */
export class BootstrapRefusedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BootstrapRefusedError';
  }
}

export interface BootstrapResult {
  userPublicId: string;
  /** Acceptance link with the invitation token in its fragment: printed to stdout only. */
  link: string;
  expiresAt: Date;
  reused: boolean;
}

/**
 * Initial access (D10): invites a super admin of the platform organization and returns the
 * acceptance link. Refuses when an active super admin exists unless `additional` is set.
 */
@Injectable()
export class BootstrapAdminService {
  constructor(
    private readonly organizations: OrganizationsAuthRepository,
    private readonly repository: BootstrapRepository,
    private readonly transactions: TransactionRunner,
    private readonly invitations: InvitationService,
    private readonly audit: AuditService,
    private readonly principalCache: PrincipalCacheService,
  ) {}

  async invite(input: {
    email: string;
    displayName: string;
    additional: boolean;
  }): Promise<BootstrapResult> {
    const platform = await this.organizations.findBySlug(PLATFORM_ORGANIZATION_SLUG);
    if (!platform || platform.kind !== 'platform' || platform.deletedAt !== null) {
      throw new BootstrapRefusedError(
        'The platform organization does not exist: run `pnpm db:seed` first',
      );
    }
    const roleId = await this.repository.findSystemRoleId(BOOTSTRAP_ROLE_KEY);
    if (roleId === null) {
      throw new BootstrapRefusedError(
        'The super_admin role does not exist: run `pnpm db:seed` first',
      );
    }
    if (!input.additional && (await this.repository.countActiveWithRole(platform.id, roleId)) > 0) {
      throw new BootstrapRefusedError(
        'An active super admin already exists. Invite further administrators through the API, ' +
          'or pass --additional to issue another bootstrap invitation.',
      );
    }

    const now = new Date();
    const result = await this.transactions.run(async (tx) => {
      const existing = await this.repository.findUser(tx, platform.id, input.email);
      if (existing && existing.deletedAt === null && existing.status !== 'invited') {
        throw new BootstrapRefusedError(
          `A ${existing.status} platform user with this email already exists; nothing to bootstrap`,
        );
      }
      const user =
        existing ??
        (await this.repository.createInvitedUser(tx, {
          organizationId: platform.id,
          email: input.email,
          displayName: input.displayName,
          now,
        }));
      if (existing) {
        await this.repository.resetToInvited(tx, existing.id, {
          displayName: input.displayName,
          now,
        });
      }
      await this.repository.ensureRole(tx, {
        userId: user.id,
        roleId,
        organizationId: platform.id,
      });
      const token = await this.invitations.createToken(tx, {
        userId: user.id,
        organizationId: platform.id,
        createdByUserId: null,
      });
      await this.audit.record(
        {
          organizationId: platform.id,
          actor: SYSTEM_ACTOR,
          action: 'user.bootstrap_invited',
          resourceType: 'user',
          resourceId: user.publicId,
          metadata: {
            roleKey: BOOTSTRAP_ROLE_KEY,
            reused: existing !== null,
            additional: input.additional,
          },
        },
        tx,
      );
      return { user, token, reused: existing !== null };
    });
    await this.principalCache.invalidateUserByPublicId(result.user.publicId);
    return {
      userPublicId: result.user.publicId,
      link: this.invitations.link(result.token.token),
      expiresAt: result.token.expiresAt,
      reused: result.reused,
    };
  }
}
