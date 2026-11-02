import { Injectable } from '@nestjs/common';
import { TENANT_PERMISSIONS } from '@email-gateway/database';
import { UsersAuthRepository } from '../repositories/users-auth.repository';
import { PrincipalCacheService, type PrincipalSnapshot } from './principal-cache.service';

const TENANT = new Set<string>(TENANT_PERMISSIONS);

/**
 * Loads the principal snapshot of a user: from the cache when current, otherwise from the writer
 * (D9). On a miss the organization and user versions are read **before** the snapshot is read
 * from the database (the user's organization never changes, so a light lookup finds it first):
 * an invalidation committed after the database read moves a version, so a snapshot filled from
 * older data is never served.
 */
@Injectable()
export class PrincipalLoaderService {
  constructor(
    private readonly cache: PrincipalCacheService,
    private readonly users: UsersAuthRepository,
  ) {}

  async load(userPublicId: string): Promise<PrincipalSnapshot | null> {
    const cached = await this.cache.get(userPublicId);
    if (cached) return cached;

    const organizationId = await this.users.findOrganizationIdByPublicId(userPublicId);
    if (organizationId === null) return null;
    const orgVersion = await this.cache.organizationVersion(organizationId);
    const userVersion = await this.cache.userVersion(userPublicId);
    const source = await this.users.loadPrincipalSource(userPublicId);
    if (!source) return null;
    const { user, permissions } = source;
    const snapshot: PrincipalSnapshot = {
      orgVersion,
      userVersion,
      user: {
        id: user.id.toString(),
        publicId: user.publicId,
        status: user.status,
        deleted: user.deletedAt !== null,
        mfaEnabled: user.mfaEnabled,
      },
      org: {
        id: user.organization.id.toString(),
        publicId: user.organization.publicId,
        kind: user.organization.kind,
        status: user.organization.status,
        deleted: user.organization.deletedAt !== null,
        mfaRequired: user.organization.mfaRequired,
      },
      // Defence in depth: platform permissions only ever count inside the platform organization.
      permissions:
        user.organization.kind === 'platform'
          ? permissions
          : permissions.filter((key) => TENANT.has(key)),
    };
    // Users never change organization; if the rows disagree, serve this request uncached.
    if (user.organizationId === organizationId) await this.cache.put(snapshot);
    return snapshot;
  }
}
