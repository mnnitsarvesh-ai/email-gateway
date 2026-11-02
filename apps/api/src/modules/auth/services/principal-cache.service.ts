import { randomUUID } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import type { OrganizationKind, OrganizationStatus, UserStatus } from '@email-gateway/database';
import { KeyValueStore } from '../../../kv/key-value-store';
import {
  ENTITY_CACHE_VERSION_TTL_SECONDS,
  kvKeys,
  PRINCIPAL_CACHE_TTL_SECONDS,
} from '../auth.constants';
import { UsersAuthRepository } from '../repositories/users-auth.repository';

/**
 * What authorization needs about a user, cached for 60 s (D9). Valid only while its
 * `orgVersion` equals the organization's current version (one INCR invalidates every cached
 * principal of an organization) and its `userVersion` equals the user's current version nonce.
 * Both are read before the database when the entry is filled, so an invalidation that races a
 * fill always leaves the filled entry stale. Ids are decimal strings (JSON has no bigint).
 */
export interface PrincipalSnapshot {
  orgVersion: number;
  /** The user's version nonce when the entry was filled ('' = never invalidated). */
  userVersion: string;
  user: {
    id: string;
    publicId: string;
    status: UserStatus;
    deleted: boolean;
    mfaEnabled: boolean;
  };
  org: {
    id: string;
    publicId: string;
    kind: OrganizationKind;
    status: OrganizationStatus;
    deleted: boolean;
    mfaRequired: boolean;
  };
  permissions: string[];
}

function isSnapshot(value: unknown): value is PrincipalSnapshot {
  const v = value as PrincipalSnapshot | null;
  return (
    typeof v === 'object' &&
    v !== null &&
    typeof v.orgVersion === 'number' &&
    typeof v.userVersion === 'string' &&
    typeof v.user?.id === 'string' &&
    typeof v.user.publicId === 'string' &&
    typeof v.org?.id === 'string' &&
    typeof v.org.publicId === 'string' &&
    Array.isArray(v.permissions)
  );
}

/**
 * Principal snapshot cache (D9). Writers that change a user's status, roles or MFA state call
 * `invalidateUser`; organization status changes and custom-role permission edits call
 * `invalidateOrganization`; API-key revocation calls `invalidateApiKey`. Always after commit.
 *
 * Invalidation never just deletes: it moves a version (organization: INCR; user and API key: a
 * fresh random nonce, kept longer than any entry) that cache readers compare, and cache fillers
 * read those versions **before** the database. A fill that read the database before a commit
 * therefore carries an older version and is never served, however the requests interleave.
 * Errors propagate: authentication fails closed and invalidation failures surface to the caller.
 */
@Injectable()
export class PrincipalCacheService {
  private readonly logger = new Logger(PrincipalCacheService.name);

  constructor(
    private readonly kv: KeyValueStore,
    private readonly users: UsersAuthRepository,
  ) {}

  /** Current version of the organization's cached authorization data (missing = 0). */
  async organizationVersion(organizationId: bigint): Promise<number> {
    const value = await this.kv.get(kvKeys.orgVersion(organizationId));
    return value === null ? 0 : Number(value);
  }

  /** Current version nonce of the user's cached snapshot ('' when never invalidated). */
  async userVersion(userPublicId: string): Promise<string> {
    return (await this.kv.get(kvKeys.userVersion(userPublicId))) ?? '';
  }

  /** Current version nonce of the API key's cached record ('' when never invalidated). */
  async apiKeyVersion(prefix: string): Promise<string> {
    return (await this.kv.get(kvKeys.apiKeyVersion(prefix))) ?? '';
  }

  /** The cached snapshot if present and still current, else null. */
  async get(userPublicId: string): Promise<PrincipalSnapshot | null> {
    const raw = await this.kv.get(kvKeys.principal(userPublicId));
    if (raw === null) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = null;
    }
    if (!isSnapshot(parsed) || parsed.user.publicId !== userPublicId) {
      await this.kv.del(kvKeys.principal(userPublicId));
      return null;
    }
    const orgVersion = await this.organizationVersion(BigInt(parsed.org.id));
    if (parsed.orgVersion !== orgVersion) return null;
    return parsed.userVersion === (await this.userVersion(userPublicId)) ? parsed : null;
  }

  async put(snapshot: PrincipalSnapshot): Promise<void> {
    await this.kv.set(
      kvKeys.principal(snapshot.user.publicId),
      JSON.stringify(snapshot),
      PRINCIPAL_CACHE_TTL_SECONDS,
    );
  }

  /** Drops the user's snapshot (status, roles, MFA or password changes). */
  async invalidateUser(userId: bigint): Promise<void> {
    const publicId = await this.users.findPublicId(userId);
    if (publicId) await this.invalidateUserByPublicId(publicId);
  }

  async invalidateUserByPublicId(userPublicId: string): Promise<void> {
    await this.kv.set(
      kvKeys.userVersion(userPublicId),
      randomUUID(),
      ENTITY_CACHE_VERSION_TTL_SECONDS,
    );
    await this.kv.del(kvKeys.principal(userPublicId));
  }

  /**
   * Invalidates every cached principal and API key of the organization (status changes,
   * custom-role permission edits).
   */
  async invalidateOrganization(organizationId: bigint): Promise<void> {
    const version = await this.kv.incr(kvKeys.orgVersion(organizationId));
    this.logger.debug({ message: 'Organization auth cache invalidated', version });
  }

  /** Revocation (or organization deletion): the key's cached record stops being served. */
  async invalidateApiKey(prefix: string): Promise<void> {
    await this.kv.set(kvKeys.apiKeyVersion(prefix), randomUUID(), ENTITY_CACHE_VERSION_TTL_SECONDS);
    await this.kv.del(kvKeys.apiKey(prefix));
  }
}
