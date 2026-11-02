import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryKeyValueStore } from '../../../../test/support/in-memory-key-value-store';
import type {
  AuthUserRecord,
  PrincipalSource,
  UsersAuthRepository,
} from '../repositories/users-auth.repository';
import { PrincipalCacheService } from './principal-cache.service';
import { PrincipalLoaderService } from './principal-loader.service';

function source(kind: 'customer' | 'platform', permissions: string[]): PrincipalSource {
  const user: AuthUserRecord = {
    id: 10n,
    publicId: randomUUID(),
    organizationId: 2n,
    email: 'a@example.test',
    displayName: 'A',
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
      kind,
      status: 'active',
      deletedAt: null,
      mfaRequired: true,
    },
  };
  return { user, permissions };
}

describe('PrincipalLoaderService and PrincipalCacheService', () => {
  let kv: InMemoryKeyValueStore;
  let current: PrincipalSource;
  let users: {
    loadPrincipalSource: ReturnType<typeof vi.fn>;
    findPublicId: ReturnType<typeof vi.fn>;
    findOrganizationIdByPublicId: ReturnType<typeof vi.fn>;
  };
  let cache: PrincipalCacheService;
  let loader: PrincipalLoaderService;

  beforeEach(() => {
    vi.useFakeTimers();
    kv = new InMemoryKeyValueStore();
    current = source('customer', ['user:read']);
    users = {
      loadPrincipalSource: vi.fn(() => Promise.resolve(current)),
      findPublicId: vi.fn(() => Promise.resolve(current.user.publicId)),
      findOrganizationIdByPublicId: vi.fn(() => Promise.resolve(current.user.organizationId)),
    };
    cache = new PrincipalCacheService(kv, users as unknown as UsersAuthRepository);
    loader = new PrincipalLoaderService(cache, users as unknown as UsersAuthRepository);
  });
  afterEach(() => vi.useRealTimers());

  const publicId = () => current.user.publicId;

  it('loads from the database once and serves the cache for 60 s', async () => {
    const first = await loader.load(publicId());
    expect(first).toMatchObject({
      orgVersion: 0,
      userVersion: '',
      user: { id: '10', status: 'active', mfaEnabled: false },
      org: { id: '2', kind: 'customer', mfaRequired: true },
      permissions: ['user:read'],
    });
    await loader.load(publicId());
    expect(users.loadPrincipalSource).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(61_000);
    await loader.load(publicId());
    expect(users.loadPrincipalSource).toHaveBeenCalledTimes(2);
  });

  it('invalidateUser drops the snapshot', async () => {
    await loader.load(publicId());
    current = { ...current, permissions: ['user:read', 'user:manage'] };
    await cache.invalidateUser(10n);
    expect((await loader.load(publicId()))?.permissions).toEqual(['user:read', 'user:manage']);
  });

  it('invalidateOrganization bumps the version, invalidating every snapshot of the org', async () => {
    await loader.load(publicId());
    await cache.invalidateOrganization(2n);
    expect(await cache.get(publicId())).toBeNull();
    const reloaded = await loader.load(publicId());
    expect(reloaded?.orgVersion).toBe(1);
    expect(await cache.get(publicId())).not.toBeNull();
  });

  /**
   * The database read returns the old row, then the writer commits and invalidates before the
   * filler writes the cache: the filled entry carries the older version and is never served.
   */
  function invalidateDuringRead(invalidate: () => Promise<void>, next: PrincipalSource): void {
    users.loadPrincipalSource.mockImplementationOnce(async () => {
      const stale = current;
      current = next;
      await invalidate();
      return stale;
    });
  }

  it('a user invalidation racing a fill is not overwritten by the older snapshot', async () => {
    invalidateDuringRead(() => cache.invalidateUser(10n), {
      ...current,
      permissions: ['user:read', 'user:manage'],
    });
    expect((await loader.load(publicId()))?.permissions).toEqual(['user:read']);
    expect(await cache.get(publicId())).toBeNull();
    expect((await loader.load(publicId()))?.permissions).toEqual(['user:read', 'user:manage']);
    expect(await cache.get(publicId())).not.toBeNull();
  });

  it('an organization invalidation racing a fill is not overwritten by the older snapshot', async () => {
    const suspended = source('customer', ['user:read']);
    suspended.user.publicId = current.user.publicId;
    suspended.user.organization.status = 'suspended';
    invalidateDuringRead(() => cache.invalidateOrganization(2n), suspended);
    expect((await loader.load(publicId()))?.org.status).toBe('active');
    expect(await cache.get(publicId())).toBeNull();
    expect((await loader.load(publicId()))?.org.status).toBe('suspended');
  });

  it('a user version nonce outlives the cache entries written before it', async () => {
    await loader.load(publicId());
    await cache.invalidateUser(10n);
    expect(await kv.ttl(`auth:userver:${publicId()}`)).toBeGreaterThan(60);
    expect(await kv.get(`auth:principal:${publicId()}`)).toBeNull();
  });

  it('never grants platform permissions outside the platform organization', async () => {
    current = source('customer', ['platform:organizations', 'user:read']);
    expect((await loader.load(publicId()))?.permissions).toEqual(['user:read']);
    current = source('platform', ['platform:organizations', 'user:read']);
    expect((await loader.load(publicId()))?.permissions).toEqual([
      'platform:organizations',
      'user:read',
    ]);
  });

  it('discards corrupted cache entries', async () => {
    await kv.set(`auth:principal:${publicId()}`, '{not json', 60);
    expect(await cache.get(publicId())).toBeNull();
    expect(await kv.get(`auth:principal:${publicId()}`)).toBeNull();
  });

  it('invalidateApiKey drops the cached key record and moves the key version', async () => {
    await kv.set('auth:apikey:egk_abcdefghijkl', '{}', 60);
    expect(await cache.apiKeyVersion('egk_abcdefghijkl')).toBe('');
    await cache.invalidateApiKey('egk_abcdefghijkl');
    expect(await kv.get('auth:apikey:egk_abcdefghijkl')).toBeNull();
    const first = await cache.apiKeyVersion('egk_abcdefghijkl');
    expect(first).not.toBe('');
    await cache.invalidateApiKey('egk_abcdefghijkl');
    expect(await cache.apiKeyVersion('egk_abcdefghijkl')).not.toBe(first);
  });
});
