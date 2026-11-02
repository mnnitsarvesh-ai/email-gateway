import { randomBytes, randomUUID } from 'node:crypto';
import { Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryKeyValueStore } from '../../../../test/support/in-memory-key-value-store';
import { generateApiKey, TokenHasher } from '../../../crypto/tokens';
import type { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import type {
  ApiKeyAuthRecord,
  ApiKeysAuthRepository,
} from '../repositories/api-keys-auth.repository';
import type { UsersAuthRepository } from '../repositories/users-auth.repository';
import {
  ApiKeyAuthenticatorService,
  effectiveApiKeyPermissions,
} from './api-key-authenticator.service';
import { PrincipalCacheService } from './principal-cache.service';

describe('effectiveApiKeyPermissions', () => {
  it('keeps tenant permissions only and drops forbidden scopes', () => {
    expect([
      ...effectiveApiKeyPermissions([
        'user:read',
        'platform:organizations',
        'apikey:manage',
        'role:manage',
        'session:manage',
        'nope',
        42,
      ]),
    ]).toEqual(['user:read']);
    expect(effectiveApiKeyPermissions('user:read').size).toBe(0);
  });
});

describe('ApiKeyAuthenticatorService', () => {
  const hasher = new TokenHasher({ AUTH_TOKEN_PEPPER: randomBytes(32).toString('hex') });
  let kv: InMemoryKeyValueStore;
  let record: ApiKeyAuthRecord;
  let key: string;
  let prefix: string;
  let featureOn: boolean;
  let repo: {
    findByPrefix: ReturnType<typeof vi.fn>;
    findOrganizationIdByPrefix: ReturnType<typeof vi.fn>;
    touchLastUsed: ReturnType<typeof vi.fn>;
  };
  let cache: PrincipalCacheService;
  let service: ApiKeyAuthenticatorService;

  beforeEach(() => {
    ({ key, prefix } = generateApiKey());
    kv = new InMemoryKeyValueStore();
    record = {
      id: 5n,
      publicId: randomUUID(),
      organizationId: 7n,
      keyHash: hasher.hmacHex(key),
      scopes: ['user:read', 'apikey:manage'],
      expiresAt: new Date(Date.now() + 3_600_000),
      revokedAt: null,
      organization: { publicId: randomUUID(), status: 'active', deletedAt: null },
    };
    featureOn = true;
    repo = {
      findByPrefix: vi.fn((p: string) => Promise.resolve(p === prefix ? record : null)),
      findOrganizationIdByPrefix: vi.fn((p: string) =>
        Promise.resolve(p === prefix ? record.organizationId : null),
      ),
      touchLastUsed: vi.fn(() => Promise.resolve()),
    };
    cache = new PrincipalCacheService(kv, {} as UsersAuthRepository);
    service = new ApiKeyAuthenticatorService(
      repo as unknown as ApiKeysAuthRepository,
      hasher,
      kv,
      cache,
      { isEnabled: () => Promise.resolve(featureOn) } as unknown as OrganizationFeaturesService,
    );
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => vi.restoreAllMocks());

  it('authenticates a valid key with its effective permissions', async () => {
    const principal = await service.authenticate(key);
    expect(principal).toMatchObject({ kind: 'api_key', apiKeyId: 5n, organizationId: 7n });
    expect([...principal!.permissions]).toEqual(['user:read']);
    await vi.waitFor(() => expect(repo.touchLastUsed).toHaveBeenCalledTimes(1));
  });

  it('caches the lookup and throttles last_used_at', async () => {
    await service.authenticate(key);
    await service.authenticate(key);
    expect(repo.findByPrefix).toHaveBeenCalledTimes(1);
    await vi.waitFor(() => expect(repo.touchLastUsed).toHaveBeenCalledTimes(1));
  });

  it('rejects wrong secrets, malformed keys, revoked, expired, inactive org and api_access off', async () => {
    expect(
      await service.authenticate(`${prefix}_${randomBytes(32).toString('base64url')}`),
    ).toBeNull();
    expect(await service.authenticate('egk_short')).toBeNull();
    // Revocation (WP4) invalidates the cached record, as every revoking caller must.
    record.revokedAt = new Date();
    await cache.invalidateApiKey(prefix);
    expect(await service.authenticate(key)).toBeNull();
  });

  it('sees revocation after the organization cache version changes', async () => {
    expect(await service.authenticate(key)).not.toBeNull();
    record.organization.status = 'suspended';
    expect(await service.authenticate(key)).not.toBeNull(); // cached for up to 60 s
    await cache.invalidateOrganization(7n);
    expect(await service.authenticate(key)).toBeNull();
  });

  /** The key row is read, then a writer commits and invalidates before the cache is written. */
  function invalidateDuringRead(change: () => void, invalidate: () => Promise<void>): void {
    repo.findByPrefix.mockImplementationOnce(async () => {
      const stale: ApiKeyAuthRecord = { ...record, organization: { ...record.organization } };
      change();
      await invalidate();
      return stale;
    });
  }

  it('an organization suspension racing a fill takes effect on the next request', async () => {
    invalidateDuringRead(
      () => {
        record.organization.status = 'suspended';
      },
      () => cache.invalidateOrganization(7n),
    );
    expect(await service.authenticate(key)).not.toBeNull(); // this request read the old row
    expect(await service.authenticate(key)).toBeNull();
    expect(repo.findByPrefix).toHaveBeenCalledTimes(2);
  });

  it('a revocation racing a fill takes effect on the next request', async () => {
    invalidateDuringRead(
      () => {
        record.revokedAt = new Date();
      },
      () => cache.invalidateApiKey(prefix),
    );
    expect(await service.authenticate(key)).not.toBeNull();
    expect(await service.authenticate(key)).toBeNull();
  });

  it('checks expiry and the api_access feature on every request', async () => {
    expect(await service.authenticate(key, new Date(Date.now() + 7_200_000))).toBeNull();
    featureOn = false;
    expect(await service.authenticate(key)).toBeNull();
  });
});
