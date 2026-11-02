import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { TENANT_PERMISSIONS } from '@email-gateway/database';
import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../audit/audit.service';
import type { UserPrincipal } from '../../auth-contracts/principal';
import { systemScope } from '../../auth-contracts/tenant-scope';
import { parseApiKey, type TokenHasher } from '../../crypto/tokens';
import type { TransactionRunner } from '../../database/transaction-runner';
import type { OrganizationFeaturesService } from '../../tenancy/organization-features.service';
import type { PrincipalCacheService } from '../auth/services/principal-cache.service';
import type { ApiKeyRecord, ApiKeysRepository, NewApiKey } from './api-keys.repository';
import {
  API_KEY_FORBIDDEN_SCOPES,
  ApiKeysService,
  assertValidApiKeyScopes,
  resolveApiKeyExpiry,
  toApiKeyView,
} from './api-keys.service';

const DAY = 86_400_000;
const now = new Date('2026-11-02T10:00:00Z');
const scope = systemScope(7n);
const client = { ip: '203.0.113.5', userAgent: null };
const all = new Set<string>(TENANT_PERMISSIONS);

function expectBadRequest(fn: () => unknown, fragment: string): void {
  try {
    fn();
    expect.unreachable();
  } catch (err) {
    expect(err).toBeInstanceOf(BadRequestException);
    expect((err as BadRequestException).getResponse()).toMatchObject({
      message: [expect.stringContaining(fragment)],
    });
  }
}

describe('API key scopes (D11)', () => {
  it('forbids managing keys, roles and sessions', () => {
    expect([...API_KEY_FORBIDDEN_SCOPES].sort()).toEqual([
      'apikey:manage',
      'role:manage',
      'session:manage',
    ]);
    for (const scopeKey of API_KEY_FORBIDDEN_SCOPES) {
      expectBadRequest(() => assertValidApiKeyScopes([scopeKey], all), scopeKey);
    }
  });

  it('accepts tenant permissions the creator holds', () => {
    expect(() => assertValidApiKeyScopes(['user:read', 'domain:read'], all)).not.toThrow();
  });

  it('refuses empty, platform and unknown scopes (400) and unheld scopes (403)', () => {
    expectBadRequest(() => assertValidApiKeyScopes([], all), 'at least one');
    expectBadRequest(() => assertValidApiKeyScopes(['platform:operations'], all), 'platform');
    expectBadRequest(() => assertValidApiKeyScopes(['made:up'], all), 'made:up');
    expect(() => assertValidApiKeyScopes(['user:manage'], new Set(['user:read']))).toThrow(
      ForbiddenException,
    );
  });
});

describe('API key expiry', () => {
  it('defaults to 365 days and allows at most 730', () => {
    expect(resolveApiKeyExpiry(undefined, now).getTime()).toBe(now.getTime() + 365 * DAY);
    const max = new Date(now.getTime() + 730 * DAY).toISOString();
    expect(resolveApiKeyExpiry(max, now).toISOString()).toBe(max);
    expectBadRequest(
      () => resolveApiKeyExpiry(new Date(now.getTime() + 731 * DAY).toISOString(), now),
      '730',
    );
    expectBadRequest(() => resolveApiKeyExpiry(now.toISOString(), now), 'future');
  });
});

function principal(extra: Partial<UserPrincipal> = {}): UserPrincipal {
  return {
    kind: 'user',
    userId: 1n,
    userPublicId: '0190a0b0-0000-7000-8000-000000000001',
    organizationId: 7n,
    organizationPublicId: '0190a0b0-0000-7000-8000-000000000007',
    organizationKind: 'customer',
    sessionId: '3f0e8c1a-2b3c-4d5e-8f90-a1b2c3d4e5f6',
    mfaAuthenticated: false,
    mfaEnrollmentRequired: false,
    permissions: all,
    ...extra,
  };
}

const record = (data: Partial<ApiKeyRecord> = {}): ApiKeyRecord => ({
  id: 5n,
  publicId: '0190a0b0-0000-7000-8000-0000000000k5',
  name: 'ci',
  keyPrefix: 'egk_AAAAAAAAAAAA',
  scopes: ['user:read'],
  createdBy: { publicId: '0190a0b0-0000-7000-8000-000000000001', displayName: 'Admin' },
  lastUsedAt: null,
  expiresAt: now,
  revokedAt: null,
  createdAt: now,
  ...data,
});

function setup(apiAccess = true) {
  const created: NewApiKey[] = [];
  const repo = {
    list: vi.fn(() => Promise.resolve([record()])),
    findByPublicId: vi.fn(() => Promise.resolve(record())),
    create: vi.fn((_tx: unknown, _s: unknown, data: NewApiKey) => {
      created.push(data);
      return Promise.resolve(record({ keyPrefix: data.keyPrefix, scopes: data.scopes }));
    }),
    revoke: vi.fn(() => Promise.resolve(true)),
  };
  const audit = {
    record: vi.fn(() => Promise.resolve()),
    actorFrom: vi.fn(() => ({ type: 'user', id: 'actor' })),
  };
  const cache = { invalidateApiKey: vi.fn(() => Promise.resolve()) };
  const service = new ApiKeysService(
    repo as unknown as ApiKeysRepository,
    { run: (fn: (tx: unknown) => Promise<unknown>) => fn({}) } as unknown as TransactionRunner,
    { hmacHex: (v: string) => `hmac(${v.length})` } as unknown as TokenHasher,
    { isEnabled: () => Promise.resolve(apiAccess) } as unknown as OrganizationFeaturesService,
    audit as unknown as AuditService,
    cache as unknown as PrincipalCacheService,
  );
  return { service, repo, audit, cache, created };
}

describe('ApiKeysService', () => {
  const body = { name: 'ci', scopes: ['user:read'] };

  it('returns the key once and stores only prefix and HMAC; the audit row has no key', async () => {
    const { service, created, audit } = setup();
    const res = await service.create(principal(), scope, body, client);
    expect(parseApiKey(res.key)?.prefix).toBe(res.apiKey.prefix);
    expect(created[0]).toMatchObject({ keyPrefix: res.apiKey.prefix, createdByUserId: 1n });
    expect(created[0]!.keyHash).not.toContain(res.key);
    const audited = JSON.stringify(audit.record.mock.calls, (_k, v: unknown) =>
      typeof v === 'bigint' ? v.toString() : v,
    );
    expect(audited).not.toContain(res.key);
    expect(audited).toContain(res.apiKey.prefix);
    expect(JSON.stringify(res.apiKey)).not.toContain(res.key);
  });

  it('requires the api_access feature (403) and refuses creation under an override', async () => {
    await expect(setup(false).service.create(principal(), scope, body, client)).rejects.toThrow(
      /API access/,
    );
    await expect(
      setup().service.create(
        principal({
          override: {
            id: 'o',
            reason: 'Customer ticket 1',
            targetOrganizationId: 7n,
            targetOrganizationPublicId: 'x',
            expiresAt: now,
          },
        }),
        scope,
        body,
        client,
      ),
    ).rejects.toThrow(ForbiddenException);
  });

  it('revocation is idempotent and always drops the cached key', async () => {
    const { service, repo, audit, cache } = setup();
    repo.revoke.mockResolvedValueOnce(true).mockResolvedValueOnce(false);
    await service.revoke(principal(), scope, record().publicId, client);
    await service.revoke(principal(), scope, record().publicId, client);
    expect(audit.record).toHaveBeenCalledTimes(1);
    expect(cache.invalidateApiKey).toHaveBeenCalledTimes(2);
    expect(cache.invalidateApiKey).toHaveBeenCalledWith('egk_AAAAAAAAAAAA');
  });

  it('answers 404 for keys outside the scope', async () => {
    const { service, repo } = setup();
    repo.findByPublicId.mockResolvedValueOnce(null as unknown as ApiKeyRecord);
    await expect(service.revoke(principal(), scope, 'x', client)).rejects.toThrow(
      NotFoundException,
    );
  });

  it('maps rows without secrets and paginates with a cursor', async () => {
    expect(Object.keys(toApiKeyView(record())).sort()).toEqual(
      [
        'createdAt',
        'createdBy',
        'expiresAt',
        'id',
        'lastUsedAt',
        'name',
        'prefix',
        'revokedAt',
        'scopes',
      ].sort(),
    );
    const { service, repo } = setup();
    repo.list.mockResolvedValueOnce([record({ id: 9n }), record({ id: 8n })]);
    const page = await service.list(scope, { limit: 1 });
    expect(page.data).toHaveLength(1);
    expect(page.nextCursor).not.toBeNull();
    expect(repo.list).toHaveBeenCalledWith(scope, { take: 2 });
  });
});
