import { describe, expect, it } from 'vitest';
import type { ApiKeyPrincipal, UserPrincipal } from './principal';
import { scopeFromPrincipal, systemScope, tenantWhere } from './tenant-scope';

const user: UserPrincipal = {
  kind: 'user',
  userId: 10n,
  userPublicId: '0190a0b0-0000-7000-8000-000000000010',
  organizationId: 1n,
  organizationPublicId: '0190a0b0-0000-7000-8000-000000000001',
  organizationKind: 'platform',
  sessionId: 'b5f2c4a8-1111-4222-8333-444455556666',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['user:read']),
};

const apiKey: ApiKeyPrincipal = {
  kind: 'api_key',
  apiKeyId: 5n,
  apiKeyPublicId: '0190a0b0-0000-7000-8000-000000000005',
  organizationId: 7n,
  organizationPublicId: '0190a0b0-0000-7000-8000-000000000007',
  permissions: new Set(['user:read']),
};

describe('scopeFromPrincipal', () => {
  it('scopes a user to their home organization as a member', () => {
    expect(scopeFromPrincipal(user)).toMatchObject({ organizationId: 1n, via: 'member' });
  });

  it('scopes an API key to its organization', () => {
    expect(scopeFromPrincipal(apiKey)).toMatchObject({ organizationId: 7n, via: 'api_key' });
  });

  it('scopes an override to the target organization, never the home organization', () => {
    const scope = scopeFromPrincipal({
      ...user,
      override: {
        id: '3f0e8c1a-2b3c-4d5e-8f90-a1b2c3d4e5f6',
        reason: 'Customer ticket 1234',
        targetOrganizationId: 42n,
        targetOrganizationPublicId: '0190a0b0-0000-7000-8000-000000000042',
        expiresAt: new Date(Date.now() + 60_000),
      },
    });
    expect(scope).toMatchObject({ organizationId: 42n, via: 'platform_override' });
  });

  it('returns frozen scopes', () => {
    const scope = scopeFromPrincipal(user);
    expect(Object.isFrozen(scope)).toBe(true);
    expect(() => {
      (scope as { organizationId: bigint }).organizationId = 99n;
    }).toThrow(TypeError);
  });
});

describe('systemScope', () => {
  it('marks the scope as system', () => {
    expect(systemScope(3n)).toMatchObject({ organizationId: 3n, via: 'system' });
  });

  it('rejects ids that cannot be organizations', () => {
    expect(() => systemScope(0n)).toThrow();
    expect(() => systemScope(3 as unknown as bigint)).toThrow();
  });
});

describe('tenantWhere', () => {
  const scope = systemScope(7n);

  it('adds the organization to an empty filter', () => {
    expect(tenantWhere(scope)).toEqual({ organizationId: 7n });
  });

  it('keeps the other conditions', () => {
    expect(tenantWhere(scope, { publicId: 'abc', deletedAt: null })).toEqual({
      publicId: 'abc',
      deletedAt: null,
      organizationId: 7n,
    });
  });

  it('accepts a matching organization id', () => {
    expect(tenantWhere(scope, { organizationId: 7n })).toEqual({ organizationId: 7n });
  });

  it('refuses a conflicting organization id instead of widening the query', () => {
    expect(() => tenantWhere(scope, { organizationId: 8n })).toThrow(/conflicts/);
  });
});
