import { ForbiddenException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import type { ApiKeyPrincipal, UserPrincipal } from '../../../auth-contracts/principal';
import { scopeFromPrincipal } from '../../../auth-contracts/tenant-scope';
import {
  assertCanManage,
  assertPlatform,
  organizationAccessOf,
  type OrganizationAccess,
} from './organization-access';

const platformUser: UserPrincipal = {
  kind: 'user',
  userId: 10n,
  userPublicId: '0190a0b0-0000-7000-8000-000000000010',
  organizationId: 1n,
  organizationPublicId: '0190a0b0-0000-7000-8000-000000000001',
  organizationKind: 'platform',
  sessionId: 'b5f2c4a8-1111-4222-8333-444455556666',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['platform:organizations', 'organization:read']),
};

const member: UserPrincipal = {
  ...platformUser,
  userId: 20n,
  organizationId: 7n,
  organizationKind: 'customer',
  permissions: new Set(['organization:read', 'organization:manage']),
};

const apiKey: ApiKeyPrincipal = {
  kind: 'api_key',
  apiKeyId: 5n,
  apiKeyPublicId: '0190a0b0-0000-7000-8000-000000000005',
  organizationId: 7n,
  organizationPublicId: '0190a0b0-0000-7000-8000-000000000007',
  permissions: new Set(['organization:read']),
};

const access = (p: UserPrincipal | ApiKeyPrincipal): OrganizationAccess =>
  organizationAccessOf(p, scopeFromPrincipal(p));

describe('organizationAccessOf', () => {
  it('gives a platform user with platform:organizations the catalog', () => {
    expect(access(platformUser).kind).toBe('platform');
  });

  it('scopes a member to the own organization', () => {
    const result = access(member);
    expect(result).toMatchObject({ kind: 'scoped', scope: { organizationId: 7n, via: 'member' } });
  });

  it('never gives a customer-organization user the catalog, even with the permission', () => {
    const result = access({ ...member, permissions: new Set(['platform:organizations']) });
    expect(result).toMatchObject({ kind: 'scoped', scope: { organizationId: 7n } });
  });

  it('scopes a platform user without platform:organizations to the platform organization', () => {
    const result = access({ ...platformUser, permissions: new Set(['organization:read']) });
    expect(result).toMatchObject({ kind: 'scoped', scope: { organizationId: 1n } });
  });

  it('scopes an override to its target, even if a platform permission were present', () => {
    // The guard strips platform:* under an override; the policy does not rely on it.
    const result = access({
      ...platformUser,
      override: {
        id: '3f0e8c1a-2b3c-4d5e-8f90-a1b2c3d4e5f6',
        reason: 'Customer ticket 1234',
        targetOrganizationId: 42n,
        targetOrganizationPublicId: '0190a0b0-0000-7000-8000-000000000042',
        expiresAt: new Date(Date.now() + 60_000),
      },
    });
    expect(result).toMatchObject({
      kind: 'scoped',
      scope: { organizationId: 42n, via: 'platform_override' },
    });
  });

  it('never gives an API key the catalog, whatever its permissions claim', () => {
    const result = access({
      ...apiKey,
      permissions: new Set(['platform:organizations', 'organization:read']),
    });
    expect(result).toMatchObject({ kind: 'scoped', scope: { organizationId: 7n, via: 'api_key' } });
  });
});

describe('assertCanManage / assertPlatform', () => {
  it('lets the catalog and organization managers write', () => {
    expect(() => assertCanManage(access(platformUser))).not.toThrow();
    expect(() => assertCanManage(access(member))).not.toThrow();
  });

  it('refuses scoped principals without organization:manage', () => {
    expect(() => assertCanManage(access(apiKey))).toThrow(ForbiddenException);
  });

  it('restricts catalog functions to platform access', () => {
    expect(() => assertPlatform(access(platformUser))).not.toThrow();
    expect(() => assertPlatform(access(member))).toThrow(ForbiddenException);
    expect(() => assertPlatform(access(apiKey))).toThrow(ForbiddenException);
  });
});
