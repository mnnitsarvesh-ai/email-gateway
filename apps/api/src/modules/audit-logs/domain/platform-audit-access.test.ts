import { describe, expect, it } from 'vitest';
import type { ApiKeyPrincipal, UserPrincipal } from '../../../auth-contracts/principal';
import { scopeFromPrincipal } from '../../../auth-contracts/tenant-scope';
import { CodedForbiddenException } from '../../../http/coded-exception';
import { assertPlatformAuditAccess, platformAuditDenial } from './platform-audit-access';

const platformUser = (overrides: Partial<UserPrincipal> = {}): UserPrincipal => ({
  kind: 'user',
  userId: 1n,
  userPublicId: 'u-1',
  organizationId: 1n,
  organizationPublicId: 'org-platform',
  organizationKind: 'platform',
  sessionId: 's',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['platform:operations', 'audit:read']),
  ...overrides,
});

const check = (p: UserPrincipal | ApiKeyPrincipal) => platformAuditDenial(p, scopeFromPrincipal(p));

describe('platform audit access (step 6.1 D7)', () => {
  it('allows an MFA session of a platform user with platform:operations and audit:read', () => {
    const p = platformUser();
    expect(check(p)).toBeNull();
    expect(() => assertPlatformAuditAccess(p, scopeFromPrincipal(p))).not.toThrow();
  });

  it('refuses API keys, customer users, overrides, sessions without MFA and missing permissions', () => {
    const apiKey: ApiKeyPrincipal = {
      kind: 'api_key',
      apiKeyId: 1n,
      apiKeyPublicId: 'k',
      organizationId: 1n,
      organizationPublicId: 'org-platform',
      permissions: new Set(['platform:operations', 'audit:read']),
    };
    expect(check(apiKey)).toBe('api_key');
    expect(check(platformUser({ organizationKind: 'customer' }))).toBe('not_platform_organization');
    expect(
      check(
        platformUser({
          override: {
            id: 'o',
            reason: 'ticket',
            targetOrganizationId: 9n,
            targetOrganizationPublicId: 'org-9',
            expiresAt: new Date(),
          },
        }),
      ),
    ).toBe('override');
    expect(check(platformUser({ mfaAuthenticated: false }))).toBe('mfa');
    expect(check(platformUser({ permissions: new Set(['audit:read']) }))).toBe('permission');
    expect(check(platformUser({ permissions: new Set(['platform:operations']) }))).toBe(
      'permission',
    );
    const denied = platformUser({ organizationKind: 'customer' });
    expect(() => assertPlatformAuditAccess(denied, scopeFromPrincipal(denied))).toThrow(
      CodedForbiddenException,
    );
  });
});
