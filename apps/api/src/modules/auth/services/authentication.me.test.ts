import { describe, expect, it, vi } from 'vitest';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import { AuthenticationService } from './authentication.service';

const principal: UserPrincipal = {
  kind: 'user',
  userId: 10n,
  userPublicId: '0190a0b0-0000-7000-8000-000000000001',
  organizationId: 7n,
  organizationPublicId: '0190a0b0-0000-7000-8000-000000000007',
  organizationKind: 'customer',
  sessionId: '3f0e8c1a-2b3c-4d5e-8f90-a1b2c3d4e5f6',
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['journal:read', 'archive:read']),
};

function service(profile: 'gateway' | 'archive_only') {
  const users = {
    findById: vi.fn(() =>
      Promise.resolve({
        id: 10n,
        publicId: principal.userPublicId,
        email: 'u@example.test',
        displayName: 'U',
        status: 'active',
        mfaEnabled: true,
        emailVerifiedAt: new Date(),
        organization: {
          publicId: principal.organizationPublicId,
          slug: 'acme',
          name: 'Acme',
          kind: 'customer',
        },
      }),
    ),
    roleKeys: vi.fn(() => Promise.resolve(['compliance_officer'])),
  };
  const features = { serviceProfile: vi.fn(() => Promise.resolve(profile)) };
  const none = {} as never;
  return {
    features,
    svc: new AuthenticationService(
      users as never,
      none,
      none,
      none,
      none,
      none,
      none,
      features as unknown as OrganizationFeaturesService,
    ),
  };
}

describe('AuthenticationService.me: serviceProfile (step 8.6 D13, ADR-0090)', () => {
  it.each(['gateway', 'archive_only'] as const)(
    'returns organization.serviceProfile %s of the home organization (additive)',
    async (profile) => {
      const { svc, features } = service(profile);
      const me = await svc.me(principal);
      expect(me.organization).toEqual({
        id: principal.organizationPublicId,
        slug: 'acme',
        name: 'Acme',
        kind: 'customer',
        serviceProfile: profile,
      });
      expect(features.serviceProfile).toHaveBeenCalledWith(7n);
      expect(me.permissions).toEqual(['archive:read', 'journal:read']);
    },
  );
});
