import type { Me } from '@/lib/api/types';
import type { SessionState } from '@/lib/session/session-client';
import { PLATFORM_ROLE_KEYS, ROLE_PERMISSIONS, type SystemRoleKey } from './roles';

export const TEST_ORG = {
  id: '01930000-0000-7000-8000-00000000a001',
  slug: 'alpha',
  name: 'Alpha Industries (example)',
  kind: 'customer' as const,
};
export const TEST_PLATFORM_ORG = {
  id: '01930000-0000-7000-8000-000000000001',
  slug: 'platform',
  name: 'Gateway Platform Operations',
  kind: 'platform' as const,
};

/** A `GET /auth/me` body for a system role (or explicit permissions). */
export function makeMe(
  options: { role?: SystemRoleKey; permissions?: readonly string[]; overrides?: Partial<Me> } = {},
): Me {
  const role = options.role ?? 'organization_admin';
  const platform = PLATFORM_ROLE_KEYS.includes(role);
  return {
    user: {
      id: '01930000-0000-7000-8000-000000000101',
      email: `${role}@example.com`,
      displayName: 'Test User',
      status: 'active',
    },
    organization: platform ? TEST_PLATFORM_ORG : TEST_ORG,
    roles: [role],
    permissions: [...(options.permissions ?? ROLE_PERMISSIONS[role])],
    mfaEnabled: platform,
    emailVerified: true,
    mfaEnrollmentRequired: false,
    session: { id: '01930000-0000-7000-8000-000000000501', mfaAuthenticated: platform },
    override: null,
    ...options.overrides,
  };
}

export function makeSession(overrides: Partial<SessionState> = {}): SessionState {
  return {
    authenticated: true,
    accessExpiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    refreshExpiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString(),
    mfaEnrollmentRequired: false,
    override: null,
    devFixtures: false,
    ...overrides,
  };
}
