import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CodedForbiddenException } from '../../../http/coded-exception';

export const PLATFORM_OPERATIONS = 'platform:operations';
export const AUDIT_READ = 'audit:read';

/**
 * Who may search any organization's audit log (step 6.1 D7, §3.3): a user of the platform
 * organization, acting as itself (no override: an override session is scoped to its target and
 * has its `platform:*` permissions stripped), MFA-authenticated, holding `platform:operations`
 * and `audit:read`. API keys never qualify. The route decorators require the same; this check
 * keeps the service correct on its own. Anything else is `403 forbidden`.
 */
export function platformAuditDenial(principal: Principal, scope: TenantScope): string | null {
  if (principal.kind !== 'user') return 'api_key';
  if (principal.override !== undefined || scope.via !== 'member') return 'override';
  if (principal.organizationKind !== 'platform') return 'not_platform_organization';
  if (scope.organizationId !== principal.organizationId) return 'scope';
  if (!principal.mfaAuthenticated) return 'mfa';
  if (!principal.permissions.has(PLATFORM_OPERATIONS) || !principal.permissions.has(AUDIT_READ)) {
    return 'permission';
  }
  return null;
}

export function assertPlatformAuditAccess(
  principal: Principal,
  scope: TenantScope,
): asserts principal is UserPrincipal {
  if (platformAuditDenial(principal, scope) !== null) {
    throw new CodedForbiddenException(
      'forbidden',
      'Searching audit logs across organizations requires an MFA session of a platform user',
    );
  }
}
