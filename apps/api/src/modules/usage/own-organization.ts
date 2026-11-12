import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';

/**
 * Public id of the organization a request acts on (its tenant scope): the API key's
 * organization, the user's home organization, or under a platform override the override target.
 * Always derived from the authenticated principal, never from client input (step 6.1 D7).
 */
export function scopeOrganizationPublicId(principal: Principal, scope: TenantScope): string {
  if (principal.kind === 'user' && principal.override) {
    if (principal.override.targetOrganizationId !== scope.organizationId) {
      throw new Error('scopeOrganizationPublicId: the scope is not the override target');
    }
    return principal.override.targetOrganizationPublicId;
  }
  if (principal.organizationId !== scope.organizationId) {
    throw new Error('scopeOrganizationPublicId: the scope is not the principal organization');
  }
  return principal.organizationPublicId;
}
