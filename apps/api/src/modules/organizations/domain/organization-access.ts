import { ForbiddenException } from '@nestjs/common';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';

/** The organization catalog permission (D9: a platform function, not an override). */
export const PLATFORM_ORGANIZATIONS = 'platform:organizations';
export const ORGANIZATION_READ = 'organization:read';
export const ORGANIZATION_MANAGE = 'organization:manage';

/**
 * Which organizations a request may see (D9, D12):
 *
 * - `platform`: a user of the platform organization (never an API key, never under an override,
 *   because both have their `platform:*` permissions stripped by the authentication guard)
 *   holding `platform:organizations`. Sees and manages every organization.
 * - `scoped`: everybody else. Sees only the organization of its tenant scope (the home
 *   organization, the API key's organization, or the override target); anything else is `404`.
 *
 * Built only from the authenticated principal and its scope, never from client input.
 */
export type OrganizationAccess =
  | { readonly kind: 'platform'; readonly principal: Principal }
  | { readonly kind: 'scoped'; readonly principal: Principal; readonly scope: TenantScope };

export function organizationAccessOf(principal: Principal, scope: TenantScope): OrganizationAccess {
  if (
    principal.kind === 'user' &&
    principal.override === undefined &&
    // Platform roles exist only in the platform organization (D8); checked again here.
    principal.organizationKind === 'platform' &&
    scope.via === 'member' &&
    principal.permissions.has(PLATFORM_ORGANIZATIONS)
  ) {
    return Object.freeze({ kind: 'platform', principal });
  }
  return Object.freeze({ kind: 'scoped', principal, scope });
}

export function isPlatformAccess(
  access: OrganizationAccess,
): access is Extract<OrganizationAccess, { kind: 'platform' }> {
  return access.kind === 'platform';
}

/**
 * Writes on an organization the caller can see: the catalog (`platform`) or `organization:manage`
 * within the own scope. The route guard already requires one of the two permissions; this check
 * keeps the service correct on its own.
 */
export function assertCanManage(access: OrganizationAccess): void {
  if (access.kind === 'platform') return;
  if (!access.principal.permissions.has(ORGANIZATION_MANAGE)) throw new ForbiddenException();
}

/** Catalog-only operations (plan changes, status, entitlements, deletion). */
export function assertPlatform(access: OrganizationAccess): void {
  if (access.kind !== 'platform') throw new ForbiddenException();
}
