import type { Principal } from './principal';

declare const tenantScopeBrand: unique symbol;

/**
 * The organization a request may touch. Repositories of tenant-owned rows take it as their first
 * parameter and filter with `tenantWhere` (D9). Branded so it can only come from
 * `scopeFromPrincipal` (requests) or `systemScope` (CLI, jobs, fixtures), never from a raw id.
 */
export interface TenantScope {
  readonly organizationId: bigint;
  readonly via: 'member' | 'api_key' | 'platform_override' | 'system';
  readonly [tenantScopeBrand]: true;
}

function makeScope(organizationId: bigint, via: TenantScope['via']): TenantScope {
  if (typeof organizationId !== 'bigint' || organizationId < 1n) {
    throw new Error('A tenant scope needs a positive bigint organization id');
  }
  return Object.freeze({ organizationId, via }) as TenantScope;
}

/** Under a platform override the scope is the override's target, not the user's home org. */
export function scopeFromPrincipal(principal: Principal): TenantScope {
  if (principal.kind === 'api_key') return makeScope(principal.organizationId, 'api_key');
  if (principal.override) {
    return makeScope(principal.override.targetOrganizationId, 'platform_override');
  }
  return makeScope(principal.organizationId, 'member');
}

/** For CLI commands, background jobs and test fixtures only; never for request handling. */
export function systemScope(organizationId: bigint): TenantScope {
  return makeScope(organizationId, 'system');
}

/**
 * Adds the scope's organization to a Prisma `where`. A conflicting `organizationId` in `where`
 * is a programming error and throws instead of silently widening or narrowing the filter.
 */
export function tenantWhere<W extends object>(
  scope: TenantScope,
  where?: W,
): W & { organizationId: bigint } {
  const given = (where as { organizationId?: unknown } | undefined)?.organizationId;
  if (given !== undefined && given !== scope.organizationId) {
    throw new Error('tenantWhere: where.organizationId conflicts with the tenant scope');
  }
  return { ...(where ?? ({} as W)), organizationId: scope.organizationId };
}
