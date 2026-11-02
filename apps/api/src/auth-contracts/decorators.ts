import {
  createParamDecorator,
  type ExecutionContext,
  SetMetadata,
  UnauthorizedException,
} from '@nestjs/common';
import type { Principal } from './principal';
import type { AuthenticatedRequest } from './request';
import type { TenantScope } from './tenant-scope';

export { IS_PUBLIC_KEY, Public } from '@email-gateway/common';

/** Metadata keys read by the permissions guard (WP3). */
export const AUTHZ_KEY = 'authz:requirement';
export const USER_ONLY_KEY = 'authz:userOnly';
export const REQUIRE_MFA_KEY = 'authz:requireMfa';
export const ALLOW_DURING_MFA_ENROLLMENT_KEY = 'authz:allowDuringMfaEnrollment';

export type AuthzRequirement =
  | { mode: 'all'; permissions: string[] }
  | { mode: 'any'; permissions: string[] }
  | { mode: 'authenticated' };

function permissionRequirement(
  mode: 'all' | 'any',
  permissions: string[],
): MethodDecorator & ClassDecorator {
  if (permissions.length === 0 || permissions.some((p) => typeof p !== 'string' || p === '')) {
    throw new Error(`A ${mode} permission requirement needs at least one permission key`);
  }
  const requirement: AuthzRequirement = { mode, permissions: [...permissions] };
  return SetMetadata(AUTHZ_KEY, requirement);
}

/** The principal must hold every listed permission. */
export const RequirePermissions = (...permissions: string[]): MethodDecorator & ClassDecorator =>
  permissionRequirement('all', permissions);

/** The principal must hold at least one of the listed permissions. */
export const RequireAnyPermission = (...permissions: string[]): MethodDecorator & ClassDecorator =>
  permissionRequirement('any', permissions);

/** Any authenticated principal; no particular permission. */
export const AuthenticatedOnly = (): MethodDecorator & ClassDecorator =>
  SetMetadata(AUTHZ_KEY, { mode: 'authenticated' } satisfies AuthzRequirement);

/** API keys get `403`. */
export const UserOnly = (): MethodDecorator & ClassDecorator => SetMetadata(USER_ONLY_KEY, true);

/** The session must be MFA-authenticated (`403 MFA required` otherwise). */
export const RequireMfa = (): MethodDecorator & ClassDecorator =>
  SetMetadata(REQUIRE_MFA_KEY, true);

/** Reachable by a principal whose organization requires MFA and who has not enrolled yet. */
export const AllowDuringMfaEnrollment = (): MethodDecorator & ClassDecorator =>
  SetMetadata(ALLOW_DURING_MFA_ENROLLMENT_KEY, true);

/** `req.principal`; `401` if the route was reached without one (a wiring error). */
export function principalFromContext(context: ExecutionContext): Principal {
  const req = context.switchToHttp().getRequest<AuthenticatedRequest>();
  if (!req.principal) throw new UnauthorizedException();
  return req.principal;
}

/** `req.tenantScope`; `401` if absent. */
export function scopeFromContext(context: ExecutionContext): TenantScope {
  const req = context.switchToHttp().getRequest<AuthenticatedRequest>();
  if (!req.tenantScope) throw new UnauthorizedException();
  return req.tenantScope;
}

const currentPrincipal = createParamDecorator((_data: unknown, context: ExecutionContext) =>
  principalFromContext(context),
);
const currentScope = createParamDecorator((_data: unknown, context: ExecutionContext) =>
  scopeFromContext(context),
);

export const CurrentPrincipal = (): ParameterDecorator => currentPrincipal();
export const CurrentScope = (): ParameterDecorator => currentScope();
