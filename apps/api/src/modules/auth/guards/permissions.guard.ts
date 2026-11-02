import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  ALLOW_DURING_MFA_ENROLLMENT_KEY,
  AUTHZ_KEY,
  type AuthzRequirement,
  IS_PUBLIC_KEY,
  REQUIRE_MFA_KEY,
  USER_ONLY_KEY,
} from '../../../auth-contracts/decorators';
import type { AuthenticatedRequest } from '../../../auth-contracts/request';

/**
 * Global authorization (D9), after `AuthGuard`. Fails closed: a non-public route without an
 * authorization requirement is `403` and logged as a wiring error. Checks, in order: MFA
 * enrollment restriction, `@UserOnly()`, `@RequireMfa()`, then the `all`/`any` permissions.
 */
@Injectable()
export class PermissionsGuard implements CanActivate {
  private readonly logger = new Logger(PermissionsGuard.name);

  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const targets = [context.getHandler(), context.getClass()];
    if (this.reflector.getAllAndOverride<boolean | undefined>(IS_PUBLIC_KEY, targets)) return true;

    const requirement = this.reflector.getAllAndOverride<AuthzRequirement | undefined>(
      AUTHZ_KEY,
      targets,
    );
    if (!requirement) {
      this.logger.error({
        message: 'Route has no authorization requirement; denied',
        controller: context.getClass().name,
        handler: context.getHandler().name,
      });
      throw new ForbiddenException();
    }

    const principal = context.switchToHttp().getRequest<AuthenticatedRequest>().principal;
    if (!principal) throw new UnauthorizedException();

    if (
      principal.kind === 'user' &&
      principal.mfaEnrollmentRequired &&
      !this.reflector.getAllAndOverride<boolean | undefined>(
        ALLOW_DURING_MFA_ENROLLMENT_KEY,
        targets,
      )
    ) {
      throw new ForbiddenException('MFA enrollment required');
    }
    if (
      principal.kind === 'api_key' &&
      this.reflector.getAllAndOverride<boolean | undefined>(USER_ONLY_KEY, targets)
    ) {
      throw new ForbiddenException('This operation requires a user');
    }
    if (
      this.reflector.getAllAndOverride<boolean | undefined>(REQUIRE_MFA_KEY, targets) &&
      !(principal.kind === 'user' && principal.mfaAuthenticated)
    ) {
      throw new ForbiddenException('MFA required');
    }

    const held = principal.permissions;
    const allowed =
      requirement.mode === 'authenticated' ||
      (requirement.mode === 'all' && requirement.permissions.every((p) => held.has(p))) ||
      (requirement.mode === 'any' && requirement.permissions.some((p) => held.has(p)));
    if (!allowed) throw new ForbiddenException();
    return true;
  }
}
