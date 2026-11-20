import {
  type CanActivate,
  type ExecutionContext,
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
import {
  AUTHORIZATION_MESSAGES,
  type AuthorizationRefusal,
  satisfiesRequirement,
} from '../../../auth-contracts/authorization';
import type { AuthenticatedRequest } from '../../../auth-contracts/request';
import { CodedForbiddenException } from '../../../http/coded-exception';

/** The coded 403s of the guard (step 6.1 D2); the messages are those of steps 1.2/1.3. */
export const forbidden = (code: AuthorizationRefusal, message: string): CodedForbiddenException =>
  new CodedForbiddenException(code, message);

/**
 * Global authorization (D9), after `AuthGuard`. Fails closed: a non-public route without an
 * authorization requirement is `403` and logged as a wiring error. Checks, in order: MFA
 * enrollment restriction, `@UserOnly()`, `@RequireMfa()`, then the `all`/`any` permissions —
 * the pure predicate `satisfiesRequirement` (auth-contracts/authorization.ts), shared with the AI
 * assistant's tool pre-filter (step AI-1 D5).
 * Every refusal is a coded `403` (step 6.1 D2): `mfa_enrollment_required`, `user_required`,
 * `mfa_required` or `forbidden`, with the messages of earlier steps.
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
      throw forbidden('forbidden', 'Forbidden');
    }

    const principal = context.switchToHttp().getRequest<AuthenticatedRequest>().principal;
    if (!principal) throw new UnauthorizedException();

    const flag = (key: string): boolean =>
      this.reflector.getAllAndOverride<boolean | undefined>(key, targets) === true;
    const decision = satisfiesRequirement(principal, requirement, {
      userOnly: flag(USER_ONLY_KEY),
      requireMfa: flag(REQUIRE_MFA_KEY),
      allowDuringMfaEnrollment: flag(ALLOW_DURING_MFA_ENROLLMENT_KEY),
    });
    if (!decision.ok) throw forbidden(decision.code, AUTHORIZATION_MESSAGES[decision.code]);
    return true;
  }
}
