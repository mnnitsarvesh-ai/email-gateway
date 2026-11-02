import { createParamDecorator, type ExecutionContext, ForbiddenException } from '@nestjs/common';
import { principalFromContext } from '../../auth-contracts/decorators';
import type { UserPrincipal } from '../../auth-contracts/principal';

/** The user principal of a `@UserOnly()` route (`403` for an API key, `401` without one). */
export const CurrentUser = createParamDecorator(
  (_data: unknown, context: ExecutionContext): UserPrincipal => {
    const principal = principalFromContext(context);
    if (principal.kind !== 'user') throw new ForbiddenException('This operation requires a user');
    return principal;
  },
);
