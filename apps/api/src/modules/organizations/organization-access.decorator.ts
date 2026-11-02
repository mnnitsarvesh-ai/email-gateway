import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import { principalFromContext, scopeFromContext } from '../../auth-contracts/decorators';
import { organizationAccessOf } from './domain/organization-access';

/**
 * The caller's `OrganizationAccess`, derived from the authenticated principal and its tenant
 * scope (set by the authentication guard). Never from client-supplied identifiers.
 */
export const OrgAccess = createParamDecorator((_data: unknown, context: ExecutionContext) =>
  organizationAccessOf(principalFromContext(context), scopeFromContext(context)),
);
