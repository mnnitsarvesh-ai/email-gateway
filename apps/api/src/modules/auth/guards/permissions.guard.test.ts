import { type ExecutionContext, ForbiddenException, HttpStatus, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AllowDuringMfaEnrollment,
  AuthenticatedOnly,
  RequirePermissions,
  RequireMfa,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import { CodedForbiddenException } from '../../../http/coded-exception';
import { PermissionsGuard } from './permissions.guard';

class Routes {
  unannotated(): void {}

  @RequirePermissions('user:manage')
  manage(): void {}

  @AuthenticatedOnly()
  @UserOnly()
  userOnly(): void {}

  @AuthenticatedOnly()
  @RequireMfa()
  stepUp(): void {}

  @AuthenticatedOnly()
  @AllowDuringMfaEnrollment()
  enrollment(): void {}
}

const user = (overrides: Partial<Principal & { kind: 'user' }> = {}): Principal => ({
  kind: 'user',
  userId: 1n,
  userPublicId: 'u-1',
  organizationId: 2n,
  organizationPublicId: 'o-1',
  organizationKind: 'customer',
  sessionId: 's-1',
  mfaAuthenticated: false,
  mfaEnrollmentRequired: false,
  permissions: new Set(['user:read']),
  ...overrides,
});
const apiKey: Principal = {
  kind: 'api_key',
  apiKeyId: 1n,
  apiKeyPublicId: 'k-1',
  organizationId: 2n,
  organizationPublicId: 'o-1',
  permissions: new Set(['user:manage']),
};

function refusal(handler: () => void, principal: Principal): { code: string; message: string } {
  const guard = new PermissionsGuard(new Reflector());
  const context = {
    getType: () => 'http',
    getHandler: () => handler,
    getClass: () => Routes,
    switchToHttp: () => ({ getRequest: () => ({ principal }) }),
  } as unknown as ExecutionContext;
  try {
    guard.canActivate(context);
  } catch (error) {
    expect(error).toBeInstanceOf(CodedForbiddenException);
    expect(error).toBeInstanceOf(ForbiddenException);
    const coded = error as CodedForbiddenException;
    expect(coded.getStatus()).toBe(HttpStatus.FORBIDDEN);
    expect(coded.getResponse()).toEqual({ message: coded.message, code: coded.code });
    return { code: coded.code, message: coded.message };
  }
  return expect.fail('expected a 403');
}

describe('PermissionsGuard coded refusals (step 6.1 D2)', () => {
  beforeEach(() => {
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => vi.restoreAllMocks());

  it('codes every refusal and keeps the messages of earlier steps', () => {
    expect(refusal(Routes.prototype.unannotated, user())).toEqual({
      code: 'forbidden',
      message: 'Forbidden',
    });
    expect(refusal(Routes.prototype.manage, user())).toEqual({
      code: 'forbidden',
      message: 'Forbidden',
    });
    expect(refusal(Routes.prototype.userOnly, apiKey)).toEqual({
      code: 'user_required',
      message: 'This operation requires a user',
    });
    expect(refusal(Routes.prototype.stepUp, user())).toEqual({
      code: 'mfa_required',
      message: 'MFA required',
    });
    expect(refusal(Routes.prototype.manage, user({ mfaEnrollmentRequired: true }))).toEqual({
      code: 'mfa_enrollment_required',
      message: 'MFA enrollment required',
    });
  });
});
