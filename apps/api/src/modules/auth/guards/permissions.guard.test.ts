import { type ExecutionContext, ForbiddenException, HttpStatus, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AUTHORIZATION_MESSAGES,
  type AuthorizationRefusal,
  satisfiesRequirement,
} from '../../../auth-contracts/authorization';
import {
  AllowDuringMfaEnrollment,
  AuthenticatedOnly,
  type AuthzRequirement,
  RequireAnyPermission,
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

const all = (...permissions: string[]): AuthzRequirement => ({ mode: 'all', permissions });
const any = (...permissions: string[]): AuthzRequirement => ({ mode: 'any', permissions });
const AUTH: AuthzRequirement = { mode: 'authenticated' };

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

// ---------------------------------------------------------------------------------------------
// Step AI-1 D5: the guard and the shared predicate `satisfiesRequirement` decide identically.
// ---------------------------------------------------------------------------------------------

type Flags = { userOnly: boolean; requireMfa: boolean; allowDuringMfaEnrollment: boolean };

/** A route class decorated with exactly the given requirement and flags. */
function routeFor(requirement: AuthzRequirement, flags: Flags): () => void {
  class Dynamic {
    handler(): void {}
  }
  const handler = Dynamic.prototype.handler;
  const decorators: MethodDecorator[] = [
    requirement.mode === 'authenticated'
      ? AuthenticatedOnly()
      : requirement.mode === 'all'
        ? RequirePermissions(...requirement.permissions)
        : RequireAnyPermission(...requirement.permissions),
  ];
  if (flags.userOnly) decorators.push(UserOnly());
  if (flags.requireMfa) decorators.push(RequireMfa());
  if (flags.allowDuringMfaEnrollment) decorators.push(AllowDuringMfaEnrollment());
  const descriptor = Object.getOwnPropertyDescriptor(Dynamic.prototype, 'handler')!;
  for (const decorate of decorators) decorate(Dynamic.prototype, 'handler', descriptor);
  return Object.assign(handler, { owner: Dynamic });
}

/** The guard's outcome: `ok` or the refusal code. */
function guardDecision(handler: () => void, principal: Principal): string {
  const guard = new PermissionsGuard(new Reflector());
  const owner = (handler as unknown as { owner: new () => unknown }).owner;
  const context = {
    getType: () => 'http',
    getHandler: () => handler,
    getClass: () => owner,
    switchToHttp: () => ({ getRequest: () => ({ principal }) }),
  } as unknown as ExecutionContext;
  try {
    guard.canActivate(context);
    return 'ok';
  } catch (error) {
    const coded = error as CodedForbiddenException;
    expect(coded.message).toBe(AUTHORIZATION_MESSAGES[coded.code as AuthorizationRefusal]);
    return coded.code;
  }
}

const predicateDecision = (
  principal: Principal,
  requirement: AuthzRequirement,
  flags: Flags,
): string => {
  const decision = satisfiesRequirement(principal, requirement, flags);
  return decision.ok ? 'ok' : decision.code;
};

const NONE: Flags = { userOnly: false, requireMfa: false, allowDuringMfaEnrollment: false };

describe('satisfiesRequirement (step AI-1 D5): the predicate of PermissionsGuard', () => {
  const table: Array<[string, Principal, AuthzRequirement, Flags, string]> = [
    ['all held', user({ permissions: new Set(['a', 'b']) }), all('a', 'b'), NONE, 'ok'],
    ['all, one missing', user({ permissions: new Set(['a']) }), all('a', 'b'), NONE, 'forbidden'],
    ['any, one held', user({ permissions: new Set(['b']) }), any('a', 'b'), NONE, 'ok'],
    ['any, none held', user({ permissions: new Set(['c']) }), any('a', 'b'), NONE, 'forbidden'],
    ['authenticated', user({ permissions: new Set() }), AUTH, NONE, 'ok'],
    ['api key, user only', apiKey, AUTH, { ...NONE, userOnly: true }, 'user_required'],
    ['api key, permitted', apiKey, all('user:manage'), NONE, 'ok'],
    ['api key, MFA route', apiKey, AUTH, { ...NONE, requireMfa: true }, 'mfa_required'],
    ['user without MFA', user(), AUTH, { ...NONE, requireMfa: true }, 'mfa_required'],
    ['user with MFA', user({ mfaAuthenticated: true }), AUTH, { ...NONE, requireMfa: true }, 'ok'],
    [
      'enrollment pending',
      user({ mfaEnrollmentRequired: true }),
      AUTH,
      NONE,
      'mfa_enrollment_required',
    ],
    [
      'enrollment pending, allowed',
      user({ mfaEnrollmentRequired: true }),
      AUTH,
      { ...NONE, allowDuringMfaEnrollment: true },
      'ok',
    ],
    [
      'enrollment before user-only (user)',
      user({ mfaEnrollmentRequired: true, permissions: new Set() }),
      all('x'),
      { ...NONE, userOnly: true, requireMfa: true },
      'mfa_enrollment_required',
    ],
    [
      'user-only before MFA (api key)',
      apiKey,
      all('missing'),
      { ...NONE, userOnly: true, requireMfa: true },
      'user_required',
    ],
    [
      'MFA before permissions',
      user({ permissions: new Set() }),
      all('missing'),
      { ...NONE, requireMfa: true },
      'mfa_required',
    ],
  ];

  it.each(table)('%s', (_name, principal, requirement, flags, expected) => {
    expect(predicateDecision(principal, requirement, flags)).toBe(expected);
    expect(guardDecision(routeFor(requirement, flags), principal)).toBe(expected);
  });

  it('agrees with the guard on 2 000 seeded random principals, requirements and flags', () => {
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    // Deterministic xorshift32 so a failure is reproducible.
    let state = 0x9e3779b9;
    const next = (): number => {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      return (state >>> 0) / 0x1_0000_0000;
    };
    const pick = <T>(items: readonly T[]): T => items[Math.floor(next() * items.length)]!;
    const subset = (items: readonly string[]): string[] => items.filter(() => next() < 0.5);
    const KEYS = ['a', 'b', 'c', 'd', 'platform:read'];
    for (let i = 0; i < 2000; i += 1) {
      const permissions = new Set(subset(KEYS));
      const principal: Principal =
        next() < 0.25
          ? { ...apiKey, permissions }
          : user({
              permissions,
              mfaAuthenticated: next() < 0.5,
              mfaEnrollmentRequired: next() < 0.2,
            });
      const listed = subset(KEYS);
      const mode = pick(['all', 'any', 'authenticated'] as const);
      const requirement: AuthzRequirement =
        mode === 'authenticated' || listed.length === 0 ? AUTH : { mode, permissions: listed };
      const flags: Flags = {
        userOnly: next() < 0.4,
        requireMfa: next() < 0.4,
        allowDuringMfaEnrollment: next() < 0.3,
      };
      expect(
        guardDecision(routeFor(requirement, flags), principal),
        JSON.stringify({ i, mode, listed, flags }),
      ).toBe(predicateDecision(principal, requirement, flags));
    }
    vi.restoreAllMocks();
  });
});
