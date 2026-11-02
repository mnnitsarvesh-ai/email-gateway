import { type ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { describe, expect, it } from 'vitest';
import {
  ALLOW_DURING_MFA_ENROLLMENT_KEY,
  AllowDuringMfaEnrollment,
  AUTHZ_KEY,
  AuthenticatedOnly,
  IS_PUBLIC_KEY,
  Public,
  principalFromContext,
  REQUIRE_MFA_KEY,
  RequireAnyPermission,
  RequireMfa,
  RequirePermissions,
  scopeFromContext,
  USER_ONLY_KEY,
  UserOnly,
} from './decorators';
import type { ApiKeyPrincipal } from './principal';
import { systemScope } from './tenant-scope';

class Routes {
  @Public()
  open(): void {}
  @RequirePermissions('user:read', 'user:manage')
  all(): void {}
  @RequireAnyPermission('organization:read', 'platform:organizations')
  any(): void {}
  @AuthenticatedOnly()
  @UserOnly()
  @RequireMfa()
  @AllowDuringMfaEnrollment()
  self(): void {}
}

const reflector = new Reflector();

describe('authorization metadata', () => {
  it('uses distinct keys', () => {
    const keys = [
      IS_PUBLIC_KEY,
      AUTHZ_KEY,
      USER_ONLY_KEY,
      REQUIRE_MFA_KEY,
      ALLOW_DURING_MFA_ENROLLMENT_KEY,
    ];
    expect(new Set(keys).size).toBe(keys.length);
    expect(AUTHZ_KEY).toBe('authz:requirement');
  });

  it('records the requirement of each route', () => {
    expect(reflector.get(IS_PUBLIC_KEY, Routes.prototype.open)).toBe(true);
    expect(reflector.get(AUTHZ_KEY, Routes.prototype.all)).toEqual({
      mode: 'all',
      permissions: ['user:read', 'user:manage'],
    });
    expect(reflector.get(AUTHZ_KEY, Routes.prototype.any)).toEqual({
      mode: 'any',
      permissions: ['organization:read', 'platform:organizations'],
    });
    expect(reflector.get(AUTHZ_KEY, Routes.prototype.self)).toEqual({ mode: 'authenticated' });
    expect(reflector.get(USER_ONLY_KEY, Routes.prototype.self)).toBe(true);
    expect(reflector.get(REQUIRE_MFA_KEY, Routes.prototype.self)).toBe(true);
    expect(reflector.get(ALLOW_DURING_MFA_ENROLLMENT_KEY, Routes.prototype.self)).toBe(true);
    expect(reflector.get(AUTHZ_KEY, Routes.prototype.open)).toBeUndefined();
  });

  it('refuses an empty permission list at decoration time', () => {
    expect(() => RequirePermissions()).toThrow();
    expect(() => RequireAnyPermission('')).toThrow();
  });
});

function contextWith(req: object): ExecutionContext {
  return { switchToHttp: () => ({ getRequest: () => req }) } as unknown as ExecutionContext;
}

describe('CurrentPrincipal / CurrentScope resolution', () => {
  const principal: ApiKeyPrincipal = {
    kind: 'api_key',
    apiKeyId: 1n,
    apiKeyPublicId: '0190a0b0-0000-7000-8000-000000000001',
    organizationId: 2n,
    organizationPublicId: '0190a0b0-0000-7000-8000-000000000002',
    permissions: new Set(),
  };

  it('returns what the guard attached', () => {
    const scope = systemScope(2n);
    const ctx = contextWith({ principal, tenantScope: scope });
    expect(principalFromContext(ctx)).toBe(principal);
    expect(scopeFromContext(ctx)).toBe(scope);
  });

  it('throws 401 when the guard did not run', () => {
    expect(() => principalFromContext(contextWith({}))).toThrow(UnauthorizedException);
    expect(() => scopeFromContext(contextWith({}))).toThrow(UnauthorizedException);
  });
});
