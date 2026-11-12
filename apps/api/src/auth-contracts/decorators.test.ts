import { type ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { describe, expect, it } from 'vitest';
import {
  ALLOW_DURING_MFA_ENROLLMENT_KEY,
  AllowDuringMfaEnrollment,
  AUTHZ_KEY,
  AuthenticatedOnly,
  CURSOR_LIST_KEY,
  CursorList,
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

describe('OpenAPI extensions of the authorization and list decorators (step 6.1 D14)', () => {
  const API_EXTENSION = 'swagger/apiExtension';

  class Documented {
    @RequirePermissions('message:read')
    one(): void {}
    @RequireAnyPermission('a:read', 'b:read')
    either(): void {}
    @CursorList('v1')
    @RequirePermissions('message:read')
    list(): void {}
    @CursorList('v0')
    @RequirePermissions('message:read')
    legacy(): void {}
  }

  it('documents the requirement as x-eg-permissions and keeps the AUTHZ_KEY metadata', () => {
    expect(Reflect.getMetadata(API_EXTENSION, Documented.prototype.one)).toEqual({
      'x-eg-permissions': { mode: 'all', permissions: ['message:read'] },
    });
    expect(Reflect.getMetadata(API_EXTENSION, Documented.prototype.either)).toEqual({
      'x-eg-permissions': { mode: 'any', permissions: ['a:read', 'b:read'] },
    });
    expect(reflector.get(AUTHZ_KEY, Documented.prototype.one)).toEqual({
      mode: 'all',
      permissions: ['message:read'],
    });
  });

  it('records the cursor encoding of a list (metadata and x-eg-cursor)', () => {
    expect(reflector.get(CURSOR_LIST_KEY, Documented.prototype.list)).toBe('v1');
    expect(reflector.get(CURSOR_LIST_KEY, Documented.prototype.legacy)).toBe('v0');
    expect(Reflect.getMetadata(API_EXTENSION, Documented.prototype.list)).toMatchObject({
      'x-eg-cursor': 'v1',
    });
    expect(() => CursorList('v2' as 'v1')).toThrow();
  });
});
