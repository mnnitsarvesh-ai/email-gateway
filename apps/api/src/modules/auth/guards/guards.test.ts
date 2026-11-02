import { randomBytes, randomUUID } from 'node:crypto';
import {
  type ExecutionContext,
  ForbiddenException,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { getContext, runWithContext } from '@email-gateway/logger';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AllowDuringMfaEnrollment,
  AuthenticatedOnly,
  Public,
  RequireAnyPermission,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type {
  ApiKeyPrincipal,
  OverrideContext,
  Principal,
} from '../../../auth-contracts/principal';
import type { AuthenticatedRequest } from '../../../auth-contracts/request';
import type { ApiKeyAuthenticatorService } from '../services/api-key-authenticator.service';
import type { OverrideRequestAuditor } from '../services/override-request-auditor.service';
import type { PlatformOverrideService } from '../services/platform-override.service';
import type { PrincipalSnapshot } from '../services/principal-cache.service';
import type { PrincipalLoaderService } from '../services/principal-loader.service';
import type { SessionService } from '../services/session.service';
import { TokenService } from '../services/token.service';
import { AuthGuard } from './auth.guard';
import { PermissionsGuard } from './permissions.guard';

class Routes {
  @Public()
  open(): void {}

  unannotated(): void {}

  @RequirePermissions('user:read', 'user:manage')
  all(): void {}

  @RequireAnyPermission('organization:read', 'platform:organizations')
  any(): void {}

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

function contextFor(handler: () => void, req: Partial<AuthenticatedRequest>): ExecutionContext {
  const res = { once: vi.fn() };
  return {
    getType: () => 'http',
    getHandler: () => handler,
    getClass: () => Routes,
    switchToHttp: () => ({ getRequest: () => req, getResponse: () => res }),
  } as unknown as ExecutionContext;
}

const ids = {
  user: randomUUID(),
  org: randomUUID(),
  platform: randomUUID(),
  target: randomUUID(),
};

function snapshot(overrides: Partial<PrincipalSnapshot> = {}): PrincipalSnapshot {
  return {
    orgVersion: 0,
    userVersion: '',
    user: { id: '10', publicId: ids.user, status: 'active', deleted: false, mfaEnabled: true },
    org: {
      id: '2',
      publicId: ids.org,
      kind: 'customer',
      status: 'active',
      deleted: false,
      mfaRequired: false,
    },
    permissions: ['user:read', 'organization:read'],
    ...overrides,
  };
}

describe('AuthGuard', () => {
  let tokens: TokenService;
  let snap: PrincipalSnapshot | null;
  let revoked: Set<string>;
  let live: boolean;
  let override: OverrideContext | null;
  let apiKeyPrincipal: ApiKeyPrincipal | null;
  let failing: boolean;
  let attach: ReturnType<typeof vi.fn>;
  let guard: AuthGuard;

  beforeEach(() => {
    tokens = new TokenService({
      AUTH_JWT_SECRET: randomBytes(32).toString('hex'),
      AUTH_JWT_ISSUER: 'iss',
      AUTH_JWT_AUDIENCE: 'aud',
      AUTH_ACCESS_TOKEN_TTL_SECONDS: 600,
    });
    snap = snapshot();
    revoked = new Set();
    live = true;
    override = null;
    apiKeyPrincipal = null;
    failing = false;
    attach = vi.fn();
    const fail = () => {
      if (failing) throw new Error('redis down');
    };
    guard = new AuthGuard(
      new Reflector(),
      tokens,
      {
        isRevoked: (sid: string) => Promise.resolve().then(() => (fail(), revoked.has(sid))),
        isLive: () => Promise.resolve(live),
      } as unknown as SessionService,
      {
        load: () => Promise.resolve().then(() => (fail(), snap)),
      } as unknown as PrincipalLoaderService,
      { resolve: () => Promise.resolve(override) } as unknown as PlatformOverrideService,
      {
        authenticate: () => Promise.resolve(apiKeyPrincipal),
      } as unknown as ApiKeyAuthenticatorService,
      { attach } as unknown as OverrideRequestAuditor,
    );
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => vi.restoreAllMocks());

  const access = async (
    extra: { amr?: Array<'pwd' | 'otp'>; overrideId?: string; org?: string } = {},
  ) =>
    (
      await tokens.issue({
        userPublicId: ids.user,
        organizationPublicId: extra.org ?? snap?.org.publicId ?? ids.org,
        sessionId: 'b5f2c4a8-1111-4222-8333-444455556666',
        amr: extra.amr ?? ['pwd'],
        ...(extra.overrideId && { overrideId: extra.overrideId }),
      })
    ).token;

  const run = async (headers: Record<string, string>, handler = Routes.prototype.all) => {
    const req = { headers } as unknown as AuthenticatedRequest;
    await guard.canActivate(contextFor(handler, req));
    return req;
  };

  it('lets public routes through without credentials', async () => {
    await expect(
      guard.canActivate(contextFor(Routes.prototype.open, { headers: {} })),
    ).resolves.toBe(true);
  });

  it('requires exactly one well-formed credential', async () => {
    await expect(run({})).rejects.toThrow(UnauthorizedException);
    await expect(run({ authorization: 'Basic abc' })).rejects.toThrow(UnauthorizedException);
    await expect(run({ authorization: 'Bearer not-a-jwt' })).rejects.toThrow(UnauthorizedException);
    await expect(
      run({ authorization: `Bearer ${await access()}`, 'x-api-key': 'egk_x' }),
    ).rejects.toThrow(UnauthorizedException);
  });

  it('attaches the user principal, the member scope and the log tenant', async () => {
    await runWithContext({ correlationId: 'corr-guard-test' }, async () => {
      const req = await run({ authorization: `Bearer ${await access({ amr: ['pwd', 'otp'] })}` });
      expect(req.principal).toMatchObject({
        kind: 'user',
        userId: 10n,
        organizationId: 2n,
        mfaAuthenticated: true,
        mfaEnrollmentRequired: false,
      });
      expect(req.tenantScope).toMatchObject({ organizationId: 2n, via: 'member' });
      expect(getContext()?.tenantId).toBe('2');
    });
    expect(attach).not.toHaveBeenCalled();
  });

  it('rejects deny-listed sessions, org mismatches and inactive users or organizations', async () => {
    const token = await access();
    revoked.add('b5f2c4a8-1111-4222-8333-444455556666');
    await expect(run({ authorization: `Bearer ${token}` })).rejects.toThrow(UnauthorizedException);
    revoked.clear();
    await expect(
      run({ authorization: `Bearer ${await access({ org: randomUUID() })}` }),
    ).rejects.toThrow(UnauthorizedException);
    snap = snapshot({ user: { ...snapshot().user, status: 'disabled' } });
    await expect(run({ authorization: `Bearer ${token}` })).rejects.toThrow(UnauthorizedException);
    snap = snapshot({ org: { ...snapshot().org, status: 'suspended' } });
    await expect(run({ authorization: `Bearer ${token}` })).rejects.toThrow(UnauthorizedException);
    snap = null;
    await expect(run({ authorization: `Bearer ${token}` })).rejects.toThrow(UnauthorizedException);
  });

  it('derives the enrollment restriction from the current organization policy', async () => {
    snap = snapshot({
      user: { ...snapshot().user, mfaEnabled: false },
      org: { ...snapshot().org, mfaRequired: true },
    });
    const req = await run({ authorization: `Bearer ${await access()}` });
    expect(req.principal).toMatchObject({ mfaEnrollmentRequired: true });
  });

  describe('platform override', () => {
    const overrideId = randomUUID();
    beforeEach(() => {
      snap = snapshot({
        org: { ...snapshot().org, publicId: ids.platform, kind: 'platform' },
        permissions: [
          'platform:tenant_override',
          'platform:organizations',
          'user:read',
          'audit:read',
        ],
      });
      override = {
        id: overrideId,
        reason: 'Customer ticket 4711',
        targetOrganizationId: 42n,
        targetOrganizationPublicId: ids.target,
        expiresAt: new Date(Date.now() + 600_000),
      };
    });

    it('scopes to the target, intersects permissions with tenant permissions and audits', async () => {
      const req = await run({
        authorization: `Bearer ${await access({ amr: ['pwd', 'otp'], overrideId })}`,
      });
      const principal = req.principal as Principal & { kind: 'user' };
      expect([...principal.permissions].sort()).toEqual(['audit:read', 'user:read']);
      expect(principal.override?.id).toBe(overrideId);
      expect(req.tenantScope).toMatchObject({ organizationId: 42n, via: 'platform_override' });
      expect(attach).toHaveBeenCalledTimes(1);
    });

    it('rejects ended overrides, non-MFA tokens, revoked sessions and lost permissions', async () => {
      const mfaToken = await access({ amr: ['pwd', 'otp'], overrideId });
      override = null;
      await expect(run({ authorization: `Bearer ${mfaToken}` })).rejects.toThrow(
        UnauthorizedException,
      );
      override = {
        id: overrideId,
        reason: 'r',
        targetOrganizationId: 42n,
        targetOrganizationPublicId: ids.target,
        expiresAt: new Date(Date.now() + 1000),
      };
      await expect(
        run({ authorization: `Bearer ${await access({ overrideId })}` }),
      ).rejects.toThrow(UnauthorizedException);
      live = false;
      await expect(run({ authorization: `Bearer ${mfaToken}` })).rejects.toThrow(
        UnauthorizedException,
      );
      live = true;
      snap = snapshot({ org: snap!.org, permissions: ['user:read'] });
      await expect(run({ authorization: `Bearer ${mfaToken}` })).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  it('authenticates API keys through the API-key path', async () => {
    apiKeyPrincipal = {
      kind: 'api_key',
      apiKeyId: 5n,
      apiKeyPublicId: randomUUID(),
      organizationId: 7n,
      organizationPublicId: randomUUID(),
      permissions: new Set(['user:read']),
    };
    const req = await run({ 'x-api-key': 'egk_anything' });
    expect(req.tenantScope).toMatchObject({ organizationId: 7n, via: 'api_key' });
    apiKeyPrincipal = null;
    await expect(run({ 'x-api-key': 'egk_anything' })).rejects.toThrow(UnauthorizedException);
  });

  it('fails closed with 503 when the key-value store is unavailable', async () => {
    const token = await access();
    failing = true;
    await expect(run({ authorization: `Bearer ${token}` })).rejects.toThrow(
      ServiceUnavailableException,
    );
  });
});

describe('PermissionsGuard', () => {
  const guard = new PermissionsGuard(new Reflector());
  const user = (overrides: Partial<Principal & { kind: 'user' }> = {}): Principal => ({
    kind: 'user',
    userId: 1n,
    userPublicId: ids.user,
    organizationId: 2n,
    organizationPublicId: ids.org,
    organizationKind: 'customer',
    sessionId: randomUUID(),
    mfaAuthenticated: false,
    mfaEnrollmentRequired: false,
    permissions: new Set(['user:read', 'organization:read']),
    ...overrides,
  });
  const apiKey: Principal = {
    kind: 'api_key',
    apiKeyId: 1n,
    apiKeyPublicId: randomUUID(),
    organizationId: 2n,
    organizationPublicId: ids.org,
    permissions: new Set(['user:read', 'user:manage']),
  };
  const check = (handler: () => void, principal?: Principal) =>
    guard.canActivate(contextFor(handler, { principal } as Partial<AuthenticatedRequest>));

  beforeEach(() => {
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
  });
  afterEach(() => vi.restoreAllMocks());

  it('passes public routes', () => {
    expect(check(Routes.prototype.open)).toBe(true);
  });

  it('denies and logs a route without a requirement (fail closed)', () => {
    expect(() => check(Routes.prototype.unannotated, user())).toThrow(ForbiddenException);
    expect(Logger.prototype.error).toHaveBeenCalledWith(
      expect.objectContaining({ handler: 'unannotated' }),
    );
  });

  it('checks all / any permission requirements', () => {
    expect(() => check(Routes.prototype.all, user())).toThrow(ForbiddenException);
    expect(check(Routes.prototype.all, apiKey)).toBe(true);
    expect(check(Routes.prototype.any, user())).toBe(true);
    expect(() => check(Routes.prototype.any, apiKey)).toThrow(ForbiddenException);
  });

  it('refuses API keys on user-only routes', () => {
    expect(check(Routes.prototype.userOnly, user())).toBe(true);
    expect(() => check(Routes.prototype.userOnly, apiKey)).toThrow(
      'This operation requires a user',
    );
  });

  it('requires an MFA session for step-up routes', () => {
    expect(() => check(Routes.prototype.stepUp, user())).toThrow('MFA required');
    expect(() => check(Routes.prototype.stepUp, apiKey)).toThrow('MFA required');
    expect(check(Routes.prototype.stepUp, user({ mfaAuthenticated: true }))).toBe(true);
  });

  it('restricts principals that must enroll in MFA to enrollment routes', () => {
    const enrolling = user({ mfaEnrollmentRequired: true });
    expect(check(Routes.prototype.enrollment, enrolling)).toBe(true);
    expect(() => check(Routes.prototype.any, enrolling)).toThrow('MFA enrollment required');
  });

  it('401 when no principal was attached', () => {
    expect(() => check(Routes.prototype.any)).toThrow(UnauthorizedException);
  });
});
