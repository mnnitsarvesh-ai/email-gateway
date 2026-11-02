import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { SYSTEM_ROLES, TENANT_PERMISSIONS } from '@email-gateway/database';
import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../audit/audit.service';
import type { ApiKeyPrincipal, UserPrincipal } from '../../auth-contracts/principal';
import { systemScope } from '../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../database/transaction-runner';
import type { OrganizationLimitsService } from '../../tenancy/organization-limits.service';
import type { PrincipalCacheService } from '../auth/services/principal-cache.service';
import type { RoleRecord, RolesRepository } from './roles.repository';
import { RolesService, seesPlatformPermissions } from './roles.service';

const scope = systemScope(7n);
const client = { ip: '203.0.113.9', userAgent: null };
const now = new Date('2026-11-02T10:00:00Z');

function systemRole(key: string, id: bigint): RoleRecord {
  const def = SYSTEM_ROLES.find((r) => r.key === key)!;
  return {
    id,
    organizationId: null,
    key,
    name: def.name,
    description: def.description,
    isSystem: true,
    permissions: [...def.permissions].sort(),
    createdAt: now,
    updatedAt: now,
  };
}

function customRole(key: string, permissions: string[], id = 100n): RoleRecord {
  return {
    id,
    organizationId: 7n,
    key,
    name: key,
    description: null,
    isSystem: false,
    permissions: [...permissions].sort(),
    createdAt: now,
    updatedAt: now,
  };
}

function user(permissions: Iterable<string>, extra: Partial<UserPrincipal> = {}): UserPrincipal {
  return {
    kind: 'user',
    userId: 1n,
    userPublicId: '0190a0b0-0000-7000-8000-000000000001',
    organizationId: 7n,
    organizationPublicId: '0190a0b0-0000-7000-8000-000000000007',
    organizationKind: 'customer',
    sessionId: '3f0e8c1a-2b3c-4d5e-8f90-a1b2c3d4e5f6',
    mfaAuthenticated: true,
    mfaEnrollmentRequired: false,
    permissions: new Set(permissions),
    ...extra,
  };
}

const orgAdmin = user(TENANT_PERMISSIONS);

function setup(options: { kind?: 'customer' | 'platform'; roles?: RoleRecord[] } = {}) {
  const roles = options.roles ?? [
    systemRole('super_admin', 1n),
    systemRole('platform_admin', 2n),
    systemRole('organization_admin', 3n),
    systemRole('read_only_user', 8n),
  ];
  const repo = {
    listPermissions: vi.fn(() =>
      Promise.resolve([
        { id: 1n, key: 'platform:operations', description: 'p', category: 'platform' },
        { id: 2n, key: 'user:read', description: 'u', category: 'user' },
      ]),
    ),
    permissionIds: vi.fn((keys: readonly string[]) =>
      Promise.resolve(
        new Map(
          keys
            .filter((k) => (TENANT_PERMISSIONS as readonly string[]).includes(k))
            .map((k, i) => [k, BigInt(i + 1)]),
        ),
      ),
    ),
    organizationKind: vi.fn(() => Promise.resolve(options.kind ?? 'customer')),
    listVisible: vi.fn(() => Promise.resolve(roles)),
    findVisibleByKey: vi.fn((_s: unknown, key: string) =>
      Promise.resolve(roles.find((r) => r.key === key) ?? null),
    ),
    findVisibleByKeys: vi.fn((_s: unknown, keys: readonly string[]) =>
      Promise.resolve(roles.filter((r) => keys.includes(r.key))),
    ),
    createCustom: vi.fn(
      (_tx: unknown, _s: unknown, data: { key: string; permissionIds: bigint[] }) =>
        Promise.resolve(customRole(data.key, ['user:read'])),
    ),
    updateCustom: vi.fn(),
    deleteCustom: vi.fn(() => Promise.resolve(true)),
    countAssignments: vi.fn(() => Promise.resolve(0)),
    countActiveAdministrators: vi.fn(() => Promise.resolve(1)),
  };
  const tx = {};
  const transactions = { run: vi.fn((fn: (t: unknown) => Promise<unknown>) => fn(tx)) };
  const limits = { lockOrganization: vi.fn(() => Promise.resolve()) };
  const audit = {
    record: vi.fn(() => Promise.resolve()),
    actorFrom: vi.fn(() => ({ type: 'user', id: 'actor' })),
  };
  const cache = { invalidateOrganization: vi.fn(() => Promise.resolve()) };
  const service = new RolesService(
    repo as unknown as RolesRepository,
    transactions as unknown as TransactionRunner,
    limits as unknown as OrganizationLimitsService,
    audit as unknown as AuditService,
    cache as unknown as PrincipalCacheService,
  );
  return { service, repo, audit, cache, limits };
}

describe('permission catalog visibility', () => {
  it('shows platform permissions only to platform users outside an override', async () => {
    const platformUser = user([], { organizationKind: 'platform' });
    expect(seesPlatformPermissions(platformUser)).toBe(true);
    expect(seesPlatformPermissions(user([]))).toBe(false);
    expect(
      seesPlatformPermissions({
        ...platformUser,
        override: {
          id: 'o',
          reason: 'r',
          targetOrganizationId: 9n,
          targetOrganizationPublicId: 'x',
          expiresAt: now,
        },
      }),
    ).toBe(false);
    const key: ApiKeyPrincipal = {
      kind: 'api_key',
      apiKeyId: 1n,
      apiKeyPublicId: 'k',
      organizationId: 7n,
      organizationPublicId: 'o',
      permissions: new Set(),
    };
    expect(seesPlatformPermissions(key)).toBe(false);

    const { service } = setup();
    expect((await service.listPermissions(user([]))).map((p) => p.key)).toEqual(['user:read']);
    expect((await service.listPermissions(platformUser)).map((p) => p.key)).toEqual([
      'platform:operations',
      'user:read',
    ]);
  });
});

describe('role listing', () => {
  it('hides platform roles from customer organizations', async () => {
    const { service } = setup({
      roles: [systemRole('super_admin', 1n), systemRole('read_only_user', 8n)],
    });
    expect((await service.list(scope)).map((r) => r.key)).toEqual(['read_only_user']);
    await expect(service.get(scope, 'super_admin')).rejects.toThrow(NotFoundException);
  });

  it('shows platform roles in the platform organization', async () => {
    const { service } = setup({ kind: 'platform', roles: [systemRole('super_admin', 1n)] });
    expect((await service.list(scope)).map((r) => r.key)).toEqual(['super_admin']);
  });
});

describe('custom role creation', () => {
  const body = { key: 'mail_ops', name: 'Mail ops', permissions: ['user:read'] };

  it('creates and audits a custom role', async () => {
    const { service, audit } = setup();
    const view = await service.create(orgAdmin, scope, body, client);
    expect(view).toMatchObject({ key: 'mail_ops', system: false, permissions: ['user:read'] });
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'role.created', resourceId: 'mail_ops' }),
      expect.anything(),
    );
  });

  it('reserves system keys (409), refuses platform permissions (400) and escalation (403)', async () => {
    const { service } = setup();
    await expect(
      service.create(orgAdmin, scope, { ...body, key: 'organization_admin' }, client),
    ).rejects.toThrow(ConflictException);
    await expect(
      service.create(orgAdmin, scope, { ...body, permissions: ['platform:operations'] }, client),
    ).rejects.toThrow(BadRequestException);
    await expect(
      service.create(
        user(['role:manage']),
        scope,
        { ...body, permissions: ['user:manage'] },
        client,
      ),
    ).rejects.toThrow(ForbiddenException);
  });

  it('answers 409 for a duplicate key', async () => {
    const { service, repo } = setup();
    repo.createCustom.mockResolvedValueOnce(null as unknown as RoleRecord);
    await expect(service.create(orgAdmin, scope, body, client)).rejects.toThrow(ConflictException);
  });
});

describe('custom role changes', () => {
  const admins = customRole('admins', ['user:manage', 'user:read'], 100n);

  it('refuses to edit or delete system roles', async () => {
    const { service } = setup();
    await expect(
      service.update(
        orgAdmin,
        scope,
        'organization_admin',
        { name: 'x', permissions: ['user:read'] },
        client,
      ),
    ).rejects.toThrow(ConflictException);
    await expect(service.remove(orgAdmin, scope, 'read_only_user', client)).rejects.toThrow(
      ConflictException,
    );
  });

  it('refuses removing user:manage from the last administrators', async () => {
    const { service, repo, cache } = setup({ roles: [admins] });
    repo.updateCustom.mockResolvedValue(customRole('admins', ['user:read']));
    repo.countActiveAdministrators.mockResolvedValueOnce(1).mockResolvedValueOnce(0);
    await expect(
      service.update(orgAdmin, scope, 'admins', { name: 'a', permissions: ['user:read'] }, client),
    ).rejects.toThrow(ConflictException);
    expect(cache.invalidateOrganization).not.toHaveBeenCalled();
  });

  it('requires the old and new permissions (no escalation by editing)', async () => {
    const { service } = setup({ roles: [admins] });
    await expect(
      service.update(
        user(['role:manage', 'user:read']),
        scope,
        'admins',
        { name: 'a', permissions: ['user:read'] },
        client,
      ),
    ).rejects.toThrow(ForbiddenException);
  });

  it('invalidates the organization cache after a permission change', async () => {
    const { service, repo, cache, limits } = setup({ roles: [admins] });
    repo.updateCustom.mockResolvedValue(
      customRole('admins', ['user:manage', 'user:read', 'role:read']),
    );
    await service.update(
      orgAdmin,
      scope,
      'admins',
      { name: 'a', permissions: ['role:read', 'user:manage', 'user:read'] },
      client,
    );
    expect(limits.lockOrganization).toHaveBeenCalled();
    expect(cache.invalidateOrganization).toHaveBeenCalledWith(7n);
  });

  it('refuses to delete an assigned role', async () => {
    const { service, repo } = setup({ roles: [admins] });
    repo.countAssignments.mockResolvedValue(2);
    await expect(service.remove(orgAdmin, scope, 'admins', client)).rejects.toThrow(/assigned/);
    expect(repo.deleteCustom).not.toHaveBeenCalled();
  });

  it('answers 404 for an unknown role', async () => {
    const { service } = setup();
    await expect(service.remove(orgAdmin, scope, 'nope_role', client)).rejects.toThrow(
      NotFoundException,
    );
  });
});

describe('role assignment resolution', () => {
  it('rejects unknown keys and platform roles in customer organizations', async () => {
    const { service } = setup();
    await expect(
      service.resolveForAssignment({} as never, scope, ['ghost_role']),
    ).rejects.toMatchObject({
      response: { message: [expect.stringContaining('ghost_role')] },
    });
    await expect(
      service.resolveForAssignment({} as never, scope, ['platform_admin']),
    ).rejects.toThrow(BadRequestException);
    const roles = await service.resolveForAssignment({} as never, scope, [
      'organization_admin',
      'organization_admin',
    ]);
    expect(roles.map((r) => r.key)).toEqual(['organization_admin']);
  });
});
