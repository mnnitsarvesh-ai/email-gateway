import type { PrismaReadService, PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { systemScope } from '../../auth-contracts/tenant-scope';
import { ApiKeysRepository } from '../api-keys/api-keys.repository';
import { LoginEventsRepository } from '../login-audit/login-events.repository';
import { RolesRepository } from '../roles/roles.repository';
import { UsersRepository } from './users.repository';

/**
 * Every identity-administration query of a tenant-owned table carries the scope's organization
 * (D9). Global tables (`permissions`) and the organization row itself are listed explicitly.
 */

interface Call {
  client: 'writer' | 'reader';
  model: string;
  method: string;
  args: { where?: unknown; data?: unknown };
}

const DEFAULTS: Record<string, unknown> = {
  findMany: [],
  findFirst: null,
  findFirstOrThrow: { id: 1n, publicId: 'x' },
  count: 0,
  updateMany: { count: 1 },
  deleteMany: { count: 1 },
  createMany: { count: 1 },
  create: { id: 1n, publicId: 'x', permissions: [], userRoles: [] },
};

function recordingClients() {
  const calls: Call[] = [];
  const make = (client: Call['client']) =>
    new Proxy(
      {},
      {
        get: (_t, model: string) =>
          new Proxy(
            {},
            {
              get: (_m, method: string) => (args: Call['args']) => {
                calls.push({ client, model, method, args });
                return Promise.resolve(DEFAULTS[method] ?? null);
              },
            },
          ),
      },
    );
  return {
    writer: make('writer') as unknown as PrismaService & Prisma.TransactionClient,
    reader: { client: make('reader') } as unknown as PrismaReadService,
    calls,
  };
}

function scopedTo(value: unknown, id: bigint): boolean {
  if (value === null || typeof value !== 'object') return false;
  if ((value as { organizationId?: unknown }).organizationId === id) return true;
  return Object.values(value).some((v) => scopedTo(v, id));
}

const SCOPE = systemScope(42n);
const GLOBAL_MODELS = new Set(['permission']);

function expectScoped(calls: Call[]): void {
  expect(calls.length).toBeGreaterThan(0);
  for (const call of calls) {
    const label = `${call.model}.${call.method}`;
    if (GLOBAL_MODELS.has(call.model)) continue;
    if (call.model === 'organization') {
      expect(call.args.where, label).toEqual({ id: 42n });
    } else if (call.model === 'rolePermission') {
      // Only after the role was matched in the scope (updateCustom), keyed by its id.
      expect(call.args.where ?? call.args.data, label).toBeDefined();
    } else if (call.method === 'create') {
      expect(scopedTo(call.args.data, 42n), label).toBe(true);
    } else if (call.method === 'createMany') {
      for (const row of call.args.data as unknown[]) expect(scopedTo(row, 42n), label).toBe(true);
    } else {
      expect(scopedTo(call.args.where, 42n), label).toBe(true);
    }
  }
}

describe('identity repositories are tenant-scoped (D9)', () => {
  it('users', async () => {
    const { writer, reader, calls } = recordingClients();
    const repo = new UsersRepository(writer, reader);
    const now = new Date();
    await repo.list(SCOPE, { status: 'active', q: 'a', role: 'read_only_user' }, { take: 26 });
    await repo.findByPublicId(SCOPE, 'p');
    await repo.findIdByPublicId(SCOPE, 'p');
    await repo.publicIds(SCOPE, [1n]);
    await repo.findAnyByEmail(writer, SCOPE, 'a@b.test');
    await repo.countNonDeleted(writer, SCOPE);
    await repo.createInvited(writer, SCOPE, { email: 'a@b.test', displayName: 'A', now });
    await repo.reinstateAsInvited(writer, SCOPE, 1n, { displayName: 'A', now });
    await repo.replaceRoles(writer, SCOPE, 1n, [2n], null);
    await repo.updateProfile(writer, SCOPE, 1n, { email: 'b@b.test' });
    await repo.setStatus(writer, SCOPE, 1n, {
      status: 'disabled',
      reason: null,
      now,
      clearLockout: false,
    });
    await repo.softDelete(writer, SCOPE, 1n, now);
    await repo.resetMfa(writer, SCOPE, 1n);
    await repo.consumeTokens(writer, SCOPE, 1n, ['invitation'], now);
    await repo.organizationName(SCOPE);
    expectScoped(calls);
    expect(calls.filter((c) => c.client === 'reader').map((c) => c.method)).toEqual([
      'findMany',
      'findFirst',
      'findMany',
    ]);
  });

  it('roles', async () => {
    const { writer, reader, calls } = recordingClients();
    const repo = new RolesRepository(writer, reader);
    await repo.organizationKind(SCOPE);
    await repo.listVisible(SCOPE);
    await repo.findVisibleByKey(SCOPE, 'mail_ops');
    await repo.findVisibleByKeys(SCOPE, ['mail_ops']);
    await repo.createCustom(writer, SCOPE, {
      key: 'mail_ops',
      name: 'M',
      description: null,
      permissionIds: [1n],
    });
    await repo.updateCustom(writer, SCOPE, 5n, { name: 'M', description: null, permissionIds: [] });
    await repo.deleteCustom(writer, SCOPE, 5n);
    await repo.countAssignments(writer, SCOPE, 5n);
    await repo.countActiveAdministrators(writer, SCOPE);
    expectScoped(calls);
    // Visible roles: system roles (no organization) OR the scope's own custom roles, never others.
    const visible = calls.find((c) => c.method === 'findMany' && c.model === 'role')!;
    expect(
      JSON.stringify(visible.args.where, (_k, v: unknown) => (typeof v === 'bigint' ? `${v}n` : v)),
    ).toContain('"organizationId":null,"isSystem":true');
  });

  it('API keys never select the hash and are scoped', async () => {
    const { writer, reader, calls } = recordingClients();
    const repo = new ApiKeysRepository(writer, reader);
    await repo.list(SCOPE, { take: 26 });
    await repo.findByPublicId(SCOPE, 'p');
    await repo.create(writer, SCOPE, {
      name: 'n',
      keyPrefix: 'egk_x',
      keyHash: 'h',
      scopes: [],
      createdByUserId: 1n,
      expiresAt: new Date(),
    });
    await repo.revoke(writer, SCOPE, 1n, new Date());
    expectScoped(calls);
    for (const call of calls) {
      const select = (call.args as { select?: Record<string, unknown> }).select;
      if (select) expect(select.keyHash).toBeUndefined();
    }
  });

  it('login events', async () => {
    const { reader, calls } = recordingClients();
    const repo = new LoginEventsRepository(reader);
    await repo.list(
      SCOPE,
      { from: new Date(0), to: new Date(), outcome: 'failure', userId: 3n },
      { take: 26, beforeId: 10n },
    );
    expectScoped(calls);
    expect(calls[0]!.client).toBe('reader');
  });
});
