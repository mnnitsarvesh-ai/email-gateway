/**
 * In-memory double of SavedViewsRepository (step 7.2 §2 E4) for the stubbed e2e suites: rows per
 * organization and user, the case-insensitive unique name (P2002 like MySQL), compare-and-set
 * updates. Test-only: never used by production code.
 */
import { randomUUID } from 'node:crypto';
import { Prisma, type SavedViewKind } from '@email-gateway/database';
import type { TestingModuleBuilder } from '@nestjs/testing';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import { TransactionRunner } from '../../src/database/transaction-runner';
import {
  type SavedViewRow,
  SavedViewsRepository,
  type ViewOwner,
} from '../../src/modules/saved-views/saved-views.repository';
import { immediateRunner } from './api-test-app';

export class SavedViewsWorld {
  rows: SavedViewRow[] = [];
  private nextId = 100n;

  add(organizationId: bigint, userId: bigint, over: Partial<SavedViewRow> = {}): SavedViewRow {
    this.nextId += 1n;
    const at = new Date(Date.now() - 1000);
    const row: SavedViewRow = {
      id: this.nextId,
      publicId: randomUUID(),
      organizationId,
      userId,
      kind: 'message_explorer',
      name: `View ${this.nextId}`,
      definition: {
        version: 1,
        filters: { verdict: 'phishing' },
        sort: '-receivedAt',
        range: { kind: 'relative', preset: '24h' },
        columns: null,
      },
      rowVersion: 1,
      createdAt: at,
      updatedAt: at,
      ...over,
    };
    this.rows.push(row);
    return row;
  }
}

const unique = () =>
  new Prisma.PrismaClientKnownRequestError('Unique constraint failed on the constraint', {
    code: 'P2002',
    clientVersion: 'test',
    meta: { target: 'saved_views_organization_id_user_id_kind_name_key' },
  });

export function savedViewsDouble(world: SavedViewsWorld): Partial<SavedViewsRepository> {
  const mine = (scope: TenantScope, owner: ViewOwner) =>
    world.rows.filter(
      (r) => r.organizationId === scope.organizationId && r.userId === owner.userId,
    );
  const nameTaken = (
    scope: TenantScope,
    owner: ViewOwner,
    kind: SavedViewKind,
    name: string,
    except?: bigint,
  ) =>
    mine(scope, owner).some(
      (r) => r.kind === kind && r.name.toLowerCase() === name.toLowerCase() && r.id !== except,
    );
  const findWith = (_db: unknown, scope: TenantScope, owner: ViewOwner, publicId: string) =>
    Promise.resolve(mine(scope, owner).find((r) => r.publicId === publicId) ?? null);
  return {
    list: (scope, owner, kind, page) =>
      Promise.resolve(
        mine(scope, owner)
          .filter((r) => r.kind === kind && (page.beforeId === undefined || r.id < page.beforeId))
          .sort((a, b) => (a.id < b.id ? 1 : -1))
          .slice(0, page.take),
      ),
    find: (scope, owner, publicId) => findWith(null, scope, owner, publicId),
    findWith: findWith,
    lockOwner: () => Promise.resolve(),
    count: (_tx, scope, owner, kind) =>
      Promise.resolve(mine(scope, owner).filter((r) => r.kind === kind).length),
    create: (_tx, scope, owner, data) => {
      if (nameTaken(scope, owner, data.kind, data.name)) return Promise.reject(unique());
      return Promise.resolve(
        world.add(scope.organizationId, owner.userId, {
          kind: data.kind,
          name: data.name,
          definition: data.definition as SavedViewRow['definition'],
        }),
      );
    },
    update: (_tx, scope, owner, publicId, expected, data) => {
      const row = mine(scope, owner).find((r) => r.publicId === publicId);
      if (!row || row.rowVersion !== expected) return Promise.resolve(false);
      if (nameTaken(scope, owner, row.kind, data.name, row.id)) return Promise.reject(unique());
      Object.assign(row, {
        name: data.name,
        definition: data.definition,
        rowVersion: row.rowVersion + 1,
        updatedAt: new Date(),
      });
      return Promise.resolve(true);
    },
    delete: (_tx, scope, owner, publicId) => {
      const before = world.rows.length;
      world.rows = world.rows.filter(
        (r) =>
          !(
            r.organizationId === scope.organizationId &&
            r.userId === owner.userId &&
            r.publicId === publicId
          ),
      );
      return Promise.resolve(world.rows.length < before);
    },
  };
}

/** Overrides the saved views repository and the transaction runner with the doubles. */
export function overrideSavedViews(
  builder: TestingModuleBuilder,
  world: SavedViewsWorld,
): TestingModuleBuilder {
  return builder
    .overrideProvider(SavedViewsRepository)
    .useValue(savedViewsDouble(world))
    .overrideProvider(TransactionRunner)
    .useValue(immediateRunner);
}
