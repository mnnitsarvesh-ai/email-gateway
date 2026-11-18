import { randomBytes } from 'node:crypto';
import { LocalRootKeyProvider, unwrapTenantKey, wrapTenantKey } from '@email-gateway/archive';
import { Prisma } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { metricValue, silentLogger, testMetrics } from '../archive.test-support';
import { ROOT_REWRAP_ACTION, RootRewrapJob } from './root-rewrap';
import { TenantKeyService, TenantKeyUnavailableError } from './tenant-keys';

const ORG = 42n;
const hex = () => randomBytes(32).toString('hex');

interface KeyRow {
  id: bigint;
  organizationId: bigint;
  version: number;
  status: 'active' | 'retired' | 'destroyed';
  wrappedKey: string | null;
  rootKeyId: string;
}

/** archive_encryption_keys in memory, with the unique (organization_id, version). */
function keyTable(rows: KeyRow[] = [], options: { raceOnCreate?: () => Promise<void> } = {}) {
  let creates = 0;
  return {
    rows,
    get creates() {
      return creates;
    },
    archiveEncryptionKey: {
      findFirst: ({ where }: { where: { organizationId: bigint } }) =>
        Promise.resolve(
          rows
            .filter(
              (r) =>
                r.organizationId === where.organizationId &&
                r.status === 'active' &&
                r.wrappedKey !== null,
            )
            .sort((a, b) => b.version - a.version)[0] ?? null,
        ),
      count: ({ where }: { where: { organizationId: bigint } }) =>
        Promise.resolve(rows.filter((r) => r.organizationId === where.organizationId).length),
      findUnique: ({
        where,
      }: {
        where: { organizationId_version: { organizationId: bigint; version: number } };
      }) =>
        Promise.resolve(
          rows.find(
            (r) =>
              r.organizationId === where.organizationId_version.organizationId &&
              r.version === where.organizationId_version.version,
          ) ?? null,
        ),
      create: async ({ data }: { data: Omit<KeyRow, 'id'> }) => {
        creates += 1;
        await options.raceOnCreate?.();
        if (
          rows.some((r) => r.organizationId === data.organizationId && r.version === data.version)
        ) {
          throw new Prisma.PrismaClientKnownRequestError('dup', {
            code: 'P2002',
            clientVersion: 'test',
          });
        }
        rows.push({ ...data, id: BigInt(rows.length + 1) });
        return { id: BigInt(rows.length) };
      },
    },
  };
}

describe('TenantKeyService (A8, A9)', () => {
  const provider = LocalRootKeyProvider.fromConfig({
    ARCHIVE_ROOT_KEY: hex(),
    ARCHIVE_ROOT_KEY_ID: 'r1',
  });

  it('creates version 1 on first use (wrapped under the root key) and caches it', async () => {
    const table = keyTable();
    const service = new TenantKeyService(table as never, provider, { cacheTtlMs: 60_000 });
    const a = await service.active(ORG);
    const b = await service.active(ORG);
    expect(a.version).toBe(1);
    expect(a.key.equals(b.key)).toBe(true);
    expect(table.creates).toBe(1);
    expect(table.rows[0]).toMatchObject({
      version: 1,
      status: 'active',
      rootKeyId: 'r1',
      algorithm: 'aes-256-gcm',
    });
    const unwrapped = await unwrapTenantKey(provider, table.rows[0]!.wrappedKey!, {
      organizationId: ORG,
      version: 1,
    });
    expect(unwrapped.key.equals(a.key)).toBe(true);
  });

  it('the loser of a creation race re-reads the winner', async () => {
    const winnerKey = randomBytes(32);
    const winner: KeyRow = {
      id: 1n,
      organizationId: ORG,
      version: 1,
      status: 'active',
      wrappedKey: await wrapTenantKey(provider, { organizationId: ORG, version: 1 }, winnerKey),
      rootKeyId: 'r1',
    };
    const table = keyTable([], {
      raceOnCreate: () => Promise.resolve(void table.rows.push(winner)),
    });
    const service = new TenantKeyService(table as never, provider, { cacheTtlMs: 60_000 });
    expect((await service.active(ORG)).key.equals(winnerKey)).toBe(true);
  });

  it('uses the newest active version after a rotation (after the cache TTL), unwraps retired ones, refuses destroyed', async () => {
    const k1 = randomBytes(32);
    const k2 = randomBytes(32);
    const rows: KeyRow[] = [
      {
        id: 1n,
        organizationId: ORG,
        version: 1,
        status: 'active',
        wrappedKey: await wrapTenantKey(provider, { organizationId: ORG, version: 1 }, k1),
        rootKeyId: 'r1',
      },
    ];
    let now = 0;
    const service = new TenantKeyService(keyTable(rows) as never, provider, {
      cacheTtlMs: 1_000,
      now: () => now,
    });
    expect((await service.active(ORG)).version).toBe(1);
    rows[0]!.status = 'retired';
    rows.push({
      id: 2n,
      organizationId: ORG,
      version: 2,
      status: 'active',
      wrappedKey: await wrapTenantKey(provider, { organizationId: ORG, version: 2 }, k2),
      rootKeyId: 'r1',
    });
    expect((await service.active(ORG)).version).toBe(1); // cached
    now = 2_000;
    expect((await service.active(ORG)).version).toBe(2);
    expect((await service.version(ORG, 1)).key.equals(k1)).toBe(true);
    rows.push({
      id: 3n,
      organizationId: ORG,
      version: 3,
      status: 'destroyed',
      wrappedKey: null,
      rootKeyId: 'r1',
    });
    await expect(service.version(ORG, 3)).rejects.toBeInstanceOf(TenantKeyUnavailableError);
    // Keys exist but none is active (impossible through the api): never creates another version 1.
    rows.forEach((r) => (r.status = 'retired'));
    service.clear();
    await expect(service.active(ORG)).rejects.toBeInstanceOf(TenantKeyUnavailableError);
  });
});

describe('RootRewrapJob (A9)', () => {
  it('re-wraps every key under the previous root id with a CAS update and writes one audit row', async () => {
    const oldRoot = hex();
    const old = LocalRootKeyProvider.fromConfig({
      ARCHIVE_ROOT_KEY: oldRoot,
      ARCHIVE_ROOT_KEY_ID: 'r1',
    });
    const next = LocalRootKeyProvider.fromConfig({
      ARCHIVE_ROOT_KEY: hex(),
      ARCHIVE_ROOT_KEY_ID: 'r2',
      ARCHIVE_ROOT_KEY_PREVIOUS: oldRoot,
      ARCHIVE_ROOT_KEY_PREVIOUS_ID: 'r1',
    });
    const tenantKey = randomBytes(32);
    const rows = [
      {
        id: 1n,
        organization_id: ORG,
        version: 1,
        wrapped_key: await wrapTenantKey(old, { organizationId: ORG, version: 1 }, tenantKey),
        root_key_id: 'r1',
      },
    ];
    const audits: unknown[] = [];
    const db = {
      $queryRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
        const sql = Prisma.sql(strings, ...values).sql;
        if (sql.includes('COUNT(*)'))
          return Promise.resolve([{ n: rows.filter((r) => r.root_key_id === 'r1').length }]);
        return Promise.resolve(rows.filter((r) => r.root_key_id === 'r1'));
      },
      $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
        const [wrapped, rootId, id, prev] = values as [string, string, bigint, string];
        const row = rows.find((r) => r.id === id && r.root_key_id === prev);
        if (!row) return Promise.resolve(0);
        Object.assign(row, { wrapped_key: wrapped, root_key_id: rootId });
        void strings;
        return Promise.resolve(1);
      },
      auditLog: { create: (a: unknown) => Promise.resolve(void audits.push(a)) },
    };
    const { metrics, service } = testMetrics();
    const job = new RootRewrapJob(db as never, {
      provider: next,
      metrics,
      logger: silentLogger,
      batchSize: 10,
    });
    const report = await job.runOnce();
    expect(report).toMatchObject({ rewrapped: 1, failed: 0, pending: 0 });
    expect(rows[0]!.root_key_id).toBe('r2');
    const reopened = await unwrapTenantKey(next, rows[0]!.wrapped_key, {
      organizationId: ORG,
      version: 1,
    });
    expect(reopened.key.equals(tenantKey)).toBe(true);
    expect(reopened.usedPreviousKey).toBe(false);
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({
      data: {
        action: ROOT_REWRAP_ACTION,
        actorType: 'system',
        metadata: { fromRootKeyId: 'r1', toRootKeyId: 'r2', rewrapped: 1 },
      },
    });
    expect(await metricValue(service, 'archive_root_rewrap_pending')).toBe(0);
    // Without a previous key there is nothing to do (and no audit row).
    const idle = new RootRewrapJob(db as never, {
      provider: old,
      metrics,
      logger: silentLogger,
      batchSize: 10,
    });
    expect(await idle.runOnce()).toMatchObject({ rewrapped: 0, pending: 0 });
    expect(audits).toHaveLength(1);
  });
});
