import type { PrismaService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { systemScope } from '../../auth-contracts/tenant-scope';
import type { ArchiveRecordsRepository } from '../archive/repositories/archive-records.repository';
import {
  ARCHIVE_PURGE_ORDER,
  ArchivePurgeRefusedError,
  ArchiveTenantDataRepository,
} from './archive-tenant-data.repository';

const SCOPE = systemScope(42n);
const NOW = new Date('2026-11-17T00:00:00.000Z');

/** A fake writer: holds, retained count, live record ids, remaining rows, open disposals. */
function fakeWriter(state: {
  holds?: number;
  retained?: number;
  live?: bigint[];
  remaining?: number;
  openDisposals?: number;
  /** Active holds seen inside the batch transaction (a hold committed after the pre-check). */
  holdsInTx?: number;
}) {
  const statements: string[] = [];
  const decisions: bigint[] = [];
  const created: unknown[] = [];
  const live = [...(state.live ?? [])];
  const orgLocks: string[] = [];
  const tx = {
    archiveLegalHold: { count: () => Promise.resolve(state.holdsInTx ?? state.holds ?? 0) },
    $queryRaw: () => {
      const rows = live.splice(0, 2).map((id) => ({ id, received_at: NOW }));
      return Promise.resolve(rows);
    },
    emailArchive: {
      findFirst: (args: { where: { id: bigint } }) =>
        Promise.resolve({ id: args.where.id, organizationId: 42n }),
    },
  };
  const writer = {
    archiveLegalHold: { count: () => Promise.resolve(state.holds ?? 0) },
    $queryRaw: (strings: TemplateStringsArray) => {
      statements.push(strings.join('?').replace(/\s+/g, ' ').trim());
      return Promise.resolve([{ n: BigInt(state.retained ?? 0) }]);
    },
    $transaction: (fn: (t: unknown) => Promise<number>) => fn(tx),
    archiveIndexQueue: {
      count: () => Promise.resolve(0),
      create: (args: unknown) => {
        created.push(args);
        return Promise.resolve({ id: 1n });
      },
    },
    emailArchive: { count: () => Promise.resolve(state.remaining ?? 0) },
    archiveDisposal: { count: () => Promise.resolve(state.openDisposals ?? 0) },
    $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
      statements.push(strings.join('?').replace(/\s+/g, ' ').trim());
      expect(values[0] instanceof Date ? values[1] : values[0]).toBe(42n);
      return Promise.resolve(statements.at(-1)!.startsWith('UPDATE') ? 2 : 0);
    },
  } as unknown as PrismaService;
  const records = {
    lockOrganizationForHolds: (_tx: unknown, scope: { organizationId: bigint }) => {
      orgLocks.push(scope.organizationId.toString());
      return Promise.resolve();
    },
    writeDisposalDecision: (
      _tx: unknown,
      _scope: unknown,
      d: { record: { id: bigint }; reason: string },
    ) => {
      expect(d.reason).toBe('organization_deleted');
      decisions.push(d.record.id);
      return Promise.resolve();
    },
  } as unknown as ArchiveRecordsRepository;
  return { writer, records, statements, decisions, created, orgLocks };
}

describe('organization purge: archive (step 8.1 A24)', () => {
  it('is refused under an active hold or running retention (nothing changed)', async () => {
    const held = fakeWriter({ holds: 1, live: [1n] });
    const e1 = await new ArchiveTenantDataRepository(held.writer, held.records)
      .purgeOrganization(SCOPE, { now: NOW })
      .catch((e: unknown) => e);
    expect(e1).toBeInstanceOf(ArchivePurgeRefusedError);
    expect((e1 as ArchivePurgeRefusedError).reason).toBe('legal_hold');
    expect(held.decisions).toEqual([]);
    const retained = fakeWriter({ retained: 3, live: [1n] });
    const e2 = await new ArchiveTenantDataRepository(retained.writer, retained.records)
      .purgeOrganization(SCOPE, { now: NOW })
      .catch((e: unknown) => e);
    expect(e2).toMatchObject({ reason: 'retention', count: 3 });
    expect(retained.decisions).toEqual([]);
  });

  it('re-checks holds under the organization lock in every batch: a hold committed after the pre-check stops the purge', async () => {
    const f = fakeWriter({ holdsInTx: 1, live: [1n, 2n] });
    const e = await new ArchiveTenantDataRepository(f.writer, f.records)
      .purgeOrganization(SCOPE, { now: NOW })
      .catch((error: unknown) => error);
    expect(e).toBeInstanceOf(ArchivePurgeRefusedError);
    expect((e as ArchivePurgeRefusedError).reason).toBe('legal_hold');
    expect(f.orgLocks).toEqual(['42']);
    expect(f.decisions).toEqual([]);
  });

  it('phase 1 sends every live record through the disposal decision and queues purge_org; incomplete while disposals run', async () => {
    const f = fakeWriter({ live: [1n, 2n, 3n], remaining: 3, openDisposals: 3 });
    const result = await new ArchiveTenantDataRepository(f.writer, f.records).purgeOrganization(
      SCOPE,
      {
        now: NOW,
        batch: 2,
      },
    );
    expect(f.decisions).toEqual([1n, 2n, 3n]);
    expect(result).toMatchObject({
      complete: false,
      counts: { disposalsRequested: 3, keysDestroyed: 0 },
    });
    expect(f.created).toEqual([
      expect.objectContaining({
        data: expect.objectContaining({ op: 'purge_org', organizationId: 42n }),
      }),
    ]);
    expect(f.statements.some((s) => s.startsWith('DELETE'))).toBe(false);
  });

  it('phase 2 deletes in RESTRICT-safe order and destroys the keys last', async () => {
    const f = fakeWriter({});
    const result = await new ArchiveTenantDataRepository(f.writer, f.records).purgeOrganization(
      SCOPE,
      { now: NOW },
    );
    expect(result.complete).toBe(true);
    expect(result.counts.keysDestroyed).toBe(2);
    const deletes = f.statements.filter((s) => s.startsWith('DELETE'));
    expect(deletes.map((s) => /^DELETE FROM (\w+)/.exec(s)![1])).toEqual([...ARCHIVE_PURGE_ORDER]);
    expect(f.statements.at(-1)).toMatch(
      /^UPDATE archive_encryption_keys SET status = 'destroyed', wrapped_key = NULL/,
    );
    expect(deletes.find((s) => s.includes('archive_legal_holds'))).toContain("status = 'released'");
    expect(deletes.find((s) => s.includes('archive_capture_intents'))).not.toContain('ORDER BY');
    const at = (t: (typeof ARCHIVE_PURGE_ORDER)[number]) => ARCHIVE_PURGE_ORDER.indexOf(t);
    expect(at('ediscovery_search_hits')).toBeLessThan(at('ediscovery_searches'));
    expect(at('ediscovery_exports')).toBeLessThan(at('ediscovery_searches'));
    expect(at('archive_legal_holds')).toBeLessThan(at('ediscovery_cases'));
    expect(at('archive_settings')).toBeLessThan(at('archive_retention_policies'));
    expect(ARCHIVE_PURGE_ORDER).not.toContain('archive_disposals');
  });

  it('refuses a non-positive batch', async () => {
    const f = fakeWriter({});
    await expect(
      new ArchiveTenantDataRepository(f.writer, f.records).purgeOrganization(SCOPE, { batch: 0 }),
    ).rejects.toThrow('batch must be positive');
  });
});
