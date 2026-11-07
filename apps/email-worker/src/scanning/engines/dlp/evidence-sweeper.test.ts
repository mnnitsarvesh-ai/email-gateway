import { MetricsService } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import { describe, expect, it } from 'vitest';
import { MemoryEvidence } from './dlp.test-support';
import { DlpMetrics } from './dlp-metrics';
import { DLP_EVIDENCE_LOCK, DlpEvidenceSweeper } from './evidence-sweeper';

const NOW = new Date('2026-11-07T06:00:00Z');
const AT = new Date('2026-10-01T00:00:00Z');

interface Row {
  id: bigint;
  receivedAt: Date;
  organizationId: bigint;
  objectKey: string | null;
  wrappedKey: string | null;
  expiresAt: Date;
  purgedAt: Date | null;
  purgeReason: string | null;
}

const key = (org: bigint, id: bigint) =>
  `org/${org.toString()}/dlp-evidence/2026/10/${id.toString()}-0196f3a0-0000-7000-8000-00000000000${id.toString()}.bin`;
const row = (id: bigint, expired: boolean, over: Partial<Row> = {}): Row => ({
  id,
  receivedAt: AT,
  organizationId: 5n,
  objectKey: key(5n, id),
  wrappedKey: 'v1.k1.a.b.c',
  expiresAt: new Date(NOW.getTime() + (expired ? -1 : 1) * 86_400_000),
  purgedAt: null,
  purgeReason: null,
  ...over,
});

const matches = (r: Row, where: Record<string, unknown>): boolean => {
  for (const [k, v] of Object.entries(where)) {
    const value = (r as unknown as Record<string, unknown>)[k];
    if (k === 'organizationId' && typeof v === 'object' && v !== null && 'in' in v) {
      if (!(v.in as bigint[]).includes(r.organizationId)) return false;
    } else if (k === 'expiresAt') {
      if (!(r.expiresAt.getTime() <= (v as { lte: Date }).lte.getTime())) return false;
    } else if (k === 'OR') {
      if (!(v as Record<string, unknown>[]).some((w) => matches(r, w))) return false;
    } else if (typeof v === 'object' && v !== null && 'not' in v) {
      if (value === v.not) return false;
    } else if (v instanceof Date) {
      if (!(value instanceof Date) || value.getTime() !== v.getTime()) return false;
    } else if (value !== v) return false;
  }
  return true;
};

function setup(rows: Row[], options: { leader?: boolean; forge?: boolean } = {}) {
  const evidence = {
    findMany: (args: { where: Record<string, unknown>; take: number }) =>
      Promise.resolve(
        rows
          .filter((r) => matches(r, args.where))
          .slice(0, args.take)
          .map((r) => (options.forge ? { ...r, purgedAt: NOW } : { ...r })),
      ),
    updateMany: (args: { where: Record<string, unknown>; data: Partial<Row> }) => {
      let count = 0;
      for (const r of rows) {
        if (matches(r, args.where)) {
          Object.assign(r, args.data);
          count += 1;
        }
      }
      return Promise.resolve({ count });
    },
    count: (args: { where: Record<string, unknown> }) =>
      Promise.resolve(rows.filter((r) => matches(r, args.where)).length),
  };
  const prisma = {
    dlpEvidence: evidence,
    $transaction: (fn: (tx: unknown) => Promise<unknown>) => fn({ dlpEvidence: evidence }),
  } as unknown as PrismaClient;
  const objects = new MemoryEvidence();
  for (const r of rows) if (r.objectKey) objects.objects.set(r.objectKey, Buffer.from('x'));
  const registry = new MetricsService({ service: 'dlp-sweeper-test' });
  const locks: string[] = [];
  const sweeper = new DlpEvidenceSweeper({
    prisma,
    objects,
    locks: {
      ensure: (name: string) => {
        locks.push(name);
        return Promise.resolve(options.leader ?? true);
      },
      release: () => Promise.resolve(),
    },
    metrics: DlpMetrics.for(registry),
    logger: createLogger({ service: 'dlp-sweeper-test', level: 'silent' }),
    intervalMs: 1_000,
    txTimeoutMs: 1_000,
    batchSize: 2,
    now: () => NOW,
  });
  return { sweeper, objects, registry, locks };
}

describe('DLP evidence sweeper (step 4.5 D16)', () => {
  it('crypto-shreds expired rows, then deletes their objects and clears object_key', async () => {
    const rows = [row(1n, true), row(2n, true), row(3n, true), row(4n, false)];
    const { sweeper, objects, registry, locks } = setup(rows);
    const report = await sweeper.sweepOnce();
    expect(locks).toEqual([DLP_EVIDENCE_LOCK]);
    expect(report).toMatchObject({
      outcome: 'swept',
      shredded: 3,
      objectsDeleted: 3,
      expiredUnpurged: 0,
    });
    for (const r of rows.slice(0, 3)) {
      expect(r).toMatchObject({ wrappedKey: null, objectKey: null, purgeReason: 'retention' });
      expect(r.purgedAt).toEqual(NOW);
    }
    expect(rows[3]).toMatchObject({ wrappedKey: 'v1.k1.a.b.c', purgedAt: null });
    expect(objects.objects.size).toBe(1);
    const text = await registry.metrics();
    expect(text).toMatch(/dlp_evidence_purged_total\{reason="retention"[^}]*\} 3/);
    expect(text).toMatch(/dlp_evidence_expired_unpurged\{[^}]*\} 0/);
  });

  it('keeps object_key when the delete fails (retried next pass) and reports the gauge', async () => {
    const rows = [row(1n, true)];
    const { sweeper, objects, registry } = setup(rows);
    objects.failDelete = true;
    const first = await sweeper.sweepOnce();
    expect(first).toMatchObject({
      shredded: 1,
      objectsDeleted: 0,
      objectsLeft: 1,
      expiredUnpurged: 1,
    });
    expect(rows[0]).toMatchObject({ wrappedKey: null });
    expect(rows[0]!.objectKey).not.toBeNull();
    expect(await registry.metrics()).toMatch(/dlp_evidence_expired_unpurged\{[^}]*\} 1/);
    objects.failDelete = false;
    const second = await sweeper.sweepOnce();
    expect(second).toMatchObject({ shredded: 0, objectsDeleted: 1, expiredUnpurged: 0 });
  });

  it('never deletes outside the organization prefix; not the leader → nothing', async () => {
    const rows = [row(1n, true, { objectKey: 'org/6/dlp-evidence/2026/10/1-x.bin' })];
    const { sweeper } = setup(rows);
    expect(await sweeper.sweepOnce()).toMatchObject({
      shredded: 1,
      objectsDeleted: 0,
      objectsLeft: 1,
    });
    const follower = setup([row(1n, true)], { leader: false });
    expect(await follower.sweeper.sweepOnce()).toMatchObject({
      outcome: 'not_leader',
      shredded: 0,
    });
  });

  it('a forged read is a database error (counted), never a purge', async () => {
    const rows = [row(1n, true)];
    const { sweeper, registry } = setup(rows, { forge: true });
    expect((await sweeper.sweepOnce()).outcome).toBe('database_error');
    expect(rows[0]!.wrappedKey).toBe('v1.k1.a.b.c');
    expect(await registry.metrics()).toMatch(
      /scan_dlp_inconsistent_reads_total\{read="evidence"[^}]*\} 1/,
    );
  });
});
