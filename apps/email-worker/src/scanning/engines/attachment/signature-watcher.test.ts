import { MetricsService } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import { describe, expect, it } from 'vitest';
import { AttachmentMetrics } from './attachment-metrics';
import {
  type ComponentVersion,
  SignatureWatcher,
  type SignatureRescanMode,
} from './signature-watcher';

interface VersionRow {
  id: bigint;
  engine: string;
  component: string;
  version: string;
  firstSeenAt: Date;
  lastSeenAt: Date;
}

/** The scan_signature_versions / attachment_rescan_jobs calls of the watcher, in memory. */
function fakePrisma() {
  const versions: VersionRow[] = [];
  const jobs: Array<Record<string, unknown>> = [];
  const faults = { createManyOnce: false };
  let id = 1n;
  const prisma = {
    /** Interactive transaction: the writes of a callback that throws are rolled back. */
    $transaction: async <T>(fn: (tx: unknown) => Promise<T>): Promise<T> => {
      const savedVersions = versions.length;
      const savedJobs = jobs.length;
      try {
        return await fn(prisma);
      } catch (error) {
        versions.length = savedVersions;
        jobs.length = savedJobs;
        throw error;
      }
    },
    scanSignatureVersion: {
      findUnique: ({
        where,
      }: {
        where: { engine_component_version: { engine: string; component: string; version: string } };
      }) => {
        const k = where.engine_component_version;
        return Promise.resolve(
          versions.find(
            (r) => r.engine === k.engine && r.component === k.component && r.version === k.version,
          ) ?? null,
        );
      },
      update: ({ where, data }: { where: { id: bigint }; data: { lastSeenAt: Date } }) => {
        const row = versions.find((r) => r.id === where.id)!;
        row.lastSeenAt = data.lastSeenAt;
        return Promise.resolve({ id: row.id });
      },
      findFirst: ({ where }: { where: { engine: string; component: string } }) => {
        const rows = versions.filter(
          (r) => r.engine === where.engine && r.component === where.component,
        );
        rows.sort((a, b) => b.lastSeenAt.getTime() - a.lastSeenAt.getTime() || Number(b.id - a.id));
        return Promise.resolve(rows[0] ?? null);
      },
      create: ({ data }: { data: Omit<VersionRow, 'id'> }) => {
        versions.push({ id: id++, ...data });
        return Promise.resolve({ id });
      },
    },
    attachmentRescanJob: {
      createMany: ({ data }: { data: Array<Record<string, unknown>> }) => {
        if (faults.createManyOnce) {
          faults.createManyOnce = false;
          return Promise.reject(new Error('connection lost'));
        }
        let count = 0;
        for (const job of data) {
          if (jobs.some((j) => j.dedupeKey === job.dedupeKey)) continue;
          jobs.push(job);
          count += 1;
        }
        return Promise.resolve({ count });
      },
    },
  };
  return { prisma: prisma as unknown as PrismaClient, versions, jobs, faults };
}

function watcher(mode: SignatureRescanMode, leader = true) {
  const db = fakePrisma();
  const registry = new MetricsService({ service: `sig-${Math.random().toString(16).slice(2, 8)}` });
  let current: ComponentVersion[] = [
    { component: 'clamav_db', version: '28174' },
    { component: 'clamav_engine', version: '1.4.6' },
    { component: 'yara_bundle', version: 'yara-1-462fab6e5cc4' },
  ];
  let fail = false;
  let now = new Date('2026-11-05T10:00:00Z');
  const instance = new SignatureWatcher({
    prisma: db.prisma,
    locks: { ensure: () => Promise.resolve(leader), release: () => Promise.resolve() },
    source: {
      current: () =>
        fail
          ? Promise.reject(new Error('clamd down'))
          : Promise.resolve({ versions: current, clamavDbTime: new Date('2026-11-05T06:00:00Z') }),
    },
    metrics: AttachmentMetrics.for(registry),
    logger: createLogger({ service: 'sig-test', level: 'silent' }),
    intervalMs: 1000,
    mode,
    windowHours: 24,
    maxMessages: 5000,
    txTimeoutMs: 120_000,
    now: () => now,
  });
  return {
    instance,
    db,
    registry,
    set: (next: ComponentVersion[]) => (current = next),
    fail: () => (fail = true),
    at: (d: Date) => (now = d),
  };
}

describe('SignatureWatcher (step 4.2 A13)', () => {
  it('records the first versions without a change, then detects a new database version', async () => {
    const w = watcher('rescan');
    expect(await w.instance.poll()).toEqual({ outcome: 'polled', changes: [] });
    expect(w.db.versions.map((r) => `${r.component}=${r.version}`)).toEqual([
      'clamav_db=28174',
      'clamav_engine=1.4.6',
      'yara_bundle=yara-1-462fab6e5cc4',
    ]);
    // Same versions again: last_seen_at only.
    w.at(new Date('2026-11-05T10:05:00Z'));
    expect((await w.instance.poll()).changes).toEqual([]);
    expect(w.db.versions[0]!.lastSeenAt.toISOString()).toBe('2026-11-05T10:05:00.000Z');
    w.at(new Date('2026-11-05T12:00:00Z'));
    w.set([{ component: 'clamav_db', version: '28175' }]);
    expect((await w.instance.poll()).changes).toEqual([
      { component: 'clamav_db', from: '28174', to: '28175', jobCreated: true },
    ]);
    expect(w.db.jobs).toEqual([
      expect.objectContaining({
        trigger: 'signature_update',
        status: 'pending',
        dedupeKey: 'sig:clamav_db:28175',
        organizationId: null,
        windowStart: new Date('2026-11-04T12:00:00Z'),
        windowEnd: new Date('2026-11-05T12:00:00Z'),
        states: ['scanned', 'scan_failed', 'quarantined', 'held_for_review'],
        component: 'clamav_db',
        fromVersion: '28174',
        toVersion: '28175',
        maxMessages: 5000,
      }),
    ]);
    const text = await w.registry.metrics();
    expect(text).toMatch(
      /scan_attachment_signature_changes_total\{[^}]*component="clamav_db"[^}]*\} 1/,
    );
    expect(text).toMatch(
      /scan_attachment_signature_info\{[^}]*component="clamav_db"[^}]*version="28175"[^}]*\} 1/,
    );
    expect(text).toMatch(/scan_attachment_clamav_db_age_seconds\{[^}]*\} 21600/);
  });

  it('record mode writes a skipped audit job; off writes none; the dedupe key makes one job per change', async () => {
    const record = watcher('record');
    await record.instance.poll();
    record.set([{ component: 'yara_bundle', version: 'yara-2-000000000000' }]);
    await record.instance.poll();
    expect(record.db.jobs).toEqual([
      expect.objectContaining({
        status: 'skipped',
        dedupeKey: 'sig:yara_bundle:yara-2-000000000000',
      }),
    ]);
    const off = watcher('off');
    await off.instance.poll();
    off.set([{ component: 'clamav_engine', version: '1.4.7' }]);
    expect((await off.instance.poll()).changes[0]).toMatchObject({ jobCreated: false });
    expect(off.db.jobs).toEqual([]);
  });

  it('a failed job insert rolls the new version back, so the next poll creates the job', async () => {
    const w = watcher('rescan');
    await w.instance.poll();
    w.set([{ component: 'clamav_db', version: '28175' }]);
    w.db.faults.createManyOnce = true;
    expect((await w.instance.poll()).outcome).toBe('database_error');
    expect(w.db.versions.map((r) => r.version)).toEqual(['28174', '1.4.6', 'yara-1-462fab6e5cc4']);
    expect(w.db.jobs).toEqual([]);
    const retry = await w.instance.poll();
    expect(retry).toEqual({
      outcome: 'polled',
      changes: [{ component: 'clamav_db', from: '28174', to: '28175', jobCreated: true }],
    });
    expect(w.db.jobs).toEqual([
      expect.objectContaining({ status: 'pending', dedupeKey: 'sig:clamav_db:28175' }),
    ]);
  });

  it('does nothing without the leader lock and survives an unavailable clamd', async () => {
    const follower = watcher('rescan', false);
    expect((await follower.instance.poll()).outcome).toBe('not_leader');
    expect(follower.db.versions).toEqual([]);
    const down = watcher('rescan');
    down.fail();
    expect((await down.instance.poll()).outcome).toBe('unavailable');
  });
});
