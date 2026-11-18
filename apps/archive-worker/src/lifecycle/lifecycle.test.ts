import { ARCHIVE_PARTIES_EXAMPLE, decideExpiry } from '@email-gateway/archive';
import { Prisma } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { FakeStorage, metricValue, silentLogger, testMetrics } from '../archive.test-support';
import { DisposalPipeline, type DisposalObjects, recordVersions } from './disposal';
import { applyExpiryDecision, holdFactsOf } from './expiry';
import { LockPass, OrphanReconciler } from './maintenance';

const ORG = 42n;
const PUBLIC = '0190a5d0-0000-7000-8000-0000000000aa';
const CAPTURE = '0190a5d0-0000-7000-8000-0000000000bb';
const PREFIX = `org/${ORG}/archive/2026/11/16/${PUBLIC}/`;
const key = (name: string, capture = CAPTURE) => `${PREFIX}${capture}/${name}`;

function objectsOf(storage: FakeStorage) {
  const eml = storage.seed('archive', key('eml.bin'), Buffer.from('e'));
  const journal = storage.seed('archive', key('journal.bin'), Buffer.from('j'));
  return {
    captureId: CAPTURE,
    eml: { key: key('eml.bin'), versionId: eml, sha256: 'a'.repeat(64), bytes: 1 },
    journal: { key: key('journal.bin'), versionId: journal, sha256: 'b'.repeat(64), bytes: 1 },
    scans: [],
  };
}

describe('expiry application (A10, A13)', () => {
  it('extends every recorded version BEFORE the row update (extend-only), then enqueues an index upsert', async () => {
    const storage = new FakeStorage();
    const objects = objectsOf(storage);
    const order: string[] = [];
    const tx = {
      $executeRaw: () => {
        order.push('row');
        return Promise.resolve(1);
      },
      archiveIndexQueue: { create: () => Promise.resolve(void order.push('index')) },
    };
    const record = {
      id: 1n,
      receivedAt: new Date('2026-11-16T10:00:00Z'),
      messageId: 9n,
      organizationId: ORG,
      messagePublicId: PUBLIC,
      lockMode: 'governance',
      lockUntil: new Date('2026-11-17T00:00:00Z'),
      objects,
    };
    const realPut = storage.putRetention.bind(storage);
    storage.putRetention = (...args) => {
      order.push('lock');
      return realPut(...args);
    };
    const decision = decideExpiry({
      now: new Date('2026-11-18T00:00:00Z'),
      mode: 'expiry',
      record: {
        receivedAt: record.receivedAt,
        retainUntil: new Date('2026-11-17T00:00:00Z'),
        expiryAction: 'delete',
        lockMode: 'governance',
        lockUntil: record.lockUntil,
        status: 'active',
      },
      policy: null,
      holds: [{ id: 'h', criteria: {}, criteriaVersion: 'archive-hold/1' }],
      holdFacts: { receivedAt: record.receivedAt, senderAddresses: [], recipientAddresses: [] },
      holdExtensionDays: 30,
      reviewExtensionDays: 30,
    });
    expect(decision.outcome).toBe('held');
    await applyExpiryDecision(tx as never, record as never, decision, {
      storage: storage.asStorage(),
      metrics: testMetrics().metrics,
      replicaTargets: [],
      reason: 'retention_expired',
      requestedByUserId: null,
      now: new Date(),
    });
    expect(order).toEqual(['lock', 'lock', 'row', 'index']);
    expect(
      (await storage.getRetention('archive', objects.eml.key, objects.eml.versionId))!.until,
    ).toEqual(decision.lockUntil);
  });

  it('hold facts come from the writer row: senders, every recipient and directions', () => {
    const f = holdFactsOf({
      receivedAt: new Date(0),
      direction: 'inbound',
      envelopeFrom: 'A@B.example',
      headerFrom: 'Name <c@d.example>',
      parties: ARCHIVE_PARTIES_EXAMPLE,
    } as never);
    expect(f).toEqual({
      receivedAt: new Date(0),
      direction: 'inbound',
      recipientDirections: ['inbound'],
      senderAddresses: ['a@b.example', 'c@d.example'],
      recipientAddresses: ['user@example.com'],
    });
    expect(
      recordVersions({
        organizationId: 43n,
        objects: {
          captureId: CAPTURE,
          eml: { key: key('eml.bin'), versionId: 'v', sha256: 'a'.repeat(64), bytes: 1 },
          journal: { key: key('journal.bin'), versionId: 'w', sha256: 'a'.repeat(64), bytes: 1 },
          scans: [],
        },
      }),
    ).toEqual([]); // foreign keys are never touched
  });
});

describe('DisposalPipeline (A14)', () => {
  function pipelineWith(
    storage: FakeStorage,
    state: 'shredded' | 'objects_deleted' | 'index_deleted',
    objects: DisposalObjects,
    opts: { attempts?: number; queued?: number; visible?: boolean } = {},
  ) {
    const updates: string[] = [];
    const disposal = {
      id: 5n,
      requested_at: new Date('2026-11-16T00:00:00Z'),
      organization_id: ORG,
      message_id: 9n,
      message_public_id: PUBLIC,
      message_received_at: new Date('2026-11-16T10:00:00Z'),
      archive_record_id: 1n,
      state,
      attempts: opts.attempts ?? 0,
      objects,
      replica_status: { targets: ['replica'], pending: [] },
    };
    const db = {
      updates,
      $transaction: (fn: (tx: unknown) => Promise<unknown>) => fn(db),
      $queryRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
        const sql = Prisma.sql(strings, ...values).sql;
        if (sql.includes('FOR UPDATE SKIP LOCKED')) return Promise.resolve([disposal]);
        if (sql.includes('maintenance_watermarks')) return Promise.resolve([{ value: 1n }]);
        if (sql.includes('COUNT(*)')) return Promise.resolve([{ n: 0 }]);
        return Promise.resolve([{ at: null }]);
      },
      $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
        const s = Prisma.sql(strings, ...values);
        updates.push(
          `${s.sql.trim().replace(/\s+/g, ' ')} ${s.values.filter((v) => typeof v === 'string').join(',')}`,
        );
        return Promise.resolve(1);
      },
      archiveIndexQueue: { count: () => Promise.resolve(opts.queued ?? 0) },
    };
    const { metrics, service } = testMetrics();
    const search = { count: () => Promise.resolve(opts.visible ? 1 : 0) };
    const pipeline = new DisposalPipeline(db as never, {
      storage: storage.asStorage(),
      search: search as never,
      indexPrefix: 'eg-archive',
      replicaTargets: [{ bucket: 'replica', region: null }],
      governanceBypassOrphans: true,
      maxAttempts: 3,
      metrics,
      logger: silentLogger,
      batchSize: 10,
    });
    return { pipeline, db, service };
  }

  it('deletes recorded versions, orphans (with bypass) and replica copies, then waits for the index, then deletes the row', async () => {
    const storage = new FakeStorage();
    const objects = objectsOf(storage);
    storage.seed(
      'archive',
      key('eml.bin', '0190a5d0-0000-7000-8000-0000000000cc'),
      Buffer.from('orphan'),
      { mode: 'governance', until: new Date(Date.now() + 3_600_000) },
    );
    storage.seed('replica', key('eml.bin'), Buffer.from('copy'));
    const versions = {
      captureId: CAPTURE,
      prefix: PREFIX,
      versions: [
        { key: objects.eml.key, versionId: objects.eml.versionId },
        { key: objects.journal.key, versionId: objects.journal.versionId },
      ],
    };
    const waiting = pipelineWith(storage, 'shredded', versions, { queued: 1 });
    await waiting.pipeline.runOnce();
    expect(storage.versions('archive', PREFIX)).toHaveLength(0);
    expect(storage.versions('replica', PREFIX)).toHaveLength(0);
    expect(storage.calls).toContain(
      `delete:${key('eml.bin', '0190a5d0-0000-7000-8000-0000000000cc')}:bypass`,
    );
    expect(storage.calls).toContain(`delete:${objects.eml.key}:plain`);
    expect(waiting.db.updates.some((u) => u.includes('objects_deleted'))).toBe(true);
    expect(
      waiting.db.updates.some((u) => u.includes(',index_deleted') || u.endsWith(' index_deleted')),
    ).toBe(false); // index op still queued
    const done = pipelineWith(storage, 'objects_deleted', versions);
    await done.pipeline.runOnce();
    expect(done.db.updates.some((u) => u.startsWith('DELETE FROM'))).toBe(true);
    expect(done.db.updates.some((u) => u.includes('completed'))).toBe(true);
    expect(
      await metricValue(done.service, 'archive_disposals_total', { stage: 'row', result: 'ok' }),
    ).toBe(1);
  });

  it('records versions still locked with their retain-until and retries after it (compliance orphan)', async () => {
    const storage = new FakeStorage();
    const until = new Date(Date.now() + 3_600_000);
    storage.seed(
      'archive',
      key('eml.bin', '0190a5d0-0000-7000-8000-0000000000cc'),
      Buffer.from('x'),
      { mode: 'compliance', until },
    );
    const run = pipelineWith(storage, 'shredded', {
      captureId: null,
      prefix: PREFIX,
      versions: [],
    });
    await run.pipeline.runOnce();
    const saved = run.db.updates.find((u) => u.includes('pending'))!;
    expect(saved).toContain(until.toISOString());
    expect(
      await metricValue(run.service, 'archive_disposals_total', {
        stage: 'objects',
        result: 'locked',
      }),
    ).toBe(1);
  });

  it('fails after ARCHIVE_DISPOSAL_MAX_ATTEMPTS', async () => {
    const storage = new FakeStorage();
    storage.deleteVersion = () =>
      Promise.reject(Object.assign(new Error('s3 down'), { name: 'ServiceUnavailable' }));
    const versions = {
      captureId: CAPTURE,
      prefix: PREFIX,
      versions: [{ key: key('eml.bin'), versionId: 'v' }],
    };
    const run = pipelineWith(storage, 'shredded', versions, { attempts: 2 });
    await run.pipeline.runOnce();
    expect(run.db.updates.some((u) => u.includes('ServiceUnavailable'))).toBe(true);
    expect(await metricValue(run.service, 'archive_disposals_total', { result: 'failed' })).toBe(1);
  });
});

describe('maintenance (A10, A15)', () => {
  it('apply-lock pass: governance → compliance sends the bypass; the cursor is removed when done', async () => {
    const storage = new FakeStorage();
    const objects = objectsOf(storage);
    await storage.putRetention('archive', objects.eml.key, objects.eml.versionId, {
      mode: 'governance',
      until: new Date(Date.now() + 60_000),
    });
    const removed: string[] = [];
    const db = {
      streamCursor: {
        findMany: () =>
          Promise.resolve([
            { name: `archive:lock:${ORG}`, positionId: 0n },
            { name: 'archive:lock:bogus', positionId: null },
          ]),
        deleteMany: ({ where }: { where: { name: string } }) =>
          Promise.resolve(void removed.push(where.name)),
      },
      archiveSetting: {
        findUnique: () => Promise.resolve({ organizationId: ORG, objectLockMode: 'compliance' }),
      },
      emailArchive: {
        findMany: () =>
          Promise.resolve([
            {
              id: 1n,
              receivedAt: new Date(),
              messageId: 9n,
              organizationId: ORG,
              messagePublicId: PUBLIC,
              lockMode: 'governance',
              lockUntil: new Date(Date.now() + 60_000),
              retainUntil: new Date(Date.now() + 120_000),
              objects,
            },
          ]),
      },
      $transaction: (fn: (tx: unknown) => Promise<unknown>) =>
        fn({
          $executeRaw: () => Promise.resolve(1),
          archiveIndexQueue: { create: () => Promise.resolve({}) },
        }),
    };
    const lockState = { available: true } as never;
    const pass = new LockPass(db as never, {
      storage: storage.asStorage(),
      lockState,
      metrics: testMetrics().metrics,
      logger: silentLogger,
      batchSize: 10,
    });
    expect(await pass.runOnce()).toMatchObject({ applied: 1, finished: 1 });
    expect(storage.calls.filter((c) => c.startsWith('retention:')).slice(-2)).toEqual([
      `retention:${objects.eml.key}:compliance:bypass`,
      `retention:${objects.journal.key}:compliance:bypass`,
    ]);
    expect(removed).toEqual([`archive:lock:${ORG}`]);
  });

  it('orphan reconciliation deletes only unreferenced versions older than 24 h', async () => {
    const storage = new FakeStorage();
    storage.now = () => new Date(Date.now() - 2 * 86_400_000);
    const objects = objectsOf(storage);
    const orphan = key('eml.bin', '0190a5d0-0000-7000-8000-0000000000cc');
    storage.seed('archive', orphan, Buffer.from('o'));
    storage.now = () => new Date();
    storage.seed(
      'archive',
      key('journal.bin', '0190a5d0-0000-7000-8000-0000000000dd'),
      Buffer.from('young'),
    );
    const db = {
      emailArchive: { findMany: () => Promise.resolve([{ organizationId: ORG, objects }]) },
      archiveDisposal: { findMany: () => Promise.resolve([]) },
    };
    const reconciler = new OrphanReconciler(db as never, {
      storage: storage.asStorage(),
      metrics: testMetrics().metrics,
      logger: silentLogger,
      governanceBypass: true,
      windowDays: 34,
    });
    const report = { days: 0, scanned: 0, deleted: 0, locked: 0, failed: 0 };
    await reconciler.scanDay(ORG, '2026-11-16', report);
    expect(report).toMatchObject({ deleted: 1, locked: 0 });
    expect(
      storage
        .versions('archive', PREFIX)
        .map((v) => v.key)
        .sort(),
    ).toEqual(
      [
        key('eml.bin'),
        key('journal.bin'),
        key('journal.bin', '0190a5d0-0000-7000-8000-0000000000dd'),
      ].sort(),
    );
  });
});
