import { describe, expect, it } from 'vitest';
import {
  counter,
  FakeSandboxObjects,
  FakeSandboxStore,
  newSandboxMetrics,
  silent,
} from './fakes.test-support';
import { SANDBOX_SWEEP_LOCK, SANDBOX_SWEEP_STEPS, SandboxSweeper } from './sandbox-sweeper';

const NOW = new Date('2026-11-08T10:00:00.000Z');
const RECEIVED = new Date('2026-11-08T08:00:00.000Z');
const ORG = 7n;
const HOUR = 3_600_000;
const DAY = 86_400_000;

function setup(options: { leader?: boolean; lockError?: boolean } = {}) {
  const store = new FakeSandboxStore();
  const objects = new FakeSandboxObjects(store.log);
  const { metrics, registry } = newSandboxMetrics();
  const locks = {
    names: [] as string[],
    ensure: (name: string) => {
      locks.names.push(name);
      return options.lockError
        ? Promise.reject(new Error('db down'))
        : Promise.resolve(options.leader ?? true);
    },
    release: () => Promise.resolve(),
  };
  const sweeper = new SandboxSweeper({
    store,
    objects,
    locks,
    metrics,
    logger: silent,
    intervalMs: 60_000,
    batchSize: 500,
    submissionTtlSeconds: 3_600,
    now: () => NOW,
  });
  let seq = 0;
  const scanned = (
    status: 'pending' | 'submitted',
    analysisId: bigint | null = null,
    createdAt = RECEIVED,
  ) => {
    seq += 1;
    const scanId = 700n + BigInt(seq);
    store.addScan({
      scanId,
      receivedAt: RECEIVED,
      organizationId: ORG,
      messageId: 40n + BigInt(seq),
      lifecycleRound: 0,
    });
    return store.addSubmission({
      scanId,
      receivedAt: RECEIVED,
      organizationId: ORG,
      messageId: 40n + BigInt(seq),
      status,
      analysisId,
      createdAt,
    });
  };
  return { store, objects, metrics, registry, locks, sweeper, scanned };
}

describe('sandbox sweeper (X16)', () => {
  it('runs only as the scan:sandbox leader; a lock error backs off', async () => {
    const follower = setup({ leader: false });
    expect((await follower.sweeper.sweepOnce()).outcome).toBe('not_leader');
    expect(follower.locks.names).toEqual([SANDBOX_SWEEP_LOCK]);
    const broken = setup({ lockError: true });
    expect((await broken.sweeper.sweepOnce()).outcome).toBe('database_error');
  });

  it('runs the steps a–f in order', async () => {
    const t = setup();
    expect((await t.sweeper.sweepOnce()).steps).toEqual([...SANDBOX_SWEEP_STEPS]);
  });

  it('(a) expires pending submissions older than the TTL (timeout final), not younger ones', async () => {
    const t = setup();
    const old = t.scanned('pending', null, new Date(NOW.getTime() - 2 * HOUR));
    const young = t.scanned('pending', null, new Date(NOW.getTime() - 10 * 60_000));
    const report = await t.sweeper.sweepOnce();
    expect(report.submissionsExpired).toBe(1);
    expect(t.store.submission(old.id)).toMatchObject({
      status: 'expired',
      sandboxVerdict: 'timeout',
      sandboxReasonCodes: ['sandbox.timeout'],
    });
    expect(t.store.submission(young.id).status).toBe('pending');
    expect(t.store.final(old.scanId, RECEIVED)).toMatchObject({ outcome: 'timeout' });
    expect(await counter(t.registry, 'scan_sandbox_submissions_total', { result: 'expired' })).toBe(
      1,
    );
  });

  it('(b) expires overdue analyses (dedupe key cleared) and their linked submissions', async () => {
    const t = setup();
    const analysis = t.store.addAnalysis({
      sha256: 'b'.repeat(64),
      organizationId: ORG,
      status: 'dispatched',
      dedupeKey: `${'b'.repeat(64)}:0123456789abcdef`,
      deadlineAt: new Date(NOW.getTime() - 1),
    });
    const fresh = t.store.addAnalysis({
      sha256: 'c'.repeat(64),
      organizationId: ORG,
      status: 'pending',
      deadlineAt: new Date(NOW.getTime() + HOUR),
    });
    const linked = t.scanned('submitted', analysis.id);
    const report = await t.sweeper.sweepOnce();
    expect(report.analysesExpired).toBe(1);
    expect(t.store.analysis(analysis.id)).toMatchObject({
      status: 'expired',
      verdict: 'timeout',
      dedupeKey: null,
      reasonCodes: ['sandbox.timeout'],
    });
    expect(t.store.analysis(fresh.id).status).toBe('pending');
    expect(t.store.submission(linked.id)).toMatchObject({
      status: 'expired',
      sandboxVerdict: 'timeout',
      externalRef: analysis.publicId,
    });
    expect(t.store.final(linked.scanId, RECEIVED)).toMatchObject({ outcome: 'timeout' });
    expect(await counter(t.registry, 'scan_sandbox_analyses_total', { status: 'expired' })).toBe(1);
  });

  it('(c) completes submitted submissions whose analysis is terminal (catch-up)', async () => {
    const t = setup();
    const analysis = t.store.addAnalysis({
      sha256: 'd'.repeat(64),
      organizationId: ORG,
      status: 'completed',
      verdict: 'suspicious',
      reasonCodes: ['sandbox.static.office_macro'],
      isolation: 'process',
      executed: false,
      sampleDeletedAt: NOW,
    });
    const rows = [t.scanned('submitted', analysis.id), t.scanned('submitted', analysis.id)];
    const report = await t.sweeper.sweepOnce();
    expect(report.caughtUp).toBe(2);
    for (const row of rows) {
      expect(t.store.submission(row.id)).toMatchObject({
        status: 'completed',
        sandboxVerdict: 'suspicious',
      });
      expect(t.store.final(row.scanId, RECEIVED)).toMatchObject({ outcome: 'suspicious' });
    }
  });

  it('(d) deletes samples of terminal analyses; a failed delete is counted and retried next pass', async () => {
    const t = setup();
    const done = t.store.addAnalysis({
      sha256: 'e'.repeat(64),
      organizationId: ORG,
      status: 'completed',
      verdict: 'unknown',
    });
    const running = t.store.addAnalysis({
      sha256: 'f'.repeat(64),
      organizationId: ORG,
      status: 'dispatched',
      deadlineAt: new Date(NOW.getTime() + HOUR),
    });
    t.objects.objects.set(done.sampleObjectKey!, Buffer.from('s'));
    t.objects.objects.set(running.sampleObjectKey!, Buffer.from('s'));
    t.objects.failDeletes = 1;
    const first = await t.sweeper.sweepOnce();
    expect(first).toMatchObject({ samplesDeleted: 0, samplesLeft: 1 });
    expect(await counter(t.registry, 'scan_sandbox_purge_failures_total', { kind: 'sample' })).toBe(
      1,
    );
    const second = await t.sweeper.sweepOnce();
    expect(second.samplesDeleted).toBe(1);
    expect(t.store.analysis(done.id).sampleDeletedAt).toEqual(NOW);
    expect(t.objects.objects.has(done.sampleObjectKey!)).toBe(false);
    expect(t.objects.objects.has(running.sampleObjectKey!)).toBe(true);
    expect(t.store.analysis(running.id).sampleDeletedAt).toBeNull();
  });

  it('(e) crypto-shreds expired artifacts before deleting their objects; failed deletes are retried', async () => {
    const t = setup();
    const analysis = t.store.addAnalysis({
      sha256: 'a'.repeat(64),
      organizationId: ORG,
      status: 'completed',
      verdict: 'unknown',
      sampleDeletedAt: NOW,
    });
    const key = (seq: number) =>
      `artifacts/2026/10/${analysis.publicId}/0123456789abcdef/${seq}-static_report.bin`;
    await t.store.transaction(async (tx) =>
      tx.insertArtifacts(
        analysis.id,
        [0, 1].map((seq) => ({
          seq,
          kind: 'static_report' as const,
          contentType: 'application/json',
          objectKey: key(seq),
          objectSha256: '0'.repeat(64),
          plainSha256: '1'.repeat(64),
          sizeBytes: 2,
          wrappedKey: 'x1.abcd1234.a.b.c.d',
          keyId: 'abcd1234',
          algorithm: 'sandbox-artifact/1',
          expiresAt: seq === 0 ? new Date(NOW.getTime() - DAY) : new Date(NOW.getTime() + DAY),
        })),
      ),
    );
    t.objects.failDeletes = 1;
    const first = await t.sweeper.sweepOnce();
    expect(first).toMatchObject({
      artifactKeysShredded: 1,
      artifactObjectsDeleted: 0,
      artifactObjectsLeft: 1,
    });
    const [expired, live] = [...t.store.state.artifacts.values()];
    expect(expired).toMatchObject({
      shredded: true,
      purgeReason: 'retention',
      purgedAt: NOW,
      objectDeletedAt: null,
    });
    expect(live).toMatchObject({ shredded: false, purgedAt: null });
    const second = await t.sweeper.sweepOnce();
    expect(second.artifactObjectsDeleted).toBe(1);
    expect(t.store.log.filter((l) => l.includes(key(0)))).toEqual([
      `shred:${key(0)}`,
      `delete:${key(0)}`,
    ]);
    expect(t.store.log.some((l) => l.includes(key(1)))).toBe(false);
    expect(await counter(t.registry, 'scan_sandbox_purged_total', { kind: 'artifact_key' })).toBe(
      1,
    );
    expect(
      await counter(t.registry, 'scan_sandbox_purged_total', { kind: 'artifact_object' }),
    ).toBe(1);
    expect(
      await counter(t.registry, 'scan_sandbox_purge_failures_total', { kind: 'artifact_object' }),
    ).toBe(1);
  });

  it('(f) deletes expired analyses only after every artifact object is deleted', async () => {
    const t = setup();
    const analysis = t.store.addAnalysis({
      sha256: '9'.repeat(64),
      organizationId: ORG,
      status: 'completed',
      verdict: 'unknown',
      sampleDeletedAt: new Date(NOW.getTime() - 200 * DAY),
      expiresAt: new Date(NOW.getTime() - DAY),
    });
    await t.store.transaction(async (tx) =>
      tx.insertArtifacts(analysis.id, [
        {
          seq: 0,
          kind: 'process_log',
          contentType: 'text/plain',
          objectKey: `artifacts/2026/04/${analysis.publicId}/0123456789abcdef/0-process_log.bin`,
          objectSha256: '0'.repeat(64),
          plainSha256: '1'.repeat(64),
          sizeBytes: 2,
          wrappedKey: 'x1.abcd1234.a.b.c.d',
          keyId: 'abcd1234',
          algorithm: 'sandbox-artifact/1',
          expiresAt: new Date(NOW.getTime() - 2 * DAY),
        },
      ]),
    );
    t.objects.failDeletes = 1;
    const first = await t.sweeper.sweepOnce();
    expect(first.analysesDeleted).toBe(0);
    expect(t.store.state.analyses.has(analysis.id)).toBe(true);
    const second = await t.sweeper.sweepOnce();
    expect(second.analysesDeleted).toBe(1);
    expect(t.store.state.analyses.has(analysis.id)).toBe(false);
    expect(t.store.state.artifacts.size).toBe(0);
    expect(await counter(t.registry, 'scan_sandbox_purged_total', { kind: 'analysis' })).toBe(1);
  });

  it('never deletes keys outside samples/ and artifacts/', async () => {
    const t = setup();
    const odd = t.store.addAnalysis({
      sha256: '8'.repeat(64),
      organizationId: ORG,
      status: 'failed',
      verdict: 'error',
      sampleObjectKey: 'org/7/part/x.att',
    });
    const report = await t.sweeper.sweepOnce();
    expect(report.samplesLeft).toBe(1);
    expect(t.objects.deleted).toEqual([]);
    expect(t.store.analysis(odd.id).sampleDeletedAt).toBeNull();
  });
});
