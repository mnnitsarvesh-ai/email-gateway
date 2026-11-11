import { MetricsService } from '@email-gateway/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RiskMetrics } from '../src/scanning/risk/risk-metrics';
import { createRiskScorer } from '../src/scanning/risk/risk-scorer';
import { buildResult } from '../src/scanning/sandbox/result-builder.test-support';
import { SandboxMetrics } from '../src/scanning/sandbox/sandbox-metrics';
import { PrismaSandboxStore } from '../src/scanning/sandbox/sandbox-store';
import { SandboxSweeper } from '../src/scanning/sandbox/sandbox-sweeper';
import { S3SandboxObjects, type SandboxObjects } from '../src/scanning/sandbox/sample-stager';
import { testLocks } from './support/attachments';
import { silentLogger } from './support/fixtures';
import { benignScript, deliver, SandboxFixtures, type SandboxRound } from './support/sandbox';
import { ScanFixtures } from './support/scan';

/**
 * Package integration of the sandbox sweeper (step 4.6 §9.2, X16) on the real writer and the
 * sandbox bucket: submission TTL and analysis deadline expiry (`timeout` finals), sample
 * deletion, artifact retention purge (the wrapped key is nulled and committed before the object
 * is deleted: checked at the moment of each delete) and analysis deletion. Time is advanced by
 * the sweeper's clock only; every row and object it touches belongs to this run.
 */
const fx = new ScanFixtures();
let sfx: SandboxFixtures;
const locks = testLocks();
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

beforeAll(() => {
  sfx = new SandboxFixtures(fx);
});

afterAll(async () => {
  await locks.close();
  await sfx?.cleanup();
  await fx.cleanup();
});

/** Records, at each artifact delete, the row's purge state as the writer has it committed. */
class ObservedObjects implements SandboxObjects {
  readonly artifactStates: { key: string; wrappedKey: string | null; purgedAt: Date | null }[] = [];

  constructor(private readonly inner: SandboxObjects) {}

  put(key: string, body: Buffer, sha256Hex: string): Promise<void> {
    return this.inner.put(key, body, sha256Hex);
  }

  async delete(key: string): Promise<void> {
    if (key.startsWith('artifacts/')) {
      const row = await sfx.prisma.sandboxArtifact.findFirst({
        where: { objectKey: key },
        select: { wrappedKey: true, purgedAt: true },
      });
      this.artifactStates.push({
        key,
        wrappedKey: row?.wrappedKey ?? null,
        purgedAt: row?.purgedAt ?? null,
      });
    }
    await this.inner.delete(key);
  }

  check(): Promise<void> {
    return this.inner.check();
  }
}

function sweeperAt(offsetMs: number) {
  const registry = new MetricsService({ service: `it-sbx-sweep-${String(offsetMs)}` });
  const objects = new ObservedObjects(
    new S3SandboxObjects(fx.s3.client, sfx.bucket, sfx.config.SCAN_S3_TIMEOUT_MS),
  );
  const sweeper = new SandboxSweeper({
    store: new PrismaSandboxStore(fx.prisma, {
      txTimeoutMs: sfx.config.SCAN_DB_TIMEOUT_MS,
      organizationIds: fx.organizationIds,
      risk: createRiskScorer({
        config: sfx.config,
        metrics: RiskMetrics.for(registry),
        logger: silentLogger,
      }),
    }),
    objects,
    locks,
    metrics: SandboxMetrics.for(registry),
    logger: silentLogger,
    intervalMs: 60_000,
    batchSize: 500,
    submissionTtlSeconds: sfx.config.SANDBOX_SUBMISSION_TTL_SECONDS,
    lockName: `scan:sandbox:it-sweep-${fx.suffix}`,
    now: () => new Date(Date.now() + offsetMs),
  });
  return { sweeper, objects, registry };
}

async function dispatched(round: SandboxRound) {
  const { jobs } = sfx.jobs();
  await deliver((e) => jobs.dispatcher.handle(e), round.event);
  const [analysis] = await sfx.analyses(round.sha256);
  sfx.track(analysis!);
  return analysis!;
}

describe('sandbox sweeper (X16)', () => {
  it('(a) a pending submission past SANDBOX_SUBMISSION_TTL_SECONDS → expired, timeout final', async () => {
    const org = await sfx.tenant('ttl');
    const round = await sfx.round(org, benignScript('ttl'));
    // A stopped dispatcher: the submission stays pending.
    const early = await sweeperAt(10 * 60_000).sweeper.sweepOnce();
    expect(early.submissionsExpired).toBe(0);
    const { sweeper } = sweeperAt(sfx.config.SANDBOX_SUBMISSION_TTL_SECONDS * 1000 + 60_000);
    const report = await sweeper.sweepOnce();
    expect(report.outcome).toBe('swept');
    expect(report.submissionsExpired).toBeGreaterThanOrEqual(1);
    expect(await sfx.submission(round)).toMatchObject({
      status: 'expired',
      sandboxVerdict: 'timeout',
    });
    expect(await sfx.finalOf(round)).toMatchObject({
      outcome: 'timeout',
      reasonCodes: ['sandbox.timeout'],
    });
  });

  it('(b, d) an analysis past its deadline → expired (timeout final, dedupe key cleared); its sample is deleted', async () => {
    const org = await sfx.tenant('deadline');
    const round = await sfx.round(org, benignScript('deadline'));
    const analysis = await dispatched(round);
    expect(await sfx.objectExists(analysis.sampleObjectKey!)).toBe(true);
    const { sweeper } = sweeperAt(sfx.config.SANDBOX_TASK_DEADLINE_SECONDS * 1000 + 60_000);
    const report = await sweeper.sweepOnce();
    expect(report.analysesExpired).toBeGreaterThanOrEqual(1);
    const expired = await sfx.prisma.sandboxAnalysis.findUniqueOrThrow({
      where: { id: analysis.id },
    });
    expect(expired).toMatchObject({ status: 'expired', verdict: 'timeout', dedupeKey: null });
    expect(expired.sampleDeletedAt).not.toBeNull();
    expect(await sfx.objectExists(analysis.sampleObjectKey!)).toBe(false);
    expect(await sfx.submission(round)).toMatchObject({
      status: 'expired',
      sandboxVerdict: 'timeout',
      externalRef: analysis.publicId,
    });
    expect(await sfx.finalOf(round)).toMatchObject({ outcome: 'timeout' });
    // A late result for the expired analysis is ignored.
    const { jobs } = sfx.jobs();
    const late = buildResult({
      taskId: analysis.publicId,
      analysisId: analysis.id.toString(),
      sampleSha256: analysis.sha256,
      resultKey: sfx.config.SANDBOX_RESULT_KEY,
      organizationId: analysis.organizationId.toString(),
      tokenSha256: analysis.resultTokenSha256 ?? '0'.repeat(64),
    });
    expect(await jobs.results.handle(sfx.resultEvent(org, late.payload))).toBe('handled');
    expect(
      (await sfx.prisma.sandboxAnalysis.findUniqueOrThrow({ where: { id: analysis.id } })).status,
    ).toBe('expired');
  });

  it('(e, f) artifact retention: wrapped key nulled before each object delete; then the analysis row goes', async () => {
    const org = await sfx.tenant('retention');
    const round = await sfx.round(org, benignScript('retention'));
    const analysis = await dispatched(round);
    const built = buildResult({
      taskId: analysis.publicId,
      analysisId: analysis.id.toString(),
      sampleSha256: analysis.sha256,
      resultKey: sfx.config.SANDBOX_RESULT_KEY,
      organizationId: analysis.organizationId.toString(),
      tokenSha256: analysis.resultTokenSha256 ?? '0'.repeat(64),
      artifacts: [
        { kind: 'static_report', bytes: Buffer.from('{"v":1}') },
        { kind: 'network_log', bytes: Buffer.from('synthetic\n') },
      ],
    });
    for (const object of built.objects) await sfx.putObject(object.key, object.body);
    const { jobs } = sfx.jobs();
    await jobs.results.handle(sfx.resultEvent(org, built.payload));
    const keys = built.objects.map((o) => o.key);
    for (const key of keys) expect(await sfx.objectExists(key)).toBe(true);

    // Before the retention: nothing is purged.
    const early = sweeperAt(DAY);
    expect((await early.sweeper.sweepOnce()).artifactKeysShredded).toBe(0);

    const later = sweeperAt((sfx.config.SANDBOX_ARTIFACT_RETENTION_DAYS + 1) * DAY);
    const report = await later.sweeper.sweepOnce();
    expect(report.artifactKeysShredded).toBeGreaterThanOrEqual(2);
    expect(report.artifactObjectsDeleted).toBeGreaterThanOrEqual(2);
    const observed = later.objects.artifactStates.filter((s) => keys.includes(s.key));
    expect(observed).toHaveLength(2);
    for (const state of observed) {
      expect(state.wrappedKey).toBeNull();
      expect(state.purgedAt).not.toBeNull();
    }
    for (const key of keys) expect(await sfx.objectExists(key)).toBe(false);
    const rows = await sfx.prisma.sandboxArtifact.findMany({ where: { analysisId: analysis.id } });
    expect(
      rows.every(
        (r) => r.wrappedKey === null && r.purgeReason === 'retention' && r.objectDeletedAt !== null,
      ),
    ).toBe(true);
    expect(await sfx.prisma.sandboxAnalysis.count({ where: { id: analysis.id } })).toBe(1);

    // After the analysis retention: artifact rows, then the analysis row are deleted.
    const end = sweeperAt((sfx.config.SANDBOX_ANALYSIS_RETENTION_DAYS + 1) * DAY);
    expect((await end.sweeper.sweepOnce()).analysesDeleted).toBeGreaterThanOrEqual(1);
    expect(await sfx.prisma.sandboxAnalysis.count({ where: { id: analysis.id } })).toBe(0);
    expect(await sfx.prisma.sandboxArtifact.count({ where: { analysisId: analysis.id } })).toBe(0);
    // The submission keeps its own (partition) retention and its terminal state.
    expect(await sfx.submission(round)).toMatchObject({ status: 'completed' });
  });
});
