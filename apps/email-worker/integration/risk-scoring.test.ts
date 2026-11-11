import { MetricsService, uuidv7 } from '@email-gateway/common';
import type { MessageRiskScore, Prisma } from '@email-gateway/database';
import { canonicalJson, resolveProfile, sha256Hex } from '@email-gateway/risk-scoring';
import type { AuthResults, EngineOutcome } from '@email-gateway/security-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DeadlineSweeper } from '../src/scanning/deadline-sweeper';
import { createRiskScorer, type RiskScorer } from '../src/scanning/risk/risk-scorer';
import { expiredOutcome, finishSubmissions } from '../src/scanning/sandbox/sandbox-finalizer';
import { SandboxMetrics } from '../src/scanning/sandbox/sandbox-metrics';
import { PrismaSandboxStore } from '../src/scanning/sandbox/sandbox-store';
import { ScanMetrics } from '../src/scanning/scan-metrics';
import { ScanRepository } from '../src/scanning/scan-repository';
import type { FinalRowInput, ScanRound } from '../src/scanning/scan-store';
import { testLocks } from './support/attachments';
import { silentLogger, workerConfig } from './support/fixtures';
import { benignScript, SandboxFixtures, type SandboxRound } from './support/sandbox';
import { ScanFixtures, type ScanMessage } from './support/scan';

/**
 * Package integration of risk scoring in the email-worker (step 5.1 §9.3, R13, ADR-0042) on the
 * real MySQL writer: the profile snapshot at round open, revision 0 in the completion transaction
 * (platform and tenant profiles, the snapshot wins over a later pointer change), revision 1 from a
 * sandbox final before and after completion (exactly once), rescans (new rows, old kept), the
 * fail-safe error row, idempotent redelivered completions and the deadline sweeper. Rounds are
 * opened and finalized through the production `ScanRepository`; engine results are synthetic
 * finals (codes and outcomes only). Profile rows are inserted directly (published), as the api
 * (WP4) would write them.
 */
const fx = new ScanFixtures();
let sfx: SandboxFixtures;
const config = workerConfig({ SCAN_ENGINES: 'rspamd', SANDBOX_ENABLED: 'true' });
const registry = new MetricsService({ service: `it-risk-${fx.suffix}` });
const metrics = new ScanMetrics(registry);
let risk: RiskScorer;
let repo: ScanRepository;
/** `duration_us` of every row read back, by row id. */
const durations = new Map<string, number>();

beforeAll(() => {
  sfx = new SandboxFixtures(fx);
  risk = createRiskScorer({ config, metrics: metrics.risk, logger: silentLogger });
  repo = new ScanRepository(fx.prisma, config.SCAN_DB_TIMEOUT_MS, risk, metrics.lifecycle);
});

afterAll(async () => {
  if (durations.size > 0) {
    const sorted = [...durations.values()].sort((a, b) => a - b);
    const p = (q: number) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))]!;
    // The measured scoring cost inside the completion / sandbox transaction (design §8).
    process.stdout.write(
      `risk scoring duration_us over ${String(sorted.length)} rows: min ${String(sorted[0])}, ` +
        `p50 ${String(p(0.5))}, p90 ${String(p(0.9))}, max ${String(sorted[sorted.length - 1])}\n`,
    );
  }
  await sfx?.cleanup();
  await fx.cleanup();
});

const passAuth = (): AuthResults => ({
  spf: { result: 'pass', domain: null },
  dkim: { result: 'pass', signatures: [] },
  dmarc: { result: 'pass', policy: 'reject', domain: null },
  arc: { result: 'none' },
});

const rspamdFinal = (
  outcome: EngineOutcome,
  reasonCodes: string[],
  over: Partial<FinalRowInput> = {},
): FinalRowInput => ({
  engine: 'rspamd',
  attempt: 1,
  outcome,
  errorCode: null,
  engineVersion: 'rspamd/3.12.1',
  score: outcome === 'spam' ? 11.25 : 0.4,
  requiredScore: 15,
  action: 'no action',
  reasonCodes,
  evidence: null,
  durationMs: 5,
  settingsVersion: 'rspamd-map/2;p=000000000000;t=none',
  auth: passAuth(),
  ...over,
});

async function openRound(message: ScanMessage, round = 0, deadlineSeconds = 1_800) {
  const record = await repo.loadMessage(
    message.messageId,
    message.receivedAt,
    message.organizationId,
  );
  if (!record) throw new Error('fixture message not found');
  const opened = await repo.openRound({
    message: record,
    round,
    scanKind: round === 0 ? 'initial' : 'rescan',
    trigger: round === 0 ? 'parsed' : 'rescan',
    engine: 'rspamd',
    eventId: uuidv7(),
    correlationId: `it-risk-${fx.suffix}`,
    requiredEngines: ['rspamd'],
    deadlineSeconds,
    now: new Date(),
  });
  if (opened.kind !== 'open') throw new Error(`round not opened: ${opened.reason}`);
  return opened.round;
}

function finalize(scan: ScanRound, final: FinalRowInput | null, eventId = uuidv7()) {
  return repo.finalize({
    consumer: fx.consumer('rspamd'),
    eventId,
    round: scan,
    final,
    completion: {
      causationEventId: eventId,
      correlationId: `it-risk-${fx.suffix}`,
      now: new Date(),
    },
  });
}

async function rows(scanId: bigint, receivedAt: Date): Promise<MessageRiskScore[]> {
  const found = await fx.prisma.messageRiskScore.findMany({
    where: { scanId, receivedAt },
    orderBy: { revision: 'asc' },
  });
  for (const r of found) durations.set(r.id.toString(), r.durationUs);
  return found;
}

const scanRow = (scan: ScanRound) =>
  fx.prisma.emailScan.findFirstOrThrow({ where: { id: scan.scanId, receivedAt: scan.receivedAt } });

/** A published tenant version (as the api's publish writes it) and, optionally, the pointer. */
async function publishVersion(
  organizationId: bigint,
  versionNo: number,
  overrides: Record<string, unknown>,
  activate = true,
): Promise<{ id: bigint; publicId: string }> {
  const profile = await fx.prisma.riskScoringProfile.upsert({
    where: { organizationId },
    create: { publicId: uuidv7(), organizationId },
    update: {},
  });
  const publicId = uuidv7();
  const resolved = resolveProfile('rsk-default/1', {
    publicId,
    versionNo,
    baseProfile: 'rsk-default/1',
    overrides,
  });
  expect(resolved.source).toBe('tenant');
  const version = await fx.prisma.riskScoringProfileVersion.create({
    data: {
      publicId,
      organizationId,
      profileId: profile.id,
      versionNo,
      status: 'published',
      baseProfile: 'rsk-default/1',
      overrides: overrides as Prisma.InputJsonObject,
      overridesSha256: sha256Hex(canonicalJson(overrides)),
      profileSha256: resolved.sha256,
      publishedAt: new Date(),
    },
  });
  if (activate) {
    await fx.prisma.riskScoringProfile.update({
      where: { id: profile.id },
      data: { activeVersionId: version.id, version: { increment: 1 } },
    });
  }
  return { id: version.id, publicId };
}

const sandboxStore = () =>
  new PrismaSandboxStore(fx.prisma, {
    txTimeoutMs: config.SCAN_DB_TIMEOUT_MS,
    organizationIds: fx.organizationIds,
    risk,
  });

/** Completes the round's sandbox submission with a malicious static result (X15). */
async function sandboxMalicious(round: SandboxRound): Promise<void> {
  const store = sandboxStore();
  const ctx = {
    now: new Date(),
    correlationId: `it-risk-${fx.suffix}`,
    metrics: SandboxMetrics.for(registry),
  };
  const submission = await sfx.submission(round);
  const result = await store.transaction(async (tx) => {
    const row = await tx.loadSubmission({ id: submission.id, receivedAt: submission.receivedAt });
    if (!row) throw new Error('submission not found');
    return finishSubmissions(
      tx,
      [
        {
          submission: row,
          outcome: {
            status: 'completed',
            verdict: 'malicious',
            reasonCodes: ['sandbox.static.eicar_test', 'sandbox.static_only'],
            executed: false,
            isolation: 'process',
            analysisPublicId: null,
          },
        },
      ],
      ctx,
    );
  });
  expect(result).toMatchObject({ changed: 1, finals: ['malicious'] });
}

const series = async (name: string, labels: Record<string, string>): Promise<number> => {
  const text = await registry.metrics();
  const wanted = Object.entries(labels).map(([k, v]) => `${k}="${v}"`);
  let total = 0;
  for (const line of text.split('\n')) {
    if (line.startsWith(`${name}{`) && wanted.every((w) => line.includes(w))) {
      total += Number(line.slice(line.lastIndexOf(' ') + 1));
    }
  }
  return total;
};

describe('risk scoring in the round completion (step 5.1 R13)', () => {
  it('revision 0 with the platform default: the row, the round columns, before scanned.v1', async () => {
    const org = await fx.organization('platform');
    const message = await fx.message(org, { eml: Buffer.from('x'), upload: false });
    const scan = await openRound(message);
    expect(scan.riskProfileVersionId).toBeNull();
    const result = await finalize(scan, rspamdFinal('clean', ['clean.below_threshold']));
    expect(result).toMatchObject({ completion: { kind: 'completed', transition: 'applied' } });

    const [row, ...more] = await rows(scan.scanId, scan.receivedAt);
    expect(more).toEqual([]);
    expect(row).toMatchObject({
      organizationId: org,
      messageId: message.messageId,
      lifecycleRound: 0,
      revision: 0,
      direction: 'inbound',
      status: 'scored',
      score: 0,
      level: 'none',
      verdict: 'clean',
      recommendedAction: 'deliver',
      profileSource: 'platform',
      profileVersionId: null,
      profileIdText: 'rsk-default/1',
      scorerVersion: 'risk-score/1',
      signalMapVersion: 'risk-signals/1',
      inputVersion: 'risk-input/1',
    });
    expect(row!.inputSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(row!.explanationText).toContain('Risk 0/1000');
    expect(await scanRow(scan)).toMatchObject({
      status: 'completed',
      verdict: 'clean',
      riskScore: 0,
      scoringVersion: 'risk-score/1',
      riskProfileVersionId: null,
    });
    // The row committed with scanned.v1 (same transaction): the event exists and so does the row.
    expect((await fx.state(message)).scanned).toHaveLength(1);
    expect(
      await series('scan_risk_scores_total', { revision: '0', level: 'none', status: 'scored' }),
    ).toBeGreaterThanOrEqual(1);
  });

  it('revision 0 with a published tenant version: its id, its overrides and the snapshot', async () => {
    const org = await fx.organization('tenant');
    const version = await publishVersion(org, 1, { actions: { medium: 'quarantine' } });
    const message = await fx.message(org, { eml: Buffer.from('x'), upload: false });
    const scan = await openRound(message);
    expect(scan.riskProfileVersionId).toBe(version.id);
    await finalize(scan, rspamdFinal('spam', ['spam.score']));
    const [row] = await rows(scan.scanId, scan.receivedAt);
    expect(row).toMatchObject({
      revision: 0,
      level: 'medium',
      verdict: 'spam',
      // The platform default recommends tag at medium; the tenant version says quarantine.
      recommendedAction: 'quarantine',
      profileSource: 'tenant',
      profileVersionId: version.id,
      profileIdText: `rsk-default/1+t:${version.publicId}#1`,
    });
    expect(await scanRow(scan)).toMatchObject({
      riskProfileVersionId: version.id,
      verdict: 'spam',
    });
  });

  it('a pointer change after the round opened applies to the next round only; a rescan keeps the old rows', async () => {
    const org = await fx.organization('snapshot');
    const v1 = await publishVersion(org, 1, { actions: { medium: 'quarantine' } });
    const message = await fx.message(org, { eml: Buffer.from('x'), upload: false });
    const first = await openRound(message);
    // Published and activated while the round is open.
    const v2 = await publishVersion(org, 2, { actions: { medium: 'require_approval' } });
    await finalize(first, rspamdFinal('spam', ['spam.score']));
    const [firstRow] = await rows(first.scanId, first.receivedAt);
    expect(firstRow).toMatchObject({ profileVersionId: v1.id, recommendedAction: 'quarantine' });

    // Administrative rescan (E19): a new round with its own snapshot and its own row.
    const rescan = await fx.rescan(message);
    const round = (rescan.payload as { lifecycleRound: number }).lifecycleRound;
    const second = await openRound(message, round);
    expect(second.scanId).not.toBe(first.scanId);
    expect(second.riskProfileVersionId).toBe(v2.id);
    await finalize(second, rspamdFinal('spam', ['spam.score']));
    const [secondRow] = await rows(second.scanId, second.receivedAt);
    expect(secondRow).toMatchObject({
      lifecycleRound: round,
      profileVersionId: v2.id,
      recommendedAction: 'require_approval',
    });
    // The first round's row is never updated.
    expect((await rows(first.scanId, first.receivedAt))[0]).toEqual(firstRow);
  });

  it('a scoring failure writes the fail-safe error row and the round still completes', async () => {
    const org = await fx.organization('error-row');
    // A published row the scorer cannot resolve (a malformed public id written by a defect):
    // profile_error. Malformed engine codes cannot reach here: scanned.v1 refuses them first.
    const profile = await fx.prisma.riskScoringProfile.create({
      data: { publicId: uuidv7(), organizationId: org },
    });
    const broken = await fx.prisma.riskScoringProfileVersion.create({
      data: {
        publicId: 'zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz',
        organizationId: org,
        profileId: profile.id,
        versionNo: 1,
        status: 'published',
        baseProfile: 'rsk-default/1',
        overrides: {},
        overridesSha256: sha256Hex(canonicalJson({})),
        publishedAt: new Date(),
      },
    });
    await fx.prisma.riskScoringProfile.update({
      where: { id: profile.id },
      data: { activeVersionId: broken.id },
    });
    const message = await fx.message(org, { eml: Buffer.from('x'), upload: false });
    const scan = await openRound(message);
    expect(scan.riskProfileVersionId).toBe(broken.id);
    const result = await finalize(scan, rspamdFinal('clean', ['clean.below_threshold']));
    expect(result).toMatchObject({ completion: { kind: 'completed', transition: 'applied' } });
    const [row] = await rows(scan.scanId, scan.receivedAt);
    expect(row).toMatchObject({
      status: 'error',
      score: 550,
      level: 'high',
      verdict: 'unknown',
      recommendedAction: 'quarantine',
      profileSource: 'platform',
      profileVersionId: null,
    });
    expect(row!.reasonCodes as string[]).toContain('risk.scoring_error');
    expect(row!.explanationText).toContain('fail-safe');
    expect(await scanRow(scan)).toMatchObject({ status: 'completed', riskScore: 550 });
    expect((await fx.state(message)).scanned).toHaveLength(1);
    expect(await series('scan_risk_errors_total', { reason: 'profile_error' })).toBe(1);
  });

  it('a redelivered completion is idempotent: one row per round and revision', async () => {
    const org = await fx.organization('redelivery');
    const message = await fx.message(org, { eml: Buffer.from('x'), upload: false });
    const scan = await openRound(message);
    const eventId = uuidv7();
    await finalize(scan, rspamdFinal('clean', ['clean.below_threshold']), eventId);
    const [before] = await rows(scan.scanId, scan.receivedAt);
    expect(await finalize(scan, rspamdFinal('clean', ['clean.below_threshold']), eventId)).toEqual({
      kind: 'duplicate',
    });
    // Another delivery of the engine (a new event id): the round is no longer running.
    expect(await finalize(scan, null)).toMatchObject({
      completion: { kind: 'already_completed' },
    });
    expect(await rows(scan.scanId, scan.receivedAt)).toEqual([before]);
  });

  it('the deadline sweeper completes overdue rounds through the same path: they are scored', async () => {
    const org = await fx.organization('sweeper');
    const message = await fx.message(org, { eml: Buffer.from('x'), upload: false });
    const scan = await openRound(message, 0, 1);
    await new Promise((r) => setTimeout(r, 1_100));
    const locks = testLocks();
    try {
      const sweeper = new DeadlineSweeper({
        store: repo,
        locks,
        metrics,
        logger: silentLogger,
        intervalMs: 60_000,
        lookbackHours: 48,
        batchSize: 50,
        lockName: `it-risk:deadline:${fx.suffix}`,
        organizationIds: [org],
      });
      expect(await sweeper.sweepOnce()).toMatchObject({ outcome: 'swept', completed: 1 });
    } finally {
      await locks.close();
    }
    const [row] = await rows(scan.scanId, scan.receivedAt);
    expect(row).toMatchObject({ revision: 0, status: 'scored', recommendedAction: 'quarantine' });
    expect(row!.reasonCodes as string[]).toContain('risk.engine.rspamd.timeout');
    expect(await scanRow(scan)).toMatchObject({ status: 'timed_out', verdict: 'unknown' });
  });
});

describe('risk revision 1 from the sandbox (step 5.1 R13 (a)/(b))', () => {
  it('sandbox final before completion: completion writes revisions 0 and 1, exactly once', async () => {
    const org = await sfx.tenant('sbx-before');
    const round = await sfx.round(org, benignScript('risk-before'), {
      required: ['attachment', 'dlp'],
    });
    await sandboxMalicious(round);
    // The round is still running: no row yet (revision 1 waits for completion).
    expect(await rows(round.scan.scanId, round.scan.receivedAt)).toEqual([]);
    await sfx.completeRound(round.scan);
    const written = await rows(round.scan.scanId, round.scan.receivedAt);
    expect(written.map((r) => r.revision)).toEqual([0, 1]);
    // Revision 0 never includes the sandbox; revision 1 adds it (hard block, critical).
    expect(written[0]!.evidence).toMatchObject({ sandbox: null });
    expect(written[0]!.level).not.toBe('critical');
    expect(written[1]).toMatchObject({ level: 'critical', verdict: 'malware' });
    expect(written[1]!.hardBlocks).toEqual([expect.objectContaining({ id: 'hb.malware_sandbox' })]);
    // The round row carries revision 0 only.
    expect(await sfx.scanRow(round)).toMatchObject({ riskScore: written[0]!.score });
    // A second finisher (sweeper re-check) finds the final: nothing more.
    const again = await sandboxStore().transaction(async (tx) => {
      const row = await tx.loadSubmission({
        id: (await sfx.submission(round)).id,
        receivedAt: round.scan.receivedAt,
      });
      return finishSubmissions(tx, [{ submission: row!, outcome: expiredOutcome() }], {
        now: new Date(),
        correlationId: 'x',
        metrics: SandboxMetrics.for(registry),
      });
    });
    expect(again).toEqual({ changed: 0, finals: [] });
    expect(await rows(round.scan.scanId, round.scan.receivedAt)).toHaveLength(2);
  });

  it('sandbox final after completion: the sandbox transaction writes revision 1, exactly once', async () => {
    const org = await sfx.tenant('sbx-after');
    const round = await sfx.round(org, benignScript('risk-after'));
    // Required ['attachment']: the round completed with the attachment final.
    expect((await rows(round.scan.scanId, round.scan.receivedAt)).map((r) => r.revision)).toEqual([
      0,
    ]);
    await sandboxMalicious(round);
    const written = await rows(round.scan.scanId, round.scan.receivedAt);
    expect(written.map((r) => r.revision)).toEqual([0, 1]);
    expect(written[1]).toMatchObject({
      level: 'critical',
      verdict: 'malware',
      lifecycleRound: round.scan.round,
    });
    // A second attempt (a concurrent or repeated finisher) is a counted no-op.
    const duplicatesBefore = await series('scan_risk_duplicates_total', { revision: '1' });
    const scanRef = {
      scanId: round.scan.scanId,
      receivedAt: round.scan.receivedAt,
      organizationId: org,
      messageId: round.message.messageId,
    };
    const record = await fx.prisma.$transaction((tx) => risk.scoreSandboxRevision(tx, scanRef));
    expect(record).toMatchObject({ kind: 'duplicate', revision: 1 });
    risk.record([record!]);
    expect(await series('scan_risk_duplicates_total', { revision: '1' })).toBe(
      duplicatesBefore + 1,
    );
    expect(await rows(round.scan.scanId, round.scan.receivedAt)).toHaveLength(2);
    // The round row still carries revision 0.
    expect(await sfx.scanRow(round)).toMatchObject({ riskScore: written[0]!.score });
  });
});
