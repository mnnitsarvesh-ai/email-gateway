import { EventTypes } from '@email-gateway/event-contracts';
import * as lifecycle from '@email-gateway/message-lifecycle';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DeadlineSweeper } from '../deadline-sweeper';
import { newMetrics } from '../fakes.test-support';
import { ScanRepository } from '../scan-repository';
import type { FinalRowInput, ScanRound } from '../scan-store';
import {
  FakeRiskDb,
  MESSAGE,
  ORG,
  RECEIVED,
  riskSetup,
  SCAN,
  series,
  silentLogger,
} from './fakes.test-support';

/**
 * Step 5.1 R13 in `ScanRepository`: the round's completion (shared by the engines' finalize and
 * the deadline sweeper) writes the risk score before the lifecycle transition, whatever the
 * transition's result; the open transaction stores the profile snapshot. The lifecycle service is
 * replaced by recorders (its own tests cover it); every other statement runs against the fake.
 */
vi.mock('@email-gateway/message-lifecycle', async (importOriginal) => {
  const actual = await importOriginal<typeof lifecycle>();
  return { ...actual, lockLifecycle: vi.fn(), transitionMessage: vi.fn() };
});

const EML = `org/${ORG.toString()}/eml/2026/11/10/${MESSAGE.toString()}.eml`;
const snapshot = (state = 'scanning') =>
  ({
    state,
    round: 0,
    version: 2,
    direction: 'inbound',
    emlObjectKey: EML,
  }) as unknown as lifecycle.LifecycleSnapshot;

let db: FakeRiskDb;
let transition: 'applied' | 'stale' | Error = 'applied';

beforeEach(() => {
  db = new FakeRiskDb();
  transition = 'applied';
  vi.mocked(lifecycle.lockLifecycle).mockReset();
  vi.mocked(lifecycle.lockLifecycle).mockImplementation(() => Promise.resolve(snapshot()));
  vi.mocked(lifecycle.transitionMessage).mockReset();
  vi.mocked(lifecycle.transitionMessage).mockImplementation((_tx, request) => {
    db.log.push(`transition:${request.to}`);
    if (transition instanceof Error) return Promise.reject(transition);
    return Promise.resolve(
      transition === 'applied'
        ? ({ result: 'applied', snapshot: snapshot(request.to) } as never)
        : ({ result: 'stale', why: 'overtaken', snapshot: snapshot('scanned') } as never),
    );
  });
});

function repository() {
  const risk = riskSetup();
  const { metrics } = newMetrics();
  const repo = new ScanRepository(db.client(), 120_000, risk.scorer, metrics.lifecycle);
  return { repo, ...risk, scanMetrics: metrics };
}

const scanRound = (): ScanRound => ({
  scanId: SCAN,
  receivedAt: RECEIVED,
  messageId: MESSAGE,
  organizationId: ORG,
  round: 0,
  scanKind: 'initial',
  requiredEngines: ['rspamd'],
  startedAt: RECEIVED,
  deadlineAt: new Date(RECEIVED.getTime() + 60_000),
  riskProfileVersionId: null,
});

const rspamdFinal = (over: Partial<FinalRowInput> = {}): FinalRowInput => ({
  engine: 'rspamd',
  attempt: 1,
  outcome: 'clean',
  errorCode: null,
  engineVersion: 'rspamd/3.12.1',
  score: 0.4,
  requiredScore: 15,
  action: 'no action',
  reasonCodes: ['clean.below_threshold'],
  evidence: null,
  durationMs: 12,
  settingsVersion: 'rspamd-map/2;p=000000000000;t=none',
  auth: null,
  ...over,
});

const finalize = (repo: ScanRepository, eventId = 'e-1', final = rspamdFinal()) =>
  repo.finalize({
    consumer: 'it',
    eventId,
    round: scanRound(),
    final,
    completion: { causationEventId: eventId, correlationId: 'c', now: new Date() },
  });

describe('round completion writes the risk score (step 5.1 R13, ADR-0042)', () => {
  it('scores revision 0 after the email_scans update and before the transition and scanned.v1', async () => {
    db.addAuth();
    const { repo, registry } = repository();
    const result = await finalize(repo);
    expect(result).toMatchObject({
      kind: 'handled',
      completion: { kind: 'completed', transition: 'applied' },
    });
    expect(db.log).toEqual([
      'final:rspamd',
      'scan:complete',
      'risk:0',
      'scan:risk',
      'transition:scanned',
      `outbox:${EventTypes.MessageScanned}`,
    ]);
    expect(db.riskRows).toHaveLength(1);
    expect(db.riskRows[0]).toMatchObject({ revision: 0, status: 'scored', verdict: 'clean' });
    // Recorded after the commit.
    expect(await series(registry, 'scan_risk_scores_total', { revision: '0' })).toBe(1);
  });

  it('writes the score even when the transition is stale (the score belongs to the round)', async () => {
    transition = 'stale';
    const { repo } = repository();
    const result = await finalize(repo);
    expect(result).toMatchObject({ completion: { kind: 'completed', transition: 'stale' } });
    expect(db.log).toEqual([
      'final:rspamd',
      'scan:complete',
      'risk:0',
      'scan:risk',
      'transition:scanned',
    ]);
    expect(db.riskRows).toHaveLength(1);
    expect(db.outbox).toEqual([]);
  });

  it('records nothing when the completion transaction fails after scoring', async () => {
    transition = Object.assign(new Error('deadlock'), { code: 'P2034' });
    const { repo, registry } = repository();
    await expect(finalize(repo)).rejects.toThrow('deadlock');
    expect(await series(registry, 'scan_risk_scores_total')).toBe(0);
  });

  it('a redelivered completion is a ledger duplicate: no second score', async () => {
    const { repo } = repository();
    await finalize(repo, 'e-1');
    expect(await finalize(repo, 'e-1')).toEqual({ kind: 'duplicate' });
    // Another event of the engine after completion: the round is no longer running.
    expect(await finalize(repo, 'e-2')).toMatchObject({
      completion: { kind: 'already_completed' },
    });
    expect(db.riskRows).toHaveLength(1);
  });

  it('a sandbox final present at completion adds revision 1 in the same transaction', async () => {
    db.addFinal({
      engine: 'sandbox',
      outcome: 'malicious',
      reasonCodes: ['sandbox.static.eicar_test'],
    });
    const { repo } = repository();
    await finalize(repo);
    expect(db.log.slice(0, 5)).toEqual([
      'final:rspamd',
      'scan:complete',
      'risk:0',
      'scan:risk',
      'risk:1',
    ]);
    expect(db.riskRows.map((r) => [r.revision, r.level])).toEqual([
      [0, expect.not.stringMatching(/^critical$/) as unknown],
      [1, 'critical'],
    ]);
    // Revision 0 never includes the sandbox (order independence).
    expect(db.riskRows[0]!.evidence).toMatchObject({ sandbox: null });
    expect(db.scanUpdates.filter((u) => u.riskScore !== undefined)).toHaveLength(1);
  });

  it('a skipped sandbox final gives no revision 1', async () => {
    db.addFinal({
      engine: 'sandbox',
      outcome: 'skipped',
      reasonCodes: ['sandbox.skipped.type_excluded'],
    });
    const { repo } = repository();
    await finalize(repo);
    expect(db.riskRows.map((r) => r.revision)).toEqual([0]);
  });

  it('a round whose message row is gone completes without a score (counted as skipped)', async () => {
    vi.mocked(lifecycle.lockLifecycle).mockImplementation(() => Promise.resolve(null));
    db.messages = [];
    transition = 'stale';
    const { repo, registry } = repository();
    await finalize(repo);
    expect(db.riskRows).toEqual([]);
    expect(
      await series(registry, 'scan_risk_skipped_total', { revision: '0', reason: 'message_gone' }),
    ).toBe(1);
  });

  it('the deadline sweeper completes through the same function: swept rounds are scored', async () => {
    const { repo, registry } = repository();
    const { metrics } = newMetrics();
    const sweeper = new DeadlineSweeper({
      store: repo,
      locks: { ensure: () => Promise.resolve(true), release: () => Promise.resolve() },
      metrics,
      logger: silentLogger,
      intervalMs: 10,
      lookbackHours: 48,
      batchSize: 10,
      now: () => new Date(RECEIVED.getTime() + 3_600_000),
    });
    const report = await sweeper.sweepOnce();
    expect(report).toMatchObject({ outcome: 'swept', completed: 1, finalizedEngines: 1 });
    expect(db.log).toEqual([
      'final:rspamd',
      'scan:complete',
      'risk:0',
      'scan:risk',
      'transition:scan_failed',
      `outbox:${EventTypes.MessageScanned}`,
    ]);
    expect(db.riskRows[0]).toMatchObject({
      revision: 0,
      status: 'scored',
      recommendedAction: 'quarantine',
    });
    expect(db.riskRows[0]!.reasonCodes).toContain('risk.engine.rspamd.timeout');
    expect(
      await series(registry, 'scan_risk_scores_total', { revision: '0', action: 'quarantine' }),
    ).toBe(1);
  });
});

describe('profile snapshot at round open (step 5.1 R13)', () => {
  const open = (repo: ScanRepository, eventId: string) =>
    repo.openRound({
      message: {
        id: MESSAGE,
        receivedAt: RECEIVED,
        organizationId: ORG,
        direction: 'inbound',
        emlObjectKey: EML,
        sizeBytes: 10,
        clientIp: null,
        clientHelo: null,
        clientName: null,
        envelopeFrom: '',
        mtaQueueId: null,
        recipients: [],
      },
      round: 0,
      scanKind: 'initial',
      trigger: 'parsed',
      engine: 'rspamd',
      eventId,
      correlationId: 'c',
      requiredEngines: ['rspamd'],
      deadlineSeconds: 60,
      now: RECEIVED,
    });

  it('stores the active version with the email_scans insert; the first opener wins', async () => {
    db.scans = [];
    db.profiles.push({ organizationId: ORG, activeVersionId: 501n });
    const { repo } = repository();
    const first = await open(repo, 'e-1');
    expect(first).toMatchObject({ kind: 'open', round: { riskProfileVersionId: 501n } });
    // The pointer changes while the round is open: a second engine joins the same round.
    db.profiles[0]!.activeVersionId = 777n;
    const second = await open(repo, 'e-2');
    expect(second).toMatchObject({ kind: 'open', round: { riskProfileVersionId: 501n } });
    expect(db.scans).toHaveLength(1);
    expect(db.scans[0]!.risk_profile_version_id).toBe(501n);
  });

  it('no profile row: NULL (platform default)', async () => {
    db.scans = [];
    const { repo } = repository();
    expect(await open(repo, 'e-1')).toMatchObject({ round: { riskProfileVersionId: null } });
  });

  it('completion scores with the snapshot, not with the current pointer', async () => {
    db.addVersion();
    db.addVersion({ id: 777n, publicId: '0196f3a0-0000-7000-8000-0000000000ff', versionNo: 4 });
    db.profiles.push({ organizationId: ORG, activeVersionId: 777n });
    db.scan.risk_profile_version_id = 501n;
    const { repo } = repository();
    await finalize(repo);
    expect(db.riskRows[0]).toMatchObject({ profileSource: 'tenant', profileVersionId: 501n });
    expect(String(db.riskRows[0]!.profileIdText)).toMatch(/#3$/);
  });
});
