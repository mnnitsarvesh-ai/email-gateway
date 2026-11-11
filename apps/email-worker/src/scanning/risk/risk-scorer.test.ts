import * as library from '@email-gateway/risk-scoring';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FakeRiskDb, ORG, riskSetup, round, series, VERSION_PUBLIC_ID } from './fakes.test-support';
import { toRiskFinal } from './risk-reader';

vi.mock('@email-gateway/risk-scoring', async (importOriginal) => {
  const actual = await importOriginal<typeof library>();
  return { ...actual, scoreRisk: vi.fn(actual.scoreRisk) };
});

/** A clean rspamd-only round (the fake's scan row requires rspamd). */
function cleanDb() {
  const db = new FakeRiskDb();
  db.addFinal({
    engine: 'rspamd',
    outcome: 'clean',
    reasonCodes: ['clean.below_threshold'],
    score: '0.5',
  });
  db.addAuth();
  return db;
}

const finalsOf = (db: FakeRiskDb) =>
  db.results.filter((r) => r.isFinal).map((r) => toRiskFinal(r as never));

afterEach(() => vi.mocked(library.scoreRisk).mockClear());

describe('RiskScorer (step 5.1 R13)', () => {
  it('writes revision 0 with the platform profile and sets the round row', async () => {
    const db = cleanDb();
    const { scorer, registry } = riskSetup();
    const record = await scorer.scoreRound(db.tx(), round(), 0, {
      scanStatus: 'completed',
      finals: finalsOf(db),
    });
    expect(record).toMatchObject({
      kind: 'written',
      revision: 0,
      level: 'none',
      action: 'deliver',
    });
    expect(db.riskRows).toHaveLength(1);
    expect(db.riskRows[0]).toMatchObject({
      scanId: round().scanId,
      organizationId: ORG,
      revision: 0,
      lifecycleRound: 0,
      direction: 'inbound',
      status: 'scored',
      score: 0,
      level: 'none',
      verdict: 'clean',
      recommendedAction: 'deliver',
      profileSource: 'platform',
      profileIdText: 'rsk-default/1',
      profileVersionId: null,
      scorerVersion: 'risk-score/1',
      signalMapVersion: 'risk-signals/1',
      inputVersion: 'risk-input/1',
      durationUs: 1500,
    });
    expect(db.riskRows[0]!.inputSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(db.scanUpdates).toEqual([
      { verdict: 'clean', riskScore: 0, scoringVersion: 'risk-score/1' },
    ]);
    // Metrics only after the caller's commit.
    expect(await series(registry, 'scan_risk_scores_total')).toBe(0);
    scorer.record([record]);
    expect(
      await series(registry, 'scan_risk_scores_total', {
        revision: '0',
        level: 'none',
        action: 'deliver',
        direction: 'inbound',
        status: 'scored',
      }),
    ).toBe(1);
    expect(await series(registry, 'scan_risk_trust_total', { status: 'not_trusted' })).toBe(1);
    expect(await series(registry, 'scan_risk_duration_seconds_count')).toBe(1);
    expect(await series(registry, 'scan_risk_score_count', { revision: '0' })).toBe(1);
  });

  it('scores with the tenant snapshot and stores its version id', async () => {
    const db = cleanDb();
    db.addVersion();
    const { scorer } = riskSetup();
    await scorer.scoreRound(db.tx(), round({ riskProfileVersionId: 501n }), 0, {
      scanStatus: 'completed',
      finals: finalsOf(db),
    });
    expect(db.riskRows[0]).toMatchObject({
      profileSource: 'tenant',
      profileIdText: `rsk-default/1+t:${VERSION_PUBLIC_ID}#3`,
      profileVersionId: 501n,
    });
  });

  it('a foreign version is scored with the platform default and counted', async () => {
    const db = cleanDb();
    db.addVersion({ organizationId: 8n });
    const { scorer, registry } = riskSetup();
    const record = await scorer.scoreRound(db.tx(), round({ riskProfileVersionId: 501n }), 0, {
      scanStatus: 'completed',
      finals: finalsOf(db),
    });
    expect(db.riskRows[0]).toMatchObject({ profileSource: 'platform', profileVersionId: null });
    expect(db.riskRows[0]!.reasonCodes).toContain('risk.profile.foreign_fallback');
    scorer.record([record]);
    expect(await series(registry, 'scan_risk_profile_fallback_total', { reason: 'foreign' })).toBe(
      1,
    );
  });

  it('a failed round is never clean: failure floors and the engine failure series', async () => {
    const db = new FakeRiskDb();
    db.addFinal({
      engine: 'rspamd',
      outcome: 'timeout',
      errorCode: 'deadline_exceeded',
      reasonCodes: ['engine.deadline_exceeded'],
    });
    const { scorer, registry } = riskSetup();
    const record = await scorer.scoreRound(db.tx(), round(), 0, {
      scanStatus: 'timed_out',
      finals: finalsOf(db),
    });
    expect(db.riskRows[0]).toMatchObject({ status: 'scored', recommendedAction: 'quarantine' });
    expect(db.riskRows[0]!.verdict).not.toBe('clean');
    expect(db.riskRows[0]!.reasonCodes).toContain('risk.engine.rspamd.timeout');
    scorer.record([record]);
    expect(
      await series(registry, 'scan_risk_engine_failures_total', {
        engine: 'rspamd',
        status: 'timeout',
      }),
    ).toBe(1);
  });

  it('an input the builder refuses writes the fail-safe error row (input_invalid)', async () => {
    const db = new FakeRiskDb();
    db.addFinal({ engine: 'rspamd', outcome: 'clean', reasonCodes: ['NOT A CODE'] });
    const { scorer, registry } = riskSetup();
    const record = await scorer.scoreRound(db.tx(), round(), 0, {
      scanStatus: 'completed',
      finals: finalsOf(db),
    });
    expect(record).toMatchObject({ kind: 'written', errorReason: 'input_invalid' });
    expect(db.riskRows[0]).toMatchObject({
      status: 'error',
      level: 'high',
      verdict: 'unknown',
      recommendedAction: 'quarantine',
      score: 550,
    });
    expect(db.riskRows[0]!.reasonCodes).toContain('risk.scoring_error');
    expect(db.scanUpdates).toEqual([
      { verdict: 'unknown', riskScore: 550, scoringVersion: 'risk-score/1' },
    ]);
    scorer.record([record]);
    expect(await series(registry, 'scan_risk_errors_total', { reason: 'input_invalid' })).toBe(1);
    expect(await series(registry, 'scan_risk_scores_total', { status: 'error' })).toBe(1);
  });

  it('an exception of the scorer writes the error row (scorer_exception)', async () => {
    const db = cleanDb();
    vi.mocked(library.scoreRisk).mockImplementationOnce(() => {
      throw new Error('defect');
    });
    const { scorer, registry } = riskSetup();
    const record = await scorer.scoreRound(db.tx(), round(), 0, {
      scanStatus: 'completed',
      finals: finalsOf(db),
    });
    expect(record).toMatchObject({ errorReason: 'scorer_exception' });
    expect(db.riskRows[0]).toMatchObject({ status: 'error', recommendedAction: 'quarantine' });
    // The error row still hashes the input that was built.
    expect(db.riskRows[0]!.inputSha256).not.toBe(library.sha256Hex('risk-input/unavailable'));
    scorer.record([record]);
    expect(await series(registry, 'scan_risk_errors_total', { reason: 'scorer_exception' })).toBe(
      1,
    );
  });

  it('a malformed profile row writes the error row (profile_error) with the platform profile', async () => {
    const db = cleanDb();
    db.addVersion({ publicId: 'broken' });
    const { scorer, registry } = riskSetup();
    const record = await scorer.scoreRound(db.tx(), round({ riskProfileVersionId: 501n }), 0, {
      scanStatus: 'completed',
      finals: finalsOf(db),
    });
    expect(db.riskRows[0]).toMatchObject({ status: 'error', profileSource: 'platform' });
    scorer.record([record]);
    expect(await series(registry, 'scan_risk_errors_total', { reason: 'profile_error' })).toBe(1);
  });

  it('a second attempt of the same revision is a counted no-op (unique key)', async () => {
    const db = cleanDb();
    const { scorer, registry } = riskSetup();
    const ctx = { scanStatus: 'completed' as const, finals: finalsOf(db) };
    const first = await scorer.scoreRound(db.tx(), round(), 0, ctx);
    const second = await scorer.scoreRound(db.tx(), round(), 0, ctx);
    expect(second).toMatchObject({ kind: 'duplicate', revision: 0 });
    expect(db.riskRows).toHaveLength(1);
    expect(db.scanUpdates).toHaveLength(1);
    scorer.record([first, second]);
    expect(await series(registry, 'scan_risk_duplicates_total', { revision: '0' })).toBe(1);
    expect(await series(registry, 'scan_risk_scores_total')).toBe(1);
  });

  it('revision 1 adds the sandbox and never touches the round row', async () => {
    const db = cleanDb();
    db.addFinal({
      engine: 'sandbox',
      outcome: 'malicious',
      reasonCodes: ['sandbox.static.eicar_test'],
    });
    const { scorer, registry } = riskSetup();
    const record = await scorer.scoreRound(db.tx(), round(), 1, {
      scanStatus: 'completed',
      finals: finalsOf(db),
    });
    expect(db.riskRows[0]).toMatchObject({ revision: 1, level: 'critical', verdict: 'malware' });
    expect(db.scanUpdates).toEqual([]);
    scorer.record([record]);
    expect(
      await series(registry, 'scan_risk_hard_blocks_total', { indicator: 'hb.malware_sandbox' }),
    ).toBe(1);
  });

  it('a missing message row writes nothing and is counted as skipped', async () => {
    const db = cleanDb();
    db.messages = [];
    const { scorer, registry } = riskSetup();
    const record = await scorer.scoreRound(db.tx(), round(), 0, {
      scanStatus: 'completed',
      finals: finalsOf(db),
    });
    expect(record).toMatchObject({ kind: 'skipped', reason: 'message_gone' });
    expect(db.riskRows).toEqual([]);
    scorer.record([record]);
    expect(
      await series(registry, 'scan_risk_skipped_total', { revision: '0', reason: 'message_gone' }),
    ).toBe(1);
  });

  it('an unmapped engine code contributes nothing but is counted by engine', async () => {
    const db = new FakeRiskDb();
    db.addFinal({
      engine: 'rspamd',
      outcome: 'clean',
      reasonCodes: ['clean.below_threshold', 'future.new_signal'],
    });
    db.addAuth();
    const { scorer, registry } = riskSetup();
    const record = await scorer.scoreRound(db.tx(), round(), 0, {
      scanStatus: 'completed',
      finals: finalsOf(db),
    });
    expect(db.riskRows[0]!.verdict).toBe('unknown');
    scorer.record([record]);
    expect(await series(registry, 'scan_risk_unmapped_codes_total', { engine: 'rspamd' })).toBe(1);
  });

  it('database errors propagate (the completion rolls back and is retried)', async () => {
    const db = cleanDb();
    db.failRiskInsert = Object.assign(new Error('lock wait timeout'), { code: 'P2034' });
    const { scorer } = riskSetup();
    await expect(
      scorer.scoreRound(db.tx(), round(), 0, { scanStatus: 'completed', finals: finalsOf(db) }),
    ).rejects.toThrow('lock wait timeout');
  });

  it('the sandbox path scores revision 1 only for a round that is no longer running', async () => {
    const db = cleanDb();
    db.addFinal({ engine: 'sandbox', outcome: 'suspicious', reasonCodes: [] });
    const { scorer } = riskSetup();
    const ref = {
      scanId: round().scanId,
      receivedAt: round().receivedAt,
      organizationId: ORG,
      messageId: round().messageId,
    };
    expect(await scorer.scoreSandboxRevision(db.tx(), ref)).toBeNull();
    db.scan.status = 'failed';
    expect(await scorer.scoreSandboxRevision(db.tx(), ref)).toMatchObject({
      kind: 'written',
      revision: 1,
    });
    expect(db.riskRows[0]).toMatchObject({ revision: 1 });
    expect(db.riskRows[0]!.evidence).toMatchObject({ sandbox: { outcome: 'suspicious' } });
    // A failed round keeps its failure floor in revision 1 too (status from the locked row).
    expect(db.riskRows[0]!.recommendedAction).toBe('quarantine');
  });
});
