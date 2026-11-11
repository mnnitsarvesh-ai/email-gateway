import { EventTypes } from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import { FakeSandboxStore, newSandboxMetrics } from './fakes.test-support';
import {
  expiredOutcome,
  finishSubmissions,
  outcomeFromAnalysis,
  SANDBOX_ENGINE_VERSION,
  type SubmissionOutcome,
  writeRoundFinal,
} from './sandbox-finalizer';
import { scanKey } from './sandbox-store';

const NOW = new Date('2026-11-08T10:00:00.000Z');
const RECEIVED = new Date('2026-11-08T09:00:00.000Z');
const ORG = 7n;

function setup() {
  const store = new FakeSandboxStore();
  const { metrics, registry } = newSandboxMetrics();
  const scan = {
    scanId: 77n,
    receivedAt: RECEIVED,
    organizationId: ORG,
    messageId: 5n,
    lifecycleRound: 2,
  };
  store.addScan(scan);
  const sub = (partIndex: number, status: 'pending' | 'submitted' = 'submitted') =>
    store.addSubmission({
      scanId: scan.scanId,
      receivedAt: RECEIVED,
      organizationId: ORG,
      messageId: scan.messageId,
      partIndex,
      status,
      settingsVersion: `sandbox-map/1;p=aaaaaaaaaaaa;t=${partIndex}`,
    });
  const ctx = { now: NOW, correlationId: 'corr', metrics };
  return { store, metrics, registry, scan, sub, ctx };
}

const malicious = (store: FakeSandboxStore) => {
  const a = store.addAnalysis({
    sha256: 'e'.repeat(64),
    organizationId: ORG,
    status: 'completed',
    verdict: 'malicious',
    reasonCodes: ['sandbox.static.eicar_test', 'sandbox.static_only'],
    executed: false,
    isolation: 'process',
    controllerVersion: 'sandbox-controller/0.1.0',
    backend: 'static',
    backendVersion: 'sandbox-static/1',
  });
  return a;
};

describe('sandbox finalizer (X15)', () => {
  it('writes the round final only when every submission of the round is terminal', async () => {
    const t = setup();
    const first = t.sub(1);
    const second = t.sub(2);
    const analysis = malicious(t.store);
    t.store.submission(first.id).analysisId = analysis.id;
    await t.store.transaction((tx) =>
      finishSubmissions(
        tx,
        [{ submission: t.store.submission(first.id), outcome: outcomeFromAnalysis(analysis) }],
        t.ctx,
      ),
    );
    expect(t.store.final(t.scan.scanId, RECEIVED)).toBeUndefined();
    const outcome: SubmissionOutcome = {
      status: 'skipped',
      skipReason: 'type_excluded',
      settingsVersion: null,
    };
    const report = await t.store.transaction((tx) =>
      finishSubmissions(tx, [{ submission: second, outcome }], t.ctx),
    );
    expect(report).toEqual({ changed: 1, finals: ['malicious'] });
    expect(t.store.final(t.scan.scanId, RECEIVED)).toEqual({
      outcome: 'malicious',
      engineVersion: 'sandbox-controller/0.1.0+static/sandbox-static/1',
      reasonCodes: ['sandbox.static_only', 'sandbox.static.eicar_test'],
      evidence: { submissions: 2, executed: 0, isolation: ['process'] },
      settingsVersion: 'sandbox-map/1;p=aaaaaaaaaaaa;t=1',
      completedAt: NOW,
    });
    const events = t.store.outboxOf(EventTypes.AttachmentSandboxCompleted);
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({
      organizationId: ORG,
      aggregateType: 'attachment',
      aggregateId: first.id.toString(),
    });
    expect((events[0]!.payload as { lifecycleRound: number }).lifecycleRound).toBe(2);
  });

  it('the final follows aggregateSubmissions: most severe wins, all skipped → skipped', async () => {
    const t = setup();
    const a = t.sub(1);
    const b = t.sub(2);
    await t.store.transaction((tx) =>
      finishSubmissions(
        tx,
        [
          { submission: a, outcome: expiredOutcome() },
          {
            submission: b,
            outcome: {
              status: 'completed',
              verdict: 'unknown',
              reasonCodes: ['sandbox.static_only', 'sandbox.no_findings'],
              executed: false,
              isolation: 'process',
              analysisPublicId: null,
            },
          },
        ],
        t.ctx,
      ),
    );
    expect(t.store.final(t.scan.scanId, RECEIVED)).toMatchObject({
      outcome: 'timeout',
      reasonCodes: ['sandbox.timeout', 'sandbox.no_findings', 'sandbox.static_only'],
      engineVersion: SANDBOX_ENGINE_VERSION,
    });
    const s = setup();
    const only = s.sub(1, 'pending');
    await s.store.transaction((tx) =>
      finishSubmissions(
        tx,
        [
          {
            submission: only,
            outcome: { status: 'skipped', skipReason: 'feature_disabled', settingsVersion: 'v' },
          },
        ],
        s.ctx,
      ),
    );
    expect(s.store.final(s.scan.scanId, RECEIVED)).toMatchObject({
      outcome: 'skipped',
      reasonCodes: ['sandbox.feature_disabled'],
    });
  });

  it('concurrent finishers of one round serialize: exactly one final, each submission once', async () => {
    const t = setup();
    const subs = [t.sub(1), t.sub(2), t.sub(3)];
    const analysis = malicious(t.store);
    const reports = await Promise.all(
      subs.map((submission) =>
        t.store.transaction((tx) =>
          finishSubmissions(tx, [{ submission, outcome: outcomeFromAnalysis(analysis) }], t.ctx),
        ),
      ),
    );
    expect(
      reports.flatMap((r) => (r === Symbol.for('x') ? [] : (r as { finals: string[] }).finals)),
    ).toEqual(['malicious']);
    expect(t.store.state.finals.size).toBe(1);
    // Repeating every completion changes nothing (state condition).
    const again = await t.store.transaction((tx) =>
      finishSubmissions(
        tx,
        subs.map((submission) => ({ submission, outcome: expiredOutcome() })),
        t.ctx,
      ),
    );
    expect(again).toEqual({ changed: 0, finals: [] });
    expect(t.store.outboxOf(EventTypes.AttachmentSandboxCompleted)).toHaveLength(3);
  });

  it('a final written earlier is kept; a round whose scan row is gone gets no event and no final', async () => {
    const t = setup();
    const sub = t.sub(1);
    t.store.state.finals.set(`${t.scan.scanId.toString()}@${RECEIVED.getTime()}`, {
      outcome: 'unknown',
      engineVersion: 'x',
      reasonCodes: [],
      evidence: {},
      settingsVersion: null,
      completedAt: NOW,
    });
    const report = await t.store.transaction((tx) =>
      finishSubmissions(tx, [{ submission: sub, outcome: expiredOutcome() }], t.ctx),
    );
    expect(report).toEqual({ changed: 1, finals: [] });
    expect(t.store.final(t.scan.scanId, RECEIVED)!.outcome).toBe('unknown');

    const gone = setup();
    const orphan = gone.sub(1);
    gone.store.state.scans.clear();
    await gone.store.transaction((tx) =>
      finishSubmissions(tx, [{ submission: orphan, outcome: expiredOutcome() }], gone.ctx),
    );
    expect(gone.store.submission(orphan.id).status).toBe('expired');
    expect(gone.store.state.outbox).toHaveLength(0);
    expect(gone.store.state.finals.size).toBe(0);
  });

  it('maps terminal analyses to submission outcomes; never clean without vm isolation', () => {
    const t = setup();
    const base = { sha256: 'e'.repeat(64), organizationId: ORG };
    expect(
      outcomeFromAnalysis(
        t.store.addAnalysis({
          ...base,
          status: 'not_executed',
          verdict: 'unknown',
          isolation: 'none',
          executed: false,
        }),
      ),
    ).toMatchObject({
      status: 'completed',
      verdict: 'unknown',
      isolation: 'none',
      executed: false,
    });
    expect(
      outcomeFromAnalysis(t.store.addAnalysis({ ...base, status: 'failed', verdict: 'error' })),
    ).toMatchObject({ status: 'failed', verdict: 'error', isolation: null });
    expect(
      outcomeFromAnalysis(t.store.addAnalysis({ ...base, status: 'expired', verdict: null })),
    ).toMatchObject({ status: 'expired', verdict: 'timeout', reasonCodes: ['sandbox.timeout'] });
    expect(() =>
      outcomeFromAnalysis(t.store.addAnalysis({ ...base, status: 'dispatched' })),
    ).toThrow();
  });
});

describe('risk revision 1 from the sandbox final (step 5.1 R13 (a), ADR-0042)', () => {
  const key = (t: ReturnType<typeof setup>) => scanKey(t.scan.scanId, RECEIVED);

  it('a round still running gets no revision 1 here (its completion writes it)', async () => {
    const t = setup();
    const sub = t.sub(1);
    const analysis = malicious(t.store);
    await t.store.transaction((tx) =>
      finishSubmissions(tx, [{ submission: sub, outcome: outcomeFromAnalysis(analysis) }], t.ctx),
    );
    expect(t.store.final(t.scan.scanId, RECEIVED)?.outcome).toBe('malicious');
    expect(t.store.state.riskRevisions.size).toBe(0);
  });

  it('a round that completed first gets revision 1 from the final, exactly once', async () => {
    const t = setup();
    t.store.setScanStatus(t.scan.scanId, RECEIVED, 'completed');
    const sub = t.sub(1);
    const analysis = malicious(t.store);
    await t.store.transaction((tx) =>
      finishSubmissions(tx, [{ submission: sub, outcome: outcomeFromAnalysis(analysis) }], t.ctx),
    );
    expect(t.store.state.riskRevisions.get(key(t))).toBe(1);
    // Re-checks (sweeper, redelivery): the final exists, nothing is scored again.
    const again = await t.store.transaction(async (tx) => {
      const scans = await tx.lockScans([{ scanId: t.scan.scanId, receivedAt: RECEIVED }]);
      return writeRoundFinal(tx, scans.get(key(t))!, t.ctx);
    });
    expect(again).toBeNull();
    expect(t.store.state.riskRevisions.size).toBe(1);
    expect(t.store.state.riskDuplicates).toBe(0);
  });

  it('failed and timed-out rounds are scored too; a skipped final never is', async () => {
    for (const status of ['failed', 'timed_out']) {
      const t = setup();
      t.store.setScanStatus(t.scan.scanId, RECEIVED, status);
      const sub = t.sub(1);
      await t.store.transaction((tx) =>
        finishSubmissions(tx, [{ submission: sub, outcome: expiredOutcome() }], t.ctx),
      );
      expect(t.store.final(t.scan.scanId, RECEIVED)?.outcome).toBe('timeout');
      expect(t.store.state.riskRevisions.size).toBe(1);
    }
    const s = setup();
    s.store.setScanStatus(s.scan.scanId, RECEIVED, 'completed');
    const only = s.sub(1, 'pending');
    await s.store.transaction((tx) =>
      finishSubmissions(
        tx,
        [
          {
            submission: only,
            outcome: { status: 'skipped', skipReason: 'feature_disabled', settingsVersion: 'v' },
          },
        ],
        s.ctx,
      ),
    );
    expect(s.store.final(s.scan.scanId, RECEIVED)?.outcome).toBe('skipped');
    expect(s.store.state.riskRevisions.size).toBe(0);
  });

  it('a scoring failure rolls the final back with it (one transaction)', async () => {
    const t = setup();
    t.store.setScanStatus(t.scan.scanId, RECEIVED, 'completed');
    const sub = t.sub(1);
    const failing = (tx: Parameters<typeof finishSubmissions>[0]) => {
      tx.scoreRiskRevision = () => Promise.reject(new Error('lock wait timeout'));
      return finishSubmissions(tx, [{ submission: sub, outcome: expiredOutcome() }], t.ctx);
    };
    await expect(t.store.transaction(failing)).rejects.toThrow('lock wait timeout');
    expect(t.store.final(t.scan.scanId, RECEIVED)).toBeUndefined();
    expect(t.store.submission(sub.id).status).toBe('submitted');
  });
});
