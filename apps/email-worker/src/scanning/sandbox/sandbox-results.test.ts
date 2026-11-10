import {
  attachmentSandboxCompletedV1,
  type EventEnvelope,
  EventTypes,
  type SandboxTaskCompletedV1,
} from '@email-gateway/event-contracts';
import type { SandboxFindingCode } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import {
  counter,
  FAKE_RESULT_TOKEN_SHA256,
  type FakeAnalysis,
  FakeSandboxObjects,
  FakeSandboxStore,
  newSandboxMetrics,
  silent,
} from './fakes.test-support';
import { buildResult, type ResultSpec } from './result-builder.test-support';
import { artifactKeysValid, reuseUntilFor, SandboxResultsService } from './sandbox-results';

const RESULT_KEY = '2'.repeat(64);
const NOW = new Date('2026-11-08T10:00:00.000Z');
const RECEIVED = new Date('2026-11-08T09:00:00.000Z');
const SHA = 'c'.repeat(64);
const ORG = 7n;
const RUN = '0123456789abcdef';
const WINDOWS = { definiteSeconds: 86_400, unknownSeconds: 21_600, notExecutedSeconds: 3_600 };

function setup(options: { publishHashes?: boolean } = {}) {
  const store = new FakeSandboxStore();
  const objects = new FakeSandboxObjects();
  const { metrics, registry } = newSandboxMetrics();
  const service = new SandboxResultsService({
    store,
    objects,
    metrics,
    logger: silent,
    resultKey: RESULT_KEY,
    reuse: WINDOWS,
    artifactRetentionDays: 30,
    publishHashes: options.publishHashes ?? false,
    now: () => NOW,
  });
  const analysis = store.addAnalysis({
    sha256: SHA,
    organizationId: ORG,
    status: 'dispatched',
    dedupeKey: `${SHA}:0123456789abcdef`,
    dispatchedAt: new Date(NOW.getTime() - 60_000),
  });
  objects.objects.set(analysis.sampleObjectKey!, Buffer.from('sealed'));
  let seq = 0;
  const link = (count = 1, organizationId = ORG) => {
    const rows = [];
    for (let i = 0; i < count; i += 1) {
      seq += 1;
      const scanId = 900n + BigInt(seq);
      const messageId = 3000n + BigInt(seq);
      store.addScan({ scanId, receivedAt: RECEIVED, organizationId, messageId, lifecycleRound: 0 });
      rows.push(
        store.addSubmission({
          scanId,
          receivedAt: RECEIVED,
          organizationId,
          messageId,
          sha256: SHA,
          status: 'submitted',
          analysisId: analysis.id,
          settingsVersion: 'sandbox-map/1;p=000000000000;t=1',
        }),
      );
    }
    return rows;
  };
  let events = 0;
  const event = (
    spec: Partial<ResultSpec> = {},
    organizationId = ORG.toString(),
    target: FakeAnalysis = analysis,
  ): EventEnvelope<SandboxTaskCompletedV1> => {
    events += 1;
    const built = buildResult({
      taskId: target.publicId,
      analysisId: target.id.toString(),
      sampleSha256: target.sha256,
      resultKey: RESULT_KEY,
      organizationId,
      tokenSha256: target.resultTokenSha256 ?? FAKE_RESULT_TOKEN_SHA256,
      at: NOW,
      ...spec,
    });
    return {
      eventId: `0190f3a0-0000-7000-8000-${String(events).padStart(12, '0')}`,
      eventType: EventTypes.SandboxTaskCompleted,
      occurredAt: NOW.toISOString(),
      correlationId: 'corr-result',
      organizationId,
      payload: built.payload,
    };
  };
  return { store, objects, metrics, registry, service, analysis, link, event };
}

const nothingWritten = (t: ReturnType<typeof setup>) => {
  expect(t.store.analysis(t.analysis.id)).toMatchObject({ status: 'dispatched', verdict: null });
  expect(t.store.state.artifacts.size).toBe(0);
  expect(t.store.state.outbox).toHaveLength(0);
  expect(t.store.state.finals.size).toBe(0);
  expect([...t.store.state.submissions.values()].every((s) => s.status === 'submitted')).toBe(true);
};

describe('reuse windows and artifact keys (X13 results steps 2–3)', () => {
  it('reuse_until by verdict: definite, unknown, not executed; error never; 0 disables', () => {
    expect(reuseUntilFor('completed', 'malicious', WINDOWS, NOW)).toEqual(
      new Date(NOW.getTime() + 86_400_000),
    );
    expect(reuseUntilFor('completed', 'suspicious', WINDOWS, NOW)).toEqual(
      new Date(NOW.getTime() + 86_400_000),
    );
    expect(reuseUntilFor('completed', 'unknown', WINDOWS, NOW)).toEqual(
      new Date(NOW.getTime() + 21_600_000),
    );
    expect(reuseUntilFor('not_executed', 'unknown', WINDOWS, NOW, 'type_not_supported')).toEqual(
      new Date(NOW.getTime() + 3_600_000),
    );
    expect(reuseUntilFor('failed', 'error', WINDOWS, NOW)).toBeNull();
    expect(
      reuseUntilFor('completed', 'malicious', { ...WINDOWS, definiteSeconds: 0 }, NOW),
    ).toBeNull();
  });

  it.each([
    ['type_not_supported', 3_600_000],
    ['profile_not_supported', 3_600_000],
    ['size_exceeded', 3_600_000],
    ['deadline_passed', null],
    ['backend_disabled', null],
  ] as const)(
    'not_executed/%s: reuse window %s (operational reasons are never reused)',
    (reason, ms) => {
      expect(reuseUntilFor('not_executed', 'unknown', WINDOWS, NOW, reason)).toEqual(
        ms === null ? null : new Date(NOW.getTime() + ms),
      );
    },
  );

  it('not_executed without a reason, or with the window 0, is never reused', () => {
    expect(reuseUntilFor('not_executed', 'unknown', WINDOWS, NOW)).toBeNull();
    expect(
      reuseUntilFor(
        'not_executed',
        'unknown',
        { ...WINDOWS, notExecutedSeconds: 0 },
        NOW,
        'size_exceeded',
      ),
    ).toBeNull();
  });

  it('artifact keys must embed the task, seq and kind, in the dispatch..now months, seqs unique', () => {
    const taskId = '0190f3a0-0000-7000-8000-000000000001';
    const entry = (key: string, seq = 0) =>
      ({ key, seq, kind: 'static_report' }) as SandboxTaskCompletedV1['artifacts'][number];
    const ok = `artifacts/2026/11/${taskId}/${RUN}/0-static_report.bin`;
    expect(artifactKeysValid([entry(ok)], taskId, NOW, NOW)).toBe(true);
    expect(artifactKeysValid([entry(ok)], taskId, new Date('2026-10-31T23:59:00Z'), NOW)).toBe(
      true,
    );
    expect(
      artifactKeysValid(
        [entry(`artifacts/2026/10/${taskId}/${RUN}/0-static_report.bin`)],
        taskId,
        NOW,
        NOW,
      ),
    ).toBe(false);
    expect(
      artifactKeysValid(
        [entry(`artifacts/2026/12/${taskId}/${RUN}/0-static_report.bin`)],
        taskId,
        NOW,
        NOW,
      ),
    ).toBe(false);
    expect(
      artifactKeysValid(
        [entry(ok.replace(taskId, '0190f3a0-0000-7000-8000-000000000002'))],
        taskId,
        NOW,
        NOW,
      ),
    ).toBe(false);
    expect(artifactKeysValid([entry(ok, 1)], taskId, NOW, NOW)).toBe(false);
    expect(artifactKeysValid([entry(`samples/2026/11/${taskId}.bin`)], taskId, NOW, NOW)).toBe(
      false,
    );
    // One run per result: two run ids → invalid; no run id → invalid.
    const second = `artifacts/2026/11/${taskId}/${RUN}/1-static_report.bin`;
    expect(artifactKeysValid([entry(ok), entry(second, 1)], taskId, NOW, NOW)).toBe(true);
    expect(
      artifactKeysValid(
        [entry(ok), entry(second.replace(RUN, 'ffffffffffffffff'), 1)],
        taskId,
        NOW,
        NOW,
      ),
    ).toBe(false);
    expect(
      artifactKeysValid(
        [entry(`artifacts/2026/11/${taskId}/0-static_report.bin`)],
        taskId,
        NOW,
        NOW,
      ),
    ).toBe(false);
  });
});

describe('sandbox results consumer: rejections (X13 results steps 1–2)', () => {
  it.each([
    ['invalid_result (schema)', 'invalid_result', { patch: { status: 'exploded' as never } }],
    [
      'invalid_result (unknown finding code)',
      'invalid_result',
      {
        patch: {
          observations: {
            ...buildResult({
              taskId: '0190f3a0-0000-7000-8000-000000000001',
              analysisId: '1',
              sampleSha256: SHA,
              resultKey: RESULT_KEY,
              organizationId: '7',
              tokenSha256: FAKE_RESULT_TOKEN_SHA256,
            }).payload.observations,
            findings: [{ code: 'static.unheard_of', severity: 'high', count: 1 }],
          },
        } as Partial<SandboxTaskCompletedV1>,
      },
    ],
    [
      'invalid_result (wrong severity)',
      'invalid_result',
      {
        patch: {
          observations: {
            ...buildResult({
              taskId: '0190f3a0-0000-7000-8000-000000000001',
              analysisId: '1',
              sampleSha256: SHA,
              resultKey: RESULT_KEY,
              organizationId: '7',
              tokenSha256: FAKE_RESULT_TOKEN_SHA256,
            }).payload.observations,
            findings: [{ code: 'static.eicar_test', severity: 'low', count: 1 }],
          },
        } as Partial<SandboxTaskCompletedV1>,
      },
    ],
    ['bad_mac (another key)', 'bad_mac', { resultKey: '3'.repeat(64) }],
    ['bad_mac (another task token)', 'bad_mac', { tokenSha256: 'ab'.repeat(32) }],
    [
      'bad_mac (genuine MAC, findings dropped from the body)',
      'bad_mac',
      {
        findings: ['static.eicar_test'] as SandboxFindingCode[],
        patch: {
          observations: {
            ...buildResult({
              taskId: '0190f3a0-0000-7000-8000-000000000001',
              analysisId: '1',
              sampleSha256: SHA,
              resultKey: RESULT_KEY,
              organizationId: '7',
              tokenSha256: FAKE_RESULT_TOKEN_SHA256,
            }).payload.observations,
          },
        } as Partial<SandboxTaskCompletedV1>,
      },
    ],
    [
      'bad_mac (genuine MAC, body rewritten to a vm run of 30 s)',
      'bad_mac',
      {
        patch: {
          backend: 'vm',
          isolation: 'vm',
          backendVersion: 'vm/1',
          durationMs: 30_000,
        } as Partial<SandboxTaskCompletedV1>,
      },
    ],

    [
      'bad_mac (status changed after signing)',
      'bad_mac',
      {
        status: 'completed' as const,
        patch: {
          status: 'not_executed',
          notExecutedReason: 'backend_disabled',
          backend: 'disabled',
          isolation: 'none',
          backendVersion: 'disabled/1',
        } as Partial<SandboxTaskCompletedV1>,
      },
    ],
  ] as const)('%s → rejected, nothing but the ledger row written', async (_label, reason, spec) => {
    const t = setup();
    t.link(2);
    const e = t.event(spec);
    expect(await t.service.handle(e)).toBe('handled');
    nothingWritten(t);
    expect(t.store.state.ledger.has(`${t.service.consumer}|${e.eventId}`)).toBe(true);
    expect(await counter(t.registry, 'scan_sandbox_results_rejected_total', { reason })).toBe(1);
    expect(await t.service.handle(e)).toBe('duplicate');
  });

  it('a genuine MAC copied onto a modified body ahead of the genuine result is rejected; the genuine result then applies', async () => {
    const t = setup();
    t.link(1);
    const genuine = t.event({
      findings: ['static.eicar_test'],
      artifacts: [{ kind: 'static_report', bytes: Buffer.from('{"v":1}') }],
    });
    const forgeries: EventEnvelope<SandboxTaskCompletedV1>[] = [];
    const copy = (edit: (p: SandboxTaskCompletedV1) => void) => {
      const forged = structuredClone(genuine);
      forged.eventId = `0190f3a0-0000-7000-8001-${String(forgeries.length).padStart(12, '0')}`;
      edit(forged.payload);
      forgeries.push(forged);
    };
    copy((p) => {
      p.observations.findings = [];
    });
    copy((p) => {
      p.artifacts[0]!.wrappedKey = p.artifacts[0]!.wrappedKey.replace(/.$/, (c) =>
        c === 'A' ? 'B' : 'A',
      );
    });
    copy((p) => {
      p.artifacts[0]!.objectSha256 = 'f'.repeat(64);
    });
    copy((p) => {
      p.durationMs += 1;
    });
    for (const forged of forgeries) expect(await t.service.handle(forged)).toBe('handled');
    nothingWritten(t);
    expect(
      await counter(t.registry, 'scan_sandbox_results_rejected_total', { reason: 'bad_mac' }),
    ).toBe(forgeries.length);
    expect(await t.service.handle(genuine)).toBe('handled');
    expect(t.store.analysis(t.analysis.id)).toMatchObject({
      status: 'completed',
      verdict: 'malicious',
    });
    expect([...t.store.state.artifacts.values()][0]!.wrappedKey).toBe(
      genuine.payload.artifacts[0]!.wrappedKey,
    );
  });

  it('an analysis without a result token hash accepts no result (bad_mac)', async () => {
    const t = setup();
    t.link(1);
    t.store.analysis(t.analysis.id).resultTokenSha256 = null;
    expect(await t.service.handle(t.event())).toBe('handled');
    nothingWritten(t);
    expect(
      await counter(t.registry, 'scan_sandbox_results_rejected_total', { reason: 'bad_mac' }),
    ).toBe(1);
  });

  it('unknown analysis, another organization, another hash or task id → rejected', async () => {
    const t = setup();
    t.link(1);
    const unknown = t.event({ analysisId: '999999' });
    await t.service.handle(unknown);
    const otherOrg = t.event({}, '8');
    await t.service.handle(otherOrg);
    const otherHash = t.event({ sampleSha256: 'd'.repeat(64) });
    await t.service.handle(otherHash);
    const otherTask = t.event({ taskId: '0190f3a0-0000-7000-8000-0000000000ff' });
    await t.service.handle(otherTask);
    nothingWritten(t);
    expect(
      await counter(t.registry, 'scan_sandbox_results_rejected_total', {
        reason: 'unknown_analysis',
      }),
    ).toBe(1);
    expect(
      await counter(t.registry, 'scan_sandbox_results_rejected_total', {
        reason: 'analysis_mismatch',
      }),
    ).toBe(3);
  });

  it('a result for a pending analysis → not_dispatched; a bad artifact key → artifact_key_invalid', async () => {
    const t = setup();
    t.link(1);
    t.store.analysis(t.analysis.id).status = 'pending';
    await t.service.handle(t.event());
    t.store.analysis(t.analysis.id).status = 'dispatched';
    // Signed by the controller (valid MAC), but the key is outside the dispatch..now months.
    const forged = t.event({
      artifacts: [{ kind: 'static_report', bytes: Buffer.from('{}') }],
      beforeSign: (p) => {
        p.artifacts[0]!.key = p.artifacts[0]!.key.replace('/2026/11/', '/2026/09/');
      },
    });
    await t.service.handle(forged);
    nothingWritten(t);
    expect(
      await counter(t.registry, 'scan_sandbox_results_rejected_total', {
        reason: 'not_dispatched',
      }),
    ).toBe(1);
    expect(
      await counter(t.registry, 'scan_sandbox_results_rejected_total', {
        reason: 'artifact_key_invalid',
      }),
    ).toBe(1);
  });

  it('a terminal analysis → duplicate no-op; an expired one → late no-op (no metric of rejection)', async () => {
    const t = setup();
    t.link(1);
    await t.service.handle(t.event({ findings: ['static.eicar_test'] }));
    const verdict = t.store.analysis(t.analysis.id).verdict;
    expect(await t.service.handle(t.event({ status: 'not_executed' }))).toBe('handled');
    expect(t.store.analysis(t.analysis.id).verdict).toBe(verdict);
    const late = setup();
    late.store.analysis(late.analysis.id).status = 'expired';
    expect(await late.service.handle(late.event())).toBe('handled');
    expect(late.store.analysis(late.analysis.id).status).toBe('expired');
    for (const reason of ['not_dispatched', 'analysis_mismatch']) {
      expect(await counter(late.registry, 'scan_sandbox_results_rejected_total', { reason })).toBe(
        0,
      );
    }
  });
});

describe('sandbox results consumer: applying a result (X13 results steps 3–5)', () => {
  it('maps the result, stores the bounded report and artifacts, completes submissions and writes finals', async () => {
    const t = setup();
    const [a, b] = t.link(2);
    const e = t.event({
      findings: ['static.eicar_test', 'static.embedded_urls'],
      artifacts: [{ kind: 'static_report', bytes: Buffer.from('{"v":1}') }],
    });
    expect(await t.service.handle(e)).toBe('handled');
    const analysis = t.store.analysis(t.analysis.id);
    expect(analysis).toMatchObject({
      status: 'completed',
      verdict: 'malicious',
      backend: 'static',
      backendVersion: 'sandbox-static/1',
      isolation: 'process',
      executed: false,
      controllerVersion: 'sandbox-controller/0.1.0',
      analyzerVersion: 'sandbox-static/1',
      mapVersion: 'sandbox-map/1',
      resultEventId: e.eventId,
      completedAt: NOW,
      reuseUntil: new Date(NOW.getTime() + 86_400_000),
      dedupeKey: `${SHA}:0123456789abcdef`,
    });
    expect(analysis.reasonCodes).toEqual(
      expect.arrayContaining(['sandbox.static.eicar_test', 'sandbox.static_only']),
    );
    expect(analysis.report).toMatchObject({
      v: 1,
      findings: [{ code: 'static.eicar_test' }, { code: 'static.embedded_urls' }],
    });
    const [artifact] = [...t.store.state.artifacts.values()];
    expect(artifact).toMatchObject({
      analysisId: t.analysis.id,
      seq: 0,
      kind: 'static_report',
      contentType: 'application/json',
      algorithm: 'sandbox-artifact/1',
      expiresAt: new Date(NOW.getTime() + 30 * 86_400_000),
    });
    expect(artifact!.wrappedKey).toMatch(/^x1\./);
    for (const submission of [a!, b!]) {
      expect(t.store.submission(submission.id)).toMatchObject({
        status: 'completed',
        sandboxVerdict: 'malicious',
        externalRef: t.analysis.publicId,
      });
      expect(t.store.final(submission.scanId, RECEIVED)).toMatchObject({
        outcome: 'malicious',
        engineVersion: 'sandbox-controller/0.1.0+static/sandbox-static/1',
        evidence: { submissions: 1, executed: 0, isolation: ['process'] },
        settingsVersion: 'sandbox-map/1;p=000000000000;t=1',
      });
    }
    const events = t.store.outboxOf(EventTypes.AttachmentSandboxCompleted);
    expect(events).toHaveLength(2);
    expect(events.map((o) => o.organizationId)).toEqual([ORG, ORG]);
    expect(attachmentSandboxCompletedV1.parse(events[0]!.payload)).toMatchObject({
      status: 'completed',
      verdict: 'malicious',
      executed: false,
      isolation: 'process',
    });
    // After commit: the sample is deleted and sample_deleted_at set.
    expect(t.objects.objects.has(t.analysis.sampleObjectKey!)).toBe(false);
    expect(analysis.sampleDeletedAt).toEqual(NOW);
    expect(await counter(t.registry, 'scan_sandbox_verdicts_total', { verdict: 'malicious' })).toBe(
      1,
    );
    expect(await counter(t.registry, 'scan_sandbox_finals_total', { outcome: 'malicious' })).toBe(
      2,
    );
    expect(await counter(t.registry, 'scan_sandbox_purged_total', { kind: 'sample' })).toBe(1);
    // Duplicate delivery: a ledger duplicate, nothing changes.
    expect(await t.service.handle(e)).toBe('duplicate');
    expect(t.store.outboxOf(EventTypes.AttachmentSandboxCompleted)).toHaveLength(2);
  });

  it('not_executed → unknown with its reason, never clean; failed → error, no reuse, dedupe key cleared', async () => {
    const t = setup();
    t.link(1);
    await t.service.handle(t.event({ status: 'not_executed' }));
    expect(t.store.analysis(t.analysis.id)).toMatchObject({
      status: 'not_executed',
      verdict: 'unknown',
      reasonCodes: ['sandbox.not_executed', 'sandbox.not_executed.backend_disabled'],
      notExecutedReason: 'backend_disabled',
      // backend_disabled is operational: no reuse window, the dedupe key is released.
      reuseUntil: null,
      dedupeKey: null,
    });
    const typeNs = setup();
    typeNs.link(1);
    await typeNs.service.handle(
      typeNs.event({ status: 'not_executed', notExecutedReason: 'type_not_supported' }),
    );
    expect(typeNs.store.analysis(typeNs.analysis.id)).toMatchObject({
      status: 'not_executed',
      reuseUntil: new Date(NOW.getTime() + 3_600_000),
      dedupeKey: `${SHA}:0123456789abcdef`,
    });
    const late = setup();
    late.link(1);
    await late.service.handle(
      late.event({ status: 'not_executed', notExecutedReason: 'deadline_passed' }),
    );
    expect(late.store.analysis(late.analysis.id)).toMatchObject({
      status: 'not_executed',
      reasonCodes: ['sandbox.not_executed', 'sandbox.not_executed.deadline_passed'],
      reuseUntil: null,
      dedupeKey: null,
    });
    const f = setup();
    f.link(1);
    await f.service.handle(f.event({ status: 'failed' }));
    expect(f.store.analysis(f.analysis.id)).toMatchObject({
      status: 'failed',
      verdict: 'error',
      errorCode: 'analyzer_crashed',
      reuseUntil: null,
      dedupeKey: null,
    });
    expect(await counter(f.registry, 'scan_sandbox_submissions_total', { result: 'failed' })).toBe(
      1,
    );
  });

  it('a static run without findings is unknown (static_only, no_findings)', async () => {
    const t = setup();
    t.link(1);
    await t.service.handle(t.event());
    expect(t.store.analysis(t.analysis.id)).toMatchObject({
      verdict: 'unknown',
      reasonCodes: ['sandbox.no_findings', 'sandbox.static_only'],
    });
  });

  it('completes at most 200 linked submissions per result; the rest wait for the sweeper', async () => {
    const t = setup();
    const rows = t.link(205);
    await t.service.handle(t.event());
    const statuses = rows.map((r) => t.store.submission(r.id).status);
    expect(statuses.filter((s) => s === 'completed')).toHaveLength(200);
    expect(statuses.filter((s) => s === 'submitted')).toHaveLength(5);
  });

  it('publishes a malicious hash only with SANDBOX_PUBLISH_HASHES', async () => {
    const off = setup();
    off.link(1);
    await off.service.handle(off.event({ findings: ['static.eicar_test'] }));
    expect(off.store.state.hashes.size).toBe(0);
    const on = setup({ publishHashes: true });
    on.link(1);
    await on.service.handle(on.event({ findings: ['static.eicar_test'] }));
    expect(on.store.state.hashes.get(SHA)).toEqual({
      publicId: on.analysis.publicId,
      expiresAt: new Date(NOW.getTime() + 90 * 86_400_000),
    });
    const unknown = setup({ publishHashes: true });
    unknown.link(1);
    await unknown.service.handle(unknown.event());
    expect(unknown.store.state.hashes.size).toBe(0);
  });

  it('a failed sample delete after commit is left to the sweeper (result still applied)', async () => {
    const t = setup();
    t.link(1);
    t.objects.failDeletes = 1;
    expect(await t.service.handle(t.event())).toBe('handled');
    expect(t.store.analysis(t.analysis.id)).toMatchObject({
      status: 'completed',
      sampleDeletedAt: null,
    });
  });
});
