import {
  attachmentSandboxCompletedV1,
  type EventEnvelope,
  EventTypes,
  type SandboxTaskCompletedV1,
} from '@email-gateway/event-contracts';
import { openArtifact, parseArtifactPrivateKey } from '@email-gateway/sandbox';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildResult, type ResultSpec } from '../src/scanning/sandbox/result-builder.test-support';
import { eventually } from './support/broker';
import {
  benignScript,
  deliver,
  SandboxBroker,
  SandboxFixtures,
  type SandboxRound,
} from './support/sandbox';
import { ScanFixtures } from './support/scan';

/**
 * Package integration of the sandbox results consumer and the round final (step 4.6 §9.2, X13
 * results, X14, X15) on the real writer and MinIO: forged results are rejected with nothing
 * written, a valid result (built here with the result MAC and artifacts sealed to a fresh X25519
 * key, as the controller does) completes the analysis, its artifacts, the submissions and the
 * round's `sandbox` final — before and after the round completes — and never changes
 * `email_scans.scan_verdict`. Samples are synthetic benign scripts.
 */
const fx = new ScanFixtures();
let sfx: SandboxFixtures;

beforeAll(() => {
  sfx = new SandboxFixtures(fx);
});

afterAll(async () => {
  await sfx?.cleanup();
  await fx.cleanup();
});

/** A dispatched analysis for `round` (the dispatcher ran). */
async function dispatched(round: SandboxRound) {
  const { jobs } = sfx.jobs();
  await deliver((e) => jobs.dispatcher.handle(e), round.event);
  const [analysis] = await sfx.analyses(round.sha256);
  expect(analysis!.status).toBe('dispatched');
  sfx.track(analysis!);
  return analysis!;
}

function result(
  analysis: {
    publicId: string;
    id: bigint;
    sha256: string;
    organizationId: bigint;
    resultTokenSha256: string | null;
  },
  spec: Partial<ResultSpec> = {},
) {
  return buildResult({
    taskId: analysis.publicId,
    analysisId: analysis.id.toString(),
    sampleSha256: analysis.sha256,
    resultKey: sfx.config.SANDBOX_RESULT_KEY,
    organizationId: analysis.organizationId.toString(),
    // The hash the dispatcher stored (X11): the controller derives it from the sealed token.
    tokenSha256: analysis.resultTokenSha256 ?? '0'.repeat(64),
    ...spec,
  });
}

async function snapshot(round: SandboxRound) {
  const [analysis] = await sfx.analyses(round.sha256);
  return {
    analysis,
    submission: await sfx.submission(round),
    final: await sfx.finalOf(round),
    artifacts: await sfx.prisma.sandboxArtifact.count({ where: { analysisId: analysis!.id } }),
    completions: (await sfx.outbox(EventTypes.AttachmentSandboxCompleted)).length,
  };
}

describe('sandbox results consumer (X13 results)', () => {
  it('forged results (bad MAC, unknown analysis, wrong organization, wrong hash, bad artifact key) write nothing', async () => {
    const org = await sfx.tenant('forged');
    const other = await sfx.tenant('forged-other');
    const round = await sfx.round(org, benignScript('forged'));
    const analysis = await dispatched(round);
    const before = await snapshot(round);
    const { jobs, registry } = sfx.jobs();
    const forged: EventEnvelope<SandboxTaskCompletedV1>[] = [
      sfx.resultEvent(org, result(analysis, { resultKey: 'ab'.repeat(32) }).payload),
      sfx.resultEvent(org, result({ ...analysis, id: 999_999_999_999n }).payload),
      sfx.resultEvent(other, result(analysis).payload),
      sfx.resultEvent(org, result({ ...analysis, sha256: 'd'.repeat(64) }).payload),
    ];
    // Signed (valid MAC) but its artifact key lies outside the dispatch..now months.
    const badKey = result(analysis, {
      artifacts: [{ kind: 'static_report', bytes: Buffer.from('{}') }],
      beforeSign: (p) => {
        p.artifacts[0]!.key = p.artifacts[0]!.key.replace(
          /^artifacts\/\d{4}\/\d{2}\//,
          'artifacts/2001/01/',
        );
      },
    });
    forged.push(sfx.resultEvent(org, badKey.payload));
    // A genuine MAC copied onto a modified body (a vm run, no findings, 30 s: rule C1 would
    // say clean) and a result signed with another task's token hash.
    const genuine = result(analysis, { findings: ['static.eicar_test'] }).payload;
    forged.push(
      sfx.resultEvent(org, {
        ...genuine,
        backend: 'vm',
        backendVersion: 'vm/1',
        isolation: 'vm',
        durationMs: 30_000,
        observations: { ...genuine.observations, findings: [] },
      }),
    );
    forged.push(sfx.resultEvent(org, result(analysis, { tokenSha256: 'ab'.repeat(32) }).payload));
    for (const event of forged) expect(await jobs.results.handle(event)).toBe('handled');
    expect(await snapshot(round)).toEqual(before);
    expect(before.analysis!.status).toBe('dispatched');
    const metrics = await registry.metrics();
    for (const [reason, n] of [
      ['bad_mac', 3],
      ['unknown_analysis', 1],
      ['analysis_mismatch', 2],
      ['artifact_key_invalid', 1],
    ] as const) {
      expect(metrics).toMatch(
        new RegExp(`scan_sandbox_results_rejected_total\\{[^}]*reason="${reason}"[^}]*\\} ${n}`),
      );
    }
    // Each rejection is a ledger no-op (a redelivery is a duplicate).
    expect(
      await fx.ledgerRows(
        jobs.results.consumer,
        forged.map((e) => e.eventId),
      ),
    ).toBe(forged.length);
  });

  it("a valid result before the round completes: analysis, artifacts, submission, event and final; the verdict stays the round's", async () => {
    const org = await sfx.tenant('before');
    const round = await sfx.round(org, benignScript('before'), { required: ['attachment', 'dlp'] });
    expect(await sfx.scanRow(round)).toMatchObject({ status: 'running', scanVerdict: null });
    const analysis = await dispatched(round);
    const built = result(analysis, {
      findings: ['static.eicar_test'],
      artifacts: [
        { kind: 'static_report', bytes: Buffer.from('{"v":1,"findings":["static.eicar_test"]}') },
        { kind: 'process_log', bytes: Buffer.from('synthetic log\n') },
      ],
    });
    for (const object of built.objects) await sfx.putObject(object.key, object.body);
    const { jobs } = sfx.jobs();
    const event = sfx.resultEvent(org, built.payload);
    expect(await jobs.results.handle(event)).toBe('handled');

    const done = await sfx.prisma.sandboxAnalysis.findUniqueOrThrow({ where: { id: analysis.id } });
    expect(done).toMatchObject({
      status: 'completed',
      verdict: 'malicious',
      backend: 'static',
      isolation: 'process',
      executed: false,
      controllerVersion: 'sandbox-controller/0.1.0',
      mapVersion: 'sandbox-map/1',
      resultEventId: event.eventId,
    });
    expect(done.reasonCodes as string[]).toEqual(
      expect.arrayContaining(['sandbox.static.eicar_test', 'sandbox.static_only']),
    );
    expect(done.reuseUntil).not.toBeNull();
    // After commit the sample is deleted.
    expect(done.sampleDeletedAt).not.toBeNull();
    expect(await sfx.objectExists(done.sampleObjectKey!)).toBe(false);

    const artifacts = await sfx.prisma.sandboxArtifact.findMany({
      where: { analysisId: analysis.id },
      orderBy: { seq: 'asc' },
    });
    expect(artifacts.map((a) => [a.seq, a.kind, a.contentType])).toEqual([
      [0, 'static_report', 'application/json'],
      [1, 'process_log', 'text/plain'],
    ]);
    // The wrapped key exists only in the row; the private key (tests/ops only) opens the object.
    const privateKey = parseArtifactPrivateKey(built.privateKey!);
    const object = await sfx.getObject(artifacts[0]!.objectKey);
    expect(
      openArtifact(privateKey, object!, artifacts[0]!.wrappedKey!, {
        taskId: analysis.publicId,
        seq: 0,
        kind: 'static_report',
      }).toString(),
    ).toContain('static.eicar_test');

    expect(await sfx.submission(round)).toMatchObject({
      status: 'completed',
      sandboxVerdict: 'malicious',
      externalRef: analysis.publicId,
    });
    const [completion] = await sfx.outbox(EventTypes.AttachmentSandboxCompleted, {
      organizationId: org,
    });
    expect(attachmentSandboxCompletedV1.parse(completion!.payload)).toMatchObject({
      status: 'completed',
      verdict: 'malicious',
      isolation: 'process',
      executed: false,
      scanId: round.scan.scanId.toString(),
    });
    const final = await sfx.finalOf(round);
    expect(final).toMatchObject({
      outcome: 'malicious',
      engineVersion: 'sandbox-controller/0.1.0+static/sandbox-static/1',
      attempt: 1,
      durationMs: 0,
      evidence: { submissions: 1, executed: 0, isolation: ['process'] },
    });
    // The round is still running (dlp missing): the sandbox final did not complete it.
    expect(await sfx.scanRow(round)).toMatchObject({ status: 'running', scanVerdict: null });
    await sfx.completeRound(round.scan);
    // Completion aggregates the synchronous engines only: suspicious (attachment), not malicious.
    const scan = await sfx.scanRow(round);
    expect(scan).toMatchObject({ status: 'completed', scanVerdict: 'suspicious' });
    expect(scan.reasonCodes as string[]).not.toContain('sandbox.static.eicar_test');

    // Duplicate result: a ledger duplicate; another delivery id of the same result: a no-op.
    expect(await jobs.results.handle(event)).toBe('duplicate');
    const again = sfx.resultEvent(org, built.payload);
    expect(await jobs.results.handle(again)).toBe('handled');
    expect(await sfx.prisma.sandboxArtifact.count({ where: { analysisId: analysis.id } })).toBe(2);
    expect(
      await sfx.outbox(EventTypes.AttachmentSandboxCompleted, { organizationId: org }),
    ).toHaveLength(1);
  });

  it('a valid result after the round completed writes the final and leaves email_scans untouched', async () => {
    const org = await sfx.tenant('after');
    const round = await sfx.round(org, benignScript('after'));
    const scanBefore = await sfx.scanRow(round);
    expect(scanBefore).toMatchObject({ status: 'completed', scanVerdict: 'suspicious' });
    const analysis = await dispatched(round);
    const { jobs } = sfx.jobs();
    await jobs.results.handle(
      sfx.resultEvent(org, result(analysis, { status: 'not_executed' }).payload),
    );
    expect(await sfx.finalOf(round)).toMatchObject({
      outcome: 'unknown',
      reasonCodes: ['sandbox.not_executed', 'sandbox.not_executed.backend_disabled'],
      engineVersion: 'sandbox-controller/0.1.0+disabled/disabled/1',
    });
    const scanAfter = await sfx.scanRow(round);
    expect(scanAfter).toEqual(scanBefore);
    const message = await sfx.prisma.emailMessage.findFirstOrThrow({
      where: { id: round.message.messageId, receivedAt: round.message.receivedAt },
      select: { status: true, version: true },
    });
    expect(message.status).toBe('scanned');
  });

  it('rescan: the new round reuses the analysis and gets its own final', async () => {
    const org = await sfx.tenant('rescan');
    const bytes = benignScript('rescan');
    const first = await sfx.round(org, bytes);
    const analysis = await dispatched(first);
    const { jobs } = sfx.jobs();
    // A sample-dependent not_executed reason has a reuse window (operational ones never do).
    await jobs.results.handle(
      sfx.resultEvent(
        org,
        result(analysis, { status: 'not_executed', notExecutedReason: 'type_not_supported' })
          .payload,
      ),
    );
    expect(await sfx.finalOf(first)).toMatchObject({ outcome: 'unknown' });
    // Administrative rescan (E19) → round 1 → the attachment engine submits again.
    const rescan = await fx.rescan(first.message);
    const second = await sfx.round(org, bytes, {
      message: first.message,
      lifecycleRound: (rescan.payload as { lifecycleRound: number }).lifecycleRound,
    });
    expect(second.scan.scanId).not.toBe(first.scan.scanId);
    await deliver((e) => jobs.dispatcher.handle(e), second.event);
    expect(await sfx.analyses(bytes.length ? first.sha256 : '')).toHaveLength(1);
    expect(await sfx.submission(second)).toMatchObject({
      status: 'completed',
      analysisId: analysis.id,
      sandboxVerdict: 'unknown',
    });
    const finals = await sfx.prisma.scanEngineResult.findMany({
      where: {
        messageId: first.message.messageId,
        receivedAt: first.message.receivedAt,
        engine: 'sandbox',
        isFinal: true,
      },
    });
    expect(finals.map((f) => f.scanId).sort()).toEqual(
      [first.scan.scanId, second.scan.scanId].sort(),
    );
    expect(
      await sfx.outbox(EventTypes.SandboxTaskRequested, { aggregateId: analysis.id.toString() }),
    ).toHaveLength(1);
  });

  it('wires the results consumer on scan.sandbox.results (topology v8 vhost)', async () => {
    const org = await sfx.tenant('results-consumer');
    const round = await sfx.round(org, benignScript('results-consumer'));
    const analysis = await dispatched(round);
    const broker = await SandboxBroker.start();
    const { jobs } = sfx.jobs({ connection: broker.connection, publisher: broker.publisher });
    try {
      jobs.resultsConsumer.start((e) => jobs.results.handle(e));
      await broker.publish(sfx.resultEvent(org, result(analysis).payload));
      await eventually(
        async () => (await sfx.submission(round)).status === 'completed',
        30_000,
        'the submission completed by the results consumer',
      );
      expect(await sfx.finalOf(round)).toMatchObject({ outcome: 'unknown' });
    } finally {
      await jobs.resultsConsumer.stop();
      await broker.close();
    }
  });
});
