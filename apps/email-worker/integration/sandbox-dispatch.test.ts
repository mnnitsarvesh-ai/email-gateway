import {
  attachmentSandboxCompletedV1,
  EventTypes,
  sandboxTaskRequestedV1,
} from '@email-gateway/event-contracts';
import { openResultToken, openSample } from '@email-gateway/sandbox';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { classifyScanFailure } from '../src/scanning/engine-consumer';
import { eventually } from './support/broker';
import {
  benignScript,
  composeMinio,
  deliver,
  SandboxBroker,
  SandboxFixtures,
} from './support/sandbox';
import { ScanFixtures } from './support/scan';

/**
 * Package integration of the sandbox dispatcher (step 4.6 §9.2, X13 steps 1–7) against the real
 * MySQL writer, MinIO (mail and sandbox buckets) and, for the consumer wiring, a throwaway
 * RabbitMQ vhost with topology v8. Samples are synthetic benign scripts; nothing is executed.
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

describe('sandbox dispatcher (X13)', () => {
  it('an opted-in tenant: analysis, sealed sample in the sandbox bucket, task outbox row', async () => {
    const org = await sfx.tenant('dispatch');
    const bytes = benignScript('dispatch');
    const round = await sfx.round(org, bytes);
    const { jobs } = sfx.jobs();
    expect(await deliver((e) => jobs.dispatcher.handle(e), round.event)).toBe('handled');

    const [analysis] = await sfx.analyses(round.sha256);
    expect(analysis).toMatchObject({
      status: 'dispatched',
      profile: 'execute',
      organizationId: org,
      requestedEventId: round.event.eventId,
      sizeBytes: bytes.length,
      detectedType: 'script_shell',
    });
    expect(analysis!.dedupeKey).toBe(`${round.sha256}:${analysis!.analysisKey}`);
    expect(analysis!.sampleObjectKey).toMatch(
      new RegExp(`^samples/\\d{4}/\\d{2}/${analysis!.publicId}\\.bin$`),
    );
    const submission = await sfx.submission(round);
    expect(submission).toMatchObject({ status: 'submitted', analysisId: analysis!.id });
    expect(submission.settingsVersion).toMatch(/^sandbox-map\/1;p=[0-9a-f]{12};t=1$/);

    // The object is sealed (sandbox-sample/1): no plaintext, opens only with the sample key.
    const object = await sfx.getObject(analysis!.sampleObjectKey!);
    expect(object).not.toBeNull();
    expect(object!.subarray(0, 7).toString('ascii')).toBe('EGSBXS1');
    expect(object!.includes(bytes)).toBe(false);
    expect(
      openSample({ current: sfx.config.SANDBOX_SAMPLE_KEY }, object!, {
        taskId: analysis!.publicId,
        sha256: round.sha256,
      }).plaintext,
    ).toEqual(bytes);

    const tasks = await sfx.outbox(EventTypes.SandboxTaskRequested, {
      aggregateId: analysis!.id.toString(),
    });
    expect(tasks).toHaveLength(1);
    expect(tasks[0]).toMatchObject({
      aggregateType: 'sandbox_analysis',
      organizationId: org,
      publishedAt: null,
    });
    const task = sandboxTaskRequestedV1.parse(tasks[0]!.payload);
    expect(task).toMatchObject({
      taskId: analysis!.publicId,
      analysisId: analysis!.id.toString(),
      sample: { key: analysis!.sampleObjectKey, sha256: round.sha256, sizeBytes: bytes.length },
      profile: 'execute',
    });
    expect(JSON.stringify(tasks[0]!.payload)).not.toContain('run.sh');
    // The one-time result token (X11): sealed in the task, only its SHA-256 in MySQL.
    expect(analysis!.resultTokenSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(openResultToken(sfx.config.SANDBOX_RESULT_KEY, task.taskId, task.resultToken)).toBe(
      analysis!.resultTokenSha256,
    );
    expect(JSON.stringify(tasks[0]!.payload)).not.toContain(analysis!.resultTokenSha256!);
    // Redelivery: a ledger duplicate.
    expect(await jobs.dispatcher.handle(round.event)).toBe('duplicate');
    expect(
      await sfx.outbox(EventTypes.SandboxTaskRequested, { aggregateId: analysis!.id.toString() }),
    ).toHaveLength(1);
  });

  it('the same event three times and two tenants with the same SHA-256 → one analysis, one task, both linked', async () => {
    const first = await sfx.tenant('dedup-a');
    const second = await sfx.tenant('dedup-b');
    const bytes = benignScript('dedup');
    const a = await sfx.round(first, bytes);
    const b = await sfx.round(second, bytes);
    const { jobs } = sfx.jobs();
    const handle = (e: typeof a.event) => jobs.dispatcher.handle(e);
    const outcomes = await Promise.all([
      deliver(handle, a.event),
      deliver(handle, a.event),
      deliver(handle, a.event),
    ]);
    expect(outcomes.filter((o) => o === 'handled').length).toBeGreaterThanOrEqual(1);
    expect(await deliver(handle, b.event)).toBe('handled');

    const analyses = await sfx.analyses(a.sha256);
    expect(analyses).toHaveLength(1);
    expect(analyses[0]).toMatchObject({ status: 'dispatched', organizationId: first });
    for (const round of [a, b]) {
      expect(await sfx.submission(round)).toMatchObject({
        status: 'submitted',
        analysisId: analyses[0]!.id,
      });
    }
    expect(
      await sfx.outbox(EventTypes.SandboxTaskRequested, {
        aggregateId: analyses[0]!.id.toString(),
      }),
    ).toHaveLength(1);
  });

  it('a tenant that did not opt in: skipped/tenant_disabled, completion event and skipped final', async () => {
    const org = await sfx.tenant('not-opted', { settings: null });
    const round = await sfx.round(org, benignScript('skip'));
    const { jobs } = sfx.jobs();
    await deliver((e) => jobs.dispatcher.handle(e), round.event);
    expect(await sfx.submission(round)).toMatchObject({
      status: 'skipped',
      skipReason: 'tenant_disabled',
      sandboxVerdict: null,
    });
    expect(await sfx.analyses(round.sha256)).toHaveLength(0);
    const [completed] = await sfx.outbox(EventTypes.AttachmentSandboxCompleted, {
      organizationId: org,
    });
    expect(attachmentSandboxCompletedV1.parse(completed!.payload)).toMatchObject({
      status: 'skipped',
      reasonCodes: ['sandbox.tenant_disabled'],
    });
    expect(await sfx.finalOf(round)).toMatchObject({
      outcome: 'skipped',
      engineVersion: 'sandbox-engine/1',
    });
    // The round itself is unaffected (attachment alone decided it).
    expect(await sfx.scanRow(round)).toMatchObject({
      status: 'completed',
      scanVerdict: 'suspicious',
    });
    const plan = await sfx.tenant('no-feature', { feature: false });
    const gated = await sfx.round(plan, benignScript('feature'));
    await deliver((e) => jobs.dispatcher.handle(e), gated.event);
    expect(await sfx.submission(gated)).toMatchObject({
      status: 'skipped',
      skipReason: 'feature_disabled',
    });
  });

  it('MinIO paused during staging → transient retry, then success after unpause', async () => {
    const org = await sfx.tenant('minio-pause');
    const round = await sfx.round(org, benignScript('pause'));
    const { jobs, registry } = sfx.jobs();
    let error: unknown;
    composeMinio('pause');
    try {
      error = await jobs.dispatcher.handle(round.event).catch((e: unknown) => e);
    } finally {
      composeMinio('unpause');
    }
    expect(error).toBeInstanceOf(Error);
    expect(classifyScanFailure(error)).toBe('transient');
    const [pending] = await sfx.analyses(round.sha256);
    expect(pending).toMatchObject({ status: 'pending' });
    expect(await sfx.submission(round)).toMatchObject({
      status: 'submitted',
      analysisId: pending!.id,
    });
    expect(await registry.metrics()).toMatch(
      /scan_sandbox_staging_failures_total\{[^}]*reason="storage_unavailable"[^}]*\} 1/,
    );
    // The hold retry (redelivery of the same event) resumes at staging.
    await eventually(
      async () => {
        try {
          await jobs.objects.check();
          return true;
        } catch {
          return false;
        }
      },
      30_000,
      'MinIO answering again',
    );
    expect(await deliver((e) => jobs.dispatcher.handle(e), round.event, 30)).toBe('handled');
    const [dispatched] = await sfx.analyses(round.sha256);
    expect(dispatched).toMatchObject({ id: pending!.id, status: 'dispatched' });
    expect(await sfx.objectExists(dispatched!.sampleObjectKey!)).toBe(true);
    expect(
      await sfx.outbox(EventTypes.SandboxTaskRequested, { aggregateId: dispatched!.id.toString() }),
    ).toHaveLength(1);
  });

  it('wires the dispatch consumer on scan.sandbox.submissions (topology v8 vhost)', async () => {
    const org = await sfx.tenant('consumer');
    const round = await sfx.round(org, benignScript('consumer'));
    const broker = await SandboxBroker.start();
    const { jobs } = sfx.jobs({ connection: broker.connection, publisher: broker.publisher });
    try {
      jobs.dispatchConsumer.start((e) => jobs.dispatcher.handle(e));
      await broker.publish(round.event);
      await eventually(
        async () => (await sfx.analyses(round.sha256))[0]?.status === 'dispatched',
        30_000,
        'the analysis dispatched by the consumer',
      );
      const [analysis] = await sfx.analyses(round.sha256);
      expect(
        await sfx.outbox(EventTypes.SandboxTaskRequested, { aggregateId: analysis!.id.toString() }),
      ).toHaveLength(1);
    } finally {
      await jobs.dispatchConsumer.stop();
      await broker.close();
    }
  });
});
