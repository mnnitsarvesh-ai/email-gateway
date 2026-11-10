import { createHash } from 'node:crypto';
import { NonRetryableError } from '@email-gateway/common';
import {
  type AttachmentSandboxRequestedV1,
  type EventEnvelope,
  EventTypes,
  sandboxTaskRequestedV1,
  attachmentSandboxCompletedV1,
} from '@email-gateway/event-contracts';
import { openResultToken, openSample } from '@email-gateway/sandbox';
import {
  SANDBOX_PLATFORM_DEFAULTS,
  type SandboxPlatformSettings,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { classifyScanFailure } from '../engine-consumer';
import type { PartRead, PartSource } from '../parts/part-reader';
import {
  counter,
  FakeSandboxObjects,
  FakeSandboxStore,
  newSandboxMetrics,
  silent,
} from './fakes.test-support';
import { limitsFor, profileFor, SandboxDispatcher } from './sandbox-dispatcher';
import { InconsistentSandboxReadError } from './sandbox-store';
import { SampleStager } from './sample-stager';

const SAMPLE_KEY = '1'.repeat(64);
const RESULT_KEY = '2'.repeat(64);
const NOW = new Date('2026-11-08T10:00:00.000Z');
const RECEIVED = new Date('2026-11-08T09:59:00.000Z');
const ORG = 7n;
const BYTES = Buffer.from('#!/bin/sh\necho synthetic benign sample\n');
const SHA = createHash('sha256').update(BYTES).digest('hex');
const LIMITS = {
  wallTimeoutMs: 60_000,
  memoryMb: 512,
  cpuMillis: 1_000,
  pids: 128,
  scratchMb: 64,
  maxArtifacts: 16,
  maxArtifactBytes: 2_097_152,
  maxTotalArtifactBytes: 8_388_608,
};

class FakeParts implements PartSource {
  readonly parts = new Map<string, Buffer>();
  reads = 0;
  failNext: Error | null = null;

  read(key: string, sizeBytes: number, sha256: string): Promise<PartRead> {
    this.reads += 1;
    if (this.failNext) {
      const error = this.failNext;
      this.failNext = null;
      return Promise.reject(error);
    }
    const bytes = this.parts.get(key);
    if (!bytes) return Promise.resolve({ kind: 'missing' });
    if (bytes.length !== sizeBytes || createHash('sha256').update(bytes).digest('hex') !== sha256) {
      return Promise.resolve({ kind: 'integrity' });
    }
    return Promise.resolve({ kind: 'ok', bytes: Buffer.from(bytes) });
  }
}

const s3Outage = (): Error =>
  Object.assign(new Error('minio paused'), { $metadata: { httpStatusCode: 503 } });

function setup(options: { platform?: Partial<SandboxPlatformSettings>; now?: Date } = {}) {
  const store = new FakeSandboxStore();
  const objects = new FakeSandboxObjects();
  const parts = new FakeParts();
  const { metrics, registry } = newSandboxMetrics();
  const invalid: string[] = [];
  let now = options.now ?? NOW;
  const dispatcher = new SandboxDispatcher({
    store,
    stager: new SampleStager({ parts, objects, sampleKey: SAMPLE_KEY, timeoutMs: 5_000 }),
    metrics,
    settingsInvalid: (engine) => invalid.push(engine),
    logger: silent,
    platform: { ...SANDBOX_PLATFORM_DEFAULTS, ...options.platform },
    limits: LIMITS,
    epoch: 1,
    deadlineSeconds: 900,
    analysisRetentionDays: 180,
    resultKey: RESULT_KEY,
    now: () => now,
  });
  let seq = 0;
  let events = 0;
  const submit = (
    organizationId = ORG,
    spec: { bytes?: Buffer; detectedType?: string; sizeBytes?: number; scanId?: bigint } = {},
  ) => {
    seq += 1;
    const bytes = spec.bytes ?? BYTES;
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    const messageId = 1000n + BigInt(seq);
    const scanId = spec.scanId ?? 500n + BigInt(seq);
    store.addScan({ scanId, receivedAt: RECEIVED, organizationId, messageId, lifecycleRound: 0 });
    const submission = store.addSubmission({
      scanId,
      receivedAt: RECEIVED,
      organizationId,
      messageId,
      sha256,
      sizeBytes: spec.sizeBytes ?? bytes.length,
      detectedType: spec.detectedType ?? 'script_shell',
      createdAt: RECEIVED,
    });
    parts.parts.set(submission.objectKey, bytes);
    return submission;
  };
  const eventFor = (
    submission: ReturnType<typeof submit>,
    eventId = `0190f3a0-0000-7000-8000-${String(1000 + (events += 1)).padStart(12, '0')}`,
    organizationId = submission.organizationId.toString(),
  ): EventEnvelope<AttachmentSandboxRequestedV1> => ({
    eventId,
    eventType: EventTypes.AttachmentSandboxRequested,
    occurredAt: NOW.toISOString(),
    correlationId: 'corr-sandbox',
    organizationId,
    payload: {
      submissionId: submission.id.toString(),
      messageId: submission.messageId.toString(),
      receivedAt: submission.receivedAt.toISOString(),
      direction: 'inbound',
      scanId: submission.scanId.toString(),
      lifecycleRound: 0,
      attachment: {
        partIndex: submission.partIndex,
        sha256: submission.sha256,
        sizeBytes: submission.sizeBytes,
        detectedType:
          submission.detectedType as AttachmentSandboxRequestedV1['attachment']['detectedType'],
        objectKey: submission.objectKey,
      },
      attachmentVerdict: 'suspicious',
      reasonCodes: ['archive.encrypted'],
      requestedAt: NOW.toISOString(),
    },
  });
  const optIn = (organizationId = ORG, settings: unknown = { enabled: true }) => {
    store.state.features.set(organizationId, true);
    store.state.settings.set(organizationId, { settings, version: 3 });
  };
  return {
    store,
    objects,
    parts,
    metrics,
    registry,
    invalid,
    dispatcher,
    submit,
    eventFor,
    optIn,
    setNow: (value: Date) => {
      now = value;
    },
  };
}

const tasks = (store: FakeSandboxStore) => store.outboxOf(EventTypes.SandboxTaskRequested);
const completions = (store: FakeSandboxStore) =>
  store.outboxOf(EventTypes.AttachmentSandboxCompleted);

describe('profile and limits (X13 step 4)', () => {
  it('chooses browser for html/svg when allowed, execute for executable and script types, else static', () => {
    expect(profileFor('html', true)).toBe('browser');
    expect(profileFor('svg', true)).toBe('browser');
    expect(profileFor('html', false)).toBe('static');
    for (const type of [
      'script_shell',
      'script_js',
      'script_ps1',
      'hta',
      'pe_executable',
      'msi',
      'elf',
      'lnk',
    ]) {
      expect(profileFor(type, true)).toBe('execute');
    }
    for (const type of ['pdf', 'ooxml_word', 'ole_office', 'rtf', 'zip']) {
      expect(profileFor(type, true)).toBe('static');
    }
  });

  it('raises browser limits to 1024 MiB and 256 pids and keeps the others', () => {
    expect(limitsFor('browser', LIMITS)).toMatchObject({
      memoryMb: 1024,
      pids: 256,
      wallTimeoutMs: 60_000,
    });
    expect(limitsFor('browser', { ...LIMITS, memoryMb: 2048, pids: 512 })).toMatchObject({
      memoryMb: 2048,
      pids: 512,
    });
    expect(limitsFor('execute', LIMITS)).toEqual(LIMITS);
  });
});

describe('sandbox dispatcher: gates (X13 steps 1–3)', () => {
  it('refuses a key of another organization (fatal tenant_mismatch) before any read', async () => {
    const t = setup();
    const submission = t.submit();
    const event = t.eventFor(submission, undefined, '99');
    await expect(t.dispatcher.handle(event)).rejects.toThrow(NonRetryableError);
    await expect(t.dispatcher.handle(event)).rejects.toThrow('tenant_mismatch');
    expect(t.store.state.ledger.size).toBe(0);
    expect(classifyScanFailure(new NonRetryableError('tenant_mismatch'))).toBe('fatal');
  });

  it('a missing submission is a ledger no-op; a terminal one is a duplicate no-op', async () => {
    const t = setup();
    const submission = t.submit();
    const event = t.eventFor(submission);
    t.store.state.submissions.delete(submission.id);
    expect(await t.dispatcher.handle(event)).toBe('handled');
    expect(await t.dispatcher.handle(event)).toBe('duplicate');
    const done = t.submit();
    t.store.submission(done.id).status = 'completed';
    expect(await t.dispatcher.handle(t.eventFor(done))).toBe('handled');
    expect(t.store.state.analyses.size).toBe(0);
    expect(t.store.state.outbox).toHaveLength(0);
  });

  it('a wrong read (row of another submission) is retryable and counted', async () => {
    const t = setup();
    t.optIn();
    t.submit();
    const submission = t.submit();
    t.store.wrongSubmissionRead = true;
    await expect(t.dispatcher.handle(t.eventFor(submission))).rejects.toThrow(
      InconsistentSandboxReadError,
    );
    expect(
      await counter(t.registry, 'scan_sandbox_inconsistent_reads_total', { read: 'submission' }),
    ).toBe(1);
    expect(t.store.state.ledger.size).toBe(0);
  });

  it.each([
    [
      'feature_disabled',
      (t: ReturnType<typeof setup>) =>
        t.store.state.settings.set(ORG, { settings: { enabled: true }, version: 1 }),
    ],
    ['tenant_disabled', (t: ReturnType<typeof setup>) => t.store.state.features.set(ORG, true)],
    [
      'type_excluded',
      (t: ReturnType<typeof setup>) => t.optIn(ORG, { enabled: true, fileTypes: ['pdf'] }),
    ],
    [
      'size_excluded',
      (t: ReturnType<typeof setup>) => t.optIn(ORG, { enabled: true, maxSampleBytes: 10 }),
    ],
  ] as const)(
    'skips with %s, completes the submission and writes the skipped final',
    async (reason, arrange) => {
      const t = setup();
      arrange(t);
      const submission = t.submit();
      expect(await t.dispatcher.handle(t.eventFor(submission))).toBe('handled');
      expect(t.store.submission(submission.id)).toMatchObject({
        status: 'skipped',
        skipReason: reason,
        sandboxVerdict: null,
        sandboxReasonCodes: [`sandbox.${reason}`],
      });
      expect(t.store.submission(submission.id).settingsVersion).toMatch(/^sandbox-map\/1;/);
      const [completed] = completions(t.store);
      expect(attachmentSandboxCompletedV1.parse(completed!.payload)).toMatchObject({
        status: 'skipped',
        verdict: null,
        reasonCodes: [`sandbox.${reason}`],
        executed: false,
        isolation: null,
      });
      expect(t.store.final(submission.scanId, RECEIVED)).toMatchObject({
        outcome: 'skipped',
        reasonCodes: [`sandbox.${reason}`],
        engineVersion: 'sandbox-engine/1',
      });
      expect(t.store.state.analyses.size).toBe(0);
      expect(tasks(t.store)).toHaveLength(0);
      expect(
        await counter(t.registry, 'scan_sandbox_submissions_total', {
          result: `skipped_${reason}`,
        }),
      ).toBe(1);
    },
  );

  it('an empty part is size_excluded', async () => {
    const t = setup();
    t.optIn();
    const submission = t.submit(ORG, { sizeBytes: 0 });
    await t.dispatcher.handle(t.eventFor(submission));
    expect(t.store.submission(submission.id).skipReason).toBe('size_excluded');
  });

  it('an invalid tenant row falls back to the platform settings and counts scan_settings_invalid_total', async () => {
    const t = setup({ platform: { tenantDefaultEnabled: true } });
    t.optIn(ORG, { enabled: true, fileTypes: ['not-a-type'] });
    const submission = t.submit();
    await t.dispatcher.handle(t.eventFor(submission));
    expect(t.invalid).toEqual(['sandbox']);
    // Platform default enabled = true: dispatched with the platform settings (row version none).
    expect(tasks(t.store)).toHaveLength(1);
    expect(t.store.submission(submission.id).settingsVersion).toMatch(/;t=none$/);
  });
});

describe('sandbox dispatcher: dedup, staging and dispatch (X13 steps 4–7)', () => {
  it('creates the analysis, stages a sealed sample and writes one task outbox row', async () => {
    const t = setup();
    t.optIn();
    const submission = t.submit();
    const event = t.eventFor(submission);
    expect(await t.dispatcher.handle(event)).toBe('handled');
    const [analysis] = t.store.analysesBySha(SHA);
    expect(analysis).toMatchObject({
      status: 'dispatched',
      profile: 'execute',
      organizationId: ORG,
      requestedEventId: event.eventId,
      deadlineAt: new Date(NOW.getTime() + 900_000),
    });
    expect(analysis!.dedupeKey).toBe(`${SHA}:${analysis!.analysisKey}`);
    expect(analysis!.sampleObjectKey).toBe(`samples/2026/11/${analysis!.publicId}.bin`);
    expect(t.store.submission(submission.id)).toMatchObject({
      status: 'submitted',
      analysisId: analysis!.id,
    });
    // The staged object is sealed: the plaintext is not in it and it opens with the key.
    const object = t.objects.objects.get(analysis!.sampleObjectKey!)!;
    expect(object.includes(BYTES)).toBe(false);
    expect(
      openSample({ current: SAMPLE_KEY }, object, { taskId: analysis!.publicId, sha256: SHA })
        .plaintext,
    ).toEqual(BYTES);
    const [task] = tasks(t.store);
    expect(task).toMatchObject({
      aggregateType: 'sandbox_analysis',
      aggregateId: analysis!.id.toString(),
      organizationId: ORG,
    });
    expect(sandboxTaskRequestedV1.parse(task!.payload)).toMatchObject({
      taskId: analysis!.publicId,
      analysisId: analysis!.id.toString(),
      sample: {
        key: analysis!.sampleObjectKey,
        sha256: SHA,
        sizeBytes: BYTES.length,
        detectedType: 'script_shell',
      },
      profile: 'execute',
      limits: LIMITS,
    });
    // The one-time result token (X11): sealed in the task, only its hash on the analysis.
    const payload = sandboxTaskRequestedV1.parse(task!.payload);
    expect(analysis!.resultTokenSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(openResultToken(RESULT_KEY, analysis!.publicId, payload.resultToken)).toBe(
      analysis!.resultTokenSha256,
    );
    expect(JSON.stringify(task!.payload)).not.toContain(analysis!.resultTokenSha256!);
    expect(() =>
      openResultToken('3'.repeat(64), analysis!.publicId, payload.resultToken),
    ).toThrow();
    expect(
      await counter(t.registry, 'scan_sandbox_submissions_total', { result: 'dispatched' }),
    ).toBe(1);
    expect(await t.dispatcher.handle(event)).toBe('duplicate');
    expect(tasks(t.store)).toHaveLength(1);
  });

  it('an in-flight analysis of the same hash is linked (two tenants, one task)', async () => {
    const t = setup();
    t.optIn(ORG);
    t.optIn(8n);
    const first = t.submit(ORG);
    const second = t.submit(8n);
    await t.dispatcher.handle(t.eventFor(first));
    await t.dispatcher.handle(t.eventFor(second));
    expect(t.store.analysesBySha(SHA)).toHaveLength(1);
    expect(tasks(t.store)).toHaveLength(1);
    const analysisId = t.store.analysesBySha(SHA)[0]!.id;
    expect(t.store.submission(second.id)).toMatchObject({ status: 'submitted', analysisId });
    expect(t.parts.reads).toBe(1);
    expect(await counter(t.registry, 'scan_sandbox_submissions_total', { result: 'linked' })).toBe(
      1,
    );
  });

  it('a reusable terminal analysis completes the submission at once (no staging, no task)', async () => {
    const t = setup();
    t.optIn();
    const first = t.submit();
    await t.dispatcher.handle(t.eventFor(first));
    const analysis = t.store.analysesBySha(SHA)[0]!;
    Object.assign(t.store.analysis(analysis.id), {
      status: 'not_executed',
      verdict: 'unknown',
      reasonCodes: ['sandbox.not_executed', 'sandbox.not_executed.backend_disabled'],
      isolation: 'none',
      executed: false,
      controllerVersion: 'sandbox-controller/0.1.0',
      backend: 'disabled',
      backendVersion: 'disabled/1',
      reuseUntil: new Date(NOW.getTime() + 3_600_000),
    });
    const second = t.submit();
    await t.dispatcher.handle(t.eventFor(second));
    expect(t.store.submission(second.id)).toMatchObject({
      status: 'completed',
      analysisId: analysis.id,
      sandboxVerdict: 'unknown',
      externalRef: analysis.publicId,
    });
    expect(t.store.final(second.scanId, RECEIVED)).toMatchObject({
      outcome: 'unknown',
      engineVersion: 'sandbox-controller/0.1.0+disabled/disabled/1',
      evidence: { submissions: 1, executed: 0, isolation: ['none'] },
    });
    expect(tasks(t.store)).toHaveLength(1);
    expect(t.parts.reads).toBe(1);
    expect(await counter(t.registry, 'scan_sandbox_submissions_total', { result: 'reused' })).toBe(
      1,
    );
  });

  it('reuse keeps the lock order analysis → scan → submission (no deadlock with the results consumer)', async () => {
    const t = setup();
    t.optIn();
    const first = t.submit();
    await t.dispatcher.handle(t.eventFor(first));
    const analysis = t.store.analysesBySha(SHA)[0]!;
    Object.assign(t.store.analysis(analysis.id), {
      status: 'completed',
      verdict: 'unknown',
      reasonCodes: ['sandbox.no_findings', 'sandbox.static_only'],
      isolation: 'process',
      executed: false,
      reuseUntil: new Date(NOW.getTime() + 3_600_000),
    });
    const second = t.submit();
    t.store.locks.length = 0;
    await t.dispatcher.handle(t.eventFor(second));
    expect(t.store.submission(second.id).status).toBe('completed');
    const locks = t.store.locks;
    const analysisLock = locks.indexOf(`analysis:${analysis.id.toString()}`);
    const scanLock = locks.indexOf(`scan:${second.scanId.toString()}`);
    const submissionWrite = locks.indexOf(`submission:${second.id.toString()}`);
    expect(analysisLock).toBeGreaterThanOrEqual(0);
    expect(scanLock).toBeGreaterThan(analysisLock);
    expect(submissionWrite).toBeGreaterThan(scanLock);
  });

  it.each([
    [
      'a terminal analysis past its reuse window',
      { status: 'completed', reuseUntil: new Date(NOW.getTime() - 1) },
    ],
    ['a terminal analysis without a reuse window', { status: 'failed', reuseUntil: null }],
    [
      'an in-flight analysis past its deadline',
      { status: 'dispatched', deadlineAt: new Date(NOW.getTime() - 1) },
    ],
  ] as const)(
    '%s is stale: its dedupe key is cleared and a new analysis created',
    async (_label, patch) => {
      const t = setup();
      t.optIn();
      const first = t.submit();
      await t.dispatcher.handle(t.eventFor(first));
      const old = t.store.analysesBySha(SHA)[0]!;
      Object.assign(t.store.analysis(old.id), { ...patch, verdict: 'unknown' });
      const second = t.submit();
      await t.dispatcher.handle(t.eventFor(second));
      const all = t.store.analysesBySha(SHA);
      expect(all).toHaveLength(2);
      expect(t.store.analysis(old.id).dedupeKey).toBeNull();
      const fresh = all.find((a) => a.id !== old.id)!;
      expect(fresh.dedupeKey).toBe(old.dedupeKey === null ? fresh.dedupeKey : old.dedupeKey);
      expect(t.store.submission(second.id).analysisId).toBe(fresh.id);
      expect(tasks(t.store)).toHaveLength(2);
    },
  );

  it('a concurrent dispatcher winning the unique dedupe key → re-read and link', async () => {
    const t = setup();
    t.optIn();
    const submission = t.submit();
    t.store.beforeCreateAnalysis = (input) => {
      t.store.beforeCreateAnalysis = null;
      t.store.addAnalysis({
        sha256: input.sha256,
        organizationId: 8n,
        dedupeKey: input.dedupeKey,
        status: 'pending',
        deadlineAt: new Date(NOW.getTime() + 600_000),
      });
    };
    expect(await t.dispatcher.handle(t.eventFor(submission))).toBe('handled');
    const all = t.store.analysesBySha(SHA);
    expect(all).toHaveLength(1);
    expect(t.store.submission(submission.id).analysisId).toBe(all[0]!.id);
    expect(tasks(t.store)).toHaveLength(0);
    expect(t.parts.reads).toBe(0);
  });

  it('resumes after a crash between transaction A and B: one staging retry, one task', async () => {
    const t = setup();
    t.optIn();
    const submission = t.submit();
    const event = t.eventFor(submission);
    t.parts.failNext = s3Outage();
    const error = await t.dispatcher.handle(event).catch((e: unknown) => e);
    expect(classifyScanFailure(error)).toBe('transient');
    const analysis = t.store.analysesBySha(SHA)[0]!;
    expect(analysis.status).toBe('pending');
    expect(t.store.submission(submission.id).status).toBe('submitted');
    expect(
      await counter(t.registry, 'scan_sandbox_staging_failures_total', {
        reason: 'storage_unavailable',
      }),
    ).toBe(1);
    // Another event of the same hash meanwhile only links (it did not create the analysis).
    const other = t.submit();
    await t.dispatcher.handle(t.eventFor(other));
    expect(t.store.submission(other.id)).toMatchObject({
      status: 'submitted',
      analysisId: analysis.id,
    });
    expect(tasks(t.store)).toHaveLength(0);
    // The redelivery of the creating event resumes at staging.
    expect(await t.dispatcher.handle(event)).toBe('handled');
    expect(t.store.analysis(analysis.id).status).toBe('dispatched');
    expect(tasks(t.store)).toHaveLength(1);
    expect(t.store.analysesBySha(SHA)).toHaveLength(1);
  });

  it('concurrent deliveries of the creating event dispatch exactly one task', async () => {
    const t = setup();
    t.optIn();
    const submission = t.submit();
    const event = t.eventFor(submission);
    const outcomes = await Promise.all([1, 2, 3].map(() => t.dispatcher.handle(event)));
    expect(outcomes.filter((o) => o === 'handled')).toHaveLength(1);
    expect(outcomes.filter((o) => o === 'duplicate')).toHaveLength(2);
    expect(t.store.analysesBySha(SHA)).toHaveLength(1);
    expect(t.store.analysesBySha(SHA)[0]!.status).toBe('dispatched');
    expect(tasks(t.store)).toHaveLength(1);
  });

  it('a put failure (S3 outage on the sandbox bucket) is transient and resumes', async () => {
    const t = setup();
    t.optIn();
    const submission = t.submit();
    const event = t.eventFor(submission);
    t.objects.failPuts = 1;
    await expect(t.dispatcher.handle(event)).rejects.toThrow('s3 down');
    expect(await t.dispatcher.handle(event)).toBe('handled');
    expect(tasks(t.store)).toHaveLength(1);
  });

  it.each([
    ['sample_unavailable', (t: ReturnType<typeof setup>, key: string) => t.parts.parts.delete(key)],
    [
      'sample_integrity',
      (t: ReturnType<typeof setup>, key: string) =>
        t.parts.parts.set(key, Buffer.from('other bytes')),
    ],
  ] as const)(
    '%s fails the analysis (dedupe key cleared) and its submissions; final error',
    async (code, arrange) => {
      const t = setup();
      t.optIn();
      const submission = t.submit();
      arrange(t, submission.objectKey);
      expect(await t.dispatcher.handle(t.eventFor(submission))).toBe('handled');
      const analysis = t.store.analysesBySha(SHA)[0]!;
      expect(analysis).toMatchObject({
        status: 'failed',
        verdict: 'error',
        errorCode: code,
        dedupeKey: null,
        reasonCodes: ['sandbox.error', `sandbox.error.${code}`],
      });
      expect(t.store.submission(submission.id)).toMatchObject({
        status: 'failed',
        sandboxVerdict: 'error',
      });
      expect(t.store.final(submission.scanId, RECEIVED)).toMatchObject({ outcome: 'error' });
      expect(tasks(t.store)).toHaveLength(0);
      expect(t.objects.objects.size).toBe(0);
      expect(
        await counter(t.registry, 'scan_sandbox_staging_failures_total', { reason: code }),
      ).toBe(1);
    },
  );

  it('does not dispatch when the deadline passed while staging (the sweeper expires it)', async () => {
    const t = setup();
    t.optIn();
    const submission = t.submit();
    const event = t.eventFor(submission);
    t.parts.failNext = s3Outage();
    await expect(t.dispatcher.handle(event)).rejects.toThrow();
    t.setNow(new Date(NOW.getTime() + 901_000));
    expect(await t.dispatcher.handle(event)).toBe('handled');
    expect(t.store.analysesBySha(SHA)[0]!.status).toBe('pending');
    expect(tasks(t.store)).toHaveLength(0);
  });

  it('resume on a terminal analysis completes the linked submission (catch-up)', async () => {
    const t = setup();
    t.optIn();
    const submission = t.submit();
    const event = t.eventFor(submission);
    t.parts.failNext = s3Outage();
    await expect(t.dispatcher.handle(event)).rejects.toThrow();
    const analysis = t.store.analysesBySha(SHA)[0]!;
    Object.assign(t.store.analysis(analysis.id), {
      status: 'expired',
      verdict: 'timeout',
      reasonCodes: ['sandbox.timeout'],
    });
    await t.dispatcher.handle(event);
    expect(t.store.submission(submission.id)).toMatchObject({
      status: 'expired',
      sandboxVerdict: 'timeout',
    });
    expect(t.store.final(submission.scanId, RECEIVED)).toMatchObject({ outcome: 'timeout' });
  });
});
