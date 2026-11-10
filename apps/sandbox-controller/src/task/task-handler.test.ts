import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NonRetryableError } from '@email-gateway/common';
import {
  EventTypes,
  type EventEnvelope,
  type SandboxTaskCompletedV1,
  type SandboxTaskRequestedV1,
} from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import {
  generateArtifactKeyPair,
  openArtifact,
  parseArtifactPrivateKey,
  parseArtifactPublicKey,
  sampleObjectKey,
  sealResultToken,
  sealSample,
  verifyResultMac,
} from '@email-gateway/sandbox';
import { emptySandboxObservations } from '@email-gateway/security-contracts';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { ArtifactSealer, PNG_SIGNATURE } from '../artifacts/artifact-sealer';
import {
  type BackendObservation,
  BackendRefusedError,
  type RunContext,
  type SandboxBackend,
  type SandboxTaskInput,
} from '../backends/backend';
import { disabledObservation, DisabledBackend } from '../backends/disabled.backend';
import type { ControllerMetricsPort } from '../metrics/controller-metrics';
import { ScratchArea } from '../scratch/scratch';
import {
  SampleMissingError,
  type SampleStore,
  StorageUnavailableError,
} from '../storage/sandbox-s3';
import { TransientTaskError } from './errors';
import { TaskHandler, type TaskHandlerOptions } from './task-handler';
import { pathViolations, type TaskState } from './task-state';

const logger = createLogger({ service: 'handler-test', level: 'silent' });
const resultKey = randomBytes(32).toString('hex');
const sampleKey = randomBytes(32).toString('hex');
const pair = generateArtifactKeyPair();
const root = mkdtempSync(join(tmpdir(), 'eg-sbx-handler-'));
const ORG = '42';

afterAll(() => rmSync(root, { recursive: true, force: true }));

const maxima = {
  SANDBOX_MAX_RUN_TIMEOUT_MS: 300_000,
  SANDBOX_MAX_MEMORY_MB: 1024,
  SANDBOX_MAX_CPU_MILLIS: 2000,
  SANDBOX_MAX_PIDS: 256,
  SANDBOX_MAX_SCRATCH_MB: 256,
  SANDBOX_MAX_ARTIFACTS: 16,
  SANDBOX_MAX_ARTIFACT_BYTES: 2_097_152,
  SANDBOX_MAX_TOTAL_ARTIFACT_BYTES: 8_388_608,
  SANDBOX_MAX_SAMPLE_BYTES: 26_214_400,
  SANDBOX_TASK_TIMEOUT_MS: 180_000,
};

class MemoryStore implements SampleStore {
  readonly objects = new Map<string, Buffer>();
  readonly gets: string[] = [];
  readonly puts: string[] = [];
  failGet: Error | null = null;
  failPut: Error | null = null;
  getSample(key: string, maxBytes: number): Promise<Buffer> {
    this.gets.push(key);
    if (this.failGet) return Promise.reject(this.failGet);
    const object = this.objects.get(key);
    if (!object) return Promise.reject(new SampleMissingError());
    if (object.length > maxBytes) return Promise.reject(new Error('too large'));
    return Promise.resolve(object);
  }
  putArtifact(key: string, body: Buffer): Promise<void> {
    if (this.failPut) return Promise.reject(this.failPut);
    this.puts.push(key);
    this.objects.set(key, body);
    return Promise.resolve();
  }
  probe(): Promise<void> {
    return Promise.resolve();
  }
  close(): void {}
}

function metricsRecorder(): ControllerMetricsPort & { events: string[] } {
  const events: string[] = [];
  const rec =
    (name: string) =>
    (...args: unknown[]) =>
      events.push(`${name}:${args.map(String).join(',')}`);
  return {
    events,
    task: rec('task'),
    taskDuration: () => undefined,
    setRunnersActive: rec('runners'),
    reap: rec('reap'),
    cleanupFailure: rec('cleanup'),
    limitHit: rec('limit'),
    finding: rec('finding'),
    artifact: rec('artifact'),
    s3Error: rec('s3'),
    publishFailure: rec('publishFailure'),
    setReady: rec('ready'),
    backend: rec('backend'),
  };
}

interface Fixture {
  handler: TaskHandler;
  store: MemoryStore;
  published: EventEnvelope<SandboxTaskCompletedV1>[];
  metrics: ReturnType<typeof metricsRecorder>;
  paths: Map<string, readonly string[]>;
  shutdown: AbortController;
  scratch: ScratchArea;
  options: TaskHandlerOptions;
}

let publishImpl: ((e: EventEnvelope<SandboxTaskCompletedV1>) => Promise<void>) | null;

function fixture(backend: SandboxBackend, overrides: Partial<TaskHandlerOptions> = {}): Fixture {
  const store = new MemoryStore();
  const published: EventEnvelope<SandboxTaskCompletedV1>[] = [];
  const metrics = metricsRecorder();
  const paths = new Map<string, readonly string[]>();
  const shutdown = new AbortController();
  const scratch = new ScratchArea(join(root, randomUUID()));
  const options: TaskHandlerOptions = {
    backend,
    store,
    sealer: new ArtifactSealer(parseArtifactPublicKey(pair.publicKey), store),
    scratch,
    publish: async (envelope) => {
      if (publishImpl) await publishImpl(envelope);
      published.push(envelope);
    },
    metrics,
    logger,
    keys: { result: resultKey, sample: sampleKey, samplePrevious: null },
    maxima,
    controllerVersion: 'sandbox-controller/test',
    retry: { maxDelayMs: 60_000, maxRetryAgeMs: 3_600_000 },
    shutdown: shutdown.signal,
    onFinished: (taskId, path) => paths.set(taskId, path),
    ...overrides,
  };
  return {
    handler: new TaskHandler(options),
    store,
    published,
    metrics,
    paths,
    shutdown,
    scratch,
    options,
  };
}

beforeEach(() => {
  publishImpl = null;
});

function taskEvent(
  bytes: Buffer,
  options: {
    detectedType?: string;
    deadlineMs?: number;
    requestedAgoMs?: number;
    sha256?: string;
    limits?: Partial<SandboxTaskRequestedV1['limits']>;
  } = {},
): {
  event: EventEnvelope<SandboxTaskRequestedV1>;
  key: string;
  sealed: Buffer;
  tokenSha256: string;
} {
  const taskId = randomUUID();
  const token = sealResultToken(resultKey, taskId);
  const sha256 = options.sha256 ?? createHash('sha256').update(bytes).digest('hex');
  const key = sampleObjectKey(taskId, new Date());
  const sealed = sealSample({ current: sampleKey }, bytes, {
    taskId,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  }).object;
  const now = Date.now();
  return {
    key,
    sealed,
    tokenSha256: token.tokenSha256,
    event: {
      eventId: randomUUID(),
      eventType: EventTypes.SandboxTaskRequested,
      occurredAt: new Date(now).toISOString(),
      correlationId: randomUUID(),
      organizationId: ORG,
      payload: {
        taskId,
        analysisId: '7',
        sample: {
          key,
          sha256,
          sizeBytes: bytes.length,
          detectedType: (options.detectedType ?? 'script_shell') as never,
        },
        profile: 'static',
        limits: {
          wallTimeoutMs: 60_000,
          memoryMb: 512,
          cpuMillis: 1000,
          pids: 128,
          scratchMb: 64,
          maxArtifacts: 16,
          maxArtifactBytes: 2_097_152,
          maxTotalArtifactBytes: 8_388_608,
          ...options.limits,
        },
        requestedAt: new Date(now - (options.requestedAgoMs ?? 1000)).toISOString(),
        deadlineAt: new Date(now + (options.deadlineMs ?? 600_000)).toISOString(),
        resultToken: token.sealed,
      },
    },
  };
}

/** A fake analyzing backend: records its input and the scratch dir, returns `result`. */
function analyzing(
  result: (
    task: SandboxTaskInput,
    ctx: RunContext,
  ) => Promise<BackendObservation> | BackendObservation,
): SandboxBackend & { inputs: SandboxTaskInput[]; dirs: string[] } {
  const inputs: SandboxTaskInput[] = [];
  const dirs: string[] = [];
  return {
    name: 'static',
    isolation: 'process',
    version: 'sandbox-static/1',
    executes: false,
    inputs,
    dirs,
    selfTest: () => Promise.resolve({ ok: true, code: 'ok', details: {} }),
    supports: (task) =>
      task.sample.detectedType === 'zip'
        ? { ok: false, reason: 'type_not_supported' }
        : { ok: true },
    run: async (task, ctx) => {
      inputs.push({ ...task, sample: { ...task.sample, bytes: Buffer.from(task.sample.bytes) } });
      dirs.push(ctx.scratchDir);
      expect(existsSync(ctx.scratchDir)).toBe(true);
      return result(task, ctx);
    },
    reap: () => Promise.resolve({ runnersRemoved: 0, scratchRemoved: 0, failures: 0 }),
    close: () => Promise.resolve(),
  };
}

const completed = (
  artifacts: BackendObservation['artifacts'] = [],
  patch: Partial<BackendObservation> = {},
): BackendObservation => ({
  status: 'completed',
  executed: false,
  notExecutedReason: null,
  errorCode: null,
  observations: {
    ...emptySandboxObservations(),
    findings: [{ code: 'static.script_download_cradle', severity: 'high', count: 1 }],
  },
  artifacts,
  analyzerVersion: 'sandbox-static/1',
  cleanup: { runnerRemoved: null, scratchRemoved: false },
  ...patch,
});

function expectValidPath(f: Fixture, taskId: string, expected?: TaskState[]): void {
  const path = f.paths.get(taskId) ?? [];
  expect(pathViolations(path as TaskState[])).toEqual([]);
  if (expected) expect(path).toEqual(expected);
}

describe('TaskHandler (X7)', () => {
  it('disabled: not_executed/backend_disabled without reading the bucket', async () => {
    const f = fixture(new DisabledBackend());
    const { event, tokenSha256 } = taskEvent(Buffer.from('echo hi'));
    expect(await f.handler.handle(event)).toBe('handled');
    expect(f.store.gets).toEqual([]);
    const result = f.published[0]!;
    expect(result.eventType).toBe(EventTypes.SandboxTaskCompleted);
    expect(result.organizationId).toBe(ORG);
    expect(result.correlationId).toBe(event.correlationId);
    expect(result.payload).toMatchObject({
      status: 'not_executed',
      notExecutedReason: 'backend_disabled',
      errorCode: null,
      backend: 'disabled',
      isolation: 'none',
      executed: false,
      artifacts: [],
    });
    expect(result.payload).not.toHaveProperty('verdict');
    // The MAC covers the whole payload and the organization, keyed to the task's token (X11).
    const macInput = {
      organizationId: ORG,
      tokenSha256,
      payload: JSON.parse(JSON.stringify(result.payload)) as Record<string, unknown>,
    };
    expect(verifyResultMac(resultKey, macInput, result.payload.resultMac)).toBe(true);
    expect(
      verifyResultMac(
        resultKey,
        { ...macInput, payload: { ...macInput.payload, notExecutedReason: 'type_not_supported' } },
        result.payload.resultMac,
      ),
    ).toBe(false);
    expect(
      verifyResultMac(
        resultKey,
        { ...macInput, tokenSha256: 'f'.repeat(64) },
        result.payload.resultMac,
      ),
    ).toBe(false);
    expectValidPath(f, event.payload.taskId, [
      'received',
      'validated',
      'admitted',
      'not_executed',
      'published',
      'acked',
    ]);
    expect(f.metrics.events).toContain('task:disabled,not_executed');
  });

  it('answers deadline_passed and size_exceeded without a run', async () => {
    const backend = analyzing(() => completed());
    const f = fixture(backend);
    const late = taskEvent(Buffer.from('x'), { deadlineMs: 1000 });
    late.event.payload.deadlineAt = new Date(Date.now() - 1).toISOString();
    late.event.payload.requestedAt = new Date(Date.now() - 5000).toISOString();
    await f.handler.handle(late.event);
    expect(f.published[0]!.payload.notExecutedReason).toBe('deadline_passed');
    expectValidPath(f, late.event.payload.taskId, [
      'received',
      'validated',
      'deadline_passed',
      'published',
      'acked',
    ]);
    const big = taskEvent(Buffer.from('x'));
    big.event.payload.sample.sizeBytes = maxima.SANDBOX_MAX_SAMPLE_BYTES + 1;
    await f.handler.handle(big.event);
    expect(f.published[1]!.payload.notExecutedReason).toBe('size_exceeded');
    const zip = taskEvent(Buffer.from('PK'), { detectedType: 'zip' });
    await f.handler.handle(zip.event);
    expect(f.published[2]!.payload.notExecutedReason).toBe('type_not_supported');
    expect(backend.inputs).toEqual([]);
    expect(f.store.gets).toEqual([]);
  });

  it('fetches and opens the sample, runs in a scratch removed before publishing, seals artifacts', async () => {
    const report = Buffer.from(JSON.stringify({ v: 1 }));
    const png = Buffer.concat([PNG_SIGNATURE, Buffer.from('fake-image')]);
    const backend = analyzing(() =>
      completed([
        { kind: 'static_report', contentType: 'application/json', bytes: report },
        { kind: 'screenshot', contentType: 'image/png', bytes: png },
      ]),
    );
    const f = fixture(backend);
    const sample = Buffer.from('#!/bin/sh\necho hi\n');
    const { event, key, sealed } = taskEvent(sample, {
      limits: { memoryMb: 4096, wallTimeoutMs: 600_000 },
    });
    f.store.objects.set(key, sealed);
    let scratchAtPublish: boolean | null = null;
    publishImpl = () => {
      scratchAtPublish = existsSync(backend.dirs[0]!);
      return Promise.resolve();
    };
    await f.handler.handle(event);
    expect(backend.inputs[0]!.sample.bytes.equals(sample)).toBe(true);
    expect(backend.inputs[0]!.limits).toMatchObject({ memoryMb: 1024, wallTimeoutMs: 165_000 });
    expect(backend.dirs[0]).toMatch(new RegExp(`${event.payload.taskId}-1$`));
    expect(scratchAtPublish).toBe(false);
    const payload = f.published[0]!.payload;
    expect(payload).toMatchObject({
      status: 'completed',
      backend: 'static',
      isolation: 'process',
      executed: false,
      analyzerVersion: 'sandbox-static/1',
      cleanup: { runnerRemoved: null, scratchRemoved: true },
    });
    expect(payload.artifacts.map((a) => [a.seq, a.kind])).toEqual([
      [0, 'static_report'],
      [1, 'screenshot'],
    ]);
    const prefix = `artifacts/${new Date().toISOString().slice(0, 4)}/`;
    for (const a of payload.artifacts) {
      expect(a.key.startsWith(prefix)).toBe(true);
      expect(a.key).toMatch(
        new RegExp(`/${event.payload.taskId}/[0-9a-f]{16}/${String(a.seq)}-${a.kind}\\.bin$`),
      );
      const plain = openArtifact(
        parseArtifactPrivateKey(pair.privateKey),
        f.store.objects.get(a.key)!,
        a.wrappedKey,
        {
          taskId: event.payload.taskId,
          seq: a.seq,
          kind: a.kind,
        },
      );
      expect(plain.equals(a.kind === 'screenshot' ? png : report)).toBe(true);
    }
    expectValidPath(f, event.payload.taskId, [
      'received',
      'validated',
      'admitted',
      'fetching',
      'running',
      'collected',
      'cleaned',
      'stored',
      'published',
      'acked',
    ]);
    expect(f.metrics.events).toEqual(
      expect.arrayContaining(['task:static,completed', 'finding:high', 'artifact:static_report,7']),
    );
  });

  it('classifies missing and non-authentic samples as failed results', async () => {
    const f = fixture(analyzing(() => completed()));
    const missing = taskEvent(Buffer.from('a'));
    await f.handler.handle(missing.event);
    expect(f.published[0]!.payload).toMatchObject({
      status: 'failed',
      errorCode: 'sample_unavailable',
    });
    expectValidPath(f, missing.event.payload.taskId, [
      'received',
      'validated',
      'admitted',
      'fetching',
      'failed',
      'published',
      'acked',
    ]);
    const tampered = taskEvent(Buffer.from('b'));
    const bytes = Buffer.from(tampered.sealed);
    bytes.writeUInt8(bytes.readUInt8(bytes.length - 1) ^ 1, bytes.length - 1);
    f.store.objects.set(tampered.key, bytes);
    await f.handler.handle(tampered.event);
    expect(f.published[1]!.payload).toMatchObject({
      status: 'failed',
      errorCode: 'sample_integrity',
    });
    const wrongHash = taskEvent(Buffer.from('c'), { sha256: 'f'.repeat(64) });
    f.store.objects.set(wrongHash.key, wrongHash.sealed);
    await f.handler.handle(wrongHash.event);
    expect(f.published[2]!.payload).toMatchObject({
      status: 'failed',
      errorCode: 'sample_integrity',
    });
  });

  it('retries a bucket outage without a result, then publishes storage_unavailable when the budget is spent', async () => {
    const f = fixture(analyzing(() => completed()));
    f.store.failGet = new StorageUnavailableError('get_sample', 'TimeoutError');
    const early = taskEvent(Buffer.from('a'));
    await expect(f.handler.handle(early.event)).rejects.toBeInstanceOf(TransientTaskError);
    expect(f.published).toEqual([]);
    expect(f.metrics.events).toEqual(
      expect.arrayContaining(['s3:get_sample', 'task:static,retried']),
    );
    expectValidPath(f, early.event.payload.taskId, [
      'received',
      'validated',
      'admitted',
      'fetching',
      'transient_failure',
    ]);
    const late = taskEvent(Buffer.from('a'), { deadlineMs: 30_000 });
    await f.handler.handle(late.event);
    expect(f.published[0]!.payload).toMatchObject({
      status: 'failed',
      errorCode: 'storage_unavailable',
    });
    const old = taskEvent(Buffer.from('a'), { requestedAgoMs: 3_590_000 });
    await f.handler.handle(old.event);
    expect(f.published[1]!.payload).toMatchObject({
      status: 'failed',
      errorCode: 'storage_unavailable',
    });
  });

  it('retries an artifact put outage after the cleanup (no result)', async () => {
    const backend = analyzing(() =>
      completed([
        { kind: 'static_report', contentType: 'application/json', bytes: Buffer.from('{}') },
      ]),
    );
    const f = fixture(backend);
    const { event, key, sealed } = taskEvent(Buffer.from('x'));
    f.store.objects.set(key, sealed);
    f.store.failPut = new StorageUnavailableError('put_artifact', 'ServiceUnavailable');
    await expect(f.handler.handle(event)).rejects.toBeInstanceOf(TransientTaskError);
    expect(existsSync(backend.dirs[0]!)).toBe(false);
    expect(f.published).toEqual([]);
    expectValidPath(f, event.payload.taskId, [
      'received',
      'validated',
      'admitted',
      'fetching',
      'running',
      'collected',
      'cleaned',
      'transient_failure',
    ]);
  });

  it('classifies backend failures', async () => {
    const cases: [() => Promise<BackendObservation>, string][] = [
      [() => Promise.reject(new BackendRefusedError('spec_not_enforced')), 'backend_not_ready'],
      [
        () => Promise.reject(Object.assign(new Error('docker down'), { code: 'ECONNREFUSED' })),
        'transient',
      ],
      [() => Promise.reject(new Error('bug')), 'internal'],
      [
        () => Promise.resolve({ ...completed(), status: 'failed', errorCode: 'analyzer_crashed' }),
        'analyzer_crashed',
      ],
      [
        () =>
          Promise.resolve(
            completed([], {
              observations: {
                ...emptySandboxObservations(),
                findings: [{ code: 'static.unknown_code' as never, severity: 'low', count: 1 }],
              },
            }),
          ),
        'internal',
      ],
    ];
    for (const [run, expected] of cases) {
      const backend = analyzing(run);
      const f = fixture(backend);
      const { event, key, sealed } = taskEvent(Buffer.from('x'));
      f.store.objects.set(key, sealed);
      if (expected === 'transient') {
        await expect(f.handler.handle(event)).rejects.toBeInstanceOf(TransientTaskError);
        expect(f.published).toEqual([]);
      } else {
        await f.handler.handle(event);
        expect(f.published[0]!.payload).toMatchObject({ status: 'failed', errorCode: expected });
      }
      expect(existsSync(backend.dirs[0]!)).toBe(false);
      expectValidPath(f, event.payload.taskId);
    }
  });

  it('aborts on shutdown and retries later', async () => {
    const holder: { f?: Fixture } = {};
    const backend = analyzing((_task, ctx) => {
      holder.f?.shutdown.abort();
      return Promise.reject(ctx.signal.reason as Error);
    });
    const f = fixture(backend);
    holder.f = f;
    const { event, key, sealed } = taskEvent(Buffer.from('x'));
    f.store.objects.set(key, sealed);
    await expect(f.handler.handle(event)).rejects.toMatchObject({ code: 'shutdown' });
    expect(existsSync(backend.dirs[0]!)).toBe(false);
  });

  it('acks a duplicate in flight without a second run or result', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const backend = analyzing(async () => {
      await gate;
      return completed();
    });
    const f = fixture(backend);
    const { event, key, sealed } = taskEvent(Buffer.from('x'));
    f.store.objects.set(key, sealed);
    const first = f.handler.handle(event);
    await new Promise((r) => setTimeout(r, 20));
    expect(f.handler.activeTaskIds().has(event.payload.taskId)).toBe(true);
    const second = f.handler.handle({ ...event, eventId: randomUUID() });
    release();
    expect(await first).toBe('handled');
    expect(await second).toBe('duplicate');
    expect(backend.inputs).toHaveLength(1);
    expect(f.published).toHaveLength(1);
    expect(f.handler.activeTaskIds().size).toBe(0);
  });

  it('propagates an unconfirmed publish (no ack) and rejects an invalid task', async () => {
    const f = fixture(new DisabledBackend());
    publishImpl = () => Promise.reject(new Error('publish nacked'));
    const { event } = taskEvent(Buffer.from('x'));
    await expect(f.handler.handle(event)).rejects.toThrow('publish nacked');
    expect(f.metrics.events).toEqual(
      expect.arrayContaining(['publishFailure:', 'task:disabled,retried']),
    );
    expectValidPath(f, event.payload.taskId, [
      'received',
      'validated',
      'admitted',
      'not_executed',
      'transient_failure',
    ]);
    const bad = taskEvent(Buffer.from('x'));
    (bad.event.payload as { sample: { key: string } }).sample.key = 'samples/2026/11/other.bin';
    await expect(f.handler.handle(bad.event)).rejects.toEqual(
      new NonRetryableError('invalid_task'),
    );
    expect(f.metrics.events).toContain('task:disabled,rejected');
  });

  it('rejects a task whose result token does not open (another key or another task) without a run or result', async () => {
    const backend = analyzing(() => completed());
    const f = fixture(backend);
    const wrongKey = taskEvent(Buffer.from('x'));
    wrongKey.event.payload.resultToken = sealResultToken(
      randomBytes(32).toString('hex'),
      wrongKey.event.payload.taskId,
    ).sealed;
    const otherTask = taskEvent(Buffer.from('x'));
    otherTask.event.payload.resultToken = sealResultToken(resultKey, randomUUID()).sealed;
    for (const { event, key, sealed } of [wrongKey, otherTask]) {
      f.store.objects.set(key, sealed);
      await expect(f.handler.handle(event)).rejects.toEqual(new NonRetryableError('invalid_task'));
    }
    expect(f.published).toHaveLength(0);
    expect(f.store.gets).toEqual([]);
    expect(backend.inputs).toHaveLength(0);
    expect(f.metrics.events.filter((e) => e === 'task:static,rejected')).toHaveLength(2);
  });

  it('a second run of the same task writes its artifacts under a new run id (never over the first run)', async () => {
    const report = Buffer.from('{"v":1}');
    const backend = analyzing(() =>
      completed([{ kind: 'static_report', contentType: 'application/json', bytes: report }]),
    );
    const f = fixture(backend);
    const { event, key, sealed } = taskEvent(Buffer.from('x'));
    f.store.objects.set(key, sealed);
    await f.handler.handle(event);
    const firstRun = f.published[0]!.payload.artifacts[0]!;
    const firstObject = Buffer.from(f.store.objects.get(firstRun.key)!);
    // Redelivery after a crash (the first result may already be applied): the task runs again.
    await f.handler.handle({ ...event, eventId: randomUUID() });
    const secondRun = f.published[1]!.payload.artifacts[0]!;
    expect(secondRun.key).not.toBe(firstRun.key);
    expect(secondRun.wrappedKey).not.toBe(firstRun.wrappedKey);
    // The object the first result's row describes is untouched and still opens with its row.
    const stored = f.store.objects.get(firstRun.key)!;
    expect(stored.equals(firstObject)).toBe(true);
    expect(createHash('sha256').update(stored).digest('hex')).toBe(firstRun.objectSha256);
    expect(
      openArtifact(parseArtifactPrivateKey(pair.privateKey), stored, firstRun.wrappedKey, {
        taskId: event.payload.taskId,
        seq: 0,
        kind: 'static_report',
      }).equals(report),
    ).toBe(true);
  });

  it('drops over-cap and invalid artifacts and records the limits', async () => {
    const backend = analyzing(() =>
      completed([
        { kind: 'screenshot', contentType: 'image/png', bytes: Buffer.from('not a png') },
        { kind: 'process_log', contentType: 'text/plain', bytes: Buffer.alloc(100) },
        { kind: 'process_log', contentType: 'text/plain', bytes: Buffer.alloc(2000) },
      ]),
    );
    const f = fixture(backend);
    const { event, key, sealed } = taskEvent(Buffer.from('x'), {
      limits: { maxArtifactBytes: 1000 },
    });
    f.store.objects.set(key, sealed);
    await f.handler.handle(event);
    const payload = f.published[0]!.payload;
    expect(payload.artifacts.map((a) => a.kind)).toEqual(['process_log']);
    expect(payload.observations.limitsHit.sort()).toEqual(['artifact_cap', 'output_truncated']);
    expect(payload.observations.findings.map((f2) => f2.code)).toEqual(
      expect.arrayContaining(['limit.artifact_cap', 'limit.output_truncated']),
    );
  });

  it('meters a scratch or runner that could not be removed', async () => {
    const backend = analyzing(() => ({
      ...completed(),
      cleanup: { runnerRemoved: false, scratchRemoved: false },
    }));
    const f = fixture(backend);
    const { event, key, sealed } = taskEvent(Buffer.from('x'));
    f.store.objects.set(key, sealed);
    await f.handler.handle(event);
    expect(f.metrics.events).toContain('cleanup:runner');
    expect(f.published[0]!.payload.cleanup).toEqual({ runnerRemoved: false, scratchRemoved: true });
  });

  it('keeps a disabled-like observation from a backend valid', async () => {
    const backend = analyzing(() => disabledObservation());
    const f = fixture(backend);
    const { event, key, sealed } = taskEvent(Buffer.from('x'));
    f.store.objects.set(key, sealed);
    await f.handler.handle(event);
    expect(f.published[0]!.payload).toMatchObject({
      status: 'not_executed',
      notExecutedReason: 'backend_disabled',
    });
  });
});
