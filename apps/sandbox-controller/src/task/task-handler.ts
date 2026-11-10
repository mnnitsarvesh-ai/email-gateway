import { randomUUID } from 'node:crypto';
import { isTransientInfrastructureError, uuidv7 } from '@email-gateway/common';
import {
  EventTypes,
  sandboxTaskRequestedV1,
  type EventEnvelope,
  type RetryPolicy,
  type SandboxTaskCompletedV1,
  type SandboxTaskRequestedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import { openResultToken, openSample, SandboxEnvelopeError } from '@email-gateway/sandbox';
import type {
  NotExecutedReason,
  SandboxErrorCode,
  SandboxTaskStatus,
} from '@email-gateway/security-contracts';
import type { ArtifactSealer, StoredArtifact } from '../artifacts/artifact-sealer';
import {
  type BackendObservation,
  BackendRefusedError,
  type SandboxBackend,
} from '../backends/backend';
import { withLimits } from '../backends/composite';
import type { ControllerMetricsPort } from '../metrics/controller-metrics';
import type { ScratchArea } from '../scratch/scratch';
import {
  SampleMissingError,
  SampleTooLargeError,
  type SampleStore,
  StorageUnavailableError,
} from '../storage/sandbox-s3';
import { rejectTask, TransientTaskError } from './errors';
import {
  bareResult,
  buildResult,
  clampLimits,
  ResultInvalidError,
  type ResultInput,
} from './result-builder';
import { TaskStateTracker } from './task-state';

/**
 * The handler of `mail.sandbox.task_requested.v1` (step 4.6 X7, X8, X12, X19). Stateless (no
 * database): validate → deadline → clamp → `supports()` → fetch the sealed sample (sandbox
 * bucket, `samples/` only) and open it (`SANDBOX_SAMPLE_KEY`, SHA-256 checked) → per-task scratch
 * → `backend.run` under the task-timeout signal → remove the scratch (the runner is removed inside
 * `run`) → seal and store the artifacts (`artifacts/` only, under a fresh run id) → build the
 * result (strict validation; the result MAC over the whole payload, keyed to the task's one-time
 * result token, which is opened from the task first — a token that does not open rejects the
 * task) → publish with confirms to `email.security`
 * (`org.<id>.mail.sandbox.task_completed.v1`). The handler resolves only after the confirm, so
 * the consumer acks only then.
 *
 * Failures: a schema/tenant violation is rejected (dead-letter); an outage of the bucket or the
 * backend infrastructure is transient (retried with hold, no result) until the retry budget of
 * the task is spent — then a `failed` result is published; a property of the sample is a
 * result (`failed` `sample_unavailable` / `sample_integrity`, findings, `not_executed`), never a
 * retry. Duplicates in flight in this process wait for the first and are acked without a run.
 *
 * Logs: task id, analysis id, organization id, backend, status, codes and durations only.
 */

export interface TaskHandlerMaxima {
  SANDBOX_MAX_RUN_TIMEOUT_MS: number;
  SANDBOX_MAX_MEMORY_MB: number;
  SANDBOX_MAX_CPU_MILLIS: number;
  SANDBOX_MAX_PIDS: number;
  SANDBOX_MAX_SCRATCH_MB: number;
  SANDBOX_MAX_ARTIFACTS: number;
  SANDBOX_MAX_ARTIFACT_BYTES: number;
  SANDBOX_MAX_TOTAL_ARTIFACT_BYTES: number;
  SANDBOX_MAX_SAMPLE_BYTES: number;
  SANDBOX_TASK_TIMEOUT_MS: number;
}

export interface TaskHandlerOptions {
  backend: SandboxBackend;
  /** Null for backends that never read samples (`disabled`, `vm`). */
  store: SampleStore | null;
  sealer: ArtifactSealer | null;
  scratch: ScratchArea;
  publish: (envelope: EventEnvelope<SandboxTaskCompletedV1>) => Promise<void>;
  metrics: ControllerMetricsPort;
  logger: Logger;
  keys: { result: string; sample: string | null; samplePrevious: string | null };
  maxima: TaskHandlerMaxima;
  controllerVersion: string;
  /** The queue's retry policy: the budget after which an outage becomes a `failed` result. */
  retry: Pick<RetryPolicy, 'maxDelayMs' | 'maxRetryAgeMs'>;
  /** Aborted at shutdown: running tasks are aborted and retried later (no result). */
  shutdown: AbortSignal;
  now?: () => Date;
  newEventId?: () => string;
  /** Test hook: the path of each task. */
  onFinished?: (taskId: string, path: readonly string[]) => void;
}

type Outcome = 'handled' | 'duplicate';

export class TaskHandler {
  private readonly inFlight = new Map<string, Promise<void>>();
  private running = 0;
  private readonly now: () => Date;

  constructor(private readonly o: TaskHandlerOptions) {
    this.now = o.now ?? (() => new Date());
  }

  /** Task ids in flight in this process (the reaper's active set). */
  activeTaskIds(): ReadonlySet<string> {
    return new Set(this.inFlight.keys());
  }

  get inFlightCount(): number {
    return this.inFlight.size;
  }

  /** The `EventHandler` given to the queue consumer. */
  readonly handle = async (event: EventEnvelope<SandboxTaskRequestedV1>): Promise<Outcome> => {
    const tracker = new TaskStateTracker();
    const parsed = sandboxTaskRequestedV1.safeParse(event.payload);
    if (event.eventType !== EventTypes.SandboxTaskRequested || !parsed.success) {
      tracker.to('rejected');
      this.o.metrics.task(this.o.backend.name, 'rejected');
      this.o.logger.warn(
        { eventId: event.eventId, reason: 'invalid_task' },
        'sandbox task rejected',
      );
      throw rejectTask('invalid_task');
    }
    const task = parsed.data;
    // The one-time result token (X11): sealed to SANDBOX_RESULT_KEY and bound to the task id. A
    // task whose token does not open cannot be answered with an acceptable result.
    let tokenSha256: string;
    try {
      tokenSha256 = openResultToken(this.o.keys.result, task.taskId, task.resultToken);
    } catch (error) {
      if (!(error instanceof SandboxEnvelopeError)) throw error;
      tracker.to('rejected');
      this.o.metrics.task(this.o.backend.name, 'rejected');
      this.o.logger.warn(
        { eventId: event.eventId, taskId: task.taskId, reason: 'bad_result_token' },
        'sandbox task rejected',
      );
      throw rejectTask('invalid_task');
    }
    const first = this.inFlight.get(task.taskId);
    if (first) {
      tracker.to('duplicate');
      await first;
      tracker.to('acked');
      this.o.logger.info(
        { taskId: task.taskId, analysisId: task.analysisId, organizationId: event.organizationId },
        'duplicate sandbox task acked without a second run',
      );
      this.o.onFinished?.(task.taskId, tracker.history);
      return 'duplicate';
    }
    let release!: () => void;
    this.inFlight.set(task.taskId, new Promise<void>((resolve) => (release = resolve)));
    try {
      return await this.process(event, task, tracker, tokenSha256);
    } finally {
      this.inFlight.delete(task.taskId);
      release();
      this.o.onFinished?.(task.taskId, tracker.history);
    }
  };

  private async process(
    event: EventEnvelope<SandboxTaskRequestedV1>,
    task: SandboxTaskRequestedV1,
    tracker: TaskStateTracker,
    tokenSha256: string,
  ): Promise<Outcome> {
    const o = this.o;
    const startedAt = this.now();
    const log = o.logger.child({
      taskId: task.taskId,
      analysisId: task.analysisId,
      organizationId: event.organizationId,
      backend: o.backend.name,
    });
    const base = {
      taskId: task.taskId,
      analysisId: task.analysisId,
      sampleSha256: task.sample.sha256,
      profile: task.profile,
      backend: o.backend.name,
      backendVersion: o.backend.version,
      controllerVersion: o.controllerVersion,
      analyzerVersion: null,
      startedAt,
      cleanup: { runnerRemoved: null, scratchRemoved: true },
    };
    const notExecuted = (reason: NotExecutedReason): ResultInput =>
      bareResult({
        ...base,
        status: 'not_executed',
        notExecutedReason: reason,
        errorCode: null,
        completedAt: this.now(),
      });
    const failed = (code: SandboxErrorCode, extra: Partial<ResultInput> = {}): ResultInput => ({
      ...bareResult({
        ...base,
        status: 'failed',
        notExecutedReason: null,
        errorCode: code,
        completedAt: this.now(),
      }),
      ...extra,
    });
    const publish = (input: ResultInput) =>
      this.publishResult(event, tracker, input, tokenSha256, log);

    tracker.to('validated');
    if (Date.parse(task.deadlineAt) <= startedAt.getTime()) {
      tracker.to('deadline_passed');
      return publish(notExecuted('deadline_passed'));
    }
    const limits = clampLimits(task.limits, o.maxima);
    tracker.to('admitted');
    if (task.sample.sizeBytes > o.maxima.SANDBOX_MAX_SAMPLE_BYTES) {
      tracker.to('not_executed');
      return publish(notExecuted('size_exceeded'));
    }
    const support = o.backend.supports({
      profile: task.profile,
      sample: {
        bytes: Buffer.alloc(0),
        sha256: task.sample.sha256,
        sizeBytes: task.sample.sizeBytes,
        detectedType: task.sample.detectedType,
      },
    });
    if (!support.ok) {
      tracker.to('not_executed');
      return publish(notExecuted(support.reason));
    }

    tracker.to('fetching');
    let bytes: Buffer;
    try {
      bytes = await this.fetchSample(task);
    } catch (error) {
      if (error instanceof SampleMissingError) {
        tracker.to('failed');
        return publish(failed('sample_unavailable'));
      }
      if (error instanceof SampleTooLargeError || error instanceof SandboxEnvelopeError) {
        tracker.to('failed');
        return publish(failed('sample_integrity'));
      }
      if (error instanceof StorageUnavailableError) {
        o.metrics.s3Error('get_sample');
        return this.transientOrFailed(
          tracker,
          task,
          'storage_unavailable',
          'storage_unavailable',
          error,
          failed,
          publish,
          log,
        );
      }
      tracker.to('failed');
      log.error({ errName: (error as Error)?.name }, 'sandbox sample fetch failed');
      return publish(failed('internal'));
    }

    let scratchDir: string;
    try {
      scratchDir = await o.scratch.create(task.taskId);
    } catch (error) {
      return this.transientOrFailed(
        tracker,
        task,
        'internal',
        'scratch_unavailable',
        error,
        failed,
        publish,
        log,
      );
    }
    tracker.to('running');
    const timeout = AbortSignal.timeout(o.maxima.SANDBOX_TASK_TIMEOUT_MS);
    const signal = AbortSignal.any([timeout, o.shutdown]);
    let observation: BackendObservation | null = null;
    let runError: unknown = null;
    this.running += 1;
    o.metrics.setRunnersActive(this.running);
    try {
      observation = await o.backend.run(
        {
          taskId: task.taskId,
          analysisId: task.analysisId,
          organizationId: event.organizationId,
          profile: task.profile,
          sample: {
            bytes,
            sha256: task.sample.sha256,
            sizeBytes: bytes.length,
            detectedType: task.sample.detectedType,
          },
          limits,
          deadlineAt: new Date(task.deadlineAt),
        },
        { signal, scratchDir, logger: log, now: this.now },
      );
    } catch (error) {
      runError = error;
    } finally {
      this.running -= 1;
      o.metrics.setRunnersActive(this.running);
      bytes.fill(0);
    }
    tracker.to('collected');

    // Cleanup before anything is stored, published, acked or retried (X7, X8).
    let scratchRemoved = false;
    try {
      scratchRemoved = await o.scratch.remove(scratchDir);
    } catch {
      scratchRemoved = false;
    }
    if (!scratchRemoved) {
      o.metrics.cleanupFailure('scratch');
      log.error({ kind: 'scratch' }, 'sandbox scratch directory could not be removed');
    }
    if (observation?.cleanup.runnerRemoved === false) {
      o.metrics.cleanupFailure('runner');
      log.error({ kind: 'runner' }, 'sandbox runner could not be removed');
    }
    tracker.to('cleaned');
    const cleanup = { runnerRemoved: observation?.cleanup.runnerRemoved ?? null, scratchRemoved };

    if (runError !== null || observation === null) {
      if (o.shutdown.aborted) {
        tracker.to('transient_failure');
        o.metrics.task(o.backend.name, 'retried');
        log.warn({ reason: 'shutdown' }, 'sandbox task aborted by shutdown; retried later');
        throw new TransientTaskError('shutdown', { cause: runError });
      }
      if (runError instanceof BackendRefusedError) {
        tracker.to('failed');
        return publish(failed('backend_not_ready', { cleanup }));
      }
      if (!timeout.aborted && isTransientInfrastructureError(runError)) {
        return this.transientOrFailed(
          tracker,
          task,
          'backend_not_ready',
          'backend_unavailable',
          runError,
          (c) => failed(c, { cleanup }),
          publish,
          log,
        );
      }
      tracker.to('failed');
      log.error(
        { errName: (runError as Error)?.name, timedOut: timeout.aborted },
        'sandbox backend run failed',
      );
      return publish(failed('internal', { cleanup }));
    }

    const executed = observation.executed && o.backend.executes;
    const analyzerVersion = observation.analyzerVersion;
    if (observation.status === 'failed') {
      tracker.to('failed');
      return publish({
        ...failed(observation.errorCode ?? 'internal', { cleanup }),
        executed,
        analyzerVersion,
        observations: observation.observations,
      });
    }

    let stored: StoredArtifact[] = [];
    let observations = observation.observations;
    if (observation.status === 'completed' && observation.artifacts.length > 0) {
      if (!o.sealer) {
        observations = withLimits(observations, ['artifact_cap']);
      } else {
        try {
          const result = await o.sealer.sealAndStore({
            taskId: task.taskId,
            at: this.now(),
            artifacts: observation.artifacts,
            limits,
            signal: o.shutdown,
          });
          stored = result.stored;
          observations = withLimits(observations, result.limitsHit);
        } catch (error) {
          if (error instanceof StorageUnavailableError) o.metrics.s3Error('put_artifact');
          return this.transientOrFailed(
            tracker,
            task,
            'storage_unavailable',
            'storage_unavailable',
            error,
            (c) => failed(c, { cleanup }),
            publish,
            log,
          );
        }
      }
    }
    tracker.to('stored');
    const status: SandboxTaskStatus = observation.status;
    return publish({
      ...base,
      status,
      notExecutedReason:
        status === 'not_executed' ? (observation.notExecutedReason ?? 'type_not_supported') : null,
      errorCode: null,
      executed: status === 'completed' ? executed : false,
      analyzerVersion,
      completedAt: this.now(),
      observations,
      artifacts: stored,
      cleanup,
    });
  }

  /** `GetObject` of the sealed sample, opened with the sample key, plaintext SHA-256 verified. */
  private async fetchSample(task: SandboxTaskRequestedV1): Promise<Buffer> {
    const { store, keys } = this.o;
    if (!store || !keys.sample) throw new Error('sample store not configured');
    // The sealed object is larger than the plaintext by its header, IV and tag (< 1 KiB).
    const maxObject =
      Math.min(task.sample.sizeBytes, this.o.maxima.SANDBOX_MAX_SAMPLE_BYTES) + 2048;
    const object = await store.getSample(task.sample.key, maxObject, this.o.shutdown);
    const opened = openSample({ current: keys.sample, previous: keys.samplePrevious }, object, {
      taskId: task.taskId,
      sha256: task.sample.sha256,
    });
    if (opened.plaintext.length !== task.sample.sizeBytes) {
      opened.plaintext.fill(0);
      throw new SandboxEnvelopeError('integrity');
    }
    return opened.plaintext;
  }

  /**
   * An outage: retried (no result) while the task's retry budget lasts — the next hold would
   * still land before its deadline and inside the queue's maximum retry age — else a `failed`
   * result with `errorCode` (X19). During shutdown always a retry.
   */
  private async transientOrFailed(
    tracker: TaskStateTracker,
    task: SandboxTaskRequestedV1,
    errorCode: SandboxErrorCode,
    transientCode: TransientTaskError['code'],
    cause: unknown,
    failed: (code: SandboxErrorCode) => ResultInput,
    publish: (input: ResultInput) => Promise<Outcome>,
    log: Logger,
  ): Promise<Outcome> {
    const now = this.now().getTime();
    const { maxDelayMs, maxRetryAgeMs } = this.o.retry;
    const exhausted =
      now + maxDelayMs >= Date.parse(task.deadlineAt) ||
      now - Date.parse(task.requestedAt) + maxDelayMs >= maxRetryAgeMs;
    if (this.o.shutdown.aborted || !exhausted) {
      tracker.to('transient_failure');
      this.o.metrics.task(this.o.backend.name, 'retried');
      log.warn(
        { reason: transientCode, errName: (cause as Error | undefined)?.name },
        'sandbox task failed transiently; retrying',
      );
      throw new TransientTaskError(transientCode, { cause });
    }
    tracker.to('failed');
    log.warn(
      { reason: transientCode, errorCode },
      'sandbox task retry budget spent; publishing a failed result',
    );
    return publish(failed(errorCode));
  }

  private async publishResult(
    event: EventEnvelope<SandboxTaskRequestedV1>,
    tracker: TaskStateTracker,
    input: ResultInput,
    tokenSha256: string,
    log: Logger,
  ): Promise<Outcome> {
    const o = this.o;
    const signer = { key: o.keys.result, organizationId: event.organizationId, tokenSha256 };
    let payload: SandboxTaskCompletedV1;
    try {
      payload = buildResult(signer, input);
    } catch (error) {
      if (!(error instanceof ResultInvalidError)) throw error;
      log.error(
        { where: error.where },
        'sandbox result failed validation; publishing a failed result',
      );
      payload = buildResult(
        signer,
        bareResult({ ...input, status: 'failed', notExecutedReason: null, errorCode: 'internal' }),
      );
    }
    const envelope: EventEnvelope<SandboxTaskCompletedV1> = {
      eventId: o.newEventId?.() ?? safeUuidv7(),
      eventType: EventTypes.SandboxTaskCompleted,
      occurredAt: this.now().toISOString(),
      correlationId: event.correlationId,
      organizationId: event.organizationId,
      payload,
    };
    try {
      await o.publish(envelope);
    } catch (error) {
      o.metrics.publishFailure();
      o.metrics.task(o.backend.name, 'retried');
      tracker.to('transient_failure');
      log.warn(
        { errName: (error as Error)?.name },
        'sandbox result publish not confirmed; retrying the task',
      );
      throw error;
    }
    tracker.to('published');
    o.metrics.task(o.backend.name, payload.status);
    o.metrics.taskDuration(o.backend.name, payload.profile, payload.durationMs / 1000);
    for (const f of payload.observations.findings) o.metrics.finding(f.severity);
    for (const limit of input.observations.limitsHit) o.metrics.limitHit(limit);
    for (const a of payload.artifacts) o.metrics.artifact(a.kind, a.sizeBytes);
    log.info(
      {
        status: payload.status,
        notExecutedReason: payload.notExecutedReason,
        errorCode: payload.errorCode,
        executed: payload.executed,
        findings: payload.observations.findings.length,
        artifacts: payload.artifacts.length,
        durationMs: payload.durationMs,
      },
      'sandbox task finished',
    );
    tracker.to('acked');
    return 'handled';
  }
}

function safeUuidv7(): string {
  try {
    return uuidv7();
  } catch {
    return randomUUID();
  }
}
