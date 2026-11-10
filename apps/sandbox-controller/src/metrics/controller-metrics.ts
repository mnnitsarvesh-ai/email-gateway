import { Injectable } from '@nestjs/common';
import { MetricsService } from '@email-gateway/common';
import type {
  ArtifactKind,
  SandboxFindingSeverity,
  SandboxLimit,
} from '@email-gateway/security-contracts';

/** `sandbox_tasks_total` statuses (X20). */
export type TaskMetricStatus = 'completed' | 'not_executed' | 'failed' | 'rejected' | 'retried';
export type CleanupKind = 'runner' | 'scratch';
export type ReapKind = 'runner' | 'scratch';
export type ReapMode = 'startup' | 'periodic';
export type S3Op = 'get_sample' | 'put_artifact' | 'probe';

/**
 * The sandbox-controller series (step 4.6 X20), exactly these and nothing else of its own. Labels
 * are bounded tokens (backend, status, profile, isolation, kind, mode, limit, severity, op):
 * never a tenant, hash, host, task id or path. The process defaults and the `amqp_*` series of
 * the messaging library come from `@email-gateway/common`.
 */
@Injectable()
export class ControllerMetrics {
  private readonly tasks;
  private readonly duration;
  private readonly ready;
  private readonly info;
  private readonly runners;
  private readonly reaped;
  private readonly cleanupFailures;
  private readonly limitHits;
  private readonly findings;
  private readonly artifacts;
  private readonly artifactBytes;
  private readonly s3Errors;
  private readonly publishFailures;

  constructor(metrics: MetricsService) {
    this.tasks = metrics.counter('sandbox_tasks_total', 'Sandbox tasks by backend and status', [
      'backend',
      'status',
    ]);
    this.duration = metrics.histogram(
      'sandbox_task_duration_seconds',
      'Sandbox task duration (receive to publish)',
      ['backend', 'profile'],
      [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 60, 120, 180, 300],
    );
    this.ready = metrics.gauge(
      'sandbox_backend_ready',
      'Last self-test of the isolation backend passed (1) or not (0)',
      ['backend'],
    );
    this.info = metrics.gauge(
      'sandbox_backend_info',
      'The configured isolation backend (always 1)',
      ['backend', 'isolation', 'executes'],
    );
    this.runners = metrics.gauge(
      'sandbox_runners_active',
      'Tasks currently inside the backend (analyzer children or runners)',
    );
    this.reaped = metrics.counter(
      'sandbox_reaped_total',
      'Leftover runners and scratch directories removed by the reaper',
      ['kind', 'mode'],
    );
    this.cleanupFailures = metrics.counter(
      'sandbox_cleanup_failures_total',
      'Runners or scratch directories that could not be removed',
      ['kind'],
    );
    this.limitHits = metrics.counter('sandbox_limit_hits_total', 'Resource limits hit by tasks', [
      'limit',
    ]);
    this.findings = metrics.counter('sandbox_findings_total', 'Findings reported by severity', [
      'severity',
    ]);
    this.artifacts = metrics.counter('sandbox_artifacts_total', 'Sealed artifacts stored by kind', [
      'kind',
    ]);
    this.artifactBytes = metrics.counter(
      'sandbox_artifact_bytes_total',
      'Plaintext bytes of the sealed artifacts stored',
    );
    this.s3Errors = metrics.counter(
      'sandbox_s3_errors_total',
      'Sandbox bucket errors by operation',
      ['op'],
    );
    this.publishFailures = metrics.counter(
      'sandbox_publish_failures_total',
      'Task results whose publish was not confirmed',
    );
  }

  backend(backend: string, isolation: string, executes: boolean): void {
    this.info.set({ backend, isolation, executes: String(executes) }, 1);
  }

  setReady(backend: string, ready: boolean): void {
    this.ready.set({ backend }, ready ? 1 : 0);
  }

  task(backend: string, status: TaskMetricStatus): void {
    this.tasks.inc({ backend, status });
  }

  taskDuration(backend: string, profile: string, seconds: number): void {
    this.duration.observe({ backend, profile }, seconds);
  }

  setRunnersActive(count: number): void {
    this.runners.set(count);
  }

  reap(kind: ReapKind, mode: ReapMode, count: number): void {
    if (count > 0) this.reaped.inc({ kind, mode }, count);
  }

  cleanupFailure(kind: CleanupKind, count = 1): void {
    if (count > 0) this.cleanupFailures.inc({ kind }, count);
  }

  limitHit(limit: SandboxLimit): void {
    this.limitHits.inc({ limit });
  }

  finding(severity: SandboxFindingSeverity): void {
    this.findings.inc({ severity });
  }

  artifact(kind: ArtifactKind, bytes: number): void {
    this.artifacts.inc({ kind });
    this.artifactBytes.inc(bytes);
  }

  s3Error(op: S3Op): void {
    this.s3Errors.inc({ op });
  }

  publishFailure(): void {
    this.publishFailures.inc();
  }
}

/** The narrow view the task handler, the reaper and the sealer use (fakes in unit tests). */
export type ControllerMetricsPort = Pick<
  ControllerMetrics,
  | 'task'
  | 'taskDuration'
  | 'setRunnersActive'
  | 'reap'
  | 'cleanupFailure'
  | 'limitHit'
  | 'finding'
  | 'artifact'
  | 's3Error'
  | 'publishFailure'
  | 'setReady'
  | 'backend'
>;

/** A metrics port that records nothing (unit tests of components that do not assert metrics). */
export const NOOP_METRICS: ControllerMetricsPort = {
  task: () => undefined,
  taskDuration: () => undefined,
  setRunnersActive: () => undefined,
  reap: () => undefined,
  cleanupFailure: () => undefined,
  limitHit: () => undefined,
  finding: () => undefined,
  artifact: () => undefined,
  s3Error: () => undefined,
  publishFailure: () => undefined,
  setReady: () => undefined,
  backend: () => undefined,
};
