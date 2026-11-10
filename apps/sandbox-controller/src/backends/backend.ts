import type { Logger } from '@email-gateway/logger';
import type {
  ArtifactContentType,
  ArtifactKind,
  NotExecutedReason,
  SandboxBackendName,
  SandboxErrorCode,
  SandboxIsolationClass,
  SandboxObservations,
  SandboxProfile as ContractSandboxProfile,
} from '@email-gateway/security-contracts';

/**
 * The isolation backend interface of the sandbox-controller (step 4.6 X2, ADR-0039 decision 2;
 * docs/plan/steps/14-sandbox.md). Every backend — `disabled`, `static`, `hardened-container`
 * (local/CI test harness, NOT a VM boundary) and `vm` (preflight contract, refuses in 4.6) —
 * implements `SandboxBackend`; the controller's task handler (X7) drives it and the factory
 * (`backends/factory.ts`) builds the configured one.
 *
 * A backend never throws for a property of the sample: it returns `not_executed` or a completed
 * observation with findings. It throws only for infrastructure faults (classified by the task
 * handler) and `BackendRefusedError` when it cannot run at all. No backend produces a verdict:
 * `sandbox-map/1` runs in the email-worker.
 *
 * The vocabularies (`NotExecutedReason`, `SandboxErrorCode`, `ArtifactKind`,
 * `ArtifactContentType`, `SandboxObservations`, the backend names, isolation classes and
 * profiles) come from `@email-gateway/security-contracts` (`sandbox.ts`).
 */

export type BackendName = SandboxBackendName;
/**
 * What isolates the sample: nothing runs (none), an isolated analyzer process (process), a
 * hardened shared-kernel container (container — NOT a VM boundary), a VM-class runtime (vm).
 */
export type IsolationClass = SandboxIsolationClass;
export type SandboxProfile = ContractSandboxProfile;

export interface TaskLimits {
  wallTimeoutMs: number;
  memoryMb: number;
  cpuMillis: number;
  pids: number;
  scratchMb: number;
  maxArtifacts: number;
  maxArtifactBytes: number;
  maxTotalArtifactBytes: number;
}

export interface SandboxTaskInput {
  taskId: string;
  analysisId: string;
  organizationId: string;
  profile: SandboxProfile;
  sample: { bytes: Buffer; sha256: string; sizeBytes: number; detectedType: string };
  /** Already clamped to the controller maxima (`SANDBOX_MAX_*`). */
  limits: TaskLimits;
  deadlineAt: Date;
}

export interface RunContext {
  /** Aborted at the task timeout or shutdown. */
  signal: AbortSignal;
  /** Controller-side per-task directory (0700), removed by the caller. */
  scratchDir: string;
  /** Ids only: never sample names, indicators or artifact content. */
  logger: Logger;
  now(): Date;
}

export interface RawArtifact {
  kind: ArtifactKind;
  contentType: ArtifactContentType;
  bytes: Buffer;
}

export interface BackendObservation {
  status: 'completed' | 'not_executed' | 'failed';
  executed: boolean;
  notExecutedReason: NotExecutedReason | null;
  errorCode: SandboxErrorCode | null;
  /** Shape of the task_completed.v1 `observations` (§4). */
  observations: SandboxObservations;
  /** In memory, bounded by the limits; sealed by the controller (X12). */
  artifacts: RawArtifact[];
  analyzerVersion: string | null;
  cleanup: { runnerRemoved: boolean | null; scratchRemoved: boolean };
}

export interface BackendSelfTest {
  ok: boolean;
  /**
   * 'ok' | a refusal code (e.g. 'not_in_kubernetes', 'runtime_class_missing',
   * 'handler_not_allowed', 'self_test_failed', 'vm_runner_not_implemented', 'docker_unreachable',
   * 'spec_not_enforced').
   */
  code: string;
  /** Bounded; never secrets. */
  details: Record<string, string | number | boolean>;
}

export interface ReapReport {
  runnersRemoved: number;
  scratchRemoved: number;
  failures: number;
}

export interface SandboxBackend {
  readonly name: BackendName;
  readonly isolation: IsolationClass;
  /** E.g. 'disabled/1', 'sandbox-static/1', 'hardened-container/1+runner:<image digest prefix>'. */
  readonly version: string;
  readonly executes: boolean;
  selfTest(signal: AbortSignal): Promise<BackendSelfTest>;
  supports(
    task: Pick<SandboxTaskInput, 'profile' | 'sample'>,
  ): { ok: true } | { ok: false; reason: NotExecutedReason };
  run(task: SandboxTaskInput, ctx: RunContext): Promise<BackendObservation>;
  /** Removes runners/scratch this backend created that are not in `active` task ids. */
  reap(active: ReadonlySet<string>, mode: 'startup' | 'periodic'): Promise<ReapReport>;
  close(): Promise<void>;
}

/** A backend that cannot run (configuration or preflight refusal); the controller exits 1. */
export class BackendRefusedError extends Error {
  constructor(readonly code: string) {
    super(`sandbox backend refused: ${code}`);
    this.name = 'BackendRefusedError';
  }
}
