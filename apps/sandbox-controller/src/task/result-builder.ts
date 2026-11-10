import { resultMac } from '@email-gateway/sandbox';
import {
  emptySandboxObservations,
  SANDBOX_BACKEND_ISOLATION,
  sandboxObservationsSchema,
  type NotExecutedReason,
  type SandboxBackendName,
  type SandboxErrorCode,
  type SandboxObservations,
  type SandboxProfile,
  type SandboxTaskStatus,
} from '@email-gateway/security-contracts';
import {
  sandboxTaskCompletedV1,
  type SandboxTaskCompletedV1,
} from '@email-gateway/event-contracts';
import type { StoredArtifact } from '../artifacts/artifact-sealer';
import type { TaskLimits } from '../backends/backend';

/**
 * Builds `mail.sandbox.task_completed.v1` (step 4.6 §4, X7, X11): the result MAC (under
 * `SANDBOX_RESULT_KEY`) over the canonical JSON of the whole validated payload, the envelope
 * organization and the SHA-256 of the task's one-time result token; the backend identity, the bounded
 * observations (validated against BOTH the strict security-contracts schema — enum finding codes
 * with their fixed severities — and the event schema with its pairing rules), the sealed
 * artifact references and the cleanup record. It never carries a verdict.
 */

export class ResultInvalidError extends Error {
  override readonly name = 'ResultInvalidError';
  constructor(readonly where: 'observations' | 'event') {
    super(`task result failed ${where} validation`);
  }
}

export interface ResultInput {
  taskId: string;
  analysisId: string;
  sampleSha256: string;
  profile: SandboxProfile;
  status: SandboxTaskStatus;
  notExecutedReason: NotExecutedReason | null;
  errorCode: SandboxErrorCode | null;
  backend: SandboxBackendName;
  backendVersion: string;
  executed: boolean;
  analyzerVersion: string | null;
  controllerVersion: string;
  startedAt: Date;
  completedAt: Date;
  observations: SandboxObservations;
  artifacts: StoredArtifact[];
  cleanup: { runnerRemoved: boolean | null; scratchRemoved: boolean };
}

/** What signs a result: the key, the task's organization and its result token hash. */
export interface ResultSigner {
  key: string;
  organizationId: string;
  tokenSha256: string;
}

const UNSIGNED = '0'.repeat(64);

export function buildResult(signer: ResultSigner, input: ResultInput): SandboxTaskCompletedV1 {
  const observations = sandboxObservationsSchema.safeParse(input.observations);
  if (!observations.success) throw new ResultInvalidError('observations');
  const completedAt =
    input.completedAt.getTime() < input.startedAt.getTime() ? input.startedAt : input.completedAt;
  const payload = sandboxTaskCompletedV1.safeParse({
    taskId: input.taskId,
    analysisId: input.analysisId,
    sampleSha256: input.sampleSha256,
    resultMac: UNSIGNED,
    status: input.status,
    notExecutedReason: input.status === 'not_executed' ? input.notExecutedReason : null,
    errorCode: input.status === 'failed' ? input.errorCode : null,
    backend: input.backend,
    backendVersion: input.backendVersion.slice(0, 64),
    isolation: SANDBOX_BACKEND_ISOLATION[input.backend],
    executed: input.status === 'not_executed' ? false : input.executed,
    profile: input.profile,
    controllerVersion: input.controllerVersion,
    analyzerVersion: input.analyzerVersion,
    startedAt: input.startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationMs: Math.min(
      86_400_000,
      Math.max(0, completedAt.getTime() - input.startedAt.getTime()),
    ),
    observations: observations.data,
    artifacts: input.artifacts.map((a) => ({
      seq: a.seq,
      kind: a.kind,
      contentType: a.contentType,
      key: a.key,
      objectSha256: a.objectSha256,
      plainSha256: a.plainSha256,
      sizeBytes: a.sizeBytes,
      wrappedKey: a.wrappedKey,
      keyId: a.keyId,
      algorithm: a.algorithm,
    })),
    cleanup: input.cleanup,
  });
  if (!payload.success) throw new ResultInvalidError('event');
  // The MAC covers exactly the validated payload that is published (X11).
  return {
    ...payload.data,
    resultMac: resultMac(signer.key, {
      organizationId: signer.organizationId,
      tokenSha256: signer.tokenSha256,
      payload: payload.data,
    }),
  };
}

/** A result without observations or artifacts (not executed, failed before/after the run). */
export function bareResult(
  base: Omit<ResultInput, 'observations' | 'artifacts' | 'executed'> & { executed?: boolean },
): ResultInput {
  return {
    ...base,
    executed: base.executed ?? false,
    observations: emptySandboxObservations(),
    artifacts: [],
  };
}

/** Clamps the requested limits to the controller maxima (X7) and the task timeout. */
export function clampLimits(
  requested: TaskLimits,
  maxima: {
    SANDBOX_MAX_RUN_TIMEOUT_MS: number;
    SANDBOX_MAX_MEMORY_MB: number;
    SANDBOX_MAX_CPU_MILLIS: number;
    SANDBOX_MAX_PIDS: number;
    SANDBOX_MAX_SCRATCH_MB: number;
    SANDBOX_MAX_ARTIFACTS: number;
    SANDBOX_MAX_ARTIFACT_BYTES: number;
    SANDBOX_MAX_TOTAL_ARTIFACT_BYTES: number;
    SANDBOX_TASK_TIMEOUT_MS: number;
  },
): TaskLimits {
  // The run must end (and its cleanup run) well inside the task timeout.
  const wallCeiling = Math.max(
    5_000,
    Math.min(maxima.SANDBOX_MAX_RUN_TIMEOUT_MS, maxima.SANDBOX_TASK_TIMEOUT_MS - 15_000),
  );
  return {
    wallTimeoutMs: Math.min(requested.wallTimeoutMs, wallCeiling),
    memoryMb: Math.min(requested.memoryMb, maxima.SANDBOX_MAX_MEMORY_MB),
    cpuMillis: Math.min(requested.cpuMillis, maxima.SANDBOX_MAX_CPU_MILLIS),
    pids: Math.min(requested.pids, maxima.SANDBOX_MAX_PIDS),
    scratchMb: Math.min(requested.scratchMb, maxima.SANDBOX_MAX_SCRATCH_MB),
    maxArtifacts: Math.min(requested.maxArtifacts, maxima.SANDBOX_MAX_ARTIFACTS),
    maxArtifactBytes: Math.min(requested.maxArtifactBytes, maxima.SANDBOX_MAX_ARTIFACT_BYTES),
    maxTotalArtifactBytes: Math.min(
      requested.maxTotalArtifactBytes,
      maxima.SANDBOX_MAX_TOTAL_ARTIFACT_BYTES,
    ),
  };
}
