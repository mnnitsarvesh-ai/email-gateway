import { randomBytes } from 'node:crypto';
import { ARTIFACT_KINDS, type ArtifactKind } from '@email-gateway/security-contracts';

/**
 * Object keys in the sandbox bucket (step 4.6 X12): `samples/<yyyy>/<mm>/<taskId>.bin` (written
 * by the email-worker, read by the controller) and
 * `artifacts/<yyyy>/<mm>/<taskId>/<runId>/<seq>-<kind>.bin` (written by the controller). The
 * month is UTC. `runId` (16 lower-case hex, random per run) makes every run of a task write its
 * own objects: a retried or redelivered task never overwrites the objects a committed
 * `sandbox_artifacts` row (wrapped key, object SHA-256) already describes. The MinIO / IAM
 * policies allow the controller exactly `GetObject samples/*` and `PutObject artifacts/*`.
 */

const TASK_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const SAMPLE_KEY_PATTERN = /^samples\/(\d{4})\/(\d{2})\/([0-9a-f-]{36})\.bin$/;
export const ARTIFACT_KEY_PATTERN =
  /^artifacts\/(\d{4})\/(\d{2})\/([0-9a-f-]{36})\/([0-9a-f]{16})\/(\d{1,2})-([a-z_]+)\.bin$/;
const RUN_ID = /^[0-9a-f]{16}$/;

/** A fresh artifact run id (16 lower-case hex, 64 random bits). */
export function newArtifactRunId(): string {
  return randomBytes(8).toString('hex');
}

const assertTaskId = (taskId: string): void => {
  if (!TASK_ID.test(taskId)) throw new Error('Invalid task id');
};
const yearMonth = (at: Date): string => {
  if (Number.isNaN(at.getTime())) throw new Error('Invalid date');
  return `${String(at.getUTCFullYear()).padStart(4, '0')}/${String(at.getUTCMonth() + 1).padStart(2, '0')}`;
};

/** `samples/<yyyy>/<mm>/<taskId>.bin`. */
export function sampleObjectKey(taskId: string, at: Date): string {
  assertTaskId(taskId);
  return `samples/${yearMonth(at)}/${taskId}.bin`;
}

/** `artifacts/<yyyy>/<mm>/<taskId>/` (the prefix every artifact key of a task starts with). */
export function artifactKeyPrefix(taskId: string, at: Date): string {
  assertTaskId(taskId);
  return `artifacts/${yearMonth(at)}/${taskId}/`;
}

/** `artifacts/<yyyy>/<mm>/<taskId>/<runId>/<seq>-<kind>.bin` (seq 0..15). */
export function artifactObjectKey(
  taskId: string,
  at: Date,
  runId: string,
  seq: number,
  kind: ArtifactKind,
): string {
  if (!RUN_ID.test(runId)) throw new Error('Invalid artifact run id');
  if (!Number.isInteger(seq) || seq < 0 || seq > 15) throw new Error('Invalid artifact seq');
  if (!(ARTIFACT_KINDS as readonly string[]).includes(kind))
    throw new Error('Invalid artifact kind');
  return `${artifactKeyPrefix(taskId, at)}${runId}/${seq}-${kind}.bin`;
}

/** The task id of a sample key, or null. */
export function taskIdOfSampleKey(key: string): string | null {
  const taskId = SAMPLE_KEY_PATTERN.exec(key)?.[3];
  return taskId !== undefined && TASK_ID.test(taskId) ? taskId : null;
}

/** The parts of an artifact key, or null. */
export function parseArtifactKey(
  key: string,
): { taskId: string; runId: string; seq: number; kind: ArtifactKind; prefix: string } | null {
  const match = ARTIFACT_KEY_PATTERN.exec(key);
  if (!match) return null;
  const [, yyyy, mm, taskId, runId, seq, kind] = match as unknown as [
    string,
    string,
    string,
    string,
    string,
    string,
    string,
  ];
  if (!TASK_ID.test(taskId) || !(ARTIFACT_KINDS as readonly string[]).includes(kind)) return null;
  if (String(Number(seq)) !== seq || Number(seq) > 15) return null;
  return {
    taskId,
    runId,
    seq: Number(seq),
    kind: kind as ArtifactKind,
    prefix: `artifacts/${yyyy}/${mm}/${taskId}/`,
  };
}
