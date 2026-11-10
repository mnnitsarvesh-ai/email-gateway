import type { KeyObject } from 'node:crypto';
import { artifactObjectKey, newArtifactRunId, sealArtifact } from '@email-gateway/sandbox';
import {
  ARTIFACT_KIND_CONTENT_TYPE,
  ARTIFACT_KINDS,
  SANDBOX_ARTIFACT_ALGORITHM,
  type ArtifactContentType,
  type ArtifactKind,
  type SandboxLimit,
} from '@email-gateway/security-contracts';
import type { RawArtifact, TaskLimits } from '../backends/backend';
import type { SampleStore } from '../storage/sandbox-s3';

/**
 * Sealing and storing of artifacts (step 4.6 X12; ADR-0040 decision 6). Every raw artifact a
 * backend returned is checked (kind, the kind's content type, the PNG signature of a
 * screenshot), capped (`maxArtifacts`, `maxArtifactBytes`, `maxTotalArtifactBytes` of the
 * clamped task limits), sealed to the artifact PUBLIC key (`sandbox-artifact/1`: the controller
 * can never open what it wrote) and put to `artifacts/<yyyy>/<mm>/<taskId>/<runId>/<seq>-<kind>.bin` — a fresh run id per call,
 * so a retried or redelivered task never overwrites objects an applied result's rows describe.
 * Dropped artifacts are recorded as limits: `artifact_cap` (over a cap) or `output_truncated`
 * (invalid kind/type/signature — runner output is untrusted).
 */

export const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

export interface StoredArtifact {
  seq: number;
  kind: ArtifactKind;
  contentType: ArtifactContentType;
  key: string;
  objectSha256: string;
  plainSha256: string;
  sizeBytes: number;
  wrappedKey: string;
  keyId: string;
  algorithm: typeof SANDBOX_ARTIFACT_ALGORITHM;
}

export interface SelectedArtifact {
  seq: number;
  artifact: RawArtifact;
}

export interface ArtifactSelection {
  selected: SelectedArtifact[];
  /** Limits hit while selecting (deduplicated). */
  limitsHit: SandboxLimit[];
}

type CapLimits = Pick<TaskLimits, 'maxArtifacts' | 'maxArtifactBytes' | 'maxTotalArtifactBytes'>;

function valid(artifact: RawArtifact): boolean {
  if (!(ARTIFACT_KINDS as readonly string[]).includes(artifact.kind)) return false;
  if (ARTIFACT_KIND_CONTENT_TYPE[artifact.kind] !== artifact.contentType) return false;
  if (!Buffer.isBuffer(artifact.bytes)) return false;
  if (artifact.kind === 'screenshot') {
    return (
      artifact.bytes.length >= PNG_SIGNATURE.length &&
      artifact.bytes.subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE)
    );
  }
  return true;
}

/** Pure selection: validity, then the count, per-artifact and total caps, in backend order. */
export function selectArtifacts(
  artifacts: readonly RawArtifact[],
  limits: CapLimits,
): ArtifactSelection {
  const limitsHit = new Set<SandboxLimit>();
  const selected: SelectedArtifact[] = [];
  let total = 0;
  for (const artifact of artifacts) {
    if (!valid(artifact)) {
      limitsHit.add('output_truncated');
      continue;
    }
    const size = artifact.bytes.length;
    if (
      selected.length >= Math.min(limits.maxArtifacts, 16) ||
      size > limits.maxArtifactBytes ||
      total + size > limits.maxTotalArtifactBytes
    ) {
      limitsHit.add('artifact_cap');
      continue;
    }
    total += size;
    selected.push({ seq: selected.length, artifact });
  }
  return { selected, limitsHit: [...limitsHit] };
}

export interface SealAndStoreInput {
  taskId: string;
  /** Month of the artifact keys (UTC). */
  at: Date;
  artifacts: readonly RawArtifact[];
  limits: CapLimits;
  signal?: AbortSignal;
  /** The run id of the keys (default: a fresh one per call; tests pin it). */
  runId?: string;
}

export class ArtifactSealer {
  constructor(
    private readonly publicKey: KeyObject,
    private readonly store: Pick<SampleStore, 'putArtifact'>,
  ) {}

  /**
   * Seals and stores the selected artifacts in order under one fresh run id. A storage failure
   * throws (`StorageUnavailableError`: the whole task is retried; the retry writes under another
   * run id, never over these objects — the partial ones are removed by the bucket lifecycle
   * rule). Never logs or returns plaintext.
   */
  async sealAndStore(
    input: SealAndStoreInput,
  ): Promise<{ stored: StoredArtifact[]; limitsHit: SandboxLimit[] }> {
    const { selected, limitsHit } = selectArtifacts(input.artifacts, input.limits);
    const stored: StoredArtifact[] = [];
    const runId = input.runId ?? newArtifactRunId();
    for (const { seq, artifact } of selected) {
      const sealed = sealArtifact(this.publicKey, artifact.bytes, {
        taskId: input.taskId,
        seq,
        kind: artifact.kind,
      });
      const key = artifactObjectKey(input.taskId, input.at, runId, seq, artifact.kind);
      await this.store.putArtifact(key, sealed.object, input.signal);
      stored.push({
        seq,
        kind: artifact.kind,
        contentType: artifact.contentType,
        key,
        objectSha256: sealed.objectSha256,
        plainSha256: sealed.plainSha256,
        sizeBytes: sealed.sizeBytes,
        wrappedKey: sealed.wrappedKey,
        keyId: sealed.keyId,
        algorithm: SANDBOX_ARTIFACT_ALGORITHM,
      });
    }
    return { stored, limitsHit };
  }
}
