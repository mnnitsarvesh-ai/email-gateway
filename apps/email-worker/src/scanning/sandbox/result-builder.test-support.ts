import type { SandboxTaskCompletedV1 } from '@email-gateway/event-contracts';
import {
  artifactObjectKey,
  generateArtifactKeyPair,
  newArtifactRunId,
  parseArtifactPublicKey,
  resultMac,
  sealArtifact,
} from '@email-gateway/sandbox';
import {
  ARTIFACT_KIND_CONTENT_TYPE,
  type ArtifactKind,
  emptySandboxObservations,
  SANDBOX_FINDING_SEVERITY,
  type SandboxFindingCode,
} from '@email-gateway/security-contracts';

/**
 * Builds `mail.sandbox.task_completed.v1` payloads as the sandbox-controller does (tests only):
 * the result MAC (X11) under the given key over the whole payload, the organization and the
 * task's result token hash; artifacts sealed to an X25519 public key with keys under
 * `artifacts/<yyyy>/<mm>/<taskId>/<runId>/`. `patch` is applied AFTER the MAC (a forgery that
 * modifies a signed body). The sealed objects are returned so a test can store them.
 */
export interface ResultSpec {
  taskId: string;
  analysisId: string;
  sampleSha256: string;
  resultKey: string;
  /** The envelope organization the result is published for. */
  organizationId: string;
  /** SHA-256 of the task's one-time result token (the analysis's `resultTokenSha256`). */
  tokenSha256: string;
  /** The artifact run id (default: a fresh one). */
  runId?: string;
  status?: SandboxTaskCompletedV1['status'];
  backend?: SandboxTaskCompletedV1['backend'];
  findings?: SandboxFindingCode[];
  limitsHit?: string[];
  artifacts?: { kind: ArtifactKind; bytes: Buffer }[];
  /** The `not_executed` reason (default `backend_disabled`). */
  notExecutedReason?: NonNullable<SandboxTaskCompletedV1['notExecutedReason']>;
  /** Edits the payload BEFORE the MAC (what a controller itself signed). */
  beforeSign?: (payload: SandboxTaskCompletedV1) => void;
  /** Overrides applied after the MAC (forgeries). */
  patch?: Partial<SandboxTaskCompletedV1>;
  at?: Date;
  /** SPKI DER base64url; a fresh pair when absent. */
  publicKey?: string;
}

export interface BuiltResult {
  payload: SandboxTaskCompletedV1;
  objects: { key: string; body: Buffer }[];
  privateKey: string | null;
}

const ISOLATION = {
  disabled: 'none',
  static: 'process',
  'hardened-container': 'container',
  vm: 'vm',
} as const;

export function buildResult(spec: ResultSpec): BuiltResult {
  const at = spec.at ?? new Date();
  const status = spec.status ?? 'completed';
  const backend = spec.backend ?? (status === 'not_executed' ? 'disabled' : 'static');
  let privateKey: string | null = null;
  let publicKey = spec.publicKey;
  if (!publicKey) {
    const pair = generateArtifactKeyPair();
    publicKey = pair.publicKey;
    privateKey = pair.privateKey;
  }
  const recipient = parseArtifactPublicKey(publicKey);
  const objects: BuiltResult['objects'] = [];
  const runId = spec.runId ?? newArtifactRunId();
  const artifacts = (spec.artifacts ?? []).map((artifact, seq) => {
    const sealed = sealArtifact(recipient, artifact.bytes, {
      taskId: spec.taskId,
      seq,
      kind: artifact.kind,
    });
    const key = artifactObjectKey(spec.taskId, at, runId, seq, artifact.kind);
    objects.push({ key, body: sealed.object });
    return {
      seq,
      kind: artifact.kind,
      contentType: ARTIFACT_KIND_CONTENT_TYPE[artifact.kind],
      key,
      objectSha256: sealed.objectSha256,
      plainSha256: sealed.plainSha256,
      sizeBytes: sealed.sizeBytes,
      wrappedKey: sealed.wrappedKey,
      keyId: sealed.keyId,
      algorithm: sealed.algorithm,
    };
  });
  const observations = emptySandboxObservations();
  observations.findings = (spec.findings ?? []).map((code) => ({
    code,
    severity: SANDBOX_FINDING_SEVERITY[code],
    count: 1,
  }));
  observations.limitsHit = (spec.limitsHit ?? []) as typeof observations.limitsHit;
  const signed: SandboxTaskCompletedV1 = {
    taskId: spec.taskId,
    analysisId: spec.analysisId,
    sampleSha256: spec.sampleSha256,
    resultMac: '0'.repeat(64),
    status,
    notExecutedReason:
      status === 'not_executed' ? (spec.notExecutedReason ?? 'backend_disabled') : null,
    errorCode: status === 'failed' ? 'analyzer_crashed' : null,
    backend,
    backendVersion: backend === 'static' ? 'sandbox-static/1' : `${backend}/1`,
    isolation: ISOLATION[backend],
    executed: false,
    profile: 'static',
    controllerVersion: 'sandbox-controller/0.1.0',
    analyzerVersion: backend === 'static' ? 'sandbox-static/1' : null,
    startedAt: new Date(at.getTime() - 1_500).toISOString(),
    completedAt: at.toISOString(),
    durationMs: 1_500,
    observations: observations,
    artifacts,
    cleanup: { runnerRemoved: null, scratchRemoved: true },
  };
  spec.beforeSign?.(signed);
  signed.resultMac = resultMac(spec.resultKey, {
    organizationId: spec.organizationId,
    tokenSha256: spec.tokenSha256,
    payload: signed,
  });
  const payload: SandboxTaskCompletedV1 = { ...signed, ...spec.patch };
  return { payload, objects, privateKey };
}
