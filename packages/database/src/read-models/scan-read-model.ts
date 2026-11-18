import type { Prisma } from '@prisma/client';

/**
 * Scan read model (step 8.1, docs/plan/steps/23-journaling-archiving.md A5, §1.4 item 9): the
 * Prisma `select` objects and row types of one scan round as the api's scans view reads it
 * (`apps/api/src/modules/messages/repositories/message-scans-read.repository.ts`, the round's
 * policy evaluation of `apps/api/src/modules/policies/repositories/policy-facts.repository.ts`),
 * copied verbatim so the archive-worker freezes exactly the columns the api maps
 * (`archive-scan/1` snapshots) and the api decodes a frozen round back into the same row types.
 * WP4 switches the api to import these (behaviour-neutral); until then both copies must stay
 * identical. `scan-read-model.test.ts` pins every column list.
 *
 * Tenant rules stay with the callers: every query of these selects is scoped to the caller's
 * organization and the message's `(message_id, received_at)`. Live-only data is not part of the
 * frozen model (A5): URL click summaries (`url_click_events`), BEC feedback references and DLP
 * evidence objects.
 */

export const scanSelect = {
  id: true,
  lifecycleRound: true,
  scanKind: true,
  status: true,
  scanVerdict: true,
  reasonCodes: true,
  requiredEngines: true,
  startedAt: true,
  completedAt: true,
  deadlineAt: true,
} satisfies Prisma.EmailScanSelect;

export type ScanRoundRow = Prisma.EmailScanGetPayload<{ select: typeof scanSelect }>;

export const engineResultSelect = {
  scanId: true,
  engine: true,
  engineVersion: true,
  outcome: true,
  score: true,
  requiredScore: true,
  action: true,
  reasonCodes: true,
  errorCode: true,
  settingsVersion: true,
  durationMs: true,
  evidence: true,
  attempt: true,
  isFinal: true,
  completedAt: true,
} satisfies Prisma.ScanEngineResultSelect;

export type EngineResultRow = Prisma.ScanEngineResultGetPayload<{
  select: typeof engineResultSelect;
}>;

export const authSelect = {
  scanId: true,
  engine: true,
  spf: true,
  spfDomain: true,
  dkim: true,
  dkimSignatures: true,
  dmarc: true,
  dmarcPolicy: true,
  dmarcDomain: true,
  arc: true,
} satisfies Prisma.EmailAuthResultSelect;

export type AuthResultRow = Prisma.EmailAuthResultGetPayload<{ select: typeof authSelect }>;

export const attachmentResultSelect = {
  scanId: true,
  attachmentId: true,
  partIndex: true,
  sha256: true,
  sizeBytes: true,
  detectedType: true,
  typeFamily: true,
  typeMismatch: true,
  verdict: true,
  reasonCodes: true,
  clamavSignature: true,
  clamavEngineVersion: true,
  clamavDbVersion: true,
  yaraBundleId: true,
  yaraMatches: true,
  archive: true,
  knownHashSeverity: true,
  // Not `cache_result` / `duration_ms`: never shown to tenants (they reveal the cross-tenant
  // content cache, step 4.2 A10/A16).
} satisfies Prisma.AttachmentScanResultSelect;

export type AttachmentResultRow = Prisma.AttachmentScanResultGetPayload<{
  select: typeof attachmentResultSelect;
}>;

/**
 * Display metadata of a message's attachments by part index (`email_attachments`): the sanitized
 * filename and the declared type (the api's inline `attachmentParts` select).
 */
export const attachmentPartSelect = {
  partIndex: true,
  filename: true,
  declaredContentType: true,
} satisfies Prisma.EmailAttachmentSelect;

export interface AttachmentPartRow {
  partIndex: number;
  filename: string | null;
  declaredContentType: string | null;
}

export const sandboxSubmissionSelect = {
  id: true,
  scanId: true,
  attachmentId: true,
  partIndex: true,
  sha256: true,
  status: true,
  skipReason: true,
  sandboxVerdict: true,
  sandboxReasonCodes: true,
  completedAt: true,
  analysisId: true,
  externalRef: true,
} satisfies Prisma.SandboxSubmissionSelect;

export type SandboxSubmissionRow = Prisma.SandboxSubmissionGetPayload<{
  select: typeof sandboxSubmissionSelect;
}>;

/**
 * The fields of a `sandbox_analyses` row a tenant may see through its own completed submission
 * (step 4.6 X18). Not `organization_id` (the dispatching organization may be another tenant),
 * `dedupe_key`, `reuse_until`, `dispatched_at`, `deadline_at`, `completed_at`, `duration_ms`,
 * the event ids or the sample key: they would reveal that (and when) another organization's
 * byte-identical file was analysed first. `public_id` is read only to match the submission's
 * `external_ref` and is never returned.
 */
export const sandboxAnalysisSelect = {
  id: true,
  publicId: true,
  report: true,
  backend: true,
  backendVersion: true,
  isolation: true,
  executed: true,
  controllerVersion: true,
  analyzerVersion: true,
  mapVersion: true,
} satisfies Prisma.SandboxAnalysisSelect;

export type SandboxAnalysisRow = Prisma.SandboxAnalysisGetPayload<{
  select: typeof sandboxAnalysisSelect;
}>;

/** Artifact metadata (never the object key, hashes of the sealed object or the wrapped key). */
export const sandboxArtifactSelect = {
  analysisId: true,
  seq: true,
  kind: true,
  contentType: true,
  sizeBytes: true,
  plainSha256: true,
  expiresAt: true,
  purgedAt: true,
} satisfies Prisma.SandboxArtifactSelect;

export type SandboxArtifactRow = Prisma.SandboxArtifactGetPayload<{
  select: typeof sandboxArtifactSelect;
}>;

export const messageUrlSelect = {
  urlSeq: true,
  url: true,
  urlSha256: true,
  host: true,
  unicodeHost: true,
  registrableDomain: true,
  hostKind: true,
  flags: true,
  sources: true,
} satisfies Prisma.MessageUrlSelect;

export type MessageUrlRow = Prisma.MessageUrlGetPayload<{ select: typeof messageUrlSelect }>;

export const urlResultSelect = {
  scanId: true,
  urlSeq: true,
  urlSha256: true,
  verdict: true,
  reasonCodes: true,
  reputation: true,
  lookalike: true,
  fetchStatus: true,
  fetchError: true,
  hopCount: true,
  redirectChain: true,
  finalUrl: true,
  finalStatus: true,
  landing: true,
  rewritten: true,
  // Not `fetch_cache` / `duration_ms`: never shown to tenants (they reveal the cross-tenant
  // reputation/chain caches, step 4.3 U6/U16).
} satisfies Prisma.UrlScanResultSelect;

export type UrlResultRow = Prisma.UrlScanResultGetPayload<{ select: typeof urlResultSelect }>;

export const urlRewriteSelect = {
  scanId: true,
  lifecycleRound: true,
  status: true,
  skipReason: true,
  linksRewritten: true,
  partsRewritten: true,
  dkimSigned: true,
  expiresAt: true,
} satisfies Prisma.UrlRewriteSelect;

export type UrlRewriteRow = Prisma.UrlRewriteGetPayload<{ select: typeof urlRewriteSelect }>;

export const urlInspectionSelect = {
  scanId: true,
  urlSeq: true,
  urlSha256: true,
  status: true,
  verdict: true,
  reasonCodes: true,
  signals: true,
} satisfies Prisma.UrlDynamicInspectionSelect;

export type UrlInspectionRow = Prisma.UrlDynamicInspectionGetPayload<{
  select: typeof urlInspectionSelect;
}>;

export const becResultSelect = {
  scanId: true,
  engineVersion: true,
  rulesVersion: true,
  settingsVersion: true,
  lexiconVersion: true,
  deterministicScore: true,
  score: true,
  deterministicVerdict: true,
  verdict: true,
  inputs: true,
  rules: true,
  ai: true,
  aiShadow: true,
  // Not `identity` / `features` / `duration_ms` / `text_version`: B15 shows the evidence of the
  // rules only; the AI layer's durations are never shown.
} satisfies Prisma.BecScanResultSelect;

export type BecResultRow = Prisma.BecScanResultGetPayload<{ select: typeof becResultSelect }>;

export const dlpResultSelect = {
  scanId: true,
  engineVersion: true,
  rulesVersion: true,
  settingsVersion: true,
  policyVersion: true,
  extractorVersion: true,
  verdict: true,
  action: true,
  actionSource: true,
  matchedPolicyId: true,
  matchedRuleId: true,
  coverage: true,
  coverageDetail: true,
  categories: true,
  findings: true,
  policy: true,
  evidenceStatus: true,
  // Not `duration_ms`: the DLP engine is a coarse engine (D20); not `direction`, `finding_count`.
} satisfies Prisma.DlpScanResultSelect;

/**
 * The stored DLP result columns (masked samples only, never evidence). The api intersects this
 * with its mapper input type `DlpResultRowInput` (apps/api dlp domain), which it keeps.
 */
export type DlpResultRow = Prisma.DlpScanResultGetPayload<{ select: typeof dlpResultSelect }>;

/**
 * The evidence state of a round (`dlp_evidence`: expiry and purge time only; never the object
 * key, hash or wrapped key; the api's inline `dlpEvidence` select). Frozen as state only: the
 * evidence itself is never archived (A5).
 */
export const dlpEvidenceStateSelect = {
  scanId: true,
  expiresAt: true,
  purgedAt: true,
} satisfies Prisma.DlpEvidenceSelect;

export type DlpEvidenceStateRow = Prisma.DlpEvidenceGetPayload<{
  select: typeof dlpEvidenceStateSelect;
}>;

/**
 * The stored risk score columns the read API shows (step 5.1 R11, R15): the result fields, the
 * revision and creation time. Not `id`, `profile_version_id` (internal ids), `duration_us` or
 * the message keys.
 */
export const riskScoreSelect = {
  scanId: true,
  revision: true,
  status: true,
  score: true,
  level: true,
  verdict: true,
  recommendedAction: true,
  hardBlocks: true,
  reasonCodes: true,
  contributions: true,
  groups: true,
  engines: true,
  failures: true,
  floors: true,
  trust: true,
  evidence: true,
  explanation: true,
  explanationText: true,
  scorerVersion: true,
  signalMapVersion: true,
  inputVersion: true,
  profileSource: true,
  profileIdText: true,
  profileSha256: true,
  inputSha256: true,
  createdAt: true,
} satisfies Prisma.MessageRiskScoreSelect;

export type RiskScoreRow = Prisma.MessageRiskScoreGetPayload<{ select: typeof riskScoreSelect }>;

/**
 * The stored evaluation columns of a round's policy evaluation (`policy_execution_logs`, P10; the
 * api's `evaluationSelect` of `policy-facts.repository.ts`, read by `rowToEvaluationView`).
 */
export const evaluationSelect = {
  id: true,
  receivedAt: true,
  messageId: true,
  evaluationSeq: true,
  scanId: true,
  trigger: true,
  direction: true,
  disposition: true,
  decisionSource: true,
  decisivePolicyPublicId: true,
  decisiveRuleId: true,
  action: true,
  finalVerdict: true,
  riskScore: true,
  overrideApplied: true,
  actions: true,
  matchedRules: true,
  trace: true,
  floor: true,
  recommendation: true,
  overrideDetail: true,
  clamps: true,
  reasonCodes: true,
  delivery: true,
  deliveredObject: true,
  explanation: true,
  explanationText: true,
  policyGeneration: true,
  snapshotSha256: true,
  policyVersions: true,
  platformDefaultId: true,
  dslVersion: true,
  evaluatorVersion: true,
  inputVersion: true,
  inputSha256: true,
  tzdataVersion: true,
  durationUs: true,
  evaluatedAt: true,
  // Step 5.3 (Q4): per-recipient decisions of the round (null/false for 5.2 rows).
  recipientSplit: true,
  recipientDecisions: true,
} satisfies Prisma.PolicyExecutionLogSelect;

export type EvaluationRow = Prisma.PolicyExecutionLogGetPayload<{
  select: typeof evaluationSelect;
}>;

/**
 * Every select of the frozen round, by the `rows` key of the `archive-scan/1` snapshot
 * (§4.2): the archive-worker reads one round with these and the api decodes the snapshot back
 * into the row types above. `dlpEvidenceStateSelect` is not part of it: DLP evidence has its own
 * ≤ 180-day retention and is shown as "not retained in the archive" (A5).
 */
export const SCAN_READ_MODEL_SELECTS = Object.freeze({
  scan: scanSelect,
  engines: engineResultSelect,
  auth: authSelect,
  attachments: attachmentResultSelect,
  attachmentParts: attachmentPartSelect,
  sandboxSubmissions: sandboxSubmissionSelect,
  sandboxAnalyses: sandboxAnalysisSelect,
  sandboxArtifacts: sandboxArtifactSelect,
  urls: messageUrlSelect,
  urlResults: urlResultSelect,
  urlRewrites: urlRewriteSelect,
  urlInspections: urlInspectionSelect,
  bec: becResultSelect,
  dlp: dlpResultSelect,
  risk: riskScoreSelect,
  policy: evaluationSelect,
});

/** The row types of one frozen round (`archive-scan/1` `rows`). */
export interface ScanReadModelRows {
  scan: ScanRoundRow;
  engines: EngineResultRow[];
  auth: AuthResultRow[];
  attachments: AttachmentResultRow[];
  attachmentParts: AttachmentPartRow[];
  sandboxSubmissions: SandboxSubmissionRow[];
  sandboxAnalyses: SandboxAnalysisRow[];
  sandboxArtifacts: SandboxArtifactRow[];
  urls: MessageUrlRow[];
  urlResults: UrlResultRow[];
  urlRewrites: UrlRewriteRow[];
  urlInspections: UrlInspectionRow[];
  bec: BecResultRow[];
  dlp: DlpResultRow[];
  risk: RiskScoreRow[];
  policy: EvaluationRow | null;
}
