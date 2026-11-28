import type { MessageVerdict } from '@email-gateway/database';
import {
  COPY_DETECTED_MAX_DETECTION_IDS,
  messageCopyDetectedV1,
  type MessageCopyDetectedV1,
} from '@email-gateway/event-contracts';
import type { CopyDetection, PolicyOutcomeFacts } from '@email-gateway/mailbox-api';
import type { CopyDetectionKind } from '../metrics/mailbox-metrics';
import type { CopyDlpFacts, CopyPolicyState } from '../policy/copy-policy';

/** The message-level policy state of a copy message (A1; null = no copy to evaluate). */
export type MessagePolicyState = 'evaluated' | 'disabled' | 'failed' | 'not_applicable';

/**
 * A1: the `policy_state` of one recorded copy — report-mailbox copies `not_applicable` (C-I5),
 * inline-authority copies `inline` (P-I3), every other copy the message's state.
 */
export function copyPolicyStateOf(input: {
  reportMailbox: boolean;
  authority: 'copy' | 'inline';
  messageState: MessagePolicyState | null;
}): CopyPolicyState {
  if (input.reportMailbox) return 'not_applicable';
  if (input.authority === 'inline') return 'inline';
  return input.messageState ?? 'not_applicable';
}

/** The remediation outcome of a counted copy (A8.2 `copies.remediation`). */
export type CountedRemediation = 'pending' | 'simulated' | 'skipped' | 'none';

/** One copy counted by the detection event (copy authority, in scope, not a report mailbox). */
export interface CountedCopy {
  publicId: string;
  direction: 'inbound' | 'internal' | 'outbound';
  /** Effective mode of the copy's domain (`api` or `hybrid`; null when unknown). */
  domainMode: 'api' | 'hybrid' | 'inline' | null;
  remediation: CountedRemediation;
  detection: CopyDetection;
}

/** A8.2 `direction`: inbound before internal before outbound. */
export function detectionDirection(copies: readonly CountedCopy[]): CountedCopy['direction'] {
  if (copies.some((c) => c.direction === 'inbound')) return 'inbound';
  if (copies.some((c) => c.direction === 'internal')) return 'internal';
  return 'outbound';
}

/**
 * `kind` labels of `api_mode_copy_detections_total` for a detection: `threat` (threat verdict),
 * `dlp` (DLP action other than allow), `policy` (policy disposition other than allow, or tagged).
 */
export function detectionKinds(
  detection: CopyDetection,
  outcome: PolicyOutcomeFacts | null,
): CopyDetectionKind[] {
  const kinds: CopyDetectionKind[] = [];
  if (detection.threatVerdict !== null) kinds.push('threat');
  if (detection.dlpAction !== null) kinds.push('dlp');
  if (outcome !== null && (outcome.disposition !== 'allow' || outcome.tagged)) kinds.push('policy');
  return kinds;
}

/**
 * A8.2: the `mail.message.copy_detected.v1` payload of a copy message (validated by the strict
 * contract); null when no counted copy is a detection (A8.1) or the policy state cannot be
 * reported (`not_applicable`).
 */
export function copyDetectedPayload(input: {
  message: {
    id: bigint;
    publicId: string;
    receivedAt: Date;
    ingestSource: 'journal_intake' | 'mailbox_api';
  };
  copySource: 'journal' | 'graph' | 'gmail';
  verdict: MessageVerdict | null;
  riskScore: number | null;
  policyState: MessagePolicyState;
  messageOutcome: PolicyOutcomeFacts | null;
  dlp: CopyDlpFacts | null;
  counted: readonly CountedCopy[];
  decidedAt: Date;
}): MessageCopyDetectedV1 | null {
  const { counted } = input;
  if (counted.length === 0 || !counted.some((c) => c.detection.isDetection)) return null;
  if (input.policyState === 'not_applicable') return null;
  const evaluated = input.policyState === 'evaluated' && input.messageOutcome !== null;
  const outcome = evaluated ? input.messageOutcome : null;
  const remediation = { pending: 0, simulated: 0, skipped: 0, none: 0 };
  for (const c of counted) remediation[c.remediation] += 1;
  const dlp =
    input.dlp !== null && input.dlp.action !== 'allow'
      ? { action: input.dlp.action, verdict: input.dlp.verdict, categories: input.dlp.categories }
      : null;
  return messageCopyDetectedV1.parse({
    messageId: input.message.id.toString(),
    messagePublicId: input.message.publicId,
    receivedAt: input.message.receivedAt.toISOString(),
    ingestSource: input.message.ingestSource,
    copySource: input.copySource,
    direction: detectionDirection(counted),
    protectionMode: counted.some((c) => c.domainMode === 'api') ? 'api' : 'hybrid',
    verdict: input.verdict,
    riskScore: input.riskScore,
    policy: {
      state: evaluated ? 'evaluated' : input.policyState === 'failed' ? 'failed' : 'disabled',
      disposition: outcome?.disposition ?? null,
      decisionSource: outcome?.decisionSource ?? null,
      overrideApplied: outcome?.overrideApplied ?? false,
      actionTypes: outcome ? [...outcome.actionTypes] : [],
    },
    dlp,
    copies: { counted: counted.length, remediation },
    detectionIds: counted.slice(0, COPY_DETECTED_MAX_DETECTION_IDS).map((c) => c.publicId),
    decidedAt: input.decidedAt.toISOString(),
  });
}
