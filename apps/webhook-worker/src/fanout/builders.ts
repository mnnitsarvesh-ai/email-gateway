import type {
  AttachmentSandboxCompletedV1,
  DeliveryApprovedV1,
  DomainDnsRecordsChangedV1,
  DomainStatusChangedV1,
  EventEnvelope,
  MessageReceivedV1,
  MessageScannedV1,
  MessageStateChangedV1,
  PolicyDecidedV1,
} from '@email-gateway/event-contracts';
import {
  DOMAIN_STATUSES,
  eventSeverity,
  type MatchableEvent,
  type Severity,
  type WebhookEventType,
} from '@email-gateway/webhooks';
import type { ScanVerdict } from '@email-gateway/security-contracts';
import {
  type DomainFacts,
  type ExecutionLogFacts,
  type MessageFacts,
  type MessageKey,
  type QuarantineEntryFacts,
  type RecipientOutcomeCounts,
  type ReleaseFacts,
  reasonCodes,
  snakeCodeOrNull,
} from './facts';
import { type Candidate, failingRecords, rejectionOf, threatVerdictOf } from './projection';

/**
 * Builds the `data` of each candidate public event from the writer facts (step 6.2 W3, §5). A
 * candidate whose optional rows are absent (no tenant rule matched, no entries, no release log)
 * yields no event. Pure apart from the injected `FactsSource`, so every rule is unit-tested
 * with fake facts.
 */

/** The reads a candidate may need (`FanoutReads` bound to the fanout transaction). */
export interface FactsSource {
  message(key: MessageKey): Promise<MessageFacts>;
  scanReasonCodes(key: MessageKey, scanId: bigint): Promise<string[]>;
  executionLog(key: MessageKey, round: number): Promise<ExecutionLogFacts>;
  quarantineEntries(
    key: MessageKey,
    round: number,
    origin: 'policy' | 'manual',
  ): Promise<QuarantineEntryFacts[]>;
  release(key: MessageKey, deliverySeq: number): Promise<ReleaseFacts | null>;
  recipientOutcomes(key: MessageKey): Promise<RecipientOutcomeCounts>;
  sandboxSubmission(
    key: MessageKey,
    submissionId: bigint,
  ): Promise<{ partIndex: number; sha256: string; detectedType: string }>;
  domain(organizationId: bigint, domainId: bigint, publicId: string): Promise<DomainFacts>;
}

/** One public event ready for the envelope (W4) and the stored row. */
export interface PublicEvent {
  candidate: Candidate;
  type: WebhookEventType;
  subKey: string;
  data: Record<string, unknown>;
  severity: Severity;
  /** The attributes subscriptions are matched against (W5), now with the domain. */
  matchable: MatchableEvent;
  /** `webhook_events.message_id` / `message_received_at` (message events). */
  message: MessageKey | null;
  /** `webhook_events.domain_id` (the message's tenant domain, or the domain of a domain event). */
  domainId: bigint | null;
  /** The public id of the alert scope (domain events) — N2 `scope_key`. */
  domainPublicId: string | null;
}

const iso = (date: Date): string => date.toISOString();
const DOMAIN_STATUS_SET: ReadonlySet<string> = new Set(DOMAIN_STATUSES);
const domainStatus = (value: string | null | undefined, fallback: string): string =>
  value && DOMAIN_STATUS_SET.has(value) ? value : fallback;

function messageObject(f: MessageFacts): Record<string, unknown> {
  return {
    id: f.publicId,
    receivedAt: iso(f.key.receivedAt),
    direction: f.direction,
    domainId: f.domainPublicId,
    internetMessageId: f.internetMessageId,
    senderDomain: f.senderDomain,
    headerFromDomain: f.headerFromDomain,
    recipientCount: f.recipientCount,
    recipientDomains: f.recipientDomains,
    sizeBytes: f.sizeBytes,
    attachmentCount: f.attachmentCount,
  };
}

function quarantineObject(
  origin: 'policy' | 'manual',
  round: number,
  entries: readonly QuarantineEntryFacts[],
): Record<string, unknown> {
  const reasons: string[] = [];
  for (const e of entries) {
    if (!reasons.includes(e.reason)) reasons.push(e.reason);
  }
  const earliest = entries.reduce(
    (min, e) => (e.expiresAt.getTime() < min.getTime() ? e.expiresAt : min),
    entries[0]!.expiresAt,
  );
  return {
    origin,
    lifecycleRound: round,
    entryCount: entries.length,
    kinds: {
      quarantine: entries.filter((e) => e.kind === 'quarantine').length,
      review: entries.filter((e) => e.kind === 'review').length,
    },
    reasons: reasons.slice(0, 8),
    entryIds: entries.slice(0, 50).map((e) => e.publicId),
    earliestExpiresAt: iso(earliest),
  };
}

const messageKeyOf = (
  event: EventEnvelope<unknown>,
  payload: { messageId: string; receivedAt: string },
): MessageKey => ({
  organizationId: BigInt(event.organizationId),
  messageId: BigInt(payload.messageId),
  receivedAt: new Date(payload.receivedAt),
});

/**
 * The public events of `candidates` (already reduced to the wanted ones). Message facts are read
 * once per source event and shared by its candidates.
 */
export async function buildPublicEvents(
  event: EventEnvelope<unknown>,
  candidates: readonly Candidate[],
  facts: FactsSource,
): Promise<PublicEvent[]> {
  const organizationId = BigInt(event.organizationId);
  let messageFacts: Promise<MessageFacts> | undefined;
  const messageOf = (key: MessageKey): Promise<MessageFacts> => {
    messageFacts ??= facts.message(key);
    return messageFacts;
  };
  const out: PublicEvent[] = [];
  const push = (
    candidate: Candidate,
    data: Record<string, unknown>,
    attributes: {
      message: MessageFacts | null;
      domainId?: bigint | null;
      domainPublicId?: string | null;
      verdict?: ScanVerdict;
    },
  ): void => {
    const severity = eventSeverity(candidate.type, data as never);
    const m = attributes.message;
    const matchable: MatchableEvent = {
      type: candidate.type,
      severity,
      ...(m !== null ? { direction: m.direction, domainPublicId: m.domainPublicId } : {}),
      ...(m === null && attributes.domainPublicId !== undefined
        ? { domainPublicId: attributes.domainPublicId }
        : {}),
      ...(attributes.verdict !== undefined ? { verdict: attributes.verdict } : {}),
    };
    out.push({
      candidate,
      type: candidate.type,
      subKey: candidate.subKey,
      data,
      severity,
      matchable,
      message: m?.key ?? null,
      domainId: m !== null ? m.domainId : (attributes.domainId ?? null),
      domainPublicId: m !== null ? m.domainPublicId : (attributes.domainPublicId ?? null),
    });
  };

  for (const candidate of candidates) {
    switch (candidate.rule) {
      case 'received': {
        const p = event.payload as MessageReceivedV1;
        const m = await messageOf(messageKeyOf(event, p));
        push(candidate, { message: messageObject(m) }, { message: m });
        break;
      }
      case 'scanned': {
        const p = event.payload as MessageScannedV1;
        const m = await messageOf(messageKeyOf(event, p));
        push(
          candidate,
          {
            message: messageObject(m),
            scan: {
              lifecycleRound: p.lifecycleRound,
              kind: p.scanKind,
              outcome: p.outcome,
              verdict: p.verdict,
              engines: p.engines.map((e) => ({ engine: e.engine, outcome: e.outcome })),
              reasonCodes: reasonCodes(p.reasonCodes),
              completedAt: p.completedAt,
            },
          },
          { message: m, verdict: p.verdict },
        );
        break;
      }
      case 'threat_scan': {
        const p = event.payload as PolicyDecidedV1;
        const verdict = threatVerdictOf(p.finalVerdict);
        if (verdict === null) break;
        const key = messageKeyOf(event, p);
        const m = await messageOf(key);
        const codes = p.scanId === null ? [] : await facts.scanReasonCodes(key, BigInt(p.scanId));
        push(
          candidate,
          {
            message: messageObject(m),
            detection: {
              stage: 'scan',
              verdict,
              riskScore: p.riskScore,
              reasonCodes: codes,
              lifecycleRound: p.lifecycleRound,
              finalAction: p.finalAction,
              attachment: null,
            },
          },
          { message: m, verdict },
        );
        break;
      }
      case 'policy_triggered': {
        const p = event.payload as PolicyDecidedV1;
        const key = messageKeyOf(event, p);
        const log = await facts.executionLog(key, p.lifecycleRound);
        if (log.matchedRules.length === 0) break; // W3: only when a tenant rule matched
        const m = await messageOf(key);
        const d = p.decisive;
        push(
          candidate,
          {
            message: messageObject(m),
            policy: {
              disposition: p.disposition,
              finalAction: p.finalAction,
              decisionSource: d.source,
              decisive:
                d.source === 'tenant_rule' &&
                d.policyId !== null &&
                d.versionNo !== null &&
                d.ruleId !== null
                  ? { policyId: d.policyId, versionNo: d.versionNo, ruleId: d.ruleId }
                  : null,
              matchedRules: log.matchedRules.slice(0, 16),
              actions: log.actions,
              overrideApplied: p.overrideApplied,
              lifecycleRound: p.lifecycleRound,
              evaluatedAt: p.evaluatedAt,
            },
          },
          { message: m },
        );
        break;
      }
      case 'quarantined_policy':
      case 'quarantined_manual': {
        const origin = candidate.rule === 'quarantined_policy' ? 'policy' : 'manual';
        const p = event.payload as PolicyDecidedV1 | MessageStateChangedV1;
        const key = messageKeyOf(event, p);
        const entries = await facts.quarantineEntries(key, p.lifecycleRound, origin);
        if (entries.length === 0) break; // optional rows: no entries, no event
        const m = await messageOf(key);
        push(
          candidate,
          {
            message: messageObject(m),
            quarantine: quarantineObject(origin, p.lifecycleRound, entries),
          },
          { message: m },
        );
        break;
      }
      case 'delivered': {
        const p = event.payload as MessageStateChangedV1;
        const key = messageKeyOf(event, p);
        const [m, recipients] = await Promise.all([messageOf(key), facts.recipientOutcomes(key)]);
        push(
          candidate,
          {
            message: messageObject(m),
            delivery: {
              outcome: p.reasonCode === 'delivery_partial' ? 'partial' : 'complete',
              lifecycleRound: p.lifecycleRound,
              recipients,
              completedAt: p.changedAt,
            },
          },
          { message: m },
        );
        break;
      }
      case 'rejected': {
        const p = event.payload as MessageStateChangedV1;
        const rejection = rejectionOf(p.reasonCode);
        if (rejection === null) break;
        const m = await messageOf(messageKeyOf(event, p));
        push(
          candidate,
          {
            message: messageObject(m),
            rejection: {
              reason: rejection.reason,
              stage: rejection.stage,
              lifecycleRound: p.lifecycleRound,
              rejectedAt: p.changedAt,
            },
          },
          { message: m },
        );
        break;
      }
      case 'released': {
        const p = event.payload as DeliveryApprovedV1;
        // Any sequence: a release of a message that was never delivered (fully quarantined)
        // is planned as delivery_seq 0 (nextDeliverySeq), a later one as the highest + 1.
        const key = messageKeyOf(event, p);
        const release = await facts.release(key, p.deliverySeq);
        if (release === null || release.entryIds.length === 0) break;
        const m = await messageOf(key);
        push(
          candidate,
          {
            message: messageObject(m),
            release: {
              releaseId: release.releaseId,
              mode: release.mode,
              entryIds: release.entryIds,
              recipientCount: p.recipients.length,
              deliverySeq: p.deliverySeq,
              approvedAt: p.approvedAt,
            },
          },
          { message: m },
        );
        break;
      }
      case 'threat_sandbox': {
        const p = event.payload as AttachmentSandboxCompletedV1;
        const key = messageKeyOf(event, p);
        const [m, submission] = await Promise.all([
          messageOf(key),
          facts.sandboxSubmission(key, BigInt(p.submissionId)),
        ]);
        push(
          candidate,
          {
            message: messageObject(m),
            detection: {
              stage: 'sandbox',
              verdict: 'malicious',
              riskScore: null,
              reasonCodes: reasonCodes(p.reasonCodes),
              lifecycleRound: p.lifecycleRound,
              finalAction: null,
              attachment: {
                partIndex: p.partIndex,
                sha256: p.sha256.toLowerCase(),
                detectedType: submission.detectedType,
              },
            },
          },
          { message: m, verdict: 'malicious' },
        );
        break;
      }
      case 'domain_verified':
      case 'dns_failed_verification': {
        const p = event.payload as DomainStatusChangedV1;
        const domainId = BigInt(p.domainId);
        const row = await facts.domain(organizationId, domainId, p.domainPublicId);
        const domain = {
          id: row.publicId,
          name: row.name.toLowerCase(),
          status: domainStatus(p.status, row.status),
        };
        const data =
          candidate.rule === 'domain_verified'
            ? {
                domain,
                previousStatus:
                  p.previousStatus !== null && DOMAIN_STATUS_SET.has(p.previousStatus)
                    ? p.previousStatus
                    : null,
                verifiedAt: p.changedAt,
              }
            : {
                domain,
                failure: {
                  kind: 'verification_failed',
                  reason: snakeCodeOrNull(p.reason),
                  records: [],
                  checkedAt: p.changedAt,
                },
              };
        push(candidate, data, { message: null, domainId, domainPublicId: row.publicId });
        break;
      }
      case 'dns_failed_records': {
        const p = event.payload as DomainDnsRecordsChangedV1;
        const failing = failingRecords(p);
        if (failing.length === 0) break;
        const domainId = BigInt(p.domainId);
        const row = await facts.domain(organizationId, domainId, p.domainPublicId);
        push(
          candidate,
          {
            domain: {
              id: row.publicId,
              name: row.name.toLowerCase(),
              status: domainStatus(p.domainStatus, row.status),
            },
            failure: {
              kind: 'records_failed',
              reason: null,
              records: failing.map((r) => ({
                purpose: r.purpose,
                recordKey: r.recordKey,
                previousStatus: r.previousStatus,
                status: r.status,
              })),
              checkedAt: p.checkedAt,
            },
          },
          { message: null, domainId, domainPublicId: row.publicId },
        );
        break;
      }
    }
  }
  return out;
}
