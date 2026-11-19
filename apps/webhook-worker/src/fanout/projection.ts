import {
  type AtoAccountRiskUpdatedV1,
  type AtoResponseCompletedV1,
  type AttachmentSandboxCompletedV1,
  type DeliveryApprovedV1,
  type DomainDnsRecordsChangedV1,
  type DomainStatusChangedV1,
  type EventEnvelope,
  EventTypes,
  type MessageReceivedV1,
  type MessageScannedV1,
  type MessageStateChangedV1,
  type PolicyDecidedV1,
  type SecurityIncidentCreatedV1,
  type SecurityIncidentUpdatedV1,
} from '@email-gateway/event-contracts';
import type { ScanVerdict } from '@email-gateway/security-contracts';
import {
  type AlertKind,
  incidentWebhookSeverity,
  type Severity,
  type ThreatVerdict,
  type WebhookDirection,
  type WebhookEventType,
} from '@email-gateway/webhooks';

/**
 * The fanout's projection rules (step 6.2 W3): which public events an internal event yields,
 * decided from **payload fields only** (the cheap pre-filter: no database work), with the
 * attributes a subscription filter can be matched against before any read (type, severity,
 * direction, verdict; the domain is known only after the writer read and passes the pre-filter).
 */

/**
 * The twelve internal events bound to `email.webhooks`: the eight of topology v11 (§4.3) and the
 * four security incident / account takeover events of topology v13 (step 8.4 D16).
 */
export const FANOUT_SOURCE_TYPES = [
  EventTypes.MessageReceived,
  EventTypes.MessageScanned,
  EventTypes.PolicyDecided,
  EventTypes.MessageStateChanged,
  EventTypes.DeliveryApproved,
  EventTypes.AttachmentSandboxCompleted,
  EventTypes.DomainStatusChanged,
  EventTypes.DomainDnsRecordsChanged,
  EventTypes.SecurityIncidentCreated,
  EventTypes.SecurityIncidentUpdated,
  EventTypes.AtoAccountRiskUpdated,
  EventTypes.AtoResponseCompleted,
] as const;
export type FanoutSourceType = (typeof FANOUT_SOURCE_TYPES)[number];

export const isFanoutSourceType = (value: string): value is FanoutSourceType =>
  (FANOUT_SOURCE_TYPES as readonly string[]).includes(value);

/** What a candidate public event needs read on the writer before its data can be built. */
export type CandidateRule =
  | 'received'
  | 'scanned'
  | 'threat_scan'
  | 'policy_triggered'
  | 'quarantined_policy'
  | 'quarantined_manual'
  | 'delivered'
  | 'rejected'
  | 'released'
  | 'threat_sandbox'
  | 'domain_verified'
  | 'dns_failed_verification'
  | 'dns_failed_records'
  | 'incident_created'
  | 'incident_updated'
  | 'ato_risk_changed'
  | 'ato_response_completed';

/** One public event an internal event may yield (W3 table row). */
export interface Candidate {
  rule: CandidateRule;
  type: WebhookEventType;
  /** Distinguishes several public events of one type from one source event. */
  subKey: string;
  /** Severity by the §5.2 rules, computable from the payload. */
  severity: Severity;
  /** Carried by message events; undefined for domain events (passes the filter). */
  direction?: WebhookDirection;
  /** Carried by scan/threat events (`verdicts` filter). */
  verdict?: ScanVerdict;
  /** The security alert this event may request (N2), when its settings allow it. */
  alert: AlertKind | null;
}

const SCAN_SEVERITY: Readonly<Record<ScanVerdict, Severity>> = {
  clean: 'info',
  unknown: 'info',
  timeout: 'info',
  error: 'info',
  spam: 'low',
  suspicious: 'medium',
  malicious: 'high',
};

/**
 * The public threat verdict of a policy decision's `finalVerdict` (a risk verdict, step 5.1:
 * clean, spam, bulk, phishing, malware, bec, dlp_violation, suspicious, unknown). W3 states the
 * condition as `finalVerdict ∈ {spam, suspicious, malicious}`; the risk vocabulary has no
 * `malicious`, so the malicious classes (phishing, malware, bec) map to `malicious` and bulk to
 * `spam`. `dlp_violation`, `clean` and `unknown` are not threats (deviation recorded in §13).
 */
export const THREAT_VERDICT_OF_FINAL: Readonly<Record<string, ThreatVerdict>> = Object.freeze({
  spam: 'spam',
  bulk: 'spam',
  suspicious: 'suspicious',
  phishing: 'malicious',
  malware: 'malicious',
  bec: 'malicious',
});

export function threatVerdictOf(finalVerdict: string): ThreatVerdict | null {
  return THREAT_VERDICT_OF_FINAL[finalVerdict] ?? null;
}

/** `email.rejected` reasons: the lifecycle reason codes of E13, E17, E18, E24 (§5.2). */
const REJECTION_STAGE = {
  policy_reject: 'policy',
  policy_discard: 'policy',
  quarantine_deleted: 'quarantine',
  review_rejected: 'quarantine',
  delivery_failed: 'delivery',
} as const;
export type RejectionReason = keyof typeof REJECTION_STAGE;

export function rejectionOf(
  reasonCode: string,
): { reason: RejectionReason; stage: (typeof REJECTION_STAGE)[RejectionReason] } | null {
  return reasonCode in REJECTION_STAGE
    ? {
        reason: reasonCode as RejectionReason,
        stage: REJECTION_STAGE[reasonCode as RejectionReason],
      }
    : null;
}

/** Final actions of a decision that can come with policy quarantine entries (split included). */
const QUARANTINING_ACTIONS: readonly string[] = ['quarantine', 'require_approval', 'partial'];
/** DNS record purposes whose failure is `high` (§5.2). */
const CRITICAL_PURPOSES: readonly string[] = ['mx', 'spf', 'dkim', 'dmarc'];

/** The changes of a `domain.dns.records_changed.v1` that are failures (valid → invalid/missing). */
export function failingRecords(
  payload: DomainDnsRecordsChangedV1,
): DomainDnsRecordsChangedV1['changes'] {
  return payload.changes.filter(
    (c) => c.previousStatus === 'valid' && (c.status === 'invalid' || c.status === 'missing'),
  );
}

/**
 * The candidate public events of one internal event (W3), from its payload alone. An event of
 * another type, or one that matches no row of the W3 table, yields none.
 */
export function projectCandidates(event: EventEnvelope<unknown>): Candidate[] {
  switch (event.eventType) {
    case EventTypes.MessageReceived: {
      const p = event.payload as MessageReceivedV1;
      return [
        {
          rule: 'received',
          type: 'email.received',
          subKey: '',
          severity: 'info',
          direction: p.direction,
          alert: null,
        },
      ];
    }
    case EventTypes.MessageScanned: {
      const p = event.payload as MessageScannedV1;
      return [
        {
          rule: 'scanned',
          type: 'email.scanned',
          subKey: '',
          severity: SCAN_SEVERITY[p.verdict],
          direction: p.direction,
          verdict: p.verdict,
          alert: null,
        },
      ];
    }
    case EventTypes.PolicyDecided: {
      const p = event.payload as PolicyDecidedV1;
      const out: Candidate[] = [];
      const threat = threatVerdictOf(p.finalVerdict);
      if (threat !== null) {
        out.push({
          rule: 'threat_scan',
          type: 'email.threat.detected',
          subKey: 'scan',
          severity: SCAN_SEVERITY[threat],
          direction: p.direction,
          verdict: threat,
          alert: 'threat_detected',
        });
      }
      out.push({
        rule: 'policy_triggered',
        type: 'email.policy.triggered',
        subKey: '',
        severity: p.disposition === 'allow' ? 'low' : 'medium',
        direction: p.direction,
        alert: null,
      });
      if (
        QUARANTINING_ACTIONS.includes(p.finalAction) ||
        p.disposition === 'quarantine' ||
        p.disposition === 'require_approval'
      ) {
        out.push({
          rule: 'quarantined_policy',
          type: 'email.quarantined',
          subKey: 'policy',
          severity: 'medium',
          direction: p.direction,
          alert: null,
        });
      }
      return out;
    }
    case EventTypes.MessageStateChanged: {
      const p = event.payload as MessageStateChangedV1;
      if (p.state === 'delivered') {
        return [
          {
            rule: 'delivered',
            type: 'email.delivered',
            subKey: '',
            severity: 'info',
            direction: p.direction,
            alert: null,
          },
        ];
      }
      if (p.state === 'rejected' && rejectionOf(p.reasonCode) !== null) {
        return [
          {
            rule: 'rejected',
            type: 'email.rejected',
            subKey: '',
            severity: 'low',
            direction: p.direction,
            alert: null,
          },
        ];
      }
      if (p.state === 'quarantined' && p.reasonCode === 'manual_quarantine') {
        return [
          {
            rule: 'quarantined_manual',
            type: 'email.quarantined',
            subKey: 'manual',
            severity: 'medium',
            direction: p.direction,
            alert: null,
          },
        ];
      }
      return [];
    }
    case EventTypes.DeliveryApproved: {
      const p = event.payload as DeliveryApprovedV1;
      if (p.source !== 'quarantine_release') return [];
      // The direction is read from the message row (the approval does not carry it).
      return [
        {
          rule: 'released',
          type: 'email.released',
          subKey: String(p.deliverySeq),
          severity: 'info',
          alert: null,
        },
      ];
    }
    case EventTypes.AttachmentSandboxCompleted: {
      const p = event.payload as AttachmentSandboxCompletedV1;
      if (p.verdict !== 'malicious') return [];
      return [
        {
          rule: 'threat_sandbox',
          type: 'email.threat.detected',
          subKey: `sandbox:${p.partIndex}`,
          severity: 'high',
          verdict: 'malicious',
          alert: 'threat_detected',
        },
      ];
    }
    case EventTypes.DomainStatusChanged: {
      const p = event.payload as DomainStatusChangedV1;
      if (p.status === 'verified') {
        return [
          {
            rule: 'domain_verified',
            type: 'domain.verified',
            subKey: '',
            severity: 'info',
            alert: null,
          },
        ];
      }
      if (p.status === 'failed') {
        return [
          {
            rule: 'dns_failed_verification',
            type: 'domain.dns.failed',
            subKey: 'verification',
            severity: 'medium',
            alert: 'domain_dns_failed',
          },
        ];
      }
      return [];
    }
    case EventTypes.DomainDnsRecordsChanged: {
      const p = event.payload as DomainDnsRecordsChangedV1;
      const failing = failingRecords(p);
      if (failing.length === 0) return [];
      return [
        {
          rule: 'dns_failed_records',
          type: 'domain.dns.failed',
          subKey: 'records',
          severity: failing.some((r) => CRITICAL_PURPOSES.includes(r.purpose)) ? 'high' : 'medium',
          alert: 'domain_dns_failed',
        },
      ];
    }
    // Step 8.4 D16: metadata-only public events built from the payload (no direction, domain or
    // verdict: they pass those filters; `minSeverity` applies).
    case EventTypes.SecurityIncidentCreated: {
      const p = event.payload as SecurityIncidentCreatedV1;
      return [
        {
          rule: 'incident_created',
          type: 'security.incident.created',
          subKey: '',
          severity: incidentWebhookSeverity(p.severity),
          alert: null,
        },
      ];
    }
    case EventTypes.SecurityIncidentUpdated: {
      const p = event.payload as SecurityIncidentUpdatedV1;
      return [
        {
          rule: 'incident_updated',
          type: 'security.incident.updated',
          subKey: '',
          severity: incidentWebhookSeverity(p.severity),
          alert: null,
        },
      ];
    }
    case EventTypes.AtoAccountRiskUpdated: {
      const p = event.payload as AtoAccountRiskUpdatedV1;
      if (p.level === p.previousLevel) return [];
      return [
        {
          rule: 'ato_risk_changed',
          type: 'ato.account.risk_changed',
          subKey: '',
          severity: incidentWebhookSeverity(p.level),
          alert: null,
        },
      ];
    }
    case EventTypes.AtoResponseCompleted: {
      const p = event.payload as AtoResponseCompletedV1;
      return [
        {
          rule: 'ato_response_completed',
          type: 'ato.response.completed',
          subKey: p.phase,
          severity: p.status === 'failed' || p.status === 'rollback_failed' ? 'medium' : 'info',
          alert: null,
        },
      ];
    }
    default:
      return [];
  }
}
