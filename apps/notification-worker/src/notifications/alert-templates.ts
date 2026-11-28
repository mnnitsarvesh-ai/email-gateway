import {
  type AlertKind,
  INTEGRATION_PROVIDER_NAMES,
  integrationCheckTitle,
} from '@email-gateway/webhooks';
import { type RenderedNotice, safeText } from './templates';

/**
 * Fixed plain-text templates of the security alerts (step 6.2 N4, ADR-0056). An alert carries the
 * organization name, the kind, severity, throttle window, the counts (events in this window so
 * far, events suppressed before it) and per kind: threat → verdict, detection stage, the message
 * public id and received time of the first event and `PORTAL_PUBLIC_URL/messages/<id>`; DNS → the
 * tenant's own domain name, the failing record purposes and `/domains/<id>`; webhook disabled →
 * the subscription name (sanitized, ≤ 80), its failure counters and `/webhooks/<id>`;
 * integration unhealthy (step 8.2 D12) → the provider, the connection name (sanitized, ≤ 80), the
 * transition, the failing check titles and `/integrations/providers/<id>?tab=health`; journal
 * intake silent (step 8.6 D9) → the source display name (sanitized, ≤ 80) and kind, whether it
 * is silent (medium) or failing (high), its health now, the last accepted time and
 * `/settings/journaling/intake/<id>` (never the intake address or header token); API-mode
 * connection unhealthy (step API-1 D11.3) → the provider, the connection name (sanitized, ≤ 80),
 * whether it is degraded (medium) or failing (high), its health now, the titles of the checks
 * failing now (`api-mode-health/1` codes) and `/api-mode?connection=<id>` (never a mailbox
 * address); API-mode purge approval (step API-3 C6) → the clawback public id, trigger, status,
 * action, eligible mailbox and copy counts, approval reasons, approval state and expiry and
 * `/api-mode?tab=purge&clawback=<id>`; API-mode report received (step API-3 C13) → the counts of
 * reports waiting for triage, in review and received in the window, the oldest waiting time and
 * `/api-mode?tab=reports` (never a reporter address, subject or sender). Step API-4 (A7, A9.2,
 * B7, ADR-0106): a threat of an API-mode copy (`ingest_source <> 'gateway'`) is rendered as
 * detected after delivery (API mode) with the protection mode and
 * `/api-mode?tab=detections&message=<id>` instead of the message explorer (copies are `404`
 * there); DLP detected → the DLP action, direction, category codes, protection mode, mailbox
 * count and the same detections link (never a matched value); API-mode detect-only period ended
 * → the remediation policy's scope (organization or the tenant's domain name), whether it was a
 * reminder or the automatic switch to enforce, the policy mode now, the count of simulated
 * actions of the scope read at send time and `/api-mode?tab=remediation`.
 *
 * **Never** a subject, a body, a sender or recipient address, a URL found in mail, a file name,
 * an endpoint URL or a secret. Free text from the database (organization and subscription names)
 * is reduced to printable single-line text, and a name that looks like an address or a URL
 * (`@`, `scheme://`) is not shown at all (tenant text could carry an endpoint URL or a token).
 */

export type AlertSeverity = 'info' | 'low' | 'medium' | 'high';

interface AlertCommonFacts {
  organizationName: string;
  severity: AlertSeverity;
  window: { from: string; to: string };
  /** `notification_alert_windows.event_count` at send time (null: the row was purged). */
  eventsInWindow: number | null;
  /** Events of the previous window that were not alerted individually. */
  suppressedBefore: number;
  portalUrl: string;
}

/** Protection mode of an API-mode detection (step API-4 A8.2). */
export type DetectionProtectionMode = 'api' | 'hybrid';

export interface ThreatAlertFacts extends AlertCommonFacts {
  kind: 'threat_detected';
  threat: {
    verdict: string;
    stage: 'scan' | 'sandbox';
    messagePublicId: string;
    receivedAt: string;
    /**
     * Step API-4 A9.2: set when the message is an API-mode copy (`ingest_source <> 'gateway'`,
     * public type `mailbox.threat.detected`): detected after delivery; null for a gateway message.
     */
    copy: { protectionMode: DetectionProtectionMode; mailboxCount: number } | null;
  };
}

export interface DlpAlertFacts extends AlertCommonFacts {
  kind: 'dlp_detected';
  dlp: {
    /** `alert`, `require_approval`, `quarantine`, `block`. */
    action: string;
    direction: string;
    /** DLP category codes (≤ 8); never a matched value. */
    categories: string[];
    protectionMode: DetectionProtectionMode;
    mailboxCount: number;
    messagePublicId: string;
    receivedAt: string;
  };
}

export interface DetectOnlyEndedAlertFacts extends AlertCommonFacts {
  kind: 'api_mode_detect_only_ended';
  policy: {
    /** `api_remediation_policies.public_id`. */
    remediationPolicyPublicId: string;
    /** The organization policy (null) or the overridden domain's name. */
    domainName: string | null;
    /** What happened at the end of the period (B7). */
    then: 'remind' | 'enforce';
    /** `api_remediation_policies.mode` when the alert is sent. */
    modeNow: string;
    /** When the period ended (`detect_only_until`, else `detect_only_notified_at`). */
    endedAt: string | null;
    /** Simulated remediation actions of the policy's scope since `simulatedSince` (capped). */
    simulated: number;
    simulatedCapped: boolean;
    simulatedSince: string;
  };
}

export interface DnsAlertFacts extends AlertCommonFacts {
  kind: 'domain_dns_failed';
  dns: {
    domainPublicId: string;
    domainName: string;
    failureKind: 'verification_failed' | 'records_failed';
    /** Reason code of a verification failure (e.g. `verification_expired`). */
    reason: string | null;
    /** Purposes of the records that failed at detection (unique). */
    purposes: string[];
    /** Purposes still `invalid`/`missing` when the alert is sent. */
    stillFailing: string[];
  };
}

export interface WebhookDisabledAlertFacts extends AlertCommonFacts {
  kind: 'webhook_disabled';
  webhook: {
    subscriptionPublicId: string;
    name: string;
    status: string;
    consecutiveFailures: number;
    failingSince: string | null;
    disabledAt: string | null;
    disabledReason: string | null;
  };
}

export interface IntegrationAlertFacts extends AlertCommonFacts {
  kind: 'integration_unhealthy';
  integration: {
    connectionPublicId: string;
    name: string;
    provider: string;
    previousStatus: string;
    status: string;
    /** The connection's health when the alert is sent. */
    statusNow: string;
    /** Failing check codes of the transition (≤ 10). */
    failingChecks: string[];
    changedAt: string;
  };
}

export interface JournalIntakeAlertFacts extends AlertCommonFacts {
  kind: 'journal_intake_silent';
  intake: {
    sourcePublicId: string;
    name: string;
    /** `journal_intake_sources.kind`. */
    sourceKind: string;
    /** `journal_intake_sources.health_status` when the alert is sent. */
    healthNow: string;
    lastAcceptedAt: string | null;
    /** `silence_alert_minutes` (null: silence alerts off for the source). */
    silenceAlertMinutes: number | null;
  };
}

export interface ApiModeAlertFacts extends AlertCommonFacts {
  kind: 'api_mode_unhealthy';
  apiMode: {
    /** `api_mode_connections.public_id`. */
    connectionPublicId: string;
    /** The 8.2 provider connection's display name. */
    name: string;
    /** `api_mode_connections.provider` (`microsoft_365`, `google_workspace`). */
    provider: string;
    /** `api_mode_connections.health_status` when the alert is sent. */
    healthNow: string;
    /** `api-mode-health/1` codes of the checks that warn or fail now (stored order, ≤ 16). */
    failingChecks: string[];
  };
}

export interface PurgeApprovalAlertFacts extends AlertCommonFacts {
  kind: 'api_mode_purge_approval';
  clawback: {
    /** `api_clawbacks.public_id`. */
    clawbackPublicId: string;
    /** `api_clawbacks.trigger` (`late_verdict`, `threat_intel`, `campaign`, `report`, `admin`). */
    trigger: string;
    /** `api_clawbacks.status` when the alert is sent. */
    status: string;
    /** Explicit action of an admin purge, or null (policy mode). */
    action: string | null;
    mailboxesEligible: number;
    targetsEligible: number;
    /** `api_clawbacks.approval_status` when the alert is sent (null: none requested). */
    approvalStatus: string | null;
    /** `mailbox_threshold`, `hard_delete`, `auto_cap`. */
    approvalReasons: string[];
    approvalExpiresAt: string | null;
  };
}

export interface ReportReceivedAlertFacts extends AlertCommonFacts {
  kind: 'api_mode_report_received';
  reports: {
    pendingTriage: number;
    inReview: number;
    receivedInWindow: number;
    oldestPendingAt: string | null;
  };
}

export type AlertFacts =
  | ThreatAlertFacts
  | DnsAlertFacts
  | WebhookDisabledAlertFacts
  | IntegrationAlertFacts
  | JournalIntakeAlertFacts
  | ApiModeAlertFacts
  | PurgeApprovalAlertFacts
  | ReportReceivedAlertFacts
  | DlpAlertFacts
  | DetectOnlyEndedAlertFacts;

/**
 * Alert kinds this worker renders: the `@email-gateway/webhooks` kinds plus the step 8.6
 * `journal_intake_silent` (requested by the archive-worker's intake health loop), the step
 * API-1 `api_mode_unhealthy` (requested by the mailbox-worker's health role) and the step API-3
 * `api_mode_purge_approval` (api submit, mailbox-worker `clawback` role) and
 * `api_mode_report_received` (mailbox-worker `reports` role) and the step API-4
 * `api_mode_detect_only_ended` (mailbox-worker health leader, B7); the event contract carries
 * them, the shared webhooks vocabulary does not (`dlp_detected` is an `AlertKind` since API-4).
 */
export type SecurityAlertKind =
  | AlertKind
  | 'journal_intake_silent'
  | 'api_mode_unhealthy'
  | 'api_mode_purge_approval'
  | 'api_mode_report_received'
  | 'api_mode_detect_only_ended';

/**
 * Titles of the `api-mode-health/1` check codes (step API-1 D11.3; the codes of
 * `@email-gateway/mailbox-api` `API_MODE_HEALTH_CHECK_CODES`). An unknown code is shown as is
 * (when it is a dotted code) so a newer producer never makes an alert unreadable.
 */
export const API_MODE_CHECK_TITLES: Readonly<Record<string, string>> = Object.freeze({
  'connection.active': 'Provider connection active and bound',
  'intake.present': 'Journal copy or mailbox feeds present',
  'intake.journal_health': 'Journal intake source healthy',
  'mailbox_access.grant': 'Mailbox access grant active',
  'coverage.percent': 'Mailbox coverage',
  'lag.p95_1h': 'Detection lag (p95, last hour)',
  'throttling.1h': 'Provider throttling (last hour)',
  'feeds.errors': 'Mailbox feed errors',
  'domains.api_mode_mx': 'API-mode domains without gateway MX',
  // Step API-3 (C13).
  'clawback.stalled': 'Clawback without progress',
  'reports.backlog': 'User reports waiting for triage',
});

const KIND_TITLE: Readonly<Record<SecurityAlertKind, string>> = {
  threat_detected: 'Threat detected',
  domain_dns_failed: 'Domain DNS check failed',
  webhook_disabled: 'Webhook endpoint disabled',
  integration_unhealthy: 'Microsoft 365 / Google Workspace connection unhealthy',
  journal_intake_silent: 'Journal intake source silent or failing',
  api_mode_unhealthy: 'API-mode protection connection degraded or failing',
  api_mode_purge_approval: 'API-mode clawback needs a second approver',
  api_mode_report_received: 'API-mode user reports waiting for triage',
  dlp_detected: 'Sensitive data detected (DLP, API mode)',
  api_mode_detect_only_ended: 'API-mode detect-only period ended',
};

const KIND_SUBJECT: Readonly<Record<SecurityAlertKind, string>> = {
  threat_detected: 'threat detected',
  domain_dns_failed: 'domain DNS check failed',
  webhook_disabled: 'webhook endpoint disabled',
  integration_unhealthy: 'mail platform connection unhealthy',
  journal_intake_silent: 'journal intake source needs attention',
  api_mode_unhealthy: 'API-mode protection needs attention',
  api_mode_purge_approval: 'clawback approval requested',
  api_mode_report_received: 'reported messages need triage',
  dlp_detected: 'sensitive data detected',
  api_mode_detect_only_ended: 'detect-only period ended',
};

/** Display text of the protection modes of API-mode detections (step API-4 A8.2). */
const PROTECTION_MODE_TEXT: Readonly<Record<DetectionProtectionMode, string>> = {
  api: 'API mode (after delivery, through the mailbox API)',
  hybrid: 'Hybrid (gateway and API mode)',
};

/** Display text of the DLP actions of a detection (step API-4 A9.1). */
const DLP_ACTION_TEXT: Readonly<Record<string, string>> = {
  alert: 'alert only',
  require_approval: 'require approval',
  quarantine: 'quarantine',
  block: 'block',
};

const DIRECTION_TEXT: Readonly<Record<string, string>> = {
  inbound: 'inbound',
  outbound: 'outbound',
  internal: 'internal',
};

/** `/api-mode?tab=detections&message=<id>` (copies are 404 in the message explorer, N1). */
const detectionsLink = (portalUrl: string, messagePublicId: string): string =>
  `${portalUrl}/api-mode?tab=detections&message=${messagePublicId}`;

/** Display text of the clawback triggers (step API-3 C2). */
const CLAWBACK_TRIGGER_NAMES: Readonly<Record<string, string>> = {
  late_verdict: 'late verdict (sandbox or URL inspection)',
  threat_intel: 'threat intelligence',
  campaign: 'campaign',
  report: 'user report',
  admin: 'administrator search',
};

/** Display text of the approval reasons (step API-3 C6). */
const APPROVAL_REASON_TEXT: Readonly<Record<string, string>> = {
  mailbox_threshold: 'more mailboxes than the approval threshold',
  hard_delete: 'permanent deletion requested',
  auto_cap: 'automatic clawback above the mailbox cap',
};

/** Display names of the journal intake source kinds (step 8.6 D1). */
export const INTAKE_SOURCE_KIND_NAMES: Readonly<Record<string, string>> = {
  microsoft_365_journal: 'Microsoft 365 journaling',
  google_workspace_copy: 'Google Workspace copy',
  exchange_onprem_journal: 'On-premises Exchange journaling',
  smtp_bcc: 'SMTP BCC copy',
};

const CODE = /^[a-z][a-z0-9_]{0,63}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A lower-case snake code, or `unknown`. */
const code = (value: string | null | undefined): string =>
  value !== null && value !== undefined && CODE.test(value) ? value : 'unknown';

/** A public id (UUID), or an empty string. */
const publicId = (value: string): string => (UUID.test(value) ? value : '');

/** An ISO instant, or `unknown`. */
const instant = (value: string | null | undefined): string => {
  if (value === null || value === undefined) return 'unknown';
  const time = Date.parse(value);
  return Number.isNaN(time) ? 'unknown' : new Date(time).toISOString();
};

/**
 * Tenant text shown in an alert: printable, single-line, ≤ `max`; empty when it looks like an
 * address or a URL (it would put a mailbox, an endpoint or a token into a mail).
 */
export function displayName(value: string | null | undefined, max: number): string {
  const text = safeText(value, max);
  return /@|:\/\//.test(text) ? '' : text;
}

/** A tenant domain name: lower-case ASCII hostname characters only, ≤ 253. */
const domainName = (value: string): string => {
  const name = value.trim().toLowerCase().replace(/\.$/, '');
  return /^[a-z0-9.-]{1,253}$/.test(name) ? name : '';
};

/** A dotted lower-case check code, or `unknown`. */
const CHECK_CODE = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/;
const checkLine = (value: string): string =>
  CHECK_CODE.test(value) && value.length <= 64
    ? `- ${integrationCheckTitle(value)} (${value})`
    : '- unknown';

const apiModeCheckLine = (value: string): string =>
  CHECK_CODE.test(value) && value.length <= 64
    ? `- ${API_MODE_CHECK_TITLES[value] ?? value} (${value})`
    : '- unknown';

/** Display names of the API-mode providers (step API-1). */
const API_MODE_PROVIDER_NAMES: Readonly<Record<string, string>> = {
  microsoft_365: 'Microsoft 365',
  google_workspace: 'Google Workspace',
};

const list = (values: readonly string[]): string =>
  values.length === 0 ? 'none' : [...new Set(values.map(code))].join(', ');

function header(facts: AlertFacts): string[] {
  const organization = displayName(facts.organizationName, 128) || 'your organization';
  return [
    `A security alert was raised for ${organization}.`,
    '',
    `Alert: ${KIND_TITLE[facts.kind]}`,
    `Severity: ${facts.severity}`,
    `Window: ${instant(facts.window.from)} to ${instant(facts.window.to)} (UTC)`,
    `Events in this window so far: ${
      facts.eventsInWindow === null ? 'unknown' : String(facts.eventsInWindow)
    }`,
    `Suppressed before this alert: ${String(facts.suppressedBefore)} (events of the previous window that were not alerted individually)`,
    '',
  ];
}

function body(facts: AlertFacts): string[] {
  switch (facts.kind) {
    case 'threat_detected': {
      const t = facts.threat;
      const id = publicId(t.messagePublicId);
      if (t.copy !== null) {
        // Step API-4 A9.2: a copy of a delivered message (API mode): never the explorer link.
        return [
          `Verdict: ${code(t.verdict)}`,
          `Detection stage: after delivery (API mode)${t.stage === 'sandbox' ? ', sandbox' : ''}`,
          `Protection mode: ${PROTECTION_MODE_TEXT[t.copy.protectionMode] ?? 'unknown'}`,
          `Mailboxes with a copy: ${String(t.copy.mailboxCount)}`,
          `First message of the window: ${id || 'unknown'}`,
          `Received: ${instant(t.receivedAt)}`,
          '',
          'The message was already delivered; remediation follows the API-mode remediation policy.',
          ...(id ? [`Details: ${detectionsLink(facts.portalUrl, id)}`] : []),
        ];
      }
      return [
        `Verdict: ${code(t.verdict)}`,
        `Detection stage: ${t.stage === 'sandbox' ? 'sandbox (after delivery)' : 'scan'}`,
        `First message of the window: ${id || 'unknown'}`,
        `Received: ${instant(t.receivedAt)}`,
        '',
        ...(id ? [`Details: ${facts.portalUrl}/messages/${id}`] : []),
      ];
    }
    case 'dlp_detected': {
      const d = facts.dlp;
      const id = publicId(d.messagePublicId);
      const outbound = d.direction === 'outbound';
      return [
        `DLP action: ${DLP_ACTION_TEXT[d.action] ?? 'unknown'}`,
        `Direction: ${DIRECTION_TEXT[d.direction] ?? 'unknown'}`,
        `DLP categories: ${list(d.categories.slice(0, 8))}`,
        `Protection mode: ${PROTECTION_MODE_TEXT[d.protectionMode] ?? 'unknown'}`,
        `Mailboxes with a copy: ${String(d.mailboxCount)}`,
        `First message of the window: ${id || 'unknown'}`,
        `Received: ${instant(d.receivedAt)}`,
        '',
        outbound
          ? 'The message was already sent: outbound detections are recorded, never removed from a mailbox.'
          : 'The message was already delivered; remediation follows the API-mode remediation policy.',
        ...(id ? [`Details: ${detectionsLink(facts.portalUrl, id)}`] : []),
      ];
    }
    case 'api_mode_detect_only_ended': {
      const p = facts.policy;
      const scope =
        p.domainName === null
          ? 'organization policy'
          : `domain ${domainName(p.domainName) || '(name not shown)'}`;
      return [
        `Remediation policy: ${scope} (${publicId(p.remediationPolicyPublicId) || 'unknown'})`,
        `Detect-only period ended: ${instant(p.endedAt)}`,
        p.then === 'enforce'
          ? 'What happened: the policy was switched to enforce automatically; detections are now remediated in mailboxes.'
          : 'What happened: reminder only. The policy is still detect-only: detections are recorded but nothing is removed from mailboxes.',
        `Policy mode now: ${code(p.modeNow)}`,
        `Actions that would have been taken (simulated) since ${instant(p.simulatedSince)}: ${
          p.simulatedCapped ? `${String(p.simulated)} or more` : String(p.simulated)
        }`,
        '',
        p.then === 'enforce'
          ? 'Review the simulated actions and the remediation policy.'
          : 'Review the simulated actions, then switch the policy to enforce or extend the period.',
        `Review: ${facts.portalUrl}/api-mode?tab=remediation`,
      ];
    }
    case 'domain_dns_failed': {
      const id = publicId(facts.dns.domainPublicId);
      return [
        `Domain: ${domainName(facts.dns.domainName) || 'unknown'}`,
        `Failure: ${facts.dns.failureKind === 'verification_failed' ? 'verification failed' : 'DNS records failed'}`,
        ...(facts.dns.reason ? [`Reason: ${code(facts.dns.reason)}`] : []),
        `Failed records: ${list(facts.dns.purposes)}`,
        `Still failing now: ${list(facts.dns.stillFailing)}`,
        '',
        ...(id ? [`Details: ${facts.portalUrl}/domains/${id}`] : []),
      ];
    }
    case 'webhook_disabled': {
      const w = facts.webhook;
      const id = publicId(w.subscriptionPublicId);
      return [
        `Subscription: ${displayName(w.name, 80) || '(name not shown)'} (${id || 'unknown'})`,
        `Status now: ${code(w.status)}`,
        ...(w.disabledReason ? [`Disabled because: ${code(w.disabledReason)}`] : []),
        ...(w.disabledAt ? [`Disabled at: ${instant(w.disabledAt)}`] : []),
        `Consecutive failed deliveries: ${String(w.consecutiveFailures)}`,
        `Failing since: ${instant(w.failingSince)}`,
        '',
        'Deliveries to this endpoint are paused until an administrator re-enables it.',
        ...(id ? [`Details: ${facts.portalUrl}/webhooks/${id}`] : []),
      ];
    }
    case 'integration_unhealthy': {
      const c = facts.integration;
      const id = publicId(c.connectionPublicId);
      const checks = [...new Set(c.failingChecks)].slice(0, 10);
      return [
        `Provider: ${INTEGRATION_PROVIDER_NAMES[c.provider] ?? 'unknown'}`,
        `Connection: ${displayName(c.name, 80) || '(name not shown)'} (${id || 'unknown'})`,
        `Health: ${code(c.previousStatus)} -> ${code(c.status)} at ${instant(c.changedAt)}`,
        `Health now: ${code(c.statusNow)}`,
        'Failing checks:',
        ...(checks.length === 0 ? ['- none reported'] : checks.map(checkLine)),
        '',
        'Mail flow is not changed automatically: review the checks and the setup guide.',
        ...(id ? [`Details: ${facts.portalUrl}/integrations/providers/${id}?tab=health`] : []),
      ];
    }
    case 'journal_intake_silent': {
      const i = facts.intake;
      const id = publicId(i.sourcePublicId);
      const failing = facts.severity === 'high';
      return [
        `Journal intake source: ${displayName(i.name, 80) || '(name not shown)'} (${id || 'unknown'})`,
        `Source kind: ${INTAKE_SOURCE_KIND_NAMES[i.sourceKind] ?? 'unknown'}`,
        failing
          ? 'Problem: failing. Journal mail from this source is being refused or dropped, or its provider connection is unusable; journal copies may be lost.'
          : `Problem: silent. No journal message has been accepted from this source for longer than its silence threshold${
              i.silenceAlertMinutes === null ? '' : ` (${String(i.silenceAlertMinutes)} minutes)`
            }.`,
        `Health now: ${code(i.healthNow)}`,
        `Last accepted message: ${instant(i.lastAcceptedAt)}`,
        '',
        'Check the journal rule or routing at the provider and the source health and setup guide.',
        ...(id ? [`Details: ${facts.portalUrl}/settings/journaling/intake/${id}`] : []),
      ];
    }
    case 'api_mode_unhealthy': {
      const a = facts.apiMode;
      const id = publicId(a.connectionPublicId);
      const failing = facts.severity === 'high';
      const checks = [...new Set(a.failingChecks)].slice(0, 16);
      return [
        `Provider: ${API_MODE_PROVIDER_NAMES[a.provider] ?? 'unknown'}`,
        `Connection: ${displayName(a.name, 80) || '(name not shown)'} (${id || 'unknown'})`,
        failing
          ? 'Problem: failing. Detection copies may not reach the gateway or mailbox access was lost; some mail may not be scanned.'
          : 'Problem: degraded. Coverage, detection lag, throttling or feeds need attention.',
        `Health now: ${code(a.healthNow)}`,
        'Checks needing attention:',
        ...(checks.length === 0 ? ['- none reported'] : checks.map(apiModeCheckLine)),
        '',
        'Mail flow is never changed by API mode: review the checks, the journal rule and the mailbox access grant.',
        ...(id ? [`Details: ${facts.portalUrl}/api-mode?connection=${id}`] : []),
      ];
    }
    case 'api_mode_purge_approval': {
      const c = facts.clawback;
      const id = publicId(c.clawbackPublicId);
      const reasons = [...new Set(c.approvalReasons)].filter((r) => r in APPROVAL_REASON_TEXT);
      return [
        `Clawback: ${id || 'unknown'}`,
        `Trigger: ${CLAWBACK_TRIGGER_NAMES[c.trigger] ?? 'unknown'}`,
        `Status now: ${code(c.status)}`,
        ...(c.action !== null ? [`Requested action: ${code(c.action)}`] : []),
        `Eligible mailboxes: ${String(c.mailboxesEligible)} (${String(c.targetsEligible)} message copies)`,
        `Approval needed because: ${
          reasons.length === 0
            ? 'review required'
            : reasons.map((r) => APPROVAL_REASON_TEXT[r]).join('; ')
        }`,
        `Approval status: ${c.approvalStatus === null ? 'not requested' : code(c.approvalStatus)}`,
        `Approval expires: ${instant(c.approvalExpiresAt)}`,
        '',
        'A second administrator holding the purge permission must approve or deny it; the requester cannot approve their own request.',
        ...(id ? [`Review: ${facts.portalUrl}/api-mode?tab=purge&clawback=${id}`] : []),
      ];
    }
    case 'api_mode_report_received': {
      const r = facts.reports;
      return [
        `Reports waiting for triage: ${String(r.pendingTriage)}`,
        `Reports in review: ${String(r.inReview)}`,
        `Reports received in this window: ${String(r.receivedInWindow)}`,
        `Oldest report waiting since: ${r.oldestPendingAt === null ? 'none waiting' : instant(r.oldestPendingAt)}`,
        '',
        'Users reported messages as suspicious. Triage them to give the reporters feedback and to remove dangerous messages.',
        `Review: ${facts.portalUrl}/api-mode?tab=reports`,
      ];
    }
  }
}

/** One security alert (N4): fixed subject per kind and severity, fixed body. */
export function renderSecurityAlert(facts: AlertFacts): RenderedNotice {
  return {
    subject: `[Email Gateway] Security alert (${facts.severity}): ${KIND_SUBJECT[facts.kind]}`,
    text: [
      ...header(facts),
      ...body(facts),
      '',
      'Alert settings and personal preferences are managed in the admin portal.',
      'This is an automated security alert from the email gateway. It contains no message content.',
    ].join('\n'),
  };
}

/** `<security-alert.<eventId>@<domain of the From address>>` (N4: one per alert event). */
export function securityAlertMessageId(eventId: string, from: string): string {
  const address = /<([^>]+)>/.exec(from)?.[1] ?? from;
  const domain =
    address
      .slice(address.lastIndexOf('@') + 1)
      .trim()
      .toLowerCase() || 'localhost';
  return `<security-alert.${eventId}@${domain}>`;
}
