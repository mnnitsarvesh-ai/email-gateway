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
 * `/settings/journaling/intake/<id>` (never the intake address or header token).
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

export interface ThreatAlertFacts extends AlertCommonFacts {
  kind: 'threat_detected';
  threat: {
    verdict: string;
    stage: 'scan' | 'sandbox';
    messagePublicId: string;
    receivedAt: string;
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

export type AlertFacts =
  | ThreatAlertFacts
  | DnsAlertFacts
  | WebhookDisabledAlertFacts
  | IntegrationAlertFacts
  | JournalIntakeAlertFacts;

/**
 * Alert kinds this worker renders: the `@email-gateway/webhooks` kinds plus the step 8.6
 * `journal_intake_silent` (requested by the archive-worker's intake health loop; the event
 * contract carries it, the shared webhooks vocabulary does not yet).
 */
export type SecurityAlertKind = AlertKind | 'journal_intake_silent';

const KIND_TITLE: Readonly<Record<SecurityAlertKind, string>> = {
  threat_detected: 'Threat detected',
  domain_dns_failed: 'Domain DNS check failed',
  webhook_disabled: 'Webhook endpoint disabled',
  integration_unhealthy: 'Microsoft 365 / Google Workspace connection unhealthy',
  journal_intake_silent: 'Journal intake source silent or failing',
};

const KIND_SUBJECT: Readonly<Record<SecurityAlertKind, string>> = {
  threat_detected: 'threat detected',
  domain_dns_failed: 'domain DNS check failed',
  webhook_disabled: 'webhook endpoint disabled',
  integration_unhealthy: 'mail platform connection unhealthy',
  journal_intake_silent: 'journal intake source needs attention',
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
      const id = publicId(facts.threat.messagePublicId);
      return [
        `Verdict: ${code(facts.threat.verdict)}`,
        `Detection stage: ${facts.threat.stage === 'sandbox' ? 'sandbox (after delivery)' : 'scan'}`,
        `First message of the window: ${id || 'unknown'}`,
        `Received: ${instant(facts.threat.receivedAt)}`,
        '',
        ...(id ? [`Details: ${facts.portalUrl}/messages/${id}`] : []),
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
