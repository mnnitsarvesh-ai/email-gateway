import type { AtoDigestCounts, AtoNoticeIntegration, AtoSeverity } from './ato-reads';
import { displayName } from './alert-templates';
import { type RenderedNotice, safeText } from './templates';

/**
 * Fixed plain-text templates of the account takeover notices (step 8.4 D16; ADR-0062 masking).
 *
 * - `incident_alert` (tenant and SOC audiences): organization name, severity, status, the
 *   account (a mailbox **masked** `j***@example.com`, a connector name or a user display name),
 *   the top reason titles (from the rule codes), the incident public id, counts and the portal
 *   link `/incidents/<id>`.
 * - `incident_alert` to the **platform SOC**: organization slug, incident public id, severity and
 *   the portal link only (no account, no reasons).
 * - `approval_requested`: the action type and impact, the masked account, the approval expiry and
 *   `/ato/responses?status=pending_approval`.
 * - `response_failed`: the action type, status and result code, the masked account, the link.
 * - `digest`: the period and its counts (incidents opened by severity, resolved by resolution,
 *   false positives, active critical incidents, pending approvals, active restrictions, top rule
 *   codes) and `/ato`.
 * - `provider_unhealthy` (step 8.5 D11): the provider, the integration's display name, the failing
 *   stream names and the missing permission names of the last probe, and
 *   `/ato/providers/<integration id>`; never the provider tenant id, an address or a token.
 *
 * **Never** an IP address, a password or token, a mail subject, a recipient address or a URL
 * found in mail. Free text from the database is reduced to printable single-line text and a name
 * that looks like an address or a URL is not shown (`displayName`).
 */

export type AtoNoticeKind =
  'incident_alert' | 'approval_requested' | 'response_failed' | 'digest' | 'provider_unhealthy';
export type AtoAudience = 'tenant' | 'soc' | 'platform_soc';

export interface AtoAccountView {
  kind: 'mailbox' | 'gateway_user' | 'smtp_connector';
  address: string | null;
  name: string | null;
}

interface CommonFacts {
  organizationName: string;
  organizationSlug: string;
  audience: AtoAudience;
  portalUrl: string;
  window: { from: string; to: string };
  eventsInWindow: number | null;
  suppressedBefore: number;
}

export interface IncidentAlertFacts extends CommonFacts {
  kind: 'incident_alert';
  incident: {
    publicId: string;
    severity: AtoSeverity;
    status: string;
    detectedAt: string;
    titleCode: string | null;
    reasonCodes: string[];
  };
  account: AtoAccountView | null;
}

export interface ApprovalRequestedFacts extends CommonFacts {
  kind: 'approval_requested';
  action: {
    publicId: string;
    actionType: string;
    impact: string;
    status: string;
    approvalExpiresAt: string | null;
  };
  account: AtoAccountView | null;
  incidentPublicId: string | null;
}

export interface ResponseFailedFacts extends CommonFacts {
  kind: 'response_failed';
  action: {
    publicId: string;
    actionType: string;
    status: string;
    provider: string;
    resultCode: string | null;
  };
  account: AtoAccountView | null;
  incidentPublicId: string | null;
}

export interface DigestFacts extends CommonFacts {
  kind: 'digest';
  period: 'daily' | 'weekly';
  counts: AtoDigestCounts;
}

export interface ProviderUnhealthyFacts extends CommonFacts {
  kind: 'provider_unhealthy';
  integration: AtoNoticeIntegration;
}

export type AtoNoticeFacts =
  | IncidentAlertFacts
  | ApprovalRequestedFacts
  | ResponseFailedFacts
  | DigestFacts
  | ProviderUnhealthyFacts;

/** Plain-language provider names (no logo, no tenant data). */
const PROVIDER_LABEL: Readonly<Record<string, string>> = {
  microsoft_entra: 'Microsoft Entra ID / Microsoft 365',
  google_workspace: 'Google Workspace',
};
const PERMISSION = /^[A-Za-z0-9._:/-]{1,128}$/;

const CODE = /^[a-z][a-z0-9_]{0,63}$/;
const DOTTED = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,4}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;

const code = (value: string | null | undefined): string =>
  value !== null && value !== undefined && CODE.test(value) ? value : 'unknown';
const publicId = (value: string | null | undefined): string =>
  value !== null && value !== undefined && UUID.test(value) ? value : '';
const instant = (value: string | null | undefined): string => {
  if (value === null || value === undefined) return 'unknown';
  const time = Date.parse(value);
  return Number.isNaN(time) ? 'unknown' : new Date(time).toISOString();
};
const words = (value: string): string => value.replace(/_/g, ' ');

/**
 * ADR-0062 `maskAddress`: the first code point of the local part and the domain, split at the last
 * `@` (`j***@example.com`). Anything that is not an address becomes `***`.
 */
export function maskAddress(address: string): string {
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1) return '***';
  const first = [...address.slice(0, at)][0] ?? '';
  const domain = address
    .slice(at + 1)
    .trim()
    .toLowerCase();
  return /^[a-z0-9.-]{1,253}$/.test(domain) ? `${first}***@${domain}` : '***';
}

/**
 * A human title of a rule code (`ato.geo.impossible_travel` → `Geo: impossible travel`). The
 * worker does not load the rule catalogue; the title is derived from the stable code.
 */
export function reasonTitle(value: string): string {
  if (!DOTTED.test(value)) return 'unknown reason';
  const parts = value.split('.');
  const rest = parts[0] === 'ato' ? parts.slice(1) : parts;
  const [group, ...name] = rest;
  const head = (group ?? '').replace(/_/g, ' ');
  const label = name.join(' ').replace(/_/g, ' ');
  const capitalized = head.charAt(0).toUpperCase() + head.slice(1);
  return label ? `${capitalized}: ${label}` : capitalized;
}

/** The account as shown in a notice: masked mailbox, connector name or user display name. */
export function accountLabel(account: AtoAccountView | null): string {
  if (account === null) return 'unknown account';
  switch (account.kind) {
    case 'mailbox':
      return account.address ? `mailbox ${maskAddress(account.address)}` : 'mailbox (not shown)';
    case 'smtp_connector':
      return `SMTP connector ${displayName(account.name, 80) || '(name not shown)'}`;
    case 'gateway_user':
      return `portal user ${displayName(account.name, 80) || '(name not shown)'}`;
  }
}

const SUBJECT: Readonly<Record<AtoNoticeKind, string>> = {
  incident_alert: 'account takeover incident',
  approval_requested: 'account takeover response awaits approval',
  response_failed: 'account takeover response failed',
  digest: 'account takeover digest',
  provider_unhealthy: 'account takeover identity provider unhealthy',
};

function header(facts: AtoNoticeFacts): string[] {
  const organization = displayName(facts.organizationName, 128) || 'your organization';
  return [
    `Account takeover notice for ${organization}.`,
    '',
    `Window: ${instant(facts.window.from)} to ${instant(facts.window.to)} (UTC)`,
    `Events in this window so far: ${
      facts.eventsInWindow === null ? 'unknown' : String(facts.eventsInWindow)
    }`,
    `Suppressed before this notice: ${String(facts.suppressedBefore)}`,
    '',
  ];
}

function incidentBody(f: IncidentAlertFacts): string[] {
  const id = publicId(f.incident.publicId);
  const reasons = [...new Set(f.incident.reasonCodes)].slice(0, 5).map(reasonTitle);
  return [
    `Incident: ${id || 'unknown'}`,
    `Severity: ${f.incident.severity}`,
    `Status: ${words(code(f.incident.status))}`,
    `Detected: ${instant(f.incident.detectedAt)}`,
    `Account: ${accountLabel(f.account)}`,
    ...(f.incident.titleCode ? [`Main reason: ${reasonTitle(f.incident.titleCode)}`] : []),
    `Top reasons: ${reasons.length === 0 ? 'none recorded (manual incident)' : reasons.join('; ')}`,
    '',
    ...(id ? [`Investigate: ${f.portalUrl}/incidents/${id}`] : []),
  ];
}

function digestBody(f: DigestFacts): string[] {
  const c = f.counts;
  const resolved = Object.entries(c.resolvedByResolution)
    .filter(([, n]) => n > 0)
    .map(([k, n]) => `${words(code(k))} ${String(n)}`);
  return [
    `Period: ${f.period === 'weekly' ? 'weekly' : 'daily'} digest`,
    `Incidents opened: critical ${String(c.openedBySeverity.critical)}, high ${String(
      c.openedBySeverity.high,
    )}, medium ${String(c.openedBySeverity.medium)}, low ${String(c.openedBySeverity.low)}`,
    `Incidents resolved: ${resolved.length === 0 ? 'none' : resolved.join(', ')}`,
    `False positives: ${String(c.falsePositives)}`,
    `Active critical incidents: ${String(c.activeCritical)}`,
    `Responses awaiting approval: ${String(c.pendingApprovals)}`,
    `Active SMTP restrictions: ${String(c.restrictedAccounts)}`,
    `Most frequent signals: ${
      c.topRuleCodes.length === 0
        ? 'none'
        : c.topRuleCodes
            .slice(0, 5)
            .map((r) => `${reasonTitle(r.code)} (${String(r.count)})`)
            .join('; ')
    }`,
    '',
    `Overview: ${f.portalUrl}/ato`,
  ];
}

function providerBody(f: ProviderUnhealthyFacts): string[] {
  const i = f.integration;
  const id = publicId(i.publicId);
  const name = displayName(i.displayName, 128);
  const streams = i.failingStreams
    .filter((s) => CODE.test(s))
    .slice(0, 7)
    .map(words);
  const permissions = i.missingPermissions.filter((p) => PERMISSION.test(p)).slice(0, 10);
  return [
    `Identity provider: ${PROVIDER_LABEL[i.provider] ?? 'unknown provider'}`,
    `Integration: ${name || '(name not shown)'}`,
    `Health: ${words(code(i.healthStatus))}`,
    `Failing streams: ${streams.length === 0 ? 'none reported' : streams.join(', ')}`,
    `Missing permissions: ${permissions.length === 0 ? 'none reported' : permissions.join(', ')}`,
    '',
    'Account takeover detection from this identity provider is degraded or stopped, and provider response actions may be unavailable. Mail flow is not affected.',
    ...(id ? [`Review: ${f.portalUrl}/ato/providers/${id}`] : []),
  ];
}

function body(facts: AtoNoticeFacts): string[] {
  switch (facts.kind) {
    case 'provider_unhealthy':
      return providerBody(facts);
    case 'incident_alert':
      return incidentBody(facts);
    case 'approval_requested': {
      const a = facts.action;
      return [
        `Response: ${words(code(a.actionType))} (${publicId(a.publicId) || 'unknown'})`,
        `Impact: ${code(a.impact)}`,
        `Status: ${words(code(a.status))}`,
        `Account: ${accountLabel(facts.account)}`,
        ...(publicId(facts.incidentPublicId)
          ? [`Incident: ${publicId(facts.incidentPublicId)}`]
          : []),
        `Approval expires: ${instant(a.approvalExpiresAt)}`,
        '',
        'Approving needs the ato:respond permission, an MFA session and a person other than the requester.',
        `Review: ${facts.portalUrl}/ato/responses?status=pending_approval`,
      ];
    }
    case 'response_failed': {
      const a = facts.action;
      const incident = publicId(facts.incidentPublicId);
      return [
        `Response: ${words(code(a.actionType))} (${publicId(a.publicId) || 'unknown'})`,
        `Status: ${words(code(a.status))}`,
        `Provider: ${code(a.provider)}`,
        ...(a.resultCode ? [`Result: ${code(a.resultCode)}`] : []),
        `Account: ${accountLabel(facts.account)}`,
        ...(incident ? [`Incident: ${incident}`] : []),
        '',
        incident
          ? `Investigate: ${facts.portalUrl}/incidents/${incident}`
          : `Review: ${facts.portalUrl}/ato/responses`,
      ];
    }
    case 'digest':
      return digestBody(facts);
  }
}

/** The platform SOC notice: organization slug, incident public id, severity, link (D16). */
function platformSocNotice(f: IncidentAlertFacts): RenderedNotice {
  const id = publicId(f.incident.publicId);
  const slug = SLUG.test(f.organizationSlug) ? f.organizationSlug : 'unknown';
  return {
    subject: `[Email Gateway] Platform SOC: critical account takeover incident (${slug})`,
    text: [
      'A critical account takeover incident was opened or escalated.',
      '',
      `Organization: ${slug}`,
      `Incident: ${id || 'unknown'}`,
      `Severity: ${f.incident.severity}`,
      '',
      ...(id ? [`Details: ${f.portalUrl}/incidents/${id}`] : []),
      '',
      'This is an automated platform notice. It contains no account, address or message data.',
    ].join('\n'),
  };
}

/** One ATO notice: fixed subject per kind (and severity), fixed body. */
export function renderAtoNotice(facts: AtoNoticeFacts): RenderedNotice {
  if (facts.kind === 'incident_alert' && facts.audience === 'platform_soc') {
    return platformSocNotice(facts);
  }
  const severity = facts.kind === 'incident_alert' ? ` (${facts.incident.severity})` : '';
  return {
    subject: `[Email Gateway] ${SUBJECT[facts.kind].charAt(0).toUpperCase()}${SUBJECT[
      facts.kind
    ].slice(1)}${severity}`,
    text: [
      ...header(facts),
      ...body(facts),
      '',
      'Notification preferences are managed in the admin portal.',
      'This is an automated security notice from the email gateway. It contains no message content, IP address or credential.',
    ]
      .map((line) => safeText(line, 400) || line.trim())
      .join('\n'),
  };
}

/** `<ato-notice.<eventId>.<audience>@<domain of the From address>>` (one per event and audience). */
export function atoNoticeMessageId(eventId: string, audience: AtoAudience, from: string): string {
  const address = /<([^>]+)>/.exec(from)?.[1] ?? from;
  const domain =
    address
      .slice(address.lastIndexOf('@') + 1)
      .trim()
      .toLowerCase() || 'localhost';
  return `<ato-notice.${eventId}.${audience.replace(/_/g, '-')}@${domain}>`;
}
