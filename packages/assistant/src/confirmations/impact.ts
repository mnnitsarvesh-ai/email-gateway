import { fillRoute, routePage } from '../results/card';
import { sanitizeText } from '../results/sanitize';
import { findOperation } from '../registry/registry';
import { fmtBytes } from '../reports/escape';
import { normalizeRecipient, recipientKindText, type RecipientKind } from '../reports/recipients';
import type { OperationTool } from '../registry/types';
import { valueAtPath } from './digest';
import {
  AI5_ESCALATION_WARNINGS,
  snapshotList,
  type ConfirmationSnapshot,
  type EachSnapshotItem,
  type SnapshotValue,
} from './specs';
import {
  CONFIRMATION_SUMMARY_VERSION,
  type ConfirmationChange,
  type ConfirmationDefinitionSummary,
  type ConfirmationRuleSummary,
  type ConfirmationSummary,
  type ConfirmationTarget,
} from './types';

/**
 * Impact templates (step AI-2 D5): one server-authored `assistant-confirmation/1` summary per
 * write operation, built from the final (validated, CAS-injected) arguments, the precondition
 * snapshot and the definition validation. Nothing here is model text: titles, sentences, impact
 * lines and warnings are fixed English; argument and record values are inserted as data,
 * sanitized and capped, and values that come from mail are marked `untrusted`. Policy
 * definitions are summarised rule by rule without depending on `@email-gateway/policy-dsl`.
 *
 * Step AI-5 (design 33 D9) adds the compliance and integrations templates: retention changes in
 * words, settings before → after, custodian counts (never addresses), never an intake address
 * or an impact token, the mail-flow preview's change set and warning codes.
 *
 * Step AI-4 (design 32 D6) adds the security-operations templates: weakening changes say what
 * stops being detected, ATO response approvals name the action and the requester, DLP pattern
 * text appears only under changes, platform operations name "every organization".
 *
 * Step AI-3 (design 30 D7) adds the identity and tenant administration templates: role changes
 * list the added and removed role keys or permissions (never the full catalogue), destinations
 * show the old and new servers, user display names, session user agents and API key creators are
 * marked untrusted, and the escalation warnings of the effective risk (D4) are appended to the
 * warnings (`ImpactInput.escalationWarnings`).
 */

export const SUMMARY_LIMITS = {
  targets: 20,
  changes: 40,
  rules: 50,
  impact: 10,
  warnings: 5,
  /** Serialized summary (UTF-8 bytes). */
  bytes: 16 * 1024,
  /** A rule's `when` text. */
  whenChars: 300,
  /** Any other string. */
  textChars: 300,
} as const;

export interface DefinitionValidation {
  ruleCount?: number | null;
  definitionSha256?: string | null;
}

export interface ImpactInput {
  /** The final arguments (validated, CAS injected): path/query at the top level, body under `body`. */
  args: Readonly<Record<string, unknown>>;
  /** The precondition snapshot (`buildSnapshot`), null for writes without a precondition. */
  snapshot?: Readonly<ConfirmationSnapshot> | null;
  /** The `each` preconditions (bulk). */
  items?: readonly EachSnapshotItem[];
  validation?: DefinitionValidation | null;
  /** The concrete request (default: built from the tool's path template and the arguments). */
  request?: { method: string; path: string };
  /**
   * The warnings of the matching risk escalations (`effectiveRisk(...).warnings`, step AI-3 D4),
   * appended to the template's warnings (deduplicated; at most `SUMMARY_LIMITS.warnings` in all).
   */
  escalationWarnings?: readonly string[];
  /**
   * The native snapshot of a native write (step AI-R D5): for `report_send_email` the report, the
   * classified recipient and the remaining daily limits, as the api's `NativeToolsService`
   * prepared them. The address is not mail-derived but is still normalized and sanitized.
   */
  native?: NativeImpactSnapshot | null;
  /**
   * `ARCHIVE_EXPORT_TTL_HOURS` of the api (step AI-5 D9): how long an eDiscovery export can be
   * downloaded in the portal. Without it the export card says "until it expires".
   */
  archiveExportTtlHours?: number | null;
}

export interface NativeImpactSnapshot {
  report: { title: string; period: string; sizeBytes: number };
  recipient: { address: string; kind: RecipientKind; domain: string };
  limits: {
    userRemaining: number;
    userLimit: number;
    tenantRemaining: number;
    tenantLimit: number;
  };
}

interface Draft {
  title: string;
  action: string;
  target?: ConfirmationTarget[];
  changes?: ConfirmationChange[];
  definition?: ConfirmationDefinitionSummary;
  impact?: string[];
  warnings?: string[];
  reversible: boolean;
  /** Overrides the portal route derived from the tool (native templates). */
  portalRoute?: string | null;
}

type Template = (ctx: TemplateContext) => Draft;

interface TemplateContext {
  args: Readonly<Record<string, unknown>>;
  body: Readonly<Record<string, unknown>>;
  snap: Readonly<ConfirmationSnapshot>;
  items: readonly EachSnapshotItem[];
  validation: DefinitionValidation | null;
  native: NativeImpactSnapshot | null;
  archiveExportTtlHours: number | null;
}

// ---------------------------------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------------------------------

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

/** A scalar as display text (`null` for missing values). */
function text(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value === 'string') return value.length > 0 ? value : null;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return null;
  }
}

const quoted = (value: unknown, fallback: string): string => {
  const t = text(value);
  return t === null ? fallback : `"${sanitizeText(t, 120)}"`;
};

const yesNo = (value: unknown): string | null =>
  value === true ? 'yes' : value === false ? 'no' : null;

const version = (value: unknown): string | null => {
  const t = text(value);
  return t === null ? null : `v${t}`;
};

function target(label: string, value: unknown, untrusted = false): ConfirmationTarget[] {
  const t = text(value);
  if (t === null) return [];
  return [{ label, value: t, ...(untrusted ? { untrusted: true } : {}) }];
}

function change(label: string, before: unknown, after: unknown): ConfirmationChange[] {
  const a = text(after);
  if (a === null) return [];
  const b = text(before);
  return [{ label, ...(before !== undefined ? { before: b } : {}), after: a }];
}

// ---------------------------------------------------------------------------------------------
// Policy definition summary
// ---------------------------------------------------------------------------------------------

function valueText(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((item) => valueText(item)).join(', ')}]`;
  if (isRecord(value)) {
    if (typeof value.pattern === 'string')
      return `/${value.pattern}/${typeof value.flags === 'string' ? value.flags : ''}`;
    return Object.entries(value)
      .map(([key, item]) => `${key}=${valueText(item)}`)
      .join(' ');
  }
  return text(value) ?? 'null';
}

/** A `when`/`unless` node as readable text: leaves `field op value`, `AND`/`OR`/`NOT`. */
export function conditionText(node: unknown, depth = 0): string {
  if (depth > 12 || !isRecord(node)) return '?';
  const group = (items: unknown, joiner: string): string => {
    const list = Array.isArray(items) ? items : [];
    const parts = list.map((item) => conditionText(item, depth + 1));
    return parts.length === 1 ? parts[0]! : `(${parts.join(joiner)})`;
  };
  if ('all' in node) return group(node.all, ' AND ');
  if ('any' in node) return group(node.any, ' OR ');
  if ('not' in node) return `NOT ${conditionText(node.not, depth + 1)}`;
  const field = text(node.field) ?? '?';
  const op = text(node.op) ?? '?';
  const quantifier =
    node.quantifier === 'any' || node.quantifier === 'all' ? `${node.quantifier} ` : '';
  const value = 'value' in node ? ` ${valueText(node.value)}` : '';
  return `${quantifier}${field} ${op}${value}`;
}

const stripOuter = (value: string): string =>
  value.startsWith('(') && value.endsWith(')') && balancedOuter(value) ? value.slice(1, -1) : value;

function balancedOuter(value: string): boolean {
  let depth = 0;
  for (let i = 0; i < value.length; i += 1) {
    if (value[i] === '(') depth += 1;
    else if (value[i] === ')') {
      depth -= 1;
      if (depth === 0 && i < value.length - 1) return false;
    }
  }
  return depth === 0;
}

/** Action types with their parameters: `QUARANTINE; TAG (label=external, subjectPrefix=[EXT])`. */
export function actionsText(actions: unknown): string {
  if (!Array.isArray(actions)) return '';
  return actions
    .map((action) => {
      if (!isRecord(action)) return '?';
      const type = text(action.type) ?? '?';
      const params = Object.entries(action)
        .filter(([key]) => key !== 'type')
        .map(([key, value]) => `${key}=${valueText(value)}`);
      return params.length > 0 ? `${type} (${params.join(', ')})` : type;
    })
    .join('; ');
}

function ruleSummary(rule: unknown, index: number): ConfirmationRuleSummary {
  const record = isRecord(rule) ? rule : {};
  const parts: string[] = [];
  if (record.enabled === false) parts.push('(disabled)');
  if (Array.isArray(record.directions) && record.directions.length > 0)
    parts.push(`[${record.directions.map((d) => text(d) ?? '?').join(', ')}]`);
  parts.push(stripOuter(conditionText(record.when)));
  if (Array.isArray(record.unless) && record.unless.length > 0)
    parts.push(
      `UNLESS ${record.unless.map((node) => stripOuter(conditionText(node))).join(' OR ')}`,
    );
  if (record.override === true) parts.push('(override)');
  return {
    id: sanitizeText(text(record.id) ?? `rule ${index + 1}`, 64),
    when: sanitizeText(parts.join(' '), SUMMARY_LIMITS.whenChars),
    actions: sanitizeText(actionsText(record.actions), SUMMARY_LIMITS.textChars),
  };
}

/** The rule-by-rule summary of a `policy-dsl/1` document (rules sorted by priority). */
export function summarizeDefinition(
  definition: unknown,
): ConfirmationDefinitionSummary | undefined {
  if (!isRecord(definition)) return undefined;
  const rules: unknown[] = Array.isArray(definition.rules) ? definition.rules : [];
  const ordered = rules
    .map((rule, index) => ({ rule, index }))
    .sort((a, b) => {
      const pa = isRecord(a.rule) && typeof a.rule.priority === 'number' ? a.rule.priority : 0;
      const pb = isRecord(b.rule) && typeof b.rule.priority === 'number' ? b.rule.priority : 0;
      return pa - pb || a.index - b.index;
    });
  return {
    direction: sanitizeText(text(definition.direction) ?? 'unknown', 32),
    priority:
      typeof definition.priority === 'number' && Number.isFinite(definition.priority)
        ? definition.priority
        : 0,
    rules: ordered.map(({ rule, index }) => ruleSummary(rule, index)),
  };
}

function definitionChanges(definition: unknown): ConfirmationChange[] {
  if (!isRecord(definition)) return [];
  const exceptions = Array.isArray(definition.exceptions) ? definition.exceptions : [];
  return exceptions.length > 0
    ? [
        {
          label: 'Policy-wide exceptions',
          after: sanitizeText(
            exceptions.map((node) => stripOuter(conditionText(node))).join(' OR '),
            SUMMARY_LIMITS.whenChars,
          ),
        },
      ]
    : [];
}

const ruleCountOf = (
  definition: unknown,
  validation: DefinitionValidation | null,
): number | null =>
  typeof validation?.ruleCount === 'number'
    ? validation.ruleCount
    : isRecord(definition) && Array.isArray(definition.rules)
      ? definition.rules.length
      : null;

// ---------------------------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------------------------

const UNDO_DELETE = 'Deleting cannot be undone.';
const APPROVAL_MAY_BE_REQUIRED =
  'May require approval by another analyst: the platform re-checks the message and creates an approval request instead when policy requires it.';

const policyName = (ctx: TemplateContext): string => quoted(ctx.snap.name, 'this policy');

const policyTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Policy', ctx.snap.name),
  ...target('Policy id', ctx.args.policyId),
  ...target('Status', ctx.snap.status),
  ...target('Direction', ctx.snap.direction),
  ...target('Active version', version(ctx.snap.activeVersionNo)),
];

const versionTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Policy id', ctx.args.policyId),
  ...target('Version', version(ctx.args.versionNo)),
  ...target('Version status', ctx.snap.status),
  ...target('Rules', ctx.snap.ruleCount),
];

const entryTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Quarantine entry', ctx.args.entryId),
  ...target('Subject', ctx.snap.subject, true),
  ...target('Sender', ctx.snap['sender.headerFrom'] ?? ctx.snap['sender.envelope'], true),
  ...target('Envelope sender', ctx.snap['sender.envelope'], true),
  ...target('Recipient', ctx.snap.recipient, true),
  ...target('Quarantine reason', ctx.snap.reason),
  ...target('Risk level', ctx.snap.riskLevel),
  ...target('Direction', ctx.snap.direction),
];

const messageTarget = (ctx: TemplateContext, id: unknown): ConfirmationTarget[] => [
  ...target('Message', id),
  ...target('Subject', ctx.snap.subject, true),
  ...target('Sender', ctx.snap.headerFrom ?? ctx.snap.envelopeFrom, true),
  ...target('Envelope sender', ctx.snap.envelopeFrom, true),
  ...target('Direction', ctx.snap.direction),
  ...target('Verdict', ctx.snap.finalVerdict),
  ...target('Recipients', ctx.snap.recipientCount),
];

const approvalTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Approval request', ctx.args.approvalId),
  ...target('Request kind', ctx.snap.kind),
  ...target('Quarantine entry', ctx.snap.entryId),
  ...target('Requested by', ctx.snap['requestedBy.type']),
  ...target('Expires at', ctx.snap.expiresAt),
];

const reasonChange = (ctx: TemplateContext): ConfirmationChange[] =>
  change('Reason', undefined, ctx.body.reason);

const POLICY_SETTINGS: ReadonlyArray<{ path: string; label: string }> = [
  { path: 'allowRecommendationOverrides', label: 'Allow overrides of level-only recommendations' },
  { path: 'recipientSplit', label: 'Per-recipient decisions' },
  { path: 'notices.senderNonDelivery', label: 'Non-delivery notices to senders' },
  { path: 'alerts.enabled', label: 'Policy alerts' },
  { path: 'tagging.platformTagHeader', label: 'Platform tag header' },
  { path: 'tagging.platformTagOutbound', label: 'Platform tag on outbound mail' },
];

function savedViewChanges(ctx: TemplateContext, before?: unknown): ConfirmationChange[] {
  const definition = isRecord(ctx.body.definition) ? ctx.body.definition : {};
  const filters = isRecord(definition.filters) ? definition.filters : {};
  const range = isRecord(definition.range) ? definition.range : null;
  const filterText = Object.entries(filters)
    .map(([key, value]) => `${key}=${text(value) ?? ''}`)
    .join(', ');
  return [
    ...change('Name', before, ctx.body.name),
    ...change('Filters', undefined, filterText.length > 0 ? filterText : 'none'),
    ...change('Sort', undefined, definition.sort),
    ...change(
      'Time range',
      undefined,
      range
        ? range.kind === 'relative'
          ? `last ${text(range.preset) ?? '?'}`
          : `${text(range.from) ?? '?'} to ${text(range.to) ?? '?'}`
        : null,
    ),
    ...change(
      'Columns',
      undefined,
      Array.isArray(definition.columns) ? definition.columns.join(', ') : null,
    ),
  ];
}

// ---------------------------------------------------------------------------------------------
// Step AI-3 helpers (design 30 D7)
// ---------------------------------------------------------------------------------------------

/** The strings of a snapshot list (`SNAPSHOT_LIST_MAX_CHARS`), or null (absent or cut). */
const snapStrings = (value: SnapshotValue | undefined): string[] | null => {
  const list = snapshotList(value);
  return list === null ? null : list.map((item) => text(item) ?? 'null');
};

/** The string items of an argument list. */
const argStrings = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.flatMap((item) => {
        const t = text(item);
        return t === null ? [] : [t];
      })
    : [];

const listText = (items: readonly string[], empty = 'none'): string =>
  items.length > 0 ? items.join(', ') : empty;

const plural = (count: number, noun: string): string => `${count} ${noun}${count === 1 ? '' : 's'}`;

/** Added and removed members (first-seen order, no duplicates). */
function setDiff(
  before: readonly string[],
  after: readonly string[],
): { added: string[]; removed: string[] } {
  const b = new Set(before);
  const a = new Set(after);
  return {
    added: [...a].filter((item) => !b.has(item)),
    removed: [...b].filter((item) => !a.has(item)),
  };
}

const onOff = (value: unknown): string | null =>
  value === true ? 'on' : value === false ? 'off' : null;

const userTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('User', ctx.snap.email),
  ...target('Display name', ctx.snap.displayName, true),
  ...target('User id', ctx.args.id),
  ...target('Status', ctx.snap.status),
];
const userName = (ctx: TemplateContext): string => quoted(ctx.snap.email, 'this user');
const userRoles = (ctx: TemplateContext): string[] | null => snapStrings(ctx.snap['roles[].key']);
const rolesTarget = (ctx: TemplateContext): ConfirmationTarget[] => {
  const roles = userRoles(ctx);
  return roles ? target('Roles', listText(roles)) : [];
};

const SIGNED_OUT = 'The user is signed out everywhere.';
const ROLE_RULE =
  'The platform refuses roles or permissions you do not hold yourself, and changes that would leave the organization without an administrator.';

const departmentTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Department', ctx.snap.name),
  ...target('Department id', ctx.args.departmentId),
  ...target('Members', ctx.snap.memberCount),
];

const domainTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Domain', ctx.snap.unicodeName ?? ctx.snap.name),
  ...target('Domain id', ctx.args.id),
  ...target('Status', ctx.snap.status),
];
const domainName = (ctx: TemplateContext): string =>
  quoted(ctx.snap.unicodeName ?? ctx.snap.name, 'this domain');

/** `host:port (priority n)` of a destination server (port and priority when given). */
function serverText(host: unknown, port: unknown, priority: unknown): string {
  const h = text(host) ?? '?';
  const p = text(port);
  const prio = text(priority);
  return `${h}${p !== null ? `:${p}` : ''}${prio !== null ? ` (priority ${prio})` : ''}`;
}

/** The current destination servers from the snapshot projections, or null when cut. */
function snapshotServers(ctx: TemplateContext): string[] | null {
  const hosts = snapStrings(ctx.snap['servers[].host']);
  if (hosts === null) return null;
  const ports = snapshotList(ctx.snap['servers[].port']) ?? [];
  const priorities = snapshotList(ctx.snap['servers[].priority']) ?? [];
  return hosts.map((host, i) => serverText(host, ports[i], priorities[i]));
}

/** The new servers of a `PUT /domains/{id}/destinations` body (by provider). */
function requestedServers(body: Readonly<Record<string, unknown>>): string {
  if (body.provider === 'google_workspace') return 'the Google Workspace MX servers';
  if (body.provider === 'microsoft_365') return serverText(body.host, undefined, undefined);
  const servers = Array.isArray(body.servers) ? body.servers : [];
  return listText(
    servers.map((server) =>
      isRecord(server) ? serverText(server.host, server.port, server.priority) : '?',
    ),
  );
}

const RECIPIENT_MODES: Readonly<Record<string, string>> = {
  accept_all: 'Mail to every address of the domain is accepted.',
  allow_list: 'Only mail to addresses on the recipient list is accepted.',
  smtp_callout: 'Recipients are checked against the destination server before mail is accepted.',
  ldap: 'Recipients are checked against the directory before mail is accepted.',
};

const recipientTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Domain id', ctx.args.id),
  ...target('Validation mode', ctx.snap.mode),
  ...target('Enforcement', ctx.snap.enforcement),
  ...target('Addresses on the list', ctx.snap.addressCount),
];

/** The local parts of a recipients body, shown capped (`a, b, c and 7 more`). */
function localPartsText(body: Readonly<Record<string, unknown>>): { count: number; text: string } {
  const parts = argStrings(body.localParts);
  const shown = parts.slice(0, 20);
  const rest = parts.length - shown.length;
  return {
    count: parts.length,
    text: `${listText(shown)}${rest > 0 ? ` and ${rest} more` : ''}`,
  };
}

const NOTIFICATION_ALERTS: ReadonlyArray<{ path: string; label: string }> = [
  { path: 'alerts.threatDetected.enabled', label: 'Threat alerts' },
  { path: 'alerts.threatDetected.minSeverity', label: 'Threat alerts: minimum severity' },
  { path: 'alerts.threatDetected.throttleMinutes', label: 'Threat alerts: throttle (minutes)' },
  { path: 'alerts.domainDnsFailed.enabled', label: 'Domain DNS failure alerts' },
  {
    path: 'alerts.domainDnsFailed.throttleMinutes',
    label: 'Domain DNS failure alerts: throttle (minutes)',
  },
  { path: 'alerts.webhookDisabled.enabled', label: 'Webhook disabled alerts' },
  {
    path: 'alerts.webhookDisabled.throttleMinutes',
    label: 'Webhook disabled alerts: throttle (minutes)',
  },
  { path: 'alerts.includeOrganizationContact', label: 'Copy the organization contact' },
];

const ORGANIZATION_SETTINGS: ReadonlyArray<{ key: string; label: string }> = [
  { key: 'timezone', label: 'Time zone' },
  { key: 'locale', label: 'Locale' },
  { key: 'quarantineRetentionDays', label: 'Quarantine retention (days)' },
  { key: 'digestEnabled', label: 'Quarantine digest' },
  { key: 'digestSchedule', label: 'Digest schedule' },
  { key: 'notificationEmail', label: 'Notification email' },
  { key: 'mfaRequired', label: 'MFA required' },
  { key: 'preferences', label: 'Preferences' },
];

const settingText = (value: unknown): string | null =>
  value === null ? '(none)' : typeof value === 'boolean' ? yesNo(value) : text(value);

const organizationTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Organization', ctx.snap.name),
  ...target('Slug', ctx.snap.slug),
  ...target('Organization id', ctx.args.id),
];

const featureTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Organization id', ctx.args.id),
  ...target('Feature', ctx.args.featureKey),
  ...target('Currently', onOff(ctx.snap.enabled)),
  ...target('Current source', ctx.snap.source ?? 'plan'),
];
const limitTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Organization id', ctx.args.id),
  ...target('Limit', ctx.args.limitKey),
  ...target('Current value', ctx.snap.value),
  ...target('Current source', ctx.snap.source ?? 'plan'),
];

const scanTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Engine', ctx.args.engine),
  ...target('Settings version', ctx.snap.version),
  ...target('Required engine', yesNo(ctx.snap.required)),
  ...target('Organization override applied', yesNo(ctx.snap.overrideApplied)),
];

const connectorTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Connector', ctx.snap.name),
  ...target('Connector id', ctx.args.id),
  ...target('Authentication', ctx.snap.authType),
  ...target('Status', ctx.snap.status),
];

const webhookTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Webhook', ctx.snap.name),
  ...target('Webhook id', ctx.args.webhookId),
  ...target('URL', ctx.snap.url),
  ...target('Status', ctx.snap.status),
];
const webhookName = (ctx: TemplateContext): string => quoted(ctx.snap.name, 'this webhook');

const REPLAY_TWICE = 'Receivers may process these events a second time.';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const count = (value: unknown): string =>
  typeof value === 'number' && Number.isFinite(value)
    ? String(Math.max(0, Math.floor(value)))
    : '0';

/** `report_send_email` (step AI-R D5 step 5). */
const reportSendEmail: Template = (ctx) => {
  const native = ctx.native;
  const raw = native?.recipient.address ?? (typeof ctx.args.to === 'string' ? ctx.args.to : null);
  const address = normalizeRecipient(raw) ?? sanitizeText(raw ?? '(unknown)', 120);
  const domain = sanitizeText(native?.recipient.domain ?? address.split('@')[1] ?? '', 253);
  const reportId = typeof ctx.args.reportId === 'string' ? ctx.args.reportId : null;
  const limits = native?.limits;
  return {
    title: 'Email security report',
    action: `Sends the security report as an HTML email to ${address}.`,
    target: [
      ...target('Report', native?.report.title),
      ...target('Period', native?.report.period),
      ...target('Recipient', address),
      ...target('Recipient type', native ? recipientKindText(native.recipient.kind, domain) : null),
      ...target('Size', native ? fmtBytes(native.report.sizeBytes) : null),
    ],
    impact: [
      'The email leaves the platform through the notification mailer; the recipient can forward it.',
      'The same HTML is attached as a file.',
    ],
    warnings: [
      'Emails cannot be recalled after sending.',
      ...(limits
        ? [
            `${count(limits.userRemaining)} of ${count(limits.userLimit)} report emails left today for you (${count(limits.tenantRemaining)} for your organization).`,
          ]
        : []),
    ],
    reversible: false,
    portalRoute:
      reportId && UUID.test(reportId)
        ? `/assistant/reports/${reportId.toLowerCase()}`
        : '/assistant',
  };
};

// ---------------------------------------------------------------------------------------------
// Step AI-4 helpers and templates (design 32 D6)
// ---------------------------------------------------------------------------------------------

/** The ATO response catalogue in words (`ato_responses_*`). */
const ATO_ACTION_WORDS: Readonly<Record<string, string>> = {
  alert_tenant_admins: 'alert the organization administrators',
  notify_soc: 'notify the SOC',
  escalate_investigation: 'escalate the investigation',
  restrict_smtp_sending: 'block outbound SMTP sending',
  block_smtp_auth: 'block SMTP authentication',
  record_manual_action: 'record a manual action',
  revoke_sessions: 'revoke the sign-in sessions',
  require_mfa: 'require MFA',
  require_password_reset: 'require a password reset',
  suspend_account: 'suspend the account',
  remove_forwarding_rule: 'remove the mail forwarding rule',
  revoke_oauth_grant: 'revoke the OAuth app grant',
};
/** Actions that run in the tenant's identity provider (not in the gateway). */
const PROVIDER_ACTIONS: ReadonlySet<string> = new Set([
  'revoke_sessions',
  'require_mfa',
  'require_password_reset',
  'suspend_account',
  'remove_forwarding_rule',
  'revoke_oauth_grant',
]);
const SMTP_RESTRICTIONS: ReadonlySet<string> = new Set([
  'restrict_smtp_sending',
  'block_smtp_auth',
]);

const actionWords = (value: unknown): string => {
  const key = text(value);
  return key === null ? 'the response' : (ATO_ACTION_WORDS[key] ?? sanitizeText(key, 64));
};

const ATO_APPROVAL_LINE =
  "Gateway actions with low impact run now; others wait for another responder's approval (you cannot approve your own request).";
const ATO_PROVIDER_WARNING = "Runs in the organization's identity provider after approval.";
const ATO_REQUEST_WARNING =
  'The response acts on a real account; check the action and the target before you confirm.';
const UNDO_REMOVE = (what: string) =>
  `Removing cannot be undone; add the ${what} again to restore it.`;
const EVERY_ORGANIZATION_SCAN = 'Applies to the next scan of every organization.';
const EVERY_ORGANIZATION_SCAN_CLICK = 'Applies to the next scan and click of every organization.';

/** A capped list: the first `max` items and how many more (`a, b and 3 more`). */
function cappedList(items: readonly string[], max = 5, empty = 'none'): string {
  if (items.length === 0) return empty;
  const shown = items.slice(0, max).map((item) => sanitizeText(item, 80));
  const rest = items.length - shown.length;
  return `${shown.join(', ')}${rest > 0 ? ` and ${rest} more` : ''}`;
}
/** A list argument as a capped list, or null when the argument is absent. */
const argList = (value: unknown, max = 10): string | null =>
  value === undefined ? null : cappedList(argStrings(value), max);
/** A snapshot list as a capped list, or null when absent or cut. */
const snapList = (value: SnapshotValue | undefined, max = 10): string | null => {
  const list = snapStrings(value);
  return list === null ? null : cappedList(list, max);
};
/** "until <date>" / "without expiry" for an optional expiry. */
const expiryText = (value: unknown): string =>
  value === null || value === undefined ? 'no expiry' : (text(value) ?? 'no expiry');
/** The keys of an object argument (sections of a settings or overrides document). */
const keysOf = (value: unknown): string[] => (isRecord(value) ? Object.keys(value) : []);
/** Every `on`/enabled entry of a map of `{ enabled }` objects (IdP streams and actions). */
const enabledKeys = (value: unknown): string[] =>
  isRecord(value)
    ? Object.entries(value)
        .filter(([, item]) => isRecord(item) && item.enabled === true)
        .map(([key]) => key)
    : [];

// --- ATO accounts ---
const atoAccountTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Account', ctx.snap.address, true),
  ...target('Display name', ctx.snap.displayName, true),
  ...target('Account id', ctx.args.accountId),
  ...target('Kind', ctx.snap.kind),
  ...target('Risk', ctx.snap.riskLevel),
  ...target('Risk score', ctx.snap.riskScore),
];

// --- ATO responses ---
const atoResponseTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Response', ctx.args.responseId),
  ...target('Action', actionWords(ctx.snap.actionType)),
  ...target('Impact', ctx.snap.impact),
  ...target('Provider', ctx.snap.provider),
  ...target('Account id', ctx.snap['account.id']),
  ...target('Account kind', ctx.snap['account.kind']),
  ...target('Target scope', ctx.snap['target.scope']),
  ...target('Duration (minutes)', ctx.snap['params.durationMinutes']),
  ...target('Mode', ctx.snap['params.mode']),
  ...target('Requested by', ctx.snap['requestedBy.type']),
  ...target('Request reason', ctx.snap.requestReason, true),
  ...target('Approval expires at', ctx.snap.approvalExpiresAt),
];
const isProviderAction = (ctx: TemplateContext): boolean =>
  PROVIDER_ACTIONS.has(text(ctx.snap.actionType) ?? '');
const restrictionLine = (
  action: unknown,
  scope: unknown,
  duration: unknown,
  mode: unknown,
): string[] =>
  SMTP_RESTRICTIONS.has(text(action) ?? '')
    ? [
        `SMTP ${action === 'block_smtp_auth' ? 'authentication' : 'sending'} is ${
          mode === 'defer' ? 'deferred' : 'rejected'
        } for ${text(duration) ?? 'the default number of'} minutes at the ${text(scope) ?? 'default'} scope.`,
      ]
    : [];

// --- incidents ---
const incidentTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Incident', ctx.args.incidentId),
  ...target('Category', ctx.snap.category),
  ...target('Subject', ctx.snap['subject.display'], true),
  ...target('Status', ctx.snap.status),
  ...target('Severity', ctx.snap.severity),
  ...target('Assignee', ctx.snap.assigneeId),
];

// --- IdP integrations ---
const providerTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Integration', ctx.snap.displayName, true),
  ...target('Integration id', ctx.args.integrationId),
  ...target('Provider', ctx.snap.provider),
  ...target('Status', ctx.snap.status),
  ...target('Health', ctx.snap['health.status']),
  ...target('Settings version', ctx.snap.settingsVersion),
];
function idpSettingsChanges(settings: unknown): ConfirmationChange[] {
  if (!isRecord(settings)) return [];
  const mfa = isRecord(settings.mfaEnforcement) ? settings.mfaEnforcement : {};
  const forwarding = isRecord(settings.forwardingRemoval) ? settings.forwardingRemoval : {};
  const snapshot = isRecord(settings.snapshot) ? settings.snapshot : {};
  return [
    ...change('Streams read', undefined, cappedList(enabledKeys(settings.streams), 7)),
    ...change('Response actions allowed', undefined, cappedList(enabledKeys(settings.actions), 6)),
    ...change('Poll interval (seconds)', undefined, settings.pollIntervalSeconds),
    ...change('Backfill (days)', undefined, settings.backfillDays),
    ...change('Mailbox sweep (hours)', undefined, snapshot.sweepIntervalHours ?? null),
    ...change('MFA enforcement group', undefined, mfa.groupId ?? null),
    ...change('MFA enforcement org unit', undefined, mfa.orgUnitPath ?? null),
    ...change('Forwarding removal', undefined, forwarding.mode),
  ];
}

// --- BEC ---
const namedTarget = (label: string, ctx: TemplateContext, name: unknown) => [
  ...target(label, name),
  ...target(`${label} id`, ctx.args.id),
];
const executiveTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...namedTarget('Executive', ctx, ctx.snap.displayName),
  ...target('Title', ctx.snap.title),
  ...target('Enabled', yesNo(ctx.snap.enabled)),
];
const vendorTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...namedTarget('Vendor', ctx, ctx.snap.name),
  ...target('Enabled', yesNo(ctx.snap.enabled)),
  ...target('Payment-change sensitive', yesNo(ctx.snap.paymentChangeSensitive)),
];
const trustedSenderTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Trusted sender', ctx.snap.value),
  ...target('Trusted sender id', ctx.args.id),
  ...target('Kind', ctx.snap.kind),
  ...target('Reason', ctx.snap.reason),
  ...target('Expires at', expiryText(ctx.snap.expiresAt)),
];

// --- DLP ---
const DLP_SCOPE_WORDS: Readonly<Record<string, string>> = {
  sender_address: 'the sender address',
  sender_domain: 'the sender domain',
  recipient_address: 'the recipient address',
  recipient_domain: 'the recipient domain',
};
const DLP_RULE_ACTIONS: Readonly<Record<string, string>> = {
  allow: 'allowed without further DLP action',
  alert: 'delivered and an alert is raised',
  require_approval: 'held until another person approves it',
  quarantine: 'quarantined',
  block: 'blocked',
};
const dictionaryTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...namedTarget('Dictionary', ctx, ctx.snap.name),
  ...target('Category', ctx.snap.category),
  ...target('Severity', ctx.snap.severity),
  ...target('Terms', ctx.snap.termCount),
  ...target('Enabled', yesNo(ctx.snap.enabled)),
];
const exceptionTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Exception', ctx.args.id),
  ...target('Scope', ctx.snap.scope),
  ...target('Value', ctx.snap.value),
  ...target('Policy', ctx.snap.policyId ?? 'every DLP policy'),
  ...target('Reason', ctx.snap.reason),
  ...target('Expires at', ctx.snap.expiresAt),
  ...target('Enabled', yesNo(ctx.snap.enabled)),
];
const patternTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...namedTarget('Pattern', ctx, ctx.snap.name),
  ...target('Severity', ctx.snap.severity),
  ...target('Validator', ctx.snap.validator),
  ...target('Enabled', yesNo(ctx.snap.enabled)),
];
const dlpPolicyTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...namedTarget('DLP policy', ctx, ctx.snap.name),
  ...target('Enabled', yesNo(ctx.snap.enabled)),
  ...target('Mode', ctx.snap.mode),
  ...target('Priority', ctx.snap.priority),
  ...target('Rules', ctx.snap.ruleCount),
];
const dlpRuleTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Rule', ctx.snap.name),
  ...target('Rule id', ctx.args.ruleId),
  ...target('DLP policy id', ctx.args.id),
  ...target('Action', ctx.snap.action),
  ...target('Enabled', yesNo(ctx.snap.enabled)),
  ...target('Priority', ctx.snap.priority),
];
/** The terms of a dictionary body: a count plus the first five (D6). */
const termsText = (value: unknown): string | null => {
  if (value === undefined) return null;
  const terms = argStrings(value);
  return `${plural(terms.length, 'term')}${terms.length > 0 ? `: ${cappedList(terms, 5)}` : ''}`;
};
function dlpConditionChanges(conditions: unknown): ConfirmationChange[] {
  if (!isRecord(conditions)) return [];
  const selectors = isRecord(conditions.selectors) ? conditions.selectors : {};
  const sender = isRecord(conditions.sender) ? conditions.sender : {};
  const recipients = isRecord(conditions.recipients) ? conditions.recipients : {};
  return [
    ...change('Detectors', undefined, argList(selectors.detectors)),
    ...change('Categories', undefined, argList(selectors.categories)),
    ...change(
      'Custom patterns',
      undefined,
      selectors.customPatternIds === undefined
        ? null
        : plural(argStrings(selectors.customPatternIds).length, 'pattern'),
    ),
    ...change(
      'Dictionaries',
      undefined,
      selectors.dictionaryIds === undefined
        ? null
        : plural(argStrings(selectors.dictionaryIds).length, 'dictionary'),
    ),
    ...change('Coverage reasons', undefined, argList(selectors.coverageReasons)),
    ...change('Minimum matches', undefined, conditions.minCount),
    ...change('Minimum confidence', undefined, conditions.minConfidence),
    ...change('Minimum severity', undefined, conditions.minSeverity),
    ...change('Directions', undefined, argList(conditions.directions)),
    ...change('Senders', undefined, argList(sender.addresses)),
    ...change('Sender domains', undefined, argList(sender.domains)),
    ...change('Recipients', undefined, argList(recipients.addresses)),
    ...change('Recipient domains', undefined, argList(recipients.domains)),
    ...change('External recipients only', undefined, yesNo(recipients.externalOnly)),
    ...change('Attachments only', undefined, yesNo(conditions.attachmentsOnly)),
  ];
}
/** Pattern fields of a create/update body; the pattern text only here, never in impact (D6). */
function patternChanges(ctx: TemplateContext, before = false): ConfirmationChange[] {
  const b = ctx.body;
  const prior = (key: string) => (before ? ctx.snap[key] : undefined);
  return [
    ...change('Name', prior('name'), b.name),
    ...change('Pattern', undefined, typeof b.pattern === 'string' ? sanitizeText(b.pattern) : null),
    ...change('Case-insensitive', undefined, yesNo(b.caseInsensitive)),
    ...change('Validator', prior('validator'), b.validator),
    ...change('Context keywords', undefined, argList(b.contextKeywords)),
    ...change('Context required', undefined, yesNo(b.requireContext)),
    ...change('Severity', prior('severity'), b.severity),
    ...change('Base confidence', undefined, b.baseConfidence),
    ...change('Mask style', undefined, b.maskStyle),
    ...change('Enabled', before ? yesNo(ctx.snap.enabled) : undefined, yesNo(b.enabled)),
  ];
}

// --- risk-scoring ---
const riskVersionTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Profile version id', ctx.args.versionId),
  ...target('Version', version(ctx.snap.versionNo)),
  ...target('Status', ctx.snap.status),
  ...target('Active', yesNo(ctx.snap.active)),
  ...target('Change note', ctx.snap.changeNote, true),
];
const riskProfileTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Active profile', ctx.snap['active.source']),
  ...target('Active version', version(ctx.snap['active.versionNo'])),
  ...target('Profile change counter', ctx.snap.profileVersion),
];
const RISK_NEXT_ROUND =
  'Applies to the next scan round only: open rounds and stored scores do not change.';

// --- platform ---
const RESCAN_STATES = 'scanned, scan failed, quarantined and held messages (the default)';
const TRAINING_WORDS: Readonly<Record<string, string>> = {
  learn_spam: 'learn it as spam',
  learn_ham: 'learn it as legitimate mail (ham)',
  fuzzy_add: 'add its fuzzy hashes',
  fuzzy_delete: 'remove its fuzzy hashes',
};

/** The 64 templates of step AI-4 (design 32 D6), keyed by operation id. */
const AI4_TEMPLATES: Readonly<Record<string, Template>> = {
  // --- ATO accounts ---
  AtoAccountsController_update_v1: (ctx) => {
    const protect = ctx.body.protected === true;
    return {
      title: protect ? 'Protect ATO account' : 'Remove ATO account protection',
      action: protect
        ? `Protects this account from automated responses.`
        : `Removes the protection of this account: automated responses may act on it again.`,
      target: [
        ...atoAccountTarget(ctx),
        ...target('Protection reason', ctx.snap['protection.reason']),
      ],
      changes: [
        ...change('Protected', yesNo(ctx.snap['protection.protected']), yesNo(ctx.body.protected)),
        ...change('Reason', undefined, ctx.body.reason),
      ],
      impact: [
        protect
          ? 'Automated responses skip this account; analysts can still request responses.'
          : 'Automated responses may act on this account again when its risk is high enough.',
      ],
      reversible: true,
    };
  },
  AtoAccountMailboxController_refresh_v1: (ctx) => ({
    title: 'Refresh mailbox settings',
    action: `Queues a priority read of the mailbox settings (forwarding, inbox rules, delegates) of this account from the identity provider.`,
    target: [
      ...target('Account', ctx.snap.address, true),
      ...target('Account id', ctx.args.accountId),
      ...target('Kind', ctx.snap.kind),
    ],
    changes: change('Mailbox state', undefined, 'refresh requested'),
    impact: ['The result appears on the account page when the provider answers.'],
    reversible: false,
  }),
  AtoAccountsController_setOverride_v1: (ctx) => {
    const benign = ctx.body.verdict === 'benign';
    return {
      title: 'Set ATO analyst verdict',
      action: `Sets the analyst verdict ${text(ctx.body.verdict) ?? '?'} on this account for ${text(ctx.body.expiresInHours) ?? '?'} hours.`,
      target: [
        ...atoAccountTarget(ctx),
        ...target('Current verdict', ctx.snap['overrideDetail.verdict'] ?? 'none'),
        ...target('Current verdict expires', ctx.snap['overrideDetail.expiresAt']),
      ],
      changes: [
        ...change('Verdict', ctx.snap['overrideDetail.verdict'] ?? 'none', ctx.body.verdict),
        ...change('Expires in (hours)', undefined, ctx.body.expiresInHours),
        ...change('Reason', undefined, ctx.body.reason),
      ],
      impact: [
        benign
          ? "The account's risk is held low until the verdict expires or a strong new signal contradicts it."
          : "The account's risk is held at least high (score 90); automation may act on it.",
        'The account is rescored now; an active verdict is replaced.',
      ],
      reversible: true,
    };
  },
  AtoAccountsController_clearOverride_v1: (ctx) => ({
    title: 'Clear ATO analyst verdict',
    action: `Removes the analyst verdict of this account: it is scored from its signals again.`,
    target: [
      ...atoAccountTarget(ctx),
      ...target('Current verdict', ctx.snap['overrideDetail.verdict'] ?? 'none'),
    ],
    changes: [
      ...change('Verdict', ctx.snap['overrideDetail.verdict'] ?? 'none', 'none'),
      ...change('Reason', undefined, ctx.body.reason),
    ],
    impact: [
      ctx.snap['overrideDetail.id'] === null || ctx.snap['overrideDetail.id'] === undefined
        ? 'The account has no active verdict: nothing changes.'
        : 'The account is rescored from its signals now.',
    ],
    reversible: true,
  }),
  AtoAccountsController_addTrustedContext_v1: (ctx) => {
    const known = snapStrings(ctx.snap['trustedContexts[].kind']);
    return {
      title: 'Add ATO trusted context',
      action: `Trusts the ${text(ctx.body.kind) ?? 'context'} ${quoted(ctx.body.value, '?')} for this account for ${text(ctx.body.expiresInDays) ?? '?'} days.`,
      target: [
        ...target('Account', ctx.snap.address, true),
        ...target('Account id', ctx.args.accountId),
        ...target('Risk', ctx.snap.riskLevel),
        ...(known ? target('Trusted contexts now', plural(known.length, 'context')) : []),
      ],
      changes: [
        ...change('Kind', undefined, ctx.body.kind),
        ...change('Value', undefined, ctx.body.value),
        ...change('Expires in (days)', undefined, ctx.body.expiresInDays),
        ...change('Reason', undefined, ctx.body.reason),
      ],
      impact: [
        'Sign-ins and mail from this context no longer raise risk for this account.',
        'An existing context of the same kind and value is renewed.',
      ],
      warnings: ['An attacker using this context is no longer detected for this account.'],
      reversible: true,
    };
  },
  AtoAccountsController_removeTrustedContext_v1: (ctx) => ({
    title: 'Remove ATO trusted context',
    action: `Removes the trusted ${text(ctx.snap.kind) ?? 'context'} ${quoted(ctx.snap.value, '?')} from the account.`,
    target: [
      ...target('Account id', ctx.args.accountId),
      ...target('Context id', ctx.args.contextId),
      ...target('Kind', ctx.snap.kind),
      ...target('Value', ctx.snap.value),
      ...target('Reason', ctx.snap.reason, true),
      ...target('Source', ctx.snap.source),
      ...target('Expires at', ctx.snap.expiresAt),
    ],
    changes: change('Trusted context', 'trusted', 'removed'),
    impact: ['Sign-ins and mail from this context raise risk for the account again.'],
    warnings: [UNDO_REMOVE('context')],
    reversible: false,
  }),
  // --- ATO responses (the existing approval model) ---
  AtoResponsesController_request_v1: (ctx) => {
    const action = ctx.body.actionType;
    const scope = isRecord(ctx.body.target) ? ctx.body.target : {};
    const params = isRecord(ctx.body.params) ? ctx.body.params : {};
    const provider = PROVIDER_ACTIONS.has(text(action) ?? '');
    return {
      title: 'Request ATO response',
      action: `Requests the response "${actionWords(action)}" for the account of this incident.`,
      target: [
        ...target('Incident', ctx.args.incidentId),
        ...target('Category', ctx.snap.category),
        ...target('Account', ctx.snap['subject.display'], true),
        ...target('Incident status', ctx.snap.status),
        ...target('Severity', ctx.snap.severity),
      ],
      changes: [
        ...change('Action', undefined, actionWords(action)),
        ...change('Target scope', undefined, scope.scope),
        ...change('Connector', undefined, scope.connectorId),
        ...change('Connector IP range', undefined, scope.cidr),
        ...change('Duration (minutes)', undefined, ctx.body.durationMinutes),
        ...change('Mode', undefined, ctx.body.mode),
        ...change('Mailbox item', undefined, params.itemId),
        ...change('Grant scope', undefined, params.scope),
        ...change('Reason', undefined, ctx.body.reason),
        ...change('Description', undefined, ctx.body.description),
      ],
      impact: [
        ATO_APPROVAL_LINE,
        ...restrictionLine(action, scope.scope, ctx.body.durationMinutes, ctx.body.mode),
        ...(action === 'remove_forwarding_rule'
          ? ['The mailbox item is not read before the request: check it on the account page first.']
          : []),
        ...(action === 'record_manual_action'
          ? ['Records what was done elsewhere; nothing runs in the gateway.']
          : []),
      ],
      warnings: [provider ? ATO_PROVIDER_WARNING : ATO_REQUEST_WARNING],
      reversible: false,
    };
  },
  AtoResponsesController_approve_v1: (ctx) => {
    const provider = isProviderAction(ctx);
    const account = text(ctx.snap['account.id']) ?? 'the account';
    return {
      title: 'Approve ATO response',
      action: provider
        ? `Runs "${actionWords(ctx.snap.actionType)}" for account ${account} now in ${text(ctx.snap.provider) ?? 'the identity provider'}; the provider confirms it later.`
        : `Runs "${actionWords(ctx.snap.actionType)}" for account ${account} now.`,
      target: atoResponseTarget(ctx),
      changes: [
        ...change('Status', ctx.snap.status, 'approved'),
        ...change('Reason', undefined, ctx.body.reason),
      ],
      impact: [
        'The response runs as soon as it is approved; the approval is recorded with your name.',
        ...restrictionLine(
          ctx.snap.actionType,
          ctx.snap['target.scope'],
          ctx.snap['params.durationMinutes'],
          ctx.snap['params.mode'],
        ),
      ],
      warnings: [
        'Approving runs the action on the account.',
        ...(provider
          ? [
              "Runs in the organization's identity provider; the user may be signed out or locked out.",
            ]
          : []),
      ],
      reversible: !provider,
    };
  },
  AtoResponsesController_reject_v1: (ctx) => ({
    title: 'Reject ATO response',
    action: `Rejects the requested response "${actionWords(ctx.snap.actionType)}".`,
    target: atoResponseTarget(ctx),
    changes: [
      ...change('Status', ctx.snap.status, 'rejected'),
      ...change('Reason', undefined, ctx.body.reason),
    ],
    impact: ['Nothing runs; the request is closed.'],
    reversible: false,
  }),
  AtoResponsesController_cancel_v1: (ctx) => ({
    title: 'Cancel ATO response',
    action: `Cancels the response "${actionWords(ctx.snap.actionType)}".`,
    target: atoResponseTarget(ctx),
    changes: [
      ...change('Status', ctx.snap.status, 'cancelled'),
      ...change('Reason', undefined, ctx.body.reason),
    ],
    impact: ['Nothing runs; the request is closed.'],
    reversible: false,
  }),
  AtoResponsesController_rollback_v1: (ctx) => {
    const action = text(ctx.snap.actionType) ?? '';
    return {
      title: 'Roll back ATO response',
      action: `Rolls back the response "${actionWords(action)}".`,
      target: [
        ...atoResponseTarget(ctx),
        ...target('Executed at', ctx.snap.executedAt),
        ...target('Effective until', ctx.snap.effectiveUntil),
      ],
      changes: [
        ...change('Status', ctx.snap.status, 'rollback requested'),
        ...change('Reason', undefined, ctx.body.reason),
      ],
      impact: [
        SMTP_RESTRICTIONS.has(action)
          ? 'The SMTP restriction is lifted.'
          : PROVIDER_ACTIONS.has(action)
            ? 'The change is reverted in the identity provider where the provider supports it (for example the account is enabled again).'
            : 'The effect of the response is reverted.',
      ],
      warnings: ['Rolling back removes the protection this response gave the account.'],
      reversible: false,
    };
  },
  // --- ATO settings ---
  AtoSettingsController_update_v1: (ctx) => {
    const settings = isRecord(ctx.body.settings) ? ctx.body.settings : {};
    const mode = settings.mode;
    return {
      title: 'Update ATO settings',
      action:
        "Replaces the organization's account takeover settings with the values shown; defaults apply to everything else.",
      target: [
        ...target('ATO enabled for the organization', yesNo(ctx.snap.featureEnabled)),
        ...target('Settings version', ctx.snap.version),
        ...target('Current mode', ctx.snap['effective.mode']),
        ...target('Learning period active', yesNo(ctx.snap['learning.active'])),
        ...target('Platform automation', onOff(ctx.snap['automation.platformEnabled'])),
        ...target('Approval window (hours)', ctx.snap['automation.approvalTtlHours']),
      ],
      changes: [
        ...change('Mode', ctx.snap['effective.mode'], mode),
        ...change('Learning (days)', undefined, settings.learningDays),
        ...change(
          'Sections set',
          undefined,
          cappedList(
            keysOf(settings).filter((key) => key !== 'mode' && key !== 'learningDays'),
            12,
          ),
        ),
        ...(isRecord(settings.automation)
          ? change(
              'Automatic responses',
              undefined,
              cappedList(
                Object.entries(settings.automation)
                  .filter(([, item]) => isRecord(item) && item.automatic === true)
                  .map(([key]) => key),
                12,
              ),
            )
          : []),
      ],
      impact: [
        'Each change creates a new settings version; the ATO worker applies it within minutes.',
        'Settings not given return to their defaults.',
      ],
      warnings: [
        ...(mode === 'off'
          ? ['ATO detection is switched off: no signals are scored and no responses run.']
          : mode === 'monitor'
            ? ['ATO detection only records: no responses run automatically.']
            : []),
        'These settings decide how account takeover is detected and answered for the whole organization.',
      ],
      reversible: true,
    };
  },
  // --- ATO identity-provider integrations ---
  AtoProvidersController_create_v1: (ctx) => ({
    title: 'Connect identity-provider integration',
    action: `Binds the provider connection shown for account takeover detection and starts reading its directory telemetry.`,
    target: [
      ...target('Connection', ctx.snap.displayName, true),
      ...target('Connection id', ctx.body.connectionId),
      ...target('Provider', ctx.snap.provider),
      ...target('Connection status', ctx.snap.status),
      ...target('Eligibility', ctx.snap.eligibility),
    ],
    changes:
      ctx.body.settings !== undefined
        ? idpSettingsChanges(ctx.body.settings)
        : change('Settings', undefined, 'the defaults'),
    impact: [
      "The gateway starts reading sign-in and mailbox telemetry of the organization's directory.",
      ...(ctx.snap.eligibility !== undefined &&
      ctx.snap.eligibility !== null &&
      ctx.snap.eligibility !== 'eligible'
        ? [
            `The connection is not eligible (${text(ctx.snap.eligibility) ?? '?'}): the platform refuses the request.`,
          ]
        : []),
    ],
    reversible: true,
  }),
  AtoProvidersController_update_v1: (ctx) => ({
    title: 'Update identity-provider integration',
    action: `Replaces the settings of this integration (the whole document).`,
    target: providerTarget(ctx),
    changes: [
      ...change(
        'Settings version',
        ctx.snap.settingsVersion,
        typeof ctx.snap.settingsVersion === 'number' ? ctx.snap.settingsVersion + 1 : 'next',
      ),
      ...idpSettingsChanges(ctx.body.settings),
    ],
    impact: ['Enabling a stream schedules it now; disabled streams stop being read.'],
    warnings: [
      'The settings decide which data the gateway reads and which response actions it may take in the identity provider.',
    ],
    reversible: true,
  }),
  AtoProvidersController_remove_v1: (ctx) => ({
    title: 'Remove identity-provider integration',
    action: `Removes this integration.`,
    target: providerTarget(ctx),
    changes: [
      ...change('Integration', ctx.snap.status, 'removed'),
      ...change('Reason', undefined, ctx.body.reason),
    ],
    impact: [
      'Telemetry from this identity provider stops, and response actions in it are no longer available.',
    ],
    warnings: [UNDO_REMOVE('integration')],
    reversible: false,
  }),
  AtoProvidersController_backfill_v1: (ctx) => ({
    title: 'Backfill identity-provider telemetry',
    action: `Queues a backfill of ${argList(ctx.body.streams) ?? 'every enabled stream'} of this integration from ${text(ctx.body.from) ?? '?'}.`,
    target: providerTarget(ctx),
    changes: [
      ...change('From', undefined, ctx.body.from),
      ...change('Streams', undefined, argList(ctx.body.streams) ?? 'every enabled stream'),
    ],
    impact: [
      'Past events are read again from the provider; detections may raise incidents for them.',
    ],
    reversible: false,
  }),
  AtoProvidersController_healthCheck_v1: (ctx) => ({
    title: 'Check identity-provider integration',
    action: `Queues a read-only health probe of this integration.`,
    target: providerTarget(ctx),
    changes: change('Health', ctx.snap['health.status'], 'probe requested'),
    impact: ['The result appears on the integration page when the probe has run.'],
    reversible: false,
  }),
  AtoProvidersController_pause_v1: (ctx) => ({
    title: 'Pause identity-provider integration',
    action: `Pauses this integration.`,
    target: providerTarget(ctx),
    changes: [
      ...change('Status', ctx.snap.status, 'paused'),
      ...change('Reason', undefined, ctx.body.reason),
    ],
    impact: [
      'Telemetry is not read while paused; detections based on it stop until it is resumed.',
    ],
    reversible: true,
  }),
  AtoProvidersController_resume_v1: (ctx) => ({
    title: 'Resume identity-provider integration',
    action: `Resumes this integration.`,
    target: providerTarget(ctx),
    changes: change('Status', ctx.snap.status, 'active'),
    impact: ['Telemetry reading restarts from where it stopped.'],
    reversible: true,
  }),
  // --- incidents ---
  IncidentsController_create_v1: (ctx) => {
    const subject = isRecord(ctx.body.subject) ? ctx.body.subject : {};
    return {
      title: 'Open incident',
      action: `Opens an incident of the category ${text(ctx.body.category) ?? '?'} for this account.`,
      target: [
        ...target('Account', ctx.snap.address, true),
        ...target('Account id', subject.id),
        ...target('Risk', ctx.snap.riskLevel),
        ...target('Active incident', ctx.snap['activeIncident.id'] ?? 'none'),
        ...target('Active incident status', ctx.snap['activeIncident.status']),
      ],
      changes: [
        ...change('Category', undefined, ctx.body.category),
        ...change('Severity', undefined, ctx.body.severity),
        ...change('Reason', undefined, ctx.body.reason),
      ],
      impact: [
        ctx.snap['activeIncident.id'] !== null && ctx.snap['activeIncident.id'] !== undefined
          ? 'The account already has an active incident; check it before opening another one.'
          : 'The incident appears on the Incidents page for triage.',
      ],
      reversible: false,
    };
  },
  IncidentsController_update_v1: (ctx) => {
    const resolution = isRecord(ctx.body.resolution) ? ctx.body.resolution : {};
    return {
      title: 'Update incident',
      action: 'Changes the incident as shown below.',
      target: incidentTarget(ctx),
      changes: [
        ...change('Status', ctx.snap.status, ctx.body.status),
        ...change('Severity', ctx.snap.severity, ctx.body.severity),
        ...(ctx.body.assigneeId !== undefined
          ? change('Assignee', ctx.snap.assigneeId, ctx.body.assigneeId ?? '(nobody)')
          : []),
        ...change('Resolution', undefined, resolution.code),
        ...change('Resolution note', undefined, resolution.note),
        ...change('Note', undefined, ctx.body.note),
        ...(ctx.body.categoryFeedback !== undefined
          ? change('Category feedback', undefined, cappedList(keysOf(ctx.body.categoryFeedback)))
          : []),
      ],
      impact: [
        ...(ctx.body.status === 'resolved' || ctx.body.status === 'false_positive'
          ? ['The incident is closed.']
          : []),
        'Fields not shown keep their values.',
      ],
      reversible: ctx.body.status !== 'resolved' && ctx.body.status !== 'false_positive',
    };
  },
  IncidentsController_addNote_v1: (ctx) => ({
    title: 'Add incident note',
    action: 'Adds a note to the incident timeline.',
    target: incidentTarget(ctx),
    changes: change('Note', undefined, ctx.body.note),
    impact: ['The note is visible to everyone who can read the incident.'],
    reversible: false,
  }),
  // --- BEC ---
  BecExecutivesController_create_v1: (ctx) => ({
    title: 'Add protected executive',
    action: `Adds the executive ${quoted(ctx.body.displayName, '(unnamed)')} to BEC impersonation protection.`,
    target: target('Executive', ctx.body.displayName),
    changes: [
      ...change('Name', undefined, ctx.body.displayName),
      ...change('Title', undefined, ctx.body.title),
      ...change('Aliases', undefined, argList(ctx.body.aliases)),
      ...change('Known addresses', undefined, argList(ctx.body.knownAddresses)),
      ...change('Enabled', undefined, yesNo(ctx.body.enabled ?? true)),
    ],
    impact: ["Mail that impersonates this executive's name is flagged by BEC detection."],
    reversible: true,
  }),
  BecExecutivesController_update_v1: (ctx) => ({
    title: 'Update protected executive',
    action: `Changes the protected executive ${quoted(ctx.snap.displayName, 'shown')}.`,
    target: executiveTarget(ctx),
    changes: [
      ...change('Name', ctx.snap.displayName, ctx.body.displayName),
      ...(ctx.body.title !== undefined
        ? change('Title', ctx.snap.title, ctx.body.title ?? '(none)')
        : []),
      ...change('Aliases', undefined, argList(ctx.body.aliases)),
      ...change(
        'Known addresses',
        snapList(ctx.snap.knownAddresses),
        argList(ctx.body.knownAddresses),
      ),
      ...change('Enabled', yesNo(ctx.snap.enabled), yesNo(ctx.body.enabled)),
    ],
    impact: [
      ctx.body.enabled === false
        ? 'Impersonation of this executive is no longer detected.'
        : 'BEC detection uses the changed executive for new mail.',
    ],
    reversible: true,
  }),
  BecExecutivesController_remove_v1: (ctx) => ({
    title: 'Remove protected executive',
    action: `Removes the executive ${quoted(ctx.snap.displayName, 'shown')} from BEC impersonation protection.`,
    target: executiveTarget(ctx),
    changes: change('Executive', 'protected', 'removed'),
    impact: ['Impersonation of this executive is no longer detected.'],
    warnings: [UNDO_DELETE],
    reversible: false,
  }),
  BecTrustedSendersController_create_v1: (ctx) => ({
    title: 'Add BEC trusted sender',
    action: `Trusts the ${text(ctx.body.kind) ?? 'sender'} ${quoted(ctx.body.value, '?')} for BEC detection.`,
    target: [...target('Kind', ctx.body.kind), ...target('Value', ctx.body.value)],
    changes: [
      ...change('Kind', undefined, ctx.body.kind),
      ...change('Value', undefined, ctx.body.value),
      ...change('Reason', undefined, ctx.body.reason),
      ...change('Expires at', undefined, expiryText(ctx.body.expiresAt)),
    ],
    impact: ['Authenticated mail from this sender skips BEC findings.'],
    warnings: [
      'A compromised trusted sender is no longer flagged when its mail authenticates.',
      ...(ctx.body.expiresAt === undefined || ctx.body.expiresAt === null
        ? ['The trust never expires.']
        : []),
    ],
    reversible: true,
  }),
  BecTrustedSendersController_update_v1: (ctx) => ({
    title: 'Update BEC trusted sender',
    action: `Changes the trusted sender ${quoted(ctx.snap.value, 'shown')}.`,
    target: trustedSenderTarget(ctx),
    changes: [
      ...change('Reason', ctx.snap.reason, ctx.body.reason),
      ...(ctx.body.expiresAt !== undefined
        ? change('Expires at', expiryText(ctx.snap.expiresAt), expiryText(ctx.body.expiresAt))
        : []),
    ],
    impact: [
      'Authenticated mail from this sender keeps skipping BEC findings until the trust expires.',
    ],
    reversible: true,
  }),
  BecTrustedSendersController_remove_v1: (ctx) => ({
    title: 'Remove BEC trusted sender',
    action: `Removes the trusted sender ${quoted(ctx.snap.value, 'shown')}.`,
    target: trustedSenderTarget(ctx),
    changes: change('Trusted sender', 'trusted', 'removed'),
    impact: ['Mail from this sender is checked by BEC detection again.'],
    warnings: [UNDO_REMOVE('sender')],
    reversible: false,
  }),
  BecVendorsController_create_v1: (ctx) => ({
    title: 'Add protected vendor',
    action: `Adds the vendor ${quoted(ctx.body.name, '(unnamed)')} to BEC impersonation protection.`,
    target: target('Vendor', ctx.body.name),
    changes: [
      ...change('Name', undefined, ctx.body.name),
      ...change('Aliases', undefined, argList(ctx.body.aliases)),
      ...change('Domains', undefined, argList(ctx.body.domains)),
      ...change('Known senders', undefined, argList(ctx.body.knownSenders)),
      ...change(
        'Payment-change sensitive',
        undefined,
        yesNo(ctx.body.paymentChangeSensitive ?? true),
      ),
      ...change('Enabled', undefined, yesNo(ctx.body.enabled ?? true)),
    ],
    impact: ['Mail that impersonates this vendor is flagged by BEC detection.'],
    reversible: true,
  }),
  BecVendorsController_update_v1: (ctx) => ({
    title: 'Update protected vendor',
    action: `Changes the protected vendor ${quoted(ctx.snap.name, 'shown')}.`,
    target: vendorTarget(ctx),
    changes: [
      ...change('Name', ctx.snap.name, ctx.body.name),
      ...change('Aliases', undefined, argList(ctx.body.aliases)),
      ...change('Domains', snapList(ctx.snap.domains), argList(ctx.body.domains)),
      ...change('Known senders', snapList(ctx.snap.knownSenders), argList(ctx.body.knownSenders)),
      ...change(
        'Payment-change sensitive',
        yesNo(ctx.snap.paymentChangeSensitive),
        yesNo(ctx.body.paymentChangeSensitive),
      ),
      ...change('Enabled', yesNo(ctx.snap.enabled), yesNo(ctx.body.enabled)),
    ],
    impact: [
      ctx.body.enabled === false
        ? 'Impersonation of this vendor is no longer detected.'
        : 'BEC detection uses the changed vendor for new mail.',
    ],
    reversible: true,
  }),
  BecVendorsController_remove_v1: (ctx) => ({
    title: 'Remove protected vendor',
    action: `Removes the vendor ${quoted(ctx.snap.name, 'shown')} from BEC impersonation protection.`,
    target: vendorTarget(ctx),
    changes: change('Vendor', 'protected', 'removed'),
    impact: [
      'Impersonation of this vendor and its payment-change requests are no longer detected.',
    ],
    warnings: [UNDO_DELETE],
    reversible: false,
  }),
  BecFeedbackController_deleteSuppression_v1: (ctx) => ({
    title: 'Delete BEC suppression',
    action: `Deletes the suppression of the BEC finding ${text(ctx.snap.reasonCode) ?? '?'} for the sender ${text(ctx.snap.senderScope) ?? 'scope'}.`,
    target: [
      ...target('Suppression', ctx.args.id),
      ...target('Reason code', ctx.snap.reasonCode),
      ...target('Sender scope', ctx.snap.senderScope),
      ...target('Sender', ctx.snap.senderValue, true),
      ...target('Expires at', ctx.snap.expiresAt),
    ],
    changes: change('Suppression', 'active', 'deleted'),
    impact: ['BEC findings with this reason code are raised again for the sender.'],
    reversible: false,
  }),
  BecMessageFeedbackController_record_v1: (ctx) => {
    const suppress = isRecord(ctx.body.suppress) ? ctx.body.suppress : null;
    return {
      title: 'Record BEC feedback',
      action: `Records ${ctx.body.kind === 'false_negative' ? 'a missed BEC finding (false negative)' : 'a false BEC finding (false positive)'} for this message.`,
      target: [
        ...target('Message', ctx.args.messageId),
        ...target('Scan', ctx.args.scanId),
        ...target('Subject', ctx.snap.subject, true),
        ...target('Sender', ctx.snap.headerFrom, true),
        ...target('Direction', ctx.snap.direction),
        ...target('Verdict', ctx.snap.finalVerdict),
      ],
      changes: [
        ...change('Feedback', undefined, ctx.body.kind),
        ...change('Reason codes', undefined, argList(ctx.body.reasonCodes)),
        ...change('Note', undefined, ctx.body.note),
        ...(suppress
          ? change(
              'Suppress',
              undefined,
              `${argList(suppress.codes) ?? '?'} for the sender ${text(suppress.scope) ?? '?'} for ${text(suppress.days) ?? '?'} days`,
            )
          : []),
      ],
      impact: [
        'The feedback is recorded for BEC tuning.',
        ...(suppress
          ? [
              `Findings with these codes are not raised for the sender ${text(suppress.scope) ?? 'scope'} for ${text(suppress.days) ?? '?'} days.`,
            ]
          : []),
      ],
      reversible: false,
    };
  },
  // --- DLP ---
  DlpComplianceController_enable_v1: (ctx) => ({
    title: 'Enable Aadhaar detection',
    action: 'Turns on Aadhaar number detection for the organization with the recorded basis.',
    target: [
      ...target('Aadhaar detection', onOff(ctx.snap['aadhaar.enabled'])),
      ...target('Current basis', ctx.snap['aadhaar.basis']),
      ...target('Review due', ctx.snap['aadhaar.reviewDueAt']),
    ],
    changes: [
      ...change('Aadhaar detection', onOff(ctx.snap['aadhaar.enabled']), 'on'),
      ...change('Basis', ctx.snap['aadhaar.basis'], ctx.body.basis),
      ...change('Reference', ctx.snap['aadhaar.reference'], ctx.body.reference),
      ...change('Attested', yesNo(ctx.snap['aadhaar.attested']), yesNo(ctx.body.attested)),
      ...change('Review due', ctx.snap['aadhaar.reviewDueAt'], ctx.body.reviewDueAt),
    ],
    impact: ['DLP detects Aadhaar numbers in mail of the organization.'],
    warnings: [
      'You attest that the organization has a lawful basis to process Aadhaar numbers; the attestation is audited.',
    ],
    reversible: true,
  }),
  DlpComplianceController_disable_v1: (ctx) => ({
    title: 'Disable Aadhaar detection',
    action: 'Turns off Aadhaar number detection for the organization.',
    target: [
      ...target('Aadhaar detection', onOff(ctx.snap['aadhaar.enabled'])),
      ...target('Basis', ctx.snap['aadhaar.basis']),
    ],
    changes: change('Aadhaar detection', onOff(ctx.snap['aadhaar.enabled']), 'off'),
    impact: ['Aadhaar numbers are no longer detected in mail of the organization.'],
    warnings: ['Mail carrying Aadhaar numbers is no longer held or blocked by DLP.'],
    reversible: true,
  }),
  DlpDictionariesController_create_v1: (ctx) => ({
    title: 'Create DLP dictionary',
    action: `Creates the DLP dictionary ${quoted(ctx.body.name, '(unnamed)')} with ${plural(argStrings(ctx.body.terms).length, 'term')}.`,
    target: [...target('Dictionary', ctx.body.name), ...target('Category', ctx.body.category)],
    changes: [
      ...change('Name', undefined, ctx.body.name),
      ...change('Category', undefined, ctx.body.category),
      ...change('Severity', undefined, ctx.body.severity),
      ...change('Terms', undefined, termsText(ctx.body.terms)),
      ...change('Minimum matches', undefined, ctx.body.minMatches),
      ...change('Base confidence', undefined, ctx.body.baseConfidence),
      ...change('Enabled', undefined, yesNo(ctx.body.enabled ?? true)),
    ],
    impact: ['Mail is matched against the dictionary once a DLP rule selects it.'],
    reversible: true,
  }),
  DlpDictionariesController_update_v1: (ctx) => ({
    title: 'Update DLP dictionary',
    action: `Changes the DLP dictionary ${quoted(ctx.snap.name, 'shown')}.`,
    target: dictionaryTarget(ctx),
    changes: [
      ...change('Name', ctx.snap.name, ctx.body.name),
      ...change('Category', ctx.snap.category, ctx.body.category),
      ...change('Severity', ctx.snap.severity, ctx.body.severity),
      ...change(
        'Terms',
        typeof ctx.snap.termCount === 'number' ? plural(ctx.snap.termCount, 'term') : undefined,
        termsText(ctx.body.terms),
      ),
      ...change('Minimum matches', undefined, ctx.body.minMatches),
      ...change('Base confidence', undefined, ctx.body.baseConfidence),
      ...change('Enabled', yesNo(ctx.snap.enabled), yesNo(ctx.body.enabled)),
    ],
    impact: ['Every DLP rule that selects this dictionary uses the new terms and settings.'],
    reversible: true,
  }),
  DlpDictionariesController_remove_v1: (ctx) => ({
    title: 'Delete DLP dictionary',
    action: `Deletes the DLP dictionary ${quoted(ctx.snap.name, 'shown')}.`,
    target: dictionaryTarget(ctx),
    changes: change('Dictionary', 'active', 'deleted'),
    impact: ['DLP rules that select this dictionary no longer match its terms.'],
    warnings: [UNDO_DELETE],
    reversible: false,
  }),
  DlpExceptionsController_create_v1: (ctx) => {
    const filters = isRecord(ctx.body.filters) ? ctx.body.filters : {};
    const scope = DLP_SCOPE_WORDS[text(ctx.body.scope) ?? ''] ?? 'the scope';
    return {
      title: 'Add DLP exception',
      action: `Exempts ${scope} ${quoted(ctx.body.value, '?')} from DLP until ${text(ctx.body.expiresAt) ?? '?'}.`,
      target: [
        ...target('Scope', ctx.body.scope),
        ...target('Value', ctx.body.value),
        ...target('Policy', ctx.body.policyId ?? 'every DLP policy'),
        ...target('Rule', ctx.body.ruleId),
      ],
      changes: [
        ...change('Scope', undefined, ctx.body.scope),
        ...change('Value', undefined, ctx.body.value),
        ...change('Detectors', undefined, argList(filters.detectors)),
        ...change('Categories', undefined, argList(filters.categories)),
        ...change('Reason', undefined, ctx.body.reason),
        ...change('Expires at', undefined, ctx.body.expiresAt),
        ...change('Enabled', undefined, yesNo(ctx.body.enabled ?? true)),
      ],
      impact: [
        'Matching mail of this scope is not held or blocked by DLP while the exception applies.',
      ],
      warnings: [
        'Mail from or to this scope can carry sensitive data out without a DLP action.',
        ...(ctx.body.policyId === undefined ? ['The exception applies to every DLP policy.'] : []),
      ],
      reversible: true,
    };
  },
  DlpExceptionsController_update_v1: (ctx) => {
    const filters = isRecord(ctx.body.filters) ? ctx.body.filters : null;
    return {
      title: 'Update DLP exception',
      action: `Changes the DLP exception for ${quoted(ctx.snap.value, 'the scope shown')}.`,
      target: exceptionTarget(ctx),
      changes: [
        ...change('Reason', ctx.snap.reason, ctx.body.reason),
        ...change('Expires at', ctx.snap.expiresAt, ctx.body.expiresAt),
        ...change('Enabled', yesNo(ctx.snap.enabled), yesNo(ctx.body.enabled)),
        ...(ctx.body.filters === null
          ? change('Filters', undefined, 'none (every detector and category)')
          : filters
            ? [
                ...change('Detectors', undefined, argList(filters.detectors)),
                ...change('Categories', undefined, argList(filters.categories)),
              ]
            : []),
      ],
      impact: [
        ctx.body.enabled === false
          ? 'DLP applies to this scope again while the exception is disabled.'
          : 'Matching mail of this scope is not held or blocked by DLP while the exception applies.',
      ],
      reversible: true,
    };
  },
  DlpExceptionsController_remove_v1: (ctx) => ({
    title: 'Delete DLP exception',
    action: `Deletes the DLP exception for ${quoted(ctx.snap.value, 'the scope shown')}.`,
    target: exceptionTarget(ctx),
    changes: change('Exception', ctx.snap.enabled === false ? 'disabled' : 'active', 'deleted'),
    impact: ['DLP applies to this scope again.'],
    warnings: [UNDO_REMOVE('exception')],
    reversible: false,
  }),
  DlpPatternsController_create_v1: (ctx) => ({
    title: 'Create DLP pattern',
    action: `Creates the DLP pattern ${quoted(ctx.body.name, '(unnamed)')}.`,
    target: [...target('Pattern', ctx.body.name), ...target('Severity', ctx.body.severity)],
    changes: patternChanges(ctx),
    impact: ['Mail is matched against the pattern once a DLP rule selects it.'],
    reversible: true,
  }),
  DlpPatternsController_update_v1: (ctx) => ({
    title: 'Update DLP pattern',
    action: `Changes the DLP pattern ${quoted(ctx.snap.name, 'shown')}.`,
    target: patternTarget(ctx),
    changes: patternChanges(ctx, true),
    impact: ['Every DLP rule that selects this pattern uses the new settings.'],
    reversible: true,
  }),
  DlpPatternsController_remove_v1: (ctx) => ({
    title: 'Delete DLP pattern',
    action: `Deletes the DLP pattern ${quoted(ctx.snap.name, 'shown')}.`,
    target: patternTarget(ctx),
    changes: change('Pattern', 'active', 'deleted'),
    impact: ['DLP rules that select this pattern no longer match it.'],
    warnings: [UNDO_DELETE],
    reversible: false,
  }),
  DlpPoliciesController_create_v1: (ctx) => ({
    title: 'Create DLP policy',
    action: `Creates the DLP policy ${quoted(ctx.body.name, '(unnamed)')}.`,
    target: target('DLP policy', ctx.body.name),
    changes: [
      ...change('Name', undefined, ctx.body.name),
      ...change('Description', undefined, ctx.body.description),
      ...change('Enabled', undefined, yesNo(ctx.body.enabled ?? true)),
      ...change('Mode', undefined, ctx.body.mode ?? 'enforce'),
      ...change('Priority', undefined, ctx.body.priority),
      ...change('Directions', undefined, argList(ctx.body.directions) ?? 'outbound, internal'),
    ],
    impact: [
      'The policy has no rules yet: it acts on mail once rules are added.',
      ...(ctx.body.mode === 'monitor' ? ['In monitor mode matches are only recorded.'] : []),
    ],
    reversible: true,
  }),
  DlpPoliciesController_update_v1: (ctx) => ({
    title: 'Update DLP policy',
    action: `Changes the DLP policy ${quoted(ctx.snap.name, 'shown')}.`,
    target: dlpPolicyTarget(ctx),
    changes: [
      ...change('Name', ctx.snap.name, ctx.body.name),
      ...(ctx.body.description !== undefined
        ? change('Description', undefined, ctx.body.description ?? '(none)')
        : []),
      ...change('Enabled', yesNo(ctx.snap.enabled), yesNo(ctx.body.enabled)),
      ...change('Mode', ctx.snap.mode, ctx.body.mode),
      ...change('Priority', ctx.snap.priority, ctx.body.priority),
      ...change('Directions', undefined, argList(ctx.body.directions)),
    ],
    impact: [
      ctx.body.enabled === false
        ? 'The policy and its rules stop evaluating new mail.'
        : ctx.body.mode === 'monitor'
          ? 'Matches are only recorded; mail is no longer held or blocked by this policy.'
          : 'DLP evaluates new mail with the changed policy.',
    ],
    reversible: true,
  }),
  DlpPoliciesController_remove_v1: (ctx) => ({
    title: 'Delete DLP policy',
    action: `Deletes the DLP policy ${quoted(ctx.snap.name, 'shown')} with its rules.`,
    target: dlpPolicyTarget(ctx),
    changes: change('DLP policy', ctx.snap.enabled === false ? 'disabled' : 'active', 'deleted'),
    impact: ['Its rules stop evaluating mail.'],
    warnings: [UNDO_DELETE],
    reversible: false,
  }),
  DlpPoliciesController_createRule_v1: (ctx) => ({
    title: 'Add DLP rule',
    action: `Adds the rule ${quoted(ctx.body.name, '(unnamed)')} to the DLP policy ${quoted(ctx.snap.name, 'shown')}.`,
    target: [
      ...target('DLP policy', ctx.snap.name),
      ...target('DLP policy id', ctx.args.id),
      ...target('Mode', ctx.snap.mode),
      ...target('Rules now', ctx.snap.ruleCount),
    ],
    changes: [
      ...change('Name', undefined, ctx.body.name),
      ...change('Action', undefined, ctx.body.action),
      ...change('Enabled', undefined, yesNo(ctx.body.enabled ?? true)),
      ...change('Priority', undefined, ctx.body.priority),
      ...dlpConditionChanges(ctx.body.conditions),
    ],
    impact: [
      ctx.snap.mode === 'monitor'
        ? 'The policy is in monitor mode: matches are only recorded.'
        : `Matching mail is ${DLP_RULE_ACTIONS[text(ctx.body.action) ?? ''] ?? 'handled by the rule'}.`,
    ],
    reversible: true,
  }),
  DlpPoliciesController_updateRule_v1: (ctx) => ({
    title: 'Update DLP rule',
    action: `Changes the DLP rule ${quoted(ctx.snap.name, 'shown')}.`,
    target: dlpRuleTarget(ctx),
    changes: [
      ...change('Name', ctx.snap.name, ctx.body.name),
      ...change('Action', ctx.snap.action, ctx.body.action),
      ...change('Enabled', yesNo(ctx.snap.enabled), yesNo(ctx.body.enabled)),
      ...change('Priority', ctx.snap.priority, ctx.body.priority),
      ...dlpConditionChanges(ctx.body.conditions),
    ],
    impact: [
      ctx.body.enabled === false
        ? 'The rule stops matching new mail.'
        : ctx.body.action !== undefined
          ? `Matching mail is ${DLP_RULE_ACTIONS[text(ctx.body.action) ?? ''] ?? 'handled by the rule'}.`
          : 'DLP evaluates new mail with the changed rule.',
    ],
    reversible: true,
  }),
  DlpPoliciesController_removeRule_v1: (ctx) => ({
    title: 'Delete DLP rule',
    action: `Deletes the DLP rule ${quoted(ctx.snap.name, 'shown')}.`,
    target: dlpRuleTarget(ctx),
    changes: change('Rule', ctx.snap.enabled === false ? 'disabled' : 'active', 'deleted'),
    impact: ['Mail matched by this rule is no longer handled by it.'],
    warnings: [UNDO_DELETE],
    reversible: false,
  }),
  // --- risk-scoring profiles ---
  RiskProfilesController_createDraft_v1: (ctx) => ({
    title: 'Create risk profile draft',
    action: "Creates a draft version of the organization's risk-scoring profile.",
    target: target('Based on version', ctx.body.basedOnVersionId ?? 'the active profile'),
    changes: [
      ...change('Overridden sections', undefined, cappedList(keysOf(ctx.body.overrides), 12)),
      ...change('Change note', undefined, ctx.body.changeNote),
    ],
    impact: ['Nothing changes for mail until the draft is published and activated.'],
    reversible: true,
  }),
  RiskProfilesController_updateDraft_v1: (ctx) => ({
    title: 'Update risk profile draft',
    action: `Replaces the overrides of the draft ${version(ctx.snap.versionNo) ?? ''} of the risk-scoring profile.`,
    target: riskVersionTarget(ctx),
    changes: [
      ...change('Overridden sections', undefined, cappedList(keysOf(ctx.body.overrides), 12)),
      ...change('Change note', ctx.snap.changeNote, ctx.body.changeNote),
    ],
    impact: ['Nothing changes for mail until the draft is published and activated.'],
    reversible: true,
  }),
  RiskProfilesController_deleteDraft_v1: (ctx) => ({
    title: 'Delete risk profile draft',
    action: `Deletes the draft ${version(ctx.snap.versionNo) ?? ''} of the risk-scoring profile.`,
    target: riskVersionTarget(ctx),
    changes: change('Draft', ctx.snap.status, 'deleted'),
    impact: ['Scoring does not change: only the draft is removed.'],
    warnings: [UNDO_DELETE],
    reversible: false,
  }),
  RiskProfilesController_publish_v1: (ctx) => {
    const activate = ctx.body.activate !== false;
    return {
      title: 'Publish risk profile version',
      action: `Publishes the draft ${version(ctx.snap.versionNo) ?? ''} of the risk-scoring profile${activate ? ' and activates it' : ''}.`,
      target: riskVersionTarget(ctx),
      changes: [
        ...change('Status', ctx.snap.status, 'published'),
        ...change('Active', yesNo(ctx.snap.active), activate ? 'yes' : yesNo(ctx.snap.active)),
      ],
      impact: [
        activate
          ? `New mail is scored with this version. ${RISK_NEXT_ROUND}`
          : 'The version can be activated later; scoring does not change now.',
      ],
      reversible: true,
    };
  },
  RiskProfilesController_activate_v1: (ctx) => ({
    title: 'Activate risk profile version',
    action: `Makes the version ${text(ctx.args.versionId) ?? '?'} the active risk-scoring profile of the organization.`,
    target: [...target('Version id', ctx.args.versionId), ...riskProfileTarget(ctx)],
    changes: change(
      'Active version',
      version(ctx.snap['active.versionNo']) ?? ctx.snap['active.source'] ?? null,
      text(ctx.args.versionId) ?? '?',
    ),
    impact: [`New mail is scored with this version. ${RISK_NEXT_ROUND}`],
    reversible: true,
  }),
  RiskProfilesController_reset_v1: (ctx) => ({
    title: 'Reset risk profile',
    action: 'Returns the organization to the platform risk-scoring profile; its versions are kept.',
    target: riskProfileTarget(ctx),
    changes: change(
      'Active profile',
      ctx.snap['active.source'] === 'tenant'
        ? (version(ctx.snap['active.versionNo']) ?? 'tenant')
        : ctx.snap['active.source'],
      'platform',
    ),
    impact: [
      ctx.snap['active.source'] === 'platform'
        ? 'The platform profile is already active: nothing changes.'
        : `New mail is scored with the platform profile. ${RISK_NEXT_ROUND}`,
    ],
    warnings: [
      "The organization's own thresholds, actions and hard blocks no longer apply until a version is activated again.",
    ],
    reversible: true,
  }),
  // --- platform operations ---
  AttachmentRescansController_request_v1: (ctx) => {
    const organization = text(ctx.body.organizationId);
    const dry = ctx.body.dryRun === true;
    return {
      title: dry ? 'Estimate attachment rescan' : 'Request attachment rescan',
      action: `Rescans up to ${text(ctx.body.maxMessages) ?? 'the platform maximum of'} messages with attachments received in the last ${text(ctx.body.windowHours) ?? '?'} hours in ${organization ? 'one organization' : 'every organization'}.`,
      target: [
        ...target('Organization', organization ?? 'every organization'),
        ...target('Window (hours)', ctx.body.windowHours),
        ...target('States', argList(ctx.body.states) ?? RESCAN_STATES),
      ],
      changes: [
        ...change('Maximum messages', undefined, ctx.body.maxMessages),
        ...change('Dry run', undefined, yesNo(dry)),
        ...change('Reason', undefined, ctx.body.reason),
      ],
      impact: [
        ...(dry ? ['Dry run: nothing is rescanned; only the estimate is returned.'] : []),
        'Messages are scanned again with the current signatures; verdicts can change and messages can be quarantined.',
        ...(organization ? [] : ['Applies to every organization.']),
      ],
      warnings: [
        organization
          ? 'Rescans add load to the scan workers.'
          : 'Rescans messages of every organization and adds load to the scan workers.',
      ],
      reversible: false,
    };
  },
  AttachmentRescansController_cancel_v1: (ctx) => ({
    title: 'Cancel attachment rescan',
    action: 'Cancels the attachment rescan job; messages not yet requested are skipped.',
    target: [
      ...target('Job', ctx.args.jobId),
      ...target('Status', ctx.snap.status),
      ...target('Organization', ctx.snap.organizationId ?? 'every organization'),
      ...target('Window start', ctx.snap.windowStart),
      ...target('Window end', ctx.snap.windowEnd),
      ...target('Maximum messages', ctx.snap.maxMessages),
      ...target('Selected', ctx.snap.selectedCount),
    ],
    changes: [
      ...change('Status', ctx.snap.status, 'cancelled'),
      ...change('Reason', undefined, ctx.body.reason),
    ],
    impact: ['Messages already requested are still rescanned.'],
    warnings: ['A cancelled job cannot be resumed; request a new one instead.'],
    reversible: false,
  }),
  DeadLettersController_replay_v1: (ctx) => {
    const dry = ctx.body.dryRun === true;
    const organization = text(ctx.body.organizationId);
    return {
      title: dry ? 'Dead-letter replay (dry run)' : 'Replay dead letters',
      action: `Moves up to ${text(ctx.body.limit) ?? '?'} dead letters of ${text(ctx.body.sourceQueue) ?? '?'} back to their work queue.`,
      target: [
        ...target('Source queue', ctx.body.sourceQueue),
        ...target('Organization', organization ?? 'every organization'),
      ],
      changes: [
        ...change('Limit', undefined, ctx.body.limit),
        ...change('Event type', undefined, ctx.body.eventType),
        ...change('Failure reason', undefined, ctx.body.failureReason),
        ...change('Dry run', undefined, yesNo(dry)),
        ...change('Reason', undefined, ctx.body.reason),
      ],
      impact: [
        ...(dry ? ['Dry run: nothing is moved; only the matching count is returned.'] : []),
        'Replayed messages are processed again by their consumers; events already processed are skipped as duplicates.',
        ...(organization ? [] : ['Dead letters of every organization can be replayed.']),
      ],
      warnings: ['Replaying adds load to the consumers of the work queue.'],
      reversible: false,
    };
  },
  ScanTrainingController_train_v1: (ctx) => ({
    title: 'Train the shared spam classifiers',
    action: `Sends the stored message to the Rspamd controller to ${TRAINING_WORDS[text(ctx.body.operation) ?? ''] ?? 'train it'}; affects classification for every organization.`,
    target: [
      ...target('Organization', ctx.args.organizationId),
      ...target('Message', ctx.args.messageId),
    ],
    changes: [
      ...change('Operation', undefined, ctx.body.operation),
      ...change('Fuzzy flag', undefined, ctx.body.fuzzyFlag),
      ...change('Reason', undefined, ctx.body.reason),
    ],
    impact: [
      'Classification of similar mail changes for every organization.',
      'The message is not rescanned.',
    ],
    warnings: [
      'Bayes and fuzzy storage are shared by every organization; wrong training lowers detection everywhere.',
    ],
    reversible: ctx.body.operation === 'fuzzy_add' || ctx.body.operation === 'fuzzy_delete',
  }),
  ThreatHashesController_add_v1: (ctx) => ({
    title: 'Add threat hash',
    action: `Adds the SHA-256 ${text(ctx.body.sha256) ?? '?'} to the platform threat catalog.`,
    target: [...target('SHA-256', ctx.body.sha256), ...target('Severity', ctx.body.severity)],
    changes: [
      ...change('MD5', undefined, ctx.body.md5),
      ...change('Severity', undefined, ctx.body.severity),
      ...change('Family', undefined, ctx.body.family),
      ...change('Expires at', undefined, expiryText(ctx.body.expiresAt)),
      ...change('Reason', undefined, ctx.body.reason),
    ],
    impact: [`${EVERY_ORGANIZATION_SCAN} Attachments with this hash are treated as malicious.`],
    warnings: ['A wrong hash blocks legitimate attachments in every organization.'],
    reversible: true,
  }),
  ThreatHashesController_remove_v1: (ctx) => ({
    title: 'Remove threat hash',
    action: `Removes the SHA-256 ${text(ctx.args.sha256) ?? '?'} from the platform threat catalog.`,
    target: [
      ...target('SHA-256', ctx.snap.sha256 ?? ctx.args.sha256),
      ...target('Severity', ctx.snap.severity),
      ...target('Family', ctx.snap.family),
      ...target('Source', ctx.snap.source),
    ],
    changes: [
      ...change('Threat hash', 'listed', 'removed'),
      ...change('Reason', undefined, ctx.args.reason),
    ],
    impact: [`${EVERY_ORGANIZATION_SCAN} Attachments with this hash are no longer matched.`],
    warnings: [UNDO_REMOVE('hash')],
    reversible: false,
  }),
  ThreatIndicatorsController_add_v1: (ctx) => ({
    title: 'Add threat indicator',
    action: `Adds the ${text(ctx.body.type) ?? 'indicator'} ${quoted(ctx.body.value, '?')} to the platform threat catalog.`,
    target: [
      ...target('Type', ctx.body.type),
      ...target('Value', ctx.body.value),
      ...target('Category', ctx.body.category),
    ],
    changes: [
      ...change('Severity', undefined, ctx.body.severity),
      ...change('Category', undefined, ctx.body.category),
      ...change('Expires at', undefined, expiryText(ctx.body.expiresAt)),
      ...change('Reason', undefined, ctx.body.reason),
    ],
    impact: [`${EVERY_ORGANIZATION_SCAN_CLICK} Matching mail and links are treated as malicious.`],
    warnings: ['A wrong indicator blocks legitimate mail or links in every organization.'],
    reversible: true,
  }),
  ThreatIndicatorsController_remove_v1: (ctx) => ({
    title: 'Remove threat indicator',
    action: `Removes the ${text(ctx.snap.type) ?? 'threat'} indicator shown from the platform threat catalog.`,
    target: [
      ...target('Indicator', ctx.args.id),
      ...target('Type', ctx.snap.type),
      ...target('Value', ctx.snap.value, true),
      ...target('Severity', ctx.snap.severity),
      ...target('Category', ctx.snap.category),
      ...target('Source', ctx.snap.source),
    ],
    changes: [
      ...change('Threat indicator', 'listed', 'removed'),
      ...change('Reason', undefined, ctx.args.reason),
    ],
    impact: [
      `${EVERY_ORGANIZATION_SCAN_CLICK} Matching mail and links are no longer flagged by it.`,
    ],
    warnings: [UNDO_REMOVE('indicator')],
    reversible: false,
  }),
};

// ---------------------------------------------------------------------------------------------
// Step AI-5 helpers and templates (design 33 D9)
// ---------------------------------------------------------------------------------------------

/** A snapshot value kept as JSON text (an object or a list of objects), parsed; null when cut. */
function snapJson(value: SnapshotValue | undefined): unknown {
  if (typeof value !== 'string' || !/^[[{]/.test(value)) return null;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
}

/** A count plus the first three values (`2 (10.0.0.0/8, 192.0.2.0/24)`), D9. */
function countAndFirst(items: readonly string[] | null): string | null {
  if (items === null) return null;
  if (items.length === 0) return 'none';
  const shown = items.slice(0, 3).map((item) => sanitizeText(item, 80));
  return `${items.length} (${shown.join(', ')}${items.length > 3 ? ', …' : ''})`;
}

const ON_EXPIRY_WORDS: Readonly<Record<string, string>> = {
  delete: 'deleted',
  review: 'held for review before deletion',
};
const onExpiryText = (value: unknown): string | null => {
  const key = text(value);
  return key === null ? null : (ON_EXPIRY_WORDS[key] ?? sanitizeText(key, 32));
};

/** Retention criteria in words (directions, outcomes, sources; domain, department, rule counts). */
function criteriaWords(criteria: unknown): string {
  if (!isRecord(criteria)) return 'all mail';
  const parts: string[] = [];
  const named = (key: string, label: string) => {
    const values = argStrings(criteria[key]);
    if (values.length > 0) parts.push(`${label} ${cappedList(values, 4)}`);
  };
  const counted = (key: string, noun: string) => {
    const values = argStrings(criteria[key]);
    if (values.length > 0) parts.push(plural(values.length, noun));
  };
  named('directions', 'directions');
  named('categories', 'outcomes');
  named('sources', 'sources');
  counted('domainIds', 'domain');
  counted('departmentIds', 'department');
  counted('policyRuleRefs', 'policy rule');
  return parts.length > 0 ? parts.join('; ') : 'all mail';
}

const RETENTION_APPLIES =
  'Applies to mail captured from now on; records already archived keep their stored dates (a longer retention extends them when they reach their date).';

const retentionTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Retention policy', ctx.snap.name, true),
  ...target('Policy id', ctx.args.policyId),
  ...target('Default policy', yesNo(ctx.snap.isDefault)),
];

/** Archive / journaling settings fields: path under `settings`, label. */
const SETTINGS_FIELDS: ReadonlyArray<{ section: string; key: string; label: string }> = [
  { section: 'directions', key: 'inbound', label: 'Capture inbound mail' },
  { section: 'directions', key: 'outbound', label: 'Capture outbound mail' },
  { section: 'directions', key: 'internal', label: 'Capture internal mail' },
  { section: 'include', key: 'rejected', label: 'Include rejected mail' },
  { section: 'include', key: 'quarantined', label: 'Include quarantined mail' },
  { section: 'include', key: 'failed', label: 'Include failed deliveries' },
  { section: 'scope', key: 'mode', label: 'Scope' },
  { section: 'policyArchive', key: 'enabled', label: 'Archive mail of archive policy actions' },
  { section: 'access', key: 'previewEnabled', label: 'Previews in the portal' },
  { section: 'access', key: 'downloadEnabled', label: 'Downloads in the portal' },
  { section: 'intake', key: 'scanEnabled', label: 'Scan journal intake mail' },
];
const settingValue = (value: unknown): string | null =>
  typeof value === 'boolean' ? onOff(value) : text(value);

/**
 * Before → after of a settings body. `wholeDocument` (archive): every section is replaced and an
 * omitted key returns to its default; otherwise (journaling) only the given sections are
 * replaced and an omitted key inside a given section returns to its default.
 */
function settingsChanges(
  ctx: TemplateContext,
  settings: unknown,
  wholeDocument: boolean,
): ConfirmationChange[] {
  if (!isRecord(settings)) return [];
  const out: ConfirmationChange[] = [];
  for (const field of SETTINGS_FIELDS) {
    const path = `settings.${field.section}.${field.key}`;
    const section = settings[field.section];
    if (!isRecord(section) && !wholeDocument) continue;
    const given = isRecord(section) ? section[field.key] : undefined;
    out.push(
      ...change(
        field.label,
        settingValue(ctx.snap[path]),
        given === undefined ? '(default)' : settingValue(given),
      ),
    );
  }
  const scope = isRecord(settings.scope) ? settings.scope : null;
  if (scope) {
    const counts = [
      ['domainIds', 'domain'],
      ['departmentIds', 'department'],
      ['userIds', 'user'],
      ['addresses', 'address'],
    ]
      .map(([key, noun]) => [argStrings(scope[key!]).length, noun!] as const)
      .filter(([n]) => n > 0)
      .map(([n, noun]) => plural(n, noun));
    out.push(...change('Scope entries', undefined, counts.length > 0 ? counts.join(', ') : 'none'));
  }
  return out;
}

const NO_BACKFILL = 'Applies to mail received from now on (no backfill).';

const IMMUTABILITY_WORDS: Readonly<Record<string, string>> = {
  none: 'none (no Object Lock)',
  governance: 'governance (Object Lock, can be lifted with special permission)',
  compliance: 'compliance (Object Lock, can never be lifted or shortened)',
};
const immutabilityText = (value: unknown): string | null => {
  const key = text(value);
  return key === null ? null : (IMMUTABILITY_WORDS[key] ?? sanitizeText(key, 32));
};

const captureTarget = (ctx: TemplateContext): ConfirmationTarget[] => {
  const sources = [
    ctx.snap['sources.journal'] === true ? 'journal' : null,
    ctx.snap['sources.policy'] === true ? 'policy' : null,
  ].filter((s): s is string => s !== null);
  return [
    ...target('Message id', ctx.args.messageId),
    ...target('Received at', ctx.snap.receivedAt),
    ...target('Capture status', ctx.snap.status),
    ...target('Failure code', ctx.snap.code),
    ...target('Attempts', ctx.snap.attempts),
    ...target('Sources', sources.length > 0 ? sources.join(', ') : null),
  ];
};

/** Never the intake address (I23): name, kind, status, TLS and health only. */
const intakeTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Intake source', ctx.snap.displayName, true),
  ...target('Source id', ctx.args.sourceId),
  ...target('Kind', ctx.snap.kind),
  ...target('Status', ctx.snap.status),
  ...target('TLS required', yesNo(ctx.snap.requireTls)),
  ...target('Health', ctx.snap['health.status']),
];

const caseTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Case', ctx.snap.name, true),
  ...target('Case id', ctx.args.caseId),
  ...target('Matter reference', ctx.snap.matterReference, true),
  ...target('Status', ctx.snap.status),
  ...target('Custodians', ctx.snap['counts.custodians']),
  ...target('Active legal holds', ctx.snap['counts.activeHolds']),
];

/** A list argument as a count (`3 senders`), or null when absent. */
const countOf = (value: unknown, noun: string): string | null =>
  value === undefined ? null : plural(argStrings(value).length, noun);
/** Custodians are shown as a count only, never their addresses (D9). */
const custodianCount = (value: unknown): string | null => countOf(value, 'custodian');

const searchTarget = (ctx: TemplateContext, searchId: unknown): ConfirmationTarget[] => [
  ...target('Case id', ctx.args.caseId),
  ...target('Search id', searchId),
  ...target('Search status', ctx.snap.status),
  ...target('Hits', ctx.snap.hitCount),
  ...target('Hits truncated', yesNo(ctx.snap.truncated)),
  ...target('Index complete', yesNo(ctx.snap.indexComplete)),
];

const REVIEW_TAG_WORDS: Readonly<Record<string, string>> = {
  untagged: 'untagged',
  relevant: 'relevant',
  not_relevant: 'not relevant',
  privileged: 'privileged',
};
const reviewTagText = (value: unknown): string => {
  const key = text(value);
  return key === null ? '?' : (REVIEW_TAG_WORDS[key] ?? sanitizeText(key, 32));
};

const connectionTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Connection', ctx.snap.displayName, true),
  ...target('Connection id', ctx.args.id),
  ...target('Provider', ctx.snap.provider),
  ...target('Status', ctx.snap.status),
];
const grantTarget = (ctx: TemplateContext): ConfirmationTarget[] => [
  ...target('Connection id', ctx.args.id),
  ...target('Grant profile', ctx.snap.profile ?? ctx.args.profile),
  ...target('Grant status', ctx.snap.status),
  ...target('Authentication', ctx.snap.authMethod),
];

const CHANGE_KIND_WORDS: Readonly<Record<string, string>> = {
  inbound: 'route inbound mail of linked domains to the provider',
  outbound: 'turn on outbound relay through the gateway (probes only)',
  activate: 'activate outbound relay and internal routing as chosen',
  proof: 'change the relay proof policy',
  suspend: 'suspend outbound relay',
  disable_outbound: 'turn outbound relay off',
  disable: 'disconnect the connection',
};

/** `host:port` of preview servers (JSON from the snapshot), or null when cut. */
function previewServers(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  return value.map((server) =>
    isRecord(server) ? serverText(server.host, server.port, server.priority) : '?',
  );
}

/**
 * The preview's change set (D9): per domain current → proposed destination servers, the connector
 * action, connection fields from → to, grants revoked. Never the impact token.
 */
function changeSetChanges(ctx: TemplateContext): ConfirmationChange[] {
  const p = 'preview.changeSet';
  const names = snapStrings(ctx.snap[`${p}.domains[].name`]) ?? [];
  const changed = snapshotList(ctx.snap[`${p}.domains[].changed`]) ?? [];
  const currentServers = snapJson(ctx.snap[`${p}.domains[].current.servers`]);
  const proposedServers = snapJson(ctx.snap[`${p}.domains[].proposed.servers`]);
  const currentProviders = snapshotList(ctx.snap[`${p}.domains[].current.provider`]) ?? [];
  const proposedProviders = snapshotList(ctx.snap[`${p}.domains[].proposed.provider`]) ?? [];
  const out: ConfirmationChange[] = [];
  names.slice(0, 20).forEach((name, i) => {
    const before = Array.isArray(currentServers) ? previewServers(currentServers[i]) : null;
    const after = Array.isArray(proposedServers) ? previewServers(proposedServers[i]) : null;
    const beforeText =
      before !== null
        ? cappedList(before, 3)
        : (text(currentProviders[i]) ?? 'see the preview in the portal');
    const afterText =
      after !== null
        ? cappedList(after, 3)
        : (text(proposedProviders[i]) ?? 'see the preview in the portal');
    out.push({
      label: `Inbound destination of ${sanitizeText(name, 80)}${changed[i] === false ? ' (unchanged)' : ''}`,
      before: beforeText,
      after: afterText,
    });
  });
  if (names.length > 20) out.push(...change('Further domains', undefined, names.length - 20));
  out.push(...change('Relay connector', undefined, ctx.snap[`${p}.connector.action`]));
  const fields = snapStrings(ctx.snap[`${p}.connection[].field`]) ?? [];
  const from = snapshotList(ctx.snap[`${p}.connection[].from`]);
  const to = snapshotList(ctx.snap[`${p}.connection[].to`]);
  fields.forEach((field, i) => {
    out.push({
      label: `Connection ${sanitizeText(field, 32)}`,
      before: from ? (text(from[i]) ?? 'null') : 'see the preview in the portal',
      after: to ? (text(to[i]) ?? 'null') : 'see the preview in the portal',
    });
  });
  const revoked = ctx.snap[`${p}.grantsRevoked`];
  if (typeof revoked === 'number' && revoked > 0)
    out.push(...change('Grants revoked', undefined, revoked));
  return out;
}

/** The preview's warning codes as one impact line, or none. */
const previewWarnings = (ctx: TemplateContext): string[] => {
  const codes = snapStrings(ctx.snap['preview.warnings']);
  return codes && codes.length > 0 ? [`Preview warnings: ${cappedList(codes, 5)}.`] : [];
};

const CHAT_NO_SECRETS =
  'Credentials, OAuth consent and validation runs stay in the portal; chat never handles them.';

const AI5_TEMPLATES: Readonly<Record<string, Template>> = {
  // --- archive retention ---
  ArchiveRetentionController_create_v1: (ctx) => {
    const onExpiry = ctx.body.onExpiry ?? 'delete';
    return {
      title: 'Create retention policy',
      action: `Creates the retention policy ${quoted(ctx.body.name, '(unnamed)')}: matching mail is kept for ${text(ctx.body.retentionDays) ?? '?'} days, then ${onExpiryText(onExpiry) ?? '?'}.`,
      target: target('Retention policy', ctx.body.name),
      changes: [
        ...change('Name', undefined, ctx.body.name),
        ...change('Retention (days)', undefined, ctx.body.retentionDays),
        ...change('On expiry', undefined, onExpiryText(onExpiry)),
        ...change('Priority', undefined, ctx.body.priority ?? 100),
        ...change('Applies to', undefined, criteriaWords(ctx.body.criteria)),
      ],
      impact: [
        RETENTION_APPLIES,
        'Policies are ranked by priority: this policy can take precedence over the default policy for the mail it matches.',
      ],
      warnings: [
        'The new policy can give the mail it matches a shorter retention than the default policy.',
        ...(onExpiry === 'delete' ? [AI5_ESCALATION_WARNINGS.expiryDelete] : []),
      ],
      reversible: true,
    };
  },
  ArchiveRetentionController_update_v1: (ctx) => {
    const before = snapJson(ctx.snap.criteria);
    return {
      title: 'Change retention policy',
      action: `Replaces this retention policy (the whole policy: fields you leave out return to their defaults).`,
      target: retentionTarget(ctx),
      changes: [
        ...change('Name', undefined, ctx.body.name),
        ...change('Retention (days)', ctx.snap.retentionDays, ctx.body.retentionDays),
        ...change(
          'On expiry',
          onExpiryText(ctx.snap.onExpiry),
          onExpiryText(ctx.body.onExpiry ?? 'delete'),
        ),
        ...change('Priority', ctx.snap.priority, ctx.body.priority ?? 100),
        ...change(
          'Applies to',
          before === null ? 'see the policy in the portal' : criteriaWords(before),
          criteriaWords(ctx.body.criteria ?? {}),
        ),
      ],
      impact: [RETENTION_APPLIES],
      reversible: true,
    };
  },
  ArchiveRetentionController_delete_v1: (ctx) => ({
    title: 'Delete retention policy',
    action: 'Deletes this retention policy.',
    target: [
      ...retentionTarget(ctx),
      ...target('Retention (days)', ctx.snap.retentionDays),
      ...target('On expiry', onExpiryText(ctx.snap.onExpiry)),
    ],
    changes: change('Retention policy', 'active', 'deleted'),
    impact: [
      'Records captured under it keep their stored retention; new mail it would have matched falls to another policy.',
    ],
    warnings: [UNDO_DELETE],
    reversible: false,
  }),
  // --- capture issues ---
  ArchiveAdminController_retry_v1: (ctx) => ({
    title: 'Retry archive capture',
    action: 'The archive retries capturing this message now.',
    target: captureTarget(ctx),
    changes: change('Capture status', ctx.snap.status, 'pending'),
    impact: [
      'The archive retries capturing this message now.',
      'The capture issues page shows the result.',
    ],
    reversible: false,
  }),
  // --- archive and journaling settings ---
  ArchiveAdminController_update_v1: (ctx) => {
    const off = ctx.body.enabled === false;
    return {
      title: 'Change archive settings',
      action: off
        ? 'Turns archiving off for the organization.'
        : ctx.body.settings !== undefined
          ? 'Replaces the archive settings of the organization.'
          : 'Changes the archive settings of the organization.',
      target: [
        ...target('Archiving', onOff(ctx.snap.enabled)),
        ...target('Entitled by plan', yesNo(ctx.snap.entitled)),
        ...target('Immutability', immutabilityText(ctx.snap.immutability)),
        ...target('Object Lock available', yesNo(ctx.snap.objectLockAvailable)),
      ],
      changes: [
        ...(ctx.body.enabled !== undefined
          ? change('Archiving', onOff(ctx.snap.enabled), onOff(ctx.body.enabled))
          : []),
        ...(ctx.body.immutability !== undefined
          ? change(
              'Immutability',
              immutabilityText(ctx.snap.immutability),
              immutabilityText(ctx.body.immutability),
            )
          : []),
        ...(ctx.body.defaultRetentionPolicyId !== undefined
          ? change(
              'Default retention policy',
              ctx.snap.defaultRetentionPolicyId ?? '(none)',
              ctx.body.defaultRetentionPolicyId ?? '(none)',
            )
          : []),
        ...settingsChanges(ctx, ctx.body.settings, true),
      ],
      impact: [
        NO_BACKFILL,
        ...(ctx.body.settings !== undefined
          ? [
              'The settings document is replaced as a whole; keys you leave out return to their defaults.',
            ]
          : []),
      ],
      warnings:
        ctx.body.immutability === 'compliance'
          ? ['Compliance mode can never be turned off or weakened afterwards.']
          : [],
      reversible: ctx.body.immutability !== 'compliance',
    };
  },
  JournalingController_update_v1: (ctx) => {
    const off = ctx.body.enabled === false;
    return {
      title: 'Change journaling settings',
      action: off
        ? 'Turns journaling off for the organization.'
        : ctx.body.settings !== undefined
          ? 'Replaces the given journaling sections of the organization.'
          : 'Changes the journaling settings of the organization.',
      target: [
        ...target('Journaling', onOff(ctx.snap.enabled)),
        ...target('Entitled by plan', yesNo(ctx.snap.entitled)),
      ],
      changes: [
        ...(ctx.body.enabled !== undefined
          ? change('Journaling', onOff(ctx.snap.enabled), onOff(ctx.body.enabled))
          : []),
        ...settingsChanges(ctx, ctx.body.settings, false),
      ],
      impact: [
        NO_BACKFILL,
        ...(ctx.body.settings !== undefined
          ? [
              'Only the given sections are replaced; keys left out inside a given section return to their defaults.',
            ]
          : []),
      ],
      reversible: true,
    };
  },
  // --- journal intake sources (never the address, I23) ---
  IntakeSourcesController_update_v1: (ctx) => {
    const paused = ctx.body.status === 'paused';
    return {
      title: 'Update journal intake source',
      action: paused
        ? 'Pauses this journal intake source.'
        : 'Changes the settings of this journal intake source.',
      target: intakeTarget(ctx),
      changes: [
        ...change('Name', undefined, ctx.body.displayName),
        ...change('Status', ctx.snap.status, ctx.body.status),
        ...(ctx.body.networks !== undefined
          ? change(
              'Allowed networks',
              countAndFirst(snapStrings(ctx.snap.networks)),
              countAndFirst(argStrings(ctx.body.networks)),
            )
          : []),
        ...change('TLS required', yesNo(ctx.snap.requireTls), yesNo(ctx.body.requireTls)),
        ...(ctx.body.clientCertFingerprints !== undefined
          ? change(
              'Client certificates',
              countAndFirst(snapStrings(ctx.snap.clientCertFingerprints)),
              countAndFirst(argStrings(ctx.body.clientCertFingerprints)),
            )
          : []),
        ...(ctx.body.maxMessageBytes !== undefined
          ? change(
              'Largest message (bytes)',
              ctx.snap.maxMessageBytes ?? 'the platform limit',
              ctx.body.maxMessageBytes ?? 'the platform limit',
            )
          : []),
        ...(ctx.body.silenceAlertMinutes !== undefined
          ? change(
              'Silence alert (minutes)',
              ctx.snap.silenceAlertMinutes ?? 'off',
              ctx.body.silenceAlertMinutes ?? 'off',
            )
          : []),
      ],
      impact: [
        paused
          ? 'Nothing is captured from this source until it is resumed; senders get a temporary failure and retry.'
          : 'Applies to journal mail this source receives from now on.',
        'The intake address does not change.',
      ],
      reversible: true,
    };
  },
  IntakeSourcesController_disable_v1: (ctx) => ({
    title: 'Disable journal intake source',
    action: 'Disables this journal intake source.',
    target: intakeTarget(ctx),
    changes: change('Status', ctx.snap.status, 'disabled'),
    impact: [
      "Terminal: the source's address is refused from now on; a new source needs a new address created in the portal.",
    ],
    warnings: ['Disabling a journal intake source cannot be undone.'],
    reversible: false,
  }),
  IntakeSourcesController_attest_v1: (ctx) => ({
    title: 'Record intake source attestation',
    action: `Records the attestation ${quoted(ctx.body.code, '(none)')} as ${ctx.body.attested === false ? 'withdrawn' : 'done'} for this journal intake source.`,
    target: intakeTarget(ctx),
    changes: [
      ...change('Attestation', undefined, ctx.body.code),
      ...change('Attested', undefined, yesNo(ctx.body.attested)),
    ],
    impact: ['The setup of the source uses the attestation; it is recorded with your name.'],
    reversible: true,
  }),
  // --- eDiscovery ---
  EdiscoveryCasesController_create_v1: (ctx) => ({
    title: 'Create eDiscovery case',
    action: `Creates the eDiscovery case ${quoted(ctx.body.name, '(unnamed)')}.`,
    target: target('Case', ctx.body.name),
    changes: [
      ...change('Name', undefined, ctx.body.name),
      ...change('Matter reference', undefined, ctx.body.matterReference),
      ...change('Description', undefined, ctx.body.description),
      ...change('Custodians', undefined, custodianCount(ctx.body.custodians) ?? 'none'),
    ],
    impact: ['The case is open; add searches, legal holds and exports on the case page.'],
    reversible: true,
  }),
  EdiscoveryCasesController_update_v1: (ctx) => ({
    title: 'Update eDiscovery case',
    action: 'Changes this eDiscovery case.',
    target: caseTarget(ctx),
    changes: [
      ...change('Name', undefined, ctx.body.name),
      ...(ctx.body.description !== undefined
        ? change('Description', undefined, ctx.body.description ?? '(none)')
        : []),
      ...(ctx.body.matterReference !== undefined
        ? change('Matter reference', undefined, ctx.body.matterReference ?? '(none)')
        : []),
      ...(ctx.body.custodians !== undefined
        ? change(
            'Custodians',
            typeof ctx.snap['counts.custodians'] === 'number'
              ? plural(ctx.snap['counts.custodians'], 'custodian')
              : null,
            custodianCount(ctx.body.custodians),
          )
        : []),
    ],
    impact: [
      ctx.body.custodians !== undefined
        ? 'Later searches and holds that use the case custodians use the new list; existing holds keep theirs.'
        : 'Searches, legal holds and exports of the case do not change.',
    ],
    reversible: true,
  }),
  EdiscoveryCasesController_close_v1: (ctx) => ({
    title: 'Close eDiscovery case',
    action: 'Closes this eDiscovery case; it is read-only afterwards.',
    target: [
      ...caseTarget(ctx),
      ...target('Searches', ctx.snap['counts.searches']),
      ...target('Exports', ctx.snap['counts.exports']),
    ],
    changes: change('Status', ctx.snap.status, 'closed'),
    impact: ['The case becomes read-only: no new searches, legal holds or exports.'],
    warnings: ['A closed case cannot be reopened.'],
    reversible: false,
  }),
  EdiscoveryCasesController_createHold_v1: (ctx) => {
    const criteria = isRecord(ctx.body.criteria) ? ctx.body.criteria : {};
    return {
      title: 'Place legal hold',
      action: `Places the legal hold ${quoted(ctx.body.name, '(unnamed)')} for this eDiscovery case.`,
      target: caseTarget(ctx),
      changes: [
        ...change('Hold name', undefined, ctx.body.name),
        ...change('Reason', undefined, ctx.body.reason),
        ...change(
          'Custodians',
          undefined,
          ctx.body.useCaseCustodians === true
            ? 'the case custodians'
            : (custodianCount(criteria.custodians) ?? 'none'),
        ),
        ...change('From', undefined, criteria.from),
        ...change('To', undefined, criteria.to),
        ...change('Directions', undefined, argList(criteria.directions) ?? 'all'),
      ],
      impact: [
        'Blocks every disposal of matching records (retention expiry, review, quarantine deletion, organization deletion) until it is released on the Legal holds page; chat cannot release it.',
      ],
      warnings: ['Only a person with the legal-hold permission can release it, in the portal.'],
      reversible: false,
    };
  },
  EdiscoverySearchesController_create_v1: (ctx) => {
    const criteria = isRecord(ctx.body.criteria) ? ctx.body.criteria : {};
    const custodians = criteria.custodians;
    return {
      title: 'Run eDiscovery search',
      action: 'Starts a search of the archive for this eDiscovery case.',
      target: caseTarget(ctx),
      changes: [
        ...change('From', undefined, criteria.from),
        ...change('To', undefined, criteria.to),
        ...change('Directions', undefined, argList(criteria.directions) ?? 'all'),
        ...change(
          'Custodians',
          undefined,
          custodians === 'case' ? 'the case custodians' : custodianCount(custodians),
        ),
        ...change('Senders', undefined, countOf(criteria.senders, 'sender')),
        ...change('Recipients', undefined, countOf(criteria.recipients, 'recipient')),
        ...change('Subject contains', undefined, criteria.subject),
        ...change('Malicious only', undefined, yesNo(criteria.malicious)),
      ],
      impact: ['Runs in the background; follow it on the case page.'],
      reversible: false,
    };
  },
  EdiscoverySearchesController_review_v1: (ctx) => {
    const count = argStrings(ctx.body.messageIds).length;
    return {
      title: 'Tag eDiscovery search hits',
      action: `Tags ${plural(count, 'message')} of this search as ${reviewTagText(ctx.body.tag)}.`,
      target: searchTarget(ctx, ctx.args.searchId),
      changes: [
        ...change('Review tag', undefined, reviewTagText(ctx.body.tag)),
        ...change('Messages', undefined, count),
      ],
      impact: [
        ctx.body.tag === 'not_relevant'
          ? 'Messages tagged not relevant are left out of exports by default.'
          : 'Exports can include or leave out messages by their review tag.',
      ],
      reversible: true,
    };
  },
  EdiscoveryExportsController_create_v1: (ctx) => {
    const tags = argStrings(ctx.body.reviewTags).map(reviewTagText);
    const hours = ctx.archiveExportTtlHours;
    return {
      title: 'Export eDiscovery search',
      action: `Builds an encrypted export of the decrypted original messages of ${text(ctx.snap.hitCount) ?? '?'} hits with the tags ${tags.length > 0 ? tags.join(', ') : 'the default selection (everything except not relevant)'}.`,
      target: [
        ...searchTarget(ctx, ctx.body.searchId),
        ...target('Incomplete because', ctx.snap.incompleteReason),
      ],
      changes: [
        ...change(
          'Review tags',
          undefined,
          tags.length > 0 ? tags.join(', ') : 'default (all but not relevant)',
        ),
        ...change(
          'Include malicious messages',
          undefined,
          yesNo(ctx.body.acknowledgeMalicious ?? false),
        ),
      ],
      impact: [
        `Download it on the case page in the portal ${
          typeof hours === 'number' && Number.isFinite(hours) && hours > 0
            ? `for ${Math.floor(hours)} hours`
            : 'until it expires'
        }; chat never shows its content.`,
        'Runs in the background; the export appears on the case page when it is ready.',
      ],
      warnings: [
        'The export contains the original messages, including attachments, readable by whoever downloads it.',
      ],
      reversible: false,
    };
  },
  // --- provider connections ---
  ProviderConnectionsController_create_v1: (ctx) => ({
    title: 'Create provider connection',
    action: `Creates the draft ${text(ctx.body.provider) ?? 'provider'} connection ${quoted(ctx.body.displayName, '(unnamed)')}.`,
    target: [
      ...target('Connection', ctx.body.displayName),
      ...target('Provider', ctx.body.provider),
    ],
    changes: [
      ...change('Name', undefined, ctx.body.displayName),
      ...change('Status', undefined, 'draft'),
    ],
    impact: [
      'A draft connection; grant access and enter credentials in the portal next.',
      CHAT_NO_SECRETS,
    ],
    reversible: true,
  }),
  ProviderConnectionsController_update_v1: (ctx) => ({
    title: 'Rename provider connection',
    action: `Renames this provider connection to ${quoted(ctx.body.displayName, '(unnamed)')}.`,
    target: connectionTarget(ctx),
    changes: change('Name', undefined, ctx.body.displayName),
    impact: ['Only the name changes.'],
    reversible: true,
  }),
  ProviderConnectionsController_disconnect_v1: (ctx) => ({
    title: 'Disconnect provider connection',
    action: 'Disconnects this provider connection.',
    target: connectionTarget(ctx),
    changes: changeSetChanges(ctx),
    impact: [
      'Inbound destinations are kept; outbound and internal routing stop; grants are revoked and their credentials wiped.',
      'The provider-side consent and connectors must be removed in the provider admin center (the result lists the steps).',
      ...previewWarnings(ctx),
    ],
    warnings: ['Disconnecting cannot be undone; a new connection needs a new setup in the portal.'],
    reversible: false,
  }),
  ProviderAttestationsController_record_v1: (ctx) => ({
    title: 'Record provider attestation',
    action: `Records the attestation ${quoted(ctx.body.code, '(none)')} as ${ctx.body.attested === false ? 'withdrawn' : 'done'} for this provider connection.`,
    target: connectionTarget(ctx),
    changes: [
      ...change('Attestation', undefined, ctx.body.code),
      ...change('Attested', undefined, yesNo(ctx.body.attested)),
    ],
    impact: ['The setup wizard uses the attestation; it is recorded with your name.'],
    reversible: true,
  }),
  ProviderDomainsController_replace_v1: (ctx) => {
    const before = snapStrings(ctx.snap['domains[].name']);
    const count = argStrings(ctx.body.domainIds).length;
    return {
      title: 'Link domains to provider connection',
      action: `Replaces the domains linked to this provider connection (${plural(count, 'domain')}).`,
      target: connectionTarget(ctx),
      changes: change(
        'Linked domains',
        before === null ? null : cappedList(before, 10),
        plural(count, 'domain'),
      ),
      impact: [
        'Linked domains can be routed through the provider in the next wizard steps; mail flow does not change until a mail-flow change is applied.',
      ],
      reversible: true,
    };
  },
  ProviderGrantsController_revoke_v1: (ctx) => ({
    title: 'Revoke provider grant',
    action: `Revokes the ${text(ctx.args.profile) ?? '?'} grant of this provider connection.`,
    target: grantTarget(ctx),
    changes: change('Grant status', ctx.snap.status, 'revoked'),
    impact: [
      'The gateway stops using this access; its credentials are wiped.',
      "The provider-side consent must be removed in the provider's admin center.",
    ],
    warnings: ['A revoked grant cannot be restored; granting access again happens in the portal.'],
    reversible: false,
  }),
  ProviderGrantsController_verify_v1: (ctx) => ({
    title: 'Verify provider grant',
    action: `Verifies the ${text(ctx.args.profile) ?? '?'} grant of this provider connection again.`,
    target: grantTarget(ctx),
    changes: change('Grant status', ctx.snap.status, 'verifying'),
    impact: [
      'The gateway checks the granted permissions with the provider; the result appears on the connection page.',
      'A first Google Workspace verification needs the delegation confirmation in the portal.',
    ],
    reversible: true,
  }),
  ProviderHealthController_checkNow_v1: (ctx) => ({
    title: 'Check provider connection health',
    action: 'Queues a read-only health check of this provider connection.',
    target: [...connectionTarget(ctx), ...target('Health', ctx.snap.health)],
    changes: change('Health', ctx.snap.health, 'check queued'),
    impact: ['The result appears on the connection page when the check has run.'],
    reversible: false,
  }),
  ProviderMailFlowController_apply_v1: (ctx) => {
    const kind = text(ctx.snap['preview.changeSet.kind'] ?? null);
    return {
      title: 'Apply mail-flow change',
      action: `Applies the previewed mail-flow change: ${kind !== null ? (CHANGE_KIND_WORDS[kind] ?? sanitizeText(kind, 32)) : 'see the changes'}.`,
      target: [
        ...connectionTarget(ctx),
        ...target('Outbound mode', ctx.snap.outboundMode),
        ...target('Internal routing', onOff(ctx.snap.internalRouting)),
      ],
      changes: changeSetChanges(ctx),
      impact: [
        'The gateway changes its own routing as shown; configuration in the provider is never changed by the gateway.',
        ...previewWarnings(ctx),
      ],
      warnings: ['Mail flow of the linked domains changes as soon as this is applied.'],
      reversible: true,
    };
  },
};

/**
 * The 168 templates (31 of step AI-2, 47 of step AI-3, the native `report_send_email` of step
 * AI-R, 64 of step AI-4, 25 of step AI-5), keyed by operation id.
 */
export const IMPACT_TEMPLATES: Readonly<Record<string, Template>> = {
  // --- native (step AI-R D5) ---
  AssistantNative_reportSendEmail: reportSendEmail,
  // --- policies ---
  PolicyManagementController_create_v1: (ctx) => {
    const definition = ctx.body.definition;
    return {
      title: 'Create policy',
      action: `Creates the policy ${quoted(ctx.body.name, '(unnamed)')} as a draft (version 1). It does not evaluate mail until it is published and activated.`,
      target: [
        ...target('Name', ctx.body.name),
        ...target('Direction', isRecord(definition) ? definition.direction : null),
        ...target('Priority', isRecord(definition) ? definition.priority : null),
      ],
      changes: [
        ...change('Name', undefined, ctx.body.name),
        ...change('Description', undefined, ctx.body.description),
        ...change('Rules', undefined, ruleCountOf(definition, ctx.validation)),
        ...change('Change note', undefined, ctx.body.changeNote),
        ...definitionChanges(definition),
      ],
      definition: summarizeDefinition(definition),
      impact: ['Nothing changes for mail until the draft is published and activated.'],
      reversible: true,
    };
  },
  PolicyManagementController_update_v1: (ctx) => ({
    title: 'Update policy',
    action: `Changes the name or description of policy ${policyName(ctx)}. Its rules and how it evaluates mail do not change.`,
    target: policyTarget(ctx),
    changes: [
      ...change('Name', ctx.snap.name, ctx.body.name),
      ...(ctx.body.description !== undefined
        ? change('Description', ctx.snap.description, ctx.body.description ?? '(none)')
        : []),
    ],
    impact: ['Rules and evaluation do not change.'],
    reversible: true,
  }),
  PolicyManagementController_enable_v1: (ctx) => ({
    title: 'Enable policy',
    action: `Enables policy ${policyName(ctx)} so that its active version evaluates new mail again.`,
    target: policyTarget(ctx),
    changes: change('Status', ctx.snap.status, 'active'),
    impact: [
      ctx.snap.activeVersionNo === null || ctx.snap.activeVersionNo === undefined
        ? 'The policy has no active version: publish and activate a version first, or the platform refuses the change.'
        : `New mail is evaluated against version ${text(ctx.snap.activeVersionNo)} of this policy again.`,
    ],
    reversible: true,
  }),
  PolicyManagementController_disable_v1: (ctx) => ({
    title: 'Disable policy',
    action: `Disables policy ${policyName(ctx)}: it stops evaluating new mail.`,
    target: policyTarget(ctx),
    changes: change('Status', ctx.snap.status, 'disabled'),
    impact: [
      'Stops evaluating this policy for new mail; mail already processed is not changed.',
      'Its rules (for example quarantine or tagging rules) no longer apply until it is enabled again.',
    ],
    reversible: true,
  }),
  PolicyManagementController_remove_v1: (ctx) => ({
    title: 'Delete policy',
    action: `Deletes policy ${policyName(ctx)}: it is archived with its versions and disappears from lists and evaluation.`,
    target: policyTarget(ctx),
    changes: change('Status', ctx.snap.status, 'archived (deleted)'),
    impact: [
      ctx.snap.status === 'active'
        ? 'The policy is active: it stops evaluating new mail immediately.'
        : 'The policy no longer appears in the policy list.',
      'Its versions are kept for history only; the name stays reserved.',
    ],
    warnings: [`${UNDO_DELETE} The policy cannot be restored from the portal or chat.`],
    reversible: false,
  }),
  PolicyManagementController_createDraft_v1: (ctx) => {
    const definition = ctx.body.definition;
    const source =
      definition !== undefined
        ? 'with the definition below'
        : ctx.body.basedOnVersionNo !== undefined
          ? `copied from version ${text(ctx.body.basedOnVersionNo)}`
          : 'copied from the latest version';
    return {
      title: 'Create draft version',
      action: `Adds a new draft version to policy ${policyName(ctx)} ${source}.`,
      target: policyTarget(ctx),
      changes: [
        ...change('Latest version', version(ctx.snap.latestVersionNo) ?? 'none', 'a new draft'),
        ...(definition !== undefined
          ? change('Rules', undefined, ruleCountOf(definition, ctx.validation))
          : []),
        ...change('Change note', undefined, ctx.body.changeNote),
        ...definitionChanges(definition),
      ],
      ...(definition !== undefined ? { definition: summarizeDefinition(definition) } : {}),
      impact: ['Drafts do not evaluate mail until they are published and activated.'],
      reversible: true,
    };
  },
  PolicyManagementController_updateDraft_v1: (ctx) => {
    const definition = ctx.body.definition;
    return {
      title: 'Replace draft definition',
      action: `Replaces the definition of draft version ${text(ctx.args.versionNo) ?? '?'} of the policy.`,
      target: versionTarget(ctx),
      changes: [
        ...change('Rules', ctx.snap.ruleCount, ruleCountOf(definition, ctx.validation)),
        ...change('Change note', ctx.snap.changeNote, ctx.body.changeNote),
        ...definitionChanges(definition),
      ],
      definition: summarizeDefinition(definition),
      impact: [
        "The draft's current definition is replaced by the one below.",
        'The draft still does not evaluate mail until it is published and activated.',
      ],
      reversible: true,
    };
  },
  PolicyManagementController_deleteDraft_v1: (ctx) => ({
    title: 'Delete draft version',
    action: `Deletes draft version ${text(ctx.args.versionNo) ?? '?'} of the policy.`,
    target: versionTarget(ctx),
    changes: change('Version', version(ctx.args.versionNo), 'deleted'),
    impact: ['The draft and its definition are removed; published versions are not affected.'],
    warnings: [`${UNDO_DELETE} The draft's definition is lost.`],
    reversible: false,
  }),
  PolicyManagementController_publish_v1: (ctx) => {
    const activate = ctx.body.activate !== false;
    const no = text(ctx.args.versionNo) ?? '?';
    return {
      title: activate ? 'Publish and activate policy version' : 'Publish policy version',
      action: activate
        ? `Publishes version ${no} and makes it the active version of the policy.`
        : `Publishes version ${no} without activating it.`,
      target: versionTarget(ctx),
      changes: [
        ...change('Version status', ctx.snap.status, 'published'),
        ...(activate ? change('Active version', null, `v${no}`) : []),
      ],
      impact: activate
        ? [
            `Version ${no} evaluates new mail from now on (if the policy is enabled).`,
            'A published version can no longer be edited; activating another version rolls back.',
          ]
        : [
            'A published version can no longer be edited.',
            'Mail evaluation does not change until the version is activated.',
          ],
      reversible: false,
    };
  },
  PolicyManagementController_activate_v1: (ctx) => {
    const no = text(ctx.args.versionNo) ?? '?';
    return {
      title: 'Activate policy version',
      action: `Makes version ${no} the active version of policy ${policyName(ctx)}.`,
      target: [...policyTarget(ctx), ...target('Version to activate', `v${no}`)],
      changes: change('Active version', version(ctx.snap.activeVersionNo) ?? 'none', `v${no}`),
      impact: [
        `New mail is evaluated against version ${no} from now on.`,
        ...(ctx.snap.status !== undefined && ctx.snap.status !== 'active'
          ? [
              `The policy status is ${text(ctx.snap.status) ?? 'unknown'}: it evaluates mail only while it is enabled.`,
            ]
          : []),
      ],
      reversible: true,
    };
  },
  PolicySettingsController_put_v1: (ctx) => {
    const settings = isRecord(ctx.body.settings) ? ctx.body.settings : {};
    return {
      title: 'Replace policy settings',
      action: "Replaces the organization's policy settings document.",
      target: target('Settings version', ctx.snap.rowVersion),
      changes: POLICY_SETTINGS.flatMap(({ path, label }) => {
        const after = valueAtPath(settings, path);
        return change(
          label,
          yesNo(ctx.snap[`effective.${path}`]),
          after === undefined ? '(default)' : yesNo(after),
        );
      }),
      impact: [
        'Changes how every policy decision of the organization is applied to new mail.',
        'Settings not included in the document return to their defaults.',
      ],
      warnings: [
        'This changes organization-wide mail handling; review every setting before confirming.',
      ],
      reversible: true,
    };
  },
  // --- quarantine ---
  QuarantineEntriesController_release_v1: (ctx) => ({
    title: 'Release quarantined message',
    action: 'Releases the quarantined message to its recipient.',
    target: entryTarget(ctx),
    changes: [...change('State', ctx.snap.state, 'released'), ...reasonChange(ctx)],
    impact: [
      'The message is delivered to the recipient.',
      'The platform re-validates the entry against the latest scan and policy first.',
    ],
    warnings: [APPROVAL_MAY_BE_REQUIRED],
    reversible: false,
  }),
  QuarantineEntriesController_reject_v1: (ctx) => ({
    title: 'Reject quarantined message',
    action: 'Rejects the quarantined message: it is not delivered.',
    target: entryTarget(ctx),
    changes: [
      ...change('State', ctx.snap.state, 'rejected'),
      ...change('Notify the sender', undefined, yesNo(ctx.body.notifySender)),
      ...reasonChange(ctx),
    ],
    impact: [
      'The message will not be delivered to the recipient.',
      ...(ctx.body.notifySender === true
        ? ['The sender is notified (outbound and internal mail only).']
        : []),
    ],
    reversible: false,
  }),
  QuarantineEntriesController_delete_v1: (ctx) => ({
    title: 'Delete quarantined message',
    action:
      'Deletes the quarantined message: it is never delivered and its stored copy is removed.',
    target: entryTarget(ctx),
    changes: [...change('State', ctx.snap.state, 'deleted'), ...reasonChange(ctx)],
    impact: ['The message can no longer be released, previewed or downloaded.'],
    warnings: [`${UNDO_DELETE} The stored message is removed.`],
    reversible: false,
  }),
  QuarantineEntriesController_requestRelease_v1: (ctx) => ({
    title: 'Request release of quarantined message',
    action: 'Asks another analyst to approve the release of the quarantined message.',
    target: entryTarget(ctx),
    changes: [...change('State', ctx.snap.state, 'pending approval'), ...reasonChange(ctx)],
    impact: [
      'An approval request is created; the message stays in quarantine until another person approves it.',
    ],
    reversible: true,
  }),
  QuarantineSelfController_release_v1: (ctx) => ({
    title: 'Release my quarantined message',
    action: 'Releases your quarantined message to your mailbox.',
    target: entryTarget(ctx),
    changes: [...change('State', ctx.snap.state, 'released'), ...reasonChange(ctx)],
    impact: [
      'The message is delivered to your mailbox.',
      'Only release mail you expected: quarantined mail may be dangerous.',
    ],
    reversible: false,
  }),
  QuarantineSelfController_requestRelease_v1: (ctx) => ({
    title: 'Request release of my quarantined message',
    action: 'Asks an administrator to release your quarantined message.',
    target: entryTarget(ctx),
    changes: [...change('State', ctx.snap.state, 'pending approval'), ...reasonChange(ctx)],
    impact: ['The message stays in quarantine until an administrator approves the request.'],
    reversible: true,
  }),
  QuarantineSelfController_putPreferences_v1: (ctx) => ({
    title: 'Change quarantine digest preference',
    action:
      ctx.body.digestOptOut === true
        ? 'Stops the quarantine digest e-mails to you.'
        : 'Turns the quarantine digest e-mails to you back on.',
    target: target('Opt-out allowed by your organization', yesNo(ctx.snap.allowOptOut)),
    changes: change(
      'Quarantine digest',
      ctx.snap.digestOptOut === true ? 'off' : ctx.snap.digestOptOut === false ? 'on' : null,
      ctx.body.digestOptOut === true ? 'off' : 'on',
    ),
    impact:
      ctx.body.digestOptOut === true
        ? ['You no longer get e-mail summaries of your quarantined messages.']
        : [],
    reversible: true,
  }),
  QuarantineToolsController_putSettings_v1: (ctx) => {
    const settings = isRecord(ctx.body.settings) ? ctx.body.settings : {};
    return {
      title: 'Replace quarantine settings',
      action: "Replaces the organization's quarantine settings document.",
      target: target('Settings version', ctx.snap.rowVersion),
      changes: Object.entries(settings).map(([key, value]) => ({
        label: `Section ${key}`,
        after: text(value) ?? 'null',
      })),
      impact: [
        'Changes apply to quarantine entries created afterwards (expiry is fixed at creation).',
        'Sections and keys not included in the document return to their defaults.',
      ],
      reversible: true,
    };
  },
  QuarantineEntriesController_manual_v1: (ctx) => {
    const seqs = Array.isArray(ctx.body.rcptSeqs) ? ctx.body.rcptSeqs : null;
    return {
      title: 'Quarantine message',
      action: `Quarantines the message for ${seqs ? `${seqs.length} selected recipient${seqs.length === 1 ? '' : 's'}` : 'every eligible recipient'}.`,
      target: messageTarget(ctx, ctx.body.messageId),
      changes: [
        ...change('Message status', ctx.snap.status, 'quarantined'),
        ...change('Recipients', undefined, seqs ? seqs.join(', ') : 'all eligible'),
        ...reasonChange(ctx),
      ],
      impact: [
        'The selected recipients get a quarantine entry; the message is not delivered to them until it is released.',
      ],
      reversible: true,
    };
  },
  QuarantineApprovalsController_approve_v1: (ctx) => ({
    title: 'Approve quarantine request',
    action: 'Approves the request: the quarantined message is released.',
    target: approvalTarget(ctx),
    changes: [...change('Request status', ctx.snap.status, 'approved'), ...reasonChange(ctx)],
    impact: [
      'The quarantined message is released to its recipient after the platform re-checks it.',
      'You cannot approve your own request or a message addressed to you (separation of duties).',
    ],
    reversible: false,
  }),
  QuarantineApprovalsController_deny_v1: (ctx) => ({
    title: 'Deny quarantine request',
    action: 'Denies the request: the message stays in quarantine.',
    target: approvalTarget(ctx),
    changes: [...change('Request status', ctx.snap.status, 'denied'), ...reasonChange(ctx)],
    impact: ['The message is not released; a new request is needed to release it later.'],
    reversible: false,
  }),
  QuarantineApprovalsController_cancel_v1: (ctx) => ({
    title: 'Cancel quarantine request',
    action: 'Cancels the pending request.',
    target: approvalTarget(ctx),
    changes: [...change('Request status', ctx.snap.status, 'cancelled'), ...reasonChange(ctx)],
    impact: ['The message stays in quarantine; nobody can approve this request any more.'],
    reversible: false,
  }),
  QuarantineToolsController_bulk_v1: (ctx) => {
    const action = text(ctx.body.action) ?? '?';
    const ids = Array.isArray(ctx.body.ids) ? ctx.body.ids : [];
    const counts = new Map<string, number>();
    for (const item of ctx.items) {
      const key = item.status ?? 'not found';
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    const preview = [...counts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], 'en'))
      .map(([status, count]) => `${count} ${status}`)
      .join(', ');
    const notPreviewed = Math.max(0, ids.length - ctx.items.length);
    const noun = action === 'approve' || action === 'deny' ? 'approval requests' : 'entries';
    return {
      title: `Bulk ${action} of quarantined messages`,
      action: `Applies "${action}" to ${ids.length} quarantine ${noun} at once.`,
      target: [...target('Action', action), ...target('Items', ids.length)],
      changes: [
        ...change('Notify the sender', undefined, yesNo(ctx.body.notifySender)),
        ...reasonChange(ctx),
      ],
      impact: [
        `${ids.length} ${noun} are processed with "${action}".`,
        ...(preview ? [`Current state of the previewed items: ${preview}.`] : []),
        ...(notPreviewed > 0 ? [`${notPreviewed} more not previewed.`] : []),
        'The platform re-checks every item; items that are not eligible are skipped and reported.',
      ],
      warnings: [
        'This acts on many messages at once.',
        ...(action === 'delete' ? [`${UNDO_DELETE} The stored messages are removed.`] : []),
        ...(action === 'release' || action === 'approve'
          ? ['Released messages cannot be recalled.']
          : []),
      ],
      reversible: false,
    };
  },
  // --- messages ---
  MessageLifecycleController_release_v1: (ctx) => ({
    title: 'Release held message',
    action: 'Releases the held message for delivery to its recipients.',
    target: messageTarget(ctx, ctx.args.messageId),
    changes: [
      ...change('Message status', ctx.snap.status, 'delivery pending'),
      ...reasonChange(ctx),
    ],
    impact: [
      'The message is delivered to its recipients.',
      'Quarantined messages are released through the quarantine workflow instead; the platform then refuses this request.',
    ],
    reversible: false,
  }),
  MessageLifecycleController_rescan_v1: (ctx) => ({
    title: 'Rescan message',
    action: 'Scans the message again in a new lifecycle round and re-evaluates the policies.',
    target: messageTarget(ctx, ctx.args.messageId),
    changes: [...change('Message status', ctx.snap.status, 'scanning'), ...reasonChange(ctx)],
    impact: [
      'A new scan round starts; its outcome may quarantine, deliver or reject the message.',
      'Results of earlier rounds stay unchanged.',
    ],
    reversible: false,
  }),
  // --- recipient suppressions ---
  RecipientSuppressionsController_create_v1: (ctx) => ({
    title: 'Suppress recipient',
    action: `Stops outbound delivery to ${quoted(ctx.body.address, 'the address')}.`,
    target: target('Address', ctx.body.address, true),
    changes: [
      ...change('Reason', undefined, ctx.body.reason ?? 'manual'),
      ...change('Expires', undefined, ctx.body.expiresAt ?? 'never'),
    ],
    impact: ['Outbound mail to this address is not delivered while the suppression applies.'],
    reversible: true,
  }),
  RecipientSuppressionsController_delete_v1: (ctx) => ({
    title: 'Remove recipient suppression',
    action: `Removes the suppression of ${quoted(ctx.snap.address, 'the address')}: outbound mail to it is delivered again.`,
    target: [
      ...target('Address', ctx.snap.address, true),
      ...target('Suppression', ctx.args.suppressionId),
      ...target('Reason', ctx.snap.reason),
      ...target('Source', ctx.snap.source, true),
      ...target('Expires', ctx.snap.expiresAt ?? 'never'),
    ],
    changes: change('Active', yesNo(ctx.snap.active), 'removed'),
    impact: ['Outbound mail to this address is delivered again from the next attempt on.'],
    warnings: [
      'A hard-bounce or complaint suppression protects your sending reputation; removing it cannot be undone (add it again manually if needed).',
    ],
    reversible: false,
  }),
  // --- saved views ---
  SavedViewsController_create_v1: (ctx) => ({
    title: 'Create saved view',
    action: `Saves the message explorer view ${quoted(ctx.body.name, '(unnamed)')}.`,
    target: [...target('Name', ctx.body.name), ...target('Kind', ctx.body.kind)],
    changes: savedViewChanges(ctx),
    impact: [],
    reversible: true,
  }),
  SavedViewsController_update_v1: (ctx) => ({
    title: 'Update saved view',
    action: `Replaces the saved view ${quoted(ctx.snap.name, '(unnamed)')} with the name and definition below.`,
    target: [
      ...target('Saved view', ctx.snap.name),
      ...target('View id', ctx.args.viewId),
      ...target('Kind', ctx.snap.kind),
    ],
    changes: savedViewChanges(ctx, ctx.snap.name),
    impact: ["The view's filters, sort, time range and columns are replaced."],
    reversible: true,
  }),
  SavedViewsController_remove_v1: (ctx) => ({
    title: 'Delete saved view',
    action: `Deletes the saved view ${quoted(ctx.snap.name, '(unnamed)')}.`,
    target: [...target('Saved view', ctx.snap.name), ...target('View id', ctx.args.viewId)],
    changes: change('Saved view', ctx.snap.name, 'deleted'),
    impact: ['The view disappears from your saved views; messages are not affected.'],
    warnings: [UNDO_DELETE],
    reversible: false,
  }),

  // ===== step AI-3 (design 30 D7) =====
  // --- users ---
  UsersController_invite_v1: (ctx) => {
    const roles = argStrings(ctx.body.roleKeys);
    return {
      title: 'Invite user',
      action: `Invites ${quoted(ctx.body.email, 'the person')} to the organization with ${plural(roles.length, 'role')}.`,
      target: [
        ...target('Email', ctx.body.email),
        ...target('Display name', ctx.body.displayName, true),
        ...target('Roles', listText(roles)),
      ],
      changes: change('Roles', undefined, listText(roles)),
      impact: ['When they accept, the person can sign in with every permission of these roles.'],
      warnings: ['An invitation email is sent; the person gets these roles when they accept.'],
      reversible: false,
    };
  },
  UsersController_update_v1: (ctx) => ({
    title: 'Update user',
    action: `Changes the profile of user ${userName(ctx)}.`,
    target: [...userTarget(ctx), ...rolesTarget(ctx)],
    changes: [
      ...change('Display name', ctx.snap.displayName, ctx.body.displayName),
      ...change('Email', ctx.snap.email, ctx.body.email),
    ],
    impact:
      ctx.body.email !== undefined
        ? ['Sign-in, invitation and password-reset mail go to the new address from now on.']
        : ['Roles, status and sign-in do not change.'],
    reversible: true,
  }),
  UsersController_changeStatus_v1: (ctx) => {
    const disable = ctx.body.status === 'disabled';
    return {
      title: disable ? 'Disable user' : 'Re-enable user',
      action: disable
        ? `Disables user ${userName(ctx)}: they can no longer sign in.`
        : `Re-enables user ${userName(ctx)} so that they can sign in again.`,
      target: [...userTarget(ctx), ...rolesTarget(ctx)],
      changes: [...change('Status', ctx.snap.status, ctx.body.status), ...reasonChange(ctx)],
      impact: disable
        ? [SIGNED_OUT, 'Their roles are kept; re-enable the user to restore access.']
        : ['The user can sign in again with the roles they hold.'],
      warnings: disable
        ? ['The user loses access immediately. ' + ROLE_RULE]
        : ['Re-enabling restores the access of every role the user holds.'],
      reversible: true,
    };
  },
  UsersController_replaceRoles_v1: (ctx) => {
    const before = userRoles(ctx);
    const after = argStrings(ctx.body.roleKeys);
    const diff = before ? setDiff(before, after) : null;
    return {
      title: 'Change user roles',
      action: `Replaces the roles of user ${userName(ctx)}.`,
      target: userTarget(ctx),
      changes: [
        ...change('Roles', before ? listText(before) : null, listText(after)),
        ...(diff && diff.added.length > 0
          ? change('Roles added', undefined, listText(diff.added))
          : []),
        ...(diff && diff.removed.length > 0
          ? change('Roles removed', undefined, listText(diff.removed))
          : []),
      ],
      impact: [
        diff === null
          ? 'The current roles could not be listed in full; the user gets exactly the roles below.'
          : diff.added.length === 0 && diff.removed.length === 0
            ? 'The roles do not change.'
            : 'The user gets the permissions of the added roles and loses those of the removed roles.',
      ],
      warnings: [`This changes what the user can see and do. ${ROLE_RULE}`],
      reversible: true,
    };
  },
  UsersController_resetMfa_v1: (ctx) => ({
    title: 'Reset user MFA',
    action: `Resets the MFA of user ${userName(ctx)}: their authenticator and recovery codes are removed.`,
    target: userTarget(ctx),
    changes: change(
      'MFA',
      ctx.snap.mfaEnabled === true
        ? 'enrolled'
        : ctx.snap.mfaEnabled === false
          ? 'not enrolled'
          : null,
      'reset',
    ),
    impact: [SIGNED_OUT, 'The user must enrol MFA again at the next sign-in.'],
    warnings: [
      "Reset MFA only after you have verified the person's identity, for example after a lost phone.",
    ],
    reversible: false,
  }),
  UsersController_remove_v1: (ctx) => {
    const roles = userRoles(ctx);
    return {
      title: 'Delete user',
      action: `Deletes user ${userName(ctx)} from the organization.`,
      target: [...userTarget(ctx), ...rolesTarget(ctx)],
      changes: change('Status', ctx.snap.status, 'deleted'),
      impact: [
        `${SIGNED_OUT} The user can no longer sign in.`,
        ...(roles && roles.length > 0 ? [`Their roles are removed: ${listText(roles)}.`] : []),
      ],
      warnings: [`${UNDO_DELETE} The person must be invited again to get access. ${ROLE_RULE}`],
      reversible: false,
    };
  },
  UsersController_resendInvitation_v1: (ctx) => ({
    title: 'Resend invitation',
    action: `Sends a new invitation email to ${userName(ctx)}.`,
    target: userTarget(ctx),
    changes: change('Invitation', undefined, 'sent again'),
    impact: [
      'A new invitation email with a new link is sent to the address.',
      ...(ctx.snap.status !== undefined && ctx.snap.status !== null && ctx.snap.status !== 'invited'
        ? [
            `The user is ${text(ctx.snap.status) ?? 'unknown'}: only invited users can get an invitation, so the platform refuses the request.`,
          ]
        : []),
    ],
    reversible: false,
  }),
  UsersController_revokeAllSessions_v1: (ctx) => ({
    title: 'Sign user out everywhere',
    action: `Signs user ${userName(ctx)} out of every session.`,
    target: userTarget(ctx),
    changes: change('Sessions', undefined, 'all revoked'),
    impact: [`${SIGNED_OUT} They must sign in again on every device.`],
    warnings: ['Revoked sessions cannot be restored; unsaved work in open portal pages is lost.'],
    reversible: false,
  }),
  UsersController_revokeSession_v1: (ctx) => ({
    title: 'Revoke user session',
    action: 'Signs the user out of one session.',
    target: [
      ...target('User id', ctx.args.id),
      ...target('Session', ctx.args.sessionId),
      ...target('IP address', ctx.snap.ipAddress),
      ...target('Browser', ctx.snap.userAgent, true),
      ...target('Signed in at', ctx.snap.authenticatedAt),
      ...target('Last used', ctx.snap.lastUsedAt),
      ...target('Signed in with MFA', yesNo(ctx.snap.mfaAuthenticated)),
    ],
    changes: change('Session', 'active', 'revoked'),
    impact: ['The user is signed out of this session and must sign in again on that device.'],
    warnings: ['A revoked session cannot be restored.'],
    reversible: false,
  }),
  // --- roles ---
  RolesController_create_v1: (ctx) => {
    const permissions = argStrings(ctx.body.permissions);
    return {
      title: 'Create role',
      action: `Creates the custom role ${quoted(ctx.body.name, '(unnamed)')} with ${plural(permissions.length, 'permission')}.`,
      target: [...target('Role key', ctx.body.key), ...target('Name', ctx.body.name)],
      changes: [
        ...change('Name', undefined, ctx.body.name),
        ...change('Description', undefined, ctx.body.description),
        ...change('Permissions', undefined, listText(permissions)),
      ],
      impact: ['Nobody holds the new role until it is assigned to a user.'],
      warnings: [
        'Users who get this role get every permission listed. The platform refuses permissions you do not hold yourself.',
      ],
      reversible: true,
    };
  },
  RolesController_update_v1: (ctx) => {
    const before = snapStrings(ctx.snap.permissions);
    const after = argStrings(ctx.body.permissions);
    const diff = before ? setDiff(before, after) : null;
    return {
      title: 'Update role',
      action: `Changes the role ${quoted(ctx.snap.name, quoted(ctx.args.key, 'this role'))} and its permissions.`,
      target: [
        ...target('Role key', ctx.args.key),
        ...target('Name', ctx.snap.name),
        ...target('System role', yesNo(ctx.snap.system)),
      ],
      changes: [
        ...change('Name', ctx.snap.name, ctx.body.name),
        ...(ctx.body.description !== undefined
          ? change('Description', ctx.snap.description, ctx.body.description ?? '(none)')
          : []),
        ...(diff === null
          ? change('Permissions', null, listText(after))
          : [
              ...(diff.added.length > 0
                ? change('Permissions added', undefined, listText(diff.added))
                : []),
              ...(diff.removed.length > 0
                ? change('Permissions removed', undefined, listText(diff.removed))
                : []),
            ]),
      ],
      impact: [
        ...(diff === null
          ? [
              'The current permissions could not be listed in full; the role gets exactly the permissions below.',
            ]
          : []),
        ...(diff && diff.added.length > 0
          ? [`Every user who holds this role gets these permissions: ${listText(diff.added)}.`]
          : []),
        ...(diff && diff.removed.length > 0
          ? [`Every user who holds this role loses these permissions: ${listText(diff.removed)}.`]
          : []),
        ...(diff && diff.added.length === 0 && diff.removed.length === 0
          ? ['The permissions of the role do not change.']
          : []),
        ...(ctx.snap.system === true
          ? ['System roles are read-only: the platform refuses this change.']
          : []),
      ],
      warnings: [
        'This changes the access of every user who holds this role. The platform refuses permissions you do not hold yourself.',
      ],
      reversible: true,
    };
  },
  RolesController_remove_v1: (ctx) => {
    const permissions = snapStrings(ctx.snap.permissions);
    return {
      title: 'Delete role',
      action: `Deletes the custom role ${quoted(ctx.snap.name, quoted(ctx.args.key, 'this role'))}.`,
      target: [
        ...target('Role key', ctx.args.key),
        ...target('Name', ctx.snap.name),
        ...target('System role', yesNo(ctx.snap.system)),
        ...(permissions ? target('Permissions', permissions.length) : []),
      ],
      changes: change('Role', ctx.snap.name ?? ctx.args.key, 'deleted'),
      impact: [
        'The platform refuses the deletion while any user holds the role.',
        ...(ctx.snap.system === true ? ['System roles cannot be deleted.'] : []),
      ],
      warnings: [UNDO_DELETE],
      reversible: false,
    };
  },
  // --- departments ---
  DepartmentsController_create_v1: (ctx) => ({
    title: 'Create department',
    action: `Creates the department ${quoted(ctx.body.name, '(unnamed)')}.`,
    target: target('Name', ctx.body.name),
    changes: [
      ...change('Name', undefined, ctx.body.name),
      ...change('Description', undefined, ctx.body.description),
    ],
    impact: [],
    reversible: true,
  }),
  DepartmentsController_update_v1: (ctx) => ({
    title: 'Update department',
    action: `Changes the department ${quoted(ctx.snap.name, 'this department')}.`,
    target: departmentTarget(ctx),
    changes: [
      ...change('Name', ctx.snap.name, ctx.body.name),
      ...(ctx.body.description !== undefined
        ? change('Description', ctx.snap.description, ctx.body.description ?? '(none)')
        : []),
    ],
    impact: ['Its members do not change.'],
    reversible: true,
  }),
  DepartmentsController_remove_v1: (ctx) => ({
    title: 'Delete department',
    action: `Deletes the department ${quoted(ctx.snap.name, 'this department')}.`,
    target: departmentTarget(ctx),
    changes: change('Department', ctx.snap.name, 'deleted'),
    impact: [
      'Its member list is deleted with it; the users and addresses themselves are not deleted.',
      'Policy conditions on this department no longer match anyone.',
    ],
    warnings: [UNDO_DELETE],
    reversible: false,
  }),
  DepartmentsController_addMember_v1: (ctx) => ({
    title: 'Add department member',
    action: `Adds a member to the department ${quoted(ctx.snap.name, 'this department')}.`,
    target: departmentTarget(ctx),
    changes: [
      ...change('User', undefined, ctx.body.userId),
      ...change('Address', undefined, ctx.body.address),
    ],
    impact: [],
    reversible: true,
  }),
  DepartmentsController_removeMember_v1: (ctx) => ({
    title: 'Remove department member',
    action: `Removes a member from the department ${quoted(ctx.snap.name, 'this department')}.`,
    target: [...departmentTarget(ctx), ...target('Member', ctx.args.memberId)],
    changes: change('Member', ctx.args.memberId, 'removed'),
    impact: ['Policy conditions on this department no longer match this member.'],
    reversible: true,
  }),
  // --- API keys ---
  ApiKeysController_revoke_v1: (ctx) => {
    const scopes = snapStrings(ctx.snap.scopes);
    return {
      title: 'Revoke API key',
      action: `Revokes the API key ${quoted(ctx.snap.name, '(unnamed)')}.`,
      target: [
        ...target('API key', ctx.snap.name),
        ...target('Key id', ctx.args.id),
        ...target('Prefix', ctx.snap.prefix),
        ...(scopes ? target('Scopes', listText(scopes)) : []),
        ...target('Last used', ctx.snap.lastUsedAt ?? 'never'),
        ...target('Created by', ctx.snap['createdBy.displayName'], true),
        ...target('Expires', ctx.snap.expiresAt ?? 'never'),
      ],
      changes: change('Status', ctx.snap.revokedAt ? 'revoked' : 'active', 'revoked'),
      impact: [
        'Every integration that uses this key stops working immediately.',
        ...(ctx.snap.revokedAt ? ['The key is already revoked.'] : []),
      ],
      warnings: ['A revoked key cannot be restored; integrations need a new key from the portal.'],
      reversible: false,
    };
  },
  // --- domains ---
  DomainsController_create_v1: (ctx) => ({
    title: 'Add domain',
    action: `Adds the domain ${quoted(ctx.body.name, '(unnamed)')}; it stays pending until its DNS records prove ownership.`,
    target: target('Domain', ctx.body.name),
    changes: [
      ...change('Domain', undefined, ctx.body.name),
      ...change('Inbound mail', undefined, onOff(ctx.body.inboundEnabled) ?? '(default)'),
      ...change(
        'DKIM Ed25519 key',
        undefined,
        isRecord(ctx.body.dkim) ? yesNo(ctx.body.dkim.ed25519) : null,
      ),
    ],
    impact: [
      'Publish the DNS records shown on the domain page, then verify the domain.',
      'Mail flow for the domain starts only after it is verified and activated.',
    ],
    reversible: true,
  }),
  DomainsController_remove_v1: (ctx) => ({
    title: 'Delete domain',
    action: `Deletes the domain ${domainName(ctx)} from the organization.`,
    target: [
      ...domainTarget(ctx),
      ...target('Inbound mail', onOff(ctx.snap.inboundEnabled)),
      ...target('Outbound mail', onOff(ctx.snap.outboundEnabled)),
    ],
    changes: change('Domain', ctx.snap.status, 'deleted'),
    impact: [
      'The gateway no longer accepts or relays mail for this domain.',
      'Its DNS records, DKIM keys, destinations and recipient list are removed.',
    ],
    warnings: [`${UNDO_DELETE} The domain must be added and verified again.`],
    reversible: false,
  }),
  DomainsController_changeStatus_v1: (ctx) => {
    const suspend = ctx.body.status === 'suspended';
    return {
      title: suspend ? 'Suspend domain' : 'Activate domain',
      action: suspend
        ? `Suspends the domain ${domainName(ctx)}: its mail flow stops.`
        : `Activates the domain ${domainName(ctx)}: its mail flow starts.`,
      target: [...domainTarget(ctx), ...target('Status reason', ctx.snap.statusReason)],
      changes: [...change('Status', ctx.snap.status, ctx.body.status), ...reasonChange(ctx)],
      impact: suspend
        ? ['The gateway no longer accepts or relays mail for this domain while it is suspended.']
        : ['The gateway accepts and relays mail for this domain.'],
      warnings: suspend
        ? ['Mail for this domain stops immediately.']
        : ['Mail for this domain flows through the gateway from now on.'],
      reversible: true,
    };
  },
  DomainDnsController_verify_v1: (ctx) => ({
    title: 'Verify domain DNS',
    action: `Checks the DNS records of the domain ${domainName(ctx)} now.`,
    target: [
      ...target('Domain', ctx.snap.name),
      ...target('Domain id', ctx.args.id),
      ...target('Status', ctx.snap.status),
      ...target('Ready for activation', yesNo(ctx.snap.readyForActivation)),
      ...target('Mail flow ready', yesNo(ctx.snap.mailFlowReady)),
    ],
    changes: change('DNS check', undefined, 'run now'),
    impact: [
      "The platform looks up the domain's DNS records now; a valid ownership record verifies the domain.",
    ],
    reversible: true,
  }),
  DomainDnsController_rotate_v1: (ctx) => {
    const selectors = snapStrings(ctx.snap['dkimKeys[].selector']);
    const statuses = snapStrings(ctx.snap['dkimKeys[].status']) ?? [];
    return {
      title: 'Rotate DKIM key',
      action: `Creates a new DKIM key for the domain ${domainName(ctx)}.`,
      target: [
        ...target('Domain', ctx.snap.name),
        ...target('Domain id', ctx.args.id),
        ...(selectors
          ? target(
              'Current keys',
              listText(selectors.map((s, i) => `${s} (${statuses[i] ?? '?'})`)),
            )
          : []),
      ],
      changes: change('DKIM key', undefined, `a new ${text(ctx.body.algorithm) ?? 'key'}`),
      impact: [
        'A new key is created; publish its DNS record before the old key retires (overlap set by the platform).',
      ],
      warnings: [
        'Outbound mail signed with the new key fails DKIM checks until its DNS record is published.',
      ],
      reversible: false,
    };
  },
  DomainDestinationsController_replace_v1: (ctx) => {
    const before = snapshotServers(ctx);
    return {
      title: 'Replace domain destinations',
      action: 'Replaces the servers that inbound mail for this domain is delivered to.',
      target: [
        ...target('Domain id', ctx.args.id),
        ...target('Current provider', ctx.snap.provider),
      ],
      changes: [
        ...change('Provider', ctx.snap.provider, ctx.body.provider),
        ...change('Servers', before ? listText(before) : null, requestedServers(ctx.body)),
      ],
      impact: ['Scanned inbound mail is delivered to the new servers from the next message on.'],
      warnings: ['All inbound mail for this domain will be delivered to these servers.'],
      reversible: true,
    };
  },
  DomainDestinationsController_remove_v1: (ctx) => {
    const before = snapshotServers(ctx);
    return {
      title: 'Remove domain destinations',
      action: 'Removes every server that inbound mail for this domain is delivered to.',
      target: [...target('Domain id', ctx.args.id), ...target('Provider', ctx.snap.provider)],
      changes: change('Servers', before ? listText(before) : null, 'none'),
      impact: [
        "The gateway has no delivery destination for the domain's inbound mail until new servers are set.",
      ],
      warnings: ['Inbound mail for this domain cannot be delivered without destinations.'],
      reversible: false,
    };
  },
  DomainRecipientsController_set_v1: (ctx) => {
    const mode = text(ctx.body.mode);
    const enforcement = text(ctx.body.enforcement) ?? text(ctx.snap.enforcement);
    return {
      title: 'Set recipient validation',
      action: `Sets the recipient validation of the domain to ${mode ?? '?'}.`,
      target: recipientTarget(ctx),
      changes: [
        ...change('Validation mode', ctx.snap.mode, ctx.body.mode),
        ...change('Enforcement', ctx.snap.enforcement, ctx.body.enforcement),
      ],
      impact: [
        (mode && RECIPIENT_MODES[mode]) || 'Changes which recipients the gateway accepts mail for.',
        enforcement === 'monitor'
          ? 'Monitor mode: unknown recipients are only logged, mail is still accepted.'
          : 'Mail to unknown recipients is rejected.',
      ],
      reversible: true,
    };
  },
  DomainRecipientsController_add_v1: (ctx) => {
    const parts = localPartsText(ctx.body);
    return {
      title: 'Add recipients',
      action: `Adds ${plural(parts.count, 'address')} to the recipient list of the domain.`,
      target: recipientTarget(ctx),
      changes: change('Addresses added', undefined, parts.text),
      impact: [],
      reversible: true,
    };
  },
  DomainRecipientsController_remove_v1: (ctx) => {
    const parts = localPartsText(ctx.body);
    const enforced = ctx.snap.mode === 'allow_list' && ctx.snap.enforcement !== 'monitor';
    return {
      title: 'Remove recipients',
      action: `Removes ${plural(parts.count, 'address')} from the recipient list of the domain.`,
      target: recipientTarget(ctx),
      changes: change('Addresses removed', undefined, parts.text),
      impact: [
        enforced
          ? 'Mail to these addresses is rejected from now on.'
          : 'These addresses are removed from the list; they are rejected once the list is enforced.',
      ],
      warnings: [
        'Removed addresses must be added again to receive mail while the list is enforced.',
      ],
      reversible: true,
    };
  },
  // --- notifications ---
  NotificationsController_putPreferences_v1: (ctx) => {
    const before = snapStrings(ctx.snap.optOut);
    const after = argStrings(ctx.body.optOut);
    return {
      title: 'Change my notification preferences',
      action: 'Replaces which notification emails you opted out of.',
      target: target(
        'Quarantine digest opt-out allowed',
        yesNo(ctx.snap.quarantineDigestOptOutAllowed),
      ),
      changes: [
        ...change('Opted out of', before ? listText(before) : null, listText(after)),
        ...change(
          'Quarantine digest',
          ctx.snap.quarantineDigestOptOut === true
            ? 'off'
            : ctx.snap.quarantineDigestOptOut === false
              ? 'on'
              : null,
          ctx.body.quarantineDigestOptOut === true ? 'off' : 'on',
        ),
      ],
      impact:
        ctx.body.quarantineDigestOptOut === true && ctx.snap.quarantineDigestOptOutAllowed === false
          ? [
              'Your organization does not allow opting out of the quarantine digest; the platform refuses the change.',
            ]
          : [],
      reversible: true,
    };
  },
  NotificationsController_putSettings_v1: (ctx) => {
    const settings = isRecord(ctx.body.settings) ? ctx.body.settings : {};
    return {
      title: 'Replace notification settings',
      action: "Replaces the organization's alert notification settings.",
      target: target('Settings version', ctx.snap.rowVersion),
      changes: NOTIFICATION_ALERTS.flatMap(({ path, label }) => {
        const after = valueAtPath(settings, path);
        return change(
          label,
          settingText(ctx.snap[`settings.${path}`]),
          after === undefined ? '(default)' : settingText(after),
        );
      }),
      impact: [
        "Changes which alert emails the organization's administrators get.",
        'Settings left out of the document return to their defaults.',
      ],
      reversible: true,
    };
  },
  // --- organizations ---
  OrganizationsController_create_v1: (ctx) => {
    const admin = isRecord(ctx.body.initialAdmin) ? ctx.body.initialAdmin : null;
    return {
      title: 'Create organization',
      action: `Creates the organization ${quoted(ctx.body.name, '(unnamed)')} (${text(ctx.body.slug) ?? '?'}).`,
      target: [
        ...target('Name', ctx.body.name),
        ...target('Slug', ctx.body.slug),
        ...target('Plan', ctx.body.planCode),
        ...target('Deployment mode', ctx.body.deploymentMode),
        ...target('Data region', ctx.body.dataRegion),
      ],
      changes: [
        ...change('Organization', undefined, ctx.body.slug),
        ...(admin ? change('Initial administrator', undefined, admin.email) : []),
        ...(admin ? change('Administrator name', undefined, admin.displayName) : []),
      ],
      impact: [
        "A new customer organization is created with the plan's features and limits.",
        ...(admin
          ? ['An invitation email is sent to the initial administrator.']
          : ['Nobody can sign in to it until a user is invited.']),
      ],
      reversible: admin === null,
    };
  },
  OrganizationsController_update_v1: (ctx) => ({
    title: 'Update organization',
    action: `Changes the organization ${quoted(ctx.snap.name, 'this organization')}.`,
    target: [
      ...organizationTarget(ctx),
      ...target('Kind', ctx.snap.kind),
      ...target('Status', ctx.snap.status),
    ],
    changes: [
      ...change('Name', ctx.snap.name, ctx.body.name),
      ...change('Plan', ctx.snap['plan.code'], ctx.body.planCode),
    ],
    impact:
      ctx.body.planCode !== undefined && ctx.body.planCode !== ctx.snap['plan.code']
        ? ["The new plan's features and limits apply to the organization from now on."]
        : ['Only the name changes.'],
    reversible: true,
  }),
  OrganizationDeletionController_cancel_v1: (ctx) => ({
    title: 'Cancel organization deletion',
    action: 'Cancels the pending deletion of the organization.',
    target: [
      ...target('Organization id', ctx.args.id),
      ...target('Organization status', ctx.snap.status),
      ...target('Deletion state', ctx.snap.state),
      ...target('Requested at', ctx.snap.requestedAt),
      ...target('Purge after', ctx.snap.purgeAfter),
    ],
    changes: [...change('Deletion', ctx.snap.state, 'cancelled'), ...reasonChange(ctx)],
    impact: [
      'The organization is no longer scheduled for deletion; its data is kept.',
      ...(ctx.snap.cancellable === false
        ? ['The deletion can no longer be cancelled: the platform refuses the request.']
        : []),
    ],
    reversible: true,
  }),
  OrganizationConfigurationController_overrideFeature_v1: (ctx) => ({
    title: 'Override organization feature',
    action: `Turns the feature ${text(ctx.args.featureKey) ?? '?'} ${ctx.body.enabled === true ? 'on' : 'off'} for the organization, regardless of its plan.`,
    target: featureTarget(ctx),
    changes: [
      ...change('Enabled', onOff(ctx.snap.enabled), onOff(ctx.body.enabled)),
      ...(ctx.body.config !== undefined
        ? change('Configuration', ctx.snap.config, ctx.body.config ?? '(none)')
        : []),
      ...change('Source', ctx.snap.source ?? 'plan', 'override'),
    ],
    impact: ['The override applies until it is reset; plan changes do not affect it.'],
    warnings: ['Feature overrides change what the organization can use, regardless of its plan.'],
    reversible: true,
  }),
  OrganizationConfigurationController_resetFeature_v1: (ctx) => ({
    title: 'Reset organization feature',
    action: `Removes the override of the feature ${text(ctx.args.featureKey) ?? '?'}: the plan value applies again.`,
    target: featureTarget(ctx),
    changes: change('Source', ctx.snap.source ?? 'plan', 'plan'),
    impact: [
      ctx.snap.source === 'override'
        ? "The feature returns to the value of the organization's plan immediately."
        : 'The feature has no override: nothing changes.',
    ],
    warnings: ['Removing the override can turn the feature on or off for the whole organization.'],
    reversible: true,
  }),
  OrganizationConfigurationController_overrideLimit_v1: (ctx) => ({
    title: 'Override organization limit',
    action: `Sets the limit ${text(ctx.args.limitKey) ?? '?'} of the organization to ${text(ctx.body.value) ?? '?'}, regardless of its plan.`,
    target: limitTarget(ctx),
    changes: [
      ...change('Value', ctx.snap.value, ctx.body.value),
      ...change('Source', ctx.snap.source ?? 'plan', 'override'),
    ],
    impact: ['The override applies until it is reset; plan changes do not affect it.'],
    warnings: [
      'A lower limit can block mail, users or domains of the organization once it is reached.',
    ],
    reversible: true,
  }),
  OrganizationConfigurationController_resetLimit_v1: (ctx) => ({
    title: 'Reset organization limit',
    action: `Removes the override of the limit ${text(ctx.args.limitKey) ?? '?'}: the plan value applies again.`,
    target: limitTarget(ctx),
    changes: change('Source', ctx.snap.source ?? 'plan', 'plan'),
    impact: [
      ctx.snap.source === 'override'
        ? "The limit returns to the value of the organization's plan immediately."
        : 'The limit has no override: nothing changes.',
    ],
    warnings: [
      'The plan value may be lower than the current value and block mail, users or domains.',
    ],
    reversible: true,
  }),
  OrganizationConfigurationController_updateSettings_v1: (ctx) => ({
    title: 'Update organization settings',
    action: "Changes the organization's settings shown below.",
    target: target('Organization id', ctx.args.id),
    changes: ORGANIZATION_SETTINGS.flatMap(({ key, label }) =>
      ctx.body[key] === undefined
        ? []
        : change(label, settingText(ctx.snap[key]), settingText(ctx.body[key])),
    ),
    impact: ['Settings not listed keep their current values.'],
    reversible: true,
  }),
  // --- scan settings ---
  ScanSettingsController_replace_v1: (ctx) => {
    const settings = isRecord(ctx.body.settings) ? ctx.body.settings : {};
    return {
      title: 'Replace scan settings',
      action: `Replaces the organization's settings of the ${text(ctx.args.engine) ?? '?'} scan engine.`,
      target: scanTarget(ctx),
      changes: Object.entries(settings).map(([key, value]) => ({
        label: `Setting ${key}`,
        after: text(value) ?? 'null',
      })),
      impact: [
        'Changes how the engine classifies new mail of the organization, within the platform bounds.',
        'Settings left out of the document return to the platform values.',
      ],
      warnings: ['Weaker settings can let more spam, phishing or malware through.'],
      reversible: true,
    };
  },
  ScanSettingsController_reset_v1: (ctx) => ({
    title: 'Reset scan settings',
    action: `Removes the organization's settings of the ${text(ctx.args.engine) ?? '?'} scan engine: the platform values apply.`,
    target: scanTarget(ctx),
    changes: change(
      'Organization override',
      ctx.snap.overrideApplied === true
        ? 'applied'
        : ctx.snap.overrideApplied === false
          ? 'none'
          : null,
      'none (platform values)',
    ),
    impact: ['The engine uses the platform values for new mail of the organization.'],
    warnings: ['Every organization-specific setting of this engine is removed.'],
    reversible: true,
  }),
  // --- SMTP connectors ---
  SmtpConnectorsController_update_v1: (ctx) => {
    const before = snapStrings(ctx.snap['networks[].cidr']);
    return {
      title: 'Update SMTP connector',
      action: `Changes the SMTP connector ${quoted(ctx.snap.name, 'this connector')}.`,
      target: connectorTarget(ctx),
      changes: [
        ...change('Name', ctx.snap.name, ctx.body.name),
        ...change('Status', ctx.snap.status, ctx.body.status),
        ...(ctx.body.networks !== undefined
          ? change(
              'Networks',
              before ? listText(before) : null,
              listText(argStrings(ctx.body.networks)),
            )
          : []),
        ...change('Require TLS', yesNo(ctx.snap.requireTls), yesNo(ctx.body.requireTls)),
      ],
      impact: [
        ctx.body.status === 'disabled'
          ? 'Mail relayed through this connector is no longer accepted.'
          : 'Changes how the gateway accepts mail relayed through this connector.',
      ],
      reversible: true,
    };
  },
  SmtpConnectorsController_remove_v1: (ctx) => ({
    title: 'Delete SMTP connector',
    action: `Deletes the SMTP connector ${quoted(ctx.snap.name, 'this connector')}.`,
    target: connectorTarget(ctx),
    changes: change('Connector', ctx.snap.status, 'deleted'),
    impact: [
      'Systems that relay mail through this connector can no longer send through the gateway.',
    ],
    warnings: [`${UNDO_DELETE} A new connector gets new credentials in the portal.`],
    reversible: false,
  }),
  // --- webhooks ---
  WebhooksController_update_v1: (ctx) => ({
    title: 'Update webhook',
    action: `Changes the webhook ${webhookName(ctx)}.`,
    target: webhookTarget(ctx),
    changes: [
      ...change('Name', ctx.snap.name, ctx.body.name),
      ...(ctx.body.description !== undefined
        ? change('Description', undefined, ctx.body.description ?? '(none)')
        : []),
      ...change('URL', ctx.snap.url, ctx.body.url),
      ...change(
        'Event types',
        undefined,
        ctx.body.eventTypes !== undefined ? listText(argStrings(ctx.body.eventTypes)) : null,
      ),
      ...(ctx.body.filters !== undefined
        ? change('Filters', undefined, ctx.body.filters ?? '(none)')
        : []),
      ...change('Status', ctx.snap.status, ctx.body.status),
      ...(ctx.body.maxConcurrency !== undefined
        ? change('Max concurrency', undefined, ctx.body.maxConcurrency ?? '(default)')
        : []),
    ],
    impact:
      ctx.body.url !== undefined
        ? ['Events are sent to the new URL from the next delivery on.']
        : [],
    reversible: true,
  }),
  WebhooksController_delete_v1: (ctx) => ({
    title: 'Delete webhook',
    action: `Deletes the webhook ${webhookName(ctx)}.`,
    target: webhookTarget(ctx),
    changes: change('Webhook', ctx.snap.status, 'deleted'),
    impact: ['No more events are sent to this webhook.'],
    warnings: [UNDO_DELETE],
    reversible: false,
  }),
  WebhooksController_test_v1: (ctx) => ({
    title: 'Send webhook test event',
    action: `Sends a test event to ${text(ctx.snap.url) ?? 'the webhook URL'}.`,
    target: webhookTarget(ctx),
    changes: change('Delivery', undefined, 'one test event'),
    impact: ["The test delivery appears in the webhook's delivery list."],
    reversible: false,
  }),
  WebhookDeliveriesController_replay_v1: (ctx) => ({
    title: 'Replay webhook delivery',
    action: 'Sends the event of this delivery to the webhook again.',
    target: [
      ...target('Webhook id', ctx.args.webhookId),
      ...target('Delivery', ctx.args.deliveryId),
      ...target('Event type', ctx.snap.eventType),
      ...target('Status', ctx.snap.status),
      ...target('Attempts', ctx.snap.attemptCount),
      ...target('Last response code', ctx.snap.lastResponseCode),
    ],
    changes: change('Delivery', ctx.snap.status, 'replayed'),
    impact: ['The event is sent again as a new replay delivery.', REPLAY_TWICE],
    reversible: false,
  }),
  WebhookDeliveriesController_createReplay_v1: (ctx) => {
    const statuses = argStrings(ctx.body.statuses);
    const types = argStrings(ctx.body.eventTypes);
    return {
      title: 'Replay webhook deliveries',
      action: `Replays the deliveries of the webhook ${webhookName(ctx)} from ${text(ctx.body.from) ?? '?'} to ${text(ctx.body.to) ?? '?'}.`,
      target: webhookTarget(ctx),
      changes: [
        ...change(
          'Range',
          undefined,
          `${text(ctx.body.from) ?? '?'} to ${text(ctx.body.to) ?? '?'}`,
        ),
        ...change('Delivery statuses', undefined, listText(statuses, 'all')),
        ...change('Event types', undefined, listText(types, 'all')),
      ],
      impact: [
        'Every matching delivery in the range is sent again as a replay delivery.',
        REPLAY_TWICE,
      ],
      reversible: false,
    };
  },
  // --- step AI-4 (design 32 D6) ---
  ...AI4_TEMPLATES,
  // --- step AI-5 (design 33 D9) ---
  ...AI5_TEMPLATES,
};

/** Generic fallback (never used by an enabled tool: the registry check requires a template). */
const FALLBACK: Template = () => ({
  title: 'Confirm change',
  action: 'Runs the request shown under technical details.',
  impact: ['The platform applies the change as requested.'],
  warnings: ['No detailed preview is available for this change.'],
  reversible: false,
});

export function hasImpactTemplate(operationId: string): boolean {
  return Object.prototype.hasOwnProperty.call(IMPACT_TEMPLATES, operationId);
}

// ---------------------------------------------------------------------------------------------
// Assembly and caps
// ---------------------------------------------------------------------------------------------

const byteLength = (value: unknown): number => Buffer.byteLength(JSON.stringify(value), 'utf8');

const scalarText = (value: unknown): string => text(value) ?? '';

/** The concrete request path built from the tool's template and the arguments (display only). */
export function requestOf(
  tool: Pick<OperationTool, 'method' | 'pathTemplate' | 'pathParams' | 'queryParams'>,
  args: Readonly<Record<string, unknown>>,
): { method: string; path: string } {
  let path = tool.pathTemplate;
  for (const name of tool.pathParams) {
    const value = args[name];
    path = path.replace(
      `{${name}}`,
      typeof value === 'string' || typeof value === 'number'
        ? encodeURIComponent(String(value))
        : `{${name}}`,
    );
  }
  const query = new URLSearchParams();
  for (const name of tool.queryParams) {
    const value = args[name];
    if (value === undefined || value === null) continue;
    query.append(
      name,
      Array.isArray(value) ? value.map((v) => scalarText(v)).join(',') : scalarText(value),
    );
  }
  const qs = query.toString();
  return { method: tool.method, path: qs ? `${path}?${qs}` : path };
}

function finalize(
  draft: Draft,
  portalRoute: string | null,
  request: ConfirmationSummary['request'],
  escalationWarnings: readonly string[] = [],
) {
  const t = (value: string, max: number = SUMMARY_LIMITS.textChars) => sanitizeText(value, max);
  const summary: ConfirmationSummary = {
    version: CONFIRMATION_SUMMARY_VERSION,
    title: t(draft.title, 120),
    action: t(draft.action),
    target: (draft.target ?? []).slice(0, SUMMARY_LIMITS.targets).map((item) => ({
      label: t(item.label, 80),
      value: t(item.value),
      ...(item.untrusted ? { untrusted: true } : {}),
    })),
    changes: (draft.changes ?? []).slice(0, SUMMARY_LIMITS.changes).map((item) => ({
      label: t(item.label, 80),
      ...(item.before !== undefined
        ? { before: item.before === null ? null : t(item.before) }
        : {}),
      after: t(item.after),
    })),
    impact: (draft.impact ?? []).slice(0, SUMMARY_LIMITS.impact).map((line) => t(line)),
    warnings: [
      ...new Set([...(draft.warnings ?? []), ...escalationWarnings].map((line) => t(line))),
    ].slice(0, SUMMARY_LIMITS.warnings),
    reversible: draft.reversible,
    portalRoute: portalRoute ? t(portalRoute, 512) : null,
    request: { method: t(request.method, 8), path: t(request.path, 2048) },
  };
  if (draft.definition)
    summary.definition = {
      direction: t(draft.definition.direction, 32),
      priority: draft.definition.priority,
      rules: draft.definition.rules.slice(0, SUMMARY_LIMITS.rules).map((rule) => ({
        id: t(rule.id, 64),
        when: t(rule.when, SUMMARY_LIMITS.whenChars),
        actions: t(rule.actions),
      })),
    };
  // 16 KiB: drop rules from the end, then changes, then targets; finally shorten long texts.
  while (byteLength(summary) > SUMMARY_LIMITS.bytes && (summary.definition?.rules.length ?? 0) > 1)
    summary.definition!.rules.pop();
  while (byteLength(summary) > SUMMARY_LIMITS.bytes && summary.changes.length > 0)
    summary.changes.pop();
  while (byteLength(summary) > SUMMARY_LIMITS.bytes && summary.target.length > 1)
    summary.target.pop();
  if (byteLength(summary) > SUMMARY_LIMITS.bytes) {
    for (const rule of summary.definition?.rules ?? []) {
      rule.when = t(rule.when, 80);
      rule.actions = t(rule.actions, 80);
    }
    summary.request.path = t(summary.request.path, 256);
  }
  return summary;
}

/**
 * The confirmation summary of a write (D5). `operationId` must be a registry tool; templates
 * exist for the 78 writes of AI-2 and AI-3, the native `report_send_email` of AI-R, the 64
 * writes of AI-4 and the 25 of AI-5 (others get the generic fallback, which the registry check keeps away from
 * enabled tools).
 */
export function impactOf(operationId: string, input: ImpactInput): ConfirmationSummary {
  const operation = findOperation(operationId);
  if (!operation || !('name' in operation))
    throw new Error(`impactOf: ${operationId} is not a tool of the registry`);
  const tool = operation;
  const body = isRecord(input.args.body) ? input.args.body : {};
  const template = IMPACT_TEMPLATES[operationId] ?? FALLBACK;
  const draft = template({
    args: input.args,
    body,
    snap: input.snapshot ?? {},
    items: input.items ?? [],
    validation: input.validation ?? null,
    native: input.native ?? null,
    archiveExportTtlHours: input.archiveExportTtlHours ?? null,
  });
  const route = tool.portalRoute;
  const portalRoute =
    draft.portalRoute !== undefined
      ? draft.portalRoute
      : route
        ? (fillRoute(route, input.args, tool.pathParams)?.href ?? routePage(route))
        : null;
  return finalize(
    draft,
    portalRoute,
    input.request ?? requestOf(tool, input.args),
    input.escalationWarnings ?? [],
  );
}
