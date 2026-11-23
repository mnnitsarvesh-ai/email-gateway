import { fillRoute, routePage } from '../results/card';
import { sanitizeText } from '../results/sanitize';
import { findOperation } from '../registry/registry';
import type { OperationTool } from '../registry/types';
import { valueAtPath } from './digest';
import {
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
}

type Template = (ctx: TemplateContext) => Draft;

interface TemplateContext {
  args: Readonly<Record<string, unknown>>;
  body: Readonly<Record<string, unknown>>;
  snap: Readonly<ConfirmationSnapshot>;
  items: readonly EachSnapshotItem[];
  validation: DefinitionValidation | null;
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

/** The 78 templates (31 of step AI-2, 47 of step AI-3), keyed by operation id. */
export const IMPACT_TEMPLATES: Readonly<Record<string, Template>> = {
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
 * exist for the 78 writes of AI-2 and AI-3 (others get the generic fallback, which the registry
 * check keeps away from enabled tools).
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
  });
  const route = tool.portalRoute;
  const portalRoute = route
    ? (fillRoute(route, input.args, tool.pathParams)?.href ?? routePage(route))
    : null;
  return finalize(
    draft,
    portalRoute,
    input.request ?? requestOf(tool, input.args),
    input.escalationWarnings ?? [],
  );
}
