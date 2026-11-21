import { fillRoute, routePage } from '../results/card';
import { sanitizeText } from '../results/sanitize';
import { findOperation } from '../registry/registry';
import type { OperationTool } from '../registry/types';
import { valueAtPath } from './digest';
import type { ConfirmationSnapshot, EachSnapshotItem } from './specs';
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

/** The 31 templates (keyed by operation id). */
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
    warnings: (draft.warnings ?? []).slice(0, SUMMARY_LIMITS.warnings).map((line) => t(line)),
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
 * exist for the 31 writes of AI-2 (others get the generic fallback, which the registry check
 * keeps away from enabled tools).
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
  return finalize(draft, portalRoute, input.request ?? requestOf(tool, input.args));
}
