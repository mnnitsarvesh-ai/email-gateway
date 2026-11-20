/**
 * Inbox rules → rule definitions for classification (design note D8.3): from Graph message rules
 * and from Exchange audit parameters (`New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules`).
 * Addresses, keywords and folder names stay inside the definition; only traits and a target domain
 * leave classification.
 */
import type { RuleDefinition } from '../../core/traits';
import { messageRuleSchema, type GraphMessageRule } from '../schemas';

type Recipients =
  readonly { emailAddress?: { address?: string | null } | null }[] | null | undefined;

function addresses(list: Recipients): string[] {
  return (list ?? [])
    .map((recipient) => recipient.emailAddress?.address ?? '')
    .filter((address) => address.length > 0);
}

export function parseGraphRule(raw: unknown): GraphMessageRule | null {
  const parsed = messageRuleSchema.safeParse(raw);
  return parsed.success ? parsed.data : null;
}

export function graphRuleDefinition(rule: GraphMessageRule): RuleDefinition {
  const conditions = rule.conditions ?? {};
  const actions = rule.actions ?? {};
  const words = [
    ...(conditions.subjectContains ?? []),
    ...(conditions.bodyContains ?? []),
    ...(conditions.bodyOrSubjectContains ?? []),
    ...(conditions.senderContains ?? []),
  ];
  const hasConditions =
    words.length > 0 ||
    (conditions.fromAddresses ?? []).length > 0 ||
    Object.entries(conditions).some(
      ([key, value]) =>
        ![
          'subjectContains',
          'bodyContains',
          'bodyOrSubjectContains',
          'senderContains',
          'fromAddresses',
        ].includes(key) &&
        value !== null &&
        value !== undefined &&
        value !== false &&
        !(Array.isArray(value) && value.length === 0),
    );
  return {
    forwardTo: addresses(actions.forwardTo),
    redirectTo: addresses(actions.redirectTo),
    forwardAsAttachmentTo: addresses(actions.forwardAsAttachmentTo),
    deletes: actions.delete === true || actions.permanentDelete === true,
    moveToFolder: actions.moveToFolder ?? null,
    marksRead: actions.markAsRead === true,
    stopsProcessing: actions.stopProcessingRules === true,
    conditionWords: words,
    hasNoConditions: !hasConditions,
  };
}

type AddressListParam = 'ForwardTo' | 'RedirectTo' | 'ForwardAsAttachmentTo';
const KEYWORD_PARAMS = [
  'SubjectContainsWords',
  'BodyContainsWords',
  'SubjectOrBodyContainsWords',
  'FromAddressContainsWords',
  'HeaderContainsWords',
];
const NON_CONDITION_PARAMS = new Set([
  'Name',
  'Identity',
  'Mailbox',
  'ForwardTo',
  'RedirectTo',
  'ForwardAsAttachmentTo',
  'DeleteMessage',
  'SoftDeleteMessage',
  'MoveToFolder',
  'MarkAsRead',
  'StopProcessingRules',
  'Enabled',
  'Priority',
  'AlwaysDeleteOutlookRulesBlob',
  'Force',
  'Confirm',
  'ErrorAction',
]);

function splitList(value: string): string[] {
  return value
    .split(/[;,]/)
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

function addressFromExchangeValue(value: string): string {
  // `"Name" [SMTP:user@example.org]`, `SMTP:user@example.org`, or a bare address
  const bracket = /\[(?:smtp|SMTP|ex|EX):([^\]]+)\]/.exec(value);
  if (bracket) return bracket[1] as string;
  return value
    .replace(/^smtp:/i, '')
    .replace(/^"[^"]*"\s*/, '')
    .trim();
}

/** A rule definition from audit parameters (names drive traits; values only classify). */
export function auditRuleDefinition(
  parameters: readonly { Name: string; Value?: string | null }[],
): RuleDefinition {
  const byName = new Map(parameters.map((p) => [p.Name, p.Value ?? '']));
  const list = (name: AddressListParam) =>
    byName.has(name) ? splitList(byName.get(name) ?? '').map(addressFromExchangeValue) : [];
  const words = KEYWORD_PARAMS.flatMap((name) =>
    byName.has(name) ? splitList(byName.get(name) ?? '') : [],
  );
  const truthy = (name: string) =>
    byName.has(name) && (byName.get(name) ?? '').toLowerCase() !== 'false';
  const moveTo = byName.get('MoveToFolder');
  const hasConditions = parameters.some((p) => !NON_CONDITION_PARAMS.has(p.Name));
  const forwardTo = list('ForwardTo');
  const redirectTo = list('RedirectTo');
  const asAttachment = list('ForwardAsAttachmentTo');
  return {
    // A forwarding parameter without a value still marks the trait.
    forwardTo: byName.has('ForwardTo') && forwardTo.length === 0 ? ['unknown'] : forwardTo,
    redirectTo: byName.has('RedirectTo') && redirectTo.length === 0 ? ['unknown'] : redirectTo,
    forwardAsAttachmentTo:
      byName.has('ForwardAsAttachmentTo') && asAttachment.length === 0 ? ['unknown'] : asAttachment,
    deletes: truthy('DeleteMessage') || truthy('SoftDeleteMessage'),
    moveToFolder: moveTo !== undefined && moveTo !== '' ? moveTo.replace(/^.*\\/, '') : null,
    marksRead: truthy('MarkAsRead'),
    stopsProcessing: truthy('StopProcessingRules'),
    conditionWords: words,
    hasNoConditions: !hasConditions,
  };
}

/** Rule name of an audit record (for the audit-derived item identity). */
export function auditRuleName(
  parameters: readonly { Name: string; Value?: string | null }[],
): string | null {
  const name = parameters.find((p) => p.Name === 'Name' || p.Name === 'Identity')?.Value;
  return name ? name.trim().toLowerCase().slice(0, 256) : null;
}
