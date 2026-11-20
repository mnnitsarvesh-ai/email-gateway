/**
 * Inbox rule / filter traits (design note D8.3). Rules are reduced to trait codes and a target
 * domain; rule keywords, folder names and forwarding addresses are read only to classify and are
 * never stored or emitted.
 */
import { domainOf } from './hash';

export const MAILBOX_RULE_TRAITS = [
  'forwards',
  'redirects',
  'forwards_as_attachment',
  'forwards_external',
  'deletes',
  'moves_to_folder',
  'moves_to_rarely_used_folder',
  'marks_read',
  'stops_processing',
  'matches_finance_keywords',
  'matches_security_keywords',
  'matches_all_messages',
] as const;
export type MailboxRuleTrait = (typeof MAILBOX_RULE_TRAITS)[number];

/** Finance-related keyword stems (lower case; matched as substrings of rule conditions). */
export const FINANCE_KEYWORDS: readonly string[] = [
  'invoice',
  'payment',
  'wire',
  'bank',
  'payroll',
  'remittance',
  'iban',
  'swift',
  'transfer',
  'purchase order',
  'billing',
  'statement',
  'salary',
  'ach',
  'factura',
  'rechnung',
  'facture',
  'zahlung',
  'paiement',
  'pago',
];

/** Security-related keyword stems (lower case). */
export const SECURITY_KEYWORDS: readonly string[] = [
  'password',
  'security',
  'phish',
  'hacked',
  'compromise',
  'mfa',
  '2fa',
  'two-factor',
  'verification',
  'verify',
  'helpdesk',
  'help desk',
  'it support',
  'suspicious',
  'sign-in',
  'login',
  'unusual activity',
  'spam',
  'passwort',
  'mot de passe',
  'contraseña',
];

/** Rarely used folders and labels (lower case); moving mail there hides it from the owner. */
export const RARELY_USED_FOLDERS: readonly string[] = [
  'archive',
  'rss feeds',
  'rss subscriptions',
  'rss',
  'conversation history',
  'junk email',
  'junk e-mail',
  'junk',
  'deleted items',
  'trash',
  'spam',
  'notes',
  'outbox',
];

/** A provider rule reduced to what classification needs (addresses and keywords stay local). */
export interface RuleDefinition {
  forwardTo: readonly string[];
  redirectTo: readonly string[];
  forwardAsAttachmentTo: readonly string[];
  deletes: boolean;
  /** Display name of the destination folder or label, or `null`. */
  moveToFolder: string | null;
  /** Gmail: the filter removes the INBOX label (archives). */
  skipsInbox?: boolean;
  marksRead: boolean;
  stopsProcessing: boolean;
  /** Words or phrases of the rule's conditions (subject, body, sender text). */
  conditionWords: readonly string[];
  /** The rule has no condition at all (applies to every message). */
  hasNoConditions: boolean;
}

export interface RuleClassification {
  traits: MailboxRuleTrait[];
  /** Domain of the first external forwarding target, else of the first target; never an address. */
  targetDomain: string | null;
}

function matchesAny(words: readonly string[], keywords: readonly string[]): boolean {
  return words.some((word) => {
    const normalized = word.toLowerCase();
    return keywords.some((keyword) =>
      keyword.length <= 4
        ? new RegExp(
            `(^|[^a-z0-9])${keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9]|$)`,
          ).test(normalized)
        : normalized.includes(keyword),
    );
  });
}

/**
 * Classifies a rule. `directoryDomains` are the integration's directory domains; a target outside
 * them makes the rule `forwards_external`.
 */
export function classifyRule(
  rule: RuleDefinition,
  context: { directoryDomains: readonly string[] },
): RuleClassification {
  const traits = new Set<MailboxRuleTrait>();
  const internal = new Set(context.directoryDomains.map((domain) => domain.toLowerCase()));
  const targets = [...rule.forwardTo, ...rule.redirectTo, ...rule.forwardAsAttachmentTo];
  if (rule.forwardTo.length > 0) traits.add('forwards');
  if (rule.redirectTo.length > 0) traits.add('redirects');
  if (rule.forwardAsAttachmentTo.length > 0) traits.add('forwards_as_attachment');
  const domains = targets.map((target) => domainOf(target)).filter((d): d is string => d !== null);
  const external = domains.find((domain) => !internal.has(domain));
  if (external !== undefined) traits.add('forwards_external');
  if (rule.deletes) traits.add('deletes');
  if (rule.moveToFolder !== null) {
    traits.add('moves_to_folder');
    if (RARELY_USED_FOLDERS.includes(rule.moveToFolder.trim().toLowerCase())) {
      traits.add('moves_to_rarely_used_folder');
    }
  }
  if (rule.skipsInbox) {
    traits.add('moves_to_folder');
    traits.add('moves_to_rarely_used_folder');
  }
  if (rule.marksRead) traits.add('marks_read');
  if (rule.stopsProcessing) traits.add('stops_processing');
  if (matchesAny(rule.conditionWords, FINANCE_KEYWORDS)) traits.add('matches_finance_keywords');
  if (matchesAny(rule.conditionWords, SECURITY_KEYWORDS)) traits.add('matches_security_keywords');
  if (rule.hasNoConditions) traits.add('matches_all_messages');
  return {
    traits: MAILBOX_RULE_TRAITS.filter((trait) => traits.has(trait)),
    targetDomain: external ?? domains[0] ?? null,
  };
}

/** Domain classification of a single forwarding target. */
export function forwardingTraits(
  target: string,
  context: { directoryDomains: readonly string[] },
): RuleClassification {
  return classifyRule(
    {
      forwardTo: [target],
      redirectTo: [],
      forwardAsAttachmentTo: [],
      deletes: false,
      moveToFolder: null,
      marksRead: false,
      stopsProcessing: false,
      conditionWords: [],
      hasNoConditions: true,
    },
    context,
  );
}
