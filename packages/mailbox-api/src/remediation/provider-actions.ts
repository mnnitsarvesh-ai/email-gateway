/**
 * The provider plan of every remediation action (step API-2 R3) as data, plus the pure helpers
 * the mailbox-worker's `remediate` role and the api use: reversibility, the reversal of an action,
 * the mailbox container of a quarantine entry, "already in target" checks over the state read
 * before acting (R5.4), Gmail label changes, and the R9.1 mappings of a mailbox quarantine entry
 * (verdict → quarantine reason, first hard block → primary engine).
 *
 * Graph (`Mail.ReadWrite`): hidden quarantine folder under `msgfolderroot`, well-known
 * `junkemail`, `recoverableitemsdeletions` and `inbox`, categories, `permanentDelete`.
 * Gmail (`gmail.modify`): hidden quarantine label, `SPAM`, tag label, Trash; `messages.delete`
 * needs the full mail scope, so a Google hard delete runs the soft-delete plan (Trash).
 */
import {
  GRAPH_REMEDIATION_WELL_KNOWN_FOLDERS,
  type GraphRemediationWellKnownFolder,
} from '../clients/graph-mail-client';
import type {
  MessageVerdict,
  ProviderRefContainer,
  RemediationAction,
  RemediationActionKind,
  RemediationMailboxContainer,
  RemediationProvider,
  ReversalAction,
} from './vocabulary';

/** Graph well-known folder names the plans use (the client's list, R6.2). */
export const GRAPH_WELL_KNOWN_FOLDERS = GRAPH_REMEDIATION_WELL_KNOWN_FOLDERS;
export type GraphWellKnownFolder = GraphRemediationWellKnownFolder;

/** Gmail system labels the plans use. */
export const GMAIL_SYSTEM_LABELS = Object.freeze({
  inbox: 'INBOX',
  spam: 'SPAM',
  trash: 'TRASH',
  sent: 'SENT',
  draft: 'DRAFT',
} as const);

/** A destination of a Graph move: the gateway's quarantine folder or a well-known folder. */
export type GraphDestination =
  { kind: 'quarantine_folder' } | { kind: 'well_known'; name: GraphWellKnownFolder };

export type GraphPlanStep =
  | { op: 'ensure_quarantine_folder' }
  | { op: 'move'; destination: GraphDestination }
  | { op: 'add_tag_category' }
  | { op: 'remove_tag_category' }
  | { op: 'permanent_delete' };

/** A Gmail label reference: a system label id or one of the gateway's labels (ids cached). */
export type GmailLabelRef =
  | { kind: 'system'; id: 'INBOX' | 'SPAM' | 'TRASH' }
  | { kind: 'quarantine_label' }
  | { kind: 'tag_label' };

export type GmailPlanStep =
  | { op: 'ensure_quarantine_label' }
  | { op: 'ensure_tag_label' }
  | { op: 'modify'; add: GmailLabelRef[]; remove: GmailLabelRef[] }
  | { op: 'trash' }
  | { op: 'untrash_if_trashed' };

export interface ProviderActionPlan {
  action: RemediationActionKind;
  graph: readonly GraphPlanStep[];
  gmail: readonly GmailPlanStep[];
  /** The action that undoes this one; null when none (reversals, hard delete). */
  reversal: ReversalAction | null;
  /** The quarantine entry's container when a success creates a mailbox entry (R9.1, R9.3). */
  quarantineContainer: RemediationMailboxContainer | null;
  /** Result code a Google execution records (R5.4), or null. */
  gmailResultCode: 'hard_delete_unsupported_provider' | null;
}

const INBOX: GmailLabelRef = { kind: 'system', id: 'INBOX' };
const SPAM: GmailLabelRef = { kind: 'system', id: 'SPAM' };
const QUARANTINE_LABEL: GmailLabelRef = { kind: 'quarantine_label' };
const TAG_LABEL: GmailLabelRef = { kind: 'tag_label' };

const SOFT_DELETE_GMAIL: readonly GmailPlanStep[] = [{ op: 'trash' }];

/** The R3 table. */
export const REMEDIATION_PROVIDER_ACTIONS: Readonly<
  Record<RemediationActionKind, Readonly<ProviderActionPlan>>
> = Object.freeze({
  move_quarantine: {
    action: 'move_quarantine',
    graph: [
      { op: 'ensure_quarantine_folder' },
      { op: 'move', destination: { kind: 'quarantine_folder' } },
    ],
    gmail: [
      { op: 'ensure_quarantine_label' },
      { op: 'modify', add: [QUARANTINE_LABEL], remove: [INBOX] },
    ],
    reversal: 'restore_inbox',
    quarantineContainer: 'quarantine_folder',
    gmailResultCode: null,
  },
  move_junk: {
    action: 'move_junk',
    graph: [{ op: 'move', destination: { kind: 'well_known', name: 'junkemail' } }],
    gmail: [{ op: 'modify', add: [SPAM], remove: [INBOX] }],
    reversal: 'restore_inbox',
    quarantineContainer: 'junk',
    gmailResultCode: null,
  },
  tag: {
    action: 'tag',
    graph: [{ op: 'add_tag_category' }],
    gmail: [{ op: 'ensure_tag_label' }, { op: 'modify', add: [TAG_LABEL], remove: [] }],
    reversal: 'remove_tag',
    quarantineContainer: null,
    gmailResultCode: null,
  },
  soft_delete: {
    action: 'soft_delete',
    graph: [{ op: 'move', destination: { kind: 'well_known', name: 'recoverableitemsdeletions' } }],
    gmail: SOFT_DELETE_GMAIL,
    reversal: 'restore_inbox',
    quarantineContainer: 'deleted_items',
    gmailResultCode: null,
  },
  hard_delete: {
    action: 'hard_delete',
    graph: [{ op: 'permanent_delete' }],
    // `gmail.modify` cannot delete permanently: Trash, recorded with the result code.
    gmail: SOFT_DELETE_GMAIL,
    reversal: null,
    quarantineContainer: null,
    gmailResultCode: 'hard_delete_unsupported_provider',
  },
  restore_inbox: {
    action: 'restore_inbox',
    graph: [
      { op: 'move', destination: { kind: 'well_known', name: 'inbox' } },
      { op: 'remove_tag_category' },
    ],
    gmail: [
      { op: 'untrash_if_trashed' },
      { op: 'modify', add: [INBOX], remove: [SPAM, QUARANTINE_LABEL] },
    ],
    reversal: null,
    quarantineContainer: null,
    gmailResultCode: null,
  },
  remove_tag: {
    action: 'remove_tag',
    graph: [{ op: 'remove_tag_category' }],
    gmail: [{ op: 'modify', add: [], remove: [TAG_LABEL] }],
    reversal: null,
    quarantineContainer: null,
    gmailResultCode: null,
  },
} satisfies Record<RemediationActionKind, ProviderActionPlan>);

export function providerActionPlan(action: RemediationActionKind): Readonly<ProviderActionPlan> {
  return REMEDIATION_PROVIDER_ACTIONS[action];
}

/** True for actions a reversal can undo (everything but hard delete and the reversals). */
export function isReversible(action: RemediationActionKind): boolean {
  return REMEDIATION_PROVIDER_ACTIONS[action].reversal !== null;
}

/** The reversal of an action (`restore_inbox`, `remove_tag`), or null. */
export function reversalOf(action: RemediationActionKind): ReversalAction | null {
  return REMEDIATION_PROVIDER_ACTIONS[action].reversal;
}

/** True for the reversal actions themselves. */
export function isReversal(action: RemediationActionKind): action is ReversalAction {
  return action === 'restore_inbox' || action === 'remove_tag';
}

/** The quarantine entry container of an action (`quarantine_folder`, `junk`, `deleted_items`). */
export function containerOf(action: RemediationActionKind): RemediationMailboxContainer | null {
  return REMEDIATION_PROVIDER_ACTIONS[action].quarantineContainer;
}

/** A success of this action creates a mailbox-located quarantine entry (R9.1, R9.3). */
export function createsQuarantineEntry(action: RemediationActionKind): boolean {
  return containerOf(action) !== null;
}

/**
 * `provider_refs.container` after a successful execution: where the message is. A Google hard
 * delete lands in Trash (`deleted_items`); a Graph hard delete and a tag record none.
 */
export function executedContainerOf(
  action: RemediationActionKind,
  provider: RemediationProvider,
): ProviderRefContainer | null {
  if (action === 'restore_inbox') return 'inbox';
  if (action === 'hard_delete') return provider === 'google_workspace' ? 'deleted_items' : null;
  return containerOf(action);
}

/** The result code an execution records besides success (R5.4), or null. */
export function executionResultCode(
  action: RemediationActionKind,
  provider: RemediationProvider,
): 'hard_delete_unsupported_provider' | null {
  return provider === 'google_workspace'
    ? REMEDIATION_PROVIDER_ACTIONS[action].gmailResultCode
    : null;
}

// ---------------------------------------------------------------------------------------------
// "Already in target" (R5.4) and Gmail label changes
// ---------------------------------------------------------------------------------------------

/** Graph container ids resolved for the mailbox (well-known ids and the cached folder id). */
export interface GraphContainerIds {
  inbox: string;
  junkemail: string;
  recoverableitemsdeletions: string;
  /** The gateway's quarantine folder, when known. */
  quarantineFolder: string | null;
}

/**
 * Graph: whether the message state read before acting already satisfies the action (moves: the
 * parent folder; tag: the category present; remove_tag: absent; restore: in the Inbox and no tag;
 * hard delete never is — a message that is gone answers 404).
 */
export function graphTargetReached(
  action: RemediationActionKind,
  state: { parentFolderId: string | null; categories: readonly string[] },
  ids: GraphContainerIds,
  tagName: string,
): boolean {
  const hasTag = state.categories.includes(tagName);
  switch (action) {
    case 'move_quarantine':
      return ids.quarantineFolder !== null && state.parentFolderId === ids.quarantineFolder;
    case 'move_junk':
      return state.parentFolderId === ids.junkemail;
    case 'soft_delete':
      return state.parentFolderId === ids.recoverableitemsdeletions;
    case 'tag':
      return hasTag;
    case 'remove_tag':
      return !hasTag;
    case 'restore_inbox':
      return state.parentFolderId === ids.inbox && !hasTag;
    case 'hard_delete':
      return false;
  }
}

/** Graph categories after adding / removing the tag (no-op when already so). */
export function graphCategoriesWith(
  categories: readonly string[],
  tagName: string,
  present: boolean,
): { categories: string[]; changed: boolean } {
  const has = categories.includes(tagName);
  if (present === has) return { categories: [...categories], changed: false };
  return present
    ? { categories: [...categories, tagName], changed: true }
    : { categories: categories.filter((c) => c !== tagName), changed: true };
}

/** Gmail label ids of the gateway for one mailbox (cached on `api_mailboxes`). */
export interface GmailGatewayLabels {
  quarantineLabelId: string | null;
  tagLabelId: string | null;
}

function resolveLabel(ref: GmailLabelRef, labels: GmailGatewayLabels): string | null {
  if (ref.kind === 'system') return ref.id;
  return ref.kind === 'quarantine_label' ? labels.quarantineLabelId : labels.tagLabelId;
}

/**
 * The `modify` label changes of a Gmail step, reduced to what still differs from `labelIds`
 * (null labels — not created — are skipped). Empty lists = nothing to change.
 */
export function gmailModifyFor(
  step: Extract<GmailPlanStep, { op: 'modify' }>,
  labelIds: readonly string[],
  labels: GmailGatewayLabels,
): { add: string[]; remove: string[] } {
  const current = new Set(labelIds);
  const add: string[] = [];
  const remove: string[] = [];
  for (const ref of step.add) {
    const id = resolveLabel(ref, labels);
    if (id !== null && !current.has(id) && !add.includes(id)) add.push(id);
  }
  for (const ref of step.remove) {
    const id = resolveLabel(ref, labels);
    if (id !== null && current.has(id) && !remove.includes(id)) remove.push(id);
  }
  return { add, remove };
}

/** Gmail: whether the labels read before acting already satisfy the action. */
export function gmailTargetReached(
  action: RemediationActionKind,
  labelIds: readonly string[],
  labels: GmailGatewayLabels,
): boolean {
  const has = (id: string | null) => id !== null && labelIds.includes(id);
  const inInbox = labelIds.includes('INBOX');
  switch (action) {
    case 'move_quarantine':
      return has(labels.quarantineLabelId) && !inInbox;
    case 'move_junk':
      return labelIds.includes('SPAM') && !inInbox;
    case 'soft_delete':
    case 'hard_delete':
      return labelIds.includes('TRASH');
    case 'tag':
      return has(labels.tagLabelId);
    case 'remove_tag':
      return !has(labels.tagLabelId);
    case 'restore_inbox':
      return (
        inInbox &&
        !labelIds.includes('TRASH') &&
        !labelIds.includes('SPAM') &&
        !has(labels.quarantineLabelId)
      );
  }
}

/**
 * Locate filter (R5.3): Graph matches that are drafts or in Sent Items are not the delivered
 * copy; at most 5 are kept.
 */
export const LOCATE_MAX_MATCHES = 5;

export function graphLocateCandidates<
  T extends { parentFolderId: string | null; isDraft: boolean },
>(matches: readonly T[], sentItemsFolderId: string | null): T[] {
  return matches
    .filter(
      (m) => !m.isDraft && (sentItemsFolderId === null || m.parentFolderId !== sentItemsFolderId),
    )
    .slice(0, LOCATE_MAX_MATCHES);
}

/** Gmail matches whose labels are only `SENT` (and read-state labels) or drafts are dropped. */
export function gmailLocateCandidates<T extends { labelIds: readonly string[] }>(
  matches: readonly T[],
): T[] {
  const ignorable = new Set(['SENT', 'UNREAD', 'IMPORTANT', 'STARRED']);
  return matches
    .filter((m) => !m.labelIds.includes('DRAFT'))
    .filter(
      (m) =>
        !(
          m.labelIds.includes('SENT') &&
          m.labelIds.every((l) => ignorable.has(l) || l.startsWith('CATEGORY_'))
        ),
    )
    .slice(0, LOCATE_MAX_MATCHES);
}

// ---------------------------------------------------------------------------------------------
// Mailbox quarantine entry mappings (R9.1)
// ---------------------------------------------------------------------------------------------

/** `QuarantineReason` values an entry of a remediated copy can carry. */
export type MailboxQuarantineReason =
  'malware' | 'phishing' | 'spam' | 'bulk' | 'bec' | 'dlp' | 'suspicious' | 'policy';

const REASON_OF_VERDICT: Readonly<Partial<Record<MessageVerdict, MailboxQuarantineReason>>> =
  Object.freeze({
    malware: 'malware',
    phishing: 'phishing',
    spam: 'spam',
    bulk: 'bulk',
    bec: 'bec',
    dlp_violation: 'dlp',
    suspicious: 'suspicious',
  });

/** R9.1: the entry's `reason` from the copy verdict (`policy` for anything else). */
export function verdictToQuarantineReason(verdict: MessageVerdict | null): MailboxQuarantineReason {
  return (verdict !== null ? REASON_OF_VERDICT[verdict] : undefined) ?? 'policy';
}

/** `QuarantinePrimaryEngine` values a mailbox entry can carry. */
export type MailboxQuarantinePrimaryEngine =
  'attachment' | 'url' | 'sandbox' | 'rspamd' | 'bec' | 'dlp' | 'none';

/** R9.1 hard block → primary engine table. */
export const HARD_BLOCK_PRIMARY_ENGINE: Readonly<Record<string, MailboxQuarantinePrimaryEngine>> =
  Object.freeze({
    'hb.malware_attachment': 'attachment',
    'hb.malware_url': 'url',
    'hb.url_tenant_blocked': 'url',
    'hb.malware_sandbox': 'sandbox',
    'hb.known_phishing': 'rspamd',
    'hb.bec_malicious': 'bec',
    'hb.dlp_block': 'dlp',
  });

/** R9.1: `primary_engine` from the first hard block (`none` without one or for another id). */
export function hardBlockToPrimaryEngine(
  hardBlocks: readonly string[],
): MailboxQuarantinePrimaryEngine {
  const first = hardBlocks[0];
  if (first === undefined) return 'none';
  return Object.prototype.hasOwnProperty.call(HARD_BLOCK_PRIMARY_ENGINE, first)
    ? (HARD_BLOCK_PRIMARY_ENGINE[first] as MailboxQuarantinePrimaryEngine)
    : 'none';
}

/** The fixed, content-free explanation of a mailbox entry (R9.1). */
export function mailboxEntryExplanation(ruleId: string | null): string {
  return ruleId === null
    ? 'Removed from the mailbox by an API-mode remediation.'
    : `Removed from the mailbox by the API-mode remediation policy (rule ${ruleId})`;
}

/** Narrowing helper for the decision actions. */
export const isRemediationAction = (action: RemediationActionKind): action is RemediationAction =>
  !isReversal(action);
