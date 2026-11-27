import {
  GMAIL_SYSTEM_LABELS,
  gmailLocateCandidates,
  gmailModifyFor,
  gmailTargetReached,
  graphCategoriesWith,
  graphLocateCandidates,
  graphTargetReached,
  isMailboxApiError,
  LOCATE_MAX_MATCHES,
  providerActionPlan,
  type GmailClient,
  type GmailGatewayLabels,
  type GraphContainerIds,
  type GraphMailClient,
  type GraphWellKnownFolder,
  type RemediationActionKind,
} from '@email-gateway/mailbox-api';

/** The Graph client calls the executor uses (the real `GraphMailClient`, or a fake in tests). */
export type GraphMailPort = Pick<
  GraphMailClient,
  | 'findMessagesByInternetMessageId'
  | 'getMessageState'
  | 'wellKnownFolderId'
  | 'ensureChildFolder'
  | 'moveMessage'
  | 'setCategories'
  | 'permanentDelete'
>;

/** The Gmail client calls the executor uses. */
export type GmailPort = Pick<
  GmailClient,
  | 'findMessagesByRfc822Id'
  | 'messageLabels'
  | 'listLabels'
  | 'ensureLabel'
  | 'modifyLabels'
  | 'trash'
  | 'untrash'
>;

/** Platform names of the gateway's containers (R17; never per tenant). */
export interface ContainerNames {
  quarantineFolderName: string;
  quarantineFolderHidden: boolean;
  gmailQuarantineLabel: string;
  tagName: string;
}

/** Container ids cached on `api_mailboxes` (Graph folder / Gmail label ids). */
export interface CachedContainers {
  quarantineId: string | null;
  tagId: string | null;
}

export interface ExecInput {
  action: RemediationActionKind;
  /** Graph: provider user id or primary address; Gmail: the mailbox address (token subject). */
  user: string;
  /** Provider ids to try first (stored copy id, the reversed action's ids); state-read first. */
  knownIds: readonly string[];
  /** The copy's `Message-ID` (locate step, R5.3); null when the message has none. */
  internetMessageId: string | null;
  containers: CachedContainers;
  names: ContainerNames;
  signal: AbortSignal;
  /** Called before each provider message is acted on (lease renewal). */
  keepAlive?: () => Promise<void>;
}

export type ExecResult =
  | {
      kind: 'done';
      /** Provider ids acted on (≤ 5), as found. */
      before: string[];
      /** Provider ids after the action (Graph moves return new ids); empty after a delete. */
      after: string[];
      /** Every message was already in the target state (R5.4 `already_in_target`). */
      already: boolean;
      /** The locate step found the message(s) (journal copies, stale ids). */
      located: boolean;
      containers: CachedContainers;
    }
  | {
      kind: 'not_found';
      /** A locate by Message-ID ran (false: nothing to locate with). */
      locatable: boolean;
      containers: CachedContainers;
    };

/** True for a provider `404` (`not_found`). */
export const isNotFound = (error: unknown): boolean =>
  isMailboxApiError(error) && error.code === 'not_found';

const unique = (ids: readonly string[]): string[] => [
  ...new Set(ids.filter((id) => typeof id === 'string' && id.length > 0)),
];

/**
 * Graph well-known folder ids of one mailbox, resolved once per process and mailbox (R5.3 "sent
 * items resolved once per mailbox"; R5.4 target checks).
 */
export class GraphFolderIds {
  private readonly cache = new Map<string, Map<GraphWellKnownFolder, string>>();

  async get(
    port: GraphMailPort,
    mailboxKey: string,
    user: string,
    name: GraphWellKnownFolder,
    signal: AbortSignal,
  ): Promise<string> {
    let folders = this.cache.get(mailboxKey);
    if (!folders) {
      if (this.cache.size >= 50_000) this.cache.clear();
      folders = new Map();
      this.cache.set(mailboxKey, folders);
    }
    const known = folders.get(name);
    if (known) return known;
    const id = await port.wellKnownFolderId(user, name, signal);
    folders.set(name, id);
    return id;
  }

  forget(mailboxKey: string): void {
    this.cache.delete(mailboxKey);
  }
}

interface GraphCandidate {
  id: string;
  parentFolderId: string | null;
  categories: string[];
}

/**
 * Executes one action on Microsoft Graph (R3, R5.3, R5.4): reads the state of the known ids
 * (else locates by Internet Message-ID, excluding drafts and Sent Items), then per message either
 * records "already in target" or runs the plan of `providerActionPlan(action).graph` (ensure the
 * hidden quarantine folder — a cached id answering `404` is re-ensured once —, move, category
 * add/remove, permanent delete). Returns the ids before and after (moves return new ids).
 */
export async function executeGraph(
  port: GraphMailPort,
  folders: GraphFolderIds,
  mailboxKey: string,
  input: ExecInput,
): Promise<ExecResult> {
  const { user, signal, names } = input;
  const containers: CachedContainers = { ...input.containers };
  let located = false;
  const candidates: GraphCandidate[] = [];
  for (const id of unique(input.knownIds).slice(0, LOCATE_MAX_MATCHES)) {
    try {
      candidates.push(await port.getMessageState(user, id, signal));
    } catch (error) {
      if (!isNotFound(error)) throw error;
    }
  }
  if (candidates.length === 0) {
    if (input.internetMessageId === null) {
      return { kind: 'not_found', locatable: false, containers };
    }
    const matches = await port.findMessagesByInternetMessageId(
      user,
      input.internetMessageId,
      signal,
    );
    const sent =
      matches.length > 0 ? await folders.get(port, mailboxKey, user, 'sentitems', signal) : null;
    located = true;
    for (const match of graphLocateCandidates(matches, sent)) {
      try {
        candidates.push(await port.getMessageState(user, match.id, signal));
      } catch (error) {
        if (!isNotFound(error)) throw error;
      }
    }
    if (candidates.length === 0) return { kind: 'not_found', locatable: true, containers };
  }

  const ids: GraphContainerIds = {
    inbox: await folders.get(port, mailboxKey, user, 'inbox', signal),
    junkemail: await folders.get(port, mailboxKey, user, 'junkemail', signal),
    recoverableitemsdeletions: await folders.get(
      port,
      mailboxKey,
      user,
      'recoverableitemsdeletions',
      signal,
    ),
    quarantineFolder: containers.quarantineId,
  };
  const plan = providerActionPlan(input.action).graph;
  const ensureFolder = async (refresh: boolean): Promise<string> => {
    if (!refresh && containers.quarantineId) return containers.quarantineId;
    const folder = await port.ensureChildFolder(
      user,
      'msgfolderroot',
      names.quarantineFolderName,
      names.quarantineFolderHidden,
      signal,
    );
    containers.quarantineId = folder.id;
    ids.quarantineFolder = folder.id;
    return folder.id;
  };
  if (plan.some((s) => s.op === 'ensure_quarantine_folder')) await ensureFolder(false);

  const before: string[] = [];
  const after: string[] = [];
  let already = 0;
  let processed = 0;
  for (const candidate of candidates) {
    await input.keepAlive?.();
    if (graphTargetReached(input.action, candidate, ids, names.tagName)) {
      before.push(candidate.id);
      after.push(candidate.id);
      already += 1;
      processed += 1;
      continue;
    }
    let currentId: string | null = candidate.id;
    let parent = candidate.parentFolderId;
    let categories = [...candidate.categories];
    try {
      for (const step of plan) {
        if (currentId === null) break;
        switch (step.op) {
          case 'ensure_quarantine_folder':
            break;
          case 'move': {
            const toQuarantine = step.destination.kind === 'quarantine_folder';
            const destination =
              step.destination.kind === 'quarantine_folder'
                ? await ensureFolder(false)
                : await folders.get(port, mailboxKey, user, step.destination.name, signal);
            if (parent === destination) break;
            let moved: { id: string; parentFolderId: string | null };
            try {
              moved = await port.moveMessage(user, currentId, destination, signal);
            } catch (error) {
              // A cached quarantine folder the user deleted: re-ensure once, then retry the move.
              if (!(toQuarantine && isNotFound(error))) throw error;
              const fresh = await ensureFolder(true);
              moved = await port.moveMessage(user, currentId, fresh, signal);
            }
            currentId = moved.id;
            parent = moved.parentFolderId;
            break;
          }
          case 'add_tag_category':
          case 'remove_tag_category': {
            const next = graphCategoriesWith(
              categories,
              names.tagName,
              step.op === 'add_tag_category',
            );
            if (next.changed) {
              categories = await port.setCategories(user, currentId, next.categories, signal);
            }
            break;
          }
          case 'permanent_delete':
            await port.permanentDelete(user, currentId, signal);
            currentId = null;
            break;
        }
      }
    } catch (error) {
      // The message vanished between the state read and the action: not acted on.
      if (isNotFound(error)) continue;
      throw error;
    }
    before.push(candidate.id);
    if (currentId !== null) after.push(currentId);
    processed += 1;
  }
  if (processed === 0) return { kind: 'not_found', locatable: located, containers };
  return {
    kind: 'done',
    before: before.slice(0, LOCATE_MAX_MATCHES),
    after: after.slice(0, LOCATE_MAX_MATCHES),
    already: already === processed,
    located,
    containers,
  };
}

interface GmailCandidate {
  id: string;
  labelIds: string[];
}

/**
 * Executes one action on Gmail (R3, R5.3, R5.4): the labels of the known ids (else locate by
 * `rfc822msgid:`, dropping drafts and Sent-only matches), then per message "already in target" or
 * the plan of `providerActionPlan(action).gmail` (ensure the hidden quarantine label / the tag
 * label, modify labels, trash, untrash). Gmail ids do not change. A hard delete runs the Trash
 * plan (`gmail.modify` cannot delete permanently; the caller records the result code).
 */
export async function executeGmail(port: GmailPort, input: ExecInput): Promise<ExecResult> {
  const { user, signal, names } = input;
  const containers: CachedContainers = { ...input.containers };
  let located = false;
  let candidates: GmailCandidate[] = [];
  for (const id of unique(input.knownIds).slice(0, LOCATE_MAX_MATCHES)) {
    try {
      const m = await port.messageLabels(user, id, signal);
      candidates.push({ id: m.id, labelIds: m.labelIds });
    } catch (error) {
      if (!isNotFound(error)) throw error;
    }
  }
  if (candidates.length === 0) {
    if (input.internetMessageId === null) {
      return { kind: 'not_found', locatable: false, containers };
    }
    located = true;
    const matches = await port.findMessagesByRfc822Id(user, input.internetMessageId, signal);
    const read: GmailCandidate[] = [];
    for (const match of matches) {
      try {
        const m = await port.messageLabels(user, match.id, signal);
        read.push({ id: m.id, labelIds: m.labelIds });
      } catch (error) {
        if (!isNotFound(error)) throw error;
      }
    }
    candidates = gmailLocateCandidates(read);
    if (candidates.length === 0) return { kind: 'not_found', locatable: true, containers };
  }

  const plan = providerActionPlan(input.action).gmail;
  const findLabel = async (name: string): Promise<string | null> => {
    const wanted = name.toLowerCase();
    return (
      (await port.listLabels(user, signal)).find((l) => l.name.toLowerCase() === wanted)?.id ?? null
    );
  };
  const needsQuarantine = plan.some(
    (s) =>
      s.op === 'ensure_quarantine_label' ||
      (s.op === 'modify' && [...s.add, ...s.remove].some((r) => r.kind === 'quarantine_label')),
  );
  const needsTag = plan.some(
    (s) =>
      s.op === 'ensure_tag_label' ||
      (s.op === 'modify' && [...s.add, ...s.remove].some((r) => r.kind === 'tag_label')),
  );
  const ensureQuarantine = async (refresh: boolean) => {
    if (!refresh && containers.quarantineId) return;
    containers.quarantineId = (
      await port.ensureLabel(user, names.gmailQuarantineLabel, true, signal)
    ).id;
  };
  const ensureTag = async (refresh: boolean) => {
    if (!refresh && containers.tagId) return;
    containers.tagId = (await port.ensureLabel(user, names.tagName, false, signal)).id;
  };
  if (plan.some((s) => s.op === 'ensure_quarantine_label')) await ensureQuarantine(false);
  else if (needsQuarantine && !containers.quarantineId) {
    // Removal only (restore): look the label up, never create it.
    containers.quarantineId = await findLabel(names.gmailQuarantineLabel);
  }
  if (plan.some((s) => s.op === 'ensure_tag_label')) await ensureTag(false);
  else if (needsTag && !containers.tagId) containers.tagId = await findLabel(names.tagName);

  const labelsOf = (): GmailGatewayLabels => ({
    quarantineLabelId: containers.quarantineId,
    tagLabelId: containers.tagId,
  });
  const before: string[] = [];
  const after: string[] = [];
  let already = 0;
  let processed = 0;
  for (const candidate of candidates) {
    await input.keepAlive?.();
    if (gmailTargetReached(input.action, candidate.labelIds, labelsOf())) {
      before.push(candidate.id);
      after.push(candidate.id);
      already += 1;
      processed += 1;
      continue;
    }
    let labels = [...candidate.labelIds];
    try {
      for (const step of plan) {
        switch (step.op) {
          case 'ensure_quarantine_label':
          case 'ensure_tag_label':
            break;
          case 'trash':
            if (!labels.includes(GMAIL_SYSTEM_LABELS.trash)) {
              labels = (await port.trash(user, candidate.id, signal)).labelIds;
            }
            break;
          case 'untrash_if_trashed':
            if (labels.includes(GMAIL_SYSTEM_LABELS.trash)) {
              labels = (await port.untrash(user, candidate.id, signal)).labelIds;
            }
            break;
          case 'modify': {
            const change = gmailModifyFor(step, labels, labelsOf());
            if (change.add.length === 0 && change.remove.length === 0) break;
            try {
              labels = (
                await port.modifyLabels(user, candidate.id, change.add, change.remove, signal)
              ).labelIds;
            } catch (error) {
              // A cached gateway label the user deleted: re-ensure once, then retry.
              const usesCached = [...step.add].some(
                (r) => r.kind === 'quarantine_label' || r.kind === 'tag_label',
              );
              if (!(usesCached && isNotFound(error))) throw error;
              if (step.add.some((r) => r.kind === 'quarantine_label')) await ensureQuarantine(true);
              if (step.add.some((r) => r.kind === 'tag_label')) await ensureTag(true);
              const retry = gmailModifyFor(step, labels, labelsOf());
              labels = (
                await port.modifyLabels(user, candidate.id, retry.add, retry.remove, signal)
              ).labelIds;
            }
            break;
          }
        }
      }
    } catch (error) {
      if (isNotFound(error)) continue;
      throw error;
    }
    before.push(candidate.id);
    after.push(candidate.id);
    processed += 1;
  }
  if (processed === 0) return { kind: 'not_found', locatable: located, containers };
  return {
    kind: 'done',
    before: before.slice(0, LOCATE_MAX_MATCHES),
    after: after.slice(0, LOCATE_MAX_MATCHES),
    already: already === processed,
    located,
    containers,
  };
}
