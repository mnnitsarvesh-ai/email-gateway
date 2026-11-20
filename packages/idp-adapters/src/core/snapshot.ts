/**
 * Mailbox state snapshots (design note D8.3): diff of one identity's current provider state against
 * the stored items, with cursor-confirmed semantics so no change is lost on a crash.
 *
 * Every item row written by a page carries `emitted_seq` = that page's cursor `seq`. When `ingest`
 * runs with a cursor whose `seq = S`, rows with `emitted_seq > S` were written by a page the
 * runner never committed: they count as not yet known and their change is re-emitted with the
 * same event id (deduplicated downstream).
 *
 * Event id: `snap:` + SHA-256(itemHash|change|versionFingerprint|emittedSeq) (deviation WP1-3:
 * the fingerprint and the emitting page's seq replace "first seen of this version", so a re-emitted
 * change has the identical id without an extra column, and A→B→A→B changes stay distinct).
 */
import type { ProviderEvent, ProviderIdentityRef, ProviderStream } from '../port/ato-port';
import type {
  MailboxItemChange,
  MailboxItemKind,
  MailboxItemRow,
  MailboxItemWrite,
} from '../port/state-ports';
import { sha256Hex } from './hash';

export interface SnapshotItem {
  kind: MailboxItemKind;
  itemHash: string;
  providerItemRef: string | null;
  targetDomain: string | null;
  traits: readonly string[];
  enabled: boolean | null;
  source: 'snapshot' | 'audit';
}

type MailboxChange = NonNullable<ProviderEvent['mailbox']>['change'];

/** Which event a change of an item kind produces (`null` = state only, no event). */
function eventChange(kind: MailboxItemKind, change: MailboxItemChange): MailboxChange | null {
  switch (kind) {
    case 'forwarding':
      return change === 'removed' ? 'forwarding_removed' : 'forwarding_added';
    case 'inbox_rule':
      if (change === 'added') return 'inbox_rule_added';
      if (change === 'changed') return 'inbox_rule_changed';
      return null;
    case 'delegate':
      return change === 'added' ? 'delegate_added' : null;
    case 'mailbox_permission':
    case 'send_as':
      return change === 'added' ? 'permission_added' : null;
  }
}

/** The stream a mailbox change belongs to (companions of the mailbox primary, D3). */
export function streamOfMailboxChange(
  kind: MailboxItemKind,
  traits: readonly string[],
): ProviderStream {
  switch (kind) {
    case 'forwarding':
      return 'forwarding_changes';
    case 'inbox_rule':
      return traits.includes('forwards') ||
        traits.includes('redirects') ||
        traits.includes('forwards_as_attachment')
        ? 'forwarding_changes'
        : 'mailbox_audit';
    case 'delegate':
    case 'mailbox_permission':
    case 'send_as':
      return 'delegation_changes';
  }
}

export function itemFingerprint(item: {
  targetDomain: string | null;
  traits: readonly string[];
  enabled: boolean | null;
  state: 'present' | 'removed';
}): string {
  return sha256Hex(
    JSON.stringify([item.state, item.enabled, item.targetDomain, [...item.traits].sort()]),
  );
}

export function snapshotEventId(
  itemHash: string,
  change: MailboxItemChange,
  fingerprint: string,
  emittedSeq: bigint,
): string {
  // 32 hex characters: 8.4 refuses runs of 40+ base64-like characters as token-shaped (WP3-2).
  return `snap:${sha256Hex(`${itemHash}|${change}|${fingerprint}|${emittedSeq.toString()}`).slice(0, 32)}`;
}

/** Whether an item emits an event at all in its current state (disabled rules are state only). */
function emitsWhenPresent(item: { kind: MailboxItemKind; enabled: boolean | null }): boolean {
  return item.enabled !== false;
}

export interface SnapshotDiffInput {
  provider: ProviderIdentityRef['provider'];
  identity: ProviderIdentityRef;
  /** The provider's current state of the covered kinds. */
  current: readonly SnapshotItem[];
  /** Stored rows of this identity (`MailboxStateStore.load`). */
  known: readonly MailboxItemRow[];
  /** Kinds this snapshot fully covers (absent items of these kinds are removed). */
  coveredKinds: readonly MailboxItemKind[];
  /** Seq of the cursor `ingest` was called with (S). */
  cursorSeq: bigint;
  /** Seq of the page being produced (S + 1). */
  pageSeq: bigint;
  now: Date;
}

export interface SnapshotDiffResult {
  events: ProviderEvent[];
  writes: MailboxItemWrite[];
}

function buildEvent(
  input: SnapshotDiffInput,
  item: {
    kind: MailboxItemKind;
    itemHash: string;
    targetDomain: string | null;
    traits: readonly string[];
  },
  change: MailboxChange,
  eventId: string,
): ProviderEvent {
  const mailbox: NonNullable<ProviderEvent['mailbox']> = { change };
  if (item.targetDomain) mailbox.targetDomain = item.targetDomain;
  if (item.kind === 'inbox_rule') {
    mailbox.ruleHash = item.itemHash;
    mailbox.ruleTraits = [...item.traits].slice(0, 16);
  }
  return {
    provider: input.provider,
    eventId,
    stream: streamOfMailboxChange(item.kind, item.traits),
    occurredAt: input.now.toISOString(),
    identity: input.identity,
    mailbox,
  };
}

export function diffSnapshot(input: SnapshotDiffInput): SnapshotDiffResult {
  const events: ProviderEvent[] = [];
  const writes: MailboxItemWrite[] = [];
  const nowIso = input.now.toISOString();
  const knownByHash = new Map(input.known.map((row) => [`${row.kind}|${row.itemHash}`, row]));
  const seen = new Set<string>();

  const emit = (
    item: {
      kind: MailboxItemKind;
      itemHash: string;
      targetDomain: string | null;
      traits: readonly string[];
    },
    change: MailboxItemChange,
    fingerprint: string,
    seq: bigint,
  ) => {
    const eventKind = eventChange(item.kind, change);
    if (eventKind === null) return;
    events.push(
      buildEvent(input, item, eventKind, snapshotEventId(item.itemHash, change, fingerprint, seq)),
    );
  };

  for (const item of input.current) {
    const key = `${item.kind}|${item.itemHash}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const row = knownByHash.get(key);
    const fingerprint = itemFingerprint({ ...item, state: 'present' });
    const base = {
      kind: item.kind,
      itemHash: item.itemHash,
      providerItemRef: item.providerItemRef,
      targetDomain: item.targetDomain,
      traits: item.traits,
      enabled: item.enabled,
      state: 'present' as const,
      source: item.source,
      lastSeenAt: nowIso,
      removedAt: null,
    };
    if (!row || row.state === 'removed') {
      const change: MailboxItemChange = 'added';
      if (emitsWhenPresent(item)) emit(item, change, fingerprint, input.pageSeq);
      writes.push({ ...base, firstSeenAt: nowIso, change });
      continue;
    }
    const rowFingerprint = itemFingerprint(row);
    const unconfirmed = row.emittedSeq > input.cursorSeq;
    if (rowFingerprint !== fingerprint) {
      const change: MailboxItemChange = 'changed';
      if (emitsWhenPresent(item)) emit(item, change, fingerprint, input.pageSeq);
      writes.push({ ...base, firstSeenAt: row.firstSeenAt, change });
      continue;
    }
    if (unconfirmed) {
      // Written by a page that was never committed: re-emit the identical event.
      if (row.lastChange !== 'removed' && emitsWhenPresent(item)) {
        emit(item, row.lastChange, fingerprint, row.emittedSeq);
      }
      writes.push({ ...base, firstSeenAt: row.firstSeenAt, change: null });
      continue;
    }
    writes.push({ ...base, firstSeenAt: row.firstSeenAt, change: null });
  }

  for (const row of input.known) {
    const key = `${row.kind}|${row.itemHash}`;
    if (seen.has(key) || !input.coveredKinds.includes(row.kind)) continue;
    if (row.state === 'removed') {
      if (row.emittedSeq > input.cursorSeq && row.lastChange === 'removed') {
        emit(row, 'removed', itemFingerprint(row), row.emittedSeq);
      }
      continue;
    }
    const removed = { ...row, state: 'removed' as const };
    const fingerprint = itemFingerprint(removed);
    emit(row, 'removed', fingerprint, input.pageSeq);
    writes.push({
      kind: row.kind,
      itemHash: row.itemHash,
      providerItemRef: row.providerItemRef,
      targetDomain: row.targetDomain,
      traits: row.traits,
      enabled: row.enabled,
      state: 'removed',
      source: row.source,
      firstSeenAt: row.firstSeenAt,
      lastSeenAt: row.lastSeenAt,
      removedAt: nowIso,
      change: 'removed',
    });
  }
  return { events, writes };
}
