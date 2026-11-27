/**
 * Mailbox state of the Graph and Gmail simulators (step API-1 D13, TEST-ONLY): synthetic messages
 * delivered through the admin API (or `deliverMessage` in-process), Graph delta sequences, Gmail
 * history ids, cursor expiry, and the Graph subscription callbacks (validation handshake, change
 * and lifecycle notifications).
 *
 * Callbacks go only to local targets (loopback, private ranges, single-label Compose service
 * names, reserved test TLDs): the simulator never contacts the Internet. Synthetic data only.
 */
import { randomBytes } from 'node:crypto';
import type { GsCustomer, GsUser } from './google-types';
import type { SimNotification, SimScript } from './script';
import type {
  MsDirectory,
  MsSubscription,
  MsUser,
  SimMailbox,
  SimMailFolder,
  SimMailMessage,
} from './types';

/** Graph's maximum lifetime of an Outlook message subscription (minutes). */
export const GRAPH_SUBSCRIPTION_MAX_MINUTES = 4230;
const CALLBACK_TIMEOUT_MS = 5_000;
const CHUNK_BYTES = 64 * 1024;
const GRAPH_ID_PREFIX = 'AAMkEXAMPLE';
const GMAIL_ID_BASE = 0x18c00000000000;
const HEADER_SCAN_BYTES = 64 * 1024;

export type MailboxOwner =
  | { provider: 'microsoft'; directory: MsDirectory; user: MsUser }
  | { provider: 'google'; customer: GsCustomer; user: GsUser };

/** The mailbox of a user, created empty on first use. */
export function mailboxOf(
  owner: { mailboxes?: Record<string, SimMailbox> },
  userId: string,
): SimMailbox {
  const mailboxes = (owner.mailboxes ??= {});
  return (mailboxes[userId] ??= { seq: 0, cursorFloor: 0, messages: [] });
}

// ---------------------------------------------------------------------------------------------
// Step API-2 (R7): Graph folders and message location state
// ---------------------------------------------------------------------------------------------

/** Graph well-known folders of a simulated mailbox: name → display name. */
export const GRAPH_WELL_KNOWN_FOLDERS: Readonly<Record<string, string>> = Object.freeze({
  msgfolderroot: 'Top of Information Store',
  inbox: 'Inbox',
  junkemail: 'Junk Email',
  sentitems: 'Sent Items',
  deleteditems: 'Deleted Items',
  drafts: 'Drafts',
  archive: 'Archive',
  recoverableitemsdeletions: 'Deletions',
});
/** Well-known folders that are not children of `msgfolderroot` (Recoverable Items). */
const RECOVERABLE_ROOT = 'recoverableitemsroot';

const folderIdOf = (userId: string, key: string): string =>
  `AAMkEXAMPLEfld${Buffer.from(`${userId}:${key}`, 'utf8').toString('base64url')}`;

/** The folders of a Graph mailbox, with the well-known ones created on first use. */
export function graphFolders(mailbox: SimMailbox, userId: string): SimMailFolder[] {
  if (!mailbox.folders) {
    const root = folderIdOf(userId, 'msgfolderroot');
    mailbox.folders = Object.entries(GRAPH_WELL_KNOWN_FOLDERS).map(([name, displayName]) => ({
      id: folderIdOf(userId, name),
      displayName,
      parentFolderId:
        name === 'msgfolderroot'
          ? null
          : name === 'recoverableitemsdeletions'
            ? folderIdOf(userId, RECOVERABLE_ROOT)
            : root,
      wellKnownName: name,
      isHidden: name === 'recoverableitemsdeletions',
    }));
  }
  return mailbox.folders;
}

/** A Graph folder by well-known name (case-insensitive) or id. */
export function graphFolder(
  mailbox: SimMailbox,
  userId: string,
  key: string,
): SimMailFolder | undefined {
  const lowered = key.toLowerCase();
  return graphFolders(mailbox, userId).find(
    (f) => f.id === key || (f.wellKnownName !== null && f.wellKnownName === lowered),
  );
}

/** The folder id of a Graph message (absent = the Inbox). */
export function graphFolderIdOf(
  mailbox: SimMailbox,
  userId: string,
  message: SimMailMessage,
): string {
  return message.folderId ?? (graphFolder(mailbox, userId, 'inbox') as SimMailFolder).id;
}

/** True when the Graph message is in the Inbox (moves into the Inbox clear `folderId`). */
export function inGraphInbox(message: SimMailMessage): boolean {
  return message.folderId === undefined;
}

/** A message that exists under this id (not moved away, not deleted). */
export function liveMessage(mailbox: SimMailbox, messageId: string): SimMailMessage | undefined {
  return mailbox.messages.find(
    (m) => m.id === messageId && m.removedSeq === undefined && m.deleted !== true,
  );
}

/** Where a message is (admin API `GET /admin/mailboxes/{user}/messages/{id}`, tests). */
export interface SimMessageLocation {
  provider: 'microsoft' | 'google';
  userId: string;
  /** The id asked for. */
  messageId: string;
  /** The id the message has now (after Graph moves), or null when it was deleted. */
  currentId: string | null;
  state: 'present' | 'deleted';
  /** Graph: the folder (`wellKnownName` null for created folders). */
  folder: {
    id: string;
    displayName: string;
    wellKnownName: string | null;
    isHidden: boolean;
  } | null;
  /** Gmail: the labels (system ids and user label ids). */
  labelIds: string[];
  /** Gmail: names of the user labels on the message. */
  labelNames: string[];
  /** Graph: categories. */
  categories: string[];
}

/**
 * The location of a message, following Graph moves from an old id to the current one. Null for
 * an unknown mailbox or id.
 */
export function messageLocation(
  script: SimScript,
  user: string,
  messageId: string,
): SimMessageLocation | null {
  const owner = findMailboxOwner(script, user);
  if (!owner) return null;
  const mailbox =
    owner.provider === 'microsoft'
      ? mailboxOf(owner.directory, owner.user.id)
      : mailboxOf(owner.customer, owner.user.id);
  let message = mailbox.messages.find((m) => m.id === messageId);
  if (!message) return null;
  for (let hops = 0; message.movedToId !== undefined && hops < 1000; hops += 1) {
    const next = mailbox.messages.find((m) => m.id === message!.movedToId);
    if (!next) break;
    message = next;
  }
  // Deleted (Graph permanentDelete, Gmail delete) or removed through the admin API.
  const gone =
    message.deleted === true ||
    (message.removedSeq !== undefined && message.movedToId === undefined);
  const base = {
    provider: owner.provider,
    userId: owner.user.id,
    messageId,
    currentId: gone ? null : message.id,
    state: gone ? ('deleted' as const) : ('present' as const),
  };
  if (owner.provider === 'microsoft') {
    const folder = graphFolder(
      mailbox,
      owner.user.id,
      graphFolderIdOf(mailbox, owner.user.id, message),
    );
    return {
      ...base,
      folder: folder
        ? {
            id: folder.id,
            displayName: folder.displayName,
            wellKnownName: folder.wellKnownName,
            isHidden: folder.isHidden,
          }
        : null,
      labelIds: [],
      labelNames: [],
      categories: [...(message.categories ?? [])],
    };
  }
  const labelIds = [...(message.labelIds ?? [])];
  const names = new Map((mailbox.labels ?? []).map((l) => [l.id, l.name]));
  return {
    ...base,
    folder: null,
    labelIds,
    labelNames: labelIds.filter((id) => names.has(id)).map((id) => names.get(id) as string),
    categories: [],
  };
}

/** Finds a user of any simulated directory by id, primary address, UPN, `mail` or alias. */
export function findMailboxOwner(script: SimScript, key: string): MailboxOwner | null {
  const lowered = key.toLowerCase();
  for (const directory of script.dataset.microsoft?.directories ?? []) {
    const user = directory.users.find(
      (u) =>
        u.id.toLowerCase() === lowered ||
        u.userPrincipalName.toLowerCase() === lowered ||
        (u.mail ?? '').toLowerCase() === lowered ||
        u.proxyAddresses.some((p) => p.toLowerCase() === `smtp:${lowered}`),
    );
    if (user) return { provider: 'microsoft', directory, user };
  }
  for (const customer of script.dataset.google?.customers ?? []) {
    const user = customer.users.find(
      (u) =>
        u.id === key ||
        u.primaryEmail.toLowerCase() === lowered ||
        u.aliases.some((alias) => alias.toLowerCase() === lowered),
    );
    if (user) return { provider: 'google', customer, user };
  }
  return null;
}

export function emlBytes(message: SimMailMessage): Buffer {
  return Buffer.from(message.emlBase64, 'base64');
}

/** The first header `name` of an EML, unfolded and trimmed (bounded scan), or null. */
export function headerValue(eml: Buffer, name: string): string | null {
  const head = eml.subarray(0, HEADER_SCAN_BYTES).toString('utf8');
  const lines = head.split(/\r?\n/);
  const wanted = name.toLowerCase();
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] as string;
    if (line.length === 0) break;
    const colon = line.indexOf(':');
    if (colon <= 0 || line.slice(0, colon).toLowerCase() !== wanted) continue;
    let value = line.slice(colon + 1);
    while (i + 1 < lines.length && /^[ \t]/.test(lines[i + 1] as string)) {
      i += 1;
      value += lines[i] as string;
    }
    return value.trim();
  }
  return null;
}

/** Every header of an EML as `{ name, value }` (bounded scan, unfolded). */
export function headerFields(eml: Buffer): { name: string; value: string }[] {
  const fields: { name: string; value: string }[] = [];
  const lines = eml.subarray(0, HEADER_SCAN_BYTES).toString('utf8').split(/\r?\n/);
  for (const line of lines) {
    if (line.length === 0) break;
    if (/^[ \t]/.test(line)) {
      const last = fields[fields.length - 1];
      if (last) last.value += line;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon > 0) fields.push({ name: line.slice(0, colon), value: line.slice(colon + 1) });
  }
  return fields.map((f) => ({ name: f.name, value: f.value.trim() }));
}

/** Slices a buffer into chunks for a streamed answer. */
export function* chunked(buffer: Buffer, size = CHUNK_BYTES): Generator<Buffer> {
  for (let offset = 0; offset < buffer.length; offset += size) {
    yield buffer.subarray(offset, offset + size);
  }
}

/** Padded base64url of a buffer in chunks (3-byte aligned slices, so chunks concatenate). */
export function* base64UrlChunks(buffer: Buffer, size = 48 * 1024): Generator<string> {
  const aligned = size - (size % 3);
  for (let offset = 0; offset < buffer.length; offset += aligned) {
    yield buffer
      .subarray(offset, offset + aligned)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }
}

const PRIVATE_V4 = [/^127\./, /^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./];
const RESERVED_SUFFIXES = ['.localhost', '.local', '.internal', '.test', '.example', '.invalid'];

/**
 * Callback targets the simulator may contact: loopback, private IPv4 ranges, single-label hosts
 * (Compose service names such as `api`) and reserved test TLDs. Never an Internet host.
 */
export function isLocalCallbackTarget(url: URL): boolean {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
  if (url.username || url.password) return false;
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host === '::1') return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return PRIVATE_V4.some((p) => p.test(host));
  if (host.includes(':')) return false; // other IPv6 literals
  if (!host.includes('.')) return /^[a-z0-9-]{1,63}$/.test(host);
  return RESERVED_SUFFIXES.some((suffix) => host.endsWith(suffix));
}

interface CallbackAnswer {
  status: number;
  text: string;
  contentType: string;
}

async function postCallback(
  url: URL,
  body: string,
  contentType: string,
): Promise<CallbackAnswer | null> {
  if (!isLocalCallbackTarget(url)) return null;
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': contentType },
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(CALLBACK_TIMEOUT_MS),
    });
    const text = (await response.text()).slice(0, 4096);
    return {
      status: response.status,
      text,
      contentType: response.headers.get('content-type') ?? '',
    };
  } catch {
    return null;
  }
}

function record(script: SimScript, entry: Omit<SimNotification, 'at'>): SimNotification {
  const full: SimNotification = { ...entry, at: new Date(script.now()).toISOString() };
  script.notifications.push(full);
  return full;
}

/**
 * Graph's validation handshake: POST `<url>?validationToken=<token>` (empty `text/plain` body);
 * the receiver must answer `200 text/plain` with exactly the token.
 */
export async function validateEndpoint(
  script: SimScript,
  target: string,
  subscriptionId: string | null,
): Promise<boolean> {
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return false;
  }
  const token = `EXAMPLE-validation-${randomBytes(12).toString('hex')}`;
  url.searchParams.set('validationToken', token);
  const answer = await postCallback(url, '', 'text/plain; charset=utf-8');
  const ok =
    answer !== null &&
    answer.status === 200 &&
    answer.text === token &&
    answer.contentType.toLowerCase().startsWith('text/plain');
  record(script, { kind: 'validation', subscriptionId, status: answer?.status ?? 0, ok });
  return ok;
}

function activeSubscriptions(script: SimScript, directory: MsDirectory, userId: string) {
  const now = script.now();
  return (directory.subscriptions ?? []).filter(
    (s) => s.userId === userId && Date.parse(s.expirationDateTime) > now,
  );
}

async function pushChange(
  script: SimScript,
  directory: MsDirectory,
  subscription: MsSubscription,
  messageId: string,
): Promise<SimNotification> {
  const resource = `Users/${subscription.userId}/Messages/${messageId}`;
  const payload = {
    value: [
      {
        subscriptionId: subscription.id,
        subscriptionExpirationDateTime: subscription.expirationDateTime,
        changeType: 'created',
        resource,
        resourceData: {
          '@odata.type': '#Microsoft.Graph.Message',
          '@odata.id': resource,
          '@odata.etag': 'W/"EXAMPLE"',
          id: messageId,
        },
        clientState: subscription.clientState,
        tenantId: directory.tenantId,
      },
    ],
  };
  const answer = await postCallback(
    new URL(subscription.notificationUrl),
    JSON.stringify(payload),
    'application/json; charset=utf-8',
  );
  const status = answer?.status ?? 0;
  return record(script, {
    kind: 'change',
    subscriptionId: subscription.id,
    status,
    ok: status >= 200 && status < 300,
  });
}

export const LIFECYCLE_EVENTS = [
  'reauthorizationRequired',
  'subscriptionRemoved',
  'missed',
] as const;
export type LifecycleEvent = (typeof LIFECYCLE_EVENTS)[number];

/**
 * Pushes a lifecycle notification of a subscription to its `lifecycleNotificationUrl` (scripted
 * by tests). `subscriptionRemoved` also deletes the subscription, as Graph does.
 */
export async function pushLifecycle(
  script: SimScript,
  subscriptionId: string,
  event: LifecycleEvent,
): Promise<SimNotification | null> {
  for (const directory of script.dataset.microsoft?.directories ?? []) {
    const subscriptions = directory.subscriptions ?? [];
    const index = subscriptions.findIndex((s) => s.id === subscriptionId);
    if (index < 0) continue;
    const subscription = subscriptions[index] as MsSubscription;
    if (event === 'subscriptionRemoved') subscriptions.splice(index, 1);
    if (!subscription.lifecycleNotificationUrl) {
      return record(script, { kind: 'lifecycle', subscriptionId, event, status: 0, ok: false });
    }
    const payload = {
      value: [
        {
          subscriptionId,
          subscriptionExpirationDateTime: subscription.expirationDateTime,
          tenantId: directory.tenantId,
          clientState: subscription.clientState,
          lifecycleEvent: event,
        },
      ],
    };
    const answer = await postCallback(
      new URL(subscription.lifecycleNotificationUrl),
      JSON.stringify(payload),
      'application/json; charset=utf-8',
    );
    const status = answer?.status ?? 0;
    return record(script, {
      kind: 'lifecycle',
      subscriptionId,
      event,
      status,
      ok: status >= 200 && status < 300,
    });
  }
  return null;
}

export interface DeliverMessageInput {
  /** User id, primary address, UPN or alias of a simulated Microsoft or Google user. */
  user: string;
  /** The synthetic EML (text or bytes). */
  eml: string | Uint8Array;
  /** Graph `receivedDateTime` / Gmail `internalDate`; default: the simulator clock. */
  receivedAt?: string;
  /** Gmail labels (default `INBOX`, `UNREAD`). */
  labelIds?: string[];
  /** Graph drafts are listed by the delta with `isDraft: true`. */
  isDraft?: boolean;
  /**
   * Step API-2: Graph well-known folder to deliver into (default the Inbox), e.g. `sentitems`
   * for the locate tests (Gmail: use `labelIds`).
   */
  folder?: string;
}

export interface DeliverMessageResult {
  provider: 'microsoft' | 'google';
  /** Microsoft tenant id or Google customer id. */
  directoryId: string;
  userId: string;
  messageId: string;
  internetMessageId: string | null;
  receivedAt: string;
  /** Gmail: the history id of the delivery; Graph: the delta sequence. */
  historyId: string;
  sizeBytes: number;
  /** Graph change notifications pushed for this delivery. */
  notifications: SimNotification[];
}

export class SimMailboxNotFoundError extends Error {
  constructor() {
    super('sim_mailbox_not_found');
  }
}

/**
 * Delivers a synthetic EML into a mailbox: assigns the provider id, `receivedDateTime` /
 * `internalDate`, the delta sequence / history id, and (Graph) pushes a change notification to
 * every active subscription of the user (awaited, so tests see the outcome).
 */
export async function deliverMessage(
  script: SimScript,
  input: DeliverMessageInput,
): Promise<DeliverMessageResult> {
  const owner = findMailboxOwner(script, input.user);
  if (!owner) throw new SimMailboxNotFoundError();
  const bytes =
    typeof input.eml === 'string' ? Buffer.from(input.eml, 'utf8') : Buffer.from(input.eml);
  const receivedAt = new Date(input.receivedAt ?? script.now()).toISOString();
  const internetMessageId = headerValue(bytes, 'Message-ID');
  const mailbox =
    owner.provider === 'microsoft'
      ? mailboxOf(owner.directory, owner.user.id)
      : mailboxOf(owner.customer, owner.user.id);
  mailbox.seq += 1;
  const seq = mailbox.seq;
  const messageId =
    owner.provider === 'microsoft'
      ? `${GRAPH_ID_PREFIX}${Buffer.from(`${owner.user.id}:${seq}`, 'utf8').toString('base64url')}`
      : (GMAIL_ID_BASE + seq).toString(16);
  const message: SimMailMessage = {
    id: messageId,
    internetMessageId,
    emlBase64: bytes.toString('base64'),
    receivedAt,
    seq,
    ...(owner.provider === 'google'
      ? { threadId: messageId, labelIds: input.labelIds ?? ['INBOX', 'UNREAD'] }
      : {}),
    ...(input.isDraft ? { isDraft: true } : {}),
  };
  if (owner.provider === 'microsoft' && input.folder !== undefined && input.folder !== 'inbox') {
    const folder = graphFolder(mailbox, owner.user.id, input.folder);
    if (!folder) throw new SimMailboxNotFoundError();
    message.folderId = folder.id;
  }
  mailbox.messages.push(message);
  const notifications: SimNotification[] = [];
  if (owner.provider === 'microsoft' && !input.isDraft && inGraphInbox(message)) {
    for (const subscription of activeSubscriptions(script, owner.directory, owner.user.id)) {
      notifications.push(await pushChange(script, owner.directory, subscription, messageId));
    }
  }
  return {
    provider: owner.provider,
    directoryId:
      owner.provider === 'microsoft' ? owner.directory.tenantId : owner.customer.customerId,
    userId: owner.user.id,
    messageId,
    internetMessageId,
    receivedAt,
    historyId: String(seq),
    sizeBytes: bytes.length,
    notifications,
  };
}

/** Removes a message from the Inbox (Graph delta then reports `@removed`). */
export function removeMessage(script: SimScript, user: string, messageId: string): boolean {
  const owner = findMailboxOwner(script, user);
  if (!owner) return false;
  const mailbox =
    owner.provider === 'microsoft'
      ? mailboxOf(owner.directory, owner.user.id)
      : mailboxOf(owner.customer, owner.user.id);
  const message = mailbox.messages.find((m) => m.id === messageId && m.removedSeq === undefined);
  if (!message) return false;
  mailbox.seq += 1;
  message.removedSeq = mailbox.seq;
  return true;
}

/**
 * Expires every cursor issued so far for a mailbox (Graph `410 syncStateNotFound`, Gmail `404`
 * for older start history ids). New cursors issued afterwards are valid.
 */
export function expireCursors(script: SimScript, user: string): boolean {
  const owner = findMailboxOwner(script, user);
  if (!owner) return false;
  const mailbox =
    owner.provider === 'microsoft'
      ? mailboxOf(owner.directory, owner.user.id)
      : mailboxOf(owner.customer, owner.user.id);
  mailbox.seq += 1;
  mailbox.cursorFloor = mailbox.seq;
  return true;
}
