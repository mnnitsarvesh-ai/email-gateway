/**
 * Gmail endpoints of the simulator for API-mode remediation (step API-2 R7, TEST-ONLY), over the
 * API-1 mailboxes (label sets per message):
 *
 * - `GET …/messages?q=rfc822msgid:<id>&includeSpamTrash=…&maxResults=…` (only `rfc822msgid:` is
 *   understood; angle brackets optional; `SPAM`/`TRASH` messages only with `includeSpamTrash`).
 * - `GET|POST …/labels` (system labels plus user labels; `409` for a duplicate name).
 * - `POST …/messages/{id}/modify { addLabelIds, removeLabelIds }` (unknown label → `400`).
 * - `POST …/messages/{id}/trash` (adds `TRASH`, drops `INBOX` and `SPAM`) and `/untrash` (drops
 *   `TRASH`; `INBOX` is not restored, as the remediation adds it back itself).
 * - `DELETE …/messages/{id}` → `403 insufficientPermissions` unless the token carries the full
 *   `https://mail.google.com/` scope (which `gmail.modify` grants do not).
 *
 * Scopes: reads `gmail.modify`, `gmail.readonly` or the full scope (labels also with
 * `gmail.labels` / `gmail.metadata`); writes `gmail.modify` or the full scope (labels also
 * `gmail.labels`). Every label change advances the mailbox history id. Synthetic data only.
 */
import type { GsCustomer, GsUser } from './google-types';
import { liveMessage, mailboxOf } from './mail';
import { json, type SimRequest, type SimResponse } from './server';
import { hasPermission, type ResolvedToken } from './tokens';
import type { SimGmailLabel, SimMailbox, SimMailMessage } from './types';

type ErrorFn = (status: number, reason?: string, statusCode?: string) => SimResponse;

const SCOPE = 'https://www.googleapis.com/auth/';
const FULL = 'https://mail.google.com/';
const MODIFY = `${SCOPE}gmail.modify`;
const READONLY = `${SCOPE}gmail.readonly`;
const LABELS = `${SCOPE}gmail.labels`;
const METADATA = `${SCOPE}gmail.metadata`;
const READ_SCOPES = [MODIFY, READONLY, FULL];
const WRITE_SCOPES = [MODIFY, FULL];

/** Gmail system labels the simulator knows (ids = names). */
export const GMAIL_SYSTEM_LABEL_IDS = [
  'INBOX',
  'SPAM',
  'TRASH',
  'UNREAD',
  'STARRED',
  'IMPORTANT',
  'SENT',
  'DRAFT',
  'CATEGORY_PERSONAL',
  'CATEGORY_SOCIAL',
  'CATEGORY_PROMOTIONS',
  'CATEGORY_UPDATES',
  'CATEGORY_FORUMS',
] as const;

const DEFAULT_MAX_RESULTS = 100;
const LABEL_NAME_MAX = 225;

const stripBrackets = (value: string): string => value.trim().replace(/^<|>$/g, '').toLowerCase();

function labelView(label: SimGmailLabel): Record<string, unknown> {
  return {
    id: label.id,
    name: label.name,
    type: 'user',
    labelListVisibility: label.labelListVisibility,
    messageListVisibility: label.messageListVisibility,
  };
}

function messageView(message: SimMailMessage): Record<string, unknown> {
  return {
    id: message.id,
    threadId: message.threadId ?? message.id,
    labelIds: [...(message.labelIds ?? [])],
  };
}

function knownLabel(mailbox: SimMailbox, id: string): boolean {
  return (
    (GMAIL_SYSTEM_LABEL_IDS as readonly string[]).includes(id) ||
    (mailbox.labels ?? []).some((l) => l.id === id)
  );
}

function stringList(value: unknown): string[] | null {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 100) return null;
  return value.every((v) => typeof v === 'string') ? value : null;
}

/** Applies a label change and advances the mailbox history id. */
function relabel(mailbox: SimMailbox, message: SimMailMessage, add: string[], remove: string[]) {
  const labels = (message.labelIds ?? []).filter((l) => !remove.includes(l));
  for (const label of add) if (!labels.includes(label)) labels.push(label);
  message.labelIds = labels;
  mailbox.seq += 1;
}

export function gmailMailWrite(
  request: SimRequest,
  token: ResolvedToken,
  customer: GsCustomer,
  user: GsUser,
  kind: string,
  messageKey: string | undefined,
  op: string | undefined,
  error: ErrorFn,
): SimResponse {
  const denied = () => error(403, 'insufficientPermissions', 'PERMISSION_DENIED');
  const invalid = () => error(400, 'invalidArgument', 'INVALID_ARGUMENT');
  const m = request.method;
  const mailbox = mailboxOf(customer, user.id);
  const body = (request.body ?? {}) as Record<string, unknown>;

  if (kind === 'labels') {
    if (m === 'GET') {
      if (!hasPermission(token, [...READ_SCOPES, LABELS, METADATA])) return denied();
      return json(200, {
        labels: [
          ...GMAIL_SYSTEM_LABEL_IDS.map((id) => ({ id, name: id, type: 'system' })),
          ...(mailbox.labels ?? []).map(labelView),
        ],
      });
    }
    if (m !== 'POST') return error(405, 'methodNotAllowed');
    if (!hasPermission(token, [...WRITE_SCOPES, LABELS])) return denied();
    const name = body.name;
    const listVisibility = body.labelListVisibility ?? 'labelShow';
    const messageVisibility = body.messageListVisibility ?? 'show';
    if (
      typeof name !== 'string' ||
      name.trim().length === 0 ||
      name.length > LABEL_NAME_MAX ||
      !['labelShow', 'labelShowIfUnread', 'labelHide'].includes(listVisibility as string) ||
      !['show', 'hide'].includes(messageVisibility as string)
    ) {
      return invalid();
    }
    const lowered = name.toLowerCase();
    if (
      (GMAIL_SYSTEM_LABEL_IDS as readonly string[]).some((id) => id.toLowerCase() === lowered) ||
      (mailbox.labels ?? []).some((l) => l.name.toLowerCase() === lowered)
    ) {
      return error(409, 'duplicate', 'ALREADY_EXISTS');
    }
    mailbox.createdCount = (mailbox.createdCount ?? 0) + 1;
    const label: SimGmailLabel = {
      id: `Label_${mailbox.createdCount}`,
      name,
      labelListVisibility: listVisibility as SimGmailLabel['labelListVisibility'],
      messageListVisibility: messageVisibility as SimGmailLabel['messageListVisibility'],
    };
    (mailbox.labels ??= []).push(label);
    return json(200, labelView(label));
  }

  if (kind === 'messages') {
    if (m !== 'GET') return error(405, 'methodNotAllowed');
    if (!hasPermission(token, READ_SCOPES)) return denied();
    const q = request.query.get('q');
    let wanted: string | null = null;
    if (q !== null && q.trim() !== '') {
      const match = /^rfc822msgid:(\S+)$/.exec(q.trim());
      if (!match) return invalid();
      wanted = stripBrackets(match[1] as string);
    }
    const max = Number(request.query.get('maxResults') ?? DEFAULT_MAX_RESULTS);
    if (!Number.isInteger(max) || max < 1 || max > 500) return invalid();
    const spamTrash = request.query.get('includeSpamTrash') === 'true';
    const found = mailbox.messages
      .filter((msg) => msg.removedSeq === undefined && msg.deleted !== true)
      .filter(
        (msg) => spamTrash || !(msg.labelIds ?? []).some((l) => l === 'SPAM' || l === 'TRASH'),
      )
      .filter(
        (msg) =>
          wanted === null ||
          (msg.internetMessageId !== null && stripBrackets(msg.internetMessageId) === wanted),
      )
      .sort((a, b) => b.seq - a.seq)
      .slice(0, max)
      .map((msg) => ({ id: msg.id, threadId: msg.threadId ?? msg.id }));
    return json(200, {
      ...(found.length > 0 ? { messages: found } : {}),
      resultSizeEstimate: found.length,
    });
  }

  // kind === 'message'
  const message = messageKey === undefined ? undefined : liveMessage(mailbox, messageKey);
  if (m === 'DELETE' && op === undefined) {
    // `messages.delete` needs the full mail scope; `gmail.modify` is not enough.
    if (!hasPermission(token, [FULL])) return denied();
    if (!message) return error(404, 'notFound', 'NOT_FOUND');
    mailbox.seq += 1;
    message.removedSeq = mailbox.seq;
    message.deleted = true;
    return json(204);
  }
  if (m !== 'POST' || op === undefined) return error(405, 'methodNotAllowed');
  if (!hasPermission(token, WRITE_SCOPES)) return denied();
  if (!message) return error(404, 'notFound', 'NOT_FOUND');
  if (op === 'modify') {
    const add = stringList(body.addLabelIds);
    const remove = stringList(body.removeLabelIds);
    if (add === null || remove === null) return invalid();
    if ([...add, ...remove].some((id) => !knownLabel(mailbox, id))) return invalid();
    relabel(mailbox, message, add, remove);
    return json(200, messageView(message));
  }
  if (op === 'trash') {
    relabel(mailbox, message, ['TRASH'], ['INBOX', 'SPAM']);
    return json(200, messageView(message));
  }
  relabel(mailbox, message, [], ['TRASH']);
  return json(200, messageView(message));
}
