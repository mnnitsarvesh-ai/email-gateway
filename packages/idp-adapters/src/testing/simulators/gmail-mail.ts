/**
 * Gmail mail endpoints of the simulator (step API-1 D13, TEST-ONLY): `users.getProfile`,
 * `users.history.list` (`messageAdded`, `labelId`, paging, `404` for a start history id older
 * than the mailbox's floor), `users.messages.get` with `format=metadata|minimal|raw`. Raw answers
 * are JSON with the base64url `raw` field in Gmail's field order, streamed chunk by chunk.
 *
 * Scopes: `gmail.modify`, `gmail.readonly` or `https://mail.google.com/` (metadata also with
 * `gmail.metadata`); the token subject must be the mailbox owner (checked by the caller).
 */
import type { GsCustomer, GsUser } from './google-types';
import { base64UrlChunks, emlBytes, headerFields, mailboxOf } from './mail';
import { gmailMailWrite } from './gmail-mail-write';
import { json, type SimRequest, type SimResponse } from './server';
import { hasPermission, type ResolvedToken } from './tokens';
import type { SimMailMessage } from './types';

const SCOPE = 'https://www.googleapis.com/auth/';
export const GMAIL_MAIL_SCOPES = {
  modify: `${SCOPE}gmail.modify`,
  readonly: `${SCOPE}gmail.readonly`,
  metadata: `${SCOPE}gmail.metadata`,
  full: 'https://mail.google.com/',
} as const;
const READ_SCOPES = [GMAIL_MAIL_SCOPES.modify, GMAIL_MAIL_SCOPES.readonly, GMAIL_MAIL_SCOPES.full];

/**
 * Profile, history and messages (API-1); step API-2 adds `labels`, the `messages` list and
 * `messages/{id}/modify|trash|untrash` (handled by `gmail-mail-write.ts`).
 */
export const GMAIL_MAIL_PATH =
  /^\/gmail\/v1\/users\/([^/]+)\/(profile|history|labels|messages(?:\/([^/]+)(?:\/(modify|trash|untrash))?)?)$/;

type ErrorFn = (status: number, reason?: string, statusCode?: string) => SimResponse;

function encodePage(offset: number): string {
  return Buffer.from(`h:${offset}`, 'utf8').toString('base64url');
}

function decodePage(token: string | null): number | null {
  if (token === null || token === '') return 0;
  const match = /^h:(\d+)$/.exec(Buffer.from(token, 'base64url').toString('utf8'));
  return match ? Number(match[1]) : null;
}

function snippetOf(message: SimMailMessage): string {
  const text = emlBytes(message).toString('utf8');
  const split = text.search(/\r?\n\r?\n/);
  const body = split < 0 ? '' : text.slice(split).trim();
  return body.replace(/\s+/g, ' ').slice(0, 120);
}

export function gmailMail(
  request: SimRequest,
  token: ResolvedToken,
  customer: GsCustomer,
  user: GsUser,
  kind: string,
  messageKey: string | undefined,
  error: ErrorFn,
  op?: string,
): SimResponse {
  // Step API-2 (R7): labels, message search and the label/trash writes.
  if (kind === 'labels' || kind === 'messages' || op !== undefined || request.method !== 'GET') {
    return gmailMailWrite(request, token, customer, user, kind, messageKey, op, error);
  }
  const format = request.query.get('format') ?? 'full';
  const metadataOnly = messageKey !== undefined && (format === 'metadata' || format === 'minimal');
  const allowed = metadataOnly
    ? hasPermission(token, [...READ_SCOPES, GMAIL_MAIL_SCOPES.metadata])
    : hasPermission(token, READ_SCOPES);
  if (!allowed) return error(403, 'insufficientPermissions', 'PERMISSION_DENIED');
  const mailbox = mailboxOf(customer, user.id);
  if (kind === 'profile') {
    return json(200, {
      emailAddress: user.primaryEmail,
      messagesTotal: mailbox.messages.filter((m) => m.removedSeq === undefined).length,
      threadsTotal: mailbox.messages.filter((m) => m.removedSeq === undefined).length,
      historyId: String(mailbox.seq),
    });
  }
  if (kind === 'history') {
    const q = request.query;
    const startText = q.get('startHistoryId');
    if (startText === null || !/^\d{1,20}$/.test(startText)) {
      return error(400, 'invalidArgument', 'INVALID_ARGUMENT');
    }
    const start = Number(startText);
    if (start < mailbox.cursorFloor) return error(404, 'notFound', 'NOT_FOUND');
    const maxResults = Number(q.get('maxResults') ?? '100');
    if (!Number.isInteger(maxResults) || maxResults < 1 || maxResults > 500) {
      return error(400, 'invalidArgument', 'INVALID_ARGUMENT');
    }
    const types = q.getAll('historyTypes');
    if (
      types.some(
        (t) => !['messageAdded', 'messageDeleted', 'labelAdded', 'labelRemoved'].includes(t),
      )
    ) {
      return error(400, 'invalidArgument', 'INVALID_ARGUMENT');
    }
    const offset = decodePage(q.get('pageToken'));
    if (offset === null) return error(400, 'invalidArgument', 'INVALID_ARGUMENT');
    const label = q.get('labelId');
    const records = mailbox.messages
      .filter((m) => m.seq > start)
      .filter((m) => label === null || (m.labelIds ?? []).includes(label))
      .filter(() => types.length === 0 || types.includes('messageAdded'))
      .sort((a, b) => a.seq - b.seq)
      .map((m) => {
        const ref = { id: m.id, threadId: m.threadId ?? m.id };
        return {
          id: String(m.seq),
          messages: [ref],
          messagesAdded: [{ message: { ...ref, labelIds: m.labelIds ?? [] } }],
        };
      });
    const slice = records.slice(offset, offset + maxResults);
    const body: Record<string, unknown> = {};
    if (slice.length > 0) body.history = slice;
    if (offset + maxResults < records.length) body.nextPageToken = encodePage(offset + maxResults);
    body.historyId = String(mailbox.seq);
    return json(200, body);
  }
  const message = mailbox.messages.find((m) => m.id === messageKey && m.removedSeq === undefined);
  if (!message) return error(404, 'notFound', 'NOT_FOUND');
  const bytes = emlBytes(message);
  const internalDate = String(Date.parse(message.receivedAt));
  const head = {
    id: message.id,
    threadId: message.threadId ?? message.id,
    labelIds: message.labelIds ?? [],
  };
  if (format === 'minimal') {
    return json(200, {
      ...head,
      snippet: snippetOf(message),
      sizeEstimate: bytes.length,
      historyId: String(message.seq),
      internalDate,
    });
  }
  if (format === 'metadata') {
    const wanted = request.query.getAll('metadataHeaders').map((h) => h.toLowerCase());
    const headers = headerFields(bytes).filter(
      (f) => wanted.length === 0 || wanted.includes(f.name.toLowerCase()),
    );
    return json(200, {
      ...head,
      snippet: snippetOf(message),
      payload: { partId: '', mimeType: 'message/rfc822', filename: '', headers },
      sizeEstimate: bytes.length,
      historyId: String(message.seq),
      internalDate,
    });
  }
  if (format === 'raw') {
    // Gmail's field order: id, threadId, labelIds, snippet, sizeEstimate, raw, historyId,
    // internalDate. The snippet may contain anything (escaped), including the text "raw".
    const prefix = `${JSON.stringify({
      ...head,
      snippet: snippetOf(message),
      sizeEstimate: bytes.length,
    }).slice(0, -1)},"raw":"`;
    const suffix = `","historyId":${JSON.stringify(String(message.seq))},"internalDate":${JSON.stringify(internalDate)}}`;
    function* chunks(): Generator<string> {
      yield prefix;
      yield* base64UrlChunks(bytes);
      yield suffix;
    }
    return {
      status: 200,
      raw: { contentType: 'application/json; charset=UTF-8', chunks: chunks() },
    };
  }
  // `full` is not simulated (the clients never ask for it).
  return error(400, 'invalidArgument', 'INVALID_ARGUMENT');
}
