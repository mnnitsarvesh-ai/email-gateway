/**
 * Microsoft Graph mail endpoints of the simulator (step API-1 D13, TEST-ONLY):
 *
 * - `GET /v1.0/users/{id}/mailFolders('inbox')/messages/delta`: opaque per-user delta and skip
 *   tokens, `Prefer: odata.maxpagesize`, created items and `@removed` entries (items that left
 *   the Inbox are reported whatever `changeType` says, so clients must tolerate them), expired
 *   cursors `410 syncStateNotFound` (`expireCursors` / admin API, or a scripted injection).
 * - `GET /v1.0/users/{id}/messages/{mid}/$value`: the EML (`message/rfc822`), streamed.
 * - `POST/PATCH/DELETE /v1.0/subscriptions[/{id}]`: Outlook message subscriptions with Graph's
 *   validation handshake on `notificationUrl` (and `lifecycleNotificationUrl`) before `201`.
 *
 * Permissions: `Mail.ReadWrite` (or `Mail.Read`) through the token registry.
 */
import { randomUUID } from 'node:crypto';
import {
  chunked,
  emlBytes,
  GRAPH_SUBSCRIPTION_MAX_MINUTES,
  isLocalCallbackTarget,
  mailboxOf,
  validateEndpoint,
} from './mail';
import { json, type SimRequest, type SimResponse } from './server';
import type { SimScript } from './script';
import { hasPermission, type ResolvedToken } from './tokens';
import type { MsDirectory, MsSubscription, MsUser, SimMailbox, SimMailMessage } from './types';

export const GRAPH_MAIL_READ_PERMISSIONS = ['Mail.ReadWrite', 'Mail.Read'] as const;
const DEFAULT_DELTA_PAGE = 10;
const MAX_DELTA_PAGE = 1000;

/** `mailFolders('inbox')`, `mailFolders(%27inbox%27)` or `mailFolders/inbox`. */
const INBOX = String.raw`mailFolders(?:\((?:'|%27)inbox(?:'|%27)\)|\/inbox)`;
export const DELTA_PATH = new RegExp(
  String.raw`^\/v1\.0\/users\/([^/]+)\/${INBOX}\/messages\/delta$`,
  'i',
);
export const VALUE_PATH = /^\/v1\.0\/users\/([^/]+)\/messages\/([^/]+)\/\$value$/;
export const SUBSCRIPTIONS_PATH = /^\/v1\.0\/subscriptions(?:\/([^/]+))?$/;
const RESOURCE = new RegExp(String.raw`^\/?users\/([^/]+)\/${INBOX}\/messages$`, 'i');

type ErrorFn = (status: number, code: string) => SimResponse;

interface DeltaState {
  userId: string;
  /** Changes after this sequence (-1: initial sync, every current item). */
  from: number;
  /** Changes up to this sequence (the snapshot of the sync round). */
  to: number;
  offset: number;
}

function encodeToken(kind: 'd' | 's', state: DeltaState): string {
  const text =
    kind === 'd'
      ? `d1|${state.userId}|${state.to}`
      : `s1|${state.userId}|${state.from}|${state.to}|${state.offset}`;
  return Buffer.from(text, 'utf8').toString('base64url');
}

function decodeToken(kind: 'd' | 's', token: string): DeltaState | null {
  const parts = Buffer.from(token, 'base64url').toString('utf8').split('|');
  if (kind === 'd' && parts.length === 3 && parts[0] === 'd1') {
    const to = Number(parts[2]);
    return Number.isInteger(to) ? { userId: parts[1] as string, from: to, to, offset: 0 } : null;
  }
  if (kind === 's' && parts.length === 5 && parts[0] === 's1') {
    const [from, to, offset] = [Number(parts[2]), Number(parts[3]), Number(parts[4])];
    if (![from, to, offset].every(Number.isInteger)) return null;
    return { userId: parts[1] as string, from, to, offset };
  }
  return null;
}

function pageSize(request: SimRequest): { size: number; applied: boolean } {
  const prefer = request.headers.prefer;
  const text = Array.isArray(prefer) ? prefer.join(',') : (prefer ?? '');
  const match = /odata\.maxpagesize\s*=\s*(\d+)/i.exec(text);
  if (!match) return { size: DEFAULT_DELTA_PAGE, applied: false };
  return { size: Math.min(Math.max(Number(match[1]), 1), MAX_DELTA_PAGE), applied: true };
}

function deltaItem(message: SimMailMessage): Record<string, unknown> {
  return {
    '@odata.type': '#microsoft.graph.message',
    '@odata.etag': 'W/"EXAMPLE"',
    id: message.id,
    receivedDateTime: message.receivedAt,
    internetMessageId: message.internetMessageId,
    isDraft: message.isDraft === true,
  };
}

/** The changes of one sync round `(from, to]`, ordered by sequence. */
function changes(mailbox: SimMailbox, from: number, to: number): Record<string, unknown>[] {
  const out: { seq: number; item: Record<string, unknown> }[] = [];
  for (const message of mailbox.messages) {
    const removedBy = message.removedSeq !== undefined && message.removedSeq <= to;
    if (from < 0) {
      if (message.seq <= to && !removedBy) out.push({ seq: message.seq, item: deltaItem(message) });
      continue;
    }
    if (message.seq > from && message.seq <= to && !removedBy) {
      out.push({ seq: message.seq, item: deltaItem(message) });
    } else if (message.seq <= from && removedBy && (message.removedSeq as number) > from) {
      out.push({
        seq: message.removedSeq as number,
        item: {
          '@odata.type': '#microsoft.graph.message',
          id: message.id,
          '@removed': { reason: 'deleted' },
        },
      });
    }
  }
  return out.sort((a, b) => a.seq - b.seq).map((entry) => entry.item);
}

export function graphDelta(
  script: SimScript,
  request: SimRequest,
  token: ResolvedToken,
  directory: MsDirectory,
  user: MsUser | undefined,
  error: ErrorFn,
): SimResponse {
  if (!hasPermission(token, GRAPH_MAIL_READ_PERMISSIONS)) {
    return error(403, 'ErrorAccessDenied');
  }
  if (!user) return error(404, 'ErrorInvalidUser');
  const mailbox = mailboxOf(directory, user.id);
  const deltaToken = request.query.get('$deltatoken');
  const skipToken = request.query.get('$skiptoken');
  let state: DeltaState;
  if (skipToken !== null) {
    const decoded = decodeToken('s', skipToken);
    if (!decoded || decoded.userId !== user.id) return error(400, 'ErrorInvalidRequest');
    state = decoded;
  } else if (deltaToken !== null) {
    const decoded = decodeToken('d', deltaToken);
    if (!decoded || decoded.userId !== user.id) return error(400, 'ErrorInvalidRequest');
    state = { ...decoded, to: mailbox.seq };
  } else {
    state = { userId: user.id, from: -1, to: mailbox.seq, offset: 0 };
  }
  // A cursor older than the mailbox's floor is gone (Graph: 410 syncStateNotFound).
  const expired =
    state.from >= 0 ? state.from < mailbox.cursorFloor : state.to < mailbox.cursorFloor;
  if (expired && (deltaToken !== null || skipToken !== null)) {
    return error(410, 'syncStateNotFound');
  }
  const all = changes(mailbox, state.from, state.to);
  const { size, applied } = pageSize(request);
  const page = all.slice(state.offset, state.offset + size);
  const base = `${request.publicBase}/v1.0/users/${encodeURIComponent(user.id)}/mailFolders('inbox')/messages/delta`;
  const body: Record<string, unknown> = {
    '@odata.context': `${request.publicBase}/v1.0/$metadata#Collection(message)`,
    value: page,
  };
  if (state.offset + size < all.length) {
    const next = encodeToken('s', { ...state, offset: state.offset + size });
    body['@odata.nextLink'] = `${base}?$skiptoken=${next}`;
  } else {
    body['@odata.deltaLink'] =
      `${base}?$deltatoken=${encodeToken('d', { ...state, from: state.to, offset: 0 })}`;
  }
  return json(200, body, applied ? { 'Preference-Applied': `odata.maxpagesize=${size}` } : {});
}

export function graphMessageValue(
  token: ResolvedToken,
  directory: MsDirectory,
  user: MsUser | undefined,
  messageId: string,
  error: ErrorFn,
): SimResponse {
  if (!hasPermission(token, GRAPH_MAIL_READ_PERMISSIONS)) {
    return error(403, 'ErrorAccessDenied');
  }
  if (!user) return error(404, 'ErrorInvalidUser');
  const mailbox = mailboxOf(directory, user.id);
  const message = mailbox.messages.find((m) => m.id === messageId && m.removedSeq === undefined);
  if (!message) return error(404, 'ErrorItemNotFound');
  const bytes = emlBytes(message);
  return {
    status: 200,
    raw: { contentType: 'message/rfc822', chunks: chunked(bytes), length: bytes.length },
  };
}

function publicSubscription(subscription: MsSubscription): Record<string, unknown> {
  return {
    '@odata.context': 'EXAMPLE/$metadata#subscriptions/$entity',
    id: subscription.id,
    resource: subscription.resource,
    applicationId: '00000000-0000-4000-8000-0000000000aa',
    changeType: subscription.changeType,
    clientState: subscription.clientState,
    notificationUrl: subscription.notificationUrl,
    lifecycleNotificationUrl: subscription.lifecycleNotificationUrl,
    expirationDateTime: subscription.expirationDateTime,
    creatorId: '00000000-0000-4000-8000-0000000000bb',
    latestSupportedTlsVersion: subscription.latestSupportedTlsVersion,
  };
}

function validExpiry(script: SimScript, value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const at = Date.parse(value);
  const now = script.now();
  if (Number.isNaN(at) || at <= now || at > now + GRAPH_SUBSCRIPTION_MAX_MINUTES * 60_000) {
    return null;
  }
  return new Date(at).toISOString();
}

function callbackUrl(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 2048) return null;
  try {
    const url = new URL(value);
    // Graph requires https; the simulator also accepts http, but only for local targets, and
    // never contacts a non-local host at all.
    return isLocalCallbackTarget(url) ? url.toString() : null;
  } catch {
    return null;
  }
}

export async function graphSubscriptions(
  script: SimScript,
  request: SimRequest,
  token: ResolvedToken,
  directory: MsDirectory,
  subscriptionId: string | undefined,
  findUser: (key: string) => MsUser | undefined,
  error: ErrorFn,
): Promise<SimResponse> {
  if (!hasPermission(token, GRAPH_MAIL_READ_PERMISSIONS)) {
    return error(403, 'ExtensionError');
  }
  const subscriptions = (directory.subscriptions ??= []);
  const m = request.method;
  if (subscriptionId === undefined) {
    if (m !== 'POST') return error(405, 'BadRequest');
    const body = (request.body ?? {}) as Record<string, unknown>;
    if (body.changeType !== 'created') return error(400, 'ValidationError');
    const resourceText = typeof body.resource === 'string' ? body.resource : '';
    const resource = RESOURCE.exec(resourceText);
    if (!resource) return error(400, 'ValidationError');
    const user = findUser(decodeURIComponent(resource[1] as string));
    if (!user) return error(404, 'ResourceNotFound');
    const notificationUrl = callbackUrl(body.notificationUrl);
    if (!notificationUrl) return error(400, 'ValidationError');
    let lifecycleNotificationUrl: string | null = null;
    if (body.lifecycleNotificationUrl !== undefined && body.lifecycleNotificationUrl !== null) {
      lifecycleNotificationUrl = callbackUrl(body.lifecycleNotificationUrl);
      if (!lifecycleNotificationUrl) return error(400, 'ValidationError');
    }
    const expirationDateTime = validExpiry(script, body.expirationDateTime);
    if (!expirationDateTime) return error(400, 'ValidationError');
    const clientState = body.clientState === undefined ? null : body.clientState;
    if (clientState !== null && (typeof clientState !== 'string' || clientState.length > 128)) {
      return error(400, 'ValidationError');
    }
    const tls = body.latestSupportedTlsVersion;
    if (tls !== undefined && tls !== 'v1_2' && tls !== 'v1_3') return error(400, 'ValidationError');
    const id = randomUUID();
    if (!(await validateEndpoint(script, notificationUrl, id))) {
      return error(400, 'ValidationError');
    }
    if (
      lifecycleNotificationUrl &&
      !(await validateEndpoint(script, lifecycleNotificationUrl, id))
    ) {
      return error(400, 'ValidationError');
    }
    const subscription: MsSubscription = {
      id,
      resource: resourceText,
      userId: user.id,
      changeType: 'created',
      notificationUrl,
      lifecycleNotificationUrl,
      clientState,
      expirationDateTime,
      latestSupportedTlsVersion: typeof tls === 'string' ? tls : null,
    };
    subscriptions.push(subscription);
    return json(201, publicSubscription(subscription));
  }
  const index = subscriptions.findIndex((s) => s.id === subscriptionId);
  if (m === 'GET') {
    return index < 0
      ? error(404, 'ResourceNotFound')
      : json(200, publicSubscription(subscriptions[index] as MsSubscription));
  }
  if (m === 'PATCH') {
    if (index < 0) return error(404, 'ResourceNotFound');
    const body = (request.body ?? {}) as Record<string, unknown>;
    const keys = Object.keys(body);
    if (keys.length !== 1 || keys[0] !== 'expirationDateTime') return error(400, 'ValidationError');
    const expirationDateTime = validExpiry(script, body.expirationDateTime);
    if (!expirationDateTime) return error(400, 'ValidationError');
    const subscription = subscriptions[index] as MsSubscription;
    subscription.expirationDateTime = expirationDateTime;
    return json(200, publicSubscription(subscription));
  }
  if (m === 'DELETE') {
    if (index < 0) return error(404, 'ResourceNotFound');
    subscriptions.splice(index, 1);
    return json(204);
  }
  return error(405, 'BadRequest');
}
