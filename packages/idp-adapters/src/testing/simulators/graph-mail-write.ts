/**
 * Microsoft Graph mailbox endpoints of the simulator for API-mode remediation (step API-2 R7,
 * TEST-ONLY). Per-mailbox message location state (folder, categories) over the API-1 mailboxes:
 *
 * - `GET /v1.0/users/{u}/messages?$filter=internetMessageId eq '…'&$select=…&$top=…` (every
 *   folder; OData string escaping; other filters `400`).
 * - `GET /v1.0/users/{u}/messages/{id}?$select=…`, `PATCH …/messages/{id}` (categories only).
 * - `POST …/messages/{id}/move { destinationId }`: returns the message with a **new id** (Graph
 *   ids are folder-scoped without immutable ids); the old id then answers `404`.
 * - `POST …/messages/{id}/permanentDelete` → `204`.
 * - `GET /v1.0/users/{u}/mailFolders/{wellKnownOrId}`, `GET|POST …/mailFolders/{id}/childFolders`
 *   (`includeHiddenFolders=true` lists hidden folders, `$filter=displayName eq '…'`, `isHidden`
 *   on create, `409 ErrorFolderExists` for a duplicate name).
 *
 * Permissions: reads need `Mail.ReadWrite` or `Mail.Read`; writes need `Mail.ReadWrite` (`403
 * ErrorAccessDenied` otherwise). Synthetic data only.
 */
import { GRAPH_MAIL_READ_PERMISSIONS } from './graph-mail';
import { graphFolder, graphFolderIdOf, graphFolders, liveMessage, mailboxOf } from './mail';
import { matches, ODataError, parseFilter } from './odata';
import { json, type SimRequest, type SimResponse } from './server';
import { hasPermission, type ResolvedToken } from './tokens';
import type { MsDirectory, MsUser, SimMailbox, SimMailFolder, SimMailMessage } from './types';

export const GRAPH_MAIL_WRITE_PERMISSIONS = ['Mail.ReadWrite'] as const;

export const GRAPH_MESSAGES_PATH = /^\/v1\.0\/users\/([^/]+)\/messages$/;
export const GRAPH_MESSAGE_PATH = /^\/v1\.0\/users\/([^/]+)\/messages\/([^/]+)$/;
export const GRAPH_MESSAGE_ACTION_PATH =
  /^\/v1\.0\/users\/([^/]+)\/messages\/([^/]+)\/(move|permanentDelete)$/;
export const GRAPH_FOLDER_PATH = /^\/v1\.0\/users\/([^/]+)\/mailFolders\/([^/()]+)$/;
export const GRAPH_CHILD_FOLDERS_PATH =
  /^\/v1\.0\/users\/([^/]+)\/mailFolders\/([^/()]+)\/childFolders$/;

const GRAPH_ID_PREFIX = 'AAMkEXAMPLE';
const MAX_TOP = 1000;
const DEFAULT_TOP = 10;

type ErrorFn = (status: number, code: string) => SimResponse;

function select(request: SimRequest, item: Record<string, unknown>): Record<string, unknown> {
  const wanted = request.query.get('$select');
  if (wanted === null || wanted.trim() === '') return item;
  const keys = new Set(['id', ...wanted.split(',').map((k) => k.trim())]);
  return Object.fromEntries(Object.entries(item).filter(([k]) => keys.has(k)));
}

function messageItem(
  mailbox: SimMailbox,
  userId: string,
  message: SimMailMessage,
): Record<string, unknown> {
  return {
    '@odata.etag': 'W/"EXAMPLE"',
    id: message.id,
    internetMessageId: message.internetMessageId,
    receivedDateTime: message.receivedAt,
    isDraft: message.isDraft === true,
    parentFolderId: graphFolderIdOf(mailbox, userId, message),
    categories: [...(message.categories ?? [])],
  };
}

function folderItem(mailbox: SimMailbox, userId: string, folder: SimMailFolder) {
  const children = graphFolders(mailbox, userId).filter((f) => f.parentFolderId === folder.id);
  return {
    id: folder.id,
    displayName: folder.displayName,
    parentFolderId: folder.parentFolderId,
    childFolderCount: children.length,
    isHidden: folder.isHidden,
    totalItemCount: mailbox.messages.filter(
      (m) =>
        m.removedSeq === undefined &&
        m.deleted !== true &&
        graphFolderIdOf(mailbox, userId, m) === folder.id,
    ).length,
  };
}

function nextId(mailbox: SimMailbox, userId: string, kind: 'msg' | 'fld'): string {
  mailbox.createdCount = (mailbox.createdCount ?? 0) + 1;
  const n = mailbox.createdCount;
  return kind === 'msg'
    ? `${GRAPH_ID_PREFIX}${Buffer.from(`${userId}:m${mailbox.seq + 1}:${n}`, 'utf8').toString('base64url')}`
    : `${GRAPH_ID_PREFIX}fld${Buffer.from(`${userId}:custom:${n}`, 'utf8').toString('base64url')}`;
}

/**
 * The remediation endpoints of the Graph simulator, or null when the path is not one of them
 * (the caller falls through to its other routes).
 */
export function graphMailbox(
  request: SimRequest,
  token: ResolvedToken,
  directory: MsDirectory,
  findUser: (key: string) => MsUser | undefined,
  error: ErrorFn,
): SimResponse | null {
  const p = request.path;
  const m = request.method;
  let match: RegExpExecArray | null;
  let route: 'messages' | 'message' | 'action' | 'folder' | 'children';
  if ((match = GRAPH_MESSAGES_PATH.exec(p))) route = 'messages';
  else if ((match = GRAPH_MESSAGE_ACTION_PATH.exec(p))) route = 'action';
  else if ((match = GRAPH_MESSAGE_PATH.exec(p))) route = 'message';
  else if ((match = GRAPH_CHILD_FOLDERS_PATH.exec(p))) route = 'children';
  else if ((match = GRAPH_FOLDER_PATH.exec(p))) route = 'folder';
  else return null;

  const write = m !== 'GET';
  if (!hasPermission(token, write ? GRAPH_MAIL_WRITE_PERMISSIONS : GRAPH_MAIL_READ_PERMISSIONS)) {
    return error(403, 'ErrorAccessDenied');
  }
  const user = findUser(decodeURIComponent(match[1] as string));
  if (!user) return error(404, 'ErrorInvalidUser');
  const mailbox = mailboxOf(directory, user.id);
  const body = (request.body ?? {}) as Record<string, unknown>;

  if (route === 'messages') {
    if (m !== 'GET') return error(405, 'ErrorInvalidRequest');
    let clauses;
    try {
      clauses = parseFilter(request.query.get('$filter'));
    } catch (e) {
      if (e instanceof ODataError) return error(400, 'ErrorInvalidUrlQueryFilter');
      throw e;
    }
    if (clauses.some((c) => c.field !== 'internetMessageId' || c.op !== 'eq')) {
      return error(400, 'ErrorInvalidUrlQueryFilter');
    }
    const top = Number(request.query.get('$top') ?? DEFAULT_TOP);
    if (!Number.isInteger(top) || top < 1 || top > MAX_TOP)
      return error(400, 'ErrorInvalidRequest');
    const items = mailbox.messages
      .filter((msg) => msg.removedSeq === undefined && msg.deleted !== true)
      .map((msg) => messageItem(mailbox, user.id, msg))
      .filter((item) => matches(item, clauses))
      .slice(0, top)
      .map((item) => select(request, item));
    return json(200, { value: items });
  }

  if (route === 'message' || route === 'action') {
    const messageId = decodeURIComponent(match[2] as string);
    const message = liveMessage(mailbox, messageId);
    if (!message) return error(404, 'ErrorItemNotFound');
    if (route === 'message') {
      if (m === 'GET') return json(200, select(request, messageItem(mailbox, user.id, message)));
      if (m !== 'PATCH') return error(405, 'ErrorInvalidRequest');
      const keys = Object.keys(body);
      const categories = body.categories;
      if (
        keys.length !== 1 ||
        keys[0] !== 'categories' ||
        !Array.isArray(categories) ||
        categories.length > 250 ||
        categories.some((c) => typeof c !== 'string' || c.length > 255)
      ) {
        return error(400, 'ErrorInvalidRequest');
      }
      message.categories = [...new Set(categories as string[])];
      return json(200, messageItem(mailbox, user.id, message));
    }
    if (m !== 'POST') return error(405, 'ErrorInvalidRequest');
    const action = match[3] as 'move' | 'permanentDelete';
    if (action === 'permanentDelete') {
      mailbox.seq += 1;
      message.removedSeq = mailbox.seq;
      message.deleted = true;
      return json(204);
    }
    const destinationId = body.destinationId;
    if (typeof destinationId !== 'string' || Object.keys(body).length !== 1) {
      return error(400, 'ErrorInvalidRequest');
    }
    const destination = graphFolder(mailbox, user.id, destinationId);
    if (!destination) return error(404, 'ErrorItemNotFound');
    const newId = nextId(mailbox, user.id, 'msg');
    mailbox.seq += 1;
    message.removedSeq = mailbox.seq;
    message.movedToId = newId;
    mailbox.seq += 1;
    const moved: SimMailMessage = {
      ...message,
      id: newId,
      seq: mailbox.seq,
      categories: [...(message.categories ?? [])],
    };
    delete moved.removedSeq;
    delete moved.movedToId;
    if (destination.wellKnownName === 'inbox') delete moved.folderId;
    else moved.folderId = destination.id;
    mailbox.messages.push(moved);
    return json(201, messageItem(mailbox, user.id, moved));
  }

  const folder = graphFolder(mailbox, user.id, decodeURIComponent(match[2] as string));
  if (!folder) return error(404, 'ErrorItemNotFound');
  if (route === 'folder') {
    if (m !== 'GET') return error(405, 'ErrorInvalidRequest');
    return json(200, select(request, folderItem(mailbox, user.id, folder)));
  }
  const children = graphFolders(mailbox, user.id).filter((f) => f.parentFolderId === folder.id);
  if (m === 'GET') {
    const includeHidden = request.query.get('includeHiddenFolders') === 'true';
    let clauses;
    try {
      clauses = parseFilter(request.query.get('$filter'));
    } catch (e) {
      if (e instanceof ODataError) return error(400, 'ErrorInvalidUrlQueryFilter');
      throw e;
    }
    const items = children
      .filter((f) => includeHidden || !f.isHidden)
      .map((f) => folderItem(mailbox, user.id, f))
      .filter((item) => matches(item, clauses))
      .map((item) => select(request, item));
    return json(200, { value: items });
  }
  if (m !== 'POST') return error(405, 'ErrorInvalidRequest');
  const displayName = body.displayName;
  const isHidden = body.isHidden;
  if (
    typeof displayName !== 'string' ||
    displayName.trim().length === 0 ||
    displayName.length > 255 ||
    (isHidden !== undefined && typeof isHidden !== 'boolean') ||
    Object.keys(body).some((k) => k !== 'displayName' && k !== 'isHidden')
  ) {
    return error(400, 'ErrorInvalidRequest');
  }
  if (children.some((f) => f.displayName.toLowerCase() === displayName.toLowerCase())) {
    return error(409, 'ErrorFolderExists');
  }
  const created: SimMailFolder = {
    id: nextId(mailbox, user.id, 'fld'),
    displayName,
    parentFolderId: folder.id,
    wellKnownName: null,
    isHidden: isHidden === true,
  };
  graphFolders(mailbox, user.id).push(created);
  return json(201, folderItem(mailbox, user.id, created));
}
