/**
 * Microsoft Graph mail client of API mode (design D9, D10.3, D10.4; family `graph`). API-1 reads:
 * users, the Inbox delta (no message content in the delta), the MIME content of one message, and
 * writes change-notification subscriptions (create, renew, delete). Step API-2 (note 36 R3, R5.3,
 * R6.2) adds the remediation calls: locate by Internet Message-ID, the message's folder and
 * categories, well-known folder ids, the hidden quarantine folder (ensure), move (returns the new
 * id), categories and permanent delete. Tokens come from
 * the `TokenSource` of the connection's active `m365.mailbox_remediation` grant (the worker
 * adapts 8.2's `ProviderTokenService.getAccessToken(grant, signal, { resource: 'graph' })`).
 *
 * Delta links and page links are opaque, provider-returned and followed only when same-origin and
 * under the Graph base path; they never appear in an error or a log line.
 */
import type { TokenSource } from '@email-gateway/idp-adapters';
import { z } from 'zod';
import { cursorExpired, isGraphCursorExpired, MailboxApiError, toMailboxApiError } from '../errors';
import {
  enc,
  guardedCall,
  hasControlCharacter,
  normalizedStream,
  type MailboxClientContext,
  type MailboxContentStream,
} from './context';

const USERS_FIRST_PAGE =
  '/v1.0/users?$select=id,mail,userPrincipalName,proxyAddresses,accountEnabled&$top=999';
const DELTA_SELECT = '$select=id,internetMessageId,receivedDateTime,isDraft&changeType=created';
/** Graph's resource path of the Inbox messages of a user. */
export const graphInboxResource = (userId: string): string =>
  `users/${userId}/mailFolders('inbox')/messages`;
/** Page size the delta asks for (D9). */
export const GRAPH_DELTA_PAGE_SIZE = 50;
const LINK = z.string().min(1).max(16_384);

const userSchema = z.object({
  id: z.string().min(1).max(128),
  mail: z.string().max(320).nullable().optional(),
  userPrincipalName: z.string().max(1024).nullable().optional(),
  proxyAddresses: z.array(z.string().max(1024)).max(2000).nullable().optional(),
  accountEnabled: z.boolean().nullable().optional(),
});
const usersPageSchema = z.object({
  value: z.array(userSchema).max(1000),
  '@odata.nextLink': LINK.optional(),
});

const deltaItemSchema = z.object({
  id: z.string().min(1).max(512),
  '@removed': z.object({ reason: z.string().max(64).optional() }).optional(),
  internetMessageId: z.string().max(998).nullable().optional(),
  receivedDateTime: z.string().max(64).nullable().optional(),
  isDraft: z.boolean().nullable().optional(),
});
const deltaPageSchema = z.object({
  value: z.array(deltaItemSchema).max(1000),
  '@odata.nextLink': LINK.optional(),
  '@odata.deltaLink': LINK.optional(),
});

const GRAPH_ID = z.string().min(1).max(512);
const CATEGORY = z.string().max(255);

const messageRefSchema = z.object({
  id: GRAPH_ID,
  parentFolderId: GRAPH_ID.nullable().optional(),
  isDraft: z.boolean().nullable().optional(),
});
const messageListSchema = z.object({ value: z.array(messageRefSchema).max(1000) });
const messageStateSchema = z.object({
  id: GRAPH_ID,
  parentFolderId: GRAPH_ID.nullable().optional(),
  categories: z.array(CATEGORY).max(250).nullable().optional(),
});
const folderSchema = z.object({
  id: GRAPH_ID,
  displayName: z.string().max(1024).nullable().optional(),
  isHidden: z.boolean().nullable().optional(),
});
const folderListSchema = z.object({ value: z.array(folderSchema).max(1000) });

/** Graph's well-known folder names the remediation uses (R6.2). */
export const GRAPH_REMEDIATION_WELL_KNOWN_FOLDERS = [
  'inbox',
  'junkemail',
  'sentitems',
  'recoverableitemsdeletions',
  'msgfolderroot',
] as const;
export type GraphRemediationWellKnownFolder = (typeof GRAPH_REMEDIATION_WELL_KNOWN_FOLDERS)[number];

/** Matches the locate step asks for (R5.3). */
export const GRAPH_LOCATE_TOP = 10;
/** RFC 5322 line limit: longer ids are refused before any call. */
const MESSAGE_ID_MAX = 998;

/** OData string literal: single quotes doubled (OData ABNF `SQUOTE-in-string`). */
export function odataStringLiteral(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

const badRequest = () => new MailboxApiError('bad_request', { retryable: false });

const subscriptionSchema = z.object({
  id: z.string().min(1).max(128),
  expirationDateTime: z.string().max(64),
});

export interface GraphMailUser {
  id: string;
  mail: string | null;
  userPrincipalName: string | null;
  /** `SMTP:`/`smtp:` entries as Graph returns them. */
  proxyAddresses: string[];
  accountEnabled: boolean | null;
}

export interface GraphUsersPage {
  users: GraphMailUser[];
  /** The next page link (same-origin checked), or null on the last page. */
  nextLink: string | null;
}

export interface GraphDeltaMessage {
  id: string;
  /** With angle brackets as Graph returns it, or null. */
  internetMessageId: string | null;
  /** Parsed `receivedDateTime`, or null when absent or invalid. */
  receivedDateTime: Date | null;
  isDraft: boolean;
}

export interface GraphDeltaPage {
  /** Created (or still present, on the initial round) Inbox messages, in provider order. */
  messages: GraphDeltaMessage[];
  /** Ids reported `@removed` (left the Inbox). */
  removed: string[];
  /** Exactly one of `nextLink` / `deltaLink` is set. Both are opaque cursors (never logged). */
  nextLink: string | null;
  deltaLink: string | null;
}

/** A located message (R5.3). */
export interface GraphMessageRef {
  id: string;
  parentFolderId: string | null;
  isDraft: boolean;
}

/** A message's folder and categories (the state read before acting, R5.4). */
export interface GraphMessageState {
  id: string;
  parentFolderId: string | null;
  categories: string[];
}

export interface CreateGraphSubscriptionInput {
  userId: string;
  notificationUrl: string;
  lifecycleNotificationUrl: string;
  expirationDateTime: Date;
  /** `deriveClientState(...)`; sent to Graph, never stored or returned. */
  clientState: string;
}

export interface GraphSubscription {
  id: string;
  expirationDateTime: Date;
}

function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : new Date(ms);
}

function subscriptionOf(data: z.infer<typeof subscriptionSchema>): GraphSubscription {
  const expiry = parseDate(data.expirationDateTime);
  if (!expiry) throw new MailboxApiError('unexpected_response', { retryable: false });
  return { id: data.id, expirationDateTime: expiry };
}

export class GraphMailClient {
  constructor(
    private readonly context: MailboxClientContext,
    private readonly token: TokenSource,
  ) {}

  /** Checks a provider link now (same origin, under the base path) so a bad page fails here. */
  private checkedLink(link: string | undefined): string | null {
    if (link === undefined) return null;
    try {
      this.context.http.relativize('graph', link);
    } catch (error) {
      throw toMailboxApiError(error);
    }
    return link;
  }

  /** One page of `GET /v1.0/users` (first page when `pageLink` is undefined). */
  listUsers(pageLink: string | undefined, signal: AbortSignal): Promise<GraphUsersPage> {
    return guardedCall(this.context, 'graph', signal, async () => {
      const response = await this.context.http.request({
        family: 'graph',
        method: 'GET',
        url: pageLink ?? USERS_FIRST_PAGE,
        pathTemplate: '/v1.0/users',
        token: this.token,
        signal,
        schema: usersPageSchema,
      });
      return {
        users: response.data.value.map((u) => ({
          id: u.id,
          mail: u.mail ?? null,
          userPrincipalName: u.userPrincipalName ?? null,
          proxyAddresses: u.proxyAddresses ?? [],
          accountEnabled: u.accountEnabled ?? null,
        })),
        nextLink: this.checkedLink(response.data['@odata.nextLink']),
      };
    });
  }

  /**
   * One page of the Inbox delta: the first round when `link` is undefined (D10.3 initializes by
   * paging to the delta link and discarding the items), else the stored next or delta link.
   * An expired cursor fails `cursor_expired` (re-initialize without backfill).
   */
  inboxDelta(
    userId: string,
    link: string | undefined,
    signal: AbortSignal,
  ): Promise<GraphDeltaPage> {
    return guardedCall(this.context, 'graph', signal, async () => {
      let response;
      try {
        response = await this.context.http.request({
          family: 'graph',
          method: 'GET',
          url:
            link ??
            `/v1.0/users/${enc(userId)}/mailFolders('inbox')/messages/delta?${DELTA_SELECT}`,
          pathTemplate: "/v1.0/users/{id}/mailFolders('inbox')/messages/delta",
          token: this.token,
          signal,
          schema: deltaPageSchema,
          headers: { Prefer: `odata.maxpagesize=${GRAPH_DELTA_PAGE_SIZE}` },
        });
      } catch (error) {
        const normalized = toMailboxApiError(error);
        if (isGraphCursorExpired(normalized)) {
          throw cursorExpired(normalized.status, normalized.providerCode);
        }
        throw normalized;
      }
      const data = response.data;
      const nextLink = this.checkedLink(data['@odata.nextLink']);
      const deltaLink = this.checkedLink(data['@odata.deltaLink']);
      if ((nextLink === null) === (deltaLink === null)) {
        throw new MailboxApiError('unexpected_response', {
          retryable: false,
          status: response.status,
        });
      }
      const messages: GraphDeltaMessage[] = [];
      const removed: string[] = [];
      for (const item of data.value) {
        if (item['@removed']) {
          removed.push(item.id);
          continue;
        }
        messages.push({
          id: item.id,
          internetMessageId: item.internetMessageId ?? null,
          receivedDateTime: parseDate(item.receivedDateTime),
          isDraft: item.isDraft === true,
        });
      }
      return { messages, removed, nextLink, deltaLink };
    });
  }

  /**
   * The MIME content of one message (`GET …/messages/{id}/$value`), streamed. More than
   * `maxBytes` fails `response_too_large` (declared or while streaming).
   */
  messageMime(
    userId: string,
    messageId: string,
    maxBytes: number,
    signal: AbortSignal,
  ): Promise<MailboxContentStream> {
    return guardedCall(this.context, 'graph', signal, async () => {
      const response = await this.context.http.requestStream({
        family: 'graph',
        method: 'GET',
        url: `/v1.0/users/${enc(userId)}/messages/${enc(messageId)}/$value`,
        pathTemplate: '/v1.0/users/{id}/messages/{mid}/$value',
        token: this.token,
        signal,
        maxBytes,
      });
      return {
        contentLength: response.headers.contentLength,
        body: normalizedStream(response.body),
      };
    });
  }

  /** `POST /v1.0/subscriptions` with exactly the D9 body (Graph validates the URLs first). */
  createSubscription(
    input: CreateGraphSubscriptionInput,
    signal: AbortSignal,
  ): Promise<GraphSubscription> {
    return guardedCall(this.context, 'graph', signal, async () => {
      const response = await this.context.http.request({
        family: 'graph',
        method: 'POST',
        url: '/v1.0/subscriptions',
        pathTemplate: '/v1.0/subscriptions',
        token: this.token,
        signal,
        schema: subscriptionSchema,
        body: {
          changeType: 'created',
          notificationUrl: input.notificationUrl,
          lifecycleNotificationUrl: input.lifecycleNotificationUrl,
          resource: graphInboxResource(input.userId),
          expirationDateTime: input.expirationDateTime.toISOString(),
          clientState: input.clientState,
          latestSupportedTlsVersion: 'v1_2',
        },
      });
      return subscriptionOf(response.data);
    });
  }

  /** `PATCH /v1.0/subscriptions/{id}` with the new expiry. */
  renewSubscription(
    subscriptionId: string,
    expirationDateTime: Date,
    signal: AbortSignal,
  ): Promise<GraphSubscription> {
    return guardedCall(this.context, 'graph', signal, async () => {
      const response = await this.context.http.request({
        family: 'graph',
        method: 'PATCH',
        url: `/v1.0/subscriptions/${enc(subscriptionId)}`,
        pathTemplate: '/v1.0/subscriptions/{id}',
        token: this.token,
        signal,
        schema: subscriptionSchema,
        body: { expirationDateTime: expirationDateTime.toISOString() },
      });
      return subscriptionOf(response.data);
    });
  }

  /** `DELETE /v1.0/subscriptions/{id}`; a subscription that is already gone counts as done. */
  deleteSubscription(
    subscriptionId: string,
    signal: AbortSignal,
  ): Promise<'deleted' | 'not_found'> {
    return guardedCall(this.context, 'graph', signal, async () => {
      try {
        await this.context.http.request({
          family: 'graph',
          method: 'DELETE',
          url: `/v1.0/subscriptions/${enc(subscriptionId)}`,
          pathTemplate: '/v1.0/subscriptions/{id}',
          token: this.token,
          signal,
        });
        return 'deleted' as const;
      } catch (error) {
        if (toMailboxApiError(error).code === 'not_found') return 'not_found' as const;
        throw error;
      }
    });
  }

  // -------------------------------------------------------------------------------------------
  // Step API-2 remediation (note 36 R3, R5.3, R5.4, R6.2). Path templates never carry ids.
  // -------------------------------------------------------------------------------------------

  /**
   * Locate step: `GET /v1.0/users/{u}/messages?$filter=internetMessageId eq '<id>'&$select=id,
   * parentFolderId,isDraft&$top=10` (every folder of the mailbox). The id keeps (or gets) its
   * angle brackets as Graph stores it; quotes are escaped per OData. A missing, over-long or
   * control-character id fails `bad_request` without a call.
   */
  findMessagesByInternetMessageId(
    userId: string,
    internetMessageId: string,
    signal: AbortSignal,
  ): Promise<GraphMessageRef[]> {
    const trimmed = internetMessageId.trim();
    const bracketed = trimmed.startsWith('<') ? trimmed : `<${trimmed}>`;
    if (
      trimmed.length === 0 ||
      bracketed.length > MESSAGE_ID_MAX ||
      hasControlCharacter(bracketed)
    ) {
      return Promise.reject(badRequest());
    }
    return guardedCall(this.context, 'graph', signal, async () => {
      const filter = `internetMessageId eq ${odataStringLiteral(bracketed)}`;
      const response = await this.context.http.request({
        family: 'graph',
        method: 'GET',
        url:
          `/v1.0/users/${enc(userId)}/messages?$filter=${enc(filter)}` +
          `&$select=id,parentFolderId,isDraft&$top=${GRAPH_LOCATE_TOP}`,
        pathTemplate: '/v1.0/users/{id}/messages',
        token: this.token,
        signal,
        schema: messageListSchema,
      });
      return response.data.value.map((m) => ({
        id: m.id,
        parentFolderId: m.parentFolderId ?? null,
        isDraft: m.isDraft === true,
      }));
    });
  }

  /** `GET …/messages/{id}?$select=id,parentFolderId,categories` (the state before acting). */
  getMessageState(
    userId: string,
    messageId: string,
    signal: AbortSignal,
  ): Promise<GraphMessageState> {
    return guardedCall(this.context, 'graph', signal, async () => {
      const response = await this.context.http.request({
        family: 'graph',
        method: 'GET',
        url: `/v1.0/users/${enc(userId)}/messages/${enc(messageId)}?$select=id,parentFolderId,categories`,
        pathTemplate: '/v1.0/users/{id}/messages/{mid}',
        token: this.token,
        signal,
        schema: messageStateSchema,
      });
      return {
        id: response.data.id,
        parentFolderId: response.data.parentFolderId ?? null,
        categories: response.data.categories ?? [],
      };
    });
  }

  /** `GET …/mailFolders/{wellKnownName}?$select=id`: the folder id of a well-known folder. */
  wellKnownFolderId(
    userId: string,
    name: GraphRemediationWellKnownFolder,
    signal: AbortSignal,
  ): Promise<string> {
    if (!(GRAPH_REMEDIATION_WELL_KNOWN_FOLDERS as readonly string[]).includes(name)) {
      return Promise.reject(badRequest());
    }
    return guardedCall(this.context, 'graph', signal, async () => {
      const response = await this.context.http.request({
        family: 'graph',
        method: 'GET',
        url: `/v1.0/users/${enc(userId)}/mailFolders/${name}?$select=id`,
        pathTemplate: '/v1.0/users/{id}/mailFolders/{wellKnown}',
        token: this.token,
        signal,
        schema: folderSchema,
      });
      return response.data.id;
    });
  }

  /**
   * Ensures a child folder of a well-known folder (R3 `move_quarantine`): looks it up first with
   * `includeHiddenFolders=true&$filter=displayName eq '<name>'` (a hidden folder is reused), then
   * creates it (`isHidden` as asked). A `409` (created concurrently) looks it up once more.
   */
  async ensureChildFolder(
    userId: string,
    parentWellKnown: GraphRemediationWellKnownFolder,
    displayName: string,
    hidden: boolean,
    signal: AbortSignal,
  ): Promise<{ id: string; created: boolean }> {
    if (
      !(GRAPH_REMEDIATION_WELL_KNOWN_FOLDERS as readonly string[]).includes(parentWellKnown) ||
      displayName.trim().length === 0 ||
      displayName.length > 255 ||
      hasControlCharacter(displayName)
    ) {
      throw badRequest();
    }
    const base = `/v1.0/users/${enc(userId)}/mailFolders/${parentWellKnown}/childFolders`;
    const pathTemplate = '/v1.0/users/{id}/mailFolders/{wellKnown}/childFolders';
    const lookup = () =>
      guardedCall(this.context, 'graph', signal, async () => {
        const filter = `displayName eq ${odataStringLiteral(displayName)}`;
        const response = await this.context.http.request({
          family: 'graph',
          method: 'GET',
          url: `${base}?includeHiddenFolders=true&$filter=${enc(filter)}&$select=id,displayName,isHidden`,
          pathTemplate,
          token: this.token,
          signal,
          schema: folderListSchema,
        });
        const wanted = displayName.toLowerCase();
        return (
          response.data.value.find((f) => (f.displayName ?? '').toLowerCase() === wanted)?.id ??
          null
        );
      });
    const existing = await lookup();
    if (existing !== null) return { id: existing, created: false };
    try {
      const created = await guardedCall(this.context, 'graph', signal, async () => {
        const response = await this.context.http.request({
          family: 'graph',
          method: 'POST',
          url: base,
          pathTemplate,
          token: this.token,
          signal,
          schema: folderSchema,
          body: { displayName, isHidden: hidden },
        });
        return response.data.id;
      });
      return { id: created, created: true };
    } catch (error) {
      if (!(error instanceof MailboxApiError) || error.code !== 'conflict') throw error;
      const raced = await lookup();
      if (raced === null) throw error;
      return { id: raced, created: false };
    }
  }

  /**
   * `POST …/messages/{id}/move { destinationId }` (a folder id or a well-known name). Graph
   * returns the moved message with a **new id** (ids are folder-scoped without immutable ids).
   */
  moveMessage(
    userId: string,
    messageId: string,
    destinationId: string,
    signal: AbortSignal,
  ): Promise<{ id: string; parentFolderId: string | null }> {
    return guardedCall(this.context, 'graph', signal, async () => {
      const response = await this.context.http.request({
        family: 'graph',
        method: 'POST',
        url: `/v1.0/users/${enc(userId)}/messages/${enc(messageId)}/move`,
        pathTemplate: '/v1.0/users/{id}/messages/{mid}/move',
        token: this.token,
        signal,
        schema: messageRefSchema,
        body: { destinationId },
      });
      return { id: response.data.id, parentFolderId: response.data.parentFolderId ?? null };
    });
  }

  /** `PATCH …/messages/{id} { categories }` (the whole list; the caller computes it). */
  setCategories(
    userId: string,
    messageId: string,
    categories: readonly string[],
    signal: AbortSignal,
  ): Promise<string[]> {
    if (
      categories.length > 250 ||
      categories.some((c) => c.length > 255 || hasControlCharacter(c))
    ) {
      return Promise.reject(badRequest());
    }
    return guardedCall(this.context, 'graph', signal, async () => {
      const response = await this.context.http.request({
        family: 'graph',
        method: 'PATCH',
        url: `/v1.0/users/${enc(userId)}/messages/${enc(messageId)}`,
        pathTemplate: '/v1.0/users/{id}/messages/{mid}',
        token: this.token,
        signal,
        schema: messageStateSchema,
        body: { categories: [...categories] },
      });
      return response.data.categories ?? [];
    });
  }

  /**
   * `POST …/messages/{id}/permanentDelete` (`204`): irreversible. Only for an explicit tenant
   * rule with `API_MODE_HARD_DELETE_ENABLED` (R-I2); never manual.
   */
  permanentDelete(userId: string, messageId: string, signal: AbortSignal): Promise<void> {
    return guardedCall(this.context, 'graph', signal, async () => {
      await this.context.http.request({
        family: 'graph',
        method: 'POST',
        url: `/v1.0/users/${enc(userId)}/messages/${enc(messageId)}/permanentDelete`,
        pathTemplate: '/v1.0/users/{id}/messages/{mid}/permanentDelete',
        token: this.token,
        signal,
      });
    });
  }
}
