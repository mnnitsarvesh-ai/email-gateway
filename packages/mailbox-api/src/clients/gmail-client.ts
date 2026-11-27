/**
 * Gmail client of API mode (design D9, D10.5; family `gmail`). API-1 reads: the profile (current
 * history id), the INBOX `messageAdded` history, one message's metadata (Message-ID, internal
 * date, size estimate, labels) and its raw content, streamed and decoded by `GmailRawExtractor`.
 * Step API-2 (note 36 R3, R5.3, R6.3) adds the remediation calls under `gmail.modify`: locate by
 * `rfc822msgid`, a message's labels, labels list/ensure (hidden), modify, trash and untrash.
 * There is deliberately no `delete`: `messages.delete` needs the full `https://mail.google.com/`
 * scope, which the mailbox grant does not request (a Google hard delete falls back to Trash).
 * Every call impersonates the mailbox (domain-wide delegation subject = the mailbox's primary
 * address): `tokens(mailbox)` returns the token source for that subject (the worker adapts 8.2's
 * `getAccessToken(grant, signal, { resource: 'google', subject })`).
 */
import type { TokenSource } from '@email-gateway/idp-adapters';
import { z } from 'zod';
import { cursorExpired, MailboxApiError, toMailboxApiError } from '../errors';
import { GmailRawExtractor } from '../gmail-raw-extractor';
import {
  enc,
  guardedCall,
  hasControlCharacter,
  normalizedStream,
  type MailboxClientContext,
  type MailboxContentStream,
} from './context';

const BASE = '/gmail/v1/users';
const HISTORY_ID = z.string().regex(/^\d{1,20}$/);
/** JSON outside the raw value of a `format=raw` answer (id, labels, snippet, …). */
const RAW_OTHER_BYTES = 256 * 1024;

const profileSchema = z.object({
  emailAddress: z.string().max(320).optional(),
  historyId: HISTORY_ID,
});

const messageRefSchema = z.object({
  id: z.string().min(1).max(64),
  threadId: z.string().max(64).optional(),
  labelIds: z.array(z.string().max(256)).max(500).optional(),
});

const historySchema = z.object({
  history: z
    .array(
      z.object({
        id: HISTORY_ID.optional(),
        messagesAdded: z
          .array(z.object({ message: messageRefSchema }))
          .max(1000)
          .optional(),
      }),
    )
    .max(1000)
    .optional(),
  nextPageToken: z.string().min(1).max(4096).optional(),
  historyId: HISTORY_ID,
});

const metadataSchema = z.object({
  id: z.string().min(1).max(64),
  threadId: z.string().max(64).optional(),
  labelIds: z.array(z.string().max(256)).max(500).optional(),
  internalDate: z
    .string()
    .regex(/^\d{1,16}$/)
    .optional(),
  sizeEstimate: z.number().int().min(0).optional(),
  historyId: HISTORY_ID.optional(),
  payload: z
    .object({
      headers: z
        .array(z.object({ name: z.string().max(256), value: z.string().max(4096) }))
        .max(200)
        .optional(),
    })
    .optional(),
});

const labelSchema = z.object({
  id: z.string().min(1).max(256),
  name: z.string().max(1024),
  type: z.string().max(32).optional(),
  labelListVisibility: z.string().max(64).optional(),
  messageListVisibility: z.string().max(64).optional(),
});
const labelListSchema = z.object({ labels: z.array(labelSchema).max(10_000).optional() });
const messageListSchema = z.object({
  messages: z
    .array(z.object({ id: z.string().min(1).max(64), threadId: z.string().max(64).optional() }))
    .max(500)
    .optional(),
  resultSizeEstimate: z.number().int().min(0).optional(),
  nextPageToken: z.string().max(4096).optional(),
});
const labeledMessageSchema = z.object({
  id: z.string().min(1).max(64),
  threadId: z.string().max(64).optional(),
  labelIds: z.array(z.string().max(256)).max(500).optional(),
});

/** Matches the locate step asks for (R5.3). */
export const GMAIL_LOCATE_MAX_RESULTS = 10;
/** Gmail's label-name limit. */
const LABEL_NAME_MAX = 225;
const MAX_LABEL_CHANGES = 100;
const badRequest = () => new MailboxApiError('bad_request', { retryable: false });

export interface GmailLabel {
  id: string;
  name: string;
  /** `system` or `user`. */
  type: string | null;
  labelListVisibility: string | null;
  messageListVisibility: string | null;
}

export interface GmailLabeledMessage {
  id: string;
  threadId: string | null;
  labelIds: string[];
}

export interface GmailProfile {
  /** The current history id (the cursor of a new feed; no backfill). */
  historyId: string;
}

export interface GmailAddedMessage {
  id: string;
  threadId: string | null;
  labelIds: string[];
  /** The message is in the Inbox (D10.5 fetches only those). */
  inInbox: boolean;
}

export interface GmailHistoryPage {
  /** `messagesAdded` of this page, de-duplicated by id, in history order. */
  added: GmailAddedMessage[];
  nextPageToken: string | null;
  /** The mailbox's current history id: the cursor to store after the last page. */
  historyId: string;
  /**
   * The highest history record id of this page (null when the page has none). Every record up to
   * it is on this or an earlier page, so it is a resumable cursor once the page is processed.
   */
  lastRecordId: string | null;
}

export interface GmailMessageMetadata {
  id: string;
  threadId: string | null;
  labelIds: string[];
  /** The `Message-ID` header (angle brackets kept), or null. */
  messageId: string | null;
  /** `internalDate` (the provider delivery time), or null. */
  internalDate: Date | null;
  /** Gmail's size estimate in bytes (the pre-check against the message cap). */
  sizeEstimate: number | null;
  historyId: string | null;
}

export class GmailClient {
  constructor(
    private readonly context: MailboxClientContext,
    private readonly tokens: (mailbox: string) => TokenSource,
  ) {}

  /** `GET /gmail/v1/users/{u}/profile`. */
  profile(mailbox: string, signal: AbortSignal): Promise<GmailProfile> {
    return guardedCall(this.context, 'gmail', signal, async () => {
      const response = await this.context.http.request({
        family: 'gmail',
        method: 'GET',
        url: `${BASE}/${enc(mailbox)}/profile`,
        pathTemplate: `${BASE}/{userId}/profile`,
        token: this.tokens(mailbox),
        signal,
        schema: profileSchema,
      });
      return { historyId: response.data.historyId };
    });
  }

  /**
   * One page of `history.list` from `startHistoryId` (`historyTypes=messageAdded`,
   * `labelId=INBOX`, 500 per page). A start id Gmail no longer has fails `cursor_expired`.
   */
  history(
    mailbox: string,
    startHistoryId: string,
    pageToken: string | undefined,
    signal: AbortSignal,
  ): Promise<GmailHistoryPage> {
    if (!/^\d{1,20}$/.test(startHistoryId)) {
      return Promise.reject(new MailboxApiError('bad_request', { retryable: false }));
    }
    return guardedCall(this.context, 'gmail', signal, async () => {
      const query = new URLSearchParams({
        startHistoryId,
        historyTypes: 'messageAdded',
        labelId: 'INBOX',
        maxResults: '500',
      });
      if (pageToken !== undefined) query.set('pageToken', pageToken);
      let response;
      try {
        response = await this.context.http.request({
          family: 'gmail',
          method: 'GET',
          url: `${BASE}/${enc(mailbox)}/history?${query.toString()}`,
          pathTemplate: `${BASE}/{userId}/history`,
          token: this.tokens(mailbox),
          signal,
          schema: historySchema,
        });
      } catch (error) {
        const normalized = toMailboxApiError(error);
        if (normalized.code === 'not_found') {
          throw cursorExpired(normalized.status, normalized.providerCode);
        }
        throw normalized;
      }
      const seen = new Set<string>();
      const added: GmailAddedMessage[] = [];
      let lastRecordId: bigint | null = null;
      for (const record of response.data.history ?? []) {
        if (record.id !== undefined) {
          const id = BigInt(record.id);
          if (lastRecordId === null || id > lastRecordId) lastRecordId = id;
        }
        for (const entry of record.messagesAdded ?? []) {
          const message = entry.message;
          if (seen.has(message.id)) continue;
          seen.add(message.id);
          const labelIds = message.labelIds ?? [];
          added.push({
            id: message.id,
            threadId: message.threadId ?? null,
            labelIds,
            inInbox: labelIds.includes('INBOX'),
          });
        }
      }
      return {
        added,
        nextPageToken: response.data.nextPageToken ?? null,
        historyId: response.data.historyId,
        lastRecordId: lastRecordId === null ? null : lastRecordId.toString(),
      };
    });
  }

  /** `messages.get?format=metadata&metadataHeaders=Message-ID`. */
  messageMetadata(
    mailbox: string,
    messageId: string,
    signal: AbortSignal,
  ): Promise<GmailMessageMetadata> {
    return guardedCall(this.context, 'gmail', signal, async () => {
      const response = await this.context.http.request({
        family: 'gmail',
        method: 'GET',
        url: `${BASE}/${enc(mailbox)}/messages/${enc(messageId)}?format=metadata&metadataHeaders=Message-ID`,
        pathTemplate: `${BASE}/{userId}/messages/{id}`,
        token: this.tokens(mailbox),
        signal,
        schema: metadataSchema,
      });
      const data = response.data;
      const header = (data.payload?.headers ?? []).find(
        (h) => h.name.toLowerCase() === 'message-id',
      );
      const internal = data.internalDate === undefined ? NaN : Number(data.internalDate);
      return {
        id: data.id,
        threadId: data.threadId ?? null,
        labelIds: data.labelIds ?? [],
        messageId: header ? header.value.trim() || null : null,
        internalDate: Number.isFinite(internal) ? new Date(internal) : null,
        sizeEstimate: data.sizeEstimate ?? null,
        historyId: data.historyId ?? null,
      };
    });
  }

  /**
   * `messages.get?format=raw`, streamed: the decoded RFC 5322 bytes (≤ `maxBytes`, else
   * `response_too_large`). The JSON is never buffered whole.
   */
  messageRaw(
    mailbox: string,
    messageId: string,
    maxBytes: number,
    signal: AbortSignal,
  ): Promise<MailboxContentStream> {
    return guardedCall(this.context, 'gmail', signal, async () => {
      const response = await this.context.http.requestStream({
        family: 'gmail',
        method: 'GET',
        url: `${BASE}/${enc(mailbox)}/messages/${enc(messageId)}?format=raw`,
        pathTemplate: `${BASE}/{userId}/messages/{id}`,
        token: this.tokens(mailbox),
        signal,
        accept: 'application/json',
        // base64 grows by 4/3 (+ padding), plus the other fields of the answer.
        maxBytes: Math.ceil(maxBytes / 3) * 4 + RAW_OTHER_BYTES,
      });
      return {
        contentLength: undefined,
        body: normalizedStream(
          GmailRawExtractor.extract(response.body, {
            maxDecodedBytes: maxBytes,
            maxOtherBytes: RAW_OTHER_BYTES,
          }),
        ),
      };
    });
  }

  // -------------------------------------------------------------------------------------------
  // Step API-2 remediation (note 36 R3, R5.3, R5.4, R6.3). Path templates never carry ids.
  // -------------------------------------------------------------------------------------------

  private labeled(data: z.infer<typeof labeledMessageSchema>): GmailLabeledMessage {
    return { id: data.id, threadId: data.threadId ?? null, labelIds: data.labelIds ?? [] };
  }

  /**
   * Locate step: `GET …/messages?q=rfc822msgid:<id>&includeSpamTrash=true&maxResults=10` (the
   * id without angle brackets). An empty id, whitespace or control characters fail `bad_request`
   * without a call (they would change the search query).
   */
  findMessagesByRfc822Id(
    mailbox: string,
    messageId: string,
    signal: AbortSignal,
  ): Promise<{ id: string; threadId: string | null }[]> {
    const bare = messageId.trim().replace(/^<|>$/g, '');
    if (bare.length === 0 || bare.length > 996 || /\s/.test(bare) || hasControlCharacter(bare)) {
      return Promise.reject(badRequest());
    }
    return guardedCall(this.context, 'gmail', signal, async () => {
      const query = new URLSearchParams({
        q: `rfc822msgid:${bare}`,
        includeSpamTrash: 'true',
        maxResults: String(GMAIL_LOCATE_MAX_RESULTS),
      });
      const response = await this.context.http.request({
        family: 'gmail',
        method: 'GET',
        url: `${BASE}/${enc(mailbox)}/messages?${query.toString()}`,
        pathTemplate: `${BASE}/{userId}/messages`,
        token: this.tokens(mailbox),
        signal,
        schema: messageListSchema,
      });
      return (response.data.messages ?? []).map((m) => ({
        id: m.id,
        threadId: m.threadId ?? null,
      }));
    });
  }

  /** `GET …/messages/{id}?format=minimal` → the message's labels (the state before acting). */
  messageLabels(
    mailbox: string,
    messageId: string,
    signal: AbortSignal,
  ): Promise<GmailLabeledMessage> {
    return guardedCall(this.context, 'gmail', signal, async () => {
      const response = await this.context.http.request({
        family: 'gmail',
        method: 'GET',
        url: `${BASE}/${enc(mailbox)}/messages/${enc(messageId)}?format=minimal`,
        pathTemplate: `${BASE}/{userId}/messages/{id}`,
        token: this.tokens(mailbox),
        signal,
        schema: labeledMessageSchema,
      });
      return this.labeled(response.data);
    });
  }

  /** `GET …/labels` (system and user labels). */
  listLabels(mailbox: string, signal: AbortSignal): Promise<GmailLabel[]> {
    return guardedCall(this.context, 'gmail', signal, async () => {
      const response = await this.context.http.request({
        family: 'gmail',
        method: 'GET',
        url: `${BASE}/${enc(mailbox)}/labels`,
        pathTemplate: `${BASE}/{userId}/labels`,
        token: this.tokens(mailbox),
        signal,
        schema: labelListSchema,
      });
      return (response.data.labels ?? []).map((l) => ({
        id: l.id,
        name: l.name,
        type: l.type ?? null,
        labelListVisibility: l.labelListVisibility ?? null,
        messageListVisibility: l.messageListVisibility ?? null,
      }));
    });
  }

  /**
   * Ensures a user label by name (case-insensitive, as Gmail compares names): reused when it
   * exists, else created — hidden labels with `labelListVisibility: labelHide` and
   * `messageListVisibility: hide`. A `409` (created concurrently) lists once more.
   */
  async ensureLabel(
    mailbox: string,
    name: string,
    hidden: boolean,
    signal: AbortSignal,
  ): Promise<{ id: string; created: boolean }> {
    if (name.trim().length === 0 || name.length > LABEL_NAME_MAX || hasControlCharacter(name)) {
      throw badRequest();
    }
    const wanted = name.toLowerCase();
    const find = async () =>
      (await this.listLabels(mailbox, signal)).find((l) => l.name.toLowerCase() === wanted)?.id ??
      null;
    const existing = await find();
    if (existing !== null) return { id: existing, created: false };
    try {
      const id = await guardedCall(this.context, 'gmail', signal, async () => {
        const response = await this.context.http.request({
          family: 'gmail',
          method: 'POST',
          url: `${BASE}/${enc(mailbox)}/labels`,
          pathTemplate: `${BASE}/{userId}/labels`,
          token: this.tokens(mailbox),
          signal,
          schema: labelSchema,
          body: {
            name,
            labelListVisibility: hidden ? 'labelHide' : 'labelShow',
            messageListVisibility: hidden ? 'hide' : 'show',
          },
        });
        return response.data.id;
      });
      return { id, created: true };
    } catch (error) {
      if (!(error instanceof MailboxApiError) || error.code !== 'conflict') throw error;
      const raced = await find();
      if (raced === null) throw error;
      return { id: raced, created: false };
    }
  }

  /** `POST …/messages/{id}/modify { addLabelIds, removeLabelIds }`. */
  modifyLabels(
    mailbox: string,
    messageId: string,
    add: readonly string[],
    remove: readonly string[],
    signal: AbortSignal,
  ): Promise<GmailLabeledMessage> {
    if (add.length > MAX_LABEL_CHANGES || remove.length > MAX_LABEL_CHANGES) {
      return Promise.reject(badRequest());
    }
    return guardedCall(this.context, 'gmail', signal, async () => {
      const response = await this.context.http.request({
        family: 'gmail',
        method: 'POST',
        url: `${BASE}/${enc(mailbox)}/messages/${enc(messageId)}/modify`,
        pathTemplate: `${BASE}/{userId}/messages/{id}/modify`,
        token: this.tokens(mailbox),
        signal,
        schema: labeledMessageSchema,
        body: { addLabelIds: [...add], removeLabelIds: [...remove] },
      });
      return this.labeled(response.data);
    });
  }

  /** `POST …/messages/{id}/trash` (recoverable for 30 days). */
  trash(mailbox: string, messageId: string, signal: AbortSignal): Promise<GmailLabeledMessage> {
    return this.trashCall(mailbox, messageId, 'trash', signal);
  }

  /** `POST …/messages/{id}/untrash`. */
  untrash(mailbox: string, messageId: string, signal: AbortSignal): Promise<GmailLabeledMessage> {
    return this.trashCall(mailbox, messageId, 'untrash', signal);
  }

  private trashCall(
    mailbox: string,
    messageId: string,
    op: 'trash' | 'untrash',
    signal: AbortSignal,
  ): Promise<GmailLabeledMessage> {
    return guardedCall(this.context, 'gmail', signal, async () => {
      const response = await this.context.http.request({
        family: 'gmail',
        method: 'POST',
        url: `${BASE}/${enc(mailbox)}/messages/${enc(messageId)}/${op}`,
        pathTemplate: `${BASE}/{userId}/messages/{id}/${op}`,
        token: this.tokens(mailbox),
        signal,
        schema: labeledMessageSchema,
      });
      return this.labeled(response.data);
    });
  }
}
