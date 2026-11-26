/**
 * Gmail client of API mode (design D9, D10.5; family `gmail`). Reads only: the profile (current
 * history id), the INBOX `messageAdded` history, one message's metadata (Message-ID, internal
 * date, size estimate, labels) and its raw content, streamed and decoded by `GmailRawExtractor`.
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
}
