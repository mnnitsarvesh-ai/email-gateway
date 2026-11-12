import type {
  MessageAction,
  MessageDirection,
  MessageVerdict,
  RecipientStatus,
} from '@email-gateway/database';
import { MESSAGE_STATES } from '@email-gateway/event-contracts';
import { z } from 'zod';
import { defineListQuery } from '../../../http/listing/list-query';
import {
  DeliveryStatusSchema,
  DirectionSchema,
  MessageStatusSchema,
} from '../../deliveries/dto/deliveries.schemas';
import { RecipientStatusSchema } from './messages.schemas';

/**
 * Request and response shapes of the step 6.1 message data routes (WP2, §3.3):
 * `GET /messages`, `GET /messages/{messageId}`, `GET /messages/{messageId}/recipients`.
 * Messages are addressed by their registry public id; internal numeric ids, S3 keys and content
 * never appear. Every list uses the signed v1 cursor (D3).
 */

export const MESSAGE_DIRECTIONS = [
  'inbound',
  'outbound',
  'internal',
] as const satisfies readonly MessageDirection[];
export const MESSAGE_VERDICTS = [
  'clean',
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp_violation',
  'suspicious',
  'unknown',
] as const satisfies readonly MessageVerdict[];
export const MESSAGE_ACTIONS = [
  'deliver',
  'tag',
  'quarantine',
  'discard',
  'reject',
  'require_approval',
  'partial',
] as const satisfies readonly MessageAction[];

/** Resource names bound into the v1 cursors (D3). */
export const MESSAGES_RESOURCE = 'messages';
export const MESSAGE_RECIPIENTS_RESOURCE = 'message_recipients';

/** `email_messages.risk_score` is 0–1000 (step 5.1 R3). */
export const RISK_SCORE_MAX = 1000;

/** `GET /messages` (D4, D5): range, allow-listed filters and the two sorts. */
export const MessageListQuerySchema = defineListQuery({
  filters: {
    direction: { type: 'enum', values: MESSAGE_DIRECTIONS, maxValues: 3 },
    status: { type: 'enum', values: MESSAGE_STATES, maxValues: 5 },
    verdict: { type: 'enum', values: MESSAGE_VERDICTS, maxValues: 5 },
    action: { type: 'enum', values: MESSAGE_ACTIONS, maxValues: 5 },
    domainId: { type: 'publicId' },
    sender: { type: 'email', maxLength: 320 },
    headerFrom: { type: 'string', maxLength: 320 },
    recipient: { type: 'email', maxLength: 320 },
    riskScore: { type: 'int', min: 0, max: RISK_SCORE_MAX, range: true },
    hasAttachments: { type: 'bool' },
    internetMessageId: { type: 'string', maxLength: 998 },
  },
  sorts: ['-receivedAt', 'receivedAt'],
  defaultSort: '-receivedAt',
  range: true,
});
export type MessageListQuery = z.output<typeof MessageListQuerySchema>;
export type MessageListFilters = MessageListQuery['filters'];

/** Documentation of each query parameter of `GET /messages` (OpenAPI). */
export const MESSAGE_LIST_PARAMETERS: Record<string, string> = {
  limit: 'Page size, 1-100 (default 25). A page may hold fewer rows (see the scan budget).',
  cursor: '`nextCursor` of the previous page (signed, bound to the filters, sort and caller)',
  sort: '`-receivedAt` (default, newest first) or `receivedAt`',
  from: 'Start of the range (ISO 8601 with offset, inclusive); default `to` − 24 h',
  to: 'End of the range (exclusive); default now. At most API_MESSAGES_MAX_RANGE_DAYS days',
  direction: '`inbound`, `outbound`, `internal`; comma list',
  status: 'Lifecycle state(s), comma list of at most 5',
  verdict: 'Final verdict(s), comma list of at most 5 (one value uses the verdict index)',
  action: 'Final action(s), comma list of at most 5',
  domainId: 'Public id of one of your domains (`404 domain_not_found` otherwise)',
  sender: 'Exact envelope sender (MAIL FROM), compared lower-cased. Audited (hashed)',
  headerFrom: 'Exact `From:` header value as stored. Audited (hashed)',
  recipient: 'Exact recipient address, compared lower-cased. Audited (hashed)',
  riskScore: 'Exact risk score (0-1000)',
  'riskScore.gte': 'Risk score at least (0-1000)',
  'riskScore.lte': 'Risk score at most (0-1000)',
  'riskScore.gt': 'Risk score above (0-1000)',
  'riskScore.lt': 'Risk score below (0-1000)',
  hasAttachments: '`true` or `false`',
  internetMessageId: 'Exact `Message-ID` header value. Audited (hashed)',
};

const IsoDate = z.iso.datetime();

export const MessageListItemSchema = z.object({
  id: z.uuid().describe('Message public id'),
  receivedAt: IsoDate,
  direction: DirectionSchema,
  status: MessageStatusSchema,
  statusChangedAt: IsoDate,
  subject: z.string().nullable().describe('Attacker-controlled text, returned as stored'),
  envelopeFrom: z.string(),
  headerFrom: z.string().nullable(),
  recipientCount: z.number().int().min(0),
  attachmentCount: z.number().int().min(0),
  sizeBytes: z.number().int().min(0),
  finalVerdict: z.enum(MESSAGE_VERDICTS).nullable(),
  finalAction: z.enum(MESSAGE_ACTIONS).nullable(),
  riskScore: z.number().int().min(0).max(RISK_SCORE_MAX).nullable().describe('0-1000'),
  domainId: z.uuid().nullable().describe('Public id of the domain, or null'),
});
export type MessageListItem = z.output<typeof MessageListItemSchema>;

export const MessageListPageSchema = z.object({
  data: z.array(MessageListItemSchema),
  nextCursor: z
    .string()
    .nullable()
    .describe('Null on the last page; may be set on a short or empty page (scan budget)'),
});
export type MessageListPage = z.output<typeof MessageListPageSchema>;

export const MessageDetailSchema = MessageListItemSchema.extend({
  internetMessageId: z.string().nullable(),
  lifecycleRound: z.number().int().min(0),
  version: z.number().int().min(0),
  statusReason: z.string().nullable(),
  clientIp: z.string().nullable(),
  clientHelo: z.string().nullable(),
  mtaQueueId: z.string().nullable(),
});
export type MessageDetail = z.output<typeof MessageDetailSchema>;

/** `GET /messages/{messageId}/recipients`: keyset `rcpt_seq`, no filters. */
export const MessageRecipientsQuerySchema = defineListQuery({
  filters: {},
  sorts: ['rcptSeq'],
  defaultSort: 'rcptSeq',
});
export type MessageRecipientsQuery = z.output<typeof MessageRecipientsQuerySchema>;

export const RECIPIENT_STATUSES =
  RecipientStatusSchema.options satisfies readonly RecipientStatus[];

export const MessageRecipientItemSchema = z.object({
  rcptSeq: z.number().int().min(0).describe('Position in the RCPT TO list'),
  address: z.string(),
  status: RecipientStatusSchema,
  finalAction: z.enum(MESSAGE_ACTIONS).nullable(),
  direction: DirectionSchema.nullable().describe('Routed direction; null before step 2.3'),
  userId: z.uuid().nullable().describe('Public id of the matched user, or null'),
  latestDelivery: z
    .object({
      deliverySeq: z.number().int().min(0),
      status: DeliveryStatusSchema,
      finalSmtpCode: z.number().int().nullable(),
      deliveredAt: IsoDate.nullable(),
    })
    .nullable()
    .describe('The delivery with the highest delivery sequence, or null before planning'),
});
export type MessageRecipientItem = z.output<typeof MessageRecipientItemSchema>;

export const MessageRecipientsPageSchema = z.object({
  data: z.array(MessageRecipientItemSchema),
  nextCursor: z.string().nullable(),
});
export type MessageRecipientsPage = z.output<typeof MessageRecipientsPageSchema>;
