import type {
  MessageAction,
  MessageDirection,
  MessageVerdict,
  RecipientStatus,
} from '@email-gateway/database';
import { DELIVERY_STATUSES, MESSAGE_STATES } from '@email-gateway/event-contracts';
import { QUARANTINE_STATES } from '@email-gateway/quarantine';
import { z } from 'zod';
import { defineListQuery } from '../../../http/listing/list-query';
import {
  codePointLength,
  normalizeMessageIdKey,
  normalizeSubjectKey,
  normalizeSubjectPrefix,
  SUBJECT_KEY_LENGTH,
} from '../domain/search-keys';
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

/** Bounds of the normalized `subjectPrefix` (§2 E2): 3–128 code points. */
export const SUBJECT_PREFIX_MIN = 3;
export const SUBJECT_PREFIX_MAX = SUBJECT_KEY_LENGTH;

/**
 * `GET /messages` (6.1 D4, D5; step 7.2 §2 E1, E2): range, allow-listed filters and the two
 * sorts. Step 7.2 adds `subject`, `subjectPrefix`, `senderDomain`, `recipientDomain`,
 * `deliveryStatus` and `quarantineStatus`, and matches `internetMessageId` on its key (angle
 * brackets optional). The refinement checks the normalized search values (a subject of reply
 * markers only, a prefix outside 3–128 characters, a bracket-only Message-ID are `400`).
 */
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
    subject: { type: 'string', maxLength: 998 },
    subjectPrefix: { type: 'string', maxLength: 998 },
    senderDomain: { type: 'domain' },
    recipientDomain: { type: 'domain' },
    deliveryStatus: { type: 'enum', values: DELIVERY_STATUSES },
    quarantineStatus: { type: 'enum', values: QUARANTINE_STATES },
  },
  sorts: ['-receivedAt', 'receivedAt'],
  defaultSort: '-receivedAt',
  range: true,
}).superRefine((query, ctx) => {
  const subject = query.filters.subject?.values?.[0];
  if (subject !== undefined && normalizeSubjectKey(subject) === '') {
    ctx.addIssue({
      code: 'custom',
      path: ['subject'],
      message: 'must contain text besides reply markers and white space',
    });
  }
  const prefix = query.filters.subjectPrefix?.values?.[0];
  if (prefix !== undefined) {
    const length = codePointLength(normalizeSubjectPrefix(prefix));
    if (length < SUBJECT_PREFIX_MIN || length > SUBJECT_PREFIX_MAX) {
      ctx.addIssue({
        code: 'custom',
        path: ['subjectPrefix'],
        message:
          `must be ${SUBJECT_PREFIX_MIN} to ${SUBJECT_PREFIX_MAX} characters once reply ` +
          'markers are removed and white space is collapsed',
      });
    }
  }
  const messageId = query.filters.internetMessageId?.values?.[0];
  if (messageId !== undefined && normalizeMessageIdKey(messageId) === '') {
    ctx.addIssue({
      code: 'custom',
      path: ['internetMessageId'],
      message: 'must contain more than angle brackets and spaces',
    });
  }
});
export type MessageListQuery = z.output<typeof MessageListQuerySchema>;
export type MessageListFilters = MessageListQuery['filters'];

/** Documentation of each query parameter of `GET /messages` (OpenAPI). */
export const MESSAGE_LIST_PARAMETERS: Record<string, string> = {
  limit:
    'Page size, 1-100 (default 25). A page may hold fewer rows when residual filters are ' +
    'combined with a search driver (scan budget)',
  cursor: '`nextCursor` of the previous page (signed, bound to the filters, sort and caller)',
  sort: '`-receivedAt` (default, newest first) or `receivedAt`',
  from: 'Start of the range (ISO 8601 with offset, inclusive); default `to` − 24 h',
  to: 'End of the range (exclusive); default now. At most API_MESSAGES_MAX_RANGE_DAYS days',
  direction: '`inbound`, `outbound`, `internal`; comma list',
  status: 'Lifecycle state(s), comma list of at most 5',
  verdict: 'Final verdict(s), comma list of at most 5 (exactly one value drives the search)',
  action: 'Final action(s), comma list of at most 5',
  domainId: 'Public id of one of your domains (`404 domain_not_found` otherwise)',
  sender:
    'Exact envelope sender (MAIL FROM), compared case-insensitively (index driver). Audited ' +
    '(hashed)',
  headerFrom:
    'Exact From address as stored (the address inside `<…>` of the first `From:` header, else ' +
    'its raw value), case-insensitive (index driver). Audited (hashed)',
  recipient:
    'Exact envelope recipient address, case-insensitive (index driver). Requires ' +
    '`message:reveal` (`403 message_filter_forbidden`): recipient addresses are masked on every ' +
    'read, so only holders of the reveal permission may confirm one by search. Audited (hashed)',
  riskScore: 'Exact risk score (0-1000)',
  'riskScore.gte': 'Risk score at least (0-1000)',
  'riskScore.lte': 'Risk score at most (0-1000)',
  'riskScore.gt': 'Risk score above (0-1000)',
  'riskScore.lt': 'Risk score below (0-1000)',
  hasAttachments: '`true` or `false`',
  internetMessageId:
    'Message-ID, angle brackets optional (matched on its first 255 characters without `<` and ' +
    '`>`; index driver). Audited (hashed)',
  subject:
    'Exact subject, ignoring leading reply/forward markers (`Re:`, `Fwd:`, `AW:`, `RE[2]:`, …), ' +
    'white space runs, case and accents; matched on the first 128 characters (index driver). ' +
    'Requires `message:reveal` (`403 message_filter_forbidden`). Audited (SHA-256 of the ' +
    'normalized value)',
  subjectPrefix:
    'Subject starts with (normalized like `subject`, 3-128 characters). Refused with `422 ' +
    'message_search_too_broad` when more than API_MESSAGES_SEARCH_MAX_MATCHES messages of the ' +
    'range match. Requires `message:reveal`. Audited (SHA-256 of the normalized value)',
  senderDomain:
    'Domain of the envelope sender (`example.com` or `@example.com`; IDNs in A-label form; ' +
    'index driver)',
  recipientDomain:
    'Domain of any envelope recipient (`example.com` or `@example.com`; IDNs in A-label form; ' +
    'index driver)',
  deliveryStatus:
    'One delivery status: at least one delivery of the message (any recipient, any delivery ' +
    'sequence) is currently in it. Requires `delivery:read`',
  quarantineStatus:
    'One quarantine entry state: at least one entry of the message (any recipient and round) ' +
    'is currently in it. Requires `quarantine:read`',
};

const IsoDate = z.iso.datetime();

export const MessageListItemSchema = z.object({
  id: z.uuid().describe('Message public id'),
  receivedAt: IsoDate,
  direction: DirectionSchema,
  status: MessageStatusSchema,
  statusChangedAt: IsoDate,
  subject: z
    .string()
    .nullable()
    .describe(
      'Always `null` since step 7.2: the subject is withheld on every read (field kept for ' +
        'compatibility). `subjectMasked` says whether one exists; holders of `message:reveal` ' +
        'read it through the audited `POST /messages/reveal` or `POST /messages/{messageId}/reveal`',
    ),
  subjectMasked: z
    .boolean()
    .describe('Step 7.2: true when the message has a subject (withheld in `subject`)'),
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
  address: z
    .string()
    .describe(
      'Masked since step 7.2 (`f***@example.com`: the first character of the local part and the ' +
        'domain); the clear address only through the audited `POST /messages/{messageId}/reveal` ' +
        '(`message:reveal`)',
    ),
  addressMasked: z.boolean().describe('Step 7.2: true (the address is masked on every read)'),
  status: RecipientStatusSchema,
  finalAction: z.enum(MESSAGE_ACTIONS).nullable(),
  direction: DirectionSchema.nullable().describe('Routed direction; null before step 2.3'),
  userId: z
    .uuid()
    .nullable()
    .describe(
      'Always `null` since step 7.2: the matched user is withheld (it maps to an address); ' +
        'revealed with the address by `POST /messages/{messageId}/reveal`',
    ),
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
