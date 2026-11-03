import { DELIVERY_STATUSES } from '@email-gateway/event-contracts';
import { z } from 'zod';
import { DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT } from '../../../http/pagination';

/**
 * Request and response shapes of the delivery status routes (step 2.3 R13):
 * `/messages/{messageId}/deliveries`, `/messages/{messageId}/deliveries/events`, `/deliveries`.
 * Internal numeric ids never appear: messages are addressed by their registry public id,
 * recipients by `rcptSeq`, deliveries by `rcptSeq` + `deliverySeq`.
 */

export const MessageIdParamSchema = z.uuid();

export const DeliveryStatusSchema = z.enum(DELIVERY_STATUSES);
export const DirectionSchema = z.enum(['inbound', 'outbound', 'internal']);
export const MessageStatusSchema = z.enum([
  'received',
  'scanning',
  'scanned',
  'policy_evaluated',
  'quarantined',
  'delivery_queued',
  'delivered',
  'partially_delivered',
  'discarded',
  'failed',
]);
export const SignalSourceSchema = z.enum([
  'planner',
  'reinjection',
  'postfix_log',
  'bounce_notice',
  'reconciler',
]);

const limit = z.coerce.number().int().min(1).max(MAX_PAGE_LIMIT).default(DEFAULT_PAGE_LIMIT);
const cursor = z.string().min(1).max(128).optional();

export const DeliveryEventsQuerySchema = z.strictObject({
  rcptSeq: z.coerce
    .number()
    .int()
    .min(0)
    .max(65_535)
    .optional()
    .describe('Only the events of this recipient (position in the RCPT list)'),
  limit,
  cursor,
});
export type DeliveryEventsQuery = z.output<typeof DeliveryEventsQuerySchema>;

export const ListDeliveriesQuerySchema = z.strictObject({
  from: z.iso
    .datetime({ offset: true })
    .optional()
    .describe('Start of the received-at range (inclusive); default `to` − 24 h'),
  to: z.iso
    .datetime({ offset: true })
    .optional()
    .describe('End of the received-at range (exclusive); default now. At most 31 days'),
  status: DeliveryStatusSchema.optional(),
  direction: DirectionSchema.optional(),
  limit,
  cursor,
});
export type ListDeliveriesQuery = z.output<typeof ListDeliveriesQuerySchema>;

// ---- Responses ---------------------------------------------------------------------------

const IsoDate = z.iso.datetime();

export const DeliverySchema = z.object({
  rcptSeq: z.number().int(),
  deliverySeq: z.number().int().describe('0 = the initial delivery; releases use 1, 2, …'),
  recipient: z.string(),
  direction: DirectionSchema.nullable(),
  status: DeliveryStatusSchema,
  attemptCount: z.number().int().describe('Attempts against a remote server'),
  lastAttemptAt: IsoDate.nullable(),
  deliveredAt: IsoDate.nullable(),
  remoteHost: z.string().nullable(),
  finalSmtpCode: z.number().int().nullable(),
  enhancedStatus: z.string().nullable(),
  finalSmtpResponse: z.string().nullable(),
  lastErrorClass: z.string().nullable(),
  failureReason: z.string().nullable().describe('Gateway-side reason (e.g. direction_changed)'),
  dsnGenerated: z.boolean().describe('Postfix sent a DSN to the original sender'),
  statusChangedAt: IsoDate.nullable(),
});
export type DeliveryView = z.output<typeof DeliverySchema>;

export const MessageDeliveriesSchema = z.object({
  message: z.object({
    id: z.uuid(),
    direction: DirectionSchema,
    status: MessageStatusSchema,
    receivedAt: IsoDate,
  }),
  deliveries: z.array(DeliverySchema),
});
export type MessageDeliveriesView = z.output<typeof MessageDeliveriesSchema>;

export const DeliveryEventSchema = z.object({
  rcptSeq: z.number().int(),
  deliverySeq: z.number().int(),
  source: SignalSourceSchema,
  fromStatus: DeliveryStatusSchema.nullable(),
  toStatus: DeliveryStatusSchema,
  applied: z.boolean().describe('false for stale, conflicting or same-state signals'),
  occurredAt: IsoDate,
  queueId: z.string().nullable(),
  smtpCode: z.number().int().nullable(),
  enhancedStatus: z.string().nullable(),
  remoteHost: z.string().nullable(),
  errorClass: z.string().nullable(),
  detail: z.string().nullable().describe('Remote reply or reason text; never message content'),
});
export type DeliveryEventView = z.output<typeof DeliveryEventSchema>;

export const DeliveryEventPageSchema = z.object({
  data: z.array(DeliveryEventSchema).describe('Oldest first'),
  nextCursor: z.string().nullable(),
});

export const DeliveryListItemSchema = z.object({
  messageId: z.uuid(),
  rcptSeq: z.number().int(),
  recipient: z.string(),
  direction: DirectionSchema.nullable(),
  status: DeliveryStatusSchema,
  attemptCount: z.number().int(),
  lastErrorClass: z.string().nullable(),
  statusChangedAt: IsoDate.nullable(),
});
export type DeliveryListItem = z.output<typeof DeliveryListItemSchema>;

export const DeliveryListPageSchema = z.object({
  data: z.array(DeliveryListItemSchema).describe('Newest first (received at, then id)'),
  nextCursor: z.string().nullable(),
});
