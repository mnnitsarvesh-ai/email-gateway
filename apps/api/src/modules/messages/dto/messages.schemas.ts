import { ACTOR_ROLES } from '@email-gateway/event-contracts';
import { z } from 'zod';
import { DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT } from '../../../http/pagination';
import { DirectionSchema, MessageStatusSchema } from '../../deliveries/dto/deliveries.schemas';

/**
 * Request and response shapes of the message lifecycle routes (step 3.3 L10, L12):
 * `GET /messages/{messageId}/lifecycle`, `GET /messages/{messageId}/lifecycle/history`,
 * `POST /messages/{messageId}/rescan`, `POST /messages/{messageId}/release`. Messages are
 * addressed by their registry public id; internal numeric ids, subjects, addresses and bodies
 * never appear.
 */

export const MessageIdSchema = z.uuid();

/** Body of rescan and release (L10.1). `reason` is stored in the audit row only. */
export const LifecycleOperationBodySchema = z.strictObject({
  expectedVersion: z
    .number()
    .int()
    .min(0)
    .max(4_294_967_295)
    .describe('The message `version` the operator saw (optimistic concurrency, 409 otherwise)'),
  reason: z
    .string()
    .trim()
    .min(10)
    .max(500)
    .describe('Why the operator acts (audited; never stored in the lifecycle history or events)'),
});
export type LifecycleOperationBody = z.output<typeof LifecycleOperationBodySchema>;

export const LifecycleHistoryQuerySchema = z.strictObject({
  limit: z.coerce.number().int().min(1).max(MAX_PAGE_LIMIT).default(DEFAULT_PAGE_LIMIT),
  cursor: z.string().min(1).max(64).optional(),
});
export type LifecycleHistoryQuery = z.output<typeof LifecycleHistoryQuerySchema>;

// ---- Responses ---------------------------------------------------------------------------

const IsoDate = z.iso.datetime();
const Version = z.number().int().min(0).describe('+1 per applied transition');
const Round = z.number().int().min(0).describe('+1 per rescan or release');

export const RescanResponseSchema = z.object({
  messageId: z.uuid(),
  state: z.literal('scanning'),
  version: Version,
  lifecycleRound: Round,
  rescanEventId: z.uuid().describe('Event id of mail.message.rescan_requested.v1'),
  note: z.string().describe('Present while no scan stage is deployed (before Phase 4)'),
});
export type RescanResponse = z.output<typeof RescanResponseSchema>;

export const ReleaseResponseSchema = z.object({
  messageId: z.uuid(),
  state: z.literal('approved'),
  version: Version,
  lifecycleRound: Round,
  deliverySeq: z.number().int().min(1).describe('Delivery sequence of the release (1, 2, …)'),
  approvalEventIds: z
    .array(z.uuid())
    .describe('Event ids of mail.delivery.approved.v1 (one per 1000 recipients)'),
  recipientCount: z.number().int().min(1).describe('Recipients approved for delivery'),
});
export type ReleaseResponse = z.output<typeof ReleaseResponseSchema>;

export const ParseStatusSchema = z.enum([
  'parsing',
  'parsed',
  'parsed_with_defects',
  'parse_limit_exceeded',
  'parse_failed',
]);

export const RecipientStatusSchema = z.enum([
  'pending',
  'delivered',
  'quarantined',
  'discarded',
  'deferred',
  'failed',
  'bounced',
]);

export const LifecycleViewSchema = z.object({
  messageId: z.uuid(),
  receivedAt: IsoDate,
  direction: DirectionSchema,
  state: MessageStatusSchema,
  statusReason: z
    .string()
    .nullable()
    .describe('Reason code of the last transition, e.g. delivery_partial'),
  version: Version,
  lifecycleRound: Round,
  statusChangedAt: IsoDate,
  parse: z
    .object({ status: ParseStatusSchema, completedAt: IsoDate.nullable() })
    .nullable()
    .describe('MIME parse stage (step 3.1); null before the parse started'),
  recipients: z.object({
    total: z.number().int(),
    byStatus: z.partialRecord(RecipientStatusSchema, z.number().int()).describe('Non-zero counts'),
  }),
  deliverySeq: z
    .number()
    .int()
    .nullable()
    .describe('Highest delivery sequence planned (0 = initial); null before planning'),
  actions: z
    .object({ rescan: z.boolean(), release: z.boolean() })
    .describe('Operations the current state allows (not the caller’s permissions)'),
});
export type LifecycleView = z.output<typeof LifecycleViewSchema>;

export const HistoryActorRoleSchema = z.enum([...ACTOR_ROLES, 'legacy']);

export const LifecycleHistoryEntrySchema = z.object({
  version: Version.describe('Message version after the transition'),
  fromState: MessageStatusSchema.nullable(),
  toState: MessageStatusSchema,
  reasonCode: z.string().nullable(),
  lifecycleRound: Round,
  actor: z.object({
    role: HistoryActorRoleSchema.describe('`legacy` for rows written before step 3.3'),
    type: z.enum(['system', 'user', 'api_key']),
    service: z.string(),
    id: z.string().nullable().describe('Public id of the user or API key; null for systems'),
  }),
  causationEventId: z.string().nullable(),
  correlationId: z.string().nullable(),
  occurredAt: IsoDate.nullable(),
  changedAt: IsoDate,
});
export type LifecycleHistoryEntry = z.output<typeof LifecycleHistoryEntrySchema>;

export const LifecycleHistoryPageSchema = z.object({
  data: z.array(LifecycleHistoryEntrySchema).describe('Oldest first (by version)'),
  nextCursor: z.string().nullable(),
});
