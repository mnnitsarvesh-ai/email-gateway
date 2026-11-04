import type { QueueName } from '@email-gateway/event-contracts';
import { z } from 'zod';
import { REPLAYABLE_QUEUES } from '../domain/dead-letter-replay';

/**
 * Request and response shapes of the dead-letter routes (step 3.2 Q9):
 * `GET /platform/dead-letters` and `POST /platform/dead-letters/replay`. Organizations are
 * addressed by their public id; internal numeric ids never appear.
 */

/** Stable message of the 400 for a dormant, delay or dead-letter queue. */
export const SOURCE_QUEUE_NOT_REPLAYABLE = 'source_queue_not_replayable';

export const MAX_REPLAY_LIMIT = 1000;

const EVENT_TYPE = /^[a-z]+(\.[a-z_]+)+\.v[1-9][0-9]{0,5}$/;
const FAILURE_REASON = /^[a-z0-9_]{1,48}$/;

export const ReplayRequestSchema = z.strictObject({
  sourceQueue: z
    .string()
    .refine(
      (q) => (REPLAYABLE_QUEUES as readonly string[]).includes(q),
      SOURCE_QUEUE_NOT_REPLAYABLE,
    )
    .transform((q) => q as QueueName)
    .describe(`The work queue whose dead letters are replayed: ${REPLAYABLE_QUEUES.join(', ')}`),
  limit: z
    .number()
    .int()
    .min(1)
    .max(MAX_REPLAY_LIMIT)
    .describe('At most this many matching dead letters are replayed'),
  eventType: z
    .string()
    .regex(EVENT_TYPE, 'must be a versioned event type such as mail.message.received.v1')
    .optional()
    .describe('Only dead letters of this event type'),
  organizationId: z
    .uuid()
    .optional()
    .describe('Only dead letters of this organization (public id)'),
  failureReason: z
    .string()
    .regex(FAILURE_REASON, 'must be a failure reason code such as max_attempts_exceeded')
    .optional()
    .describe(
      'Only dead letters with this failure reason (x-eg-failure-reason or the broker reason)',
    ),
  dryRun: z
    .boolean()
    .default(false)
    .describe('Count and list what would be replayed; every message stays in the queue'),
  reason: z.string().trim().min(10).max(500).describe('Why the operator replays (audited)'),
});
export type ReplayRequest = z.output<typeof ReplayRequestSchema>;

export const ReplayItemSchema = z.object({
  eventId: z.string().nullable(),
  eventType: z.string().nullable(),
  organizationId: z.uuid().nullable().describe('Public id; null when unknown'),
  sourceQueue: z.string(),
  failureReason: z.string().nullable(),
  replayed: z.boolean(),
});
export type ReplayItem = z.output<typeof ReplayItemSchema>;

export const ReplayResponseSchema = z.object({
  replayId: z.uuid(),
  dryRun: z.boolean(),
  scanned: z.number().int().describe('Dead letters fetched (held, then acked or returned)'),
  matched: z.number().int().describe('Dead letters matching the source queue and filters'),
  replayed: z.number().int().describe('Republished, confirmed and removed from the queue'),
  skipped: z.object({
    invalid: z.number().int().describe('Matching but undecodable or refused by the content guard'),
    notMatching: z.number().int(),
  }),
  items: z.array(ReplayItemSchema).describe('The matching dead letters (at most `limit`)'),
});
export type ReplayResponse = z.output<typeof ReplayResponseSchema>;

export const DeadLetterStatsSchema = z.object({
  queue: z.literal('email.dead-letter'),
  messages: z.number().int().describe('Ready messages (no consumer by design)'),
  consumers: z.number().int(),
});
export type DeadLetterStats = z.output<typeof DeadLetterStatsSchema>;
