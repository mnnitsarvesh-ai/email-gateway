import { z } from 'zod';
import { PageQuerySchema } from '../../../http/pagination';
import { ATTACHMENT_RESCAN_MAX_MESSAGES_LIMIT } from '../../../config';

/**
 * Shapes of the platform attachment rescan job routes (step 4.2 A13):
 * `POST|GET /platform/attachment-rescans`, `GET /platform/attachment-rescans/{jobId}`,
 * `POST /platform/attachment-rescans/{jobId}/cancel`. The api only writes and cancels job rows;
 * the email-worker's rescan runner executes them.
 */

/** The message states a job may select (A13: never `scanning`, delivery or terminal states). */
export const RESCAN_STATES = ['scanned', 'scan_failed', 'quarantined', 'held_for_review'] as const;
export type RescanState = (typeof RESCAN_STATES)[number];

/** Longest window of a job, in hours (A13). */
export const MAX_RESCAN_WINDOW_HOURS = 168;

const noControl = (value: string): boolean => {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
};

const Reason = z
  .string()
  .trim()
  .min(1)
  .max(512)
  .refine(noControl, 'Must not contain control characters');

export const RescanJobCreateSchema = z.strictObject({
  windowHours: z
    .number()
    .int()
    .min(1)
    .max(MAX_RESCAN_WINDOW_HOURS)
    .describe('Messages received in the last windowHours hours (1-168)'),
  states: z
    .array(z.enum(RESCAN_STATES))
    .min(1)
    .max(RESCAN_STATES.length)
    .refine((v) => new Set(v).size === v.length, 'Duplicate state')
    .optional()
    .describe('Message states to select (default: all four)'),
  organizationId: z
    .uuid()
    .optional()
    .describe('Only this organization (public id); default: every organization'),
  maxMessages: z
    .number()
    .int()
    .min(1)
    .max(ATTACHMENT_RESCAN_MAX_MESSAGES_LIMIT)
    .optional()
    .describe('At most this many messages (default and maximum: ATTACHMENT_RESCAN_MAX_MESSAGES)'),
  reason: Reason.describe('Why the rescan is needed (audited)'),
  dryRun: z
    .boolean()
    .default(false)
    .describe('Only count the candidates (200); nothing is written'),
});
export type RescanJobCreate = z.output<typeof RescanJobCreateSchema>;

/** Optional body: a request without one cancels without a reason. */
export const RescanJobCancelSchema = z
  .strictObject({
    reason: Reason.optional().describe('Why the job is cancelled (audited)'),
  })
  .optional()
  .transform((body) => body ?? {});
export type RescanJobCancel = z.output<typeof RescanJobCancelSchema>;

export const RESCAN_JOB_STATUSES = [
  'pending',
  'running',
  'completed',
  'cancelled',
  'failed',
  'skipped',
] as const;

export const RescanJobListQuerySchema = PageQuerySchema.extend({
  status: z.enum(RESCAN_JOB_STATUSES).optional().describe('Only jobs in this status'),
}).strict();
export type RescanJobListQuery = z.output<typeof RescanJobListQuerySchema>;

const IsoDate = z.iso.datetime();

export const RescanJobViewSchema = z.object({
  jobId: z.uuid(),
  trigger: z.enum(['signature_update', 'admin']),
  status: z.enum(RESCAN_JOB_STATUSES),
  organizationId: z.uuid().nullable().describe('null = every organization'),
  windowStart: IsoDate,
  windowEnd: IsoDate,
  states: z.array(z.string()),
  component: z
    .string()
    .nullable()
    .describe('Signature component of a signature_update job (clamav_db, yara_bundle, …)'),
  fromVersion: z.string().nullable(),
  toVersion: z.string().nullable(),
  maxMessages: z.number().int(),
  selectedCount: z.number().int(),
  requestedCount: z.number().int(),
  skippedCount: z.number().int(),
  requestedByUserId: z.uuid().nullable(),
  reason: z.string().nullable(),
  lastError: z.string().nullable(),
  startedAt: IsoDate.nullable(),
  completedAt: IsoDate.nullable(),
  createdAt: IsoDate,
  updatedAt: IsoDate,
});
export type RescanJobView = z.output<typeof RescanJobViewSchema>;

export const RescanJobPageSchema = z.object({
  data: z.array(RescanJobViewSchema).describe('Newest first'),
  nextCursor: z.string().nullable(),
});
export type RescanJobPage = z.output<typeof RescanJobPageSchema>;

export const RescanJobCreatedSchema = z.object({
  jobId: z.uuid(),
  status: z.literal('pending'),
  estimatedMessages: z
    .number()
    .int()
    .describe('Candidates now (replica), at most maxMessages; the worker selects on the writer'),
});
export type RescanJobCreated = z.output<typeof RescanJobCreatedSchema>;

export const RescanJobEstimateSchema = z.object({
  dryRun: z.literal(true),
  estimatedMessages: z.number().int().describe('Candidates now (replica), at most maxMessages'),
  windowStart: IsoDate,
  windowEnd: IsoDate,
  states: z.array(z.enum(RESCAN_STATES)),
  maxMessages: z.number().int(),
});
export type RescanJobEstimate = z.output<typeof RescanJobEstimateSchema>;
