import { z } from 'zod';
import { REPORT_GRANULARITIES } from './domain/report-window';
import {
  MESSAGE_ACTIONS,
  MESSAGE_DIRECTIONS,
  MESSAGE_VERDICTS,
  QUARANTINE_PRIMARY_ENGINES,
  QUARANTINE_REASONS,
  URL_CLICK_DECISIONS,
} from './reports.repository';

/** `/reports/*` (step 6.1 §3.3, D12): strict query schemas and the response shapes. */

const instant = z.iso
  .datetime({ offset: true })
  .transform((v) => new Date(v))
  .optional();

const range = {
  from: instant.describe('Inclusive start (ISO 8601); floored to the bucket boundary (UTC)'),
  to: instant.describe('Exclusive end (ISO 8601), default now; ceiled to the bucket boundary'),
};

export const TrafficReportQuerySchema = z.strictObject({
  ...range,
  granularity: z
    .enum(REPORT_GRANULARITIES)
    .optional()
    .describe('Bucket size: `hour` (range ≤ 7 days, default last 24 h) or `day` (default)'),
  direction: z.enum(MESSAGE_DIRECTIONS).optional(),
});
export type TrafficReportQuery = z.output<typeof TrafficReportQuerySchema>;

export const ThreatsReportQuerySchema = z.strictObject(range);
export type ThreatsReportQuery = z.output<typeof ThreatsReportQuerySchema>;

export const UrlClicksReportQuerySchema = z.strictObject({
  ...range,
  granularity: z.enum(REPORT_GRANULARITIES).optional(),
});
export type UrlClicksReportQuery = z.output<typeof UrlClicksReportQuerySchema>;

const counts = <T extends string>(keys: readonly T[]) =>
  z.strictObject(
    Object.fromEntries(keys.map((k) => [k, z.number().int().nonnegative()])) as Record<
      T,
      z.ZodNumber
    >,
  );

const VERDICT_KEYS = [...MESSAGE_VERDICTS, 'none'] as const;
const ACTION_KEYS = [...MESSAGE_ACTIONS, 'none'] as const;

const TrafficCountsSchema = z.object({
  total: z.number().int().nonnegative(),
  inbound: z.number().int().nonnegative(),
  outbound: z.number().int().nonnegative(),
  internal: z.number().int().nonnegative(),
  verdicts: counts(VERDICT_KEYS).describe('By final verdict; `none` = not decided yet'),
});

const windowFields = {
  from: z.iso.datetime().describe('Aligned inclusive start (UTC)'),
  to: z.iso.datetime().describe('Aligned exclusive end (UTC)'),
  generatedAt: z.iso
    .datetime()
    .describe('When the report was computed (served from the cache until it expires)'),
};

export const TrafficReportSchema = z.object({
  ...windowFields,
  granularity: z.enum(REPORT_GRANULARITIES),
  direction: z.enum(MESSAGE_DIRECTIONS).nullable(),
  buckets: z.array(TrafficCountsSchema.extend({ start: z.iso.datetime() })),
  totals: TrafficCountsSchema,
});
export type TrafficReport = z.output<typeof TrafficReportSchema>;

export const ThreatsReportSchema = z.object({
  ...windowFields,
  messages: z.object({
    total: z.number().int().nonnegative(),
    verdicts: counts(VERDICT_KEYS),
    actions: counts(ACTION_KEYS).describe('By final action; `none` = not decided yet'),
  }),
  quarantine: z.object({
    total: z.number().int().nonnegative().describe('Quarantine entries (one per recipient)'),
    reasons: counts(QUARANTINE_REASONS),
    primaryEngines: counts(QUARANTINE_PRIMARY_ENGINES),
  }),
});
export type ThreatsReport = z.output<typeof ThreatsReportSchema>;

const ClickCountsSchema = z.object({
  total: z.number().int().nonnegative(),
  decisions: counts(URL_CLICK_DECISIONS),
});

export const UrlClicksReportSchema = z.object({
  ...windowFields,
  granularity: z.enum(REPORT_GRANULARITIES),
  buckets: z.array(ClickCountsSchema.extend({ start: z.iso.datetime() })),
  totals: ClickCountsSchema,
});
export type UrlClicksReport = z.output<typeof UrlClicksReportSchema>;

export const zeroCounts = <T extends string>(keys: readonly T[]): Record<T, number> =>
  Object.fromEntries(keys.map((k) => [k, 0])) as Record<T, number>;

export { ACTION_KEYS, VERDICT_KEYS };

// ---- OpenAPI examples (explicit, D14) ------------------------------------------------------

const verdictsExample = {
  clean: 1180,
  spam: 41,
  bulk: 12,
  phishing: 3,
  malware: 1,
  bec: 0,
  dlp_violation: 2,
  suspicious: 5,
  unknown: 0,
  none: 4,
};

export const TRAFFIC_REPORT_EXAMPLE: TrafficReport = {
  from: '2026-11-11T00:00:00.000Z',
  to: '2026-11-12T00:00:00.000Z',
  generatedAt: '2026-11-12T09:30:00.000Z',
  granularity: 'day',
  direction: null,
  buckets: [
    {
      start: '2026-11-11T00:00:00.000Z',
      total: 1248,
      inbound: 1010,
      outbound: 220,
      internal: 18,
      verdicts: verdictsExample,
    },
  ],
  totals: { total: 1248, inbound: 1010, outbound: 220, internal: 18, verdicts: verdictsExample },
};

export const THREATS_REPORT_EXAMPLE: ThreatsReport = {
  from: '2026-11-05T09:00:00.000Z',
  to: '2026-11-12T10:00:00.000Z',
  generatedAt: '2026-11-12T09:30:00.000Z',
  messages: {
    total: 1248,
    verdicts: verdictsExample,
    actions: {
      deliver: 1190,
      tag: 20,
      quarantine: 30,
      discard: 0,
      reject: 2,
      require_approval: 1,
      partial: 1,
      none: 4,
    },
  },
  quarantine: {
    total: 34,
    reasons: {
      spam: 20,
      bulk: 4,
      phishing: 4,
      malware: 1,
      bec: 0,
      dlp: 2,
      policy: 3,
      suspicious: 0,
      engine_unavailable: 0,
      manual: 0,
    },
    primaryEngines: {
      rspamd: 24,
      attachment: 1,
      url: 4,
      bec: 0,
      dlp: 2,
      sandbox: 0,
      policy: 3,
      none: 0,
    },
  },
};

export const URL_CLICKS_REPORT_EXAMPLE: UrlClicksReport = {
  from: '2026-11-12T08:00:00.000Z',
  to: '2026-11-12T10:00:00.000Z',
  generatedAt: '2026-11-12T09:30:00.000Z',
  granularity: 'hour',
  buckets: [
    {
      start: '2026-11-12T08:00:00.000Z',
      total: 7,
      decisions: { allowed: 5, warned: 1, blocked: 1, continued: 0, expired: 0, not_found: 0 },
    },
    {
      start: '2026-11-12T09:00:00.000Z',
      total: 3,
      decisions: { allowed: 2, warned: 0, blocked: 0, continued: 1, expired: 0, not_found: 0 },
    },
  ],
  totals: {
    total: 10,
    decisions: { allowed: 7, warned: 1, blocked: 1, continued: 1, expired: 0, not_found: 0 },
  },
};
