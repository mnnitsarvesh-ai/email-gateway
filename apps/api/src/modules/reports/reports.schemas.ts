import { z } from 'zod';
import {
  DELIVERY_LATENCY_BOUNDS_MS,
  PROCESSING_LATENCY_BOUNDS_MS,
} from './domain/latency-histogram';
import { REPORT_GRANULARITIES } from './domain/report-window';
import {
  THREAT_VERDICTS,
  TOP_DOMAINS_DEFAULT_LIMIT,
  TOP_DOMAINS_MAX_LIMIT,
} from './domain/top-domains';
import {
  DELIVERY_STATUSES,
  DOMAIN_STATUSES,
  MESSAGE_ACTIONS,
  MESSAGE_DIRECTIONS,
  MESSAGE_VERDICTS,
  QUARANTINE_PRIMARY_ENGINES,
  QUARANTINE_REASONS,
  SCAN_STATUSES,
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

const granularity = z
  .enum(REPORT_GRANULARITIES)
  .optional()
  .describe('Bucket size: `hour` (range ≤ 7 days, default last 24 h) or `day` (default)');

export const DeliveryReportQuerySchema = z.strictObject({ ...range, granularity });
export type DeliveryReportQuery = z.output<typeof DeliveryReportQuerySchema>;

export const ProcessingReportQuerySchema = z.strictObject({ ...range, granularity });
export type ProcessingReportQuery = z.output<typeof ProcessingReportQuerySchema>;

export const TopDomainsReportQuerySchema = z.strictObject({
  ...range,
  limit: z.coerce
    .number()
    .int()
    .min(1)
    .max(TOP_DOMAINS_MAX_LIMIT)
    .optional()
    .describe(
      `Most domains listed (1–${TOP_DOMAINS_MAX_LIMIT}, default ${TOP_DOMAINS_DEFAULT_LIMIT})`,
    ),
});
export type TopDomainsReportQuery = z.output<typeof TopDomainsReportQuerySchema>;

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
  outcomes: z
    .array(
      z.object({
        verdict: z.enum(VERDICT_KEYS),
        action: z.enum(ACTION_KEYS),
        count: z.number().int().positive(),
      }),
    )
    .describe(
      'Messages by final verdict × final action (`none` = not decided yet): the non-zero pairs, ' +
        'ordered by count (descending), then verdict and action (alphabetical)',
    ),
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

const count = z.number().int().nonnegative();
const nullableMs = z.number().int().nonnegative().nullable();
const rate = z
  .number()
  .min(0)
  .max(1)
  .nullable()
  .describe(
    'delivered ÷ (delivered + bounced + failed + expired), 4 decimals; `null` when none of ' +
      'those final states occurred',
  );

const histogram = (bounds: readonly number[]) =>
  z
    .array(z.object({ leMs: z.number().int().positive().nullable(), count }))
    .describe(
      `Samples per latency bucket (not cumulative): \`leMs\` is the inclusive upper bound ` +
        `(${bounds.join(', ')} ms); \`leMs: null\` counts the samples above the last bound`,
    );

const upperBound = (p: number) =>
  nullableMs.describe(
    `Smallest histogram bound that ${p} % of the samples do not exceed (an upper bound, not an ` +
      'estimate); `null` without samples or when it lies above the last bound',
  );

const average = nullableMs.describe(
  'Mean latency in milliseconds (rounded); `null` without samples',
);

const DeliveryCountsSchema = z.object({
  total: count.describe('Deliveries (one per recipient delivery chain)'),
  statuses: counts(DELIVERY_STATUSES),
  successRate: rate,
});

export const DeliveryReportSchema = z.object({
  ...windowFields,
  granularity: z.enum(REPORT_GRANULARITIES),
  buckets: z.array(DeliveryCountsSchema.extend({ start: z.iso.datetime() })),
  totals: DeliveryCountsSchema,
  latency: z
    .object({
      delivered: count.describe('Delivered deliveries with a delivery time (the samples)'),
      averageMs: average,
      p50UpperBoundMs: upperBound(50),
      p95UpperBoundMs: upperBound(95),
      histogram: histogram(DELIVERY_LATENCY_BOUNDS_MS),
    })
    .describe('Delivery latency: `delivered_at − received_at` of delivered deliveries'),
});
export type DeliveryReport = z.output<typeof DeliveryReportSchema>;

export const PROCESSING_DEFINITION =
  'Time from receipt (email_scans.received_at) to completion of the initial scan round ' +
  '(completed_at); completed rounds only';

const roundCounts = {
  rounds: count.describe('Initial scan rounds'),
  statuses: counts(SCAN_STATUSES),
  averageMs: average,
};

export const ProcessingReportSchema = z.object({
  ...windowFields,
  granularity: z.enum(REPORT_GRANULARITIES),
  buckets: z.array(
    z.object({ start: z.iso.datetime(), ...roundCounts, p95UpperBoundMs: upperBound(95) }),
  ),
  totals: z.object({
    ...roundCounts,
    p50UpperBoundMs: upperBound(50),
    p95UpperBoundMs: upperBound(95),
    histogram: histogram(PROCESSING_LATENCY_BOUNDS_MS),
  }),
  definition: z.literal(PROCESSING_DEFINITION),
});
export type ProcessingReport = z.output<typeof ProcessingReportSchema>;

const threatCounts = counts(THREAT_VERDICTS);

export const TopDomainsReportSchema = z.object({
  ...windowFields,
  threatVerdicts: z
    .array(z.enum(THREAT_VERDICTS))
    .describe('The final verdicts counted as threats'),
  domains: z
    .array(
      z.object({
        domainId: z.uuid().describe('Public domain id'),
        name: z.string(),
        status: z.enum(DOMAIN_STATUSES),
        deleted: z.boolean().describe('The domain was deleted after the messages arrived'),
        inbound: count.describe('Inbound messages of the domain in the window'),
        threats: z.number().int().positive().describe('Inbound messages with a threat verdict'),
        verdicts: threatCounts,
      }),
    )
    .describe('Domains with threats, ordered by threats, inbound (descending), then name'),
  unattributed: z
    .object({ inbound: count, threats: count })
    .describe('Inbound messages without a tenant domain'),
});
export type TopDomainsReport = z.output<typeof TopDomainsReportSchema>;

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
  // Consistent with the marginals above (Σ = 1248).
  outcomes: [
    { verdict: 'clean', action: 'deliver', count: 1180 },
    { verdict: 'spam', action: 'quarantine', count: 25 },
    { verdict: 'spam', action: 'tag', count: 15 },
    { verdict: 'bulk', action: 'deliver', count: 5 },
    { verdict: 'bulk', action: 'tag', count: 5 },
    { verdict: 'suspicious', action: 'deliver', count: 5 },
    { verdict: 'none', action: 'none', count: 4 },
    { verdict: 'phishing', action: 'quarantine', count: 3 },
    { verdict: 'bulk', action: 'quarantine', count: 2 },
    { verdict: 'dlp_violation', action: 'reject', count: 2 },
    { verdict: 'malware', action: 'require_approval', count: 1 },
    { verdict: 'spam', action: 'partial', count: 1 },
  ],
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

// Step 7.1 §3.3: numbers consistent with each other (sums, rates and bounds as computed).

export const DELIVERY_REPORT_EXAMPLE: DeliveryReport = {
  from: '2026-11-10T00:00:00.000Z',
  to: '2026-11-12T00:00:00.000Z',
  generatedAt: '2026-11-12T09:30:00.000Z',
  granularity: 'day',
  buckets: [
    {
      start: '2026-11-10T00:00:00.000Z',
      total: 1040,
      statuses: {
        pending: 0,
        in_progress: 2,
        queued: 4,
        deferred: 10,
        delivered: 1000,
        bounced: 12,
        expired: 1,
        failed: 3,
        suppressed: 8,
        unknown: 0,
      },
      successRate: 0.9843,
    },
    {
      start: '2026-11-11T00:00:00.000Z',
      total: 520,
      statuses: {
        pending: 1,
        in_progress: 3,
        queued: 2,
        deferred: 6,
        delivered: 500,
        bounced: 5,
        expired: 0,
        failed: 0,
        suppressed: 3,
        unknown: 0,
      },
      successRate: 0.9901,
    },
  ],
  totals: {
    total: 1560,
    statuses: {
      pending: 1,
      in_progress: 5,
      queued: 6,
      deferred: 16,
      delivered: 1500,
      bounced: 17,
      expired: 1,
      failed: 3,
      suppressed: 11,
      unknown: 0,
    },
    successRate: 0.9862,
  },
  latency: {
    delivered: 1500,
    averageMs: 4210,
    p50UpperBoundMs: 1000,
    p95UpperBoundMs: 30000,
    histogram: [
      { leMs: 1000, count: 900 },
      { leMs: 5000, count: 420 },
      { leMs: 10000, count: 100 },
      { leMs: 30000, count: 40 },
      { leMs: 60000, count: 20 },
      { leMs: 300000, count: 12 },
      { leMs: 900000, count: 5 },
      { leMs: 3600000, count: 2 },
      { leMs: 14400000, count: 1 },
      { leMs: 86400000, count: 0 },
      { leMs: null, count: 0 },
    ],
  },
};

export const PROCESSING_REPORT_EXAMPLE: ProcessingReport = {
  from: '2026-11-12T08:00:00.000Z',
  to: '2026-11-12T10:00:00.000Z',
  generatedAt: '2026-11-12T09:30:00.000Z',
  granularity: 'hour',
  buckets: [
    {
      start: '2026-11-12T08:00:00.000Z',
      rounds: 120,
      statuses: { pending: 0, running: 1, completed: 117, failed: 1, timed_out: 1 },
      averageMs: 1830,
      p95UpperBoundMs: 5000,
    },
    {
      start: '2026-11-12T09:00:00.000Z',
      rounds: 80,
      statuses: { pending: 1, running: 0, completed: 79, failed: 0, timed_out: 0 },
      averageMs: 1620,
      p95UpperBoundMs: 5000,
    },
  ],
  totals: {
    rounds: 200,
    statuses: { pending: 1, running: 1, completed: 196, failed: 1, timed_out: 1 },
    averageMs: 1745,
    p50UpperBoundMs: 1000,
    p95UpperBoundMs: 5000,
    histogram: [
      { leMs: 250, count: 20 },
      { leMs: 500, count: 40 },
      { leMs: 1000, count: 60 },
      { leMs: 2000, count: 40 },
      { leMs: 5000, count: 28 },
      { leMs: 10000, count: 6 },
      { leMs: 30000, count: 2 },
      { leMs: 60000, count: 0 },
      { leMs: 120000, count: 0 },
      { leMs: 300000, count: 0 },
      { leMs: 900000, count: 0 },
      { leMs: null, count: 0 },
    ],
  },
  definition: PROCESSING_DEFINITION,
};

export const TOP_DOMAINS_REPORT_EXAMPLE: TopDomainsReport = {
  from: '2026-11-05T09:00:00.000Z',
  to: '2026-11-12T10:00:00.000Z',
  generatedAt: '2026-11-12T09:30:00.000Z',
  threatVerdicts: [...THREAT_VERDICTS],
  domains: [
    {
      domainId: '01930c2e-7d1a-7000-8000-00000000d001',
      name: 'alpha.example.test',
      status: 'active',
      deleted: false,
      inbound: 812,
      threats: 37,
      verdicts: { spam: 30, phishing: 3, malware: 1, bec: 0, suspicious: 3 },
    },
    {
      domainId: '01930c2e-7d1a-7000-8000-00000000d002',
      name: 'beta.example.test',
      status: 'deleted',
      deleted: true,
      inbound: 198,
      threats: 11,
      verdicts: { spam: 9, phishing: 0, malware: 0, bec: 0, suspicious: 2 },
    },
  ],
  unattributed: { inbound: 4, threats: 1 },
};
