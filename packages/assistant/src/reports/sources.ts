import { z } from 'zod';
import { findTool } from '../registry/registry';
import type { PermissionRequirement } from '../registry/types';
import {
  REPORT_RANGES,
  REPORT_SECTIONS,
  type ReportGranularity,
  type ReportRange,
  type ReportSection,
  type ReportWindow,
} from './types';

/**
 * The fixed source plan of `report_generate` (design D2 steps 3–6, D3): which enabled read tools
 * a section needs and with which arguments, the zod parsers of their 200 responses (only the
 * fields the report uses; everything else passes through) and the window helper. The api runs
 * the reads (internal loopback GETs with the user's own token), skips a source whose tool's
 * requirement the principal does not satisfy, and hands the outcomes to `buildReportModel`.
 */

export type ReportSourceKey =
  | 'traffic'
  | 'threats'
  | 'top_domains'
  | 'delivery'
  | 'processing'
  | 'url_clicks'
  | 'quarantine_summary'
  | 'ato_overview'
  | 'ato_accounts'
  | 'api_mode_overview';

// ---------------------------------------------------------------------------------------------
// Parsers (field names from the 200 response schemas of docs/api/openapi.json)
// ---------------------------------------------------------------------------------------------

const count = z.number().int().min(0);
const nullableMs = z.number().min(0).nullable();
const instant = z.string().min(1).max(64);

const VERDICT_KEYS = [
  'clean',
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp_violation',
  'suspicious',
  'unknown',
  'none',
] as const;
export type VerdictKey = (typeof VERDICT_KEYS)[number];
export const REPORT_VERDICTS: readonly VerdictKey[] = VERDICT_KEYS;

/** The top-domains threat set (`threatVerdicts`), also the summary's "threats". */
export const THREAT_VERDICTS = ['spam', 'phishing', 'malware', 'bec', 'suspicious'] as const;
export type ThreatVerdict = (typeof THREAT_VERDICTS)[number];

export const FINAL_ACTIONS = [
  'deliver',
  'tag',
  'quarantine',
  'discard',
  'reject',
  'require_approval',
  'partial',
  'none',
] as const;
export const QUARANTINE_REASONS = [
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp',
  'policy',
  'suspicious',
  'engine_unavailable',
  'manual',
] as const;
export const PRIMARY_ENGINES = [
  'rspamd',
  'attachment',
  'url',
  'bec',
  'dlp',
  'sandbox',
  'policy',
  'none',
] as const;
export const DELIVERY_STATUSES = [
  'pending',
  'in_progress',
  'queued',
  'deferred',
  'delivered',
  'bounced',
  'expired',
  'failed',
  'suppressed',
  'unknown',
] as const;
export const CLICK_DECISIONS = [
  'allowed',
  'warned',
  'blocked',
  'continued',
  'expired',
  'not_found',
] as const;
export const INCIDENT_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;

const countsOf = <const K extends readonly string[]>(keys: K) =>
  z.looseObject(
    Object.fromEntries(keys.map((key) => [key, count])) as Record<K[number], typeof count>,
  );

const verdicts = countsOf(VERDICT_KEYS);
const histogram = z.array(z.looseObject({ leMs: z.number().min(0).nullable(), count })).max(64);
const window = { from: instant, to: instant, generatedAt: instant };

export const trafficResponse = z.looseObject({
  ...window,
  buckets: z
    .array(
      z.looseObject({
        start: instant,
        total: count,
        inbound: count,
        outbound: count,
        internal: count,
        verdicts,
      }),
    )
    .max(2000),
  totals: z.looseObject({
    total: count,
    inbound: count,
    outbound: count,
    internal: count,
    verdicts,
  }),
});

export const threatsResponse = z.looseObject({
  ...window,
  messages: z.looseObject({ total: count, verdicts, actions: countsOf(FINAL_ACTIONS) }),
  outcomes: z
    .array(z.looseObject({ verdict: z.string().max(64), action: z.string().max(64), count }))
    .max(500),
  quarantine: z.looseObject({
    total: count,
    reasons: countsOf(QUARANTINE_REASONS),
    primaryEngines: countsOf(PRIMARY_ENGINES),
  }),
});

export const topDomainsResponse = z.looseObject({
  ...window,
  domains: z
    .array(
      z.looseObject({
        name: z.string().max(1024),
        status: z.string().max(64),
        deleted: z.boolean(),
        inbound: count,
        threats: count,
        verdicts: countsOf(THREAT_VERDICTS),
      }),
    )
    .max(100),
  unattributed: z.looseObject({ inbound: count, threats: count }),
});

export const deliveryResponse = z.looseObject({
  ...window,
  buckets: z
    .array(
      z.looseObject({
        start: instant,
        total: count,
        statuses: countsOf(DELIVERY_STATUSES),
        successRate: z.number().min(0).max(1).nullable(),
      }),
    )
    .max(2000),
  totals: z.looseObject({
    total: count,
    statuses: countsOf(DELIVERY_STATUSES),
    successRate: z.number().min(0).max(1).nullable(),
  }),
  latency: z.looseObject({
    delivered: count,
    averageMs: nullableMs,
    p50UpperBoundMs: nullableMs,
    p95UpperBoundMs: nullableMs,
    histogram,
  }),
});

export const processingResponse = z.looseObject({
  ...window,
  buckets: z
    .array(
      z.looseObject({
        start: instant,
        rounds: count,
        averageMs: nullableMs,
        p95UpperBoundMs: nullableMs,
      }),
    )
    .max(2000),
  totals: z.looseObject({
    rounds: count,
    averageMs: nullableMs,
    p50UpperBoundMs: nullableMs,
    p95UpperBoundMs: nullableMs,
    histogram,
  }),
});

export const urlClicksResponse = z.looseObject({
  ...window,
  buckets: z
    .array(z.looseObject({ start: instant, total: count, decisions: countsOf(CLICK_DECISIONS) }))
    .max(2000),
  totals: z.looseObject({ total: count, decisions: countsOf(CLICK_DECISIONS) }),
});

export const quarantineSummaryResponse = z.looseObject({
  from: instant,
  to: instant,
  counts: z.record(z.string().max(256), count),
  pendingApprovals: count,
});

export const atoOverviewResponse = z.looseObject({
  generatedAt: instant,
  range: z.enum(REPORT_RANGES),
  from: instant,
  to: instant,
  monitoring: z.looseObject({ featureEnabled: z.boolean(), mode: z.string().max(32) }),
  accounts: z.looseObject({ monitored: count, highRisk: count, criticalRisk: count }),
  incidents: z.looseObject({
    active: count,
    trend: z
      .array(
        z.looseObject({
          bucketStart: instant,
          low: count,
          medium: count,
          high: count,
          critical: count,
        }),
      )
      .max(2000),
  }),
  logins: z.looseObject({ suspiciousInRange: count }),
  outbound: z.looseObject({ restrictedAccounts: count }),
  geography: z.looseObject({
    available: z.boolean(),
    topCountries: z
      .array(
        z.looseObject({
          countryCode: z.string().max(256),
          successfulAuth: count,
          newCountrySignals: count,
        }),
      )
      .max(100),
  }),
});

export const atoAccountsResponse = z.looseObject({
  data: z
    .array(
      z.looseObject({
        kind: z.string().max(64),
        address: z.string().max(4096).nullable(),
        displayName: z.string().max(4096).nullable(),
        riskScore: z.number().min(0).max(1000),
        riskLevel: z.string().max(64),
        activeIncident: z
          .looseObject({ severity: z.string().max(64), status: z.string().max(64) })
          .nullable(),
      }),
    )
    .max(100),
});

const health = z.enum(['unknown', 'healthy', 'degraded', 'failing']);

/**
 * Step API-3 C16: `GET /api-mode/overview` (current state; counters of the last 24 hours). Only
 * the fields the `api_mode` section uses; connection names are tenant-authored (capped and
 * escaped by the model and renderer).
 */
export const apiModeOverviewResponse = z.looseObject({
  generatedAt: instant,
  active: z.boolean(),
  coverage: z.looseObject({
    covered: count,
    gap: count,
    total: count.nullable(),
    percent: z.number().min(0).max(100).nullable(),
  }),
  connectionsByHealth: z.looseObject({
    unknown: count,
    healthy: count,
    degraded: count,
    failing: count,
  }),
  lag: z.looseObject({ p95Seconds24h: z.number().min(0).nullable() }),
  throttling: z.looseObject({ events24h: count }),
  remediation: z.looseObject({
    succeeded24h: count,
    failed24h: count,
    restores24h: count,
    throttled24h: count,
  }),
  internal: z.looseObject({ copies24h: count, enabled: z.boolean() }),
  clawback: z.looseObject({
    active: count,
    pendingApproval: count,
    completed24h: count,
    targetsSucceeded24h: count,
    targetsFailed24h: count,
  }),
  reports: z.looseObject({ pendingTriage: count, received24h: count, resolved24h: count }),
  connections: z
    .array(
      z.looseObject({
        displayName: z.string().max(4096),
        provider: z.string().max(64),
        health,
        coverage: z.looseObject({ percent: z.number().min(0).max(100).nullable() }),
        lag: z.looseObject({ p95Seconds24h: z.number().min(0).nullable() }),
      }),
    )
    .max(200),
});

export interface ReportSourceBodies {
  traffic: z.output<typeof trafficResponse>;
  threats: z.output<typeof threatsResponse>;
  top_domains: z.output<typeof topDomainsResponse>;
  delivery: z.output<typeof deliveryResponse>;
  processing: z.output<typeof processingResponse>;
  url_clicks: z.output<typeof urlClicksResponse>;
  quarantine_summary: z.output<typeof quarantineSummaryResponse>;
  ato_overview: z.output<typeof atoOverviewResponse>;
  ato_accounts: z.output<typeof atoAccountsResponse>;
  api_mode_overview: z.output<typeof apiModeOverviewResponse>;
}

// ---------------------------------------------------------------------------------------------
// Source definitions and the per-section plan
// ---------------------------------------------------------------------------------------------

export interface ReportSourceDef<K extends ReportSourceKey = ReportSourceKey> {
  key: K;
  /** Registry name of the enabled read tool (its requirement is the pre-check). */
  tool: string;
  /** Label of the "Sources" footer (the operation summary). */
  label: string;
  /** The tool's arguments for the report window. */
  args: (window: ReportWindow) => Record<string, unknown>;
  parser: z.ZodType<ReportSourceBodies[K]>;
  /**
   * Read only after `ato_overview` succeeded and its monitoring is on (`atoAccountsWanted`);
   * optional for its section (a failure leaves a note, not an omission).
   */
  after?: 'ato_overview';
}

const fromTo = (w: ReportWindow) => ({ from: w.from, to: w.to });
const withGranularity = (w: ReportWindow) => ({ ...fromTo(w), granularity: w.granularity });

export const REPORT_SOURCE_DEFS: { readonly [K in ReportSourceKey]: ReportSourceDef<K> } = {
  traffic: {
    key: 'traffic',
    tool: 'reports_traffic',
    label: 'Traffic report',
    args: withGranularity,
    parser: trafficResponse,
  },
  threats: {
    key: 'threats',
    tool: 'reports_threats',
    label: 'Threat report',
    args: fromTo,
    parser: threatsResponse,
  },
  top_domains: {
    key: 'top_domains',
    tool: 'reports_top_domains',
    label: 'Top attacked domains report',
    args: (w) => ({ ...fromTo(w), limit: 10 }),
    parser: topDomainsResponse,
  },
  delivery: {
    key: 'delivery',
    tool: 'reports_delivery',
    label: 'Delivery report',
    args: withGranularity,
    parser: deliveryResponse,
  },
  processing: {
    key: 'processing',
    tool: 'reports_processing',
    label: 'Processing report',
    args: withGranularity,
    parser: processingResponse,
  },
  url_clicks: {
    key: 'url_clicks',
    tool: 'reports_url_clicks',
    label: 'URL click report',
    args: withGranularity,
    parser: urlClicksResponse,
  },
  quarantine_summary: {
    key: 'quarantine_summary',
    tool: 'quarantine_tools_summary',
    label: 'Quarantine summary',
    args: fromTo,
    parser: quarantineSummaryResponse,
  },
  ato_overview: {
    key: 'ato_overview',
    tool: 'ato_overview_overview',
    label: 'Account takeover overview',
    args: (w) => ({ range: w.atoRange }),
    parser: atoOverviewResponse,
  },
  ato_accounts: {
    key: 'ato_accounts',
    tool: 'ato_accounts_list',
    label: 'Accounts at highest takeover risk',
    // The list's `limit` is a string query parameter (`^\d{1,3}$`).
    args: () => ({ sort: '-riskScore', limit: '10' }),
    parser: atoAccountsResponse,
    after: 'ato_overview',
  },
  // Step API-3 C16: the API-mode overview has no window (current state, counters of 24 hours).
  api_mode_overview: {
    key: 'api_mode_overview',
    tool: 'api_mode_overview',
    label: 'Mailbox protection (API mode) overview',
    args: () => ({}),
    parser: apiModeOverviewResponse,
  },
};

/** Per section, its source tools (design D2 step 4 table); `summary` has no own read. */
export const REPORT_SOURCES: { readonly [S in ReportSection]: readonly ReportSourceKey[] } = {
  summary: [],
  traffic: ['traffic'],
  threats: ['threats'],
  domains: ['top_domains'],
  delivery: ['delivery'],
  processing: ['processing'],
  url_clicks: ['url_clicks'],
  quarantine: ['quarantine_summary'],
  ato: ['ato_overview', 'ato_accounts'],
  api_mode: ['api_mode_overview'],
};

/** Sources whose values the summary cards and figures use (the summary has no own read). */
export const SUMMARY_SOURCES: readonly ReportSourceKey[] = [
  'traffic',
  'threats',
  'delivery',
  'processing',
  'url_clicks',
  'quarantine_summary',
  'ato_overview',
];

/**
 * The sources to read for the requested sections, in a fixed order (`summary` needs the summary
 * sources). `ato_accounts` is listed but read only when `atoAccountsWanted(overview)`.
 */
export function plannedSources(sections: readonly ReportSection[]): ReportSourceDef[] {
  const keys = new Set<ReportSourceKey>();
  for (const section of sections) {
    for (const key of REPORT_SOURCES[section]) keys.add(key);
    if (section === 'summary') for (const key of SUMMARY_SOURCES) keys.add(key);
  }
  const order = Object.keys(REPORT_SOURCE_DEFS) as ReportSourceKey[];
  return order.filter((key) => keys.has(key)).map((key) => REPORT_SOURCE_DEFS[key]);
}

/** The permission requirement of a source (its tool's, the pre-filter predicate's input). */
export function sourceRequirement(def: ReportSourceDef): PermissionRequirement {
  const tool = findTool(def.tool);
  if (!tool) throw new Error(`report source ${def.key}: unknown tool ${def.tool}`);
  return tool.requirement;
}

/**
 * The full loopback path templates (`/api/v1/...`, OpenAPI form) of every source tool of
 * `REPORT_SOURCES`, deduplicated and sorted (step AI-6 D5, I26): the routes a background report
 * job's GET-only access token may call (the api's `ASSISTANT_JOB_ROUTES`). Derived from the
 * registry records, so it follows the source plan; every source tool must be a `GET`.
 */
export function reportJobRoutePaths(): readonly string[] {
  const paths = new Set<string>();
  const keys = new Set<ReportSourceKey>([
    ...Object.values(REPORT_SOURCES).flat(),
    ...SUMMARY_SOURCES,
  ]);
  for (const key of keys) {
    const def = REPORT_SOURCE_DEFS[key];
    const tool = findTool(def.tool);
    if (!tool || tool.native || tool.method !== 'GET')
      throw new Error(`report source ${key}: ${def.tool} is not a GET operation tool`);
    paths.add(tool.pathTemplate);
  }
  return Object.freeze([...paths].sort());
}

/** The permission named in an omission (`permission` reason): the first of the requirement. */
export function sourcePermission(def: ReportSourceDef): string | null {
  const requirement = sourceRequirement(def);
  return requirement.mode === 'authenticated' ? null : (requirement.permissions[0] ?? null);
}

export type SourceParse<K extends ReportSourceKey> =
  { ok: true; data: ReportSourceBodies[K] } | { ok: false };

/** Parses a 2xx body of the source (design D2 step 6); never throws, never echoes the body. */
export function parseSource<K extends ReportSourceKey>(key: K, body: unknown): SourceParse<K> {
  const result = REPORT_SOURCE_DEFS[key].parser.safeParse(body);
  return result.success ? { ok: true, data: result.data } : { ok: false };
}

/** Whether to read the accounts list after the overview (feature on and mode not `off`). */
export function atoAccountsWanted(overview: ReportSourceBodies['ato_overview']): boolean {
  return overview.monitoring.featureEnabled && overview.monitoring.mode !== 'off';
}

// ---------------------------------------------------------------------------------------------
// Window (design D2 step 3)
// ---------------------------------------------------------------------------------------------

export interface ReportWindowArgs {
  range?: unknown;
  from?: unknown;
  to?: unknown;
}

export type ReportWindowResult =
  | { ok: true; window: ReportWindow }
  | { ok: false; code: 'assistant_report_invalid_window'; message: string };

const HOUR_MS = 3_600_000;
const RANGE_MS: Readonly<Record<ReportRange, number>> = {
  '24h': 24 * HOUR_MS,
  '7d': 7 * 24 * HOUR_MS,
  '30d': 30 * 24 * HOUR_MS,
};
/** Windows up to this length use hourly buckets. */
export const HOURLY_MAX_MS = 48 * HOUR_MS;
/** How far `to` may lie in the future (clock skew). */
export const FUTURE_SKEW_MS = 60_000;
export const DEFAULT_REPORT_RANGE: ReportRange = '7d';

const granularityOf = (ms: number): ReportGranularity => (ms <= HOURLY_MAX_MS ? 'hour' : 'day');

/** The smallest of `24h | 7d | 30d` that covers the window (30d for longer ones). */
export function atoRangeFor(durationMs: number): ReportRange {
  return REPORT_RANGES.find((range) => durationMs <= RANGE_MS[range]) ?? '30d';
}

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/;

const invalid = (message: string): ReportWindowResult => ({
  ok: false,
  code: 'assistant_report_invalid_window',
  message,
});

/**
 * The report window: a relative `range` (default `7d`) ending at the current minute, or an
 * explicit `from`/`to` (both; `from < to`; at most `maxRangeDays`; `to ≤ now + 1 min`), which
 * replaces the range. Hourly buckets up to 48 hours, else daily.
 */
export function resolveReportWindow(
  args: ReportWindowArgs,
  options: { now: Date; maxRangeDays: number },
): ReportWindowResult {
  const now = options.now.getTime();
  if (!Number.isFinite(now)) return invalid('The current time is not valid.');
  const hasFrom = args.from !== undefined && args.from !== null;
  const hasTo = args.to !== undefined && args.to !== null;
  if (hasFrom || hasTo) {
    if (!hasFrom || !hasTo) return invalid('Give both from and to, or neither.');
    if (typeof args.from !== 'string' || typeof args.to !== 'string')
      return invalid('from and to must be ISO 8601 date-times.');
    if (!ISO.test(args.from) || !ISO.test(args.to))
      return invalid('from and to must be ISO 8601 date-times.');
    const from = Date.parse(args.from);
    const to = Date.parse(args.to);
    if (!Number.isFinite(from) || !Number.isFinite(to))
      return invalid('from and to must be ISO 8601 date-times.');
    if (from >= to) return invalid('from must be before to.');
    if (to > now + FUTURE_SKEW_MS) return invalid('to must not be in the future.');
    if (to - from > options.maxRangeDays * 24 * HOUR_MS)
      return invalid(`The window may span at most ${options.maxRangeDays} days.`);
    return {
      ok: true,
      window: {
        from: new Date(from).toISOString(),
        to: new Date(to).toISOString(),
        granularity: granularityOf(to - from),
        range: null,
        atoRange: atoRangeFor(to - from),
      },
    };
  }
  const range = args.range === undefined || args.range === null ? DEFAULT_REPORT_RANGE : args.range;
  if (typeof range !== 'string' || !(REPORT_RANGES as readonly string[]).includes(range))
    return invalid('range must be one of 24h, 7d, 30d.');
  const r = range as ReportRange;
  const to = Math.floor(now / 60_000) * 60_000;
  return {
    ok: true,
    window: {
      from: new Date(to - RANGE_MS[r]).toISOString(),
      to: new Date(to).toISOString(),
      granularity: granularityOf(RANGE_MS[r]),
      range: r,
      atoRange: r,
    },
  };
}

/** The requested sections in render order (default all; unknown values dropped). */
export function normalizeSections(value: unknown): ReportSection[] {
  if (!Array.isArray(value) || value.length === 0) return [...REPORT_SECTIONS];
  const wanted = new Set(value.filter((v): v is string => typeof v === 'string'));
  const sections = REPORT_SECTIONS.filter((section) => wanted.has(section));
  return sections.length > 0 ? sections : [...REPORT_SECTIONS];
}
