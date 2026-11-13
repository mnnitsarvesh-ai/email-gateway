import 'server-only';
import type { SuccessBody } from '@/lib/api/types';
import { canPerform } from '@/lib/auth/permissions';
import { SeededRandom, fixtureAnchor, hashString } from '../generator';
import {
  apiError,
  ok,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import { CUSTOMER_ORGS, resolveFixturePrincipal } from './session';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the reports (WP3, design P9): every report is computed deterministically
 * from the organization and the bucket start, so the dashboard tiles, the reports page and the
 * CSV agree. Synthetic only. Edge states by organization (start an override to see them):
 * `bravo` has no mail at all (zero buckets, success rate null, no latency samples), `charlie`
 * has no completed delivery and its time to verdict falls into the overflow bin.
 */

export type Principal = NonNullable<ReturnType<typeof resolveFixturePrincipal>>;

/** The caller (401 without a session) and the api's permission check (403) of the operation. */
export function withPrincipal(
  request: FixtureRequest,
  fn: (principal: Principal) => FixtureResponse,
): FixtureResponse {
  const principal = resolveFixturePrincipal(request.token);
  if (!principal) return apiError(401, 'unauthorized', 'Unauthorized');
  if (!canPerform(request.operationId, principal.permissions)) {
    return apiError(403, 'forbidden', 'Forbidden');
  }
  return fn(principal);
}

export function bodyOf(request: FixtureRequest): Record<string, unknown> {
  return request.body && typeof request.body === 'object' && !Array.isArray(request.body)
    ? (request.body as Record<string, unknown>)
    : {};
}

/** A string field of a request body (`fallback` when absent or not a string). */
export function str(body: Record<string, unknown>, key: string, fallback = ''): string {
  const value = body[key];
  return typeof value === 'string' ? value : fallback;
}

export function orgSlug(organizationId: string): string {
  return CUSTOMER_ORGS.find((o) => o.id === organizationId)?.slug ?? 'platform';
}

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const iso = (ms: number) => new Date(ms).toISOString();

interface Window {
  from: number;
  to: number;
  granularity: 'hour' | 'day';
  step: number;
  starts: number[];
}

/** Window rules of the traffic report: defaults, alignment, `hour` ≤ 7 days, ≤ 31 days. */
function reportWindow(
  request: FixtureRequest,
  aligned: 'bucket' | 'hour' = 'bucket',
): Window | FixtureResponse {
  const q = request.query;
  const granularity = q.get('granularity') === 'hour' ? 'hour' : 'day';
  const step = aligned === 'hour' || granularity === 'hour' ? HOUR : DAY;
  const now = fixtureAnchor() + HOUR;
  const toRaw = q.get('to') ? Date.parse(q.get('to') ?? '') : now;
  const defaultSpan = granularity === 'hour' && aligned === 'bucket' ? DAY : 7 * DAY;
  const fromRaw = q.get('from') ? Date.parse(q.get('from') ?? '') : toRaw - defaultSpan;
  if (!Number.isFinite(fromRaw) || !Number.isFinite(toRaw)) {
    return apiError(400, 'validation_failed', ['from: must be an ISO 8601 date-time']);
  }
  const from = Math.floor(fromRaw / step) * step;
  const to = Math.ceil(toRaw / step) * step;
  if (to <= from) return apiError(400, 'validation_failed', ['from: must be before to']);
  if (granularity === 'hour' && aligned === 'bucket' && to - from > 7 * DAY) {
    return apiError(400, 'validation_failed', ['granularity: hour buckets allow at most 7 days']);
  }
  if (to - from > 31 * DAY + step) {
    return apiError(400, 'validation_failed', [
      'from: the range is longer than REPORTS_MAX_RANGE_DAYS (31)',
    ]);
  }
  const bucketStep = granularity === 'hour' ? HOUR : DAY;
  const starts: number[] = [];
  for (let t = Math.floor(from / bucketStep) * bucketStep; t < to; t += bucketStep) starts.push(t);
  return { from, to, granularity, step: bucketStep, starts };
}

const isResponse = (value: Window | FixtureResponse): value is FixtureResponse => 'status' in value;

/** Messages of one bucket of an organization (deterministic). */
interface BucketMail {
  inbound: number;
  outbound: number;
  internal: number;
  verdicts: Record<(typeof VERDICTS)[number], number>;
}
const VERDICTS = [
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

function bucketMail(organizationId: string, start: number, step: number): BucketMail {
  const slug = orgSlug(organizationId);
  const zero = Object.fromEntries(VERDICTS.map((v) => [v, 0])) as BucketMail['verdicts'];
  if (slug === 'bravo') return { inbound: 0, outbound: 0, internal: 0, verdicts: zero };
  // Hourly units summed per bucket so day buckets equal the sum of their hours.
  const out: BucketMail = { inbound: 0, outbound: 0, internal: 0, verdicts: { ...zero } };
  for (let t = start; t < start + step; t += HOUR) {
    const r = new SeededRandom(hashString(`${organizationId}:${t}`));
    const hour = new Date(t).getUTCHours();
    const busy = hour >= 7 && hour <= 19 ? 1 : 0.35;
    const inbound = Math.round(r.int(25, 60) * busy);
    const outbound = Math.round(r.int(5, 20) * busy);
    const internal = Math.round(r.int(1, 6) * busy);
    out.inbound += inbound;
    out.outbound += outbound;
    out.internal += internal;
    const total = inbound + outbound + internal;
    const spam = Math.round((inbound * r.int(4, 10)) / 100);
    const bulk = Math.round((inbound * r.int(1, 4)) / 100);
    const phishing = r.bool(0.4) ? r.int(0, 3) : 0;
    const malware = r.bool(0.15) ? 1 : 0;
    const bec = r.bool(0.05) ? 1 : 0;
    const dlp = r.bool(0.1) ? r.int(0, 1) : 0;
    const suspicious = r.bool(0.3) ? 1 : 0;
    const none = r.bool(0.05) ? 1 : 0;
    const used = spam + bulk + phishing + malware + bec + dlp + suspicious + none;
    out.verdicts.spam += spam;
    out.verdicts.bulk += bulk;
    out.verdicts.phishing += phishing;
    out.verdicts.malware += malware;
    out.verdicts.bec += bec;
    out.verdicts.dlp_violation += dlp;
    out.verdicts.suspicious += suspicious;
    out.verdicts.none += none;
    out.verdicts.clean += Math.max(0, total - used);
  }
  return out;
}

function sumMail(organizationId: string, w: Window): BucketMail {
  const total: BucketMail = {
    inbound: 0,
    outbound: 0,
    internal: 0,
    verdicts: Object.fromEntries(VERDICTS.map((v) => [v, 0])) as BucketMail['verdicts'],
  };
  for (const s of w.starts) {
    const b = bucketMail(organizationId, s, w.step);
    total.inbound += b.inbound;
    total.outbound += b.outbound;
    total.internal += b.internal;
    for (const v of VERDICTS) total.verdicts[v] += b.verdicts[v];
  }
  return total;
}

const totalOf = (b: BucketMail) => b.inbound + b.outbound + b.internal;
const generatedAt = () => iso(fixtureAnchor() + 5 * 60_000);

export function trafficReport(request: FixtureRequest, organizationId: string): FixtureResponse {
  const w = reportWindow(request);
  if (isResponse(w)) return w;
  const direction = request.query.get('direction') as 'inbound' | 'outbound' | 'internal' | null;
  const shape = (b: BucketMail) => {
    if (!direction)
      return {
        total: totalOf(b),
        inbound: b.inbound,
        outbound: b.outbound,
        internal: b.internal,
        verdicts: b.verdicts,
      };
    const count = b[direction];
    const ratio = totalOf(b) === 0 ? 0 : count / totalOf(b);
    const verdicts = Object.fromEntries(
      VERDICTS.map((v) => [v, Math.round(b.verdicts[v] * ratio)]),
    ) as BucketMail['verdicts'];
    const sum = VERDICTS.reduce((a, v) => a + verdicts[v], 0);
    verdicts.clean += count - sum;
    if (verdicts.clean < 0) verdicts.clean = 0;
    return {
      total: VERDICTS.reduce((a, v) => a + verdicts[v], 0),
      inbound: direction === 'inbound' ? count : 0,
      outbound: direction === 'outbound' ? count : 0,
      internal: direction === 'internal' ? count : 0,
      verdicts,
    };
  };
  const buckets = w.starts.map((s) => ({
    start: iso(s),
    ...shape(bucketMail(organizationId, s, w.step)),
  }));
  const totals = buckets.reduce(
    (acc, b) => {
      acc.total += b.total;
      acc.inbound += b.inbound;
      acc.outbound += b.outbound;
      acc.internal += b.internal;
      for (const v of VERDICTS) acc.verdicts[v] += b.verdicts[v];
      return acc;
    },
    {
      total: 0,
      inbound: 0,
      outbound: 0,
      internal: 0,
      verdicts: Object.fromEntries(VERDICTS.map((v) => [v, 0])) as BucketMail['verdicts'],
    },
  );
  return ok('ReportsController_traffic_v1', {
    from: iso(w.from),
    to: iso(w.to),
    generatedAt: generatedAt(),
    granularity: w.granularity,
    direction,
    buckets,
    totals,
  });
}

type Outcome = SuccessBody<'ReportsController_threats_v1'>['outcomes'][number];

const spamQuarantined = (spam: number) => Math.round(spam * 0.6);

/** Final action per verdict (fixed split so outcomes add up to the marginals). */
function outcomesOf(v: BucketMail['verdicts']): Outcome[] {
  const pairs: Outcome[] = [];
  const add = (verdict: Outcome['verdict'], action: Outcome['action'], count: number) => {
    if (count > 0) pairs.push({ verdict, action, count });
  };
  add('clean', 'deliver', v.clean);
  const spamQ = spamQuarantined(v.spam);
  const spamD = Math.round(v.spam * 0.1);
  add('spam', 'quarantine', spamQ);
  add('spam', 'discard', spamD);
  add('spam', 'tag', v.spam - spamQ - spamD);
  add('bulk', 'tag', Math.ceil(v.bulk / 2));
  add('bulk', 'reject', Math.floor(v.bulk / 2));
  add('phishing', 'quarantine', v.phishing);
  add('malware', 'reject', v.malware);
  add('bec', 'require_approval', v.bec);
  add('dlp_violation', 'quarantine', v.dlp_violation);
  add('suspicious', 'tag', v.suspicious);
  add('unknown', 'deliver', v.unknown);
  add('none', 'none', v.none);
  return pairs.sort(
    (a, b) =>
      b.count - a.count || a.verdict.localeCompare(b.verdict) || a.action.localeCompare(b.action),
  );
}

export function threatsReport(request: FixtureRequest, organizationId: string): FixtureResponse {
  const w = reportWindow(request, 'hour');
  if (isResponse(w)) return w;
  const days: Window = { ...w, step: DAY, starts: [] };
  for (let t = Math.floor(w.from / DAY) * DAY; t < w.to; t += DAY) days.starts.push(t);
  const m = sumMail(organizationId, days);
  const outcomes = outcomesOf(m.verdicts);
  const actions = {
    deliver: 0,
    tag: 0,
    quarantine: 0,
    discard: 0,
    reject: 0,
    require_approval: 0,
    partial: 0,
    none: 0,
  };
  for (const o of outcomes) actions[o.action] += o.count;
  // Quarantine entries are per recipient (about 1.3 recipients per quarantined spam message).
  const spamEntries = Math.round(spamQuarantined(m.verdicts.spam) * 1.3);
  const entries = spamEntries + m.verdicts.phishing + m.verdicts.dlp_violation;
  return ok('ReportsController_threats_v1', {
    from: iso(w.from),
    to: iso(w.to),
    generatedAt: generatedAt(),
    messages: { total: totalOf(m), verdicts: m.verdicts, actions },
    outcomes,
    quarantine: {
      total: entries,
      reasons: {
        spam: spamEntries,
        bulk: 0,
        phishing: m.verdicts.phishing,
        malware: 0,
        bec: 0,
        dlp: m.verdicts.dlp_violation,
        policy: 0,
        suspicious: 0,
        engine_unavailable: 0,
        manual: 0,
      },
      primaryEngines: {
        rspamd: spamEntries,
        attachment: 0,
        url: m.verdicts.phishing,
        bec: 0,
        dlp: m.verdicts.dlp_violation,
        sandbox: 0,
        policy: 0,
        none: 0,
      },
    },
  });
}

export function urlClicksReport(request: FixtureRequest, organizationId: string): FixtureResponse {
  const w = reportWindow(request);
  if (isResponse(w)) return w;
  const zero = { allowed: 0, warned: 0, blocked: 0, continued: 0, expired: 0, not_found: 0 };
  const buckets = w.starts.map((s) => {
    if (orgSlug(organizationId) === 'bravo')
      return { start: iso(s), total: 0, decisions: { ...zero } };
    const r = new SeededRandom(hashString(`clicks:${organizationId}:${s}`));
    const scale = w.granularity === 'day' ? 24 : 1;
    const decisions = {
      allowed: r.int(0, 6) * scale,
      warned: r.int(0, 2) * Math.ceil(scale / 4),
      blocked: r.int(0, 1) * Math.ceil(scale / 6),
      continued: r.bool(0.2) ? 1 : 0,
      expired: r.bool(0.1) ? 1 : 0,
      not_found: 0,
    };
    return { start: iso(s), total: Object.values(decisions).reduce((a, b) => a + b, 0), decisions };
  });
  const totals = { total: 0, decisions: { ...zero } };
  for (const b of buckets) {
    totals.total += b.total;
    for (const k of Object.keys(zero) as (keyof typeof zero)[])
      totals.decisions[k] += b.decisions[k];
  }
  return ok('ReportsController_urlClicks_v1', {
    from: iso(w.from),
    to: iso(w.to),
    generatedAt: generatedAt(),
    granularity: w.granularity,
    buckets,
    totals,
  });
}

export const DELIVERY_BOUNDS = [
  1000, 5000, 10000, 30000, 60000, 300000, 900000, 3600000, 14400000, 86400000,
];
export const PROCESSING_BOUNDS = [
  250, 500, 1000, 2000, 5000, 10000, 30000, 60000, 120000, 300000, 900000,
];

/** `pXX` upper bound from per-bin counts (§3.3.1): `null` without samples or in the overflow. */
export function percentileBound(
  bounds: readonly number[],
  counts: readonly number[],
  p: number,
): number | null {
  const total = counts.reduce((a, b) => a + b, 0);
  if (total === 0) return null;
  let cumulative = 0;
  for (let i = 0; i < bounds.length; i += 1) {
    cumulative += counts[i] ?? 0;
    if (cumulative >= (p / 100) * total) return bounds[i] ?? null;
  }
  return null;
}

export const fixtures: FixtureHandlers = {
  ReportsController_traffic_v1: (request) =>
    withPrincipal(request, (p) => trafficReport(request, p.organizationId)),
  ReportsController_threats_v1: (request) =>
    withPrincipal(request, (p) => threatsReport(request, p.organizationId)),
  ReportsController_urlClicks_v1: (request) =>
    withPrincipal(request, (p) => urlClicksReport(request, p.organizationId)),
};

/** Shared with the dashboard fixtures (delivery, processing and top domains). */
export const reportInternals = {
  reportWindow,
  isResponse,
  bucketMail,
  sumMail,
  totalOf,
  generatedAt,
  iso,
  HOUR,
  DAY,
};
