import 'server-only';
import { SeededRandom, hashString, stableUuid } from '../generator';
import {
  apiError,
  ok,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import {
  DELIVERY_BOUNDS,
  PROCESSING_BOUNDS,
  orgSlug,
  percentileBound,
  reportInternals,
  withPrincipal,
} from './reports';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the three report operations added for the dashboard (WP1: delivery,
 * processing, top domains). Derived from the same deterministic mail volume as the traffic
 * report (`fixtures/reports.ts`). `charlie` has no completed delivery (success rate null) and
 * slow scans (p95 in the overflow bin); `bravo` has no mail.
 */

const { reportWindow, isResponse, bucketMail, totalOf, generatedAt, iso, DAY } = reportInternals;

const STATUSES = [
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
type Statuses = Record<(typeof STATUSES)[number], number>;
const zeroStatuses = (): Statuses => Object.fromEntries(STATUSES.map((s) => [s, 0])) as Statuses;
const rate = (s: Statuses) => {
  const d = s.delivered + s.bounced + s.failed + s.expired;
  return d === 0 ? null : Math.round((s.delivered / d) * 10_000) / 10_000;
};

function deliveryReport(request: FixtureRequest, organizationId: string): FixtureResponse {
  const w = reportWindow(request);
  if (isResponse(w)) return w;
  const slug = orgSlug(organizationId);
  const totals = zeroStatuses();
  const counts = DELIVERY_BOUNDS.map(() => 0).concat([0]);
  let latencySum = 0;
  const buckets = w.starts.map((s) => {
    const mail = bucketMail(organizationId, s, w.step);
    const deliveries = Math.round((mail.verdicts.clean + mail.verdicts.spam * 0.3) * 1.2);
    const r = new SeededRandom(hashString(`delivery:${organizationId}:${s}`));
    const st = zeroStatuses();
    if (slug === 'charlie') {
      st.deferred = Math.round(deliveries * 0.7);
      st.queued = deliveries - st.deferred;
    } else {
      st.bounced = Math.round((deliveries * r.int(5, 15)) / 1000);
      st.failed = Math.round((deliveries * r.int(0, 5)) / 1000);
      st.deferred = Math.round((deliveries * r.int(0, 10)) / 1000);
      st.suppressed = r.bool(0.2) ? 1 : 0;
      st.delivered = Math.max(0, deliveries - st.bounced - st.failed - st.deferred - st.suppressed);
      for (let i = 0; i < st.delivered; i += 1) {
        const roll = r.next();
        const bin = roll < 0.6 ? 0 : roll < 0.9 ? 1 : roll < 0.97 ? 2 : roll < 0.995 ? 3 : 5;
        counts[bin] = (counts[bin] ?? 0) + 1;
        latencySum += [600, 2500, 7000, 20000, 0, 180000][bin] ?? 0;
      }
    }
    for (const k of STATUSES) totals[k] += st[k];
    return {
      start: iso(s),
      total: STATUSES.reduce((a, k) => a + st[k], 0),
      statuses: st,
      successRate: rate(st),
    };
  });
  const samples = counts.reduce((a, b) => a + b, 0);
  return ok('ReportsController_delivery_v1', {
    from: iso(w.from),
    to: iso(w.to),
    generatedAt: generatedAt(),
    granularity: w.granularity,
    buckets,
    totals: {
      total: STATUSES.reduce((a, k) => a + totals[k], 0),
      statuses: totals,
      successRate: rate(totals),
    },
    latency: {
      delivered: samples,
      averageMs: samples === 0 ? null : Math.round(latencySum / samples),
      p50UpperBoundMs: percentileBound(DELIVERY_BOUNDS, counts, 50),
      p95UpperBoundMs: percentileBound(DELIVERY_BOUNDS, counts, 95),
      histogram: [
        ...DELIVERY_BOUNDS.map((leMs, i) => ({ leMs, count: counts[i] ?? 0 })),
        { leMs: null, count: counts[DELIVERY_BOUNDS.length] ?? 0 },
      ],
    },
  });
}

function processingReport(request: FixtureRequest, organizationId: string): FixtureResponse {
  const w = reportWindow(request);
  if (isResponse(w)) return w;
  const slug = orgSlug(organizationId);
  const totalCounts = PROCESSING_BOUNDS.map(() => 0).concat([0]);
  let sumAll = 0;
  const totals = { pending: 0, running: 0, completed: 0, failed: 0, timed_out: 0 };
  const midpoints = [
    150, 400, 800, 1500, 3500, 7000, 20000, 45000, 90000, 200000, 600000, 1_200_000,
  ];
  const buckets = w.starts.map((s) => {
    const rounds = totalOf(bucketMail(organizationId, s, w.step));
    const r = new SeededRandom(hashString(`scan:${organizationId}:${s}`));
    const statuses = {
      pending: 0,
      running: 0,
      completed: 0,
      failed: r.bool(0.1) ? 1 : 0,
      timed_out: r.bool(0.05) ? 1 : 0,
    };
    statuses.completed = Math.max(0, rounds - statuses.failed - statuses.timed_out);
    const counts = PROCESSING_BOUNDS.map(() => 0).concat([0]);
    let sum = 0;
    for (let i = 0; i < statuses.completed; i += 1) {
      const roll = r.next();
      const bin =
        slug === 'charlie'
          ? roll < 0.9
            ? PROCESSING_BOUNDS.length
            : 9
          : roll < 0.3
            ? 1
            : roll < 0.7
              ? 2
              : roll < 0.93
                ? 3
                : roll < 0.99
                  ? 4
                  : 6;
      counts[bin] = (counts[bin] ?? 0) + 1;
      sum += midpoints[bin] ?? 0;
    }
    counts.forEach((c, i) => (totalCounts[i] = (totalCounts[i] ?? 0) + c));
    sumAll += sum;
    for (const k of Object.keys(totals) as (keyof typeof totals)[]) totals[k] += statuses[k];
    return {
      start: iso(s),
      rounds: statuses.completed + statuses.failed + statuses.timed_out,
      statuses,
      averageMs: statuses.completed === 0 ? null : Math.round(sum / statuses.completed),
      p95UpperBoundMs: percentileBound(PROCESSING_BOUNDS, counts, 95),
    };
  });
  return ok('ReportsController_processing_v1', {
    from: iso(w.from),
    to: iso(w.to),
    generatedAt: generatedAt(),
    granularity: w.granularity,
    buckets,
    totals: {
      rounds: totals.completed + totals.failed + totals.timed_out,
      statuses: totals,
      averageMs: totals.completed === 0 ? null : Math.round(sumAll / totals.completed),
      p50UpperBoundMs: percentileBound(PROCESSING_BOUNDS, totalCounts, 50),
      p95UpperBoundMs: percentileBound(PROCESSING_BOUNDS, totalCounts, 95),
      histogram: [
        ...PROCESSING_BOUNDS.map((leMs, i) => ({ leMs, count: totalCounts[i] ?? 0 })),
        { leMs: null, count: totalCounts[PROCESSING_BOUNDS.length] ?? 0 },
      ],
    },
    definition:
      'Time from receipt (email_scans.received_at) to completion of the initial scan round (completed_at); completed rounds only',
  });
}

const DOMAINS = [
  { name: 'alpha.example.test', share: 0.55, deleted: false },
  { name: 'mail.alpha.example.test', share: 0.2, deleted: false },
  { name: 'alpha-sales.example.test', share: 0.12, deleted: false },
  { name: 'alpha-legacy.example.test', share: 0.06, deleted: true },
  { name: 'alpha-labs.example.test', share: 0.05, deleted: false },
];

function topDomainsReport(request: FixtureRequest, organizationId: string): FixtureResponse {
  const w = reportWindow(request, 'hour');
  if (isResponse(w)) return w;
  const limitRaw = request.query.get('limit');
  const limit = limitRaw === null ? 10 : Number(limitRaw);
  if (!Number.isInteger(limit) || limit < 1 || limit > 25) {
    return apiError(400, 'validation_failed', ['limit: must be an integer from 1 to 25']);
  }
  let inbound = 0;
  const v = { spam: 0, phishing: 0, malware: 0, bec: 0, suspicious: 0 };
  for (let t = Math.floor(w.from / DAY) * DAY; t < w.to; t += DAY) {
    const b = bucketMail(organizationId, t, DAY);
    inbound += b.inbound;
    v.spam += b.verdicts.spam;
    v.phishing += b.verdicts.phishing;
    v.malware += b.verdicts.malware;
    v.bec += b.verdicts.bec;
    v.suspicious += b.verdicts.suspicious;
  }
  const domains = DOMAINS.map((d) => {
    const verdicts = {
      spam: Math.floor(v.spam * d.share),
      phishing: Math.floor(v.phishing * d.share),
      malware: Math.floor(v.malware * d.share),
      bec: Math.floor(v.bec * d.share),
      suspicious: Math.floor(v.suspicious * d.share),
    };
    return {
      domainId: stableUuid(`domain:${organizationId}:${d.name}`),
      name: d.name,
      status: d.deleted ? ('deleted' as const) : ('active' as const),
      deleted: d.deleted,
      inbound: Math.floor(inbound * d.share),
      threats: Object.values(verdicts).reduce((a, b) => a + b, 0),
      verdicts,
    };
  })
    .filter((d) => d.threats > 0)
    .sort((a, b) => b.threats - a.threats || b.inbound - a.inbound || a.name.localeCompare(b.name));
  const attributedInbound = DOMAINS.reduce((a, d) => a + Math.floor(inbound * d.share), 0);
  const threatTotal = v.spam + v.phishing + v.malware + v.bec + v.suspicious;
  const attributedThreats = domains.reduce((a, d) => a + d.threats, 0);
  return ok('ReportsController_topDomains_v1', {
    from: iso(w.from),
    to: iso(w.to),
    generatedAt: generatedAt(),
    threatVerdicts: ['spam', 'phishing', 'malware', 'bec', 'suspicious'],
    domains: domains.slice(0, limit),
    unattributed: {
      inbound: inbound - attributedInbound,
      threats: Math.max(0, threatTotal - attributedThreats),
    },
  });
}

export const fixtures: FixtureHandlers = {
  ReportsController_delivery_v1: (request) =>
    withPrincipal(request, (p) => deliveryReport(request, p.organizationId)),
  ReportsController_processing_v1: (request) =>
    withPrincipal(request, (p) => processingReport(request, p.organizationId)),
  ReportsController_topDomains_v1: (request) =>
    withPrincipal(request, (p) => topDomainsReport(request, p.organizationId)),
};
