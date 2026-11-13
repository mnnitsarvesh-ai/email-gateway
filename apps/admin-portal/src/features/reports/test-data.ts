/**
 * Report bodies for component tests (synthetic, typed against the OpenAPI snapshot). Only test
 * files import this module.
 */
import type {
  DeliveryReport,
  ProcessingReport,
  ThreatsReport,
  TopDomainsReport,
  TrafficReport,
  UrlClicksReport,
} from './report-utils';

export const T_FROM = '2026-11-06T00:00:00.000Z';
export const T_TO = '2026-11-08T00:00:00.000Z';
export const T_GENERATED = '2026-11-08T00:00:05.000Z';

const verdicts = (over: Partial<TrafficReport['totals']['verdicts']> = {}) => ({
  clean: 0,
  spam: 0,
  bulk: 0,
  phishing: 0,
  malware: 0,
  bec: 0,
  dlp_violation: 0,
  suspicious: 0,
  unknown: 0,
  none: 0,
  ...over,
});

export function trafficReport(over: Partial<TrafficReport> = {}): TrafficReport {
  return {
    from: T_FROM,
    to: T_TO,
    generatedAt: T_GENERATED,
    granularity: 'day',
    direction: null,
    buckets: [
      {
        start: '2026-11-06T00:00:00.000Z',
        total: 700,
        inbound: 500,
        outbound: 150,
        internal: 50,
        verdicts: verdicts({
          clean: 600,
          spam: 60,
          bulk: 10,
          phishing: 20,
          malware: 5,
          bec: 3,
          suspicious: 2,
        }),
      },
      {
        start: '2026-11-07T00:00:00.000Z',
        total: 534,
        inbound: 400,
        outbound: 100,
        internal: 34,
        verdicts: verdicts({
          clean: 480,
          spam: 30,
          phishing: 8,
          malware: 4,
          dlp_violation: 6,
          none: 6,
        }),
      },
    ],
    totals: {
      total: 1234,
      inbound: 900,
      outbound: 250,
      internal: 84,
      verdicts: verdicts({
        clean: 1080,
        spam: 90,
        bulk: 10,
        phishing: 28,
        malware: 9,
        bec: 3,
        dlp_violation: 6,
        suspicious: 2,
        none: 6,
      }),
    },
    ...over,
  };
}

export function emptyTrafficReport(): TrafficReport {
  const zero = { total: 0, inbound: 0, outbound: 0, internal: 0, verdicts: verdicts() };
  return trafficReport({
    buckets: [{ start: '2026-11-06T00:00:00.000Z', ...zero }],
    totals: zero,
  });
}

export function threatsReport(over: Partial<ThreatsReport> = {}): ThreatsReport {
  return {
    from: T_FROM,
    to: T_TO,
    generatedAt: T_GENERATED,
    messages: {
      total: 1234,
      verdicts: verdicts({
        clean: 1080,
        spam: 90,
        bulk: 10,
        phishing: 28,
        malware: 9,
        bec: 3,
        dlp_violation: 6,
        suspicious: 2,
        none: 6,
      }),
      actions: {
        deliver: 1100,
        tag: 40,
        quarantine: 57,
        discard: 12,
        reject: 9,
        require_approval: 4,
        partial: 6,
        none: 6,
      },
    },
    // Spam blocked = 30 + 12 + 5 + 7 = 54 (spam|bulk × quarantine|discard|reject); the
    // spam→tag and bulk→deliver pairs and phishing→quarantine must not count.
    outcomes: [
      { verdict: 'clean', action: 'deliver', count: 1080 },
      { verdict: 'spam', action: 'tag', count: 40 },
      { verdict: 'spam', action: 'quarantine', count: 30 },
      { verdict: 'phishing', action: 'quarantine', count: 27 },
      { verdict: 'spam', action: 'discard', count: 12 },
      { verdict: 'bulk', action: 'reject', count: 5 },
      { verdict: 'bulk', action: 'deliver', count: 5 },
      { verdict: 'spam', action: 'reject', count: 7 },
      { verdict: 'none', action: 'none', count: 6 },
    ],
    quarantine: {
      total: 71,
      reasons: {
        spam: 30,
        bulk: 0,
        phishing: 27,
        malware: 9,
        bec: 3,
        dlp: 2,
        policy: 0,
        suspicious: 0,
        engine_unavailable: 0,
        manual: 0,
      },
      primaryEngines: {
        rspamd: 30,
        attachment: 9,
        url: 27,
        bec: 3,
        dlp: 2,
        sandbox: 0,
        policy: 0,
        none: 0,
      },
    },
    ...over,
  };
}

const statuses = (over: Partial<DeliveryReport['totals']['statuses']> = {}) => ({
  pending: 0,
  in_progress: 0,
  queued: 0,
  deferred: 0,
  delivered: 0,
  bounced: 0,
  expired: 0,
  failed: 0,
  suppressed: 0,
  unknown: 0,
  ...over,
});

export const DELIVERY_BOUNDS = [
  1000, 5000, 10000, 30000, 60000, 300000, 900000, 3600000, 14400000, 86400000,
];
export const PROCESSING_BOUNDS = [
  250, 500, 1000, 2000, 5000, 10000, 30000, 60000, 120000, 300000, 900000,
];

export function histogram(
  bounds: readonly number[],
  counts: Partial<Record<number | 'overflow', number>>,
) {
  return [
    ...bounds.map((leMs) => ({ leMs, count: counts[leMs] ?? 0 })),
    { leMs: null, count: counts.overflow ?? 0 },
  ];
}

export function deliveryReport(over: Partial<DeliveryReport> = {}): DeliveryReport {
  return {
    from: T_FROM,
    to: T_TO,
    generatedAt: T_GENERATED,
    granularity: 'day',
    buckets: [
      {
        start: '2026-11-06T00:00:00.000Z',
        total: 520,
        statuses: statuses({ delivered: 500, bounced: 10, deferred: 10 }),
        successRate: 0.9804,
      },
      {
        start: '2026-11-07T00:00:00.000Z',
        total: 400,
        statuses: statuses({ delivered: 390, failed: 5, queued: 5 }),
        successRate: 0.9873,
      },
    ],
    totals: {
      total: 920,
      statuses: statuses({ delivered: 890, bounced: 10, failed: 5, deferred: 10, queued: 5 }),
      successRate: 0.9835,
    },
    latency: {
      delivered: 890,
      averageMs: 2400,
      p50UpperBoundMs: 1000,
      p95UpperBoundMs: 5000,
      histogram: histogram(DELIVERY_BOUNDS, { 1000: 600, 5000: 270, 10000: 20 }),
    },
    ...over,
  };
}

export function processingReport(over: Partial<ProcessingReport> = {}): ProcessingReport {
  return {
    from: T_FROM,
    to: T_TO,
    generatedAt: T_GENERATED,
    granularity: 'day',
    buckets: [
      {
        start: '2026-11-06T00:00:00.000Z',
        rounds: 700,
        statuses: { pending: 0, running: 0, completed: 698, failed: 1, timed_out: 1 },
        averageMs: 1800,
        p95UpperBoundMs: 5000,
      },
      {
        start: '2026-11-07T00:00:00.000Z',
        rounds: 534,
        statuses: { pending: 2, running: 1, completed: 531, failed: 0, timed_out: 0 },
        averageMs: 1600,
        p95UpperBoundMs: 2000,
      },
    ],
    totals: {
      rounds: 1234,
      statuses: { pending: 2, running: 1, completed: 1229, failed: 1, timed_out: 1 },
      averageMs: 1712,
      p50UpperBoundMs: 1000,
      p95UpperBoundMs: 5000,
      histogram: histogram(PROCESSING_BOUNDS, { 500: 300, 1000: 400, 2000: 400, 5000: 129 }),
    },
    definition:
      'Time from receipt (email_scans.received_at) to completion of the initial scan round (completed_at); completed rounds only',
    ...over,
  };
}

export function topDomainsReport(over: Partial<TopDomainsReport> = {}): TopDomainsReport {
  return {
    from: T_FROM,
    to: T_TO,
    generatedAt: T_GENERATED,
    threatVerdicts: ['spam', 'phishing', 'malware', 'bec', 'suspicious'],
    domains: [
      {
        domainId: '01930000-0000-7000-8000-00000000d001',
        name: 'alpha.example.test',
        status: 'active',
        deleted: false,
        inbound: 812,
        threats: 37,
        verdicts: { spam: 30, phishing: 3, malware: 1, bec: 0, suspicious: 3 },
      },
      {
        domainId: '01930000-0000-7000-8000-00000000d002',
        name: 'old.example.test',
        status: 'deleted',
        deleted: true,
        inbound: 40,
        threats: 5,
        verdicts: { spam: 5, phishing: 0, malware: 0, bec: 0, suspicious: 0 },
      },
    ],
    unattributed: { inbound: 4, threats: 1 },
    ...over,
  };
}

export function urlClicksReport(over: Partial<UrlClicksReport> = {}): UrlClicksReport {
  const decisions = (o: Partial<UrlClicksReport['totals']['decisions']> = {}) => ({
    allowed: 0,
    warned: 0,
    blocked: 0,
    continued: 0,
    expired: 0,
    not_found: 0,
    ...o,
  });
  return {
    from: T_FROM,
    to: T_TO,
    generatedAt: T_GENERATED,
    granularity: 'day',
    buckets: [
      {
        start: '2026-11-06T00:00:00.000Z',
        total: 30,
        decisions: decisions({ allowed: 25, warned: 3, blocked: 2 }),
      },
      {
        start: '2026-11-07T00:00:00.000Z',
        total: 12,
        decisions: decisions({ allowed: 10, blocked: 1, continued: 1 }),
      },
    ],
    totals: {
      total: 42,
      decisions: decisions({ allowed: 35, warned: 3, blocked: 3, continued: 1 }),
    },
    ...over,
  };
}
