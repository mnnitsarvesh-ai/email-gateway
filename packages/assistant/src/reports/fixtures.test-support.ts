import type { ReportSourceResults } from './model';
import type { ReportSourceKey } from './sources';
import type { ReportWindow } from './types';

/**
 * Synthetic report fixtures (tests only; excluded from the build): 200 bodies of the nine source
 * operations shaped like the response schemas and examples of `docs/api/openapi.json`
 * (`ReportsController_*_v1`, `QuarantineToolsController_summary_v1`,
 * `AtoOverviewController_overview_v1`, `AtoAccountsController_list_v1`), with `.test` names only.
 */

export const FIXTURE_NOW = new Date('2026-11-23T09:00:30.000Z');
export const FIXTURE_GENERATED_AT = '2026-11-23T09:00:31.000Z';
export const FIXTURE_ORGANIZATION = 'Example Test Org';

export const WINDOW_7D: ReportWindow = {
  from: '2026-11-16T09:00:00.000Z',
  to: '2026-11-23T09:00:00.000Z',
  granularity: 'day',
  range: '7d',
  atoRange: '7d',
};

export const WINDOW_24H: ReportWindow = {
  from: '2026-11-22T09:00:00.000Z',
  to: '2026-11-23T09:00:00.000Z',
  granularity: 'hour',
  range: '24h',
  atoRange: '24h',
};

const DAY = 86_400_000;
const days = (n: number, start = '2026-11-16T00:00:00.000Z') =>
  Array.from({ length: n }, (_, i) => new Date(Date.parse(start) + i * DAY).toISOString());

const verdicts = (i: number) => ({
  clean: 1100 + i * 10,
  spam: 40 + i,
  bulk: 12,
  phishing: 3 + (i % 2),
  malware: i % 3 === 0 ? 1 : 0,
  bec: i === 4 ? 1 : 0,
  dlp_violation: 2,
  suspicious: 5,
  unknown: 0,
  none: 4,
});

const sumBy = <T>(rows: readonly T[], pick: (row: T) => number) =>
  rows.reduce((total, row) => total + pick(row), 0);

export function trafficBody(buckets = days(8)) {
  const rows = buckets.map((start, i) => {
    const v = verdicts(i);
    const total = sumBy(Object.values(v), (n) => n);
    return { start, total, inbound: total - 240, outbound: 220, internal: 20, verdicts: v };
  });
  const keys = Object.keys(verdicts(0)) as Array<keyof ReturnType<typeof verdicts>>;
  return {
    from: '2026-11-16T00:00:00.000Z',
    to: '2026-11-23T09:00:00.000Z',
    generatedAt: '2026-11-23T09:00:01.000Z',
    granularity: 'day',
    direction: null,
    buckets: rows,
    totals: {
      total: sumBy(rows, (r) => r.total),
      inbound: sumBy(rows, (r) => r.inbound),
      outbound: sumBy(rows, (r) => r.outbound),
      internal: sumBy(rows, (r) => r.internal),
      verdicts: Object.fromEntries(keys.map((k) => [k, sumBy(rows, (r) => r.verdicts[k])])),
    },
  };
}

export function threatsBody() {
  return {
    from: '2026-11-16T09:00:00.000Z',
    to: '2026-11-23T09:00:00.000Z',
    generatedAt: '2026-11-23T09:00:01.000Z',
    messages: {
      total: 9000,
      verdicts: {
        clean: 8600,
        spam: 300,
        bulk: 40,
        phishing: 25,
        malware: 6,
        bec: 2,
        dlp_violation: 9,
        suspicious: 18,
        unknown: 0,
        none: 0,
      },
      actions: {
        deliver: 8650,
        tag: 120,
        quarantine: 200,
        discard: 5,
        reject: 20,
        require_approval: 3,
        partial: 2,
        none: 0,
      },
    },
    outcomes: [
      { verdict: 'clean', action: 'deliver', count: 8600 },
      { verdict: 'spam', action: 'tag', count: 120 },
      { verdict: 'spam', action: 'quarantine', count: 180 },
      { verdict: 'phishing', action: 'quarantine', count: 20 },
      { verdict: 'phishing', action: 'reject', count: 5 },
      { verdict: 'malware', action: 'reject', count: 6 },
    ],
    quarantine: {
      total: 200,
      reasons: {
        spam: 150,
        bulk: 10,
        phishing: 20,
        malware: 6,
        bec: 2,
        dlp: 3,
        policy: 5,
        suspicious: 4,
        engine_unavailable: 0,
        manual: 0,
      },
      primaryEngines: {
        rspamd: 160,
        attachment: 6,
        url: 20,
        bec: 2,
        dlp: 3,
        sandbox: 0,
        policy: 5,
        none: 4,
      },
    },
  };
}

export function topDomainsBody(names = ['alpha.example.test', 'beta.example.test']) {
  return {
    from: '2026-11-16T09:00:00.000Z',
    to: '2026-11-23T09:00:00.000Z',
    generatedAt: '2026-11-23T09:00:01.000Z',
    threatVerdicts: ['spam', 'phishing', 'malware', 'bec', 'suspicious'],
    domains: names.map((name, i) => ({
      domainId: `01930c2e-7d1a-7000-8000-00000000d00${i + 1}`,
      name,
      status: i === 1 ? 'deleted' : 'active',
      deleted: i === 1,
      inbound: 800 - i * 300,
      threats: 37 - i * 20,
      verdicts: { spam: 30 - i * 20, phishing: 3, malware: 1, bec: 0, suspicious: 3 },
    })),
    unattributed: { inbound: 4, threats: 1 },
  };
}

const statuses = (delivered: number) => ({
  pending: 0,
  in_progress: 1,
  queued: 2,
  deferred: 3,
  delivered,
  bounced: 4,
  expired: 0,
  failed: 1,
  suppressed: 0,
  unknown: 0,
});

export function deliveryBody(buckets = days(8)) {
  const rows = buckets.map((start, i) => {
    const s = statuses(300 + i);
    const total = sumBy(Object.values(s), (n) => n);
    return { start, total, statuses: s, successRate: (300 + i) / total };
  });
  const totals = statuses(sumBy(rows, (r) => r.statuses.delivered));
  const total = sumBy(Object.values(totals), (n) => n) + 11 * 7;
  return {
    from: '2026-11-16T00:00:00.000Z',
    to: '2026-11-23T09:00:00.000Z',
    generatedAt: '2026-11-23T09:00:01.000Z',
    granularity: 'day',
    buckets: rows,
    totals: { total, statuses: totals, successRate: 0.9856 },
    latency: {
      delivered: totals.delivered,
      averageMs: 1830,
      p50UpperBoundMs: 1000,
      p95UpperBoundMs: 5000,
      histogram: [
        { leMs: 250, count: 400 },
        { leMs: 1000, count: 1500 },
        { leMs: 5000, count: 500 },
        { leMs: 60_000, count: 30 },
        { leMs: null, count: 2 },
      ],
    },
  };
}

export function processingBody(buckets = days(8)) {
  return {
    from: '2026-11-16T00:00:00.000Z',
    to: '2026-11-23T09:00:00.000Z',
    generatedAt: '2026-11-23T09:00:01.000Z',
    granularity: 'day',
    buckets: buckets.map((start, i) => ({
      start,
      rounds: 1200 + i,
      statuses: { pending: 0, running: 0, completed: 1200 + i, failed: 0, timed_out: 0 },
      averageMs: i === 3 ? null : 800 + i * 10,
      p95UpperBoundMs: i === 3 ? null : 2500,
    })),
    totals: {
      rounds: 9628,
      statuses: { pending: 0, running: 0, completed: 9628, failed: 0, timed_out: 0 },
      averageMs: 830,
      p50UpperBoundMs: 1000,
      p95UpperBoundMs: 2500,
      histogram: [
        { leMs: 500, count: 3000 },
        { leMs: 1000, count: 5000 },
        { leMs: 2500, count: 1400 },
        { leMs: null, count: 228 },
      ],
    },
    definition:
      'Time from receipt (email_scans.received_at) to completion of the initial scan round (completed_at); completed rounds only',
  };
}

const decisions = (i: number) => ({
  allowed: 40 + i,
  warned: 3,
  blocked: 2 + (i % 2),
  continued: 1,
  expired: 0,
  not_found: 0,
});

export function urlClicksBody(buckets = days(8)) {
  const rows = buckets.map((start, i) => {
    const d = decisions(i);
    return { start, total: sumBy(Object.values(d), (n) => n), decisions: d };
  });
  const keys = Object.keys(decisions(0)) as Array<keyof ReturnType<typeof decisions>>;
  return {
    from: '2026-11-16T00:00:00.000Z',
    to: '2026-11-23T09:00:00.000Z',
    generatedAt: '2026-11-23T09:00:01.000Z',
    granularity: 'day',
    buckets: rows,
    totals: {
      total: sumBy(rows, (r) => r.total),
      decisions: Object.fromEntries(keys.map((k) => [k, sumBy(rows, (r) => r.decisions[k])])),
    },
  };
}

export function quarantineSummaryBody() {
  return {
    from: '2026-11-16T09:00:00.000Z',
    to: '2026-11-23T09:00:00.000Z',
    counts: { held: 42, pending_approval: 3, released: 120, rejected: 20, expired: 15 },
    pendingApprovals: 3,
  };
}

export function atoOverviewBody(
  options: { featureEnabled?: boolean; mode?: string; range?: string; countries?: string[] } = {},
) {
  return {
    generatedAt: '2026-11-23T09:00:01.000Z',
    range: options.range ?? '7d',
    from: '2026-11-16T09:00:00.000Z',
    to: '2026-11-23T09:00:00.000Z',
    monitoring: {
      featureEnabled: options.featureEnabled ?? true,
      mode: options.mode ?? 'monitor',
      learning: false,
      learningEndsAt: null,
    },
    accounts: {
      monitored: 250,
      byKind: { mailbox: 240, gateway_user: 8, smtp_connector: 2 },
      highRisk: 4,
      criticalRisk: 1,
    },
    incidents: {
      active: 2,
      activeBySeverity: { low: 0, medium: 1, high: 1, critical: 0 },
      critical: 0,
      openedInRange: 5,
      trend: days(7, '2026-11-17T00:00:00.000Z').map((bucketStart, i) => ({
        bucketStart,
        low: i % 2,
        medium: i === 2 ? 2 : 0,
        high: i === 5 ? 1 : 0,
        critical: 0,
      })),
      resolvedInRange: { remediated: 2, falsePositive: 1, other: 0 },
    },
    logins: { failedInRange: 30, suspiciousInRange: 6 },
    outbound: { suspiciousInRange: 2, restrictedAccounts: 1, policyHeldInRange: 0 },
    geography: {
      available: true,
      reason: null,
      topCountries: (options.countries ?? ['IN', 'US', 'GB']).map((countryCode, i) => ({
        countryCode,
        successfulAuth: 900 - i * 300,
        newCountrySignals: i,
      })),
      impossibleTravelInRange: 0,
    },
    responses: { pendingApproval: 0, executedInRange: 1, failedInRange: 0 },
    attention: { criticalIncidents: 0, pendingApprovals: 0 },
  };
}

export function atoAccountsBody(
  accounts: Array<{ address: string | null; displayName: string | null }> = [
    { address: 'ada.admin@alpha.example.test', displayName: 'Ada Admin' },
    { address: 'bob.ops@alpha.example.test', displayName: 'Bob Ops' },
    { address: null, displayName: 'Relay connector' },
  ],
) {
  return {
    data: accounts.map((a, i) => ({
      id: `0193aaaa-0000-7000-8000-0000000000a${i}`,
      kind: a.address ? 'mailbox' : 'smtp_connector',
      address: a.address,
      displayName: a.displayName,
      domainId: null,
      status: 'active',
      riskScore: 92 - i * 15,
      riskLevel: i === 0 ? 'critical' : 'high',
      riskUpdatedAt: '2026-11-23T08:00:00.000Z',
      lastSignalAt: '2026-11-23T07:00:00.000Z',
      firstSeenAt: '2026-10-01T00:00:00.000Z',
      lastSeenAt: '2026-11-23T07:00:00.000Z',
      protected: false,
      activeIncident:
        i === 0
          ? { id: '0193aaaa-0000-7000-8000-0000000000b0', severity: 'high', status: 'open' }
          : null,
      override: null,
    })),
    nextCursor: null,
  };
}

/** Step API-3 C16: `GET /api-mode/overview` (synthetic; one connection). */
export function apiModeOverviewBody(connections = 1) {
  return {
    generatedAt: FIXTURE_GENERATED_AT,
    entitled: true,
    active: true,
    organizationMode: 'api',
    coverage: { covered: 118, gap: 2, total: 120, percent: 98.3 },
    connectionsByHealth: { unknown: 0, healthy: connections, degraded: 0, failing: 0 },
    lag: { p50Seconds1h: 60, p95Seconds1h: 300, p50Seconds24h: 60, p95Seconds24h: 900 },
    throttling: { events1h: 0, events24h: 3 },
    copiesToday: 412,
    remediation: {
      succeeded24h: 14,
      failed24h: 1,
      restores24h: 1,
      throttled24h: 0,
      skipped24h: 3,
    },
    internal: { copies24h: 37, enabled: true },
    clawback: {
      active: 1,
      reviewRequired: 0,
      pendingApproval: 1,
      completed24h: 2,
      targetsSucceeded24h: 64,
      targetsFailed24h: 1,
      oldestActiveAgeSeconds: 1800,
    },
    reports: {
      pendingTriage: 3,
      inReview: 1,
      received24h: 9,
      resolved24h: 5,
      oldestPendingAgeSeconds: 5400,
      reportMailboxes: 1,
    },
    connections: Array.from({ length: connections }, (_, i) => ({
      id: `0193bbbb-0000-7000-8000-${String(i + 1).padStart(12, '0')}`,
      displayName: i === 0 ? 'Example <Test> M365' : `Connection ${i + 1}`,
      provider: 'microsoft_365',
      health: 'healthy',
      coverage: { covered: 118, gap: 2, total: 120, percent: 98.3 },
      lag: { p50Seconds1h: 60, p95Seconds1h: 300, p50Seconds24h: 60, p95Seconds24h: 900 },
    })),
  };
}

/** Every source answered with its fixture body (200). */
export function okResults(
  overrides: Partial<Record<ReportSourceKey, unknown>> = {},
): ReportSourceResults {
  const bodies: Record<ReportSourceKey, unknown> = {
    traffic: trafficBody(),
    threats: threatsBody(),
    top_domains: topDomainsBody(),
    delivery: deliveryBody(),
    processing: processingBody(),
    url_clicks: urlClicksBody(),
    quarantine_summary: quarantineSummaryBody(),
    ato_overview: atoOverviewBody(),
    ato_accounts: atoAccountsBody(),
    api_mode_overview: apiModeOverviewBody(),
    ...overrides,
  };
  return Object.fromEntries(
    Object.entries(bodies).map(([key, body]) => [key, { status: 'ok', httpStatus: 200, body }]),
  );
}
