import { describe, expect, it } from 'vitest';
import {
  API_MODE_HEALTH_CHECK_CODES,
  apiModeHealthDocumentSchema,
  evaluateApiModeHealth,
  evaluateClawbackHealth,
  evaluateReportsHealth,
  type ApiModeClawbackHealthInput,
  type ApiModeHealthInput,
  type ApiModeReportsHealthInput,
} from './health';

// Step API-3 (note 37 C13): `clawback.stalled` and `reports.backlog` of `api-mode-health/1`.
const HEALTH_CFG = {
  coverageWarnPercent: 95,
  coverageFailPercent: 50,
  lagWarnSeconds: 900,
  lagFailSeconds: 3600,
  throttleWarnPerHour: 20,
};

const healthy = (extra: Partial<ApiModeHealthInput> = {}): ApiModeHealthInput => ({
  connection: { active: true, bound: true },
  journal: { verifiedSource: true, sourceHealth: 'healthy' },
  grantStatus: 'active',
  feeds: { enabled: false, feedMailboxes: 0, activeMailboxes: 0, errorMailboxes: 0 },
  coverage: { inventoryOk: true, inScopeMailboxes: 10, covered: 10, gap: 0 },
  lagP95SecondsLastHour: 60,
  throttleEventsLastHour: 0,
  apiModeDomainsWithGatewayMx: 0,
  ...extra,
});

const clawback = (oldestActiveAgeSeconds: number | null): ApiModeClawbackHealthInput => ({
  oldestActiveAgeSeconds,
  thresholds: { stalledWarnMinutes: 60, stalledFailMinutes: 240 },
});
const reports = (
  overrides: Partial<ApiModeReportsHealthInput> = {},
): ApiModeReportsHealthInput => ({
  hasReportMailbox: true,
  oldestPendingTriageAgeSeconds: null,
  thresholds: { triageWarnHours: 24 },
  ...overrides,
});
const remediation = {
  succeeded1h: 0,
  failed1h: 0,
  oldestPendingAgeSeconds: null,
  enforceWithoutGrant: false,
  paused: false,
  thresholds: {
    failureWarnPercent: 10,
    failureFailPercent: 50,
    backlogWarnMinutes: 15,
    backlogFailMinutes: 60,
  },
};

describe('clawback and report health checks (C13)', () => {
  it('appends the two codes (15 of 16; API-4 adds the 16th) and evaluates every check in code order', () => {
    expect(API_MODE_HEALTH_CHECK_CODES).toHaveLength(16);
    expect(API_MODE_HEALTH_CHECK_CODES.slice(13, 15)).toEqual([
      'clawback.stalled',
      'reports.backlog',
    ]);
    const result = evaluateApiModeHealth(
      healthy({
        remediation,
        clawback: clawback(null),
        reports: reports(),
        policy: { evaluations1h: 0, errors1h: 0 },
      }),
      HEALTH_CFG,
    );
    expect(result.status).toBe('healthy');
    expect(result.checks.map((c) => c.code)).toEqual([...API_MODE_HEALTH_CHECK_CODES]);
    expect(apiModeHealthDocumentSchema.parse(result.document)).toEqual(result.document);
  });

  it('omits each check without its block (API-1/API-2 callers unchanged)', () => {
    const none = evaluateApiModeHealth(healthy({ remediation }), HEALTH_CFG);
    expect(none.checks.map((c) => c.code)).not.toContain('clawback.stalled');
    expect(none.checks.map((c) => c.code)).not.toContain('reports.backlog');
    const onlyReports = evaluateApiModeHealth(healthy({ reports: reports() }), HEALTH_CFG);
    expect(onlyReports.checks.at(-1)?.code).toBe('reports.backlog');
    expect(onlyReports.checks.map((c) => c.code)).not.toContain('clawback.stalled');
  });

  it.each([
    [null, 'pass'],
    [0, 'pass'],
    [3600, 'pass'],
    [3601, 'warn'],
    [240 * 60, 'warn'],
    [240 * 60 + 1, 'fail'],
    [-5, 'pass'],
  ])('clawback.stalled: oldest active %s s → %s', (age, status) => {
    expect(evaluateClawbackHealth(clawback(age)).status).toBe(status);
  });

  it.each([
    [false, 999_999, 'pass'],
    [true, null, 'pass'],
    [true, 24 * 3600, 'pass'],
    [true, 24 * 3600 + 1, 'warn'],
    [true, 30 * 86_400, 'warn'], // never fail
  ])('reports.backlog: mailbox %s, oldest %s s → %s', (hasReportMailbox, age, status) => {
    expect(
      evaluateReportsHealth(reports({ hasReportMailbox, oldestPendingTriageAgeSeconds: age }))
        .status,
    ).toBe(status);
  });

  it('a stalled clawback fails the connection; a report backlog degrades it', () => {
    const failing = evaluateApiModeHealth(healthy({ clawback: clawback(5 * 3600) }), HEALTH_CFG);
    expect(failing.status).toBe('failing');
    expect(failing.failingChecks).toEqual(['clawback.stalled']);
    const degraded = evaluateApiModeHealth(
      healthy({ reports: reports({ oldestPendingTriageAgeSeconds: 2 * 86_400 }) }),
      HEALTH_CFG,
    );
    expect(degraded.status).toBe('degraded');
    expect(degraded.failingChecks).toEqual(['reports.backlog']);
  });

  it('keeps evidence to counts and ages (no address or subject)', () => {
    const checks = [
      evaluateClawbackHealth(clawback(1e15)),
      evaluateReportsHealth(reports({ oldestPendingTriageAgeSeconds: 1e15 })),
      evaluateReportsHealth(reports({ hasReportMailbox: false })),
    ];
    for (const c of checks) {
      expect((c.evidence ?? '').length).toBeLessThanOrEqual(512);
      expect(c.evidence).not.toMatch(/@/);
    }
    expect(checks[0]?.evidence).toBe('oldest queued or running clawback 1000000000000000 s old');
  });
});
