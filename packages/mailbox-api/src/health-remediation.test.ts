import { describe, expect, it } from 'vitest';
import {
  API_MODE_HEALTH_CHECK_CODES,
  apiModeHealthDocumentSchema,
  evaluateApiModeHealth,
  evaluateRemediationHealth,
  REMEDIATION_FAILURE_MIN_ATTEMPTS,
  type ApiModeHealthInput,
  type ApiModeRemediationHealthInput,
} from './health';

// Step API-2 (note 36 R14): the four remediation checks of `api-mode-health/1`.
const HEALTH_CFG = {
  coverageWarnPercent: 95,
  coverageFailPercent: 50,
  lagWarnSeconds: 900,
  lagFailSeconds: 3600,
  throttleWarnPerHour: 20,
};

const remediation = (
  overrides: Partial<ApiModeRemediationHealthInput> = {},
): ApiModeRemediationHealthInput => ({
  succeeded1h: 20,
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
  ...overrides,
});

const healthy = (extra: Partial<ApiModeHealthInput> = {}): ApiModeHealthInput => ({
  connection: { active: true, bound: true },
  journal: { verifiedSource: true, sourceHealth: 'healthy' },
  grantStatus: 'active',
  feeds: { enabled: true, feedMailboxes: 10, activeMailboxes: 10, errorMailboxes: 0 },
  coverage: { inventoryOk: true, inScopeMailboxes: 10, covered: 10, gap: 0 },
  lagP95SecondsLastHour: 60,
  throttleEventsLastHour: 0,
  apiModeDomainsWithGatewayMx: 0,
  ...extra,
});

const statusOf = (input: ApiModeRemediationHealthInput, code: string) =>
  evaluateRemediationHealth(input).find((c) => c.code === code)?.status;

describe('remediation health checks (R14)', () => {
  it('appends the four codes and evaluates them in order when the block is given', () => {
    expect(API_MODE_HEALTH_CHECK_CODES.slice(9, 13)).toEqual([
      'remediation.failures_1h',
      'remediation.backlog',
      'remediation.access',
      'remediation.paused',
    ]);
    const result = evaluateApiModeHealth(healthy({ remediation: remediation() }), HEALTH_CFG);
    expect(result.status).toBe('healthy');
    // Step API-3 appends clawback.stalled and reports.backlog (only with their own blocks).
    expect(result.checks.map((c) => c.code)).toEqual(API_MODE_HEALTH_CHECK_CODES.slice(0, 13));
    expect(apiModeHealthDocumentSchema.parse(result.document)).toEqual(result.document);
    expect(result.document.checks.length).toBeLessThanOrEqual(16);
  });

  it('skips the checks without the block (API-1 callers unchanged)', () => {
    const result = evaluateApiModeHealth(healthy(), HEALTH_CFG);
    expect(result.checks.some((c) => c.code.startsWith('remediation.'))).toBe(false);
  });

  it.each([
    // succeeded, failed, expected status (warn > 10 %, fail > 50 %, ≥ 5 attempts)
    [0, 0, 'pass'],
    [0, 4, 'pass'], // 4 attempts: below the minimum, not rated
    [0, REMEDIATION_FAILURE_MIN_ATTEMPTS, 'fail'],
    [9, 1, 'pass'], // exactly 10 %
    [8, 1, 'warn'], // 11.1 %
    [5, 5, 'warn'], // exactly 50 %
    [4, 5, 'fail'], // 55.6 %
  ])('failures_1h: %i succeeded, %i failed → %s', (succeeded1h, failed1h, status) => {
    expect(statusOf(remediation({ succeeded1h, failed1h }), 'remediation.failures_1h')).toBe(
      status,
    );
  });

  it.each([
    [null, 'pass'],
    [0, 'pass'],
    [15 * 60, 'pass'],
    [15 * 60 + 1, 'warn'],
    [60 * 60, 'warn'],
    [60 * 60 + 1, 'fail'],
  ])('backlog: oldest pending %s s → %s', (oldestPendingAgeSeconds, status) => {
    expect(statusOf(remediation({ oldestPendingAgeSeconds }), 'remediation.backlog')).toBe(status);
  });

  it('access and paused warn', () => {
    expect(statusOf(remediation({ enforceWithoutGrant: true }), 'remediation.access')).toBe('warn');
    expect(statusOf(remediation(), 'remediation.access')).toBe('pass');
    expect(statusOf(remediation({ paused: true }), 'remediation.paused')).toBe('warn');
    expect(statusOf(remediation(), 'remediation.paused')).toBe('pass');
  });

  it('a failing remediation check fails the connection and is listed in failingChecks', () => {
    const result = evaluateApiModeHealth(
      healthy({
        remediation: remediation({ succeeded1h: 1, failed1h: 9, paused: true }),
      }),
      HEALTH_CFG,
    );
    expect(result.status).toBe('failing');
    expect(result.failingChecks).toEqual(['remediation.failures_1h', 'remediation.paused']);
    const degraded = evaluateApiModeHealth(
      healthy({ remediation: remediation({ oldestPendingAgeSeconds: 1200 }) }),
      HEALTH_CFG,
    );
    expect(degraded.status).toBe('degraded');
  });

  it('keeps evidence non-secret and ≤ 512 characters', () => {
    const checks = evaluateRemediationHealth(
      remediation({
        succeeded1h: 1e12,
        failed1h: 1e12,
        oldestPendingAgeSeconds: 1e15,
        enforceWithoutGrant: true,
        paused: true,
      }),
    );
    for (const c of checks) {
      expect((c.evidence ?? '').length).toBeLessThanOrEqual(512);
      expect(c.evidence).not.toMatch(/@|token|Bearer/i);
    }
    expect(checks.find((c) => c.code === 'remediation.failures_1h')?.evidence).toBe(
      '50% of 2000000000000 remediations failed in the last hour (1000000000000 failed)',
    );
  });
});
