import { describe, expect, it } from 'vitest';
import { coveragePercent, evaluateMailboxCoverage, type MailboxCoverageInput } from './coverage';
import {
  API_MODE_HEALTH_CHECK_CODES,
  apiModeHealthDocumentSchema,
  evaluateApiModeHealth,
  type ApiModeHealthInput,
} from './health';

const NOW = new Date('2026-11-10T12:00:00.000Z');
const ago = (seconds: number) => new Date(NOW.getTime() - seconds * 1000);
const CFG = { feedPollIntervalSeconds: 300, journalCoverageDays: 7 };

const mailbox = (patch: Partial<MailboxCoverageInput> = {}): MailboxCoverageInput => ({
  status: 'active',
  domainEffectiveMode: 'api',
  feedStatus: 'off',
  lastSyncAt: null,
  journalLastSeenAt: null,
  ...patch,
});

describe('evaluateMailboxCoverage (D11.2)', () => {
  it.each([
    ['inline domain', { domainEffectiveMode: 'inline' as const }, 'out_of_scope'],
    ['unknown domain', { domainEffectiveMode: null }, 'out_of_scope'],
    ['disabled', { status: 'disabled' as const, journalLastSeenAt: ago(10) }, 'out_of_scope'],
    ['deleted', { status: 'deleted' as const }, 'out_of_scope'],
    ['nothing seen', {}, 'gap'],
    [
      'feed active, synced 899 s ago',
      { feedStatus: 'active' as const, lastSyncAt: ago(899) },
      'covered',
    ],
    [
      'feed active, synced exactly 3 × 300 s ago',
      { feedStatus: 'active' as const, lastSyncAt: ago(900) },
      'covered',
    ],
    [
      'feed active, synced 901 s ago',
      { feedStatus: 'active' as const, lastSyncAt: ago(901) },
      'gap',
    ],
    ['feed in error but fresh sync', { feedStatus: 'error' as const, lastSyncAt: ago(10) }, 'gap'],
    ['journal 7 days ago', { journalLastSeenAt: ago(7 * 86_400) }, 'covered'],
    ['journal 7 days + 1 s ago', { journalLastSeenAt: ago(7 * 86_400 + 1) }, 'gap'],
    [
      'hybrid with journal',
      { domainEffectiveMode: 'hybrid' as const, journalLastSeenAt: ago(60) },
      'covered',
    ],
    [
      'discovered with journal',
      { status: 'discovered' as const, journalLastSeenAt: ago(60) },
      'covered',
    ],
  ])('%s → %s', (_name, patch, expected) => {
    expect(evaluateMailboxCoverage(mailbox(patch), NOW, CFG)).toBe(expected);
  });

  it('uses the poll interval it is given (notify mode: the safety poll)', () => {
    const input = mailbox({ feedStatus: 'active', lastSyncAt: ago(3 * 3600) });
    expect(evaluateMailboxCoverage(input, NOW, CFG)).toBe('gap');
    expect(evaluateMailboxCoverage(input, NOW, { ...CFG, feedPollIntervalSeconds: 3600 })).toBe(
      'covered',
    );
  });

  it('computes the coverage percent', () => {
    expect(coveragePercent({ covered: 0, gap: 0 })).toBeNull();
    expect(coveragePercent({ covered: 19, gap: 1 })).toBe(95);
    expect(coveragePercent({ covered: 2, gap: 1 })).toBe(66.6);
  });
});

const HEALTH_CFG = {
  coverageWarnPercent: 95,
  coverageFailPercent: 50,
  lagWarnSeconds: 900,
  lagFailSeconds: 3600,
  throttleWarnPerHour: 20,
};

const healthy = (): ApiModeHealthInput => ({
  connection: { active: true, bound: true },
  journal: { verifiedSource: true, sourceHealth: 'healthy' },
  grantStatus: 'active',
  feeds: { enabled: true, feedMailboxes: 10, activeMailboxes: 10, errorMailboxes: 0 },
  coverage: { inventoryOk: true, inScopeMailboxes: 10, covered: 10, gap: 0 },
  lagP95SecondsLastHour: 60,
  throttleEventsLastHour: 0,
  apiModeDomainsWithGatewayMx: 0,
});

function statusOf(input: ApiModeHealthInput, code: string): string | undefined {
  return evaluateApiModeHealth(input, HEALTH_CFG).checks.find((c) => c.code === code)?.status;
}

describe('evaluateApiModeHealth (D11.3)', () => {
  it('a healthy connection passes every check in order and validates as api-mode-health/1', () => {
    const result = evaluateApiModeHealth(healthy(), HEALTH_CFG);
    expect(result.status).toBe('healthy');
    expect(result.checks.map((c) => c.code)).toEqual([...API_MODE_HEALTH_CHECK_CODES]);
    expect(result.checks.every((c) => c.status === 'pass')).toBe(true);
    expect(result.failingChecks).toEqual([]);
    expect(apiModeHealthDocumentSchema.parse(result.document)).toEqual(result.document);
    for (const c of result.checks) expect((c.evidence ?? '').length).toBeLessThanOrEqual(512);
  });

  const cases: [string, (i: ApiModeHealthInput) => void, string, string][] = [
    ['connection inactive', (i) => (i.connection.active = false), 'connection.active', 'fail'],
    ['tenant unbound', (i) => (i.connection.bound = false), 'connection.active', 'fail'],
    [
      'no journal, feeds on 90 %',
      (i) => {
        i.journal = { verifiedSource: false, sourceHealth: null };
        i.feeds.activeMailboxes = 9;
      },
      'intake.present',
      'pass',
    ],
    [
      'no journal, feeds on 80 %',
      (i) => {
        i.journal = { verifiedSource: false, sourceHealth: null };
        i.feeds.activeMailboxes = 8;
      },
      'intake.present',
      'fail',
    ],
    [
      'no journal, feeds off',
      (i) => {
        i.journal = { verifiedSource: false, sourceHealth: null };
        i.feeds.enabled = false;
      },
      'intake.present',
      'fail',
    ],
    ['journal silent', (i) => (i.journal.sourceHealth = 'silent'), 'intake.journal_health', 'warn'],
    ['journal paused', (i) => (i.journal.sourceHealth = 'paused'), 'intake.journal_health', 'warn'],
    [
      'journal failing',
      (i) => (i.journal.sourceHealth = 'failing'),
      'intake.journal_health',
      'fail',
    ],
    ['grant missing', (i) => (i.grantStatus = null), 'mailbox_access.grant', 'warn'],
    ['grant pending', (i) => (i.grantStatus = 'pending_consent'), 'mailbox_access.grant', 'warn'],
    ['grant revoked, feeds on', (i) => (i.grantStatus = 'revoked'), 'mailbox_access.grant', 'fail'],
    [
      'grant revoked, feeds off',
      (i) => {
        i.grantStatus = 'revoked';
        i.feeds.enabled = false;
      },
      'mailbox_access.grant',
      'warn',
    ],
    [
      'coverage 94 %',
      (i) => (i.coverage = { inventoryOk: true, inScopeMailboxes: 100, covered: 94, gap: 6 }),
      'coverage.percent',
      'warn',
    ],
    [
      'coverage 95 %',
      (i) => (i.coverage = { inventoryOk: true, inScopeMailboxes: 100, covered: 95, gap: 5 }),
      'coverage.percent',
      'pass',
    ],
    [
      'coverage 49 %',
      (i) => (i.coverage = { inventoryOk: true, inScopeMailboxes: 100, covered: 49, gap: 51 }),
      'coverage.percent',
      'fail',
    ],
    [
      'coverage without inventory',
      (i) => (i.coverage = { inventoryOk: false, inScopeMailboxes: 0, covered: 1, gap: 9 }),
      'coverage.percent',
      'pass',
    ],
    ['lag 900 s', (i) => (i.lagP95SecondsLastHour = 900), 'lag.p95_1h', 'pass'],
    ['lag 901 s', (i) => (i.lagP95SecondsLastHour = 901), 'lag.p95_1h', 'warn'],
    ['lag 3601 s', (i) => (i.lagP95SecondsLastHour = 3601), 'lag.p95_1h', 'fail'],
    ['no lag data', (i) => (i.lagP95SecondsLastHour = null), 'lag.p95_1h', 'pass'],
    ['20 throttles', (i) => (i.throttleEventsLastHour = 20), 'throttling.1h', 'pass'],
    ['21 throttles', (i) => (i.throttleEventsLastHour = 21), 'throttling.1h', 'warn'],
    ['1 of 10 feeds in error', (i) => (i.feeds.errorMailboxes = 1), 'feeds.errors', 'pass'],
    ['2 of 10 feeds in error', (i) => (i.feeds.errorMailboxes = 2), 'feeds.errors', 'warn'],
    ['MX conflict', (i) => (i.apiModeDomainsWithGatewayMx = 1), 'domains.api_mode_mx', 'warn'],
  ];

  it.each(cases)('%s → %s %s', (_name, mutate, code, expected) => {
    const input = healthy();
    mutate(input);
    expect(statusOf(input, code)).toBe(expected);
  });

  it('takes the worst status and lists failing checks', () => {
    const degraded = healthy();
    degraded.throttleEventsLastHour = 50;
    const degradedResult = evaluateApiModeHealth(degraded, HEALTH_CFG);
    expect(degradedResult.status).toBe('degraded');
    expect(degradedResult.failingChecks).toEqual(['throttling.1h']);
    const failing = healthy();
    failing.throttleEventsLastHour = 50;
    failing.connection.active = false;
    const failingResult = evaluateApiModeHealth(failing, HEALTH_CFG);
    expect(failingResult.status).toBe('failing');
    expect(failingResult.failingChecks).toEqual(['connection.active', 'throttling.1h']);
  });

  it('the stored document refuses unknown codes and long evidence', () => {
    expect(
      apiModeHealthDocumentSchema.safeParse({ v: 1, checks: [{ code: 'x', status: 'pass' }] })
        .success,
    ).toBe(false);
    expect(
      apiModeHealthDocumentSchema.safeParse({
        v: 1,
        checks: [{ code: 'lag.p95_1h', status: 'pass', evidence: 'x'.repeat(513) }],
      }).success,
    ).toBe(false);
  });
});
