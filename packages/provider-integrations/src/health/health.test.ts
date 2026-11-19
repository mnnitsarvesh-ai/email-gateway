import { describe, expect, it } from 'vitest';
import { registerPermissionProfiles } from '../profiles';
import {
  evaluateCredentialExpiry,
  evaluateHealth,
  failingCheckCodes,
  grantsForCheck,
  HEALTH_CHECKS,
  healthCheckByCode,
  HealthCheckRegistryError,
  periodicHealthChecks,
  registerHealthChecks,
  type HealthCheckResultInput,
} from './index';

const now = new Date('2026-11-18T12:00:00Z');
const ago = (minutes: number) => new Date(now.getTime() - minutes * 60_000);
const r = (
  status: HealthCheckResultInput['status'],
  severity: HealthCheckResultInput['severity'],
  firstFailedAt: Date | null = null,
  code = 'x.check',
): HealthCheckResultInput => ({
  code,
  status,
  severity,
  firstFailedAt,
});

describe('evaluateHealth', () => {
  it.each([
    ['no results', [], 'unknown'],
    ['only skipped', [r('skipped', 'info')], 'unknown'],
    ['all pass', [r('pass', 'info'), r('pass', 'critical')], 'healthy'],
    ['warn', [r('pass', 'info'), r('warn', 'warning')], 'warning'],
    ['warn with info severity', [r('pass', 'info'), r('warn', 'info')], 'healthy'],
    ['warning failure', [r('pass', 'info'), r('fail', 'warning')], 'warning'],
    [
      'critical failure wins',
      [r('warn', 'warning'), r('fail', 'critical'), r('pass', 'info')],
      'critical',
    ],
    ['info failure does not degrade', [r('pass', 'info'), r('fail', 'info')], 'healthy'],
    [
      'error within grace is ignored',
      [r('pass', 'info'), r('error', 'critical', ago(30))],
      'healthy',
    ],
    ['error past grace counts', [r('pass', 'info'), r('error', 'critical', ago(61))], 'critical'],
    [
      'error exactly at grace counts',
      [r('pass', 'info'), r('error', 'warning', ago(60))],
      'warning',
    ],
    [
      'error without a start counts as now (in grace)',
      [r('pass', 'info'), r('error', 'critical', null)],
      'healthy',
    ],
  ] as const)('%s → %s', (_name, results, expected) => {
    expect(evaluateHealth(results, now, 60)).toBe(expected);
  });

  it('keeps the previous status when nothing could be evaluated (outage in grace)', () => {
    expect(evaluateHealth([r('error', 'critical', ago(5))], now, 60, 'healthy')).toBe('healthy');
    expect(evaluateHealth([r('error', 'critical', ago(5))], now, 60)).toBe('unknown');
    expect(evaluateHealth([r('error', 'critical', ago(5))], now, 0)).toBe('critical');
  });

  it('lists failing codes, critical first, bounded', () => {
    const results = [
      r('warn', 'warning', null, 'b.warn'),
      r('fail', 'critical', null, 'z.fail'),
      r('error', 'critical', ago(5), 'in.grace'),
      r('error', 'critical', ago(90), 'a.error'),
      r('fail', 'info', null, 'info.fail'),
      r('pass', 'info', null, 'ok'),
    ];
    expect(failingCheckCodes(results, now, 60)).toEqual(['a.error', 'z.fail', 'b.warn']);
    expect(failingCheckCodes(results, now, 60, 1)).toEqual(['a.error']);
  });
});

describe('health check registry', () => {
  it('holds the D10/D11 checks with titles and guide anchors', () => {
    for (const code of [
      'credentials.token',
      'permissions.granted',
      'tenant.identity',
      'domains.provider_verified',
      'dns.mx_gateway',
      'inbound.recent_deliveries',
      'outbound.relay_activity',
      'routing.loops',
      'credential.expiry',
      'egress.ranges_fresh',
    ]) {
      const check = healthCheckByCode(code);
      expect(check?.periodic, code).toBe(true);
      expect(check?.title.length).toBeGreaterThan(5);
      expect(check?.remediation).toMatch(/^(#[a-z-]+|docs\/.+#[a-z-]+)$/);
    }
    expect(periodicHealthChecks('google_workspace').map((c) => c.code)).not.toContain(
      'inbound.destination_matches_provider',
    );
    expect(healthCheckByCode('inbound.destination_matches_provider')?.provider).toBe(
      'microsoft_365',
    );
  });

  it('R2: generic per-grant checks iterate only over mail_flow grants', () => {
    registerPermissionProfiles([
      {
        key: 'google.ato_health_test',
        version: 1,
        provider: 'google_workspace',
        purpose: 'ato_telemetry',
        readOnly: true,
        permissions: ['https://www.googleapis.com/auth/admin.reports.audit.readonly'],
        authMethods: ['platform_service_account'],
        platformApp: { clientIdKey: 'PROVIDER_GOOGLE_ATO_TEST_SA_CLIENT_ID' },
        title: 'ATO test',
        description: 'Test.',
      },
    ]);
    const grants = [
      { profile: 'google.mail_flow' },
      { profile: 'google.ato_health_test' },
      { profile: 'unknown.profile' },
    ];
    for (const code of ['credentials.token', 'permissions.granted']) {
      expect(grantsForCheck(healthCheckByCode(code)!, grants)).toEqual([
        { profile: 'google.mail_flow' },
      ]);
    }
    expect(grantsForCheck(healthCheckByCode('tenant.identity')!, grants)).toEqual([]);
  });

  it('registers a later step’s check and refuses duplicates or bad codes', () => {
    const ato = {
      code: 'ato.identity_provider',
      provider: 'any' as const,
      severityOnFail: 'warning' as const,
      periodic: true,
      title: 'Identity-provider telemetry',
      remediation: 'docs/deployment/ato-identity-providers.md#troubleshooting',
    };
    const count = HEALTH_CHECKS.length;
    registerHealthChecks([ato]);
    registerHealthChecks([ato]);
    expect(HEALTH_CHECKS).toHaveLength(count + 1);
    expect(() => registerHealthChecks([{ ...ato }])).toThrow(HealthCheckRegistryError);
    expect(() => registerHealthChecks([{ ...ato, code: 'Bad Code' }])).toThrow(
      HealthCheckRegistryError,
    );
    expect(() => registerHealthChecks([{ ...ato, code: 'x.y', remediation: '' }])).toThrow(
      HealthCheckRegistryError,
    );
  });
});

describe('credential.expiry', () => {
  it('warns at 30 days and is critical at 7 days', () => {
    const inDays = (d: number) => new Date(now.getTime() + d * 86_400_000);
    expect(evaluateCredentialExpiry(null, now).status).toBe('skipped');
    expect(evaluateCredentialExpiry(inDays(45), now)).toMatchObject({ status: 'pass' });
    expect(evaluateCredentialExpiry(inDays(29), now)).toMatchObject({
      status: 'warn',
      severity: 'warning',
    });
    expect(evaluateCredentialExpiry(inDays(6), now)).toMatchObject({
      status: 'fail',
      severity: 'critical',
    });
    expect(evaluateCredentialExpiry(inDays(-1), now)).toMatchObject({
      status: 'fail',
      severity: 'critical',
    });
  });
});
