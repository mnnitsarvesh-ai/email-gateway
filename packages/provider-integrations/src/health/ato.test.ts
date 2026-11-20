import { describe, expect, it } from 'vitest';
import {
  ATO_DEGRADED_WARN_AFTER_MS,
  ATO_IDENTITY_PROVIDER_CHECK,
  atoHealthFacts,
  degradedSinceOf,
  evaluateAtoIdentityProvider,
  type AtoIntegrationHealthInput,
} from './ato';
import {
  HEALTH_CHECKS,
  MAIL_FLOW_HEALTH_CHECKS,
  healthCheckByCode,
  periodicHealthChecks,
} from './checks';

const now = new Date('2026-11-20T10:00:00.000Z');

const integration = (
  overrides: Partial<AtoIntegrationHealthInput> = {},
): AtoIntegrationHealthInput => ({
  publicId: '0190bbbb-0000-7000-8000-000000000001',
  status: 'active',
  pausedReason: null,
  healthStatus: 'healthy',
  healthDetail: null,
  healthCheckedAt: new Date(now.getTime() - 60_000),
  ...overrides,
});

const report = {
  ok: false,
  checkedAt: now.toISOString(),
  streams: {
    sign_ins: { availability: 'missing_license', code: 'entra_p1_required' },
    risk_events: { availability: 'available' },
    session_events: { availability: 'not_offered' },
    mailbox_audit: { availability: 'missing_permission' },
  },
  grants: [
    { profile: 'm365.ato_telemetry', status: 'active', missingPermissions: ['ActivityFeed.Read'] },
    { profile: 'm365.ato_response', status: 'absent', missingPermissions: ['bad value!'] },
  ],
};

describe('ato.identity_provider (D11)', () => {
  it('is registered after 8.2’s checks: periodic, any provider, warning on failure', () => {
    expect(healthCheckByCode('ato.identity_provider')).toBe(ATO_IDENTITY_PROVIDER_CHECK);
    expect(HEALTH_CHECKS.slice(0, MAIL_FLOW_HEALTH_CHECKS.length)).toEqual([
      ...MAIL_FLOW_HEALTH_CHECKS,
    ]);
    expect(ATO_IDENTITY_PROVIDER_CHECK).toMatchObject({
      provider: 'any',
      severityOnFail: 'warning',
      periodic: true,
    });
    for (const provider of ['microsoft_365', 'google_workspace'] as const) {
      expect(periodicHealthChecks(provider).map((c) => c.code)).toContain('ato.identity_provider');
    }
  });

  it('skips without an integration, when paused by a user and before the first probe', () => {
    const run = (integrations: AtoIntegrationHealthInput[]) =>
      evaluateAtoIdentityProvider({ integrations, previousDegradedSince: null, now });
    expect(run([]).status).toBe('skipped');
    expect(run([integration({ status: 'disabled', healthStatus: 'unhealthy' })]).status).toBe(
      'skipped',
    );
    expect(run([integration({ status: 'paused', pausedReason: 'user' })]).evidence).toMatchObject({
      reason: 'paused',
    });
    expect(run([integration({ healthStatus: 'unknown' })]).evidence).toMatchObject({
      reason: 'not_probed',
    });
  });

  it('passes when healthy and fails (bounded evidence, no secrets) when unhealthy', () => {
    expect(
      evaluateAtoIdentityProvider({
        integrations: [integration()],
        previousDegradedSince: null,
        now,
      }).status,
    ).toBe('pass');
    const failed = evaluateAtoIdentityProvider({
      integrations: [
        integration(),
        integration({
          publicId: '0190bbbb-0000-7000-8000-000000000002',
          status: 'paused',
          pausedReason: 'telemetry_grant_inactive',
          healthStatus: 'unhealthy',
          healthDetail: report,
        }),
      ],
      previousDegradedSince: null,
      now,
    });
    expect(failed).toEqual({
      status: 'fail',
      evidence: {
        health: 'unhealthy',
        integrationId: '0190bbbb-0000-7000-8000-000000000002',
        checkedAt: new Date(now.getTime() - 60_000).toISOString(),
        failingStreams: ['mailbox_audit', 'sign_ins'],
        missingPermissions: ['ActivityFeed.Read'],
      },
    });
  });

  it('warns only after one hour of degradation, remembering the start in the evidence', () => {
    const degraded = [integration({ healthStatus: 'degraded', healthDetail: report })];
    const first = evaluateAtoIdentityProvider({
      integrations: degraded,
      previousDegradedSince: null,
      now,
    });
    expect(first.status).toBe('pass');
    const since = degradedSinceOf(first.evidence as never);
    expect(since?.toISOString()).toBe(now.toISOString());
    const later = new Date(now.getTime() + ATO_DEGRADED_WARN_AFTER_MS + 1_000);
    expect(
      evaluateAtoIdentityProvider({
        integrations: degraded,
        previousDegradedSince: since,
        now: later,
      }).status,
    ).toBe('warn');
    expect(degradedSinceOf(null)).toBeNull();
    expect(degradedSinceOf({ degradedSince: 'nope' })).toBeNull();
  });

  it('reads facts defensively from an untrusted probe report', () => {
    expect(atoHealthFacts('garbage')).toEqual({ failingStreams: [], missingPermissions: [] });
    expect(atoHealthFacts({ streams: 'x', grants: [{ missingPermissions: 'y' }] })).toEqual({
      failingStreams: [],
      missingPermissions: [],
    });
  });
});
