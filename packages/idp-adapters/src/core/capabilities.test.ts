import { describe, expect, it } from 'vitest';
import { MICROSOFT_DECLARED_CAPABILITIES } from '../microsoft/constants';
import { PROVIDER_ACTION_TYPES, PROVIDER_STREAMS, type ProviderStream } from '../port/ato-port';
import {
  computeEffectiveCapabilities,
  computeHealthStatus,
  isReportStale,
  type ProbeReport,
  type StreamRuntimeState,
} from './capabilities';
import { defaultBindingSettings } from './settings';

const NOW = new Date('2026-11-10T12:00:00.000Z');

function report(overrides: Partial<ProbeReport> = {}, checkedAt = NOW): ProbeReport {
  return {
    ok: true,
    checkedAt: checkedAt.toISOString(),
    directoryRefHash: null,
    streams: Object.fromEntries(
      PROVIDER_STREAMS.map((s) => [s, { availability: 'available' }]),
    ) as ProbeReport['streams'],
    actions: Object.fromEntries(
      PROVIDER_ACTION_TYPES.map((a) => [
        a,
        { availability: 'available', rollback: false, confirmation: 'synchronous' },
      ]),
    ) as ProbeReport['actions'],
    grants: [],
    ...overrides,
  };
}

const compute = (r: ProbeReport | null, settings = defaultBindingSettings(), now = NOW) =>
  computeEffectiveCapabilities({
    provider: 'microsoft_entra',
    declared: MICROSOFT_DECLARED_CAPABILITIES,
    report: r,
    settings,
    now,
    healthIntervalSeconds: 900,
  });

describe('effective capabilities (D6)', () => {
  it('is declared ∩ available ∩ enabled', () => {
    const r = report();
    r.streams.sign_ins = { availability: 'missing_license', code: 'entra_p1' };
    r.actions.require_mfa = {
      availability: 'not_configured',
      rollback: true,
      confirmation: 'polling',
    };
    const settings = defaultBindingSettings();
    settings.streams.oauth_consents.enabled = false;
    settings.actions.suspend_account.enabled = false;
    const result = compute(r, settings);
    expect(result.stale).toBe(false);
    expect(result.capabilities.streams.sign_ins?.supported).toBe(false);
    expect(result.capabilities.streams.risk_events).toEqual({
      supported: true,
      latencySeconds: 900,
    });
    expect(result.capabilities.streams.oauth_consents?.supported).toBe(false);
    expect(result.capabilities.actions.require_mfa?.supported).toBe(false);
    expect(result.capabilities.actions.suspend_account).toEqual({
      supported: false,
      rollback: false,
      confirmation: 'polling',
    });
    expect(result.capabilities.actions.revoke_sessions).toEqual({
      supported: true,
      rollback: false,
      confirmation: 'synchronous',
    });
    expect(result.capabilities.actions.remove_forwarding_rule?.rollback).toBe(true);
    expect(result.view.streams.sign_ins).toBe('missing_license');
    expect(result.view.streams.oauth_consents).toBe('disabled');
    expect(result.view.actions.require_mfa).toBe('not_configured');
    expect(result.view.actions.suspend_account).toBe('disabled');
  });

  it('marks unsupported streams of a provider not_offered (Google session_events)', () => {
    const result = computeEffectiveCapabilities({
      provider: 'google_workspace',
      declared: { streams: { sign_ins: { supported: true } }, actions: {} },
      report: report(),
      settings: defaultBindingSettings(),
      now: NOW,
      healthIntervalSeconds: 900,
    });
    expect(result.view.streams.session_events).toBe('not_offered');
    expect(result.capabilities.streams.session_events?.supported).toBe(false);
    expect(result.view.actions.revoke_sessions).toBe('not_offered');
  });

  it('makes everything unknown when the report is missing or older than 3 × the interval', () => {
    const missing = compute(null);
    expect(missing.stale).toBe(true);
    expect(missing.view.streams.sign_ins).toBe('unknown');
    expect(missing.capabilities.streams.sign_ins?.supported).toBe(false);
    const old = compute(report({}, new Date(NOW.getTime() - 2_701_000)));
    expect(old.stale).toBe(true);
    expect(old.view.actions.revoke_sessions).toBe('unknown');
    expect(isReportStale(report({}, new Date(NOW.getTime() - 2_700_000)), NOW, 900)).toBe(false);
    expect(isReportStale({ ...report(), checkedAt: 'garbage' }, NOW, 900)).toBe(true);
  });
});

describe('integration health (D6)', () => {
  const primaries: ProviderStream[] = [
    'sign_ins',
    'risk_events',
    'oauth_consents',
    'mailbox_audit',
  ];
  const streams = (
    patch: Partial<Record<ProviderStream, Partial<StreamRuntimeState>>> = {},
  ): StreamRuntimeState[] =>
    primaries.map((stream) => ({
      stream,
      enabled: true,
      role: 'primary',
      consecutiveFailures: 0,
      ...patch[stream],
    }));
  const health = (input: Partial<Parameters<typeof computeHealthStatus>[0]>) =>
    computeHealthStatus({
      report: report(),
      connectionActive: true,
      tokenFailing: false,
      streams: streams(),
      now: NOW,
      lagWarnSeconds: 3600,
      ...input,
    });

  it('is unknown before the first probe', () => {
    expect(health({ report: null })).toBe('unknown');
  });

  it('is healthy when every enabled primary is available and none fails', () => {
    expect(health({})).toBe('healthy');
    // A disabled failing stream does not count.
    expect(
      health({ streams: streams({ sign_ins: { enabled: false, consecutiveFailures: 9 } }) }),
    ).toBe('healthy');
  });

  it('is degraded for an unavailable stream, long throttling, lag or failures', () => {
    const r = report();
    r.streams.risk_events = { availability: 'missing_license' };
    expect(health({ report: r })).toBe('degraded');
    expect(
      health({ streams: streams({ sign_ins: { throttledSinceMs: NOW.getTime() - 16 * 60_000 } }) }),
    ).toBe('degraded');
    expect(
      health({ streams: streams({ sign_ins: { throttledSinceMs: NOW.getTime() - 5 * 60_000 } }) }),
    ).toBe('healthy');
    expect(health({ streams: streams({ mailbox_audit: { lagSeconds: 3601 } }) })).toBe('degraded');
    expect(health({ streams: streams({ oauth_consents: { consecutiveFailures: 1 } }) })).toBe(
      'degraded',
    );
    expect(health({ streams: streams({ oauth_consents: { consecutiveFailures: 3 } }) })).toBe(
      'degraded',
    );
  });

  it('is unhealthy when the connection is inactive, tokens fail or every enabled stream fails', () => {
    expect(health({ connectionActive: false })).toBe('unhealthy');
    expect(health({ tokenFailing: true })).toBe('unhealthy');
    const failing = Object.fromEntries(primaries.map((s) => [s, { consecutiveFailures: 3 }]));
    expect(health({ streams: streams(failing) })).toBe('unhealthy');
  });
});
