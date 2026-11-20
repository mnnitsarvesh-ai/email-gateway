import { PROVIDER_STREAMS } from '@email-gateway/ato-detection';
import {
  defaultBindingSettings,
  type ProbeReport,
  STREAM_ROLES,
} from '@email-gateway/idp-adapters';
import { describe, expect, it } from 'vitest';
import type { IntegrationRow, StreamRow } from '../repositories/ato-providers.repository';
import {
  changedPaths,
  detailView,
  kindOf,
  mailboxStateStream,
  parseReport,
  refreshSupported,
  requirementsView,
  resolveSettings,
  summaryView,
} from './ato-providers.mapper';

const NOW = new Date('2026-11-20T09:00:00.000Z');
const CTX = { now: NOW, healthIntervalSeconds: 900 };

function report(over: Partial<ProbeReport> = {}): ProbeReport {
  return {
    ok: true,
    checkedAt: '2026-11-20T08:50:00.000Z',
    directoryRefHash: null,
    streams: Object.fromEntries(
      PROVIDER_STREAMS.map((s) => [s, { availability: 'available' }]),
    ) as ProbeReport['streams'],
    actions: {
      revoke_sessions: { availability: 'available', rollback: false, confirmation: 'synchronous' },
      require_mfa: { availability: 'not_configured', rollback: true, confirmation: 'polling' },
      require_password_reset: {
        availability: 'available',
        rollback: false,
        confirmation: 'synchronous',
      },
      suspend_account: { availability: 'available', rollback: true, confirmation: 'polling' },
      remove_forwarding_rule: {
        availability: 'available',
        rollback: true,
        confirmation: 'polling',
      },
      revoke_oauth_grant: {
        availability: 'missing_permission',
        code: 'grant_missing',
        rollback: false,
        confirmation: 'synchronous',
      },
    },
    grants: [{ profile: 'm365.ato_telemetry', status: 'active', missingPermissions: [] }],
    ...over,
  };
}

function row(over: Partial<IntegrationRow> = {}): IntegrationRow {
  return {
    id: 1n,
    publicId: '0193b0a0-aaaa-7a00-8000-000000000001',
    organizationId: 9n,
    provider: 'microsoft_entra',
    connectorRef: '0193b0a0-bbbb-7a00-8000-000000000001',
    bindingKey: 'a'.repeat(64),
    status: 'active',
    capabilities: {},
    cursors: {},
    lastSuccessAt: null,
    lastErrorCode: null,
    consecutiveFailures: 0,
    nextPollAt: NOW,
    displayName: 'EXAMPLE',
    directoryRefHash: 'b'.repeat(64),
    directoryDomains: ['contoso-it.example', 'contoso-it2.example'],
    grantedPermissions: ['AuditLog.Read.All'],
    settings: defaultBindingSettings(),
    settingsVersion: 1,
    healthStatus: 'healthy',
    healthDetail: report() as never,
    healthCheckedAt: NOW,
    nextHealthAt: NOW,
    pausedReason: null,
    disabledReason: null,
    disabledAt: null,
    createdByUserId: null,
    updatedByUserId: null,
    activeMarker: 1,
    rowVersion: 1,
    createdAt: NOW,
    updatedAt: NOW,
    ...over,
  };
}

function streams(failures: Partial<Record<string, number>> = {}): StreamRow[] {
  return PROVIDER_STREAMS.map((stream, i) => ({
    id: BigInt(i + 1),
    organizationId: 9n,
    integrationId: 1n,
    stream,
    role: STREAM_ROLES.microsoft_entra[stream].role,
    enabled: true,
    status: 'active',
    availability: 'available',
    availabilityCode: null,
    cursor: null,
    cursorSeq: 0n,
    watermarkAt: new Date(NOW.getTime() - (i + 1) * 60_000),
    backfillFrom: null,
    backfillRequestedAt: null,
    backfillCompletedAt: null,
    coveredFrom: null,
    replayFrom: null,
    replayUntil: null,
    nextPollAt: NOW,
    throttledUntil: null,
    lastAttemptAt: NOW,
    lastSuccessAt: NOW,
    lastEventAt: NOW,
    lastErrorCode: null,
    consecutiveFailures: failures[stream] ?? 0,
    eventsTotal: 5n,
    pagesTotal: 1n,
    rowVersion: 1,
    createdAt: NOW,
    updatedAt: NOW,
  }));
}

describe('ato-providers mapper (step 8.5 §6, D6, D10)', () => {
  it('manages only the two provider kinds', () => {
    expect(kindOf({ provider: 'microsoft_entra' })).toBe('microsoft_entra');
    expect(kindOf({ provider: 'google_workspace' })).toBe('google_workspace');
    expect(kindOf({ provider: 'fake' })).toBeNull();
  });

  it('falls back to the defaults (flagged) for stored settings that no longer validate', () => {
    expect(resolveSettings('microsoft_entra', {})).toMatchObject({ invalid: true });
    expect(resolveSettings('microsoft_entra', defaultBindingSettings())).toMatchObject({
      invalid: false,
    });
  });

  it('parses a stored probe report defensively', () => {
    expect(parseReport(null)).toBeNull();
    expect(parseReport({ ok: true })).toBeNull();
    const { grants: _g, ...withoutGrants } = report();
    expect(parseReport(withoutGrants)?.grants).toEqual([]);
  });

  it('summarizes primaries, failures, lag and the available capabilities', () => {
    const view = summaryView(row(), 'microsoft_entra', streams({ risk_events: 3 }), null, CTX);
    expect(view.streams).toEqual({
      enabled: 4,
      available: 4,
      failing: 1,
      backfilling: 0,
      maxLagSeconds: 240,
    });
    expect(view.health).toEqual({ status: 'healthy', checkedAt: NOW.toISOString(), stale: false });
    expect(view.capabilities.actions).toEqual([
      'revoke_sessions',
      'require_password_reset',
      'suspend_account',
      'remove_forwarding_rule',
    ]);
    expect(view.connection).toMatchObject({ status: 'missing' });
  });

  it('a stale report makes capabilities unknown; disabled settings show `disabled`', () => {
    const settings = defaultBindingSettings();
    settings.actions.suspend_account.enabled = false;
    const stale = row({
      healthDetail: report({ checkedAt: '2026-11-20T07:00:00.000Z' }) as never,
      settings,
    });
    const view = detailView(stale, 'microsoft_entra', streams(), null, CTX);
    expect(view.health.stale).toBe(true);
    const byAction = Object.fromEntries(view.actions.map((a) => [a.action, a.capability]));
    expect(byAction.suspend_account).toBe('disabled');
    expect(byAction.revoke_sessions).toBe('unknown');
    expect(view.directory.domainCount).toBe(2);
    expect(view.streamDetails).toHaveLength(7);
  });

  it('a priority refresh needs an active integration with the mailbox stream proven', () => {
    expect(mailboxStateStream('microsoft_entra')).toBe('mailbox_audit');
    expect(mailboxStateStream('google_workspace')).toBe('forwarding_changes');
    expect(refreshSupported(row(), 'microsoft_entra')).toBe(true);
    expect(refreshSupported(row({ status: 'paused' }), 'microsoft_entra')).toBe(false);
    expect(refreshSupported(row({ healthDetail: null }), 'microsoft_entra')).toBe(false);
    const missing = report({
      grants: [
        {
          profile: 'm365.ato_telemetry',
          status: 'active',
          missingPermissions: ['MailboxSettings.Read'],
        },
      ],
    });
    expect(refreshSupported(row({ healthDetail: missing as never }), 'microsoft_entra')).toBe(
      false,
    );
    const google = row({
      provider: 'google_workspace',
      healthDetail: report({ grants: [] }) as never,
    });
    expect(refreshSupported(google, 'google_workspace')).toBe(true);
  });

  it('lists the changed leaf paths of two settings documents', () => {
    const a = defaultBindingSettings();
    const b = defaultBindingSettings();
    b.pollIntervalSeconds = 600;
    b.streams.sign_ins.enabled = false;
    expect(changedPaths(a, b)).toEqual(['pollIntervalSeconds', 'streams.sign_ins.enabled']);
    expect(changedPaths(a, a)).toEqual([]);
    // A stored `{}` (an 8.4 row) differs at every top-level key.
    expect(changedPaths({}, a)).toEqual(Object.keys(a).sort());
  });

  it('serves the requirements of both providers with retention per stream', () => {
    const view = requirementsView();
    expect(view.providers.map((p) => p.provider)).toEqual(['microsoft_entra', 'google_workspace']);
    const google = view.providers[1]!;
    expect(google.streams.find((s) => s.stream === 'session_events')).toMatchObject({
      role: 'unsupported',
      retentionDays: 0,
    });
    expect(view.providers[0]!.profiles.map((p) => p.key)).toEqual([
      'm365.ato_telemetry',
      'm365.ato_response',
      'm365.ato_response_extended',
    ]);
  });
});
