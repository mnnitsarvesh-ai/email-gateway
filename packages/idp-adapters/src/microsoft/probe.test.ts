import { afterEach, describe, expect, it, vi } from 'vitest';
import { MS_TENANT_ID } from '../testing/datasets/microsoft';
import {
  createMicrosoftTestbed,
  defaultMicrosoftGrants,
  type MicrosoftTestbed,
  type MicrosoftTestbedOptions,
} from '../testing/harness';

const signal = () => new AbortController().signal;
let testbed: MicrosoftTestbed | null = null;

async function bed(options: MicrosoftTestbedOptions = {}): Promise<MicrosoftTestbed> {
  testbed = await createMicrosoftTestbed(options);
  return testbed;
}

afterEach(async () => {
  // Probes are read-only (invariant 7): no simulator write, not even the subscription start.
  if (testbed) expect(testbed.sims.script.writes()).toEqual([]);
  await testbed?.stop();
  testbed = null;
});

describe('Microsoft probe (D6)', () => {
  it('reports every stream and action available with all grants intact', async () => {
    const probe = vi.fn();
    const tb = await bed({ metrics: { probe } });
    const report = await tb.adapter.probe(signal());
    expect(report.ok).toBe(true);
    expect(report.code).toBeUndefined();
    expect(report.checkedAt).toBe('2026-11-10T12:00:00.000Z');
    expect(Object.values(report.streams).map((s) => s.availability)).toEqual(
      Array(7).fill('available'),
    );
    expect(report.streams.mailbox_audit.code).toBe('subscription_pending'); // never started by a probe
    expect(Object.values(report.actions).map((a) => a.availability)).toEqual(
      Array(6).fill('available'),
    );
    expect(report.actions.suspend_account).toMatchObject({
      rollback: true,
      confirmation: 'polling',
    });
    expect(report.grants).toEqual([
      { profile: 'm365.ato_telemetry', status: 'active', missingPermissions: [] },
      { profile: 'm365.ato_response', status: 'active', missingPermissions: [] },
      { profile: 'm365.ato_response_extended', status: 'active', missingPermissions: [] },
    ]);
    expect(probe).toHaveBeenCalledWith({ provider: 'microsoft_entra', result: 'ok' });
    expect(await tb.adapter.health(signal())).toEqual({ ok: true });
  });

  it('reports a removed permission per stream, its companion and the grant', async () => {
    const tb = await bed();
    tb.sims.script.revokePermission('IdentityRiskEvent.Read.All');
    const report = await tb.adapter.probe(signal());
    expect(report).toMatchObject({ ok: false, code: 'stream_unavailable' });
    expect(report.streams.risk_events.availability).toBe('missing_permission');
    expect(report.streams.session_events.availability).toBe('missing_permission');
    expect(report.streams.sign_ins.availability).toBe('available');
    expect(report.grants[0]?.missingPermissions).toEqual(['IdentityRiskEvent.Read.All']);
    expect(await tb.adapter.health(signal())).toEqual({ ok: false, code: 'stream_unavailable' });
  });

  it('derives missing permissions from failed reads when 8.2 never verified the grant', async () => {
    const grants = defaultMicrosoftGrants().map((g) => ({ ...g, observed: false }));
    const tb = await bed({ grants });
    tb.sims.script.revokePermission('AuditLog.Read.All');
    const report = await tb.adapter.probe(signal());
    expect(report.streams.sign_ins.availability).toBe('missing_permission');
    expect(report.streams.oauth_consents.availability).toBe('missing_permission');
    expect(report.grants[0]?.missingPermissions).toEqual(
      expect.arrayContaining(['AuditLog.Read.All', 'Directory.Read.All']),
    );
  });

  it('reports missing licences (Entra ID P1/P2, unified audit logging)', async () => {
    const tb = await bed();
    tb.sims.script.setLicense(MS_TENANT_ID, 'entraP1', false);
    tb.sims.script.setLicense(MS_TENANT_ID, 'entraP2', false);
    tb.sims.script.setLicense(MS_TENANT_ID, 'unifiedAudit', false);
    const report = await tb.adapter.probe(signal());
    expect(report.streams.sign_ins.availability).toBe('missing_license');
    expect(report.streams.risk_events.availability).toBe('missing_license');
    expect(report.streams.mailbox_audit.availability).toBe('missing_license');
    expect(report.streams.forwarding_changes.availability).toBe('missing_license');
    expect(report.streams.oauth_consents.availability).toBe('available');
  });

  it('reports MFA enforcement not configured, group not found and group unreadable', async () => {
    const unset = await bed({
      settings: (s) => ({ ...s, mfaEnforcement: { groupId: null, orgUnitPath: null } }),
    });
    expect((await unset.adapter.probe(signal())).actions.require_mfa).toMatchObject({
      availability: 'not_configured',
      code: 'mfa_group_not_configured',
    });
    await unset.stop();
    const missing = await bed({
      settings: (s) => ({
        ...s,
        mfaEnforcement: { groupId: '12345678-1234-4234-8234-123456789012', orgUnitPath: null },
      }),
    });
    expect((await missing.adapter.probe(signal())).actions.require_mfa).toMatchObject({
      availability: 'not_configured',
      code: 'mfa_group_not_found',
    });
    await missing.stop();
    const denied = await bed();
    denied.sims.script.revokePermission('GroupMember.ReadWrite.All');
    const report = await denied.adapter.probe(signal());
    expect(report.actions.require_mfa.availability).toBe('missing_permission');
    expect(report.actions.revoke_oauth_grant.availability).toBe('available');
    expect(report.grants[2]?.missingPermissions).toEqual(['GroupMember.ReadWrite.All']);
  });

  it('reports actions without a response grant or with an unconsented grant', async () => {
    const grants = defaultMicrosoftGrants()
      .filter((g) => g.profile !== 'm365.ato_response_extended')
      .map((g) => (g.profile === 'm365.ato_response' ? { ...g, status: 'pending' as const } : g));
    const tb = await bed({ grants });
    const report = await tb.adapter.probe(signal());
    expect(report.ok).toBe(true); // telemetry is fine
    expect(report.actions.revoke_sessions).toMatchObject({
      availability: 'missing_permission',
      code: 'consent_missing',
    });
    expect(report.actions.require_mfa).toMatchObject({
      availability: 'missing_permission',
      code: 'grant_missing',
    });
    expect(report.grants.map((g) => g.status)).toEqual(['active', 'pending', 'absent']);
  });

  it('detects a removed MailboxSettings.Read (no refresh support) while the stream stays available', async () => {
    const tb = await bed();
    tb.sims.script.revokePermission('MailboxSettings.Read');
    const report = await tb.adapter.probe(signal());
    expect(report.streams.mailbox_audit.availability).toBe('available');
    expect(report.grants[0]?.missingPermissions).toContain('MailboxSettings.Read');
  });

  it('fails when the directory changed since binding', async () => {
    const tb = await bed();
    const changed = tb.newAdapter({ directoryRefHash: 'f'.repeat(64) });
    const report = await changed.probe(signal());
    expect(report).toMatchObject({ ok: false, code: 'directory_changed' });
    expect(report.streams.sign_ins).toEqual({ availability: 'error', code: 'directory_changed' });
    expect(tb.sims.script.calls()).toHaveLength(0);
  });

  it('fails connection_inactive, telemetry_grant_inactive and token failures', async () => {
    const tb = await bed();
    tb.connections.setGrantStatus(
      tb.integration.organizationId,
      tb.integration.connectionPublicId,
      'm365.ato_telemetry',
      'pending',
    );
    const pendingGrant = await tb.adapter.probe(signal());
    expect(pendingGrant).toMatchObject({ ok: false, code: 'telemetry_grant_inactive' });
    expect(pendingGrant.streams.sign_ins).toEqual({
      availability: 'missing_permission',
      code: 'consent_missing',
    });
    tb.connections.setGrantStatus(
      tb.integration.organizationId,
      tb.integration.connectionPublicId,
      'm365.ato_telemetry',
      'active',
    );

    tb.connections.failTokens('credentials_invalid', { profile: 'm365.ato_telemetry', times: 2 });
    const tokens = await tb.adapter.probe(signal());
    expect(tokens).toMatchObject({ ok: false, code: 'credentials_invalid' });
    expect(tokens.streams.sign_ins).toEqual({ availability: 'error', code: 'credentials_invalid' });

    tb.connections.update(tb.integration.organizationId, tb.integration.connectionPublicId, {
      status: 'configuring',
    });
    const inactive = await tb.adapter.probe(signal());
    expect(inactive).toMatchObject({
      ok: false,
      code: 'connection_inactive',
      directoryRefHash: null,
    });
  });

  it('turns a provider outage into availability error, never a thrown probe', async () => {
    const tb = await bed();
    tb.sims.script.inject({ path: '/v1.0/auditLogs/directoryAudits', status: 503 });
    const report = await tb.adapter.probe(signal());
    expect(report.streams.oauth_consents).toEqual({
      availability: 'error',
      code: 'provider_unavailable',
    });
  });
});
