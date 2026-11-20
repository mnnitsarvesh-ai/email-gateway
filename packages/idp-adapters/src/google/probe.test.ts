import { afterEach, describe, expect, it, vi } from 'vitest';
import { directoryRefHash } from '../core/hash';
import { GOOGLE_PROFILES, GOOGLE_SCOPES } from '../requirements';
import { GS_ADMIN_EMAIL, GS_DOMAIN, GS_MFA_OU } from '../testing/datasets/google';
import {
  createGoogleTestbed,
  defaultGoogleGrants,
  TEST_GS_CONNECTION_ID,
  type GoogleTestbed,
  type GoogleTestbedOptions,
} from '../testing/google-harness';

const signal = () => new AbortController().signal;
let testbed: GoogleTestbed | null = null;

async function bed(options: GoogleTestbedOptions = {}): Promise<GoogleTestbed> {
  testbed = await createGoogleTestbed(options);
  return testbed;
}

afterEach(async () => {
  // Probes are read-only (invariant 7).
  if (testbed) expect(testbed.sims.script.writes()).toEqual([]);
  await testbed?.stop();
  testbed = null;
});

const availability = (report: Awaited<ReturnType<GoogleTestbed['adapter']['probe']>>) =>
  Object.fromEntries(Object.entries(report.streams).map(([k, v]) => [k, v.availability]));

describe('Google probe (D6)', () => {
  it('reports every offered stream and action available with all grants intact', async () => {
    const probe = vi.fn();
    const tb = await bed({ metrics: { probe } });
    const report = await tb.adapter.probe(signal());
    expect(report).toMatchObject({
      ok: true,
      checkedAt: '2026-11-10T12:00:00.000Z',
      directoryRefHash: directoryRefHash('google_workspace', 'Cexample01'),
    });
    expect(report.code).toBeUndefined();
    expect(availability(report)).toEqual({
      sign_ins: 'available',
      risk_events: 'available',
      oauth_consents: 'available',
      mailbox_audit: 'available',
      forwarding_changes: 'available',
      delegation_changes: 'available',
      session_events: 'not_offered',
    });
    expect(Object.values(report.actions).map((a) => a.availability)).toEqual(
      Array(6).fill('available'),
    );
    expect(report.actions.require_mfa).toMatchObject({ rollback: true, confirmation: 'polling' });
    expect(report.actions.remove_forwarding_rule).toMatchObject({ rollback: false });
    expect(report.grants).toEqual([
      { profile: 'google.ato_telemetry', status: 'active', missingPermissions: [] },
      { profile: 'google.ato_response', status: 'active', missingPermissions: [] },
      { profile: 'google.ato_response_extended', status: 'active', missingPermissions: [] },
    ]);
    // Reads: Reports login + token (maxResults=1), the user listing and one impersonated Gmail read.
    const calls = tb.sims.script.calls();
    expect(calls.map((c) => [c.simulator, c.path])).toEqual([
      ['google-admin', '/admin/reports/v1/activity/users/all/applications/login'],
      ['google-admin', '/admin/reports/v1/activity/users/all/applications/token'],
      ['google-admin', '/admin/directory/v1/users'],
      ['gmail', `/gmail/v1/users/${encodeURIComponent(GS_ADMIN_EMAIL)}/settings/autoForwarding`],
      ['google-admin', `/admin/directory/v1/customer/my_customer/orgunits/Security/2SV-Enforced`],
    ]);
    expect(new URLSearchParams(calls[0]?.query ?? '').get('maxResults')).toBe('1');
    expect(calls[3]?.subject).toBe(GS_ADMIN_EMAIL);
    expect(probe).toHaveBeenCalledWith({ provider: 'google_workspace', result: 'ok' });
    expect(await tb.adapter.health(signal())).toEqual({ ok: true });
  });

  it('reports a removed Reports scope per stream, its companion and the grant', async () => {
    const tb = await bed();
    tb.sims.script.revokePermission(GOOGLE_SCOPES.reportsAudit);
    const report = await tb.adapter.probe(signal());
    expect(report).toMatchObject({ ok: false, code: 'stream_unavailable' });
    expect(availability(report)).toMatchObject({
      sign_ins: 'missing_permission',
      risk_events: 'missing_permission',
      oauth_consents: 'missing_permission',
      forwarding_changes: 'available',
    });
    expect(report.grants[0]?.missingPermissions).toEqual([GOOGLE_SCOPES.reportsAudit]);
  });

  it('derives missing scopes from failed reads when 8.2 never verified the grant', async () => {
    const grants = defaultGoogleGrants().map((g) =>
      g.profile === GOOGLE_PROFILES.telemetry ? { ...g, observed: false } : g,
    );
    const tb = await bed({ grants });
    tb.sims.script.revokePermission(GOOGLE_SCOPES.gmailSettingsBasic);
    const report = await tb.adapter.probe(signal());
    expect(availability(report)).toMatchObject({
      forwarding_changes: 'missing_permission',
      mailbox_audit: 'missing_permission',
      delegation_changes: 'missing_permission',
      sign_ins: 'available',
    });
    expect(report.grants[0]?.missingPermissions).toEqual([GOOGLE_SCOPES.gmailSettingsBasic]);
    expect(tb.adapter.mailboxRefreshSupported()).toBe(false);
  });

  it('reports a directory scope removed from the sweep', async () => {
    const tb = await bed();
    tb.sims.script.revokePermission(GOOGLE_SCOPES.directoryUserReadonly);
    const report = await tb.adapter.probe(signal());
    expect(report.streams.forwarding_changes.availability).toBe('missing_permission');
    expect(report.grants[0]?.missingPermissions).toEqual([GOOGLE_SCOPES.directoryUserReadonly]);
  });

  it('reports the settings sweep not_configured without an active user of a verified linked domain', async () => {
    const tb = await bed();
    tb.connections.update('1001', TEST_GS_CONNECTION_ID, {
      linkedDomains: [{ name: GS_DOMAIN, providerVerified: false }],
    });
    const report = await tb.adapter.probe(signal());
    expect(report.streams.forwarding_changes).toEqual({
      availability: 'not_configured',
      code: 'no_linked_user',
    });
    expect(tb.sims.script.calls({ simulator: 'gmail' })).toEqual([]);
  });

  it('reports MFA enforcement not configured, OU not found and OU unreadable', async () => {
    const tb = await bed({
      settings: (s) => ({ ...s, mfaEnforcement: { groupId: null, orgUnitPath: null } }),
    });
    const report = await tb.adapter.probe(signal());
    expect(report.ok).toBe(true); // actions never make the integration unhealthy
    expect(report.actions.require_mfa).toMatchObject({
      availability: 'not_configured',
      code: 'mfa_ou_not_configured',
    });
    const missing = tb.newAdapter({
      settings: {
        ...tb.integration.settings,
        mfaEnforcement: { groupId: null, orgUnitPath: '/Nope' },
      },
    });
    expect((await missing.probe(signal())).actions.require_mfa).toMatchObject({
      availability: 'not_configured',
      code: 'mfa_ou_not_found',
    });
    const configured = tb.newAdapter({
      settings: {
        ...tb.integration.settings,
        mfaEnforcement: { groupId: null, orgUnitPath: GS_MFA_OU },
      },
    });
    tb.sims.script.revokePermission(GOOGLE_SCOPES.directoryOrgunitReadonly);
    expect((await configured.probe(signal())).actions.require_mfa.availability).toBe(
      'missing_permission',
    );
  });

  it('reports actions without a response grant or with an unconsented grant', async () => {
    const grants = defaultGoogleGrants()
      .filter((g) => g.profile !== GOOGLE_PROFILES.responseExtended)
      .map((g) =>
        g.profile === GOOGLE_PROFILES.response ? { ...g, status: 'pending' as const } : g,
      );
    const tb = await bed({ grants });
    const report = await tb.adapter.probe(signal());
    expect(report.ok).toBe(true);
    expect(report.actions.suspend_account).toMatchObject({
      availability: 'missing_permission',
      code: 'consent_missing',
    });
    expect(report.actions.require_mfa).toMatchObject({
      availability: 'missing_permission',
      code: 'grant_missing',
    });
    expect(report.grants.map((g) => g.status)).toEqual(['active', 'pending', 'absent']);
  });

  it('fails delegated_admin_missing when the telemetry grant has no delegated administrator', async () => {
    const grants = defaultGoogleGrants().map((g) =>
      g.profile === GOOGLE_PROFILES.telemetry ? { ...g, subjectEmail: null } : g,
    );
    const tb = await bed({ grants });
    const report = await tb.adapter.probe(signal());
    expect(report).toMatchObject({ ok: false, code: 'delegated_admin_missing' });
    expect(report.streams.sign_ins).toEqual({
      availability: 'not_configured',
      code: 'delegated_admin_missing',
    });
    // No telemetry read was attempted; only the extended grant's OU check ran.
    expect(tb.sims.script.calls().map((c) => c.path)).toEqual([
      '/admin/directory/v1/customer/my_customer/orgunits/Security/2SV-Enforced',
    ]);
  });

  it('fails when the directory changed since binding, without calling the provider', async () => {
    const tb = await bed();
    const changed = tb.newAdapter({
      directoryRefHash: directoryRefHash('google_workspace', 'Cother99'),
    });
    const report = await changed.probe(signal());
    expect(report).toMatchObject({ ok: false, code: 'directory_changed' });
    expect(report.streams.sign_ins.availability).toBe('error');
    expect(report.streams.session_events.availability).toBe('not_offered');
    expect(tb.sims.script.calls()).toEqual([]);
  });

  it('fails connection_inactive, telemetry_grant_inactive and token failures', async () => {
    const tb = await bed();
    tb.connections.failTokens('credentials_invalid', { profile: GOOGLE_PROFILES.telemetry });
    const token = await tb.adapter.probe(signal());
    expect(token).toMatchObject({ ok: false, code: 'credentials_invalid' });
    expect(token.streams.sign_ins).toEqual({ availability: 'error', code: 'credentials_invalid' });
    tb.connections.setGrantStatus(
      '1001',
      TEST_GS_CONNECTION_ID,
      GOOGLE_PROFILES.telemetry,
      'error',
    );
    expect(await tb.adapter.probe(signal())).toMatchObject({
      ok: false,
      code: 'telemetry_grant_inactive',
    });
    tb.connections.update('1001', TEST_GS_CONNECTION_ID, { status: 'configuring' });
    const inactive = await tb.adapter.probe(signal());
    expect(inactive).toMatchObject({ ok: false, code: 'connection_inactive' });
    expect(await tb.adapter.health(signal())).toEqual({ ok: false, code: 'connection_inactive' });
  });

  it('turns a provider outage into availability error, never a thrown probe', async () => {
    const tb = await bed();
    tb.sims.script.inject({ path: '/admin/', status: 503, times: Infinity });
    const report = await tb.adapter.probe(signal());
    expect(report.ok).toBe(false);
    expect(report.streams.sign_ins).toEqual({
      availability: 'error',
      code: 'provider_unavailable',
    });
    expect(report.actions.require_mfa.availability).toBe('error');
  });
});
