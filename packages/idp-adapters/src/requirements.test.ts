import { describe, expect, it } from 'vitest';
import {
  ATO_PROVIDER_KINDS,
  connectionProviderFromKind,
  providerKindFromConnection,
} from './kinds';
import { PROVIDER_ACTION_TYPES, PROVIDER_STREAMS } from './port/ato-port';
import { GOOGLE_DECLARED_CAPABILITIES } from './google/constants';
import { MICROSOFT_DECLARED_CAPABILITIES } from './microsoft/constants';
import {
  GOOGLE_PROFILES,
  GOOGLE_SCOPES,
  PERMISSION_REQUIREMENTS,
  PROVIDER_RETENTION_DAYS,
  STREAM_ROLES,
  primaryOf,
} from './requirements';

describe('provider kinds (D1)', () => {
  it('maps 8.2 connection providers to ATO kinds and back', () => {
    expect(providerKindFromConnection('microsoft_365')).toBe('microsoft_entra');
    expect(providerKindFromConnection('google_workspace')).toBe('google_workspace');
    expect(providerKindFromConnection('okta')).toBeNull();
    expect(providerKindFromConnection('toString')).toBeNull();
    expect(connectionProviderFromKind('microsoft_entra')).toBe('microsoft_365');
  });
});

describe('stream roles (D3)', () => {
  it('matches the design table', () => {
    expect(STREAM_ROLES.microsoft_entra).toEqual({
      sign_ins: { role: 'primary' },
      risk_events: { role: 'primary' },
      session_events: { role: 'companion', primary: 'risk_events' },
      oauth_consents: { role: 'primary' },
      mailbox_audit: { role: 'primary' },
      forwarding_changes: { role: 'companion', primary: 'mailbox_audit' },
      delegation_changes: { role: 'companion', primary: 'mailbox_audit' },
    });
    expect(STREAM_ROLES.google_workspace).toEqual({
      sign_ins: { role: 'primary' },
      risk_events: { role: 'companion', primary: 'sign_ins' },
      session_events: { role: 'unsupported' },
      oauth_consents: { role: 'primary' },
      mailbox_audit: { role: 'companion', primary: 'forwarding_changes' },
      forwarding_changes: { role: 'primary' },
      delegation_changes: { role: 'companion', primary: 'forwarding_changes' },
    });
  });

  it('points every companion at a primary of the same provider', () => {
    for (const kind of ATO_PROVIDER_KINDS) {
      for (const stream of PROVIDER_STREAMS) {
        const definition = STREAM_ROLES[kind][stream];
        if (definition.role === 'companion') {
          expect(definition.primary && STREAM_ROLES[kind][definition.primary].role).toBe('primary');
        }
        expect(primaryOf(kind, stream)).toBe(
          definition.role === 'primary'
            ? stream
            : definition.role === 'companion'
              ? definition.primary
              : null,
        );
      }
    }
  });
});

describe('PERMISSION_REQUIREMENTS (D5, §3)', () => {
  it('covers every stream and action of both providers consistently with STREAM_ROLES', () => {
    for (const kind of ATO_PROVIDER_KINDS) {
      const requirements = PERMISSION_REQUIREMENTS[kind];
      expect(requirements.provider).toBe(kind);
      expect(Object.keys(requirements.streams).sort()).toEqual([...PROVIDER_STREAMS].sort());
      expect(Object.keys(requirements.actions).sort()).toEqual([...PROVIDER_ACTION_TYPES].sort());
      for (const stream of PROVIDER_STREAMS) {
        const requirement = requirements.streams[stream];
        expect(requirement.role).toBe(STREAM_ROLES[kind][stream].role);
        expect(requirement.notes.length).toBeGreaterThan(0);
        if (requirement.role === 'unsupported') {
          expect(requirement.profile).toBeNull();
          continue;
        }
        const profile = requirements.profiles.find((p) => p.key === requirement.profile);
        expect(profile?.purpose).toBe('ato_telemetry');
        const granted = profile?.permissions.map((p) => p.name) ?? [];
        for (const permission of [
          ...requirement.permissions,
          ...(requirement.optionalPermissions ?? []),
        ]) {
          expect(granted, `${kind} ${stream} ${permission}`).toContain(permission);
        }
      }
      for (const action of PROVIDER_ACTION_TYPES) {
        const requirement = requirements.actions[action];
        expect(requirement.supported).toBe(true);
        const profile = requirements.profiles.find((p) => p.key === requirement.profile);
        expect(profile?.purpose).toBe('ato_response');
        expect(profile?.readOnly).toBe(false);
        for (const permission of requirement.permissions) {
          expect(
            profile?.permissions.map((p) => p.name),
            `${kind} ${action}`,
          ).toContain(permission);
        }
      }
    }
  });

  it('has the six profiles of D5 with disjoint purposes', () => {
    expect(
      PERMISSION_REQUIREMENTS.microsoft_entra.profiles.map((p) => [p.key, p.purpose, p.readOnly]),
    ).toEqual([
      ['m365.ato_telemetry', 'ato_telemetry', true],
      ['m365.ato_response', 'ato_response', false],
      ['m365.ato_response_extended', 'ato_response', false],
    ]);
    expect(
      PERMISSION_REQUIREMENTS.google_workspace.profiles.map((p) => [p.key, p.purpose, p.readOnly]),
    ).toEqual([
      ['google.ato_telemetry', 'ato_telemetry', false],
      ['google.ato_response', 'ato_response', false],
      ['google.ato_response_extended', 'ato_response', false],
    ]);
    const telemetry =
      PERMISSION_REQUIREMENTS.microsoft_entra.profiles[0]?.permissions.map((p) => p.name) ?? [];
    expect(telemetry.some((name) => /ReadWrite|RevokeSessions|EnableDisable/.test(name))).toBe(
      false,
    );
  });

  it('requires configuration for MFA enforcement on each provider', () => {
    expect(PERMISSION_REQUIREMENTS.microsoft_entra.actions.require_mfa.requiresConfiguration).toBe(
      'mfaEnforcement.groupId',
    );
    expect(PERMISSION_REQUIREMENTS.google_workspace.actions.require_mfa.requiresConfiguration).toBe(
      'mfaEnforcement.orgUnitPath',
    );
    expect(PERMISSION_REQUIREMENTS.google_workspace.actions.require_mfa.impact).toBe('high');
  });
});

describe('PERMISSION_REQUIREMENTS: Google Workspace (D5, §3.3)', () => {
  const google = PERMISSION_REQUIREMENTS.google_workspace;
  const scopes = (key: string) =>
    google.profiles.find((p) => p.key === key)?.permissions.map((p) => p.name) ?? [];

  it('lists the D5 scopes per profile, all OAuth scopes under googleapis.com/auth', () => {
    expect(scopes(GOOGLE_PROFILES.telemetry)).toEqual([
      GOOGLE_SCOPES.reportsAudit,
      GOOGLE_SCOPES.directoryUserReadonly,
      GOOGLE_SCOPES.gmailSettingsBasic,
    ]);
    expect(scopes(GOOGLE_PROFILES.response)).toEqual([
      GOOGLE_SCOPES.directoryUser,
      GOOGLE_SCOPES.directoryUserSecurity,
      GOOGLE_SCOPES.gmailSettingsBasic,
      GOOGLE_SCOPES.gmailSettingsSharing,
    ]);
    expect(scopes(GOOGLE_PROFILES.responseExtended)).toEqual([
      GOOGLE_SCOPES.directoryUser,
      GOOGLE_SCOPES.directoryOrgunitReadonly,
    ]);
    for (const profile of google.profiles) {
      for (const permission of profile.permissions) {
        expect(permission.api).toBe('google_oauth_scope');
        expect(permission.name).toMatch(/^https:\/\/www\.googleapis\.com\/auth\/[a-z.]+$/);
      }
    }
    // Telemetry: read-only scopes except gmail.settings.basic (no read-only settings scope, PQ14).
    expect(scopes(GOOGLE_PROFILES.telemetry).filter((name) => !/readonly$/.test(name))).toEqual([
      GOOGLE_SCOPES.gmailSettingsBasic,
    ]);
  });

  it('maps streams to the Google feeds and every action to the scope of its write', () => {
    expect(google.streams.sign_ins.permissions).toEqual([GOOGLE_SCOPES.reportsAudit]);
    expect(google.streams.oauth_consents.permissions).toEqual([GOOGLE_SCOPES.reportsAudit]);
    expect(google.streams.forwarding_changes.permissions).toEqual([
      GOOGLE_SCOPES.gmailSettingsBasic,
      GOOGLE_SCOPES.directoryUserReadonly,
    ]);
    expect(google.streams.session_events).toMatchObject({ role: 'unsupported', profile: null });
    expect(google.actions.revoke_sessions.permissions).toContain(
      GOOGLE_SCOPES.directoryUserSecurity,
    );
    expect(google.actions.revoke_oauth_grant.permissions).toContain(
      GOOGLE_SCOPES.directoryUserSecurity,
    );
    expect(google.actions.remove_forwarding_rule.permissions).toEqual(
      expect.arrayContaining([
        GOOGLE_SCOPES.gmailSettingsBasic,
        GOOGLE_SCOPES.gmailSettingsSharing,
      ]),
    );
    expect(google.actions.require_mfa.profile).toBe(GOOGLE_PROFILES.responseExtended);
    // Every action reads the directory user for the linked-domain guard.
    for (const action of PROVIDER_ACTION_TYPES) {
      expect(google.actions[action].permissions, action).toContain(GOOGLE_SCOPES.directoryUser);
    }
  });

  it('matches the adapters’ declared capabilities (rollback and confirmation per action)', () => {
    for (const [kind, declared] of [
      ['google_workspace', GOOGLE_DECLARED_CAPABILITIES],
      ['microsoft_entra', MICROSOFT_DECLARED_CAPABILITIES],
    ] as const) {
      for (const action of PROVIDER_ACTION_TYPES) {
        const requirement = PERMISSION_REQUIREMENTS[kind].actions[action];
        expect(declared.actions[action], `${kind} ${action}`).toEqual({
          supported: requirement.supported,
          rollback: requirement.rollback,
          confirmation: requirement.confirmation,
        });
      }
      for (const stream of PROVIDER_STREAMS) {
        expect(declared.streams[stream]?.supported, `${kind} ${stream}`).toBe(
          STREAM_ROLES[kind][stream].role !== 'unsupported',
        );
      }
    }
  });
});

describe('PROVIDER_RETENTION_DAYS (D8.1)', () => {
  it('matches the provider retention constants', () => {
    expect(PROVIDER_RETENTION_DAYS.microsoft_entra).toMatchObject({
      sign_ins: 30,
      risk_events: 90,
      oauth_consents: 30,
      mailbox_audit: 7,
    });
    expect(PROVIDER_RETENTION_DAYS.google_workspace).toMatchObject({
      sign_ins: 180,
      oauth_consents: 180,
      forwarding_changes: 0,
    });
  });
});
