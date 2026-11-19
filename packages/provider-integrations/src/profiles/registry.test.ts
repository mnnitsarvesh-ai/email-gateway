import { describe, expect, it } from 'vitest';
import {
  comparePermissions,
  GOOGLE_MAIL_FLOW_PROFILE,
  M365_MAIL_FLOW_PROFILE,
  mailFlowDenyReason,
  mailFlowProfileFor,
  PERMISSION_PROFILES,
  PermissionProfileError,
  profileByKey,
  profilesFor,
  registerPermissionProfiles,
  requireProfile,
  validatePermissionProfile,
  type PermissionProfile,
} from './index';

const base = (overrides: Partial<PermissionProfile>): PermissionProfile => ({
  ...M365_MAIL_FLOW_PROFILE,
  key: 'm365.test_profile',
  ...overrides,
});

describe('permission profiles', () => {
  it('registers the two read-only mail-flow profiles at load', () => {
    expect(profileByKey('m365.mail_flow')).toBe(M365_MAIL_FLOW_PROFILE);
    expect(profileByKey('google.mail_flow')).toBe(GOOGLE_MAIL_FLOW_PROFILE);
    expect(PERMISSION_PROFILES.filter((p) => p.purpose === 'mail_flow')).toHaveLength(2);
    expect(mailFlowProfileFor('microsoft_365').permissions).toEqual([
      'Organization.Read.All',
      'Domain.Read.All',
    ]);
    expect(
      mailFlowProfileFor('google_workspace').permissions.every((s) => s.endsWith('.readonly')),
    ).toBe(true);
    for (const profile of [M365_MAIL_FLOW_PROFILE, GOOGLE_MAIL_FLOW_PROFILE]) {
      expect(profile.readOnly).toBe(true);
      expect(validatePermissionProfile(profile)).toEqual([]);
    }
  });

  it('names configuration keys, never values (D-WP1-1 _PATH keys)', () => {
    expect(M365_MAIL_FLOW_PROFILE.platformApp).toEqual({
      clientIdKey: 'PROVIDER_M365_MAILFLOW_APP_CLIENT_ID',
      secretKey: 'PROVIDER_M365_MAILFLOW_APP_CLIENT_SECRET',
      certFileKey: 'PROVIDER_M365_MAILFLOW_APP_CERT_PATH',
      certThumbprintKey: 'PROVIDER_M365_MAILFLOW_APP_CERT_THUMBPRINT',
    });
    expect(GOOGLE_MAIL_FLOW_PROFILE.platformApp).toEqual({
      clientIdKey: 'PROVIDER_GOOGLE_MAILFLOW_SA_CLIENT_ID',
      saKeyFileKey: 'PROVIDER_GOOGLE_MAILFLOW_SA_KEY_PATH',
    });
  });

  it.each([
    'Mail.Read',
    'Mail.ReadWrite',
    'Mail.Send',
    'MailboxSettings.Read',
    'Exchange.ManageAsApp',
    'full_access_as_app',
    'Directory.Read.All',
    'User.Read.All',
    'Policy.Read.All',
    'Application.Read.All',
    'Domain.ReadWrite.All',
  ])('the mail_flow deny list refuses the Microsoft permission %s', (permission) => {
    expect(mailFlowDenyReason('microsoft_365', permission)).not.toBeNull();
    expect(() =>
      registerPermissionProfiles([
        base({ key: 'm365.deny_test', permissions: ['Organization.Read.All', permission] }),
      ]),
    ).toThrow(PermissionProfileError);
  });

  it.each([
    'https://mail.google.com/',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.settings.basic',
    'https://www.googleapis.com/auth/admin.directory.domain',
    'https://www.googleapis.com/auth/admin.directory.user',
  ])('the mail_flow deny list refuses the Google scope %s', (scope) => {
    expect(mailFlowDenyReason('google_workspace', scope)).not.toBeNull();
    expect(() =>
      registerPermissionProfiles([
        { ...GOOGLE_MAIL_FLOW_PROFILE, key: 'google.deny_test', permissions: [scope] },
      ]),
    ).toThrow(PermissionProfileError);
  });

  it('refuses invalid profiles', () => {
    const cases: Partial<PermissionProfile>[] = [
      { key: 'Bad Key' },
      { key: `m365.${'x'.repeat(60)}` },
      { version: 0 },
      { permissions: [] },
      { permissions: ['Domain.Read.All', 'Domain.Read.All'] },
      { authMethods: ['platform_service_account'] },
      { readOnly: false },
      { platformApp: { clientIdKey: 'a-client-id-value' } },
      { title: ' ' },
    ];
    for (const overrides of cases) {
      expect(
        validatePermissionProfile(base(overrides)).length,
        JSON.stringify(overrides),
      ).toBeGreaterThan(0);
    }
    // A read-only profile of any purpose may not declare a write permission.
    expect(
      validatePermissionProfile(
        base({
          purpose: 'ato_telemetry',
          permissions: ['MailboxSettings.ReadWrite'],
          readOnly: true,
        }),
      ),
    ).toContain('read-only profile declares the write permission MailboxSettings.ReadWrite');
  });

  it('refuses duplicate keys and accepts re-registration of the same object', () => {
    expect(() => registerPermissionProfiles([{ ...M365_MAIL_FLOW_PROFILE }])).toThrow(
      /already registered/,
    );
    expect(() => registerPermissionProfiles([M365_MAIL_FLOW_PROFILE])).not.toThrow();
  });

  it('registers a later step’s profiles by concatenation (8.5 ATO profile, versioned)', () => {
    const ato: PermissionProfile = {
      key: 'm365.ato_test_telemetry',
      version: 3,
      provider: 'microsoft_365',
      purpose: 'ato_telemetry',
      readOnly: true,
      permissions: ['AuditLog.Read.All', 'IdentityRiskEvent.Read.All'],
      authMethods: ['platform_app', 'customer_app_secret'],
      platformApp: { clientIdKey: 'PROVIDER_M365_ATO_TEST_APP_CLIENT_ID' },
      title: 'Test ATO telemetry',
      description: 'Reads sign-in telemetry (test profile).',
    };
    const before = PERMISSION_PROFILES.length;
    registerPermissionProfiles([ato]);
    expect(PERMISSION_PROFILES).toHaveLength(before + 1);
    expect(requireProfile('m365.ato_test_telemetry').version).toBe(3);
    expect(profilesFor('microsoft_365', 'ato_telemetry').map((p) => p.key)).toContain(
      'm365.ato_test_telemetry',
    );
    expect(mailFlowProfileFor('microsoft_365')).toBe(M365_MAIL_FLOW_PROFILE);
    expect(() => requireProfile('m365.unknown')).toThrow(PermissionProfileError);
  });

  it('compares observed permissions (missing and excess, case-insensitive)', () => {
    expect(
      comparePermissions(M365_MAIL_FLOW_PROFILE, ['organization.read.all', 'Mail.Read']),
    ).toEqual({
      missing: ['Domain.Read.All'],
      excess: ['Mail.Read'],
    });
    expect(
      comparePermissions(M365_MAIL_FLOW_PROFILE, [...M365_MAIL_FLOW_PROFILE.permissions]),
    ).toEqual({
      missing: [],
      excess: [],
    });
  });
});
