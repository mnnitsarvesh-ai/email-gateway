import { describe, expect, it } from 'vitest';
import { grantsForCheck, healthCheckByCode } from '../health';
import { isMailFlowGrant } from '../health/checks';
import { platformCredentialsFromEnv } from '../tokens/platform-credentials';
import {
  ATO_PROFILES,
  comparePermissions,
  GOOGLE_MAILBOX_REMEDIATION_PROFILE,
  M365_MAILBOX_REMEDIATION_PROFILE,
  MAIL_FLOW_PROFILES,
  MAILBOX_PROFILE_KEYS,
  MAILBOX_PROFILES,
  mailFlowDenyReason,
  mailFlowProfileFor,
  PERMISSION_PROFILES,
  PERMISSION_PURPOSES,
  profilesFor,
  requireProfile,
  validatePermissionProfile,
} from './index';

describe('step API-1 mailbox-access permission profiles (D4)', () => {
  it('appends the purpose and registers both profiles after the mail-flow and ATO profiles', () => {
    expect(PERMISSION_PURPOSES).toEqual([
      'mail_flow',
      'ato_telemetry',
      'ato_response',
      'mailbox_remediation',
    ]);
    const keys = PERMISSION_PROFILES.map((p) => p.key);
    const before = [...MAIL_FLOW_PROFILES, ...ATO_PROFILES].map((p) => p.key);
    expect(keys.slice(0, before.length)).toEqual(before);
    expect(keys.slice(before.length)).toEqual([
      'm365.mailbox_remediation',
      'google.mailbox_remediation',
    ]);
    for (const profile of MAILBOX_PROFILES) {
      expect(requireProfile(profile.key)).toBe(profile);
      expect(validatePermissionProfile(profile)).toEqual([]);
      expect(profile.purpose).toBe('mailbox_remediation');
      expect(profile.readOnly).toBe(false);
    }
    expect(profilesFor('microsoft_365', 'mailbox_remediation')).toEqual([
      M365_MAILBOX_REMEDIATION_PROFILE,
    ]);
    expect(profilesFor('google_workspace', 'mailbox_remediation')).toEqual([
      GOOGLE_MAILBOX_REMEDIATION_PROFILE,
    ]);
    expect(MAILBOX_PROFILE_KEYS).toEqual({
      microsoft_365: 'm365.mailbox_remediation',
      google_workspace: 'google.mailbox_remediation',
    });
  });

  it('declares exactly the D4 permissions, auth methods and configuration key names', () => {
    expect(M365_MAILBOX_REMEDIATION_PROFILE.permissions).toEqual([
      'Mail.ReadWrite',
      'User.Read.All',
    ]);
    expect(M365_MAILBOX_REMEDIATION_PROFILE.authMethods).toEqual([
      'platform_app',
      'customer_app_secret',
    ]);
    expect(M365_MAILBOX_REMEDIATION_PROFILE.platformApp).toEqual({
      clientIdKey: 'PROVIDER_M365_MAILBOX_APP_CLIENT_ID',
      secretKey: 'PROVIDER_M365_MAILBOX_APP_CLIENT_SECRET',
      certFileKey: 'PROVIDER_M365_MAILBOX_APP_CERT_PATH',
      certThumbprintKey: 'PROVIDER_M365_MAILBOX_APP_CERT_THUMBPRINT',
    });
    expect(GOOGLE_MAILBOX_REMEDIATION_PROFILE.permissions).toEqual([
      'https://www.googleapis.com/auth/gmail.modify',
      'https://www.googleapis.com/auth/admin.directory.user.readonly',
    ]);
    expect(GOOGLE_MAILBOX_REMEDIATION_PROFILE.authMethods).toEqual([
      'platform_service_account',
      'customer_service_account',
    ]);
    expect(GOOGLE_MAILBOX_REMEDIATION_PROFILE.platformApp).toEqual({
      clientIdKey: 'PROVIDER_GOOGLE_MAILBOX_SA_CLIENT_ID',
      saKeyFileKey: 'PROVIDER_GOOGLE_MAILBOX_SA_KEY_PATH',
    });
    for (const profile of MAILBOX_PROFILES) {
      expect(profile.notInToken).toBeUndefined();
      expect(profile.title).toBe('Mailbox access for API mode');
      expect(profile.description).toContain('API-mode');
      expect(profile.description).toContain('Separate from the mail-flow');
      expect(profile.description).toContain('Step API-1 only reads');
      expect(profile.description).toContain('API-2');
    }
  });

  it('allows the write permissions for this purpose while the mail_flow deny list is unchanged', () => {
    // The very permissions the mail_flow deny list refuses stay refused for mail_flow …
    expect(mailFlowDenyReason('microsoft_365', 'Mail.ReadWrite')).not.toBeNull();
    expect(mailFlowDenyReason('microsoft_365', 'User.Read.All')).not.toBeNull();
    expect(
      mailFlowDenyReason('google_workspace', 'https://www.googleapis.com/auth/gmail.modify'),
    ).not.toBeNull();
    expect(
      validatePermissionProfile({ ...M365_MAILBOX_REMEDIATION_PROFILE, purpose: 'mail_flow' }),
    ).not.toEqual([]);
    // … and the mail_flow profiles are untouched.
    expect(mailFlowProfileFor('microsoft_365').permissions).toEqual([
      'Organization.Read.All',
      'Domain.Read.All',
    ]);
    // A read-only flag would be refused for these write permissions.
    expect(
      validatePermissionProfile({ ...M365_MAILBOX_REMEDIATION_PROFILE, readOnly: true }),
    ).toContain('read-only profile declares the write permission Mail.ReadWrite');
  });

  it('compares observed permissions for verification (verifyAuxiliary)', () => {
    expect(
      comparePermissions(M365_MAILBOX_REMEDIATION_PROFILE, ['User.Read.All', 'Mail.ReadWrite']),
    ).toEqual({ missing: [], excess: [] });
    expect(comparePermissions(M365_MAILBOX_REMEDIATION_PROFILE, ['User.Read.All'])).toEqual({
      missing: ['Mail.ReadWrite'],
      excess: [],
    });
  });

  it('8.2’s generic per-grant checks skip mailbox grants (not mail_flow)', () => {
    const grants = [{ profile: 'm365.mail_flow' }, { profile: 'm365.mailbox_remediation' }];
    expect(grants.filter(isMailFlowGrant)).toEqual([{ profile: 'm365.mail_flow' }]);
    expect(grantsForCheck(healthCheckByCode('permissions.granted')!, grants)).toEqual([
      { profile: 'm365.mail_flow' },
    ]);
  });

  it('empty platform keys mean no platform app (customer-owned methods only)', () => {
    const platform = platformCredentialsFromEnv({}, MAILBOX_PROFILES, {
      readFile: () => {
        throw new Error('no file expected');
      },
      googleTokenUrl: 'https://oauth2.googleapis.com/token',
      allowPlatformSecret: false,
    });
    expect(platform.microsoft.size).toBe(0);
    expect(platform.google.size).toBe(0);
  });
});
