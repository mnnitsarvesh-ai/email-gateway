import { describe, expect, it } from 'vitest';
import { grantsForCheck, healthCheckByCode } from '../health';
import { isMailFlowGrant } from '../health/checks';
import { platformCredentialsFromEnv } from '../tokens/platform-credentials';
import {
  ATO_PROFILES,
  comparePermissions,
  GOOGLE_ATO_TELEMETRY_PROFILE,
  M365_ATO_TELEMETRY_PROFILE,
  MAIL_FLOW_PROFILES,
  PERMISSION_PROFILES,
  profilesFor,
  requireProfile,
  validatePermissionProfile,
} from './index';

describe('step 8.5 ATO permission profiles (D5)', () => {
  it('registers the six profiles after 8.2’s mail-flow profiles', () => {
    const keys = PERMISSION_PROFILES.map((p) => p.key);
    expect(keys.slice(0, MAIL_FLOW_PROFILES.length)).toEqual(MAIL_FLOW_PROFILES.map((p) => p.key));
    for (const profile of ATO_PROFILES) {
      expect(requireProfile(profile.key)).toBe(profile);
      expect(validatePermissionProfile(profile)).toEqual([]);
    }
    expect(profilesFor('microsoft_365', 'ato_telemetry').map((p) => p.key)).toEqual([
      'm365.ato_telemetry',
    ]);
    expect(profilesFor('google_workspace', 'ato_response').map((p) => p.key)).toEqual([
      'google.ato_response',
      'google.ato_response_extended',
    ]);
  });

  it('keeps telemetry free of write permissions (Microsoft) and names config keys only', () => {
    expect(M365_ATO_TELEMETRY_PROFILE.readOnly).toBe(true);
    expect(GOOGLE_ATO_TELEMETRY_PROFILE.readOnly).toBe(false); // gmail.settings.basic (PQ14)
    for (const profile of ATO_PROFILES) {
      expect(profile.purpose.startsWith('ato_')).toBe(true);
      for (const key of Object.values(profile.platformApp)) {
        expect(key).toMatch(/^PROVIDER_(M365|GOOGLE)_ATO_[A-Z_]+$/);
      }
    }
    expect(M365_ATO_TELEMETRY_PROFILE.platformApp).toEqual({
      clientIdKey: 'PROVIDER_M365_ATO_TELEMETRY_APP_CLIENT_ID',
      secretKey: 'PROVIDER_M365_ATO_TELEMETRY_APP_CLIENT_SECRET',
      certFileKey: 'PROVIDER_M365_ATO_TELEMETRY_APP_CERT_PATH',
      certThumbprintKey: 'PROVIDER_M365_ATO_TELEMETRY_APP_CERT_THUMBPRINT',
    });
    expect(GOOGLE_ATO_TELEMETRY_PROFILE.platformApp).toEqual({
      clientIdKey: 'PROVIDER_GOOGLE_ATO_TELEMETRY_SA_CLIENT_ID',
      saKeyFileKey: 'PROVIDER_GOOGLE_ATO_TELEMETRY_SA_KEY_PATH',
    });
  });

  it('WP6: ActivityFeed.Read is never expected in the Graph token (notInToken)', () => {
    expect(M365_ATO_TELEMETRY_PROFILE.notInToken).toEqual(['ActivityFeed.Read']);
    const graphOnly = M365_ATO_TELEMETRY_PROFILE.permissions.filter(
      (p) => p !== 'ActivityFeed.Read',
    );
    expect(comparePermissions(M365_ATO_TELEMETRY_PROFILE, graphOnly)).toEqual({
      missing: [],
      excess: [],
    });
    expect(comparePermissions(M365_ATO_TELEMETRY_PROFILE, ['User.Read.All']).missing).toEqual(
      graphOnly.filter((p) => p !== 'User.Read.All'),
    );
    for (const profile of ATO_PROFILES.filter((p) => p !== M365_ATO_TELEMETRY_PROFILE)) {
      expect(profile.notInToken).toBeUndefined();
    }
  });

  it('R2: 8.2’s generic per-grant checks skip ATO grants', () => {
    const grants = [{ profile: 'm365.mail_flow' }, { profile: 'm365.ato_telemetry' }];
    expect(grants.filter(isMailFlowGrant)).toEqual([{ profile: 'm365.mail_flow' }]);
    for (const code of ['credentials.token', 'permissions.granted']) {
      expect(grantsForCheck(healthCheckByCode(code)!, grants)).toEqual([
        { profile: 'm365.mail_flow' },
      ]);
    }
  });

  it('empty platform keys mean no platform app (customer-owned methods only)', () => {
    const platform = platformCredentialsFromEnv({}, ATO_PROFILES, {
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
