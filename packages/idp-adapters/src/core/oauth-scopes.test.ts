import { RISKY_OAUTH_SCOPES } from '@email-gateway/ato-detection';
import { describe, expect, it } from 'vitest';
import { eventIdPart, safeDisplayText } from './normalize';
import { oauthScopeCode, oauthScopeCodes } from './oauth-scopes';

const CODE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;

describe('OAuth scope codes for 8.4 (WP3-2)', () => {
  it('maps Microsoft scopes onto 8.4’s risky classes and other scopes onto codes', () => {
    expect(oauthScopeCode('microsoft_entra', 'Mail.Read')).toBe('mail_read');
    expect(oauthScopeCode('microsoft_entra', 'Mail.ReadWrite')).toBe('mail_read');
    expect(oauthScopeCode('microsoft_entra', 'IMAP.AccessAsUser.All')).toBe('mail_read');
    expect(oauthScopeCode('microsoft_entra', 'Mail.Send')).toBe('mail_send');
    expect(oauthScopeCode('microsoft_entra', 'full_access_as_app')).toBe('full_access');
    expect(oauthScopeCode('microsoft_entra', 'offline_access')).toBe('offline_access');
    expect(oauthScopeCode('microsoft_entra', 'User.Read')).toBe('user_read');
    expect(oauthScopeCode('microsoft_entra', '  ')).toBeUndefined();
  });

  it('maps Google scope URLs onto the same classes, stripping the scope prefix', () => {
    const g = (s: string) => oauthScopeCode('google_workspace', s);
    expect(g('https://mail.google.com/')).toBe('full_access');
    expect(g('https://www.googleapis.com/auth/gmail.readonly')).toBe('mail_read');
    expect(g('https://www.googleapis.com/auth/gmail.modify')).toBe('mail_read');
    expect(g('https://www.googleapis.com/auth/gmail.send')).toBe('mail_send');
    expect(g('https://www.googleapis.com/auth/drive.file')).toBe('drive_file');
    expect(g('openid')).toBe('openid');
  });

  it('produces distinct 8.4 codes only, bounded', () => {
    const codes = oauthScopeCodes('microsoft_entra', [
      'Mail.Read',
      'Mail.ReadWrite',
      'Mail.Send',
      ...Array.from({ length: 80 }, (_, i) => `Custom.Scope${i}`),
    ]);
    expect(codes.slice(0, 2)).toEqual(['mail_read', 'mail_send']);
    expect(codes).toHaveLength(50);
    for (const code of codes) expect(code).toMatch(CODE);
    for (const risky of RISKY_OAUTH_SCOPES) {
      expect(['mail_read', 'mail_send', 'full_access', 'offline_access']).toContain(risky);
    }
  });
});

describe('event id parts and display text against 8.4’s secret-shape guard', () => {
  it('hashes token-shaped provider ids and keeps GUIDs and short ids', () => {
    const longHex = 'ab12'.repeat(16); // 64 characters, like an Entra risk detection id
    const part = eventIdPart(longHex);
    expect(part).toMatch(/^h[0-9a-f]{32}$/);
    expect(eventIdPart(longHex)).toBe(part);
    const guid = 'aaaaaaaa-0000-4000-8000-000000000001';
    expect(eventIdPart(guid)).toBe(guid);
    expect(eventIdPart('-7700001')).toBe('-7700001');
  });

  it('drops token-shaped display names', () => {
    expect(safeDisplayText('Mail Helper Example', 128)).toBe('Mail Helper Example');
    expect(safeDisplayText('x'.repeat(48), 128)).toBeUndefined();
  });
});
