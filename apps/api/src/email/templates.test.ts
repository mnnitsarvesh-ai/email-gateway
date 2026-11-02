import { describe, expect, it } from 'vitest';
import {
  buildPortalLink,
  emailVerificationEmail,
  invitationEmail,
  passwordResetEmail,
} from './templates';

const token = 'egt_abcDEF123_-abcDEF123_-abcDEF123_-abcDEF1';
const expiresAt = new Date('2026-11-09T08:30:00Z');

describe('buildPortalLink', () => {
  it('puts the token in the fragment', () => {
    expect(buildPortalLink('accept-invitation', token, 'https://portal.example.com')).toBe(
      `https://portal.example.com/auth/accept-invitation#token=${token}`,
    );
  });

  it('tolerates a trailing slash on the portal URL', () => {
    expect(buildPortalLink('verify-email', token, 'http://localhost:3001/')).toBe(
      `http://localhost:3001/auth/verify-email#token=${token}`,
    );
  });
});

describe('email builders', () => {
  const link = buildPortalLink('accept-invitation', token, 'https://portal.example.com');

  it('invitation names the organization and expiry and carries the dev link', () => {
    const email = invitationEmail({
      to: 'new@example.com',
      displayName: 'New User',
      organizationName: 'Acme',
      link,
      expiresAt,
    });
    expect(email).toMatchObject({ kind: 'invitation', to: 'new@example.com', devLink: link });
    expect(email.subject).toContain('Acme');
    expect(email.text).toContain(link);
    expect(email.text).toContain('2026-11-09 08:30 UTC');
  });

  it('strips line breaks from names so they cannot inject content', () => {
    const email = invitationEmail({
      to: 'new@example.com',
      displayName: 'Eve\r\nBcc: x@evil.example',
      organizationName: 'Acme\nInc',
      link,
      expiresAt,
    });
    expect(email.subject).not.toMatch(/[\r\n]/);
    expect(email.text).toContain('Hello Eve Bcc: x@evil.example,');
  });

  it('password reset and verification emails have their kinds and links', () => {
    expect(passwordResetEmail({ to: 'a@example.com', link, expiresAt })).toMatchObject({
      kind: 'password_reset',
      devLink: link,
    });
    const verification = emailVerificationEmail({ to: 'a@example.com', link, expiresAt });
    expect(verification).toMatchObject({ kind: 'email_verification', devLink: link });
    expect(verification.text).toContain(link);
  });
});
