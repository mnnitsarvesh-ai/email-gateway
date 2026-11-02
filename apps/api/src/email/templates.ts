import type { OutboundEmail } from './email-sender';

/** Portal pages that consume single-use tokens (they arrive with step 7.x). */
export type PortalAuthPath = 'accept-invitation' | 'reset-password' | 'verify-email';

/**
 * `${PORTAL_PUBLIC_URL}/auth/<path>#token=<token>` (pass `config.PORTAL_PUBLIC_URL`). The token
 * travels in the fragment, so it never reaches server logs or a `Referer` header.
 */
export function buildPortalLink(
  path: PortalAuthPath,
  token: string,
  portalPublicUrl: string,
): string {
  return `${portalPublicUrl.replace(/\/+$/, '')}/auth/${path}#token=${encodeURIComponent(token)}`;
}

function formatExpiry(expiresAt: Date): string {
  return `${expiresAt.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

/** Strips CR/LF so user-controlled names cannot inject lines into the body. */
function oneLine(value: string): string {
  return value.replace(/[\r\n]+/g, ' ').trim();
}

export interface InvitationEmailInput {
  to: string;
  displayName: string;
  organizationName: string;
  link: string;
  expiresAt: Date;
}

export function invitationEmail(input: InvitationEmailInput): OutboundEmail {
  const org = oneLine(input.organizationName);
  return {
    kind: 'invitation',
    to: input.to,
    subject: `You are invited to ${org} on Email Security Gateway`,
    text: [
      `Hello ${oneLine(input.displayName)},`,
      '',
      `You have been invited to join ${org} on Email Security Gateway.`,
      'Open the link below to choose a password and activate your account:',
      '',
      input.link,
      '',
      `The link expires at ${formatExpiry(input.expiresAt)} and can be used once.`,
      'If you did not expect this invitation, you can ignore this email.',
    ].join('\n'),
    devLink: input.link,
  };
}

export interface PasswordResetEmailInput {
  to: string;
  link: string;
  expiresAt: Date;
}

export function passwordResetEmail(input: PasswordResetEmailInput): OutboundEmail {
  return {
    kind: 'password_reset',
    to: input.to,
    subject: 'Reset your Email Security Gateway password',
    text: [
      'A password reset was requested for your Email Security Gateway account.',
      'Open the link below to choose a new password:',
      '',
      input.link,
      '',
      `The link expires at ${formatExpiry(input.expiresAt)} and can be used once.`,
      'Resetting your password signs you out everywhere.',
      'If you did not request this, ignore this email; your password stays unchanged.',
    ].join('\n'),
    devLink: input.link,
  };
}

export interface EmailVerificationEmailInput {
  to: string;
  link: string;
  expiresAt: Date;
}

export function emailVerificationEmail(input: EmailVerificationEmailInput): OutboundEmail {
  return {
    kind: 'email_verification',
    to: input.to,
    subject: 'Verify your email address for Email Security Gateway',
    text: [
      'Please confirm that this address belongs to your Email Security Gateway account:',
      '',
      input.link,
      '',
      `The link expires at ${formatExpiry(input.expiresAt)} and can be used once.`,
      'If you did not create or change an account, you can ignore this email.',
    ].join('\n'),
    devLink: input.link,
  };
}
