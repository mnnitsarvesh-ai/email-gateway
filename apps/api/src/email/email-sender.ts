export type EmailKind = 'invitation' | 'password_reset' | 'email_verification';

/** A plain-text transactional email (D13). */
export interface OutboundEmail {
  to: string;
  subject: string;
  text: string;
  kind: EmailKind;
  /**
   * The link with its token, logged by `LogEmailSender` only in local/CI non-production mode so
   * developers can follow it without a relay. Never logged anywhere else.
   */
  devLink?: string;
}

/**
 * Delivery port for transactional email. `SmtpEmailSender` when NOTIFY_SMTP_HOST is set,
 * otherwise `LogEmailSender`. Callers send after their transaction commits; a failure is logged
 * and does not roll anything back.
 */
export abstract class EmailSender {
  /** Transport name for the startup log line. */
  abstract readonly transport: 'smtp' | 'log';
  abstract send(email: OutboundEmail): Promise<void>;
}

/** `alice@example.com` → `a***@example.com`, for logs. */
export function maskEmail(address: string): string {
  const at = address.lastIndexOf('@');
  if (at < 1) return '***';
  return `${address[0]}***${address.slice(at)}`;
}
