import { EmailSender, type EmailKind, type OutboundEmail } from '../../src/email/email-sender';

const TOKEN = /#token=([A-Za-z0-9_%-]+)/;

/** Test double: keeps every email instead of sending it. Tests never send real email (D13). */
export class RecordingEmailSender extends EmailSender {
  readonly transport = 'log' as const;
  readonly sent: OutboundEmail[] = [];
  /** Set to make `send` reject (delivery failure paths). */
  failWith: Error | undefined;

  send(email: OutboundEmail): Promise<void> {
    if (this.failWith) return Promise.reject(this.failWith);
    this.sent.push(email);
    return Promise.resolve();
  }

  /** The most recent email of `kind` to `to` (case-insensitive address). */
  lastFor(to: string, kind: EmailKind): OutboundEmail | undefined {
    const address = to.toLowerCase();
    return [...this.sent]
      .reverse()
      .find((email) => email.kind === kind && email.to.toLowerCase() === address);
  }

  /** The token of the most recent matching email (from its devLink, else its text). */
  tokenFor(to: string, kind: EmailKind): string | undefined {
    const email = this.lastFor(to, kind);
    return email ? extractToken(email) : undefined;
  }

  clear(): void {
    this.sent.length = 0;
  }
}

/** Extracts the `#token=` fragment value of an email's link. */
export function extractToken(email: OutboundEmail): string | undefined {
  const match = TOKEN.exec(email.devLink ?? '') ?? TOKEN.exec(email.text);
  return match?.[1] ? decodeURIComponent(match[1]) : undefined;
}
