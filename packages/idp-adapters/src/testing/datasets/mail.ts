/**
 * Synthetic EMLs for the mailbox simulators (step API-1 D13): `.example` domains, documentation
 * hosts and addresses only, no real person, credential or secret-shaped value.
 */

export interface SyntheticEmlOptions {
  /** `Message-ID` value without angle brackets; omitted header when null. */
  messageId?: string | null;
  from?: string;
  to?: readonly string[];
  cc?: readonly string[];
  subject?: string;
  /** `Date:` header (RFC 5322). */
  date?: Date;
  /** Topmost `Received:` header date; no Received header when omitted. */
  receivedAt?: Date;
  /** Body text (CRLF line endings are applied). */
  body?: string;
  /** Pads the body to at least this many bytes (large-message tests). */
  minBytes?: number;
}

let counter = 0;

/** An RFC 5322 date (`Tue, 10 Nov 2026 12:00:00 +0000`). */
export function rfc5322Date(date: Date): string {
  return date.toUTCString().replace('GMT', '+0000');
}

/** A synthetic RFC 5322 message with CRLF line endings. */
export function syntheticEml(options: SyntheticEmlOptions = {}): string {
  counter += 1;
  const date = options.date ?? new Date('2026-11-10T11:59:00.000Z');
  const messageId =
    options.messageId === undefined ? `sim-${counter}@mail.example` : options.messageId;
  const headers = [
    ...(options.receivedAt
      ? [
          'Received: from mx.sender.example (mx.sender.example [192.0.2.25])',
          `\tby mx.contoso-it.example with ESMTPS id EXAMPLE${counter}; ${rfc5322Date(options.receivedAt)}`,
        ]
      : []),
    `From: Example Sender <${options.from ?? 'sender@sender.example'}>`,
    `To: ${(options.to ?? ['alex@contoso-it.example']).join(', ')}`,
    ...(options.cc && options.cc.length > 0 ? [`Cc: ${options.cc.join(', ')}`] : []),
    `Subject: ${options.subject ?? `Synthetic message ${counter}`}`,
    `Date: ${rfc5322Date(date)}`,
    ...(messageId === null ? [] : [`Message-ID: <${messageId}>`]),
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
  ];
  let body = options.body ?? 'Synthetic test message body.';
  if (options.minBytes !== undefined) {
    const line = 'Synthetic padding line 0123456789 abcdefghijklmnopqrstuvwxyz.\r\n';
    const current = headers.join('\r\n').length + body.length + 4;
    if (current < options.minBytes) {
      body += `\r\n${line.repeat(Math.ceil((options.minBytes - current) / line.length))}`;
    }
  }
  return `${headers.join('\r\n')}\r\n\r\n${body.replace(/\r?\n/g, '\r\n')}\r\n`;
}
