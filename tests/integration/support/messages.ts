import { randomUUID } from 'node:crypto';

export interface MessageOptions {
  from: string;
  to: readonly string[];
  subject: string;
  /** Extra header lines, e.g. `X-Gateway-Trace: v=1; …`. */
  headers?: readonly string[];
  body?: string;
}

/** A small RFC 5322 message with a unique Message-ID (CRLF line endings). */
export function buildMessage(options: MessageOptions): { text: string; messageId: string } {
  const messageId = `<${randomUUID()}@integration.test>`;
  const text = [
    `From: ${options.from}`,
    `To: ${options.to.join(', ')}`,
    `Subject: ${options.subject}`,
    `Message-ID: ${messageId}`,
    `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    ...(options.headers ?? []),
    '',
    options.body ?? `Body of ${options.subject}.`,
    '.a line that needs dot-stuffing',
    'Bye',
    '',
  ].join('\r\n');
  return { text, messageId };
}
