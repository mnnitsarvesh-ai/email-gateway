import { randomUUID } from 'node:crypto';
import { waitFor } from './compose';
import type { SmtpFixtures } from './smtp-fixtures';

/**
 * Helpers of the step 3.1 MIME ingestion stack suite (docs/plan/steps/06-mime-ingestion.md §9):
 * raw MIME messages and reads of what the email-worker committed for one message.
 */
const CRLF = '\r\n';

/** The stored header allow-list of design M7 (canonical spelling). */
export const STORED_HEADERS = [
  'From',
  'Sender',
  'Reply-To',
  'To',
  'Cc',
  'Subject',
  'Message-ID',
  'Date',
  'In-Reply-To',
  'References',
  'Return-Path',
  'Authentication-Results',
] as const;

/** The final parse statuses (M13). */
export const FINAL_PARSE_STATUSES = [
  'parsed',
  'parsed_with_defects',
  'parse_limit_exceeded',
  'parse_failed',
] as const;

/** RFC 2045 base64 body lines (76 characters). */
export function base64Lines(bytes: Buffer): string {
  return (bytes.toString('base64').match(/.{1,76}/g) ?? []).join(CRLF);
}

/** RFC 2047 `B` encoded-word of a UTF-8 string. */
export function encodedWord(text: string): string {
  return `=?UTF-8?B?${Buffer.from(text, 'utf8').toString('base64')}?=`;
}

/** RFC 2231 `name*=UTF-8''…` parameter value (percent-encoded UTF-8, RFC 2231 §4). */
export function rfc2231(name: string, value: string): string {
  const encoded = [...Buffer.from(value, 'utf8')]
    .map((b) =>
      /[A-Za-z0-9!#$&+.^_`|~-]/.test(String.fromCharCode(b))
        ? String.fromCharCode(b)
        : `%${b.toString(16).toUpperCase().padStart(2, '0')}`,
    )
    .join('');
  return `${name}*=UTF-8''${encoded}`;
}

export interface MultipartOptions {
  from: string;
  to: readonly string[];
  /** Encoded header value of Subject (e.g. an RFC 2047 encoded-word). */
  subjectHeader: string;
  /** Quoted-printable text body (ASCII). */
  textQp: string;
  html: string;
  attachment: { contentType: string; dispositionParam: string; bytes: Buffer };
}

/**
 * multipart/mixed: multipart/alternative (QP text + HTML) and one base64 attachment. ASCII
 * only on the wire (7bit), CRLF line endings, a unique Message-ID.
 */
export function multipartMessage(options: MultipartOptions): { text: string; messageId: string } {
  const messageId = `<${randomUUID()}@integration.test>`;
  const mixed = `mixed-${randomUUID()}`;
  const alt = `alt-${randomUUID()}`;
  const text = [
    `From: ${options.from}`,
    `To: ${options.to.join(', ')}`,
    `Subject: ${options.subjectHeader}`,
    `Message-ID: ${messageId}`,
    `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${mixed}"`,
    '',
    'This is a multi-part message in MIME format.',
    `--${mixed}`,
    `Content-Type: multipart/alternative; boundary="${alt}"`,
    '',
    `--${alt}`,
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    options.textQp,
    `--${alt}`,
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    options.html,
    `--${alt}--`,
    `--${mixed}`,
    `Content-Type: ${options.attachment.contentType}`,
    `Content-Disposition: attachment; ${options.attachment.dispositionParam}`,
    'Content-Transfer-Encoding: base64',
    '',
    base64Lines(options.attachment.bytes),
    `--${mixed}--`,
    '',
  ].join(CRLF);
  return { text, messageId };
}

/**
 * A malformed multipart message: the base64 attachment carries characters outside the
 * alphabet, and the multipart reaches EOF without its closing `--boundary--`.
 */
export function malformedMessage(options: {
  from: string;
  to: readonly string[];
  subject: string;
}): {
  text: string;
  messageId: string;
} {
  const messageId = `<${randomUUID()}@integration.test>`;
  const boundary = `broken-${randomUUID()}`;
  const text = [
    `From: ${options.from}`,
    `To: ${options.to.join(', ')}`,
    `Subject: ${options.subject}`,
    `Message-ID: ${messageId}`,
    `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Malformed body.',
    `--${boundary}`,
    'Content-Type: application/octet-stream',
    'Content-Disposition: attachment; filename="broken.bin"',
    'Content-Transfer-Encoding: base64',
    '',
    'SGVsbG8g!!!d29ybGQ*~~~',
    'QUJD$$$REVG',
    // No closing delimiter: the message ends inside the multipart.
    '',
  ].join(CRLF);
  return { text, messageId };
}

/** Waits for the email-worker's final parse row of a message (any final status). */
export function waitForFinalParse(
  fx: SmtpFixtures,
  message: { id: bigint; receivedAt: Date },
  timeoutMs = 90_000,
) {
  return waitFor(
    `a final email_message_parses row for message ${message.id.toString()}`,
    () =>
      fx.prisma.emailMessageParse
        .findFirst({ where: { messageId: message.id, receivedAt: message.receivedAt } })
        .then((row) =>
          row && (FINAL_PARSE_STATUSES as readonly string[]).includes(row.status) ? row : undefined,
        ),
    { timeoutMs, intervalMs: 500 },
  );
}

/** Everything the email-worker committed for one message (writer reads). */
export async function parseState(
  fx: SmtpFixtures,
  message: { id: bigint; receivedAt: Date; organizationId: bigint },
) {
  const where = { messageId: message.id, receivedAt: message.receivedAt };
  const [row, headers, attachments, events, outbox] = await Promise.all([
    fx.prisma.emailMessage.findFirstOrThrow({
      where: { id: message.id, receivedAt: message.receivedAt },
    }),
    fx.prisma.emailHeader.findMany({ where, orderBy: { seq: 'asc' } }),
    fx.prisma.emailAttachment.findMany({ where, orderBy: { partIndex: 'asc' } }),
    fx.prisma.emailEvent.findMany({
      where: { messageId: message.id, organizationId: message.organizationId },
      orderBy: { id: 'asc' },
    }),
    fx.prisma.messageOutbox.findMany({
      where: {
        organizationId: message.organizationId,
        aggregateId: message.id.toString(),
        eventType: { in: ['mail.message.parsed.v1', 'mail.message.parse_failed.v1'] },
      },
    }),
  ]);
  return { message: row, headers, attachments, events, outbox };
}
