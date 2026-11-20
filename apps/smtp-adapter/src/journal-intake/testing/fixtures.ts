import { randomBytes } from 'node:crypto';
import {
  deriveIntakeAddressToken,
  deriveIntakeHeaderToken,
  intakeAddress,
  intakeAddressHash,
  intakeHeaderTokenHash,
  intakeLocalPart,
} from '@email-gateway/archive';

/**
 * TEST-ONLY builders of synthetic journal intake traffic (step 8.6 §9.2; reused by the WP6 stack
 * suite): original messages, Microsoft 365 / on-premises Exchange journal reports (the documented
 * report shape: `X-MS-Journal-Report`, `multipart/mixed` with a text/plain envelope part and a
 * message/rfc822 part), Google Workspace "Also deliver to" copies with the header token, generic
 * BCC copies, and intake address / token derivation from a random test secret. Every name is a
 * reserved example domain; nothing here is a credential of a real system.
 */

export const CRLF = '\r\n';

export interface OriginalMessageOptions {
  messageId?: string;
  date?: string;
  from?: string;
  to?: string[];
  cc?: string[];
  subject?: string;
  body?: string;
  extraHeaders?: string[];
}

/** A small RFC 5322 message with CRLF line ends. */
export function originalMessage(o: OriginalMessageOptions = {}): Buffer {
  const lines = [
    `Message-ID: ${o.messageId ?? `<${randomBytes(8).toString('hex')}@example.com>`}`,
    `Date: ${o.date ?? 'Fri, 20 Nov 2026 10:00:00 +0000'}`,
    `From: ${o.from ?? 'Alice Example <alice@example.com>'}`,
    `To: ${(o.to ?? ['bob@example.org']).join(', ')}`,
    ...((o.cc ?? []).length > 0 ? [`Cc: ${o.cc!.join(', ')}`] : []),
    `Subject: ${o.subject ?? 'Synthetic journal intake message'}`,
    ...(o.extraHeaders ?? []),
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 7bit',
    '',
    o.body ?? 'Synthetic body for journal intake tests.',
    '',
  ];
  return Buffer.from(lines.join(CRLF), 'utf8');
}

export interface JournalEnvelopeLines {
  sender?: string;
  messageId?: string;
  to?: string[];
  cc?: string[];
  bcc?: string[];
  /** Older Exchange format: one `Recipient:` line per recipient instead of To/Cc/Bcc. */
  recipient?: string[];
}

/** The text/plain envelope part of an Exchange journal report. */
export function journalEnvelopeText(e: JournalEnvelopeLines): string {
  const lines = [
    `Sender: ${e.sender ?? 'alice@example.com'}`,
    'Subject: Synthetic journal intake message',
    ...(e.messageId ? [`Message-Id: ${e.messageId}`] : []),
    ...(e.to ?? []).map((a) => `To: ${a}`),
    ...(e.cc ?? []).map((a) => `Cc: ${a}`),
    ...(e.bcc ?? []).map((a) => `Bcc: ${a}`),
    ...(e.recipient ?? []).map((a) => `Recipient: ${a}`),
  ];
  return lines.join(CRLF) + CRLF;
}

export interface JournalReportOptions {
  /** The intake address the report is sent to (its To header). */
  intakeAddress: string;
  original?: Buffer;
  envelope?: JournalEnvelopeLines;
  /** Microsoft 365: the `X-MS-Exchange-CrossTenant-Id` values (none for on-premises). */
  tenantIds?: string[];
  /** Transfer encoding of the embedded message part. */
  encoding?: '7bit' | 'base64';
  boundary?: string;
  /** Header lines added to the OUTER report (spoofing tests). */
  extraOuterHeaders?: string[];
  /** Drop `X-MS-Journal-Report` (an unrecognizable report, stored as received). */
  withoutJournalHeader?: boolean;
  reportFrom?: string;
}

/** A journal report of the documented Exchange shape (synthetic). */
export function journalReport(o: JournalReportOptions): Buffer {
  const boundary = o.boundary ?? `b1_${randomBytes(6).toString('hex')}`;
  const original = o.original ?? originalMessage();
  const encoding = o.encoding ?? '7bit';
  const embedded =
    encoding === 'base64'
      ? Buffer.from((original.toString('base64').match(/.{1,76}/g) ?? []).join(CRLF), 'latin1')
      : original;
  const head = [
    ...(o.withoutJournalHeader ? [] : ['X-MS-Journal-Report:']),
    ...(o.tenantIds ?? []).map((id) => `X-MS-Exchange-CrossTenant-Id: ${id}`),
    ...(o.extraOuterHeaders ?? []),
    `From: ${o.reportFrom ?? 'Journal Agent <journal-agent@example.com>'}`,
    `To: ${o.intakeAddress}`,
    'Subject: Synthetic journal intake message',
    `Message-ID: <report-${randomBytes(6).toString('hex')}@example.com>`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    '',
    'This is a multi-part message in MIME format.',
    `--${boundary}`,
    'Content-Type: text/plain; charset="us-ascii"',
    '',
    '',
  ].join(CRLF);
  const mid = [
    '',
    `--${boundary}`,
    'Content-Type: message/rfc822',
    ...(encoding === 'base64' ? ['Content-Transfer-Encoding: base64'] : []),
    '',
    '',
  ].join(CRLF);
  const tail = ['', `--${boundary}--`, ''].join(CRLF);
  return Buffer.concat([
    Buffer.from(head, 'utf8'),
    Buffer.from(journalEnvelopeText(o.envelope ?? {}), 'utf8'),
    Buffer.from(mid, 'utf8'),
    embedded,
    Buffer.from(tail, 'utf8'),
  ]);
}

/** A Microsoft 365 journal report (tenant header of the bound tenant by default). */
export const m365JournalReport = (o: JournalReportOptions & { tenantId: string }): Buffer =>
  journalReport({ ...o, tenantIds: o.tenantIds ?? [o.tenantId] });

/** An on-premises Exchange journal report (no tenant header). */
export const onPremJournalReport = (o: JournalReportOptions): Buffer =>
  journalReport({ ...o, tenantIds: o.tenantIds ?? [] });

/** Prepends header lines to a message. */
export function withHeaders(message: Buffer, headers: readonly string[]): Buffer {
  return Buffer.concat([Buffer.from(headers.map((h) => h + CRLF).join(''), 'utf8'), message]);
}

/**
 * A Google Workspace "Also deliver to" copy: the routing rule adds `X-Gm-Original-To` and the
 * custom header `X-EG-Journal-Token` (pass `tokens: []` for none, several for the spoofing case).
 */
export function googleWorkspaceCopy(o: {
  tokens: readonly string[];
  originalTo?: readonly string[];
  original?: Buffer;
}): Buffer {
  return withHeaders(o.original ?? originalMessage(), [
    ...(o.originalTo ?? []).map((a) => `X-Gm-Original-To: ${a}`),
    ...o.tokens.map((t) => `X-EG-Journal-Token: ${t}`),
  ]);
}

/** A generic `always_bcc` copy (the message as is). */
export const smtpBccCopy = (original: Buffer = originalMessage()): Buffer => original;

/** Intake credentials of one synthetic source (what the api would derive and store). */
export interface IntakeCredentials {
  token: string;
  localPart: string;
  address: string;
  addressHash: string;
  headerToken: string;
  headerTokenHash: string;
}

/** A random test secret (64 hex) as `JOURNAL_INTAKE_ADDRESS_SECRET` would hold. */
export const testIntakeSecret = (): Buffer => randomBytes(32);

/** The address and header token of a source (ADR-0087 derivation, random test secret). */
export function intakeCredentials(
  secret: Buffer,
  sourcePublicId: string,
  addressVersion: number,
  domain: string,
): IntakeCredentials {
  const token = deriveIntakeAddressToken(secret, sourcePublicId, addressVersion);
  const headerToken = deriveIntakeHeaderToken(secret, sourcePublicId, addressVersion);
  const localPart = intakeLocalPart(token);
  return {
    token,
    localPart,
    address: intakeAddress(token, domain),
    addressHash: intakeAddressHash(localPart),
    headerToken,
    headerTokenHash: intakeHeaderTokenHash(headerToken),
  };
}
