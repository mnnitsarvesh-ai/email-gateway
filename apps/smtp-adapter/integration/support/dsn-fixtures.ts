/**
 * Postmaster copies of DSNs as Postfix 3.7 (`notify_classes = bounce, delay`) sends them to
 * `bounce_notice_recipient` / `delay_notice_recipient`: multipart/report with a text
 * notification, `message/delivery-status`, and the original headers only (text/rfc822-headers).
 */

export interface DsnFixtureRecipient {
  address: string;
  action: 'failed' | 'delayed' | 'delivered';
  status: string;
  remoteMta?: string;
  diagnostic?: string;
}

export interface DsnFixtureOptions {
  queueId: string;
  sender: string;
  recipients: DsnFixtureRecipient[];
  /** `Arrival-Date` (omitted with null). */
  arrivalDate?: string | null;
  /** Notice `Date` header. */
  date?: string;
  kind?: 'bounce' | 'delay';
  reportingMta?: string;
  /** Extra header lines of the undelivered message, e.g. `X-Gateway-Trace: v=1; …`. */
  originalHeaders?: string[];
  /** `Original-Envelope-Id` (the `MAIL … ENVID` of the reinjection, step 2.3 R8). */
  envelopeId?: string;
}

/** Folds a long Diagnostic-Code value at a space, the way Postfix does (continuation lines). */
const fold = (value: string): string => {
  const at = value.lastIndexOf(' ', 70);
  return value.length <= 70 || at <= 0
    ? value
    : `${value.slice(0, at)}\r\n    ${value.slice(at + 1)}`;
};

export function postfixPostmasterCopy(options: DsnFixtureOptions): string {
  const host = options.reportingMta ?? 'out.gateway.local';
  const kind = options.kind ?? 'bounce';
  const boundary = `${options.queueId}.1762077900/${host}`;
  const date = options.date ?? 'Mon,  2 Nov 2026 10:05:00 +0000 (UTC)';
  const subject =
    kind === 'bounce' ? 'Postmaster Copy: Undelivered Mail' : 'Postmaster Warning: Delayed Mail';
  const perRecipient = options.recipients
    .map((r) =>
      [
        `Final-Recipient: rfc822; ${r.address}`,
        `Original-Recipient: rfc822;${r.address}`,
        `Action: ${r.action}`,
        `Status: ${r.status}`,
        ...(r.remoteMta ? [`Remote-MTA: dns; ${r.remoteMta}`] : []),
        ...(r.diagnostic ? [`Diagnostic-Code: ${fold(r.diagnostic)}`] : []),
        ...(r.action === 'delayed'
          ? ['Will-Retry-Until: Sat,  7 Nov 2026 10:00:00 +0000 (UTC)']
          : []),
      ].join('\r\n'),
    )
    .join('\r\n\r\n');
  const perMessage = [
    ...(options.envelopeId ? [`Original-Envelope-Id: ${options.envelopeId}`] : []),
    `Reporting-MTA: dns; ${host}`,
    `X-Postfix-Queue-ID: ${options.queueId}`,
    `X-Postfix-Sender: rfc822; ${options.sender}`,
    ...(options.arrivalDate === null
      ? []
      : [`Arrival-Date: ${options.arrivalDate ?? 'Mon,  2 Nov 2026 10:00:00 +0000 (UTC)'}`]),
  ].join('\r\n');
  return [
    'Return-Path: <double-bounce@out.gateway.local>',
    `Received: by ${host} (Postfix)`,
    `\tid 9A1B2C3D4E5F; ${date}`,
    `Date: ${date}`,
    `From: MAILER-DAEMON@${host} (Mail Delivery System)`,
    `Subject: ${subject}`,
    'To: bounce-notices@bounces.gateway.internal',
    'Auto-Submitted: auto-replied',
    'MIME-Version: 1.0',
    'Content-Type: multipart/report; report-type=delivery-status;',
    `\tboundary="${boundary}"`,
    'Content-Transfer-Encoding: 8bit',
    `Message-Id: <20261102100500.9A1B2C3D4E5F@${host}>`,
    '',
    'This is a MIME-encapsulated message.',
    '',
    `--${boundary}`,
    'Content-Description: Notification',
    'Content-Type: text/plain; charset=us-ascii',
    '',
    kind === 'bounce'
      ? "This is the mail system at host out.gateway.local.\r\n\r\nI'm sorry to have to inform you that your message could not\r\nbe delivered to one or more recipients."
      : 'This is the mail system at host out.gateway.local.\r\n\r\n####################################################################\r\n# THIS IS A WARNING ONLY.  YOU DO NOT NEED TO RESEND YOUR MESSAGE. #\r\n####################################################################',
    '',
    `--${boundary}`,
    'Content-Description: Delivery report',
    'Content-Type: message/delivery-status',
    '',
    perMessage,
    '',
    perRecipient,
    '',
    `--${boundary}`,
    'Content-Description: Undelivered Message Headers',
    'Content-Type: text/rfc822-headers',
    'Content-Transfer-Encoding: 8bit',
    '',
    `Return-Path: <${options.sender}>`,
    ...(options.originalHeaders ?? []),
    `Received: by ${host} (Postfix, from userid 0) id ${options.queueId}`,
    `From: <${options.sender}>`,
    'Subject: quarterly report',
    `Message-Id: <${options.queueId}@acme.example>`,
    '',
    `--${boundary}--`,
    '',
  ].join('\r\n');
}

/** Hard bounce of one recipient (550 5.1.1 from the remote MX). */
export const singleHardBounce = (
  queueId: string,
  sender: string,
  recipient: string,
  originalHeaders: string[] = [],
): string =>
  postfixPostmasterCopy({
    queueId,
    sender,
    originalHeaders,
    recipients: [
      {
        address: recipient,
        action: 'failed',
        status: '5.1.1',
        remoteMta: 'mx.sink.test',
        diagnostic: `smtp; 550 5.1.1 <${recipient}>: Recipient address rejected: User unknown in virtual mailbox table`,
      },
    ],
  });
