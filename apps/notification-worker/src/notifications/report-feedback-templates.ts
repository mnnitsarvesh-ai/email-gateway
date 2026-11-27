import { safeText } from './templates';

/**
 * Fixed templates of the reporter feedback (step API-3 C12, ADR-0104): a plain-text part and an
 * HTML alternative per kind (`received`) and analyst verdict (`resolved`: `malicious`,
 * `phishing_simulation`, `spam`, `clean`, `inconclusive`). They carry the organization name
 * (sanitized; hidden when it looks like an address or a URL), the report date and the report
 * public id only — **never** the reported message's subject, sender or body, the analyst note or
 * any address. Every interpolated value is validated (UUID, ISO instant) or sanitized and, in the
 * HTML part, escaped.
 */

export type FeedbackVerdict =
  'malicious' | 'phishing_simulation' | 'spam' | 'clean' | 'inconclusive';

export type FeedbackFacts =
  | { kind: 'received'; organizationName: string; reportPublicId: string; reportedAt: Date }
  | {
      kind: 'resolved';
      verdict: FeedbackVerdict;
      organizationName: string;
      reportPublicId: string;
      reportedAt: Date;
    };

export interface RenderedFeedback {
  subject: string;
  text: string;
  html: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** HTML-escapes text for element content and attribute values. */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** The organization name for the mail, or a neutral phrase (no address- or URL-like names). */
function organization(value: string): string {
  const text = safeText(value, 128);
  return text === '' || /@|:\/\//.test(text) ? 'your organization' : text;
}

/** `YYYY-MM-DD HH:MM UTC`, or `unknown`. */
function reportDate(value: Date): string {
  const time = value.getTime();
  if (Number.isNaN(time)) return 'unknown';
  const iso = new Date(time).toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

interface Copy {
  subject: string;
  headline: string;
  lines: string[];
}

const RECEIVED: Copy = {
  subject: 'We received your report',
  headline: 'Thank you — we received the message you reported.',
  lines: [
    'Your security team will review it. You do not need to do anything else.',
    'Please do not open links or attachments in the reported message while it is reviewed.',
  ],
};

const RESOLVED: Readonly<Record<FeedbackVerdict, Copy>> = {
  malicious: {
    subject: 'Your report: the message was dangerous',
    headline: 'Thank you — this message was dangerous and has been removed.',
    lines: [
      'Your report helped protect your colleagues. Copies found in other mailboxes are removed as well.',
      'If you opened a link or attachment or entered a password, tell your IT or security team now.',
    ],
  },
  phishing_simulation: {
    subject: 'Your report: a phishing simulation',
    headline: 'This was a phishing simulation — well spotted.',
    lines: ['Reporting it was exactly the right thing to do. Keep it up.'],
  },
  spam: {
    subject: 'Your report: the message was spam',
    headline: 'This message was unwanted mail (spam), not a targeted attack.',
    lines: ['You can delete it. Thank you for reporting it.'],
  },
  clean: {
    subject: 'Your report: the message is safe',
    headline: 'This message is safe.',
    lines: ['Your security team reviewed it and found no threat. Thank you for staying careful.'],
  },
  inconclusive: {
    subject: 'Your report: review finished',
    headline: 'Your security team reviewed the message but could not reach a clear conclusion.',
    lines: [
      'Treat it with care: do not open its links or attachments, and contact your IT or security team if it asks for anything unusual.',
    ],
  },
};

/** Renders one reporter feedback mail (text + HTML) from fixed copy. */
export function renderReportFeedback(facts: FeedbackFacts): RenderedFeedback {
  const copy = facts.kind === 'received' ? RECEIVED : RESOLVED[facts.verdict];
  const org = organization(facts.organizationName);
  const id = UUID.test(facts.reportPublicId) ? facts.reportPublicId : 'unknown';
  const date = reportDate(facts.reportedAt);
  const reference = [`Report reference: ${id}`, `Reported: ${date}`];
  const footer =
    'This is an automated message from the email security service of your organization. It does not repeat the reported message.';
  const text = [
    copy.headline,
    '',
    ...copy.lines,
    '',
    ...reference,
    '',
    `Sent on behalf of the security team of ${org}.`,
    footer,
  ].join('\n');
  const paragraph = (value: string) => `<p>${escapeHtml(value)}</p>`;
  const html = [
    '<!doctype html>',
    '<html lang="en"><head><meta charset="utf-8"><title>',
    escapeHtml(copy.subject),
    '</title></head><body style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5;color:#1f2933">',
    `<p><strong>${escapeHtml(copy.headline)}</strong></p>`,
    ...copy.lines.map(paragraph),
    `<p style="color:#52606d">${escapeHtml(reference[0]!)}<br>${escapeHtml(reference[1]!)}</p>`,
    paragraph(`Sent on behalf of the security team of ${org}.`),
    `<p style="color:#7b8794;font-size:12px">${escapeHtml(footer)}</p>`,
    '</body></html>',
  ].join('');
  return { subject: `[Email Gateway] ${copy.subject}`, text, html };
}

/** `<report-feedback.<eventId>@<domain of the From address>>` (one per feedback event). */
export function reportFeedbackMessageId(eventId: string, from: string): string {
  const address = /<([^>]+)>/.exec(from)?.[1] ?? from;
  const domain =
    address
      .slice(address.lastIndexOf('@') + 1)
      .trim()
      .toLowerCase() || 'localhost';
  return `<report-feedback.${eventId}@${domain}>`;
}
