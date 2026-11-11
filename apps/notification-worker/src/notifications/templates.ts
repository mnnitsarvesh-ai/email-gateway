import type { PolicyNotificationRequestedV1 } from '@email-gateway/event-contracts';

/**
 * Fixed plain-text templates of the policy notices (step 5.2 P25). They carry the organization
 * name, the message public id, its received time, direction, the disposition, the decisive
 * policy name and rule id and a portal link; the sender notice adds the Internet-Message-ID and
 * the recipient count. **Never** a subject, a body, a file name, a URL of the message or any
 * address. Free text from the database (organization and policy names, the Internet-Message-ID)
 * is reduced to printable characters and bounded so it can never inject header or body lines.
 */

export interface NoticeFacts {
  organizationName: string;
  messagePublicId: string;
  receivedAt: string;
  direction: PolicyNotificationRequestedV1['direction'];
  disposition: PolicyNotificationRequestedV1['disposition'];
  severity: PolicyNotificationRequestedV1['severity'];
  decisive: PolicyNotificationRequestedV1['decisive'];
  /** Name of the decisive tenant policy (null for the platform default or the floor). */
  policyName: string | null;
  portalUrl: string;
  /** Sender notice only. */
  internetMessageId?: string | null;
  recipientCount?: number;
}

export interface RenderedNotice {
  subject: string;
  text: string;
}

/** Printable, single-line, bounded text (no CR/LF/control characters, no `<`/`>`). */
export function safeText(value: string | null | undefined, max = 128): string {
  if (value === null || value === undefined) return '';
  let out = '';
  for (const ch of value.normalize('NFC')) {
    const code = ch.codePointAt(0)!;
    if (code < 0x20 || code === 0x7f || (code >= 0x80 && code < 0xa0)) continue;
    if (ch === '<' || ch === '>') continue;
    out += ch;
    if (out.length >= max) break;
  }
  return out.trim();
}

const DISPOSITION_TEXT: Readonly<Record<NoticeFacts['disposition'], string>> = {
  allow: 'allowed',
  require_approval: 'held for approval',
  quarantine: 'quarantined',
  reject: 'rejected',
};

function decisiveLine(facts: NoticeFacts): string {
  if (facts.decisive.source === 'tenant_rule') {
    const name = safeText(facts.policyName) || 'a policy';
    return `Decided by: policy "${name}", rule ${safeText(facts.decisive.ruleId, 48)}`;
  }
  return facts.decisive.source === 'floor'
    ? 'Decided by: the platform strictness floor'
    : 'Decided by: the platform default policy';
}

const link = (facts: NoticeFacts) => `${facts.portalUrl}/messages/${facts.messagePublicId}`;

/** An ALERT action requested a notice to the organization's policy administrators. */
export function renderPolicyAlert(facts: NoticeFacts): RenderedNotice {
  const disposition = DISPOSITION_TEXT[facts.disposition];
  return {
    subject: `[Email Gateway] Policy alert (${facts.severity}): message ${disposition}`,
    text: [
      `A policy alert was raised for ${safeText(facts.organizationName) || 'your organization'}.`,
      '',
      `Severity: ${facts.severity}`,
      `Message: ${facts.messagePublicId}`,
      `Received: ${facts.receivedAt}`,
      `Direction: ${facts.direction}`,
      `Disposition: ${disposition}`,
      decisiveLine(facts),
      '',
      `Details: ${link(facts)}`,
      '',
      'This is an automated notice from the email gateway. It contains no message content.',
    ].join('\n'),
  };
}

/** A REJECT of an outbound/internal message: notice to the organization's own sender. */
export function renderSenderNonDelivery(facts: NoticeFacts): RenderedNotice {
  const internetMessageId = safeText(facts.internetMessageId, 256);
  return {
    subject: '[Email Gateway] Your message was not delivered',
    text: [
      `A message you sent through ${safeText(facts.organizationName) || 'your organization'} was not delivered: it was rejected by policy.`,
      '',
      `Message: ${facts.messagePublicId}`,
      ...(internetMessageId ? [`Message-ID: ${internetMessageId}`] : []),
      `Received: ${facts.receivedAt}`,
      `Recipients: ${facts.recipientCount ?? 0}`,
      decisiveLine(facts),
      '',
      'Contact your administrator if you think this is wrong. No recipient received the message.',
      `Administrators: ${link(facts)}`,
      '',
      'This is an automated notice from the email gateway. It contains no message content.',
    ].join('\n'),
  };
}

/** `<policy-notice.<eventId>@<domain of the From address>>` (P25: one per event). */
export function noticeMessageId(eventId: string, from: string): string {
  const address = /<([^>]+)>/.exec(from)?.[1] ?? from;
  const domain =
    address
      .slice(address.lastIndexOf('@') + 1)
      .trim()
      .toLowerCase() || 'localhost';
  return `<policy-notice.${eventId}@${domain}>`;
}
