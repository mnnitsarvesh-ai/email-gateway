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
  /**
   * Step API-4 A7: set for the detect evaluation of an API-mode copy (`evaluationMode =
   * 'detect'`): detected after delivery; the counted mailboxes and protection mode read at send
   * time.
   */
  detect?: { protectionMode: 'api' | 'hybrid'; mailboxCount: number };
}

export interface RenderedNotice {
  subject: string;
  text: string;
}

/**
 * Printable, single-line, bounded text (no CR/LF/control characters, no bidi controls or invisible
 * characters, no `<`/`>`).
 */
export function safeText(value: string | null | undefined, max = 128): string {
  if (value === null || value === undefined) return '';
  let out = '';
  for (const ch of value.normalize('NFC')) {
    const code = ch.codePointAt(0)!;
    if (code < 0x20 || code === 0x7f || (code >= 0x80 && code < 0xa0)) continue;
    // Bidi embeddings/overrides/isolates and invisible characters (step 5.3 hardening, Q20).
    if (
      (code >= 0x202a && code <= 0x202e) ||
      (code >= 0x2066 && code <= 0x2069) ||
      (code >= 0x200b && code <= 0x200f) ||
      code === 0xfeff ||
      code === 0x061c
    ) {
      continue;
    }
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

/** Step API-4 A7: copies are `404` in the explorer; their detections live on `/api-mode`. */
const detectLink = (facts: NoticeFacts) =>
  `${facts.portalUrl}/api-mode?tab=detections&message=${facts.messagePublicId}`;

const PROTECTION_MODE_TEXT: Readonly<Record<'api' | 'hybrid', string>> = {
  api: 'API mode (after delivery, through the mailbox API)',
  hybrid: 'Hybrid (gateway and API mode)',
};

/**
 * Step API-4 A7: the disposition of a detect evaluation describes what the tenant policy decided
 * for a message that was already delivered; the mailbox action follows the remediation policy.
 */
const DETECT_DISPOSITION_TEXT: Readonly<Record<NoticeFacts['disposition'], string>> = {
  allow: 'allow',
  require_approval: 'require approval',
  quarantine: 'quarantine',
  reject: 'reject',
};

/** An ALERT action requested a notice to the organization's policy administrators. */
export function renderPolicyAlert(facts: NoticeFacts): RenderedNotice {
  if (facts.detect !== undefined) return renderDetectPolicyAlert(facts, facts.detect);
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

/**
 * Step API-4 A7: an ALERT of the detect evaluation of an API-mode copy — "detected after delivery
 * (API mode)", the protection mode, the mailbox count and the `/api-mode` detections link (never
 * the explorer, never content).
 */
function renderDetectPolicyAlert(
  facts: NoticeFacts,
  detect: NonNullable<NoticeFacts['detect']>,
): RenderedNotice {
  return {
    subject: `[Email Gateway] Policy alert (${facts.severity}): detected after delivery (API mode)`,
    text: [
      `A policy alert was raised for ${safeText(facts.organizationName) || 'your organization'}: a tenant policy matched a message detected after delivery (API mode).`,
      '',
      `Severity: ${facts.severity}`,
      `Message: ${facts.messagePublicId}`,
      `Received: ${facts.receivedAt}`,
      `Direction: ${facts.direction}`,
      `Policy decision: ${DETECT_DISPOSITION_TEXT[facts.disposition]}`,
      decisiveLine(facts),
      `Protection mode: ${PROTECTION_MODE_TEXT[detect.protectionMode]}`,
      `Mailboxes with a copy: ${String(detect.mailboxCount)}`,
      '',
      facts.direction === 'outbound'
        ? 'The message was already sent: outbound detections are recorded, never removed from a mailbox.'
        : 'The message was already delivered; the mailbox action follows the API-mode remediation policy.',
      `Details: ${detectLink(facts)}`,
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
