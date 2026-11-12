import { sanitizeDisplayText, sanitizeSubject } from '@email-gateway/quarantine';
import { type RenderedNotice, safeText } from './templates';

/**
 * Fixed plain-text templates of the quarantine notices (step 5.3 Q20). Allowed content: ids,
 * enums, counts, times, the organization name, the envelope sender of a held message (an
 * address the recipient's own mailbox would show) and — in a user digest only, when
 * `digest.includeSubject` is on — the sanitized subject (≤ 78 characters). **Never** a body,
 * an attachment name or a URL of the message. Links point to the portal and require login (no
 * one-click actions, ADR-0047). Database text is reduced to printable, single-line, bounded
 * text so it can never inject header or body lines.
 */

/**
 * Database text in a notice: Unicode-sanitized (controls, bidi overrides and invisible
 * characters removed, single line, `sanitizeDisplayText`) and then printable without `<`/`>`
 * (`safeText`), bounded.
 */
export function clean(value: string | null | undefined, max = 128): string {
  if (value === null || value === undefined) return '';
  return safeText(sanitizeDisplayText(value, { maxChars: max }).text, max);
}

const FOOTER =
  'This is an automated notice from the email gateway. Sign in to the portal to act on it.';

/** Q20: digest subjects are cut to 78 characters (sanitized, single line). */
export const DIGEST_SUBJECT_MAX_CHARS = 78;

const REASON_TEXT: Readonly<Record<string, string>> = {
  spam: 'spam',
  bulk: 'bulk mail',
  phishing: 'phishing',
  malware: 'malware',
  bec: 'impersonation (BEC)',
  dlp: 'data loss prevention',
  policy: 'organization policy',
  suspicious: 'suspicious content',
  engine_unavailable: 'a scanner was unavailable',
  manual: 'held by an administrator',
};

export const reasonText = (reason: string): string => REASON_TEXT[reason] ?? 'held';

export interface DigestEntryFacts {
  entryId: string;
  receivedAt: string;
  sender: string;
  subject: string | null;
  reason: string;
  expiresAt: string;
}

/** A per-user digest of held mail (Q20 `user_digest`). */
export function renderUserDigest(facts: {
  organizationName: string;
  portalUrl: string;
  window: { from: string; to: string };
  entries: readonly DigestEntryFacts[];
  includeSubject: boolean;
  more: number;
}): RenderedNotice {
  const lines = [
    `Messages addressed to you were held by ${clean(facts.organizationName) || 'your organization'}'s email gateway between ${facts.window.from} and ${facts.window.to}.`,
    '',
  ];
  facts.entries.forEach((e, i) => {
    lines.push(`${String(i + 1)}. Received: ${e.receivedAt}`);
    lines.push(`   From: ${clean(e.sender, 320) || '(unknown sender)'}`);
    if (facts.includeSubject) {
      const subject = sanitizeSubject(e.subject, DIGEST_SUBJECT_MAX_CHARS);
      lines.push(`   Subject: ${clean(subject, DIGEST_SUBJECT_MAX_CHARS) || '(no subject)'}`);
    }
    lines.push(`   Reason: ${reasonText(e.reason)}`);
    lines.push(`   Held until: ${e.expiresAt}`);
    lines.push(`   Review: ${facts.portalUrl}/quarantine/me/${e.entryId}`);
    lines.push('');
  });
  if (facts.more > 0) {
    lines.push(`${String(facts.more)} more held message(s) are listed in the portal.`, '');
  }
  lines.push(`All held messages: ${facts.portalUrl}/quarantine/me`, '', FOOTER);
  return {
    subject: `[Email Gateway] ${String(facts.entries.length + facts.more)} message(s) held for you`,
    text: lines.join('\n'),
  };
}

/** Approval requests waiting for an approver (Q20 `approval_requested`). */
export function renderApprovalRequested(facts: {
  organizationName: string;
  portalUrl: string;
  requests: ReadonlyArray<{ id: string; kind: string; reason: string; approvalReasons: string[] }>;
}): RenderedNotice {
  const lines = [
    `${String(facts.requests.length)} quarantine approval request(s) of ${clean(facts.organizationName) || 'your organization'} need a decision.`,
    '',
  ];
  for (const r of facts.requests) {
    lines.push(`- Request ${r.id} (${r.kind.replace(/_/g, ' ')})`);
    lines.push(`  Held for: ${reasonText(r.reason)}`);
    if (r.approvalReasons.length > 0) {
      lines.push(
        `  Approval needed because: ${r.approvalReasons.map((x) => clean(x, 32)).join(', ')}`,
      );
    }
    lines.push(`  Decide: ${facts.portalUrl}/quarantine/approvals/${r.id}`);
  }
  lines.push('', 'You cannot approve a request you made yourself.', '', FOOTER);
  return {
    subject: `[Email Gateway] Quarantine approval requested (${String(facts.requests.length)})`,
    text: lines.join('\n'),
  };
}

/** The decision on the caller's own request (Q20 `approval_decided`). */
export function renderApprovalDecided(facts: {
  organizationName: string;
  portalUrl: string;
  decision: 'approved' | 'denied' | 'expired' | 'cancelled';
  requestIds: readonly string[];
}): RenderedNotice {
  return {
    subject: `[Email Gateway] Your quarantine request was ${facts.decision}`,
    text: [
      `Your quarantine request(s) at ${clean(facts.organizationName) || 'your organization'} were ${facts.decision}.`,
      '',
      ...facts.requestIds.map((id) => `- ${facts.portalUrl}/quarantine/approvals/${id}`),
      '',
      FOOTER,
    ].join('\n'),
  };
}

/** A release that did not go through (Q20 `release_blocked`). */
export function renderReleaseBlocked(facts: {
  organizationName: string;
  portalUrl: string;
  releaseId: string;
  outcomes: Readonly<Record<string, number>>;
}): RenderedNotice {
  const outcome = Object.entries(facts.outcomes)
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([status, n]) => `${status.replace(/_/g, ' ')}: ${String(n)}`)
    .join(', ');
  return {
    subject: '[Email Gateway] Your quarantine release was not completed',
    text: [
      `A release you requested at ${clean(facts.organizationName) || 'your organization'} was not delivered after re-validation.`,
      '',
      `Release: ${facts.releaseId}`,
      `Outcome: ${outcome || 'blocked'}`,
      'An approval may be required, the message may need a rescan, or the release is not allowed.',
      '',
      `Details: ${facts.portalUrl}/quarantine/releases/${facts.releaseId}`,
      '',
      FOOTER,
    ].join('\n'),
  };
}

/** A rate-bounded summary for the quarantine administrators (Q20 `admin_alert`). */
export function renderAdminAlert(facts: {
  organizationName: string;
  portalUrl: string;
  hardBlocks: number;
  pendingApprovals: number;
  window: { from: string; to: string } | null;
}): RenderedNotice {
  return {
    subject: '[Email Gateway] Quarantine needs attention',
    text: [
      `The quarantine of ${clean(facts.organizationName) || 'your organization'} needs attention.`,
      '',
      ...(facts.window === null ? [] : [`Window: ${facts.window.from} – ${facts.window.to}`]),
      `New hard-blocked messages: ${String(facts.hardBlocks)}`,
      `Approval requests waiting over an hour: ${String(facts.pendingApprovals)}`,
      '',
      `Quarantine: ${facts.portalUrl}/quarantine`,
      '',
      FOOTER,
    ].join('\n'),
  };
}

/** An outbound/internal message an administrator rejected (Q16 `sender_rejected`). */
export function renderSenderRejected(facts: {
  organizationName: string;
  messagePublicId: string;
  receivedAt: string;
  internetMessageId: string | null;
}): RenderedNotice {
  const internetMessageId = clean(facts.internetMessageId, 256);
  return {
    subject: '[Email Gateway] Your message was not delivered',
    text: [
      `A message you sent through ${clean(facts.organizationName) || 'your organization'} was held and then rejected by an administrator. It was not delivered to that recipient.`,
      '',
      `Message: ${facts.messagePublicId}`,
      ...(internetMessageId ? [`Message-ID: ${internetMessageId}`] : []),
      `Received: ${facts.receivedAt}`,
      '',
      'Contact your administrator if you think this is wrong.',
      '',
      'This is an automated notice from the email gateway. It contains no message content.',
    ].join('\n'),
  };
}

/** `<quarantine-notice.<eventId>@<domain of the From address>>` (Q20: one per event). */
export function quarantineNoticeMessageId(eventId: string, from: string): string {
  const address = /<([^>]+)>/.exec(from)?.[1] ?? from;
  const domain =
    address
      .slice(address.lastIndexOf('@') + 1)
      .trim()
      .toLowerCase() || 'localhost';
  return `<quarantine-notice.${eventId}@${domain}>`;
}
