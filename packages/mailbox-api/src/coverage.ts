/**
 * Mailbox coverage (design D11.2). Pure; the health role evaluates it per mailbox on each tick and
 * stores the result in `api_mailboxes.coverage_state`.
 */

export const PROTECTION_MODES = ['inline', 'api', 'hybrid'] as const;
export type ProtectionMode = (typeof PROTECTION_MODES)[number];

export const MAILBOX_STATUSES = ['active', 'discovered', 'disabled', 'deleted'] as const;
export type MailboxStatus = (typeof MAILBOX_STATUSES)[number];

export const FEED_STATUSES = ['off', 'pending', 'active', 'error', 'throttled', 'revoked'] as const;
export type FeedStatus = (typeof FEED_STATUSES)[number];

export const COVERAGE_STATES = ['covered', 'gap', 'out_of_scope'] as const;
export type CoverageState = (typeof COVERAGE_STATES)[number];

export interface MailboxCoverageInput {
  status: MailboxStatus;
  /** Effective protection mode of the mailbox's domain; null when the domain is unknown. */
  domainEffectiveMode: ProtectionMode | null;
  feedStatus: FeedStatus;
  lastSyncAt: Date | null;
  journalLastSeenAt: Date | null;
}

export interface MailboxCoverageConfig {
  /**
   * The feed's poll interval in seconds for this connection: `API_MODE_FEED_POLL_SECONDS` (300)
   * in `poll` mode, `API_MODE_FEED_SAFETY_POLL_SECONDS` (3600) with notifications.
   */
  feedPollIntervalSeconds: number;
  /** `API_MODE_JOURNAL_COVERAGE_DAYS` (7). */
  journalCoverageDays: number;
}

/**
 * D11.2: `out_of_scope` when the domain is effective `inline` (or unknown) or the mailbox is
 * `disabled`/`deleted`; `covered` when the feed is `active` and synced within 3 × the poll
 * interval, or a journal copy was seen within the journal coverage window; else `gap`.
 */
export function evaluateMailboxCoverage(
  mailbox: MailboxCoverageInput,
  now: Date,
  config: MailboxCoverageConfig,
): CoverageState {
  if (
    mailbox.domainEffectiveMode === null ||
    mailbox.domainEffectiveMode === 'inline' ||
    mailbox.status === 'disabled' ||
    mailbox.status === 'deleted'
  ) {
    return 'out_of_scope';
  }
  const nowMs = now.getTime();
  const feedFresh =
    mailbox.feedStatus === 'active' &&
    mailbox.lastSyncAt !== null &&
    mailbox.lastSyncAt.getTime() >= nowMs - 3 * config.feedPollIntervalSeconds * 1000;
  const journalFresh =
    mailbox.journalLastSeenAt !== null &&
    mailbox.journalLastSeenAt.getTime() >= nowMs - config.journalCoverageDays * 86_400_000;
  return feedFresh || journalFresh ? 'covered' : 'gap';
}

/**
 * Coverage percent of a connection: covered / (covered + gap) of `active` mailboxes, one decimal;
 * null when nothing is in scope (D11.2; the caller passes counts only when the inventory is `ok`).
 */
export function coveragePercent(counts: { covered: number; gap: number }): number | null {
  const total = counts.covered + counts.gap;
  if (total <= 0) return null;
  return Math.floor((counts.covered / total) * 1000) / 10;
}
