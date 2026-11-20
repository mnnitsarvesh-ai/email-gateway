import type { ResolvedArchiveSettings } from '../documents/settings';
import type { MessageDirection } from '../vocabulary';

/**
 * Journal eligibility and scope (A4). Pure: the caller resolves the scope's public ids once per
 * settings generation (`users.email`, department member addresses and users' emails, verified
 * domain names) and passes the resolved addresses and domains here.
 */

export interface JournalMessageFacts {
  receivedAt: Date;
  direction: MessageDirection;
  /** Envelope sender (MAIL FROM). */
  envelopeFrom: string | null;
  /** Address of the header From (display name removed), when parsed. */
  headerFrom: string | null;
  /**
   * Recipient directions. NULL (step 8.6 D3: an external recipient of a journal intake message
   * whose sender is external too) is not org-side and enables no direction.
   */
  recipients: ReadonlyArray<{ address: string; direction: MessageDirection | null }>;
}

/** The scope of `archive-settings/1` with every id resolved to addresses or domain names. */
export interface ResolvedJournalScope {
  /** `scope.addresses`. */
  addresses: readonly string[];
  /** `users.email` of `scope.userIds`. */
  userEmails: readonly string[];
  /** Member addresses and member users' emails of `scope.departmentIds`. */
  departmentAddresses: readonly string[];
  /** Verified domain names of `scope.domainIds`. */
  domains: readonly string[];
}

export const EMPTY_JOURNAL_SCOPE: ResolvedJournalScope = Object.freeze({
  addresses: [],
  userEmails: [],
  departmentAddresses: [],
  domains: [],
});

export type JournalIneligibility = 'before_enablement' | 'direction_disabled' | 'out_of_scope';

export type JournalEligibility =
  { eligible: true } | { eligible: false; reason: JournalIneligibility };

/**
 * Lower-cased bare address: `Name <a@b>` and `<a@b>` give `a@b`; null for an empty address (the
 * null sender).
 */
export function normalizeAddress(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const named = /<([^<>]*)>\s*$/.exec(value);
  const a = (named ? named[1]! : value).trim().toLowerCase();
  return a === '' ? null : a;
}

/** The domain of an address (lower-case), null without one. */
export function domainOf(address: string | null | undefined): string | null {
  const a = normalizeAddress(address);
  if (a === null) return null;
  const at = a.lastIndexOf('@');
  if (at < 0 || at === a.length - 1) return null;
  return a.slice(at + 1);
}

/**
 * Org-side parties (A4): recipients whose direction is `inbound` or `internal`, plus the
 * envelope sender and header From when the message direction is `outbound` or `internal`.
 * Normalized and de-duplicated.
 */
export function orgSideParties(message: JournalMessageFacts): string[] {
  const parties = new Set<string>();
  for (const r of message.recipients) {
    if (r.direction === 'inbound' || r.direction === 'internal') {
      const a = normalizeAddress(r.address);
      if (a !== null) parties.add(a);
    }
  }
  if (message.direction === 'outbound' || message.direction === 'internal') {
    for (const s of [message.envelopeFrom, message.headerFrom]) {
      const a = normalizeAddress(s);
      if (a !== null) parties.add(a);
    }
  }
  return [...parties];
}

/** The direction rule: the message direction or any recipient direction is enabled. */
export function directionEligible(
  settings: Pick<ResolvedArchiveSettings, 'directions'>,
  message: Pick<JournalMessageFacts, 'direction' | 'recipients'>,
): boolean {
  if (settings.directions[message.direction]) return true;
  return message.recipients.some((r) => r.direction !== null && settings.directions[r.direction]);
}

/** A matcher of one resolved scope (sets built once per settings generation). */
export function createScopeMatcher(scope: ResolvedJournalScope): (address: string) => boolean {
  const lower = (list: readonly string[]) =>
    new Set(list.map((x) => normalizeAddress(x)).filter((x): x is string => x !== null));
  const addresses = new Set([
    ...lower(scope.addresses),
    ...lower(scope.userEmails),
    ...lower(scope.departmentAddresses),
  ]);
  const domains = new Set(scope.domains.map((d) => d.trim().toLowerCase().replace(/\.$/, '')));
  return (address: string) => {
    const a = normalizeAddress(address);
    if (a === null) return false;
    if (addresses.has(a)) return true;
    const d = domainOf(a);
    return d !== null && domains.has(d);
  };
}

/** The scope rule: `all`; `include` = some org-side party matches; `exclude` = some does not. */
export function scopeEligible(
  mode: ResolvedArchiveSettings['scope']['mode'],
  parties: readonly string[],
  matches: (address: string) => boolean,
): boolean {
  if (mode === 'all') return true;
  if (mode === 'include') return parties.some((p) => matches(p));
  return parties.some((p) => !matches(p));
}

export interface JournalEligibilityInput {
  settings: ResolvedArchiveSettings;
  /** `archive_settings.journal_enabled_at` (null = never enabled: nothing is eligible). */
  journalEnabledAt: Date | null;
  message: JournalMessageFacts;
  /** The resolved scope (ignored for mode `all`). */
  scope?: ResolvedJournalScope;
  /** A prebuilt matcher of the same scope (avoids rebuilding sets per message). */
  matcher?: (address: string) => boolean;
}

/**
 * Journal eligibility of one message (A4): received at or after `journal_enabled_at`, an
 * enabled direction, and the scope. Entitlement and `enabled` are the caller's (organization
 * level) checks; policy-sourced intents never call this (they ignore directions and scope).
 */
export function journalEligibility(input: JournalEligibilityInput): JournalEligibility {
  const { settings, message } = input;
  if (
    input.journalEnabledAt === null ||
    message.receivedAt.getTime() < input.journalEnabledAt.getTime()
  ) {
    return { eligible: false, reason: 'before_enablement' };
  }
  if (!directionEligible(settings, message))
    return { eligible: false, reason: 'direction_disabled' };
  if (settings.scope.mode === 'all') return { eligible: true };
  const matcher = input.matcher ?? createScopeMatcher(input.scope ?? EMPTY_JOURNAL_SCOPE);
  return scopeEligible(settings.scope.mode, orgSideParties(message), matcher)
    ? { eligible: true }
    : { eligible: false, reason: 'out_of_scope' };
}
