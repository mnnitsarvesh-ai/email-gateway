import {
  archiveHoldCriteriaSchema,
  type ArchiveHoldCriteria,
  legacyLegalHoldCriteriaSchema,
} from '../documents/criteria';
import type { MessageDirection } from '../vocabulary';

/**
 * Legal-hold criteria matching (A12, ADR-0067), authoritative at disposal time and shared with
 * the 5.3 quarantine disposal (A23). Semantics (5.3 Q17, unchanged):
 *
 * - no custodians (absent or empty), or the envelope sender, header From or any envelope
 *   recipient is a custodian (case-insensitive, trimmed);
 * - `received_at` within `[from, to]`; a date-only bound covers the whole UTC day;
 * - `directions` (archive-hold/1 only): the message direction or any recipient direction is
 *   listed (the broader reading holds more, which is the fail-safe side);
 * - criteria that cannot be parsed match **everything** (fail-safe).
 *
 * Rows with `criteria_version` NULL are legacy rows: only the strict 5.3 subset
 * `{ custodians, from, to }` parses; `archive-hold/1` rows use the full schema; any other version
 * is unparsable.
 */

export interface LegalHoldFacts {
  receivedAt: Date;
  direction?: MessageDirection | null;
  /** Recipient directions; NULL entries (unknown, step 8.6 D3) are ignored. */
  recipientDirections?: readonly (MessageDirection | null)[];
  /** Envelope sender and header From. */
  senderAddresses: readonly string[];
  /** Envelope recipients (BCC included). */
  recipientAddresses: readonly string[];
}

/** An active `archive_legal_holds` row. */
export interface LegalHoldRow {
  id: string;
  criteria: unknown;
  /** `criteria_version` (NULL = legacy 5.3 subset). */
  criteriaVersion?: string | null;
}

const DAY_MS = 86_400_000;
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

/** The instant of a bound; date-only bounds are the first/last millisecond of the UTC day. */
export function holdBound(value: string, end: boolean): number {
  if (DATE_ONLY.test(value)) {
    const start = Date.parse(`${value}T00:00:00.000Z`);
    return end ? start + DAY_MS - 1 : start;
  }
  return Date.parse(value);
}

export type ParsedHoldCriteria =
  { matchAll: true } | { matchAll: false; criteria: ArchiveHoldCriteria };

/** Parses stored criteria by version; anything unparsable is `matchAll`. */
export function parseHoldCriteria(
  criteria: unknown,
  criteriaVersion: string | null | undefined,
): ParsedHoldCriteria {
  if (criteria === null || criteria === undefined) return { matchAll: true };
  let parsed: ArchiveHoldCriteria | null = null;
  if (criteriaVersion === null || criteriaVersion === undefined) {
    const r = legacyLegalHoldCriteriaSchema.safeParse(criteria);
    parsed = r.success ? r.data : null;
  } else if (criteriaVersion === 'archive-hold/1') {
    const r = archiveHoldCriteriaSchema.safeParse(criteria);
    parsed = r.success ? r.data : null;
  }
  if (parsed === null) return { matchAll: true };
  for (const [value, end] of [
    [parsed.from, false],
    [parsed.to, true],
  ] as const) {
    if (value !== undefined && !Number.isFinite(holdBound(value, end))) return { matchAll: true };
  }
  return { matchAll: false, criteria: parsed };
}

/** Whether one hold covers the message (see the module comment for the exact semantics). */
export function legalHoldMatches(
  criteria: unknown,
  facts: LegalHoldFacts,
  options: { criteriaVersion?: string | null } = {},
): boolean {
  const parsed = parseHoldCriteria(criteria, options.criteriaVersion);
  if (parsed.matchAll) return true;
  const c = parsed.criteria;
  const t = facts.receivedAt.getTime();
  if (c.from !== undefined && t < holdBound(c.from, false)) return false;
  if (c.to !== undefined && t > holdBound(c.to, true)) return false;
  if (c.directions !== undefined) {
    const have = [
      ...(facts.direction ? [facts.direction] : []),
      ...(facts.recipientDirections ?? []).filter((d): d is MessageDirection => d !== null),
    ];
    // Unknown directions cannot exclude the message (fail-safe).
    if (have.length > 0 && !c.directions.some((d) => have.includes(d))) return false;
  }
  if (c.custodians !== undefined && c.custodians.length > 0) {
    const custodians = new Set(c.custodians.map((x) => x.trim().toLowerCase()));
    const parties = [...facts.senderAddresses, ...facts.recipientAddresses].map((x) =>
      x.trim().toLowerCase(),
    );
    if (!parties.some((p) => custodians.has(p))) return false;
  }
  return true;
}

/** The first active hold covering the message, or null. */
export function firstMatchingHold<H extends LegalHoldRow>(
  holds: readonly H[],
  facts: LegalHoldFacts,
): H | null {
  return holds.find((h) => legalHoldMatches(h.criteria, facts, h)) ?? null;
}

/** Search filter of a hold (`holdId` filter of A17): its custodians, range and directions. */
export interface HoldSearchCriteria {
  /** Unparsable criteria: the hold covers every record of the organization. */
  matchAll: boolean;
  custodians: string[];
  from: Date | null;
  to: Date | null;
  directions: MessageDirection[];
}

export function holdToSearchCriteria(
  criteria: unknown,
  criteriaVersion?: string | null,
): HoldSearchCriteria {
  const parsed = parseHoldCriteria(criteria, criteriaVersion);
  if (parsed.matchAll) {
    return { matchAll: true, custodians: [], from: null, to: null, directions: [] };
  }
  const c = parsed.criteria;
  return {
    matchAll: false,
    custodians: [...new Set((c.custodians ?? []).map((x) => x.trim().toLowerCase()))],
    from: c.from === undefined ? null : new Date(holdBound(c.from, false)),
    to: c.to === undefined ? null : new Date(holdBound(c.to, true)),
    directions: [...(c.directions ?? [])],
  };
}
