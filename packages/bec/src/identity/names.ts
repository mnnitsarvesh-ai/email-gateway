import { isHighlyRestrictive, skeleton } from '@email-gateway/url-security';

/**
 * Display-name normalization for profile matching (docs/plan/steps/12-phishing-bec.md B5):
 * NFKC → remove `\p{Cf}` (zero-width, bidi, format; recorded) → case fold → keep letters,
 * marks, digits and spaces → collapse whitespace → tokens, plus the UTS #39 skeleton of each
 * token (url-security `skeleton`), so `Аnita` with a Cyrillic А matches `anita`.
 */

export interface NormalizedName {
  /** Tokens joined by one space. */
  normalized: string;
  tokens: string[];
  skeletons: string[];
  /** The input had invisible / bidi / format characters (`\p{Cf}`). */
  invisibleChars: boolean;
  /** Some token fails UTS #39 Highly Restrictive (mixed script). */
  mixedScript: boolean;
}

const FORMAT_CHARS = /\p{Cf}/gu;
const NOT_NAME_CHAR = /[^\p{L}\p{M}\p{N}\s]+/gu;

export function normalizeName(value: string): NormalizedName {
  const nfkc = value.normalize('NFKC');
  const stripped = nfkc.replace(FORMAT_CHARS, '');
  const invisibleChars = stripped.length !== nfkc.length;
  const folded = stripped.toLowerCase().replace(NOT_NAME_CHAR, ' ');
  const tokens = folded.split(/\s+/u).filter(Boolean);
  const skeletons = tokens.map((token) => skeleton(token));
  const mixedScript = tokens.some((token) => !isHighlyRestrictive(token));
  return { normalized: tokens.join(' '), tokens, skeletons, invisibleChars, mixedScript };
}

export type NameMatchKind = 'exact' | 'token_set' | 'confusable';

/** Single-token profile names must be at least this long (and match exactly). */
export const MIN_SINGLE_TOKEN_NAME_LENGTH = 4;

const RANK: Record<NameMatchKind, number> = { exact: 3, token_set: 2, confusable: 1 };

/**
 * Matches a display name against one profile name or alias. Multi-token names match when the
 * display name's token set contains every profile token (order-insensitive), or the full
 * normalized strings are equal; single-token names need an exact full match of ≥ 4 characters.
 * A match only through skeletons is `confusable`.
 */
export function matchName(display: NormalizedName, profile: NormalizedName): NameMatchKind | null {
  if (profile.tokens.length === 0 || display.tokens.length === 0) return null;
  if (display.normalized === profile.normalized) {
    if (
      profile.tokens.length < 2 &&
      [...profile.normalized].length < MIN_SINGLE_TOKEN_NAME_LENGTH
    ) {
      return null;
    }
    return 'exact';
  }
  if (profile.tokens.length < 2) {
    if ([...profile.normalized].length < MIN_SINGLE_TOKEN_NAME_LENGTH) return null;
    return display.skeletons.join(' ') === profile.skeletons.join(' ') ? 'confusable' : null;
  }
  const tokenSet = new Set(display.tokens);
  if (profile.tokens.every((token) => tokenSet.has(token))) return 'token_set';
  const skeletonSet = new Set(display.skeletons);
  if (profile.skeletons.every((s) => skeletonSet.has(s))) return 'confusable';
  return null;
}

/** Best match of a display name over a profile's name and aliases. */
export function matchProfileNames(
  display: NormalizedName,
  names: readonly NormalizedName[],
): NameMatchKind | null {
  let best: NameMatchKind | null = null;
  for (const name of names) {
    const match = matchName(display, name);
    if (match && (best === null || RANK[match] > RANK[best])) best = match;
    if (best === 'exact') break;
  }
  return best;
}
