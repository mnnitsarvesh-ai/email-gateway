import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { PSEUDONYM_TOKEN_WORDS, type PseudonymKind } from './detect';

/**
 * Placeholder tokens of the `pseudonymized` level (step AI-6 D3): `[KIND_n]`, `n` per kind and
 * conversation from 1, at most six digits; `[KIND_REDACTED]` past the per-conversation cap
 * (irreversible). Inbound text is neutralized first (`[EMAIL_1]` → `(EMAIL_1)`), so neither a
 * user nor a mail-derived string can forge a token.
 */

export interface PseudonymEntry {
  kind: PseudonymKind;
  /** `[EMAIL_3]`. */
  token: string;
  /** The value as first seen (content: deleted at the conversation's content purge). */
  value: string;
  /** SHA-256 (hex) of the normalized value (`normalizePseudonymValue`). */
  valueSha256: string;
}

/** The token grammar (global; reset `lastIndex` or use `new RegExp(source, flags)`). */
export const PLACEHOLDER_PATTERN = /\[(EMAIL|IP|DOMAIN|PERSON)_[0-9]{1,6}\]/g;

/** An irreversible over-cap placeholder (`[EMAIL_REDACTED]`). */
export const REDACTED_PLACEHOLDER_PATTERN = /\[(EMAIL|IP|DOMAIN|PERSON)_REDACTED\]/g;

/** The executor's message code of an unknown placeholder in tool arguments (`denied_schema`). */
export const UNKNOWN_PLACEHOLDER_CODE = 'assistant_unknown_placeholder';

/** The longest token (`[DOMAIN_999999]`, `[PERSON_999999]`): 15 characters. */
export const PLACEHOLDER_MAX_LENGTH = 15;

/** The longest stored value (`ai_chat_pseudonyms.value` VARCHAR(320)). */
export const PSEUDONYM_VALUE_MAX_LENGTH = 320;

const KIND_OF_WORD: Readonly<Record<string, PseudonymKind>> = Object.fromEntries(
  Object.entries(PSEUDONYM_TOKEN_WORDS).map(([kind, word]) => [word, kind as PseudonymKind]),
);

/** Rewrites token-shaped substrings of inbound text to `(KIND_n)` (design D3, neutralization). */
export function neutralizePlaceholders(text: string): string {
  if (!text.includes('[')) return text;
  return text.replace(
    new RegExp(PLACEHOLDER_PATTERN.source, 'g'),
    (token) => `(${token.slice(1, -1)})`,
  );
}

/** `[EMAIL_3]` for kind `email` and 3. */
export function placeholderToken(kind: PseudonymKind, n: number): string {
  return `[${PSEUDONYM_TOKEN_WORDS[kind]}_${n}]`;
}

/** `[EMAIL_REDACTED]`. */
export function redactedToken(kind: PseudonymKind): string {
  return `[${PSEUDONYM_TOKEN_WORDS[kind]}_REDACTED]`;
}

/** The kind and number of a token (`[EMAIL_3]` → `{ kind: 'email', n: 3 }`), or null. */
export function parsePlaceholder(token: string): { kind: PseudonymKind; n: number } | null {
  const match = /^\[(EMAIL|IP|DOMAIN|PERSON)_([0-9]{1,6})\]$/.exec(token);
  if (!match) return null;
  const n = Number(match[2]);
  return n >= 1 ? { kind: KIND_OF_WORD[match[1]!]!, n } : null;
}

/** Canonical IP text: IPv4 as is, IPv6 compressed lower-case (RFC 5952 via the URL serializer). */
export function canonicalIp(value: string): string {
  const bare = value.trim().replace(/^\[|\]$/g, '');
  const version = isIP(bare);
  if (version === 4) return bare;
  if (version === 6) {
    try {
      return new URL(`http://[${bare}]/`).hostname.slice(1, -1);
    } catch {
      return bare.toLowerCase();
    }
  }
  return bare.toLowerCase();
}

/**
 * The comparison form of a value: e-mail local part as typed + lower-cased domain, IPs canonical,
 * domains lower-case without a trailing dot, names whitespace-collapsed.
 */
export function normalizePseudonymValue(kind: PseudonymKind, value: string): string {
  const trimmed = value.trim();
  switch (kind) {
    case 'email': {
      const at = trimmed.lastIndexOf('@');
      return at < 0
        ? trimmed
        : `${trimmed.slice(0, at)}@${trimmed
            .slice(at + 1)
            .toLowerCase()
            .replace(/\.+$/, '')}`;
    }
    case 'ip':
      return canonicalIp(trimmed);
    case 'domain':
      return trimmed.toLowerCase().replace(/\.+$/, '');
    case 'name':
      return trimmed.replace(/\s+/g, ' ');
  }
}

/** SHA-256 (hex) of the normalized value (`ai_chat_pseudonyms.value_sha256`). */
export function pseudonymValueSha256(kind: PseudonymKind, value: string): string {
  return createHash('sha256').update(normalizePseudonymValue(kind, value), 'utf8').digest('hex');
}
