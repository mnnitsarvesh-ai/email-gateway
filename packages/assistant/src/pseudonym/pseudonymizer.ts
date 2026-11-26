import {
  BARE_HOSTNAME_PATTERN,
  DOMAIN_NAME_MODULE,
  URL_AUTHORITY_PATTERN,
  isDomainKey,
  isEmailAddress,
  isFreeTextTld,
  isHostname,
  isIpLiteral,
  isNameKey,
  replaceEmails,
  replaceIps,
  replaceMatches,
  type PseudonymKind,
} from './detect';
import { TextDemapper, demapTokens } from './demapper';
import {
  PLACEHOLDER_PATTERN,
  PSEUDONYM_VALUE_MAX_LENGTH,
  REDACTED_PLACEHOLDER_PATTERN,
  neutralizePlaceholders,
  parsePlaceholder,
  placeholderToken,
  pseudonymValueSha256,
  redactedToken,
  type PseudonymEntry,
} from './tokens';

/**
 * The per-conversation pseudonymizer of the `pseudonymized` data-sharing level (step AI-6 D3,
 * I25). The api builds one per turn from the conversation's stored mapping
 * (`ai_chat_pseudonyms`), applies it to everything the model reads (context block, user message,
 * action updates, recap, tool envelopes after the minimizer), de-maps tool-call arguments and the
 * streamed answer, and inserts `added()` in the turn's finish transaction.
 *
 * - Same normalized value → same token for the conversation's content lifetime; numbering
 *   continues from the highest existing `n` per kind.
 * - Past `maxEntries` (all kinds) a new value becomes `[KIND_REDACTED]` (not stored,
 *   `overflowCount()` counts it); a value longer than 320 characters too (not counted).
 * - Free text: neutralization, then e-mail addresses, IP addresses, `http(s)://` URL hosts and
 *   bare hostnames (ccTLD or the gTLD list). Envelope strings: neutralization, addresses, IPs and
 *   URL hosts, plus the key rules (domain and name keys, `name` of module `domains`);
 *   `{ untrusted_text }` values are free text. Keys are never changed.
 */

/** Deepest envelope nesting walked (deeper values are dropped to null; the minimizer caps at 8). */
const MAX_DEPTH = 32;

type Mode = 'text' | 'structured';

/** A bracketed token or a bare `KIND_n` at word boundaries (tool-call arguments). */
const ARGUMENT_TOKEN = new RegExp(
  `${PLACEHOLDER_PATTERN.source}|\\b(?:EMAIL|IP|DOMAIN|PERSON)_[0-9]{1,6}\\b`,
  'g',
);

export class Pseudonymizer {
  private readonly maxEntries: number;
  private readonly byToken = new Map<string, PseudonymEntry>();
  private readonly byValue = new Map<string, PseudonymEntry>();
  private readonly next: Record<PseudonymKind, number> = { email: 1, ip: 1, domain: 1, name: 1 };
  private readonly created: PseudonymEntry[] = [];
  private overflow = 0;

  constructor(options: { entries: readonly PseudonymEntry[]; maxEntries: number }) {
    if (!Number.isSafeInteger(options.maxEntries) || options.maxEntries < 0)
      throw new Error('maxEntries must be a non-negative integer');
    this.maxEntries = options.maxEntries;
    for (const entry of options.entries) {
      const parsed = parsePlaceholder(entry.token);
      if (!parsed || parsed.kind !== entry.kind) continue;
      this.byToken.set(entry.token, entry);
      this.byValue.set(`${entry.kind}:${entry.valueSha256}`, entry);
      this.next[entry.kind] = Math.max(this.next[entry.kind], parsed.n + 1);
    }
  }

  /** Entries created since construction, in creation order (to insert at the turn's finish). */
  added(): PseudonymEntry[] {
    return [...this.created];
  }

  /** New values that became `[KIND_REDACTED]` because the cap was reached. */
  overflowCount(): number {
    return this.overflow;
  }

  /** The token of a value (an existing one, a new one, or `[KIND_REDACTED]`). */
  tokenFor(kind: PseudonymKind, value: string): string {
    const trimmed = value.trim();
    const sha = pseudonymValueSha256(kind, trimmed);
    const known = this.byValue.get(`${kind}:${sha}`);
    if (known) return known.token;
    if (trimmed.length > PSEUDONYM_VALUE_MAX_LENGTH) return redactedToken(kind);
    if (this.byToken.size >= this.maxEntries || this.next[kind] > 999_999) {
      this.overflow += 1;
      return redactedToken(kind);
    }
    const entry: PseudonymEntry = {
      kind,
      token: placeholderToken(kind, this.next[kind]),
      value: trimmed,
      valueSha256: sha,
    };
    this.next[kind] += 1;
    this.byToken.set(entry.token, entry);
    this.byValue.set(`${kind}:${sha}`, entry);
    this.created.push(entry);
    return entry.token;
  }

  /** Free text (user message, action updates, recap, untrusted text): every rule of D3. */
  text(input: string): string {
    return this.detect(neutralizePlaceholders(input), 'text');
  }

  /** A person's display name (the context block's user) → `[PERSON_n]`. */
  displayName(name: string): string {
    const value = neutralizePlaceholders(name).trim();
    return value.length === 0 ? name : this.tokenFor('name', value);
  }

  /**
   * Every string of an envelope (deep, keys unchanged): addresses, IPs and URL hosts anywhere;
   * the key rules for domains and names; `{ untrusted_text }` as free text.
   */
  envelope<T>(envelope: T, options: { module: string }): T {
    const domainsModule = options.module
      .split(',')
      .map((part) => part.trim())
      .includes(DOMAIN_NAME_MODULE);
    return this.walk(envelope, null, domainsModule, 0) as T;
  }

  /**
   * Tool-call arguments from the model: known tokens (bracketed, or a bare `KIND_n` that is
   * exactly a known token at word boundaries) become the real values; an unknown bracketed token
   * (or an over-cap `[KIND_REDACTED]`) fails with that token.
   */
  demapArguments(args: unknown): { ok: true; value: unknown } | { ok: false; token: string } {
    try {
      return { ok: true, value: this.demapValue(args, 0) };
    } catch (error: unknown) {
      if (error instanceof UnknownPlaceholder) return { ok: false, token: error.token };
      throw error;
    }
  }

  /** Model text: known bracketed tokens → values (unknown tokens stay as written). */
  demapText(text: string): string {
    return demapTokens(text, this.resolve);
  }

  createTextDemapper(): TextDemapper {
    return new TextDemapper(this.resolve);
  }

  private readonly resolve = (token: string): string | null =>
    this.byToken.get(token)?.value ?? null;

  private demapValue(value: unknown, depth: number): unknown {
    if (depth > MAX_DEPTH) return value;
    if (typeof value === 'string') return this.demapString(value);
    if (Array.isArray(value)) return value.map((item) => this.demapValue(item, depth + 1));
    if (value !== null && typeof value === 'object')
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>).map(([key, item]) => [
          key,
          this.demapValue(item, depth + 1),
        ]),
      );
    return value;
  }

  private demapString(value: string): string {
    const redacted = new RegExp(REDACTED_PLACEHOLDER_PATTERN.source).exec(value);
    if (redacted) throw new UnknownPlaceholder(redacted[0]);
    if (!/(?:EMAIL|IP|DOMAIN|PERSON)_[0-9]/.test(value)) return value;
    // One pass (inserted values are never rescanned): a bracketed token must be known; a bare
    // `KIND_n` maps only when it is exactly a known token. The neutralized form `(KIND_n)` of a
    // forged token (inbound text, D3) is never a token: it stays literal, so a mail-derived
    // `[EMAIL_1]` that the model copies cannot map to the conversation's real `[EMAIL_1]`.
    return value.replace(ARGUMENT_TOKEN, (match: string, ...rest: unknown[]) => {
      if (match.startsWith('[')) {
        const real = this.resolve(match);
        if (real === null) throw new UnknownPlaceholder(match);
        return real;
      }
      const offset = rest[rest.length - 2] as number;
      const whole = rest[rest.length - 1] as string;
      if (whole[offset - 1] === '(' && whole[offset + match.length] === ')') return match;
      return this.resolve(`[${match}]`) ?? match;
    });
  }

  private detect(text: string, mode: Mode): string {
    if (text.length === 0) return text;
    let out = replaceEmails(text, (address) => this.tokenFor('email', address));
    out = replaceIps(out, (ip) => this.tokenFor('ip', ip));
    out = this.replaceUrlHosts(out);
    if (mode === 'text')
      out = replaceMatches(out, BARE_HOSTNAME_PATTERN, (host) => {
        const last = host.slice(host.lastIndexOf('.') + 1);
        return isFreeTextTld(last) ? this.tokenFor('domain', host) : null;
      });
    return out;
  }

  /** `http(s)://[userinfo@]host[:port]`: the host becomes a domain (or IP) token. */
  private replaceUrlHosts(text: string): string {
    if (!/https?:\/\//i.test(text)) return text;
    return replaceMatches(text, URL_AUTHORITY_PATTERN, (match, groups) => {
      const authority = groups[0] ?? '';
      const at = authority.lastIndexOf('@');
      const hostAndPort = authority.slice(at + 1);
      if (hostAndPort.startsWith('[')) return null; // IPv6 literal: handled by the IP rule
      const colon = hostAndPort.indexOf(':');
      const host = colon < 0 ? hostAndPort : hostAndPort.slice(0, colon);
      const bare = host.replace(/\.+$/, '');
      if (!isHostname(bare) || isIpLiteral(bare)) return null;
      const prefix = match.slice(0, match.length - authority.length);
      return `${prefix}${authority.slice(0, at + 1)}${this.tokenFor('domain', bare)}${host.slice(bare.length)}${colon < 0 ? '' : hostAndPort.slice(colon)}`;
    });
  }

  /** A domain-key value: an IP, a hostname (`*.` kept) or, otherwise, text with the D3 rules. */
  private domainValue(value: string): string {
    const neutral = neutralizePlaceholders(value);
    const trimmed = neutral.trim();
    if (trimmed.length === 0) return value;
    if (isIpLiteral(trimmed)) return this.tokenFor('ip', trimmed);
    const wildcard = trimmed.startsWith('*.') ? '*.' : '';
    const host = trimmed.slice(wildcard.length);
    if (isHostname(host)) return `${wildcard}${this.tokenFor('domain', host.replace(/\.+$/, ''))}`;
    return this.detect(neutral, 'text');
  }

  /** A name-key value: an address stays an e-mail token, anything else is a person. */
  private nameValue(value: string): string {
    const neutral = neutralizePlaceholders(value);
    const trimmed = neutral.trim();
    if (trimmed.length === 0) return value;
    if (isEmailAddress(trimmed)) return this.tokenFor('email', trimmed);
    return this.tokenFor('name', trimmed);
  }

  private walk(
    value: unknown,
    keyRule: 'domain' | 'name' | null,
    domainsModule: boolean,
    depth: number,
  ): unknown {
    if (depth > MAX_DEPTH) return null;
    if (typeof value === 'string') {
      if (keyRule === 'domain') return this.domainValue(value);
      if (keyRule === 'name') return this.nameValue(value);
      return this.detect(neutralizePlaceholders(value), 'structured');
    }
    if (Array.isArray(value))
      return value.map((item) => this.walk(item, keyRule, domainsModule, depth + 1));
    if (value === null || typeof value !== 'object') return value;
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record);
    if (
      keys.length === 1 &&
      keys[0] === 'untrusted_text' &&
      typeof record.untrusted_text === 'string'
    )
      return {
        untrusted_text:
          keyRule === 'domain'
            ? this.domainValue(record.untrusted_text)
            : keyRule === 'name'
              ? this.nameValue(record.untrusted_text)
              : this.text(record.untrusted_text),
      };
    const out: Record<string, unknown> = {};
    for (const key of keys) {
      const rule =
        isDomainKey(key) || (domainsModule && key === 'name')
          ? 'domain'
          : isNameKey(key)
            ? 'name'
            : null;
      out[key] = this.walk(record[key], rule, domainsModule, depth + 1);
    }
    return out;
  }
}

class UnknownPlaceholder extends Error {
  constructor(readonly token: string) {
    super('unknown placeholder');
  }
}
