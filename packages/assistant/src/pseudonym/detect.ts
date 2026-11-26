import { isIP } from 'node:net';

/**
 * Entity detection of the `pseudonymized` data-sharing level (step AI-6 D3, I25): pure pattern
 * and key rules, no model. E-mail addresses and IP addresses are found anywhere; domains by key,
 * by module rule (`domains` rows' `name`), as `http(s)://` URL hosts and, in free text only, as
 * bare hostnames whose last label is a two-letter ccTLD or in a fixed gTLD list; person names by
 * key only (free-text names are not detected: limitation A6-3). Public ids (UUIDs), numbers, ISO
 * dates and refs (`r3.2`, `@r3.2`) are never entities.
 */

export const PSEUDONYM_KINDS = ['email', 'ip', 'domain', 'name'] as const;
export type PseudonymKind = (typeof PSEUDONYM_KINDS)[number];

/** Token word per kind (`[EMAIL_3]`, `[IP_1]`, `[DOMAIN_4]`, `[PERSON_2]`). */
export const PSEUDONYM_TOKEN_WORDS: Readonly<Record<PseudonymKind, string>> = {
  email: 'EMAIL',
  ip: 'IP',
  domain: 'DOMAIN',
  name: 'PERSON',
};

/** The gTLDs a bare free-text hostname may end with (besides any two-letter ccTLD). */
export const FREE_TEXT_GTLDS: ReadonlySet<string> = new Set([
  'com',
  'net',
  'org',
  'io',
  'gov',
  'edu',
  'mil',
  'int',
  'info',
  'biz',
  'co',
  'app',
  'dev',
  'cloud',
  'ai',
  'online',
  'site',
  'tech',
  'xyz',
  'email',
]);

const LABEL = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?';

const ATEXT = "A-Za-z0-9!#$%&'*+/=?^_`{|}~-";
const LOCAL_PART = new RegExp(`^[${ATEXT}]+(?:\\.[${ATEXT}]+)*$`);
const ADDRESS_DOMAIN = new RegExp(`^(?:${LABEL}\\.)+[A-Za-z]{2,63}`);
const LOCAL_CHAR = new RegExp(`[.${ATEXT}]`);
const DOMAIN_CHAR = /[A-Za-z0-9.-]/;
/** RFC 5321 limits: 64 octets of local part, 253 of domain. */
const LOCAL_MAX = 64;
const DOMAIN_MAX = 253;

/** A strict whole address: an atext local part and a dotted domain with an alphabetic last label. */
const WHOLE_EMAIL = new RegExp(`^[${ATEXT}]+(?:\\.[${ATEXT}]+)*@(?:${LABEL}\\.)+[A-Za-z]{2,63}$`);

/**
 * Replaces every e-mail address of the text (strict pattern, found around each `@` within the RFC
 * length limits, so the scan stays linear on long untrusted text).
 */
export function replaceEmails(text: string, replace: (address: string) => string): string {
  if (!text.includes('@')) return text;
  let out = '';
  let copied = 0;
  for (let at = text.indexOf('@'); at >= 0; at = text.indexOf('@', at + 1)) {
    if (at < copied) continue;
    let start = at;
    while (start > copied && at - start < LOCAL_MAX && LOCAL_CHAR.test(text[start - 1]!))
      start -= 1;
    let local = text.slice(start, at);
    // the address starts after a run of dots (`a..b@x` → `b@x`), never with a dot or a slash
    // (`https://user@host`: the `//` stays)
    const dots = local.lastIndexOf('..');
    const undotted = local.slice(dots < 0 ? 0 : dots + 2).replace(/^\.+/, '');
    const unslashed = undotted.replace(/^\/+/, '');
    const trimmed = LOCAL_PART.test(unslashed) ? unslashed : undotted;
    start += local.length - trimmed.length;
    local = trimmed;
    if (!LOCAL_PART.test(local)) continue;
    let end = at + 1;
    while (end < text.length && end - at <= DOMAIN_MAX && DOMAIN_CHAR.test(text[end]!)) end += 1;
    const domain = ADDRESS_DOMAIN.exec(text.slice(at + 1, end));
    if (!domain) continue;
    const stop = at + 1 + domain[0].length;
    out += text.slice(copied, start) + replace(text.slice(start, stop));
    copied = stop;
  }
  return out + text.slice(copied);
}

const OCTET = '(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])';
/** Dotted quads with valid octets, not part of a longer dotted number (versions, OIDs). */
export const IPV4_PATTERN = new RegExp(
  `(?<![0-9.])(?:${OCTET}\\.){3}${OCTET}(?![0-9]|\\.[0-9])`,
  'g',
);

/** IPv6 candidates (validated with `net.isIP`; an embedded IPv4 tail is allowed). */
export const IPV6_CANDIDATE_PATTERN =
  /(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f]{0,4})(?![0-9A-Za-z:])/g;

/** `http(s)://` and its authority (userinfo, host, port). */
export const URL_AUTHORITY_PATTERN = /\bhttps?:\/\/([A-Za-z0-9._~%!$&'*+=:@[\]-]+)/gi;

/** Bare hostnames of free text (the last label is checked against the TLD rule). */
export const BARE_HOSTNAME_PATTERN = new RegExp(
  `(?<![A-Za-z0-9@._%+-])(?:${LABEL}\\.)+[A-Za-z]{2,63}(?![A-Za-z0-9-]|\\.[A-Za-z0-9])`,
  'g',
);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HOSTNAME = new RegExp(`^(?:${LABEL}\\.)*${LABEL}\\.?$`);

/** `domain`, `hostname`, `senderDomain`, …, also `x_domain` (design D3 rule (a)). */
export const DOMAIN_KEY_PATTERN =
  /(^|_)(domain|domainName|hostname|host|senderDomain|recipientDomain|fromDomain|rcptDomain|helo|ptr)$/i;

/** `displayName`, `fullName`, `firstName`, `lastName` and `<role>Name` keys (design D3). */
export const NAME_KEY_PATTERN =
  /^(displayName|fullName|firstName|lastName)$|(from|sender|recipient|user|custodian|owner|requester|approver|actor|reviewer|assignee)Name$/i;

/** The module whose rows' `name` is a domain (design D3 rule (b)). */
export const DOMAIN_NAME_MODULE = 'domains';

export function isDomainKey(key: string): boolean {
  return DOMAIN_KEY_PATTERN.test(key);
}

export function isNameKey(key: string): boolean {
  return NAME_KEY_PATTERN.test(key);
}

/** True for an IPv4 or IPv6 literal (`net.isIP`). */
export function isIpLiteral(value: string): boolean {
  return isIP(value) !== 0;
}

/** True for one whole e-mail address. */
export function isEmailAddress(value: string): boolean {
  return WHOLE_EMAIL.test(value);
}

/** A free-text TLD: any two-letter label or one of `FREE_TEXT_GTLDS`. */
export function isFreeTextTld(label: string): boolean {
  const lower = label.toLowerCase();
  return /^[a-z]{2}$/.test(lower) || FREE_TEXT_GTLDS.has(lower);
}

/**
 * A value that is a hostname by syntax (a domain-key value or a URL host): letters, digits and
 * hyphens in dot-separated labels with at least one letter; never a UUID or a number.
 */
export function isHostname(value: string): boolean {
  if (value.length === 0 || value.length > 254) return false;
  if (UUID.test(value) || !/[A-Za-z]/.test(value)) return false;
  return HOSTNAME.test(value);
}

/**
 * Replaces every IP address of the text: IPv6 literals first (validated with `net.isIP`, at least
 * one hex digit, so `::` alone is not one), then IPv4 dotted quads.
 */
export function replaceIps(text: string, replace: (ip: string) => string): string {
  if (!/[0-9a-f]/i.test(text)) return text;
  const v6 = text.includes(':')
    ? replaceMatches(text, IPV6_CANDIDATE_PATTERN, (candidate) =>
        /[0-9a-f]/i.test(candidate) && isIP(candidate) === 6 ? replace(candidate) : null,
      )
    : text;
  return v6.includes('.')
    ? replaceMatches(v6, IPV4_PATTERN, (candidate) =>
        isIP(candidate) === 4 ? replace(candidate) : null,
      )
    : v6;
}

/** Replaces every match of `pattern` for which `replace` returns a string. */
export function replaceMatches(
  text: string,
  pattern: RegExp,
  replace: (match: string, groups: string[]) => string | null,
): string {
  return text.replace(new RegExp(pattern.source, pattern.flags), (match: string, ...rest) => {
    const groups = rest.slice(0, -2).map((g) => (typeof g === 'string' ? g : ''));
    return replace(match, groups) ?? match;
  });
}
