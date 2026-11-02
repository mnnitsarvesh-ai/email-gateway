import { domainToASCII, domainToUnicode } from 'node:url';

/**
 * Domain-name normalization and validation for customer domains (step 2.1, D2 in
 * docs/plan/steps/03-domain-onboarding.md). Used by the api when a domain is added and by
 * `resolveActiveDomain` on the mail path, so both agree on the canonical form stored in
 * `domains.name`: lower-case ASCII (punycode), no trailing dot.
 *
 * No public-suffix-list check: claiming a public suffix would need its owner's DNS (ownership
 * proof), so it is impossible in practice.
 */

export type DomainNameErrorCode = 'invalid' | 'reserved' | 'too_long';

export class DomainNameError extends Error {
  override readonly name = 'DomainNameError';

  constructor(
    readonly code: DomainNameErrorCode,
    message: string,
  ) {
    super(message);
  }
}

export interface NormalizedDomainName {
  /** Lower-case ASCII (IDN labels as `xn--` punycode), no trailing dot: the stored form. */
  ascii: string;
  /** The same name with IDN labels decoded, for display. */
  unicode: string;
}

export interface NormalizeDomainNameOptions {
  /**
   * Accept the RFC 2606 / RFC 6761 test names (`test`, `example`, `example.com|net|org` and
   * names under them). The api passes `APP_ENV ∈ {local, ci}`; the mail-path resolver passes
   * `true` (it only looks names up).
   */
  allowTestNames: boolean;
}

/** Maximum length of a domain name in presentation form, without the trailing dot (RFC 1035). */
export const MAX_DOMAIN_NAME_LENGTH = 253;
/** Maximum length of one label (RFC 1035). */
export const MAX_DOMAIN_LABEL_LENGTH = 63;
/**
 * Inputs longer than this are rejected before IDN processing (bounded work per call). IDN
 * mapping can shrink a name (ignored code points), so the cap is well above 253.
 */
const MAX_INPUT_LENGTH = 1024;

/** Special-use names (RFC 6761, RFC 6762, RFC 7686, RFC 9476, ICANN `.internal`): never valid. */
export const ALWAYS_RESERVED_DOMAIN_SUFFIXES: readonly string[] = Object.freeze([
  'localhost',
  'local',
  'invalid',
  'arpa',
  'onion',
  'internal',
  'alt',
]);

/** Test and documentation names (RFC 2606, RFC 6761): valid only with `allowTestNames`. */
export const TEST_DOMAIN_SUFFIXES: readonly string[] = Object.freeze([
  'test',
  'example',
  'example.com',
  'example.net',
  'example.org',
]);

// eslint-disable-next-line no-control-regex -- control characters are exactly what is rejected
const ASCII_NOT_LDH_OR_DOT = /[\x00-\x2c\x2f\x3a-\x40\x5b-\x60\x7b-\x7f]/;
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const TOP_LEVEL_LABEL = /^(?:[a-z]+|xn--[a-z0-9-]+)$/;

/** True when `name` equals `suffix` or is a subdomain of it (both lower-case ASCII). */
export function isDomainAtOrUnder(name: string, suffix: string): boolean {
  return name === suffix || name.endsWith(`.${suffix}`);
}

/**
 * Normalizes and validates a customer domain name (D2):
 *
 * - trims, strips **one** trailing dot, converts IDN to punycode (`node:url` `domainToASCII`,
 *   UTS #46), lower-cases;
 * - ASCII length ≤ 253 (`too_long`);
 * - at least two labels, each 1–63 characters of `[a-z0-9-]` not starting or ending with `-`
 *   (`xn--` labels allowed), the last label alphabetic or `xn--…`; rejects `*`, `_`, `%`,
 *   IPv4/IPv6 literals and empty labels (`invalid`);
 * - rejects special-use names (`localhost`, `local`, `invalid`, `arpa`, `onion`, `internal`,
 *   `alt`, and names under them) always, and test names unless `allowTestNames` (`reserved`).
 *
 * @throws DomainNameError
 */
export function normalizeDomainName(
  input: string,
  options: NormalizeDomainNameOptions,
): NormalizedDomainName {
  if (typeof input !== 'string') {
    throw new DomainNameError('invalid', 'Domain name must be a string');
  }
  if (input.length > MAX_INPUT_LENGTH) {
    throw new DomainNameError('too_long', 'Domain name is too long');
  }
  let candidate = input.trim();
  if (candidate.endsWith('.')) candidate = candidate.slice(0, -1);
  if (candidate.length === 0) {
    throw new DomainNameError('invalid', 'Domain name is empty');
  }
  // Only letters, digits, '-' and '.' are allowed in the ASCII range. This also rejects '*',
  // '_' and IP-literal brackets, and must run before domainToASCII: the URL host parser stops at
  // '/', '?', '#' and '\' (`acme.com/x` would become `acme.com`) and percent-decodes '%'.
  // Non-ASCII input is left to UTS #46 mapping, which rejects full-width delimiters.
  if (ASCII_NOT_LDH_OR_DOT.test(candidate)) {
    throw new DomainNameError('invalid', 'Domain name contains a character that is not allowed');
  }

  const converted = domainToASCII(candidate);
  if (converted.length === 0) {
    throw new DomainNameError('invalid', 'Domain name is not a valid hostname');
  }
  const ascii = converted.toLowerCase();
  if (ascii.length > MAX_DOMAIN_NAME_LENGTH) {
    throw new DomainNameError(
      'too_long',
      `Domain name is longer than ${MAX_DOMAIN_NAME_LENGTH} characters`,
    );
  }

  const labels = ascii.split('.');
  for (const label of labels) {
    if (label.length === 0) {
      throw new DomainNameError('invalid', 'Domain name has an empty label');
    }
    if (label.length > MAX_DOMAIN_LABEL_LENGTH) {
      throw new DomainNameError(
        'invalid',
        `Domain name has a label longer than ${MAX_DOMAIN_LABEL_LENGTH} characters`,
      );
    }
    if (!LABEL.test(label)) {
      throw new DomainNameError(
        'invalid',
        'Domain name labels may contain only letters, digits and inner hyphens',
      );
    }
  }

  for (const suffix of ALWAYS_RESERVED_DOMAIN_SUFFIXES) {
    if (isDomainAtOrUnder(ascii, suffix)) {
      throw new DomainNameError('reserved', `Domain name is reserved (${suffix})`);
    }
  }
  if (!options.allowTestNames) {
    for (const suffix of TEST_DOMAIN_SUFFIXES) {
      if (isDomainAtOrUnder(ascii, suffix)) {
        throw new DomainNameError('reserved', `Domain name is reserved for testing (${suffix})`);
      }
    }
  }

  if (labels.length < 2) {
    throw new DomainNameError('invalid', 'Domain name must have at least two labels');
  }
  // Rejects IPv4 literals (numeric last label) and numeric top-level labels.
  if (!TOP_LEVEL_LABEL.test(labels[labels.length - 1]!)) {
    throw new DomainNameError('invalid', 'Domain name must end with an alphabetic top-level label');
  }

  return { ascii, unicode: domainToUnicode(ascii) || ascii };
}
