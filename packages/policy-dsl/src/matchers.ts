import { isIP } from 'node:net';
import { RE2JS } from 're2js';
import { POLICY_LIMITS } from './vocabulary';

/**
 * Value matchers of `policy-dsl/1` (step 5.2 P3): the bounded glob matcher, RE2 regexes through
 * `re2js`, IPv4/IPv6 CIDRs and domain/address normalization. No pattern from a policy document
 * is ever compiled to a JavaScript `RegExp`.
 */

// ---------------------------------------------------------------------------------------------
// Glob
// ---------------------------------------------------------------------------------------------

/** A glob is 1..128 printable characters; `*` matches any run, `?` one character. */
export function isValidGlob(pattern: unknown): pattern is string {
  return (
    typeof pattern === 'string' &&
    pattern.length >= 1 &&
    pattern.length <= POLICY_LIMITS.globLength &&
    // eslint-disable-next-line no-control-regex -- fixed platform pattern, not tenant input
    !/[\u0000-\u001f\u007f]/.test(pattern)
  );
}

/**
 * Two-pointer glob match with single-star backtracking (no recursion, no RegExp): at most
 * O(|pattern| × |subject|) steps, both bounded (pattern ≤ 128, subjects ≤ 1 024).
 * Callers lower-case both sides for case-insensitive fields.
 */
export function globMatch(pattern: string, subject: string): boolean {
  let p = 0;
  let s = 0;
  let star = -1;
  let mark = 0;
  while (s < subject.length) {
    const pc = pattern[p];
    if (pc !== undefined && pc !== '*' && (pc === '?' || pc === subject[s])) {
      p += 1;
      s += 1;
    } else if (pc === '*') {
      star = p;
      mark = s;
      p += 1;
    } else if (star !== -1) {
      p = star + 1;
      mark += 1;
      s = mark;
    } else {
      return false;
    }
  }
  while (pattern[p] === '*') p += 1;
  return p === pattern.length;
}

// ---------------------------------------------------------------------------------------------
// Regex (RE2 through re2js)
// ---------------------------------------------------------------------------------------------

export interface RegexSpec {
  pattern: string;
  flags: '' | 'i';
}

/**
 * Constructs RE2 refuses or this platform does not accept (backreferences, lookaround, atomic
 * groups, possessive quantifiers, conditionals), checked on the text so the refusal is stable.
 */
export function hasUnsupportedRegexConstruct(pattern: string): boolean {
  for (let i = 0; i < pattern.length; i += 1) {
    const c = pattern[i]!;
    if (c === '\\') {
      const n = pattern[i + 1];
      if (n !== undefined && /[1-9kg]/.test(n)) return true;
      i += 1;
      continue;
    }
    if (c === '(' && pattern[i + 1] === '?') {
      const rest = pattern.slice(i + 2, i + 5);
      if (/^(?:=|!|<=|<!|>|\(|P=|P>|&|R|\d)/.test(rest)) return true;
    }
    if ((c === '*' || c === '+' || c === '?' || c === '}') && pattern[i + 1] === '+') return true;
  }
  return false;
}

/** Largest counted repetition bound and the product of nested counted repetitions. */
export function regexRepetition(pattern: string): { maxRepeat: number; product: number } {
  const stack: number[] = [1];
  let maxRepeat = 0;
  let product = 1;
  let previous = 1;
  let inClass = false;
  const fold = () => {
    const top = stack.length - 1;
    stack[top] = Math.max(stack[top]!, previous);
    product = Math.max(product, previous);
    previous = 1;
  };
  for (let i = 0; i < pattern.length; i += 1) {
    const c = pattern[i]!;
    if (inClass) {
      if (c === '\\') i += 1;
      else if (c === ']') inClass = false;
      continue;
    }
    if (c === '{') {
      const close = pattern.indexOf('}', i);
      const m =
        close > i ? /^([0-9]{1,6})(?:,([0-9]{0,6}))?$/.exec(pattern.slice(i + 1, close)) : null;
      if (m) {
        const low = Number(m[1]);
        const high = m[2] === undefined || m[2] === '' ? low : Number(m[2]);
        const bound = Math.max(low, high, 1);
        maxRepeat = Math.max(maxRepeat, bound);
        previous *= bound;
        fold();
        i = close;
        continue;
      }
    }
    fold();
    if (c === '\\') {
      i += 1;
    } else if (c === '[') {
      inClass = true;
      if (pattern[i + 1] === '^') i += 1;
      if (pattern[i + 1] === ']') i += 1;
    } else if (c === '(') {
      stack.push(1);
    } else if (c === ')') {
      previous = stack.length > 1 ? stack.pop()! : 1;
    }
  }
  fold();
  return { maxRepeat, product: Math.max(product, ...stack) };
}

export const REGEX_MAX_REPEAT = 100;
export const REGEX_MAX_REPETITION_PRODUCT = 1_000;

/** Compiles a policy regex with RE2 semantics, or returns the refusal reason. */
export function compileRegex(
  spec: RegexSpec,
): { ok: true; re: RE2JS } | { ok: false; reason: string } {
  const { pattern, flags } = spec;
  if (pattern.length < 1 || pattern.length > POLICY_LIMITS.regexLength) {
    return { ok: false, reason: 'length' };
  }
  // eslint-disable-next-line no-control-regex -- fixed platform pattern, not tenant input
  if (/[\u0000-\u001f\u007f]/.test(pattern)) return { ok: false, reason: 'control_character' };
  if (hasUnsupportedRegexConstruct(pattern)) return { ok: false, reason: 'unsupported_construct' };
  const repetition = regexRepetition(pattern);
  if (
    repetition.maxRepeat > REGEX_MAX_REPEAT ||
    repetition.product > REGEX_MAX_REPETITION_PRODUCT
  ) {
    return { ok: false, reason: 'too_complex' };
  }
  try {
    return { ok: true, re: RE2JS.compile(pattern, flags === 'i' ? RE2JS.CASE_INSENSITIVE : 0) };
  } catch {
    return { ok: false, reason: 'syntax' };
  }
}

/** RE2 search on the subject cut to 1 024 characters. */
export function regexFind(re: RE2JS, subject: string): boolean {
  const cut =
    subject.length > POLICY_LIMITS.regexSubject
      ? subject.slice(0, POLICY_LIMITS.regexSubject)
      : subject;
  return re.matcher(cut).find();
}

// ---------------------------------------------------------------------------------------------
// IP addresses and CIDRs (node:net isIP + BigInt arithmetic)
// ---------------------------------------------------------------------------------------------

export interface IpValue {
  family: 4 | 6;
  value: bigint;
}

export interface Cidr {
  family: 4 | 6;
  network: bigint;
  prefix: number;
}

const MAPPED_PREFIX = 0xffffn << 32n;

function parseIpv4(text: string): bigint {
  let v = 0n;
  for (const part of text.split('.')) v = (v << 8n) | BigInt(Number(part));
  return v;
}

function parseIpv6(text: string): bigint | null {
  let head = text;
  let tailV4: bigint | null = null;
  const lastColon = head.lastIndexOf(':');
  if (head.includes('.')) {
    tailV4 = parseIpv4(head.slice(lastColon + 1));
    head = `${head.slice(0, lastColon + 1)}0:0`;
  }
  const halves = head.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] === '' ? [] : halves[0]!.split(':');
  const right = halves.length === 2 ? (halves[1] === '' ? [] : halves[1]!.split(':')) : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const groups = [...left, ...new Array<string>(Math.max(0, missing)).fill('0'), ...right];
  if (groups.length !== 8) return null;
  let v = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    v = (v << 16n) | BigInt(parseInt(g, 16));
  }
  if (tailV4 !== null) v = (v & ~0xffffffffn) | tailV4;
  return v;
}

/**
 * Parses an IP address (no zone id, no brackets). IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is
 * normalized to IPv4. Returns null when the text is not an address.
 */
export function parseIp(text: string): IpValue | null {
  if (typeof text !== 'string' || text.length > 64) return null;
  const kind = isIP(text);
  if (kind === 4) return { family: 4, value: parseIpv4(text) };
  if (kind === 6) {
    if (text.includes('%')) return null;
    const v = parseIpv6(text);
    if (v === null) return null;
    if (v >> 32n === 0xffffn && (v & ~0xffffffffn) === MAPPED_PREFIX) {
      return { family: 4, value: v & 0xffffffffn };
    }
    return { family: 6, value: v };
  }
  return null;
}

/** Canonical text of an address (dotted quad, or RFC 5952 lower-case compressed IPv6). */
export function formatIp(ip: IpValue): string {
  if (ip.family === 4) {
    const v = ip.value;
    return [24n, 16n, 8n, 0n].map((s) => String((v >> s) & 0xffn)).join('.');
  }
  const groups: number[] = [];
  for (let i = 7; i >= 0; i -= 1) groups.push(Number((ip.value >> BigInt(i * 16)) & 0xffffn));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i += 1;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLen && j - i >= 2) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart === -1) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLen).join(':');
  return `${left}::${right}`;
}

/**
 * Parses a CIDR `address/prefix`: prefix within the family range, no host bits set
 * (canonical). An IPv4-mapped IPv6 network with prefix ≥ 96 becomes the IPv4 network.
 */
export function parseCidr(text: unknown): Cidr | null {
  if (typeof text !== 'string' || text.length > 64) return null;
  const slash = text.indexOf('/');
  if (slash <= 0 || slash !== text.lastIndexOf('/')) return null;
  const prefixText = text.slice(slash + 1);
  if (!/^[0-9]{1,3}$/.test(prefixText)) return null;
  let prefix = Number(prefixText);
  const addrText = text.slice(0, slash);
  const kind = isIP(addrText);
  if (kind === 0 || addrText.includes('%')) return null;
  let family: 4 | 6 = kind === 4 ? 4 : 6;
  let network = kind === 4 ? parseIpv4(addrText) : parseIpv6(addrText);
  if (network === null) return null;
  if (prefix > (family === 4 ? 32 : 128)) return null;
  if (family === 6 && (network & ~0xffffffffn) === MAPPED_PREFIX && prefix >= 96) {
    family = 4;
    network &= 0xffffffffn;
    prefix -= 96;
  }
  const bits = family === 4 ? 32 : 128;
  const hostMask = (1n << BigInt(bits - prefix)) - 1n;
  if ((network & hostMask) !== 0n) return null;
  return { family, network, prefix };
}

export function cidrContains(cidr: Cidr, ip: IpValue): boolean {
  if (cidr.family !== ip.family) return false;
  const bits = cidr.family === 4 ? 32 : 128;
  const shift = BigInt(bits - cidr.prefix);
  return ip.value >> shift === cidr.network >> shift;
}

// ---------------------------------------------------------------------------------------------
// Domains and addresses
// ---------------------------------------------------------------------------------------------

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/**
 * Normalizes a domain: Unicode NFC, lower case, trailing dot removed, IDN → ASCII (punycode,
 * WHATWG URL host rules). Returns null for anything that is not a host name of LDH labels
 * (IP literals included).
 */
export function normalizeDomain(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  let text = input.normalize('NFC').toLowerCase();
  if (text.endsWith('.')) text = text.slice(0, -1);
  if (text.length < 1 || text.length > 253) return null;
  let ascii = text;
  // eslint-disable-next-line no-control-regex -- fixed platform pattern, not tenant input
  if (/[^\u0000-\u007f]/.test(text)) {
    if (/[/?#@:\\\s[\]%]/.test(text)) return null;
    try {
      ascii = new URL(`http://${text}/`).hostname;
    } catch {
      return null;
    }
  }
  if (ascii.length > 253) return null;
  const labels = ascii.split('.');
  if (labels.length < 1 || !labels.every((l) => LABEL.test(l))) return null;
  if (isIP(ascii) !== 0) return null;
  return ascii;
}

export interface NormalizedAddress {
  address: string;
  domain: string | null;
  localPart: string;
}

/**
 * Normalizes an address: local part NFC + lower case, domain via `normalizeDomain`; the address
 * is `local@domain` in that form. `domain` is null when the domain part is missing or invalid
 * (the address text is then the lower-cased NFC input).
 */
export function normalizeAddress(input: string): NormalizedAddress {
  const text = input.normalize('NFC').toLowerCase();
  const at = text.lastIndexOf('@');
  if (at <= 0 || at === text.length - 1) {
    return { address: text, domain: null, localPart: at === -1 ? text : text.slice(0, at) };
  }
  const localPart = text.slice(0, at);
  const domain = normalizeDomain(text.slice(at + 1));
  if (domain === null) return { address: text, domain: null, localPart };
  return { address: `${localPart}@${domain}`, domain, localPart };
}

/** `domain_in`: exact or label-suffix (`a.example.com` in `example.com`, not `badexample.com`). */
export function domainIn(domain: string, suffix: string): boolean {
  return domain === suffix || domain.endsWith(`.${suffix}`);
}
