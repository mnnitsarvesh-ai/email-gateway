import { type Analysis, entropy, latin1 } from './analysis';

/**
 * Generic static checks for every sample (step 4.6 X4 `generic`): the EICAR anti-virus test
 * string, embedded URLs (host names only) and IPv4 literals, and the overall entropy.
 *
 * The EICAR string is assembled from parts at runtime: no file of this repository contains it
 * (a scanner on a developer machine or in CI must not quarantine the source).
 */

const EICAR_PARTS = [
  'X5O!P%@AP[4\\PZX54(P^)7CC)7}',
  '$EICAR-STANDARD-',
  'ANTIVIRUS-TEST-',
  'FILE!$H+H*',
];
/** The 68-byte EICAR test string, built at runtime from parts. */
export function eicarTestString(): string {
  return EICAR_PARTS.join('');
}

/** Host label rules of `URL_HOST_PATTERN` (security-contracts), repeated here for the child. */
const HOST =
  /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$/;
const IPV4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const URL_IN_TEXT = /\b(?:https?|ftp):\/\/([^\s"'<>()\\/?#`{}|^[\]]{1,300})/gi;
const BARE_IPV4 =
  /(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.])/g;

/** True for a canonical IPv4 literal (no leading zeros). */
export function isCanonicalIpv4(value: string): boolean {
  return IPV4.test(value);
}

/**
 * The host of an authority (`user@host:port`), lower case, without userinfo and port; IPv4
 * literals separately; null for anything that is not a valid ASCII host.
 */
export function hostOfAuthority(authority: string): { host?: string; ip?: string } | null {
  let value = authority.trim().toLowerCase();
  const at = value.lastIndexOf('@');
  if (at >= 0) value = value.slice(at + 1);
  if (value.startsWith('[')) return null; // IPv6 literals are not extracted statically
  const colon = value.indexOf(':');
  if (colon >= 0) value = value.slice(0, colon);
  value = value.replace(/\.$/, '');
  if (value.length === 0) return null;
  if (isCanonicalIpv4(value)) return { ip: value };
  if (/^[\d.]+$/.test(value)) return null; // non-canonical numeric host
  if (!HOST.test(value) || !value.includes('.')) return null;
  return { host: value };
}

/** Records the host of every URL in `text` (bounded by the accumulator). */
export function extractUrlHosts(text: string, analysis: Analysis, max = 100_000): number {
  const re = new RegExp(URL_IN_TEXT.source, URL_IN_TEXT.flags);
  let found = 0;
  let match: RegExpExecArray | null;
  while (found < max && (match = re.exec(text)) !== null) {
    found += 1;
    const parsed = hostOfAuthority(match[1] ?? '');
    if (parsed?.host) analysis.host(parsed.host);
    if (parsed?.ip) analysis.ip(parsed.ip);
  }
  return found;
}

/** Records bare IPv4 literals (text formats only: binaries carry version numbers). */
export function extractBareIpv4(text: string, analysis: Analysis, max = 100_000): void {
  const re = new RegExp(BARE_IPV4.source, BARE_IPV4.flags);
  let found = 0;
  let match: RegExpExecArray | null;
  while (found < max && (match = re.exec(text)) !== null) {
    found += 1;
    const ip = match[0];
    // Not an address worth reporting: unspecified, loopback, broadcast.
    if (ip === '0.0.0.0' || ip.startsWith('127.') || ip === '255.255.255.255') continue;
    analysis.ip(ip);
  }
}

/** UTF-16LE text view for binaries that store wide strings (PE resources, LNK, OLE). */
function utf16View(bytes: Buffer, max: number): string {
  const slice = bytes.subarray(0, Math.min(bytes.length, max));
  const even = slice.subarray(0, slice.length - (slice.length % 2)).toString('utf16le');
  const odd =
    slice.length > 1 ? slice.subarray(1, 1 + ((slice.length - 1) & ~1)).toString('utf16le') : '';
  return `${even}\n${odd}`;
}

export interface GenericOptions {
  /** Text-like format: bare IPv4 literals are reported too. */
  text: boolean;
  /** Skip the entropy finding (formats compressed by design, e.g. OOXML). */
  skipEntropy: boolean;
}

export function analyzeGeneric(bytes: Buffer, analysis: Analysis, options: GenericOptions): void {
  if (bytes.includes(Buffer.from(eicarTestString(), 'latin1'))) analysis.add('static.eicar_test');
  const text = latin1(bytes);
  extractUrlHosts(text, analysis);
  if (options.text) extractBareIpv4(text, analysis);
  else if (bytes.length <= 16 * 1024 * 1024)
    extractUrlHosts(utf16View(bytes, 16 * 1024 * 1024), analysis);
  if (analysis.hostTotal > 0) analysis.add('static.embedded_urls', analysis.hostTotal);
  if (analysis.ipTotal > 0) analysis.add('static.embedded_ips', analysis.ipTotal);
  const h = entropy(bytes);
  analysis.fact('entropy', h);
  if (!options.skipEntropy && bytes.length >= 1024 && h > 7.5) analysis.add('static.high_entropy');
}
