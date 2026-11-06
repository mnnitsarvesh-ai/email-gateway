import { createHash } from 'node:crypto';
import { isIPv4 } from 'node:net';
import { domainToUnicode } from 'node:url';
import { parse as parseDomain } from 'tldts';
import { canonicalIp } from './ip';
import { trimC0Space } from './text';

/**
 * URL normalization (docs/plan/steps/11-url-protection.md U5). WHATWG URL parsing (Node 22's Ada:
 * UTS #46 non-transitional IDNA, CheckHyphens=false, UseSTD3ASCIIRules=false), then:
 * lower-case scheme and host, A-label host + U-label display host, default ports removed,
 * trailing dot removed, IP literals canonical, identity form (no userinfo, no fragment) for
 * hashes/feeds/caches, redirect form (no userinfo, with fragment) for the 302 target, and the
 * registrable domain via tldts (private suffixes included, `.test` by the default rule).
 */

export const DEFAULT_MAX_URL_LENGTH = 2048;

export type HostKind = 'domain' | 'ipv4' | 'ipv6';

/** Codes normalization adds to a URL (reason codes of U10 S7/R). */
export type NormalizationFlag =
  | 'url.userinfo'
  | 'url.trailing_dot'
  | 'url.nonstandard_port'
  | 'url.ip_obfuscated'
  | 'url.obfuscated_host'
  | 'url.too_long'
  | 'url.idn';

export interface NormalizedUrl {
  scheme: 'http' | 'https';
  /** ASCII host: A-labels, lower case, no trailing dot; IPv6 without brackets. */
  host: string;
  /** U-label form for display, only when it differs from `host`. */
  unicodeHost: string | null;
  hostKind: HostKind;
  /** Explicit non-default port, else null. */
  port: number | null;
  /** Registrable domain (ASCII), null for IP hosts and public suffixes. */
  registrableDomain: string | null;
  /** Serialization without userinfo and fragment (hashes, feeds, caches). */
  identity: string;
  /** Serialization without userinfo, with fragment (`message_urls.url`, the 302 target). */
  redirect: string;
  /** SHA-256 (hex) of the full identity form. */
  sha256: string;
  /** Identity form longer than the maximum: stored truncated, never rewritten or fetched. */
  truncated: boolean;
  /** `redirect` cut to the maximum length (the stored column value). */
  stored: string;
  flags: NormalizationFlag[];
}

export type NormalizeFailure = 'url.invalid' | 'url.unsupported_scheme';

export type NormalizeResult =
  { ok: true; url: NormalizedUrl } | { ok: false; code: NormalizeFailure; scheme?: string };

export interface NormalizeOptions {
  /** Base URL for relative input (only an absolute http(s) base is used). */
  base?: string | null;
  maxLength?: number;
}

export const sha256Hex = (value: string | Buffer): string =>
  createHash('sha256').update(value).digest('hex');

/** The raw host text of an absolute URL string (between `//` and the path), userinfo/port removed. */
function rawHostOf(input: string): string | null {
  // Browsers strip ASCII tab/newline anywhere and C0/space at both ends before parsing.
  const text = trimC0Space(input.replace(/[\t\n\r]/g, ''), 'start');
  const match = /^[a-z][a-z0-9+.-]*:[\\/]{2}([^\\/?#]*)/i.exec(text);
  if (!match) return null;
  let authority = match[1] ?? '';
  const at = authority.lastIndexOf('@');
  if (at >= 0) authority = authority.slice(at + 1);
  if (authority.startsWith('[')) {
    const end = authority.indexOf(']');
    return end > 0 ? authority.slice(0, end + 1) : authority;
  }
  const colon = authority.lastIndexOf(':');
  return colon >= 0 ? authority.slice(0, colon) : authority;
}

export function normalizeUrl(input: string, options: NormalizeOptions = {}): NormalizeResult {
  const maxLength = options.maxLength ?? DEFAULT_MAX_URL_LENGTH;
  let parsed: URL;
  try {
    const base =
      options.base && /^https?:\/\//i.test(options.base.trim()) ? options.base.trim() : undefined;
    parsed = base === undefined ? new URL(input) : new URL(input, base);
  } catch {
    return { ok: false, code: 'url.invalid' };
  }
  const scheme = parsed.protocol.slice(0, -1).toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') {
    return { ok: false, code: 'url.unsupported_scheme', scheme };
  }
  if (!parsed.hostname) return { ok: false, code: 'url.invalid' };

  const flags = new Set<NormalizationFlag>();
  if (parsed.username || parsed.password) {
    flags.add('url.userinfo');
    parsed.username = '';
    parsed.password = '';
  }

  let hostname = parsed.hostname;
  if (hostname.endsWith('.') && !hostname.startsWith('[')) {
    hostname = hostname.replace(/\.+$/, '');
    if (!hostname) return { ok: false, code: 'url.invalid' };
    flags.add('url.trailing_dot');
    parsed.hostname = hostname;
    if (parsed.hostname !== hostname) return { ok: false, code: 'url.invalid' };
  }

  let hostKind: HostKind = 'domain';
  let host = hostname;
  if (hostname.startsWith('[')) {
    hostKind = 'ipv6';
    host = canonicalIp(hostname) ?? hostname.slice(1, -1);
  } else if (isIPv4(hostname)) {
    hostKind = 'ipv4';
  }

  const rawHost = rawHostOf(input);
  if (rawHost !== null) {
    if (rawHost.includes('%')) flags.add('url.obfuscated_host');
    if (hostKind === 'ipv4') {
      const literal = rawHost.toLowerCase().replace(/\.+$/, '');
      if (literal !== hostname) flags.add('url.ip_obfuscated');
    }
  }

  if (parsed.port !== '') flags.add('url.nonstandard_port');
  const port = parsed.port === '' ? null : Number(parsed.port);

  let unicodeHost: string | null = null;
  if (hostKind === 'domain') {
    if (host.split('.').some((label) => label.startsWith('xn--'))) flags.add('url.idn');
    const unicode = domainToUnicode(host);
    if (unicode && unicode !== host) unicodeHost = unicode;
  }

  const redirect = parsed.href;
  parsed.hash = '';
  const identity = parsed.href;
  const registrableDomain =
    hostKind === 'domain'
      ? (parseDomain(host, { allowPrivateDomains: true }).domain ?? null)
      : null;

  const truncated = identity.length > maxLength || redirect.length > maxLength;
  if (truncated) flags.add('url.too_long');

  return {
    ok: true,
    url: {
      scheme,
      host,
      unicodeHost,
      hostKind,
      port,
      registrableDomain,
      identity,
      redirect,
      sha256: sha256Hex(identity),
      truncated,
      stored: redirect.slice(0, maxLength),
      flags: [...flags].sort(),
    },
  };
}

/** Registrable domain of an ASCII host (null for IPs and public suffixes). */
export function registrableDomainOf(host: string): string | null {
  if (canonicalIp(host) !== null) return null;
  return parseDomain(host, { allowPrivateDomains: true }).domain ?? null;
}

/** The public suffix of an ASCII host per tldts (private suffixes included). */
export function publicSuffixOf(host: string): string | null {
  return parseDomain(host, { allowPrivateDomains: true }).publicSuffix ?? null;
}

/**
 * A host (or registrable domain) typed by an administrator: IDNA to ASCII through the WHATWG
 * parser, lower case, trailing dots removed. Refuses IP literals, single labels and public
 * suffixes (`co.uk`, `github.io`).
 */
export type DomainInputResult =
  | { ok: true; domain: string; registrableDomain: string }
  | { ok: false; code: 'invalid' | 'ip_literal' | 'public_suffix' | 'single_label' };

export function normalizeDomainInput(value: string): DomainInputResult {
  const text = value.trim().replace(/\.+$/, '');
  if (canonicalIp(text) !== null || /^\[.*\]$/.test(text)) return { ok: false, code: 'ip_literal' };
  if (!text || /[\s/\\?#@:]/.test(text)) return { ok: false, code: 'invalid' };
  let host: string;
  try {
    host = new URL(`http://${text}/`).hostname;
  } catch {
    return { ok: false, code: 'invalid' };
  }
  if (isIPv4(host) || host.startsWith('[')) return { ok: false, code: 'ip_literal' };
  if (!host.includes('.')) return { ok: false, code: 'single_label' };
  const info = parseDomain(host, { allowPrivateDomains: true });
  if (!info.domain) return { ok: false, code: 'public_suffix' };
  return { ok: true, domain: host, registrableDomain: info.domain };
}

/** True when `host` equals `domain` or is a subdomain of it (suffix match on whole labels). */
export function hostMatchesDomain(host: string, domain: string): boolean {
  const h = host.toLowerCase().replace(/\.+$/, '');
  const d = domain.toLowerCase().replace(/\.+$/, '');
  return d.length > 0 && (h === d || h.endsWith(`.${d}`));
}

export function hostMatchesAny(host: string, domains: Iterable<string>): boolean {
  for (const domain of domains) if (hostMatchesDomain(host, domain)) return true;
  return false;
}

/** Threat-indicator values (U16): url identity form, ASCII domain, canonical IP; and their hash. */
export type IndicatorType = 'url' | 'domain' | 'ip';
export type IndicatorResult =
  | { ok: true; type: IndicatorType; value: string; valueSha256: string }
  | { ok: false; code: 'invalid' | 'public_suffix' | 'too_long' | 'ip_literal' | 'single_label' };

export function normalizeIndicator(type: IndicatorType, raw: string): IndicatorResult {
  if (type === 'url') {
    const result = normalizeUrl(raw.trim());
    if (!result.ok) return { ok: false, code: 'invalid' };
    if (result.url.truncated) return { ok: false, code: 'too_long' };
    return { ok: true, type, value: result.url.identity, valueSha256: result.url.sha256 };
  }
  if (type === 'ip') {
    const ip = canonicalIp(raw.trim());
    if (ip === null) return { ok: false, code: 'invalid' };
    return { ok: true, type, value: ip, valueSha256: sha256Hex(ip) };
  }
  const domain = normalizeDomainInput(raw);
  if (!domain.ok) return { ok: false, code: domain.code };
  return { ok: true, type, value: domain.domain, valueSha256: sha256Hex(domain.domain) };
}
