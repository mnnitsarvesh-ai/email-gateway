/**
 * The reason codes of the verdict map `url-map/1` (docs/plan/steps/11-url-protection.md U10),
 * in table order (M1 … C1; S1 lookalike codes, then mixed script, then the tenant TLD swap), then
 * the engine-level codes and U5's informational `url.invalid` — the same order as
 * security-contracts `URL_REASON_CODES`. `@email-gateway/security-contracts`
 * holds the same list as `URL_REASON_CODES` (WP1); a contract test asserts equality (WP3).
 * Also the label set of `scan_url_findings_total{code}`.
 */

export const URL_MAP_VERSION = 'url-map/1';

export type UrlVerdict = 'clean' | 'unknown' | 'suspicious' | 'malicious';
export const URL_VERDICT_SEVERITY: Readonly<Record<UrlVerdict, number>> = {
  clean: 1,
  unknown: 2,
  suspicious: 3,
  malicious: 4,
};

/** Code → the verdict it raises (`none` = informational). Order = the U10 table. */
export const URL_CODE_EFFECTS = {
  // M1
  'url.feed_malicious': 'malicious',
  // M2
  'url.dnsbl_phishing': 'malicious',
  'url.dnsbl_malware': 'malicious',
  'url.dnsbl_c2': 'malicious',
  // M3
  'url.phishing_high_confidence': 'malicious',
  // M4
  'url.tenant_blocked': 'malicious',
  // M5
  'url.dynamic_phishing': 'malicious',
  // S1
  'url.lookalike_homoglyph': 'suspicious',
  'url.lookalike_edit_distance': 'suspicious',
  'url.lookalike_combosquat': 'suspicious',
  'url.mixed_script': 'suspicious',
  'url.lookalike_tld_swap': 'suspicious',
  // S2
  'url.new_domain': 'suspicious',
  // S3
  'url.ip_host': 'suspicious',
  'url.redirect_to_ip': 'suspicious',
  // S4
  'url.redirect_limit': 'suspicious',
  'url.many_redirects': 'suspicious',
  // S5 (and S9's "JS redirect into a blocked address")
  'url.redirect_blocked_internal': 'suspicious',
  // S6
  'url.feed_suspicious': 'suspicious',
  'url.dnsbl_spam': 'suspicious',
  // S7
  'url.userinfo': 'suspicious',
  'url.obfuscated_host': 'suspicious',
  'url.ip_obfuscated': 'suspicious',
  'url.entity_obfuscation': 'suspicious',
  'url.control_chars': 'suspicious',
  'url.text_mismatch': 'suspicious',
  'url.too_long': 'suspicious',
  // S8
  'url.credential_form': 'suspicious',
  'url.credential_form_cross_origin': 'suspicious',
  // S9
  'url.dynamic_download': 'suspicious',
  'url.dynamic_cross_origin_form': 'suspicious',
  // U1
  'url.fetch_timeout': 'unknown',
  'url.fetch_dns_error': 'unknown',
  'url.fetch_tls_error': 'unknown',
  'url.fetch_connection_error': 'unknown',
  'url.fetch_http_error': 'unknown',
  'url.fetch_too_large': 'unknown',
  'url.fetch_blocked_port': 'unknown',
  'url.fetch_not_performed': 'unknown',
  // U2
  'url.reputation_unavailable': 'unknown',
  // U3
  'url.dynamic_failed': 'unknown',
  // R (informational)
  'url.shortened': 'none',
  'url.redirected': 'none',
  'url.meta_refresh': 'none',
  'url.idn': 'none',
  'url.brand_tld_variant': 'none',
  'url.nonstandard_port': 'none',
  'url.trailing_dot': 'none',
  'url.in_attachment': 'none',
  'url.allowlisted': 'none',
  'url.charset_guess': 'none',
  'url.fetch_skipped_limit': 'none',
  // C1
  'clean.no_findings': 'clean',
  // Engine level (U0, E1, message codes)
  'url.none': 'none',
  'url.content_incomplete': 'suspicious',
  'url.script_scheme': 'suspicious',
  'url.data_uri': 'suspicious',
  'url.unsafe_scheme': 'suspicious',
  'limit.url_count': 'suspicious',
  // U5: a link whose host fails IDNA / the URL parser (informational message count).
  'url.invalid': 'none',
} as const satisfies Record<string, UrlVerdict | 'none'>;

export type UrlReasonCode = keyof typeof URL_CODE_EFFECTS;

/** Every code of the U10 table and the engine-level codes, in table order. */
export const URL_MAPPER_CODES = Object.keys(URL_CODE_EFFECTS) as readonly UrlReasonCode[];

export const isUrlReasonCode = (code: string): code is UrlReasonCode =>
  Object.prototype.hasOwnProperty.call(URL_CODE_EFFECTS, code);

const EFFECT_RANK: Readonly<Record<UrlVerdict | 'none', number>> = {
  malicious: 4,
  suspicious: 3,
  unknown: 2,
  clean: 1,
  none: 0,
};

/** Severity of the code's effect, then name (the U10 ordering of reason codes). */
export function compareCodes(a: string, b: string): number {
  const ra = isUrlReasonCode(a) ? EFFECT_RANK[URL_CODE_EFFECTS[a]] : -1;
  const rb = isUrlReasonCode(b) ? EFFECT_RANK[URL_CODE_EFFECTS[b]] : -1;
  return rb - ra || (a < b ? -1 : a > b ? 1 : 0);
}

export function sortCodes(codes: Iterable<string>, max = Number.POSITIVE_INFINITY): string[] {
  return [...new Set(codes)].sort(compareCodes).slice(0, max);
}

export function mostSevereVerdict(verdicts: Iterable<UrlVerdict>): UrlVerdict | null {
  let best: UrlVerdict | null = null;
  for (const v of verdicts)
    if (best === null || URL_VERDICT_SEVERITY[v] > URL_VERDICT_SEVERITY[best]) best = v;
  return best;
}
