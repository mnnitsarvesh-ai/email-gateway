import { isIP } from 'node:net';
import type { LookalikeFinding } from '../lookalike/lookalike';
import { hostMatchesAny, normalizeUrl, type HostKind } from '../normalize/url';
import type { FetchHop, FetchResult } from '../net/fetcher';
import { INTERNAL_BLOCK_REASONS } from '../net/ssrf-guard';
import type { DynamicSignals } from '../reputation/cache';
import type { ProviderAnswer } from '../reputation/types';
import {
  URL_CODE_EFFECTS,
  isUrlReasonCode,
  sortCodes,
  type UrlReasonCode,
  type UrlVerdict,
} from './codes';

/**
 * The verdict map `url-map/1` (U10), pure, shared by the URL engine (scan time) and the
 * click-service (click time, with M5/S9/U3). Every applicable rule adds its code; the verdict is
 * the most severe (`malicious > suspicious > unknown > clean`); `clean` only by C1. Tenant
 * `allowedDomains` suppresses lookalike, new-domain, structure and landing rules
 * (`url.allowlisted`), never M1/M2.
 */

export interface UrlMapInput {
  phase: 'scan' | 'click';
  url: { host: string; hostKind: HostKind; registrableDomain: string | null; truncated: boolean };
  /** Extraction and normalization codes of the URL (U4, U5). */
  flags: readonly string[];
  /** Answers for the URL's items, its chain hops and its final URL (all providers). */
  reputation: ReadonlyArray<
    Pick<ProviderAnswer, 'status' | 'category' | 'severity' | 'detail'> & { provider: string }
  >;
  /** Lookalike result of the URL (and, merged by the caller, of its final URL). */
  lookalike: {
    findings: readonly LookalikeFinding[];
    mixedScript: boolean;
    idn: boolean;
    highConfidence: boolean;
  } | null;
  /** Host is a shortener (U9). */
  shortened: boolean;
  fetch: {
    /** A fetch was required (shortener): not performing it can never be clean. */
    required: boolean;
    /** Selected but above URL_FETCH_MAX_PER_MESSAGE (`url.fetch_skipped_limit`). */
    skippedLimit: boolean;
    /** Null when no fetch was attempted. */
    result: Pick<
      FetchResult,
      'status' | 'error' | 'blockedReason' | 'hops' | 'finalUrl' | 'landing'
    > | null;
  };
  /** Click time only: the latest dynamic inspection of the URL. */
  dynamic?: { status: 'completed' | 'failed'; signals: DynamicSignals | null } | null;
  tenant: { allowedDomains: readonly string[]; blockedDomains: readonly string[] };
  /** URL_FETCH_SUSPICIOUS_HOPS. */
  suspiciousHops: number;
}

export interface UrlMapResult {
  verdict: UrlVerdict;
  reasonCodes: UrlReasonCode[];
}

/** Codes suppressed for an allow-listed URL (lookalike, new domain, structure, landing). */
const ALLOWLIST_SUPPRESSED = new Set<UrlReasonCode>([
  'url.lookalike_homoglyph',
  'url.lookalike_edit_distance',
  'url.lookalike_combosquat',
  'url.lookalike_tld_swap',
  'url.mixed_script',
  'url.phishing_high_confidence',
  'url.dynamic_phishing',
  'url.new_domain',
  'url.ip_host',
  'url.redirect_to_ip',
  'url.many_redirects',
  'url.redirect_limit',
  'url.userinfo',
  'url.obfuscated_host',
  'url.ip_obfuscated',
  'url.entity_obfuscation',
  'url.control_chars',
  'url.text_mismatch',
  'url.too_long',
  'url.credential_form',
  'url.credential_form_cross_origin',
  'url.dynamic_download',
  'url.dynamic_cross_origin_form',
]);

const FETCH_ERROR_CODES: Readonly<Record<string, UrlReasonCode>> = {
  timeout: 'url.fetch_timeout',
  dns_error: 'url.fetch_dns_error',
  tls_error: 'url.fetch_tls_error',
  connection_error: 'url.fetch_connection_error',
  http_error: 'url.fetch_http_error',
  too_large: 'url.fetch_too_large',
  header_limit: 'url.fetch_http_error',
};

const S7_FLAGS: readonly UrlReasonCode[] = [
  'url.userinfo',
  'url.obfuscated_host',
  'url.ip_obfuscated',
  'url.entity_obfuscation',
  'url.control_chars',
  'url.text_mismatch',
  'url.too_long',
];
const R_FLAGS: readonly UrlReasonCode[] = [
  'url.idn',
  'url.nonstandard_port',
  'url.trailing_dot',
  'url.in_attachment',
  'url.charset_guess',
];

const isMaliciousCategory = (category: string | null): boolean =>
  category === 'phishing' || category === 'malware' || category === 'c2';

function hostOf(url: string | null): string | null {
  if (!url) return null;
  const result = normalizeUrl(url);
  return result.ok ? result.url.host : null;
}

export function mapUrlVerdict(input: UrlMapInput): UrlMapResult {
  const codes = new Set<UrlReasonCode>();
  const finalHost = hostOf(input.fetch.result?.finalUrl ?? null);
  const allowlisted =
    hostMatchesAny(input.url.host, input.tenant.allowedDomains) ||
    (input.url.registrableDomain !== null &&
      hostMatchesAny(input.url.registrableDomain, input.tenant.allowedDomains));

  // M1 / S6 (local feed), M2 / S6 (DNSBL), S2 (rdap), U2 (any provider error).
  for (const answer of input.reputation) {
    if (answer.status === 'error') {
      codes.add('url.reputation_unavailable');
      continue;
    }
    if (answer.status !== 'listed') continue;
    if (answer.provider === 'local_feed') {
      codes.add(
        answer.severity === 'high' || answer.severity === 'critical'
          ? 'url.feed_malicious'
          : 'url.feed_suspicious',
      );
    } else if (answer.provider === 'dnsbl') {
      if (answer.category === 'phishing') codes.add('url.dnsbl_phishing');
      else if (answer.category === 'malware') codes.add('url.dnsbl_malware');
      else if (answer.category === 'c2') codes.add('url.dnsbl_c2');
      else codes.add('url.dnsbl_spam');
    } else if (answer.provider === 'rdap') {
      if (answer.detail === 'new_domain') codes.add('url.new_domain');
    } else if (
      isMaliciousCategory(answer.category) ||
      answer.severity === 'high' ||
      answer.severity === 'critical'
    ) {
      // A provider added later behind the same interface: malicious categories map like the feed.
      codes.add('url.feed_malicious');
    } else {
      codes.add('url.feed_suspicious');
    }
  }

  // M4: tenant block list (host or registrable domain of the URL or its final URL).
  const blockedHosts = [input.url.host, ...(finalHost ? [finalHost] : [])];
  if (blockedHosts.some((host) => hostMatchesAny(host, input.tenant.blockedDomains)))
    codes.add('url.tenant_blocked');

  // S1 + informational L5/L6.
  const lookalike = input.lookalike;
  if (lookalike) {
    for (const finding of lookalike.findings) {
      if (finding.rule === 'L1') codes.add('url.lookalike_homoglyph');
      else if (finding.rule === 'L2') codes.add('url.lookalike_edit_distance');
      else if (finding.rule === 'L3') codes.add('url.lookalike_combosquat');
      else
        codes.add(
          finding.targetKind === 'brand' ? 'url.brand_tld_variant' : 'url.lookalike_tld_swap',
        );
    }
    if (lookalike.mixedScript) codes.add('url.mixed_script');
    if (lookalike.idn) codes.add('url.idn');
  }

  // S3: IP literal host, a hop or the final URL on an IP literal.
  if (input.url.hostKind !== 'domain') codes.add('url.ip_host');
  const result = input.fetch.result;
  const hops: readonly FetchHop[] = result?.hops ?? [];
  if (
    hops.slice(1).some((hop) => isIP(hop.host) !== 0) ||
    (finalHost !== null && isIP(finalHost) !== 0 && finalHost !== input.url.host)
  ) {
    codes.add('url.redirect_to_ip');
  }

  // Fetch outcome: S4, S5, U1, R.
  if (result) {
    const redirects = Math.max(0, hops.length - 1);
    if (redirects > 0) codes.add('url.redirected');
    if (hops.some((hop) => hop.kind === 'meta')) codes.add('url.meta_refresh');
    if (redirects >= input.suspiciousHops) codes.add('url.many_redirects');
    if (result.status === 'blocked') {
      const reason = result.blockedReason;
      if (reason === 'port') codes.add('url.fetch_blocked_port');
      else if (reason !== null && (INTERNAL_BLOCK_REASONS.has(reason) || reason === 'scheme')) {
        codes.add('url.redirect_blocked_internal');
      } else codes.add('url.fetch_not_performed');
    } else if (result.status === 'error') {
      if (result.error === 'redirect_limit') codes.add('url.redirect_limit');
      else codes.add(FETCH_ERROR_CODES[result.error ?? ''] ?? 'url.fetch_connection_error');
    }
    // S8: credential form on the landing page.
    const landing = result.landing;
    if (landing && landing.passwordFields > 0) {
      codes.add('url.credential_form');
      if (landing.crossOriginFormAction) codes.add('url.credential_form_cross_origin');
    }
  } else if (input.fetch.required) {
    codes.add('url.fetch_not_performed');
  }
  if (input.fetch.skippedLimit) codes.add('url.fetch_skipped_limit');
  if (input.shortened) codes.add('url.shortened');

  // M3: high-confidence lookalike AND a credential form (static, or dynamic at click time).
  const dynamic = input.phase === 'click' ? (input.dynamic ?? null) : null;
  const dynamicSignals = dynamic?.status === 'completed' ? dynamic.signals : null;
  const passwordStatic = (result?.landing?.passwordFields ?? 0) > 0;
  const passwordDynamic = (dynamicSignals?.passwordFields ?? 0) > 0;
  if (lookalike?.highConfidence && (passwordStatic || passwordDynamic))
    codes.add('url.phishing_high_confidence');

  // M5 / S9 / U3 (click time, dynamic inspection).
  if (dynamicSignals) {
    if (
      passwordDynamic &&
      (lookalike?.highConfidence || dynamicSignals.titleBrandMatches.length > 0)
    ) {
      codes.add('url.dynamic_phishing');
    }
    if (dynamicSignals.downloadAttempted) codes.add('url.dynamic_download');
    if (dynamicSignals.crossOriginFormAction) codes.add('url.dynamic_cross_origin_form');
    if (dynamicSignals.jsRedirect && dynamicSignals.blockedRequests > 0)
      codes.add('url.redirect_blocked_internal');
  }

  // S7 + R flags from extraction/normalization.
  for (const flag of input.flags) {
    if (!isUrlReasonCode(flag)) continue;
    if (S7_FLAGS.includes(flag) || R_FLAGS.includes(flag)) codes.add(flag);
  }
  if (input.url.truncated) codes.add('url.too_long');

  if (allowlisted) {
    for (const code of [...codes]) if (ALLOWLIST_SUPPRESSED.has(code)) codes.delete(code);
    codes.add('url.allowlisted');
  }

  // U3: dynamic inspection failed, only if no other rule decided.
  const decided = (): boolean => [...codes].some((code) => URL_CODE_EFFECTS[code] !== 'none');
  if (dynamic?.status === 'failed' && !decided()) codes.add('url.dynamic_failed');

  let verdict: UrlVerdict = 'clean';
  for (const code of codes) {
    const effect = URL_CODE_EFFECTS[code];
    if (effect === 'malicious') verdict = 'malicious';
    else if (effect === 'suspicious' && verdict !== 'malicious') verdict = 'suspicious';
    else if (effect === 'unknown' && verdict === 'clean') verdict = 'unknown';
  }
  // C1: every provider answered, any attempted fetch completed, nothing raised.
  if (verdict === 'clean') {
    const fetchOk = result === null ? !input.fetch.required : result.status === 'completed';
    if (!fetchOk) {
      codes.add('url.fetch_not_performed');
      verdict = 'unknown';
    } else {
      codes.add('clean.no_findings');
    }
  }
  return { verdict, reasonCodes: sortCodes(codes) as UrlReasonCode[] };
}
