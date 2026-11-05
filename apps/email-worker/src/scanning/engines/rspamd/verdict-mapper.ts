import type { NormalizedRspamdResult } from '@email-gateway/rspamd';
import {
  type DefiniteVerdict,
  MAX_REASON_CODES,
  mostSevere,
  type RspamdEffectiveSettings,
  VERDICT_SEVERITY,
} from '@email-gateway/security-contracts';
import { inCategory, type SymbolCategory } from './symbol-catalog';

/** `scan_engine_results.settings_version` prefix and `mappingVersion` of every Rspamd result. */
export const RSPAMD_MAPPING_VERSION = 'rspamd-map/2';

/** `i=` of an ARC symbol option (`<domain>:s=<selector>:i=<instance>`). */
const ARC_INSTANCE = /:i=(\d{1,2})$/;

function arcInstances(options: readonly string[]): number[] {
  return options.flatMap((option) => {
    const match = ARC_INSTANCE.exec(option.trim());
    return match ? [Number(match[1])] : [];
  });
}

/**
 * R6's trust in an ARC chain (step 4.1 S7). `ARC_ALLOW` only proves that the chain verifies
 * cryptographically, and anyone can seal a message with a key of their own domain, so it never
 * suppresses a DMARC failure by itself. The chain is trusted only when all of these hold:
 *
 * - Rspamd verified it (`ARC_ALLOW`) and found no failure (`ARC_REJECT` absent);
 * - `ARC_ALLOW_TRUSTED` is present: a sealer of the chain is on the platform's trusted-sealer list
 *   (RSPAMD_ARC_TRUSTED_SEALERS, Rspamd `whitelisted_signers_map`; empty list = never);
 * - that trusted sealer is the **latest** instance (its `i=` equals the `i=` of `ARC_ALLOW`), so
 *   no untrusted hop sealed (and could have changed) the message after it;
 * - its score is negative: Rspamd multiplies it to 0 when that sealer's
 *   ARC-Authentication-Results itself recorded a DMARC (or SPF without DMARC) failure.
 */
export function isTrustedArcChain(result: NormalizedRspamdResult): boolean {
  const find = (category: SymbolCategory) =>
    result.symbols.find((s) => inCategory(category, s.name, s.score));
  const allow = find('arcAllow');
  const trusted = find('arcTrusted');
  if (!allow || !trusted || find('arcFail')) return false;
  if (!(trusted.score < 0)) return false;
  const latest = Math.max(...arcInstances(allow.options));
  if (!Number.isFinite(latest)) return false;
  return arcInstances(trusted.options).includes(latest);
}

export interface MappedVerdict {
  outcome: DefiniteVerdict;
  /** Ordered by the severity of the rule that added them, then name; at most 32, unique. */
  reasonCodes: string[];
}

/** Severity rank of an informational reason (it raises no verdict). */
const INFORMATIONAL = 0;

/**
 * The Rspamd verdict mapping of step 4.1 S7 (pure): the normalized reply of a complete,
 * schema-valid scan (S9) and the tenant's effective settings (S8) → a definite verdict and its
 * reason codes. Transport failures (R0) never reach it: they are attempt failures.
 *
 * - **R1** a skipped scan (`skipped`, i.e. `is_skipped` without a deciding pre-filter such as
 *   GTUBE) or a reply without symbols → `unknown` (`engine.skipped` / `engine.empty_result`);
 *   evaluation ends. (`engine.too_large` is decided by the engine before any call.)
 * - **R2–R8** may each raise the verdict and add reason codes; **R9** adds informational codes;
 *   the result is the most severe verdict raised, **R10** `clean` (`clean.below_threshold`) when
 *   none was.
 *
 * `clean` is reachable only from here, i.e. from a complete reply that is not skipped, was not
 * decided by a pre-filter and has symbols (§2.0 invariant 1).
 */
export function mapRspamdVerdict(
  result: NormalizedRspamdResult,
  settings: RspamdEffectiveSettings,
): MappedVerdict {
  // R1
  if (result.skipped) return { outcome: 'unknown', reasonCodes: ['engine.skipped'] };
  if (result.symbols.length === 0) {
    return { outcome: 'unknown', reasonCodes: ['engine.empty_result'] };
  }

  const raised: DefiniteVerdict[] = [];
  const codes = new Map<string, number>();
  const add = (code: string, verdict: DefiniteVerdict | null): void => {
    const rank = verdict === null ? INFORMATIONAL : VERDICT_SEVERITY[verdict];
    if ((codes.get(code) ?? -1) < rank) codes.set(code, rank);
    if (verdict !== null) raised.push(verdict);
  };
  const has = (category: SymbolCategory): boolean =>
    result.symbols.some((s) => inCategory(category, s.name, s.score));

  const { score, auth } = result;
  const dmarcFail = auth.dmarc.result === 'fail';
  const spfFail = auth.spf.result === 'fail' || has('spfFail');
  const arcTrusted = isTrustedArcChain(result);

  // R2: known-bad URL feeds and fuzzy phishing.
  if (has('phishingUrl')) add('phishing.known_bad_url', 'malicious');
  if (has('malwareUrl')) add('malware.known_bad_url', 'malicious');
  if (has('fuzzyPhish')) add('fuzzy.phish', 'malicious');

  // R3: link text vs target mismatch.
  if (has('phishingAuthFail')) {
    add('phishing.link_mismatch_auth_failure', 'malicious');
  } else if (has('phishingMismatch')) {
    if (dmarcFail || spfFail || score >= settings.spamScore) {
      add('phishing.link_mismatch_auth_failure', 'malicious');
    } else {
      add('phishing.link_mismatch', settings.phishingVerdict);
    }
  }

  // R4: GTUBE, Rspamd's reject action, fuzzy spam.
  if (has('gtube')) add('spam.gtube', 'spam');
  if (result.action === 'reject') add('spam.reject_action', 'spam');
  if (has('fuzzySpam')) add('fuzzy.spam', 'spam');

  // R5 / R8: score thresholds.
  if (score >= settings.spamScore) add('spam.score', 'spam');
  else if (score >= settings.suspiciousScore) add('spam.suspicious_score', 'suspicious');

  // R6: DMARC policy failures, unless a trusted ARC chain vouches for the message (a chain is
  // trusted only through the platform's trusted-sealer list, see isTrustedArcChain).
  if (has('dmarcReject')) {
    if (arcTrusted) add('auth.dmarc_fail_arc_trusted', null);
    else add('auth.dmarc_reject', settings.dmarcRejectVerdict);
  }
  if (has('dmarcQuarantine')) {
    if (arcTrusted) add('auth.dmarc_fail_arc_trusted', null);
    else add('auth.dmarc_quarantine', 'suspicious');
  }

  // R7: SPF, DKIM and ARC failures (reason only by default).
  const authVerdict: DefiniteVerdict | null =
    settings.authFailureVerdict === 'suspicious' ? 'suspicious' : null;
  if (spfFail) add('auth.spf_fail', authVerdict);
  if (has('dkimFail')) add('auth.dkim_fail', authVerdict);
  if (has('arcFail')) add('auth.arc_fail', authVerdict);

  // R9: informational.
  if (has('ipListed')) add('reputation.ip_listed', null);
  if (has('domainListed')) add('reputation.domain_listed', null);
  if (has('headerAnomaly')) add('header.anomaly', null);
  if (has('bayesSpam')) add('bayes.spam', null);
  if (has('bayesHam')) add('bayes.ham', null);
  if (has('fuzzyUnknown')) add('fuzzy.unknown', null);
  if (has('authTemperror')) add('auth.temperror', null);

  // R1 (pre-filter results): a pre-filter (`passthrough_module`) decided the reply without the
  // full scan. One that raised a verdict (GTUBE → R4) is definite; one that raised none (a
  // whitelisting multimap, `force_actions`, `settings`, ...) is a skipped scan: `unknown`,
  // never clean (§2.0 invariant 1).
  const decided = mostSevere(raised);
  if (decided === null && result.passthroughModule !== null) {
    return { outcome: 'unknown', reasonCodes: ['engine.skipped'] };
  }

  // R10
  const outcome = decided ?? 'clean';
  if (outcome === 'clean') add('clean.below_threshold', null);

  const reasonCodes = [...codes.entries()]
    .sort(([a, ra], [b, rb]) => rb - ra || (a < b ? -1 : a > b ? 1 : 0))
    .slice(0, MAX_REASON_CODES)
    .map(([code]) => code);
  return { outcome, reasonCodes };
}
