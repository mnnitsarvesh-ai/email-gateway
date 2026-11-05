/**
 * Rspamd symbol categories of the verdict mapping (step 4.1 S7), as data: exact names and name
 * prefixes. Names verified against rspamd/rspamd:3.12.1 by WP2 (docs/deployment/rspamd.md,
 * "Verified symbols and reply fields"); names of the production feeds that cannot be reached
 * locally (SURBL, Spamhaus DBL, OpenPhish, PhishTank) are Rspamd's defaults.
 */
export interface SymbolMatcher {
  readonly exact?: readonly string[];
  readonly prefixes?: readonly string[];
  /**
   * Signed single symbols (`SENDER_REP`, `DKIM_REPUTATION`) match only with a score above this
   * (their negative side means good reputation).
   */
  readonly positive?: readonly string[];
}

export const SYMBOL_CATEGORIES = {
  /** R2: phishing URL feeds and the local known-bad-URL map. */
  phishingUrl: {
    exact: ['EG_BAD_URL', 'PH_SURBL_MULTI', 'DBL_PHISH', 'PHISHED_OPENPHISH', 'PHISHED_PHISHTANK'],
  },
  /** R2: malware URL feeds. */
  malwareUrl: { exact: ['MW_SURBL_MULTI', 'DBL_ABUSE_MALWARE', 'DBL_MALWARE'] },
  /** R2: administrator fuzzy phishing hash (flag 12). */
  fuzzyPhish: { exact: ['EG_FUZZY_PHISH'] },
  /** R3: link text vs target mismatch, or the local composite with an authentication failure. */
  phishingMismatch: { exact: ['PHISHING'] },
  phishingAuthFail: { exact: ['EG_PHISH_AUTH_FAIL'] },
  /** R4. */
  gtube: { exact: ['GTUBE'] },
  /** R4: administrator fuzzy spam hash (flag 11). */
  fuzzySpam: { exact: ['EG_FUZZY_SPAM'] },
  /** R6. */
  dmarcReject: { exact: ['DMARC_POLICY_REJECT'] },
  dmarcQuarantine: { exact: ['DMARC_POLICY_QUARANTINE'] },
  arcAllow: { exact: ['ARC_ALLOW'] },
  /**
   * R6: a valid chain with a sealer on the platform's trusted list (Rspamd `arc`
   * `whitelisted_signers_map`, rendered from RSPAMD_ARC_TRUSTED_SEALERS). Rspamd emits it only
   * when that list is configured; ARC_ALLOW alone never vouches for anything (anyone can seal).
   */
  arcTrusted: { exact: ['ARC_ALLOW_TRUSTED'] },
  /** R7. */
  spfFail: { exact: ['R_SPF_FAIL'] },
  dkimFail: { exact: ['R_DKIM_REJECT'] },
  arcFail: { exact: ['ARC_REJECT'] },
  /** R9: IP listed. */
  ipListed: {
    exact: ['IP_REPUTATION_SPAM'],
    prefixes: ['RBL_', 'RECEIVED_', 'EG_TEST_RBL'],
  },
  /** R9: domain listed. */
  domainListed: {
    exact: ['DBL_SPAM', 'SENDER_REP_SPAM'],
    prefixes: ['URIBL_', 'SURBL_', 'EG_TEST_DBL'],
    positive: ['SENDER_REP'],
  },
  /** R9: header anomalies. */
  headerAnomaly: {
    exact: ['EG_DISPLAY_NAME_ADDRESS'],
    prefixes: ['HFILTER_', 'MISSING_', 'MULTIPLE_', 'FORGED_', 'MID_', 'DATE_IN_', 'EG_HDR_'],
  },
  /** R9: Bayes. */
  bayesSpam: { exact: ['BAYES_SPAM'] },
  bayesHam: { exact: ['BAYES_HAM'] },
  /** R9: fuzzy hashes of an unknown flag. */
  fuzzyUnknown: { exact: ['EG_FUZZY_UNKNOWN', 'FUZZY_UNKNOWN'] },
  /** R9: SPF/DKIM/DMARC temporary errors. */
  authTemperror: { exact: ['R_SPF_DNSFAIL', 'R_DKIM_TEMPFAIL', 'DMARC_DNSFAIL'] },
} as const satisfies Record<string, SymbolMatcher>;

export type SymbolCategory = keyof typeof SYMBOL_CATEGORIES;

/** True when a symbol (name, score) belongs to the category. */
export function inCategory(category: SymbolCategory, name: string, score: number): boolean {
  const matcher: SymbolMatcher = SYMBOL_CATEGORIES[category];
  if (matcher.exact?.includes(name)) return true;
  if (matcher.positive?.includes(name)) return score > 0;
  return matcher.prefixes?.some((prefix) => name.startsWith(prefix)) ?? false;
}
