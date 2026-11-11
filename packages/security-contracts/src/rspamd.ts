import { z } from 'zod';

/**
 * The Rspamd verdict map `rspamd-map/2` as a contract list (step 5.1 R18,
 * docs/plan/steps/15-risk-scoring.md; ADR-0041 decision 2). The mapper itself stays in the
 * email-worker (`scanning/engines/rspamd/verdict-mapper.ts`); this list is every reason code it
 * (and the Rspamd engine, which decides `engine.too_large` before any call) can emit, so the risk
 * scorer's exhaustiveness test can cover Rspamd like the other engines. An email-worker contract
 * test asserts that the mapper emits only these codes and that its `RSPAMD_MAPPING_VERSION`
 * equals this one.
 */
export const RSPAMD_MAPPING_VERSION = 'rspamd-map/2';

/** Every code of `rspamd-map/2`, in rule order (R2 … R10, then R1 and the engine's own code). */
export const RSPAMD_REASON_CODES = [
  // R2: known-bad URL feeds and fuzzy phishing.
  'phishing.known_bad_url',
  'malware.known_bad_url',
  'fuzzy.phish',
  // R3: link text vs target mismatch.
  'phishing.link_mismatch_auth_failure',
  'phishing.link_mismatch',
  // R4: GTUBE, the reject action, fuzzy spam.
  'spam.gtube',
  'spam.reject_action',
  'fuzzy.spam',
  // R5 / R8: score thresholds.
  'spam.score',
  'spam.suspicious_score',
  // R6: DMARC policy failures (or a trusted ARC chain vouching for one).
  'auth.dmarc_fail_arc_trusted',
  'auth.dmarc_reject',
  'auth.dmarc_quarantine',
  // R7: SPF, DKIM and ARC failures.
  'auth.spf_fail',
  'auth.dkim_fail',
  'auth.arc_fail',
  // R9: informational.
  'reputation.ip_listed',
  'reputation.domain_listed',
  'header.anomaly',
  'bayes.spam',
  'bayes.ham',
  'fuzzy.unknown',
  'auth.temperror',
  // R1: skipped scan, empty reply; the engine's size limit (decided before the call).
  'engine.skipped',
  'engine.empty_result',
  'engine.too_large',
  // R10: clean.
  'clean.below_threshold',
] as const;
export type RspamdReasonCode = (typeof RSPAMD_REASON_CODES)[number];
export const rspamdReasonCodeSchema = z.enum(RSPAMD_REASON_CODES);

export const isRspamdReasonCode = (value: string): value is RspamdReasonCode =>
  (RSPAMD_REASON_CODES as readonly string[]).includes(value);
