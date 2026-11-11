import {
  ATTACHMENT_REASON_CODES,
  BEC_REASON_CODES,
  DLP_REASON_CODES,
  ENGINE_NAMES,
  type EngineName,
  SANDBOX_REASON_CODES,
} from '@email-gateway/security-contracts';
import type { RiskVerdict } from './vocabulary';

/**
 * The versioned signal map `risk-signals/1` (step 5.1 R3, docs/plan/steps/15-risk-scoring.md;
 * ADR-0041 decision 2), as data. A **signal** is one fact about the message; it lists the
 * `engine:code` pairs that assert it (several engines asserting the same fact raise it once),
 * its group, its weight (integer points on 0–1000), whether trust may reduce it (R7) and the
 * directions it applies to. A **group** combines the weights of its fired signals with one rule
 * (`max` or `capped_sum`): overlapping evidence shares a group, so it is never counted twice.
 *
 * Signals derived from the structured inputs rather than reason codes (DLP action, severity and
 * coverage; sandbox outcome; engine failures and unknown results) list pseudo assertions of the
 * form `<engine>:<input fact>` (e.g. `dlp:action.quarantine`, `rspamd:status.failed`); they are
 * recorded in contributions exactly like codes and never collide with an engine's own codes.
 */

export const RISK_SIGNAL_GROUPS = [
  'auth_dmarc',
  'auth_other',
  'spam',
  'reputation_ip',
  'reputation_domain',
  'url_threat',
  'lookalike',
  'credential',
  'url_structure',
  'phishing_content',
  'attachment_malware',
  'attachment_risky',
  'bec_impersonation',
  'bec_identity',
  'bec_intent',
  'bec_history',
  'dlp',
  'coverage',
  'engine_failure',
  'engine_unknown',
  'sandbox',
] as const;
export type RiskSignalGroup = (typeof RISK_SIGNAL_GROUPS)[number];

export type GroupRule = 'max' | 'capped_sum';

export interface RiskGroupDefinition {
  readonly group: RiskSignalGroup;
  readonly rule: GroupRule;
  /**
   * Cap of the group total (`null` for `max` groups; `engine_failure` uses the profile's
   * `failures.groupCap`, recorded here as its default).
   */
  readonly cap: number | null;
  /** The cap comes from the profile (`failures.groupCap`). */
  readonly capFromProfile: boolean;
  /** Verdict category of the group (R8). */
  readonly verdict: RiskVerdict;
  /** Group multiplier locked at 1000 (R10). */
  readonly locked: boolean;
}

const group = (
  name: RiskSignalGroup,
  rule: GroupRule,
  cap: number | null,
  verdict: RiskVerdict,
  locked = false,
  capFromProfile = false,
): RiskGroupDefinition =>
  Object.freeze({ group: name, rule, cap, capFromProfile, verdict, locked });

/** Group catalog (R3 rule and cap, R8 verdict category, R10 locked multipliers), catalog order. */
export const RISK_GROUP_DEFINITIONS: Readonly<Record<RiskSignalGroup, RiskGroupDefinition>> =
  Object.freeze({
    auth_dmarc: group('auth_dmarc', 'max', null, 'phishing'),
    auth_other: group('auth_other', 'capped_sum', 150, 'suspicious'),
    spam: group('spam', 'max', null, 'spam'),
    reputation_ip: group('reputation_ip', 'max', null, 'spam'),
    reputation_domain: group('reputation_domain', 'max', null, 'spam'),
    url_threat: group('url_threat', 'max', null, 'phishing'),
    lookalike: group('lookalike', 'max', null, 'phishing'),
    credential: group('credential', 'max', null, 'phishing'),
    url_structure: group('url_structure', 'capped_sum', 300, 'phishing'),
    phishing_content: group('phishing_content', 'max', null, 'phishing'),
    attachment_malware: group('attachment_malware', 'max', null, 'malware', true),
    attachment_risky: group('attachment_risky', 'max', null, 'suspicious'),
    bec_impersonation: group('bec_impersonation', 'max', null, 'bec'),
    bec_identity: group('bec_identity', 'capped_sum', 250, 'bec'),
    bec_intent: group('bec_intent', 'capped_sum', 350, 'bec'),
    bec_history: group('bec_history', 'capped_sum', 150, 'bec'),
    dlp: group('dlp', 'max', null, 'dlp_violation'),
    coverage: group('coverage', 'capped_sum', 200, 'unknown'),
    engine_failure: group('engine_failure', 'capped_sum', 600, 'unknown', true, true),
    engine_unknown: group('engine_unknown', 'capped_sum', 200, 'unknown', true),
    sandbox: group('sandbox', 'max', null, 'suspicious', true),
  });

export const RISK_LOCKED_GROUPS: readonly RiskSignalGroup[] = Object.freeze(
  RISK_SIGNAL_GROUPS.filter((g) => RISK_GROUP_DEFINITIONS[g].locked),
);

export type MessageDirection = 'inbound' | 'outbound' | 'internal';
export const MESSAGE_DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;

/** `in` of the R3 table: inbound, and internal mail when the engine produced the code. */
const IN: readonly MessageDirection[] = Object.freeze(['inbound', 'internal']);
const ALL: readonly MessageDirection[] = Object.freeze(['inbound', 'outbound', 'internal']);

/** Where the weight comes from: the map, or the profile's failure weights (R6). */
export type SignalWeightSource = 'map' | 'failures.engineFailureWeight' | 'failures.unknownWeight';

export interface RiskSignalDefinition {
  readonly id: string;
  readonly group: RiskSignalGroup;
  /** `engine:code` assertions (or `engine:<input fact>` for input-derived signals). */
  readonly codes: readonly string[];
  /** Default weight (points on 0–1000); for profile-weighted signals the platform default. */
  readonly weight: number;
  readonly weightFrom: SignalWeightSource;
  /** `T` of R3: trust may reduce it (R7). */
  readonly trustReducible: boolean;
  readonly directions: readonly MessageDirection[];
  /** `code`: asserted by engine reason codes; `input`: derived from a structured input. */
  readonly source: 'code' | 'input';
}

const sig = (
  id: string,
  groupName: RiskSignalGroup,
  codes: readonly string[],
  weight: number,
  trustReducible: boolean,
  directions: readonly MessageDirection[],
  source: 'code' | 'input' = 'code',
  weightFrom: SignalWeightSource = 'map',
): RiskSignalDefinition =>
  Object.freeze({
    id,
    group: groupName,
    codes: Object.freeze([...codes]),
    weight,
    weightFrom,
    trustReducible,
    directions,
    source,
  });

const T = true;
const N = false;

const ATTACHMENT_LIMIT_CODES = ATTACHMENT_REASON_CODES.filter((c) => c.startsWith('limit.')).map(
  (c) => `attachment:${c}`,
);

/** The U1 fetch-failure codes of `url-map/1` (U10 table; `unknown` effect). */
const URL_U1_CODES = [
  'url.fetch_timeout',
  'url.fetch_dns_error',
  'url.fetch_tls_error',
  'url.fetch_connection_error',
  'url.fetch_http_error',
  'url.fetch_too_large',
  'url.fetch_blocked_port',
  'url.fetch_not_performed',
].map((c) => `url:${c}`);

/** Synchronous round engines (the sandbox is asynchronous and never in `engines`, R2). */
export const ROUND_ENGINES: readonly EngineName[] = Object.freeze(
  ENGINE_NAMES.filter((e) => e !== 'sandbox'),
);

/** Signal id of a required engine's failure (R6). */
/**
 * The synthetic code `buildScoringInput` adds to an engine whose expected child row is missing
 * (R2): an integrity failure of the round, scored as `engine_failed:<engine>` with the failure
 * floors (R6). The Rspamd row is `email_auth_results` (a successful Rspamd check always writes
 * one), so a missing row means the SPF/DKIM/DMARC evidence was lost, not that it was absent.
 */
export const RISK_ROW_MISSING_CODES = Object.freeze({
  rspamd: 'risk.input.auth_row_missing',
  bec: 'risk.input.bec_row_missing',
  dlp: 'risk.input.dlp_row_missing',
} as const);

const rowMissingAssertions = (engine: string): string[] => {
  const code = (RISK_ROW_MISSING_CODES as Readonly<Record<string, string>>)[engine];
  return code === undefined ? [] : [`${engine}:${code}`];
};

export const engineFailedSignal = (engine: EngineName): string => `engine_failed_${engine}`;
/** Signal id of a required engine's `unknown` result (R6). */
export const engineUnknownSignal = (engine: EngineName): string => `engine_unknown_${engine}`;

/** The default signal map `risk-signals/1` (R3 table, in table order). */
export const RISK_SIGNALS: readonly RiskSignalDefinition[] = Object.freeze([
  // auth_dmarc (max)
  sig('auth_dmarc_reject', 'auth_dmarc', ['rspamd:auth.dmarc_reject'], 300, N, IN),
  sig('auth_tenant_domain_spoof', 'auth_dmarc', ['bec:bec.auth.tenant_domain_spoof'], 400, N, IN),
  sig('auth_dmarc_quarantine', 'auth_dmarc', ['rspamd:auth.dmarc_quarantine'], 200, N, IN),
  sig('auth_dmarc_fail', 'auth_dmarc', ['bec:bec.auth.dmarc_fail'], 120, N, IN),
  // auth_other (capped_sum 150)
  sig('auth_spf_fail', 'auth_other', ['rspamd:auth.spf_fail', 'bec:bec.auth.spf_fail'], 60, N, IN),
  sig(
    'auth_dkim_fail',
    'auth_other',
    ['rspamd:auth.dkim_fail', 'bec:bec.auth.dkim_fail'],
    40,
    N,
    IN,
  ),
  sig('auth_arc_fail', 'auth_other', ['rspamd:auth.arc_fail'], 30, N, IN),
  sig(
    'auth_none',
    'auth_other',
    ['bec:bec.auth.none', 'bec:bec.sender.not_authenticated'],
    40,
    N,
    IN,
  ),
  sig(
    'auth_temperror',
    'auth_other',
    ['rspamd:auth.temperror', 'bec:bec.auth.temperror'],
    20,
    N,
    IN,
  ),
  sig(
    'trusted_sender_unauthenticated',
    'auth_other',
    ['bec:bec.trusted_sender_unauthenticated'],
    100,
    N,
    IN,
  ),
  sig('header_anomaly', 'auth_other', ['rspamd:header.anomaly'], 40, N, IN),
  // spam (max)
  sig('spam_gtube', 'spam', ['rspamd:spam.gtube'], 600, T, ALL),
  sig('spam_reject_action', 'spam', ['rspamd:spam.reject_action'], 600, T, ALL),
  sig('spam_score', 'spam', ['rspamd:spam.score'], 450, T, ALL),
  sig('spam_fuzzy', 'spam', ['rspamd:fuzzy.spam'], 450, T, ALL),
  sig('spam_suspicious_score', 'spam', ['rspamd:spam.suspicious_score'], 200, T, ALL),
  sig('spam_bayes', 'spam', ['rspamd:bayes.spam'], 100, T, ALL),
  // reputation_ip (max)
  sig('ip_listed', 'reputation_ip', ['rspamd:reputation.ip_listed'], 150, T, IN),
  // reputation_domain (max)
  sig('domain_feed_suspicious', 'reputation_domain', ['url:url.feed_suspicious'], 200, T, ALL),
  sig(
    'domain_listed',
    'reputation_domain',
    ['rspamd:reputation.domain_listed', 'url:url.dnsbl_spam'],
    150,
    T,
    ALL,
  ),
  sig('domain_new', 'reputation_domain', ['url:url.new_domain'], 80, T, ALL),
  // url_threat (max)
  sig(
    'url_known_phishing',
    'url_threat',
    [
      'rspamd:phishing.known_bad_url',
      'rspamd:fuzzy.phish',
      'url:url.feed_malicious',
      'url:url.dnsbl_phishing',
      'url:url.phishing_high_confidence',
      // Placement decided in WP2 (wp2 note): M5 of url-map/1, a malicious verdict like M1–M3.
      'url:url.dynamic_phishing',
    ],
    800,
    N,
    ALL,
  ),
  sig(
    'url_known_malware',
    'url_threat',
    ['rspamd:malware.known_bad_url', 'url:url.dnsbl_malware', 'url:url.dnsbl_c2'],
    1000,
    N,
    ALL,
  ),
  sig('url_tenant_blocked', 'url_threat', ['url:url.tenant_blocked'], 700, N, ALL),
  sig(
    'url_unsafe_scheme',
    'url_threat',
    [
      'url:url.script_scheme',
      'url:url.data_uri',
      'url:url.unsafe_scheme',
      // Placement decided in WP2 (wp2 note): S9, a link whose page triggers a download.
      'url:url.dynamic_download',
    ],
    250,
    N,
    ALL,
  ),
  // lookalike (max)
  sig('lookalike_sender_tenant', 'lookalike', ['bec:bec.lookalike.sender_tenant'], 450, N, IN),
  sig(
    'lookalike_sender_vendor',
    'lookalike',
    ['bec:bec.lookalike.sender_vendor', 'bec:bec.history.first_contact_lookalike'],
    400,
    N,
    IN,
  ),
  sig(
    'lookalike_sender_brand',
    'lookalike',
    [
      'bec:bec.lookalike.sender_brand',
      'bec:bec.lookalike.mixed_script_domain',
      'bec:bec.reply_to.lookalike',
    ],
    350,
    N,
    IN,
  ),
  sig(
    'lookalike_url',
    'lookalike',
    [
      'url:url.lookalike_homoglyph',
      'url:url.lookalike_edit_distance',
      'url:url.lookalike_combosquat',
      'url:url.mixed_script',
      'url:url.lookalike_tld_swap',
      'bec:bec.link.lookalike',
    ],
    300,
    N,
    ALL,
  ),
  // credential (max)
  sig(
    'credential_form_cross_origin',
    'credential',
    [
      'url:url.credential_form_cross_origin',
      'bec:bec.link.credential_harvesting',
      // Placement decided in WP2 (wp2 note): S9, the same fact observed by the dynamic fetch.
      'url:url.dynamic_cross_origin_form',
    ],
    450,
    N,
    ALL,
  ),
  sig(
    'credential_form',
    'credential',
    ['url:url.credential_form', 'bec:bec.link.credential_form'],
    350,
    N,
    ALL,
  ),
  sig('credential_link_malicious', 'credential', ['bec:bec.link.malicious'], 500, N, ALL),
  // url_structure (capped_sum 300)
  sig('url_redirect_internal', 'url_structure', ['url:url.redirect_blocked_internal'], 200, N, ALL),
  sig(
    'url_obfuscation',
    'url_structure',
    [
      'url:url.obfuscated_host',
      'url:url.ip_obfuscated',
      'url:url.entity_obfuscation',
      'url:url.control_chars',
      'url:url.userinfo',
    ],
    150,
    T,
    ALL,
  ),
  sig('url_ip_host', 'url_structure', ['url:url.ip_host', 'url:url.redirect_to_ip'], 120, T, ALL),
  sig('url_text_mismatch', 'url_structure', ['url:url.text_mismatch'], 120, T, ALL),
  sig(
    'url_redirects',
    'url_structure',
    ['url:url.redirect_limit', 'url:url.many_redirects'],
    80,
    T,
    ALL,
  ),
  sig('url_too_long', 'url_structure', ['url:url.too_long'], 40, T, ALL),
  // phishing_content (max)
  sig(
    'phish_link_mismatch_auth',
    'phishing_content',
    ['rspamd:phishing.link_mismatch_auth_failure'],
    600,
    N,
    IN,
  ),
  sig('phish_link_mismatch', 'phishing_content', ['rspamd:phishing.link_mismatch'], 250, N, ALL),
  sig(
    'phish_brand_display_name',
    'phishing_content',
    ['bec:bec.display_name.brand_mismatch'],
    300,
    N,
    IN,
  ),
  // attachment_malware (max)
  sig(
    'attachment_malware',
    'attachment_malware',
    ['attachment:malware.known_hash', 'attachment:malware.clamav', 'attachment:yara.high'],
    1000,
    N,
    ALL,
  ),
  // attachment_risky (max)
  sig(
    'attachment_disguised_exec',
    'attachment_risky',
    ['attachment:type.executable_disguised'],
    500,
    N,
    ALL,
  ),
  sig(
    'attachment_known_suspicious',
    'attachment_risky',
    ['attachment:hash.known_suspicious', 'attachment:clamav.heuristic'],
    400,
    N,
    ALL,
  ),
  sig(
    'attachment_denied_type',
    'attachment_risky',
    ['attachment:type.denied', 'attachment:type.denied_in_archive'],
    400,
    N,
    ALL,
  ),
  sig(
    'attachment_archive_attack',
    'attachment_risky',
    ['attachment:archive.path_traversal', 'attachment:archive.overlapping_entries'],
    400,
    N,
    ALL,
  ),
  sig('attachment_yara_medium', 'attachment_risky', ['attachment:yara.medium'], 350, N, ALL),
  sig('attachment_pua', 'attachment_risky', ['attachment:clamav.pua'], 300, N, ALL),
  sig('attachment_encrypted', 'attachment_risky', ['attachment:archive.encrypted'], 300, N, ALL),
  sig('attachment_not_allowed', 'attachment_risky', ['attachment:type.not_allowed'], 300, N, ALL),
  sig(
    'attachment_name_tricks',
    'attachment_risky',
    [
      'attachment:filename.bidi_control',
      'attachment:filename.double_extension',
      'attachment:filename.executable_extension',
    ],
    250,
    N,
    ALL,
  ),
  sig('attachment_type_mismatch', 'attachment_risky', ['attachment:type.mismatch'], 250, N, ALL),
  sig('attachment_malformed', 'attachment_risky', ['attachment:archive.malformed'], 200, N, ALL),
  sig('attachment_macros', 'attachment_risky', ['attachment:office.macros'], 100, N, ALL),
  sig('attachment_yara_low', 'attachment_risky', ['attachment:yara.low'], 80, N, ALL),
  // bec_impersonation (max)
  sig(
    'bec_exec_freemail',
    'bec_impersonation',
    ['bec:bec.impersonation.executive_freemail', 'bec:bec.impersonation.executive_reply_to'],
    450,
    N,
    IN,
  ),
  sig(
    'bec_vendor_unauthenticated',
    'bec_impersonation',
    ['bec:bec.impersonation.vendor_unauthenticated'],
    400,
    N,
    IN,
  ),
  sig('bec_exec_name', 'bec_impersonation', ['bec:bec.impersonation.executive_name'], 300, N, IN),
  sig('bec_vendor_name', 'bec_impersonation', ['bec:bec.impersonation.vendor_name'], 300, N, IN),
  sig(
    'bec_vendor_unknown_sender',
    'bec_impersonation',
    ['bec:bec.vendor.unknown_sender'],
    150,
    N,
    IN,
  ),
  // bec_identity (capped_sum 250)
  sig(
    'bec_display_name_tricks',
    'bec_identity',
    ['bec:bec.display_name.embedded_address', 'bec:bec.display_name.obfuscated'],
    150,
    T,
    IN,
  ),
  sig('bec_forged_return_path', 'bec_identity', ['bec:bec.return_path.forged_header'], 120, T, IN),
  sig('bec_reply_to_freemail', 'bec_identity', ['bec:bec.reply_to.freemail'], 120, T, IN),
  sig('bec_from_invalid', 'bec_identity', ['bec:bec.sender.from_invalid'], 100, T, IN),
  sig('bec_reply_to_mismatch', 'bec_identity', ['bec:bec.reply_to.domain_mismatch'], 100, T, IN),
  sig(
    'bec_sender_mismatch',
    'bec_identity',
    ['bec:bec.return_path.domain_mismatch', 'bec:bec.sender.sender_mismatch'],
    60,
    T,
    IN,
  ),
  // bec_intent (capped_sum 350)
  sig(
    'bec_payment_change',
    'bec_intent',
    [
      'bec:bec.vendor.payment_change',
      'bec:bec.content.bank_detail_change',
      'bec:bec.content.payroll_diversion',
    ],
    250,
    T,
    IN,
  ),
  sig('bec_gift_card', 'bec_intent', ['bec:bec.content.gift_card'], 200, T, IN),
  sig('bec_credential_request', 'bec_intent', ['bec:bec.content.credential_request'], 200, T, IN),
  sig(
    'bec_wire_or_invoice',
    'bec_intent',
    ['bec:bec.content.wire_transfer', 'bec:bec.content.invoice_change'],
    150,
    T,
    IN,
  ),
  sig('bec_payment_request', 'bec_intent', ['bec:bec.content.payment_request'], 100, T, IN),
  sig('bec_secrecy', 'bec_intent', ['bec:bec.content.secrecy'], 80, T, IN),
  sig('bec_urgency', 'bec_intent', ['bec:bec.content.urgency'], 60, T, IN),
  sig(
    'bec_financial_identifiers',
    'bec_intent',
    ['bec:bec.content.financial_identifiers'],
    60,
    T,
    IN,
  ),
  // bec_history (capped_sum 150)
  sig(
    'bec_first_contact_payment',
    'bec_history',
    ['bec:bec.history.first_contact_payment'],
    120,
    T,
    IN,
  ),
  sig(
    'bec_reply_without_history',
    'bec_history',
    ['bec:bec.history.reply_without_history'],
    100,
    T,
    IN,
  ),
  sig('bec_new_infrastructure', 'bec_history', ['bec:bec.history.new_infrastructure'], 60, T, IN),
  sig('bec_first_contact', 'bec_history', ['bec:bec.history.first_contact'], 40, T, IN),
  // dlp (max), from the dlp input
  sig('dlp_action_quarantine', 'dlp', ['dlp:action.quarantine'], 500, N, ALL, 'input'),
  sig('dlp_action_require_approval', 'dlp', ['dlp:action.require_approval'], 400, N, ALL, 'input'),
  sig('dlp_severity_critical', 'dlp', ['dlp:severity.critical'], 300, N, ALL, 'input'),
  sig('dlp_severity_high', 'dlp', ['dlp:severity.high'], 200, N, ALL, 'input'),
  sig('dlp_action_alert', 'dlp', ['dlp:action.alert'], 100, N, ALL, 'input'),
  sig('dlp_severity_medium', 'dlp', ['dlp:severity.medium'], 100, N, ALL, 'input'),
  // coverage (capped_sum 200)
  sig(
    'coverage_not_scanned',
    'coverage',
    [
      'attachment:attachment.not_scanned',
      'attachment:attachment.parse_incomplete',
      'url:url.content_incomplete',
      'bec:bec.content_incomplete',
    ],
    100,
    N,
    ALL,
  ),
  sig(
    'coverage_input_missing',
    'coverage',
    [
      'bec:bec.input_unavailable.auth',
      'bec:bec.input_unavailable.url',
      'bec:bec.history_unavailable',
    ],
    80,
    N,
    ALL,
  ),
  sig(
    'coverage_limits',
    'coverage',
    [
      ...ATTACHMENT_LIMIT_CODES,
      'attachment:archive.unsupported_format',
      'url:limit.url_count',
      // R3 informational paragraph: listed as coverage, not informational (wp2 note).
      'url:url.fetch_skipped_limit',
    ],
    60,
    N,
    ALL,
  ),
  sig(
    'coverage_reputation_unavailable',
    'coverage',
    [
      'url:url.reputation_unavailable',
      ...URL_U1_CODES,
      'url:url.invalid',
      // Placement decided in WP2 (wp2 note): U3, the dynamic fetch failed (unknown effect).
      'url:url.dynamic_failed',
    ],
    60,
    N,
    ALL,
  ),
  sig('coverage_dlp_partial', 'coverage', ['dlp:coverage.partial'], 50, N, ALL, 'input'),
  // engine_failure (capped_sum, profile cap): one signal per synchronous engine
  ...ROUND_ENGINES.map((engine) =>
    sig(
      engineFailedSignal(engine),
      'engine_failure',
      [`${engine}:status.failed`, `${engine}:status.missing`, ...rowMissingAssertions(engine)],
      300,
      N,
      ALL,
      'input',
      'failures.engineFailureWeight',
    ),
  ),
  // engine_unknown (capped_sum 200)
  ...ROUND_ENGINES.map((engine) =>
    sig(
      engineUnknownSignal(engine),
      'engine_unknown',
      [`${engine}:outcome.unknown`],
      60,
      N,
      ALL,
      'input',
      'failures.unknownWeight',
    ),
  ),
  // sandbox (max; revision 1 only)
  sig('sandbox_suspicious', 'sandbox', ['sandbox:outcome.suspicious'], 400, N, ALL, 'input'),
  sig(
    'sandbox_failed',
    'sandbox',
    ['sandbox:outcome.timeout', 'sandbox:outcome.error'],
    0,
    N,
    ALL,
    'input',
  ),
]);

export const RISK_SIGNAL_IDS: readonly string[] = Object.freeze(RISK_SIGNALS.map((s) => s.id));

const SIGNAL_BY_ID = new Map(RISK_SIGNALS.map((s) => [s.id, s]));

export function riskSignal(id: string): RiskSignalDefinition | undefined {
  return SIGNAL_BY_ID.get(id);
}

/** `engine:code` → signal id (code-asserted and input-derived assertions). */
const SIGNAL_BY_ASSERTION: ReadonlyMap<string, RiskSignalDefinition> = (() => {
  const map = new Map<string, RiskSignalDefinition>();
  for (const signal of RISK_SIGNALS) {
    for (const code of signal.codes) {
      if (map.has(code)) throw new Error(`Assertion mapped twice in risk-signals/1: ${code}`);
      map.set(code, signal);
    }
  }
  return map;
})();

/** The signal that `engine:code` asserts, or undefined. */
export function signalForAssertion(assertion: string): RiskSignalDefinition | undefined {
  return SIGNAL_BY_ASSERTION.get(assertion);
}

/**
 * Codes that contribute 0 (R3 "Informational"), as `engine:code`. Built from the engine code
 * lists so that it stays complete: the `clean.*` codes, `URL_INFORMATIONAL_CODES` except
 * `url.fetch_skipped_limit` (coverage), `url.none`, `attachment.none`, `bayes.ham`,
 * `fuzzy.unknown`, `auth.dmarc_fail_arc_trusted`, the Rspamd `engine.*` codes (their effect is the
 * `unknown` status), the attachment `engine.*` attempt-failure codes (their effect is the
 * `failed` status, R6), `bec.trusted_sender` (trust is R7), `bec.feedback_suppressed`,
 * `bec.not_inbound`, the AI codes `bec.ai.*` (R9), every DLP code (DLP enters through its row:
 * action, severity, coverage) and every sandbox code (the sandbox enters through its outcome).
 */
export const RISK_INFORMATIONAL_CODES: readonly string[] = Object.freeze([
  // rspamd
  'rspamd:clean.below_threshold',
  'rspamd:bayes.ham',
  'rspamd:fuzzy.unknown',
  'rspamd:auth.dmarc_fail_arc_trusted',
  'rspamd:engine.skipped',
  'rspamd:engine.empty_result',
  'rspamd:engine.too_large',
  // attachment
  'attachment:clean.no_findings',
  'attachment:attachment.none',
  ...ATTACHMENT_REASON_CODES.filter((c) => c.startsWith('engine.')).map((c) => `attachment:${c}`),
  // url
  'url:clean.no_findings',
  'url:url.none',
  'url:url.shortened',
  'url:url.redirected',
  'url:url.meta_refresh',
  'url:url.idn',
  'url:url.brand_tld_variant',
  'url:url.nonstandard_port',
  'url:url.trailing_dot',
  'url:url.in_attachment',
  'url:url.allowlisted',
  'url:url.charset_guess',
  // bec
  'bec:clean.below_threshold',
  'bec:bec.trusted_sender',
  'bec:bec.feedback_suppressed',
  'bec:bec.not_inbound',
  ...BEC_REASON_CODES.filter((c) => c.startsWith('bec.ai.')).map((c) => `bec:${c}`),
  // dlp: every code (the row is authoritative)
  ...DLP_REASON_CODES.map((c) => `dlp:${c}`),
  // sandbox: every code (the outcome is authoritative)
  ...SANDBOX_REASON_CODES.map((c) => `sandbox:${c}`),
]);

const INFORMATIONAL = new Set(RISK_INFORMATIONAL_CODES);

/**
 * Whether `engine:code` is informational: listed, or an `engine.*` attempt/size code of any
 * engine (handled by status, R6).
 */
export function isInformationalAssertion(engine: string, code: string): boolean {
  return INFORMATIONAL.has(`${engine}:${code}`) || code.startsWith('engine.');
}
