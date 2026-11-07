import type { LookalikeParams } from '@email-gateway/url-security';
import type { AuthResultRow } from '../identity/alignment';
import type { NameMatchKind } from '../identity/names';
import type { TextAnalysis, TextInput, TextSpan } from '../text/analyze';
import type { BecRuleCategory, BecRuleId, BecSeverity, BecVerdict } from './codes';

/**
 * Plain structural inputs of `evaluateBecRules` (B4/B6). The caller (the email-worker bec
 * adapter, WP3) reads and echo-checks every row; this package never touches a database, S3,
 * Redis or the network on the deterministic path.
 */

export type BecDirection = 'inbound' | 'outbound' | 'internal';

/** Stored top-level headers (`email_headers`), decoded; names compared case-insensitively. */
export type BecHeaders = Readonly<Record<string, readonly string[]>>;

export interface BecEnvelope {
  direction: BecDirection;
  /** SMTP MAIL FROM (trusted return path); null or '' for the null sender. */
  envelopeFrom: string | null;
  /** Envelope recipients (RCPT TO). */
  recipients: readonly string[];
  clientIp: string | null;
  receivedAt: Date;
}

export type BecAuthInput =
  { state: 'available'; row: AuthResultRow } | { state: 'failed' | 'missing' | 'not_in_round' };

export type UrlVerdictValue = 'clean' | 'unknown' | 'suspicious' | 'malicious';

/** `url_scan_results` joined with `message_urls` (≤ 200, ordered by url_seq). */
export interface BecUrlRow {
  urlSeq: number;
  verdict: UrlVerdictValue;
  reasonCodes: readonly string[];
  host?: string | null;
  registrableDomain?: string | null;
}

export type BecUrlInput =
  { state: 'available'; rows: readonly BecUrlRow[] } | { state: 'failed' | 'not_in_round' };

export interface ExecutiveProfile {
  publicId: string;
  name: string;
  aliases: readonly string[];
  knownAddresses: readonly string[];
}

export interface VendorProfile {
  publicId: string;
  name: string;
  aliases: readonly string[];
  domains: readonly string[];
  knownSenders: readonly string[];
  paymentChangeSensitive: boolean;
}

export interface TrustedSender {
  publicId: string;
  kind: 'address' | 'domain';
  value: string;
  expiresAt: Date | null;
}

export interface SuppressionRule {
  publicId: string;
  reasonCode: string;
  senderScope: 'address' | 'domain';
  senderValue: string;
  expiresAt: Date;
}

/** Enabled / active / unexpired tenant data (the caller filters `enabled`; expiry is re-checked). */
export interface BecTenantData {
  tenantDomains: readonly string[];
  executives: readonly ExecutiveProfile[];
  vendors: readonly VendorProfile[];
  trustedSenders: readonly TrustedSender[];
  suppressions: readonly SuppressionRule[];
  freemailExtraDomains: readonly string[];
  /** URL_PROTECTED_EXTRA_DOMAINS ∪ the url tenant settings' lookalike.extraProtectedDomains. */
  extraProtectedDomains: readonly string[];
}

export interface HistoryInfraEntry {
  fp: string;
  count: number;
  lastSeenAt: Date | string;
}

/** A `bec_contact_history` row as read (only the fields the rules use). */
export interface HistoryRow {
  messageCount: number;
  firstSeenAt: Date;
  lastSeenAt: Date;
  infra?: readonly HistoryInfraEntry[] | null;
}

export interface HistorySnapshot {
  /** Sender scope row of the From address (null: never seen). */
  sender: HistoryRow | null;
  /** Pair rows of (From, each envelope recipient), ≤ BEC_HISTORY_MAX_RECIPIENTS. */
  pairs: ReadonlyArray<HistoryRow | null>;
  /** Fingerprint hash of this message's infrastructure (history/keys), null when unknown. */
  fingerprintHash: string | null;
}

export type BecHistoryInput = HistorySnapshot | 'disabled' | 'error';

export interface BecRuleSettings {
  suspiciousScore: number;
  maliciousScore: number;
  /** BEC_SUPPRESSION_MAX_WEIGHT (40). */
  suppressionMaxWeight: number;
  /** BEC_HISTORY_MIN_MESSAGES (3). */
  historyMinMessages: number;
  /** BEC_TEXT_MAX_CHARS (40 000). */
  textMaxChars: number;
  /** URL_LOOKALIKE_* platform values. */
  lookalike: LookalikeParams;
}

export interface BecEvaluationInput {
  headers: BecHeaders;
  envelope: BecEnvelope;
  auth: BecAuthInput;
  url: BecUrlInput;
  text: TextInput;
  tenant: BecTenantData;
  history: BecHistoryInput;
  /**
   * The stored header set is not the whole top-level header block (step 3.1
   * `stored_headers_truncated`, or more stored rows than the engine reads): a Reply-To, Sender
   * or Return-Path after the cap was never examined, so the verdict is never `clean` (E1
   * `bec.content_incomplete`, §2.0 invariant 1). Absent = complete.
   */
  headersIncomplete?: boolean;
}

export type InputState = {
  auth: 'available' | 'failed' | 'missing' | 'not_in_round';
  url: 'available' | 'failed' | 'not_in_round';
  text: 'complete' | 'incomplete' | 'absent';
  history: 'enabled' | 'disabled' | 'error';
};

export type HeaderName = 'From' | 'Reply-To' | 'Sender' | 'Return-Path' | 'envelope';

/** Rule evidence (B15). Never body text, span text or hashes. */
export interface RuleEvidence {
  header?: HeaderName;
  address?: string | null;
  displayName?: string | null;
  domain?: string | null;
  /** Name matches only (B15); domain / lookalike matches are shown by `domain` / `lookalike`. */
  profile?: { kind: 'executive' | 'vendor'; id: string; match: NameMatchKind };
  lookalike?: { rule: string; targetKind: string; targetDomain: string; score: number };
  auth?: {
    spf: string | null;
    dkim: string | null;
    dmarc: string | null;
    dmarcPolicy: string | null;
    aligned: { dkim: boolean; spf: boolean };
  };
  keywords?: { category: string; language: string; lexiconIds: string[]; spans: TextSpan[] };
  /** C10 pattern counts (counts only; key names of the security-contracts view schema). */
  patterns?: { iban: number; swift: number; ifsc_account: number; amount: number };
  urls?: number[];
  history?: { firstContact: boolean; priorMessages: '0' | '1-2' | '3-9' | '10+' };
  trusted?: { id: string };
  suppression?: { id: string };
  /** S1: the codes suppressed by tenant feedback (trust-neutralized rules carry `suppressed`). */
  suppressedCodes?: string[];
}

export interface FiredRule {
  id: BecRuleId;
  code: string;
  category: BecRuleCategory;
  severity: BecSeverity;
  /** bec-map/1 weight (the effective weight is 0 when suppressed). */
  weight: number;
  suppressed: null | 'trust' | 'feedback';
  evidence: RuleEvidence[];
}

export interface BecSignal {
  name: string;
  score: number;
  options: string[];
}

export type DomainKind = 'freemail' | 'tenant' | 'vendor' | 'lookalike' | 'external';

export interface IdentitySummaryEntry {
  displayName: string | null;
  address: string | null;
  domain: string | null;
  registrableDomain: string | null;
  kind: DomainKind | null;
}

/** `bec_scan_results.identity` (the tenant's own header metadata, bounded). */
export interface IdentitySummary {
  from: IdentitySummaryEntry | null;
  fromCount: number;
  replyTo: IdentitySummaryEntry[];
  sender: IdentitySummaryEntry | null;
  returnPath: string | null;
  envelopeFrom: string | null;
  isReply: boolean;
  flags: string[];
}

export interface BecRulesResult {
  rulesVersion: string;
  /** Deterministic verdict D ('skipped' for E0). */
  verdict: BecVerdict;
  /** Deterministic score (0..100). */
  score: number;
  /** Reason codes (≤ 32): fired, non-suppressed rule codes by severity, weight, name; engine codes; C0. */
  codes: string[];
  signals: BecSignal[];
  firedRules: FiredRule[];
  identityEvidence: boolean;
  intentEvidence: boolean;
  /** Any rule other than T1/S1 fired (P4 of the invariant uses "no deterministic rule fired"). */
  anyRuleFired: boolean;
  engineCodes: string[];
  inputs: InputState;
  identity: IdentitySummary;
  /** The AI feature vector (AI_FEATURE_NAMES order). */
  features: Record<string, number>;
  /** Text analysis summary (null for E0). */
  text: TextAnalysis | null;
  authenticatedAsFrom: boolean;
}

export type { BecRuleId };
