import { createHash, timingSafeEqual } from 'node:crypto';
import {
  classifyDkimSignature,
  type DkimProofResult,
  type DkimSignatureEvidence,
  MAX_EVIDENCE_DKIM_DOMAINS,
  type ProofResult,
  type RelayProvider,
} from './provider-relay';

/**
 * Content proof of journal intake (step 8.6 D2.6, ADR-0087; contracts §34). Pure: the
 * smtp-adapter journal LMTP collects the evidence from the OUTER message (the journal report or
 * the copy as received) and the source row, and stores the `journal-intake-proof/1` document of a
 * passing proof in `journal_intake_messages.proof` (schema `journalIntakeProofSchema` of
 * `@email-gateway/archive`, which this module restates structurally to keep the package free of
 * an archive dependency; the smtp-adapter parses the document with that schema before storing).
 *
 * - `microsoft_365_journal`: at least one `X-MS-Exchange-CrossTenant-Id` and every value equal to
 *   the bound connection's `external_tenant_id`. DKIM is recorded as evidence (aligned to a linked
 *   domain, a parent of one, or a `<tenant>.onmicrosoft.com` domain) and never required: a DKIM
 *   verifier or DNS failure only records `temperror` in the evidence.
 * - `google_workspace_copy`: exactly one `X-EG-Journal-Token` whose SHA-256 (of the trimmed,
 *   lower-cased value, as `intakeHeaderTokenHash`) equals the current token hash, or the previous
 *   one while it is still valid (constant-time comparison).
 * - `exchange_onprem_journal`, `smtp_bcc`: no content proof (the address secret, the source's
 *   networks and TLS at RCPT are the proof).
 *
 * A header block cut by the header limit fails for the provider kinds (evidence beyond the limit
 * is unseen). A source whose binding is gone (no tenant id, no token hash) is `temperror`: the
 * RCPT re-check refuses such a source, so this only happens when the state changes mid-delivery.
 */

export const JOURNAL_INTAKE_PROOF_SCHEMA = 'journal-intake-proof/1';

export const JOURNAL_INTAKE_KINDS = [
  'microsoft_365_journal',
  'google_workspace_copy',
  'exchange_onprem_journal',
  'smtp_bcc',
] as const;
export type JournalIntakeKind = (typeof JOURNAL_INTAKE_KINDS)[number];

export const isJournalIntakeKind = (value: unknown): value is JournalIntakeKind =>
  typeof value === 'string' && (JOURNAL_INTAKE_KINDS as readonly string[]).includes(value);

/** The provider whose egress ranges and connection a provider-bound kind uses; null otherwise. */
export function intakeKindProvider(kind: JournalIntakeKind): RelayProvider | null {
  switch (kind) {
    case 'microsoft_365_journal':
      return 'microsoft_365';
    case 'google_workspace_copy':
      return 'google_workspace';
    default:
      return null;
  }
}

/** Kinds whose message is a journal report to unwrap (the others are stored as received). */
export const isJournalReportKind = (kind: JournalIntakeKind): boolean =>
  kind === 'microsoft_365_journal' || kind === 'exchange_onprem_journal';

export type IntakeNetworkProof = 'provider_egress' | 'source_networks';
export type IntakeTenantHeaderResult = 'match' | 'mismatch' | 'absent' | 'n/a';
export type IntakeHeaderTokenResult = 'match' | 'previous' | 'mismatch' | 'absent' | 'n/a';
export type IntakeDkimEvidenceResult = DkimProofResult | 'n/a';

/** `journal-intake-proof/1` (the stored document; only passing proofs are stored). */
export interface JournalIntakeProofDocument {
  v: 1;
  network: IntakeNetworkProof;
  tls: boolean;
  clientCert: 'match' | 'n/a';
  tenantHeader: IntakeTenantHeaderResult;
  headerToken: IntakeHeaderTokenResult;
  dkim: { result: IntakeDkimEvidenceResult; domains: string[] };
  result: 'pass';
}

/** What the LMTP saw (outer message) and what the RCPT re-check established. */
export interface IntakeProofEvidence {
  kind: JournalIntakeKind;
  /** How the connecting client was authorized (provider egress set or the source's networks). */
  network: IntakeNetworkProof;
  /** The SMTP session used TLS. */
  tls: boolean;
  /** A configured client certificate fingerprint matched. */
  clientCertMatched: boolean;
  /** The outer header block ended within the header limit. */
  headerBlockComplete: boolean;
  /** Every `X-MS-Exchange-CrossTenant-Id` value of the outer message. */
  tenantHeaderValues: readonly string[];
  /** Every raw `X-EG-Journal-Token` value of the outer message. */
  headerTokens: readonly string[];
  /** Microsoft 365 only: the DKIM verification of the outer message (null = not run). */
  dkim?: { signatures: readonly DkimSignatureEvidence[]; verifierError: boolean } | null;
}

/** The source's expectations (from the writer re-check at LMTP). */
export interface IntakeProofPolicy {
  /** `provider_connections.external_tenant_id` of the bound connection. */
  expectedTenantId: string | null;
  /** Domains linked to the bound connection (DKIM evidence only). */
  linkedDomains: readonly string[];
  /** `journal_intake_sources.header_token_hash` (Google). */
  headerTokenSha256: string | null;
  /** `previous_header_token_hash`, accepted until `previousValidUntil`. */
  previousHeaderTokenSha256: string | null;
  previousValidUntil: Date | null;
  now: Date;
}

export type IntakeProofRule = 'tenant_header' | 'header_token' | 'header_block';

export interface IntakeProofOutcome {
  result: ProofResult;
  /** The rule that failed (or could not be checked); null on pass. */
  failedRule: IntakeProofRule | null;
  /** Bounded failure vocabulary; null on pass. */
  failureCode: string | null;
  tenantHeader: IntakeTenantHeaderResult;
  headerToken: IntakeHeaderTokenResult;
  dkim: { result: IntakeDkimEvidenceResult; domains: string[] };
  /** The document to store; set only when `result` is `pass`. */
  document: JournalIntakeProofDocument | null;
}

const SHA256_HEX = /^[0-9a-f]{64}$/;
const ONMICROSOFT = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.onmicrosoft\.com$/;

const normalizeDomain = (domain: string): string => domain.trim().toLowerCase().replace(/\.$/, '');

/** SHA-256 (hex) of a header token as stored: trimmed and lower-cased (`intakeHeaderTokenHash`). */
export function journalTokenSha256(token: string): string {
  return createHash('sha256').update(token.trim().toLowerCase(), 'utf8').digest('hex');
}

/** Constant-time comparison of two SHA-256 hex digests (false for malformed input). */
export function sha256HexEquals(a: string | null, b: string | null): boolean {
  if (a === null || b === null || !SHA256_HEX.test(a) || !SHA256_HEX.test(b)) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

/**
 * A signing domain acceptable as Microsoft 365 journal evidence: a linked domain or a parent of
 * one (relaxed alignment by label suffix), or a tenant's initial `<name>.onmicrosoft.com` domain.
 */
export function intakeDkimDomainAcceptable(
  signingDomain: string,
  linkedDomains: readonly string[],
): boolean {
  const d = normalizeDomain(signingDomain);
  if (d.length === 0) return false;
  if (ONMICROSOFT.test(d)) return true;
  return linkedDomains.some((linked) => {
    const l = normalizeDomain(linked);
    return l === d || l.endsWith(`.${d}`);
  });
}

/** The DKIM evidence of a Microsoft 365 journal report (never a reason to fail). */
export function intakeDkimEvidence(
  dkim: IntakeProofEvidence['dkim'],
  linkedDomains: readonly string[],
): { result: DkimProofResult; domains: string[] } {
  const signatures = dkim?.signatures ?? [];
  const domains = [
    ...new Set(signatures.map((s) => normalizeDomain(s.domain)).filter((d) => d.length > 0)),
  ].slice(0, MAX_EVIDENCE_DKIM_DOMAINS);
  if (!dkim || dkim.verifierError) return { result: 'temperror', domains };
  if (signatures.length === 0) return { result: 'none', domains };
  // The strength rules of 8.2 (no l=, h= covers from, algorithm, key size) via classifyDkimSignature
  // with the signature's own domain as the alignment target; the domain rule is ours.
  const classes = signatures.map((signature) => {
    const own = normalizeDomain(signature.domain);
    const cls = classifyDkimSignature(signature, {
      headerFromDomain: own,
      linkedDomains: new Set([own]),
    });
    if (cls !== 'aligned_pass') return cls;
    return intakeDkimDomainAcceptable(own, linkedDomains) ? 'aligned_pass' : 'unaligned_pass';
  });
  if (classes.includes('aligned_pass')) return { result: 'aligned_pass', domains };
  if (classes.includes('temperror')) return { result: 'temperror', domains };
  if (classes.includes('unaligned_pass')) return { result: 'unaligned_pass', domains };
  return { result: 'fail', domains };
}

/**
 * `evaluateIntakeProof(evidence, policy)` (D2.6): `pass` with the document to store, `fail`
 * (accept-and-drop at the LMTP) or `temperror` (451, retried by Postfix) with the rule.
 */
export function evaluateIntakeProof(
  evidence: IntakeProofEvidence,
  policy: IntakeProofPolicy,
): IntakeProofOutcome {
  let tenantHeader: IntakeTenantHeaderResult = 'n/a';
  let headerToken: IntakeHeaderTokenResult = 'n/a';
  let dkim: IntakeProofOutcome['dkim'] = { result: 'n/a', domains: [] };
  const state: {
    result: ProofResult;
    failedRule: IntakeProofRule | null;
    failureCode: string | null;
  } = { result: 'pass', failedRule: null, failureCode: null };
  const fail = (rule: IntakeProofRule, code: string, outcome: ProofResult = 'fail') => {
    state.result = outcome;
    state.failedRule = rule;
    state.failureCode = code;
  };

  if (evidence.kind === 'microsoft_365_journal') {
    dkim = intakeDkimEvidence(evidence.dkim ?? null, policy.linkedDomains);
    const expected = policy.expectedTenantId?.trim().toLowerCase() ?? '';
    const values = evidence.tenantHeaderValues.map((value) => value.trim().toLowerCase());
    if (!evidence.headerBlockComplete) {
      tenantHeader = values.length === 0 ? 'absent' : 'mismatch';
      fail('header_block', 'header_block_truncated');
    } else if (values.length === 0) {
      tenantHeader = 'absent';
      fail('tenant_header', 'tenant_header_absent');
    } else if (expected === '') {
      tenantHeader = 'mismatch';
      fail('tenant_header', 'tenant_unbound', 'temperror');
    } else if (values.some((value) => value !== expected)) {
      tenantHeader = 'mismatch';
      fail('tenant_header', 'tenant_header_mismatch');
    } else {
      tenantHeader = 'match';
    }
  } else if (evidence.kind === 'google_workspace_copy') {
    const current = policy.headerTokenSha256;
    const previous =
      policy.previousHeaderTokenSha256 !== null &&
      policy.previousValidUntil !== null &&
      policy.previousValidUntil.getTime() > policy.now.getTime()
        ? policy.previousHeaderTokenSha256
        : null;
    if (!evidence.headerBlockComplete) {
      headerToken = evidence.headerTokens.length === 0 ? 'absent' : 'mismatch';
      fail('header_block', 'header_block_truncated');
    } else if (evidence.headerTokens.length === 0) {
      headerToken = 'absent';
      fail('header_token', 'header_token_absent');
    } else if (evidence.headerTokens.length > 1) {
      headerToken = 'mismatch';
      fail('header_token', 'header_token_multiple');
    } else if (current === null || !SHA256_HEX.test(current)) {
      headerToken = 'mismatch';
      fail('header_token', 'header_token_unconfigured', 'temperror');
    } else {
      const hash = journalTokenSha256(evidence.headerTokens[0]!);
      // Both comparisons always run, so the timing does not tell which hash matched.
      const matchesCurrent = sha256HexEquals(hash, current);
      const matchesPrevious = previous !== null && sha256HexEquals(hash, previous);
      if (matchesCurrent) headerToken = 'match';
      else if (matchesPrevious) headerToken = 'previous';
      else {
        headerToken = 'mismatch';
        fail('header_token', 'header_token_mismatch');
      }
    }
  }

  const document: JournalIntakeProofDocument | null =
    state.result === 'pass'
      ? {
          v: 1,
          network: evidence.network,
          tls: evidence.tls,
          clientCert: evidence.clientCertMatched ? 'match' : 'n/a',
          tenantHeader,
          headerToken,
          dkim,
          result: 'pass',
        }
      : null;
  return { ...state, tenantHeader, headerToken, dkim, document };
}
