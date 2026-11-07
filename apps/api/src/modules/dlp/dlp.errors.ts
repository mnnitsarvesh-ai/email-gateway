import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../http/coded-exception';

/**
 * Stable error codes of the DLP routes (step 4.5 D9, D16, D17, D21,
 * docs/plan/steps/13-dlp.md). Bodies carry ids, kinds, counts, limits and codes only: never a
 * pattern, a test sample, a dictionary term, an address or an evidence value.
 */
export const DLP_POLICY_NOT_FOUND = 'dlp_policy_not_found';
export const DLP_RULE_NOT_FOUND = 'dlp_rule_not_found';
export const DLP_EXCEPTION_NOT_FOUND = 'dlp_exception_not_found';
export const DLP_PATTERN_NOT_FOUND = 'dlp_pattern_not_found';
export const DLP_DICTIONARY_NOT_FOUND = 'dlp_dictionary_not_found';
export const DLP_SCAN_NOT_FOUND = 'scan_not_found';
export const DLP_EVIDENCE_NOT_FOUND = 'dlp_evidence_not_found';
export const DLP_POLICY_EXISTS = 'dlp_policy_exists';
export const DLP_RULE_EXISTS = 'dlp_rule_exists';
export const DLP_EXCEPTION_EXISTS = 'dlp_exception_exists';
export const DLP_PATTERN_EXISTS = 'dlp_pattern_exists';
export const DLP_DICTIONARY_EXISTS = 'dlp_dictionary_exists';
export const DLP_POLICY_IN_USE = 'dlp_policy_in_use';
export const DLP_RULE_IN_USE = 'dlp_rule_in_use';
export const DLP_PATTERN_IN_USE = 'dlp_pattern_in_use';
export const DLP_DICTIONARY_IN_USE = 'dlp_dictionary_in_use';
export const DLP_VERSION_CONFLICT = 'version_conflict';
export const DLP_LIMIT_REACHED = 'dlp_limit_reached';
export const DLP_REFERENCE_INVALID = 'dlp_reference_invalid';
export const DLP_DIRECTIONS_INVALID = 'dlp_directions_invalid';
/** The D9 rejection codes of a custom pattern (`@email-gateway/dlp` `compileCustomPattern`). */
export const DLP_PATTERN_CODES = [
  'pattern_syntax',
  'pattern_unsupported',
  'pattern_too_complex',
  'pattern_matches_empty',
  'pattern_too_broad',
  'pattern_too_slow',
  'pattern_invalid_options',
] as const;
/** The D8 rejection codes of dictionary terms (`checkDictionaryTerms`). */
export const DLP_DICTIONARY_CODES = ['dictionary_terms_count', 'dictionary_term_invalid'] as const;
export const EVIDENCE_PURGED = 'evidence_purged';
export const EVIDENCE_EXPIRED = 'evidence_expired';
export const EVIDENCE_UNAVAILABLE = 'evidence_unavailable';
export const EVIDENCE_UNREADABLE = 'evidence_unreadable';
export const INCONSISTENT_READ = 'inconsistent_read';

export type DlpResource = 'policy' | 'rule' | 'exception' | 'pattern' | 'dictionary';

const NOT_FOUND: Record<DlpResource, [string, string]> = {
  policy: [DLP_POLICY_NOT_FOUND, 'DLP policy not found'],
  rule: [DLP_RULE_NOT_FOUND, 'DLP rule not found'],
  exception: [DLP_EXCEPTION_NOT_FOUND, 'DLP exception not found'],
  pattern: [DLP_PATTERN_NOT_FOUND, 'DLP custom pattern not found'],
  dictionary: [DLP_DICTIONARY_NOT_FOUND, 'DLP keyword dictionary not found'],
};

/** Unknown id or another organization's id: never confirms existence. */
export const dlpNotFound = (resource: DlpResource): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, NOT_FOUND[resource][0], NOT_FOUND[resource][1]);

export const dlpScanNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, DLP_SCAN_NOT_FOUND, 'Scan not found');

/** The round has no evidence row (no reportable finding, evidence disabled, or not stored). */
export const dlpEvidenceNotFound = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.NOT_FOUND,
    DLP_EVIDENCE_NOT_FOUND,
    'The scan has no DLP evidence',
  );

const EXISTS: Record<DlpResource, [string, string]> = {
  policy: [DLP_POLICY_EXISTS, 'A DLP policy with this name exists'],
  rule: [DLP_RULE_EXISTS, 'A rule with this name exists in the policy'],
  exception: [DLP_EXCEPTION_EXISTS, 'An exception for this scope, value and target exists'],
  pattern: [DLP_PATTERN_EXISTS, 'A custom pattern with this name exists'],
  dictionary: [DLP_DICTIONARY_EXISTS, 'A keyword dictionary with this name exists'],
};

/** The unique key (name, or scope + value + target) is taken; `id` when known. */
export const dlpExists = (resource: DlpResource, id: string | null): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    EXISTS[resource][0],
    EXISTS[resource][1],
    id === null ? {} : { id },
  );

const IN_USE: Record<'policy' | 'rule' | 'pattern' | 'dictionary', [string, string]> = {
  policy: [DLP_POLICY_IN_USE, 'Exceptions target this policy or one of its rules'],
  rule: [DLP_RULE_IN_USE, 'Exceptions target this rule'],
  pattern: [DLP_PATTERN_IN_USE, 'Rules select this custom pattern'],
  dictionary: [DLP_DICTIONARY_IN_USE, 'Rules select this keyword dictionary'],
};

/** Deleting would leave references behind (`references` = how many rows refer to it). */
export const dlpInUse = (
  resource: 'policy' | 'rule' | 'pattern' | 'dictionary',
  references: number,
): CodedHttpException =>
  new CodedHttpException(HttpStatus.CONFLICT, IN_USE[resource][0], IN_USE[resource][1], {
    references,
  });

/** `version` is not the current version of the row. */
export const dlpVersionConflict = (currentVersion: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    DLP_VERSION_CONFLICT,
    'The resource changed since version; read it and retry',
    { currentVersion },
  );

/** A per-organization (or per-policy) cap (`DLP_*_MAX_*`) would be exceeded. */
export const dlpLimitReached = (resource: string, limit: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    DLP_LIMIT_REACHED,
    'The organization reached its limit for this resource',
    { resource, limit },
  );

/** A referenced policy, rule, pattern or dictionary id is not one of the organization's. */
export const dlpReferenceInvalid = (
  field: string,
  index: number | null = null,
): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.BAD_REQUEST,
    DLP_REFERENCE_INVALID,
    'A referenced id is not a policy, rule, custom pattern or dictionary of the organization',
    index === null ? { field } : { field, index },
  );

/** Rule directions outside the policy's directions (D11). */
export const dlpDirectionsInvalid = (references: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.BAD_REQUEST,
    DLP_DIRECTIONS_INVALID,
    'Rule directions must be a subset of the policy directions',
    { references },
  );

/**
 * A custom pattern was refused by the D9 validation; the code is the D9 code
 * (`DLP_PATTERN_CODES`) with the measured complexity. Never echoes the pattern.
 */
export const dlpPatternInvalid = (
  code: (typeof DLP_PATTERN_CODES)[number],
  complexity: { repetitionProduct: number; length: number } | null,
): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.BAD_REQUEST,
    code,
    'The custom pattern was refused by the safety validation',
    complexity === null
      ? {}
      : { repetitionProduct: complexity.repetitionProduct, length: complexity.length },
  );

/**
 * Dictionary terms refused (`dictionary_terms_count`, or `dictionary_term_invalid` with the term
 * `index`: length, tokens or a duplicate after normalization). Never echoes a term.
 */
export const dlpDictionaryInvalid = (
  code: (typeof DLP_DICTIONARY_CODES)[number],
  index?: number,
): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.BAD_REQUEST,
    code,
    'The dictionary terms were refused (count, length, tokens or a duplicate after normalization)',
    index === undefined ? {} : { index },
  );

/** The evidence was crypto-shredded (tenant request, retention or organization deletion). */
export const evidencePurged = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.GONE, EVIDENCE_PURGED, 'The DLP evidence was purged');

/** The evidence is past its retention (`expires_at`) and awaits the sweeper. */
export const evidenceExpired = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.GONE, EVIDENCE_EXPIRED, 'The DLP evidence has expired');

/** Object storage did not answer (retry later); the read was audited. */
export const evidenceUnavailable = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.SERVICE_UNAVAILABLE,
    EVIDENCE_UNAVAILABLE,
    'The DLP evidence is temporarily unavailable; retry later',
  );

/** The evidence object is missing, altered or cannot be opened; the read was audited. */
export const evidenceUnreadable = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.INTERNAL_SERVER_ERROR,
    EVIDENCE_UNREADABLE,
    'The DLP evidence cannot be read',
  );

/** A writer read returned another row twice in a row (step 4.5 §6); retry later. */
export const inconsistentRead = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.SERVICE_UNAVAILABLE,
    INCONSISTENT_READ,
    'The database returned an inconsistent read; retry the request',
  );

/**
 * A read on the writer returned a row other than the one asked for (4.2 §6: Prisma may hand back
 * the reply of an abandoned statement). The writer retries the transaction once, then answers
 * `503 inconsistent_read`.
 */
export class InconsistentDlpReadError extends Error {
  constructor(readonly read: string) {
    super(`inconsistent read (${read})`);
    this.name = 'InconsistentDlpReadError';
  }
}
