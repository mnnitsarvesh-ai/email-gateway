import type { ListItem, RequestBody, SuccessBody } from '@/lib/api/types';

/**
 * Types and vocabularies of the DLP and BEC configuration editors (step 7.3 WP5, design §2 B13).
 * Every type comes from the generated client (`schema.gen.ts`, the OpenAPI snapshot). The value
 * lists are `Record<Enum, label>` tables: a value the API adds or removes fails to compile here,
 * and `model.test.ts` compares each list with `docs/api/openapi.json`. The labels are
 * presentation only; the API validates and decides everything.
 */

export type DlpPolicyRow = ListItem<'DlpPoliciesController_list_v1'>;
export type DlpPolicyDetail = SuccessBody<'DlpPoliciesController_get_v1'>;
export type DlpRule = DlpPolicyDetail['rules'][number];
export type DlpRuleConditions = DlpRule['conditions'];
export type DlpExceptionRow = ListItem<'DlpExceptionsController_list_v1'>;
export type DlpPatternRow = ListItem<'DlpPatternsController_list_v1'>;
export type DlpDictionaryRow = ListItem<'DlpDictionariesController_list_v1'>;
export type DlpDictionary = SuccessBody<'DlpDictionariesController_get_v1'>;
export type DlpCompliance = SuccessBody<'DlpComplianceController_get_v1'>;
export type DlpIncident = ListItem<'DlpIncidentsController_list_v1'>;
export type PatternTestResult = SuccessBody<'DlpPatternsController_test_v1'>;
export type Executive = ListItem<'BecExecutivesController_list_v1'>;
export type Vendor = ListItem<'BecVendorsController_list_v1'>;
export type TrustedSender = ListItem<'BecTrustedSendersController_list_v1'>;
export type BecFeedback = ListItem<'BecFeedbackController_list_v1'>;
export type Suppression = ListItem<'BecFeedbackController_listSuppressions_v1'>;

type RuleBody = RequestBody<'DlpPoliciesController_createRule_v1'>;
type Selectors = RuleBody['conditions']['selectors'];
type PatternBody = RequestBody<'DlpPatternsController_create_v1'>;

export type DlpDirection = DlpPolicyRow['directions'][number];
export type DlpMode = DlpPolicyRow['mode'];
export type DlpAction = RuleBody['action'];
export type DlpDetector = NonNullable<Selectors['detectors']>[number];
export type DlpCategory = NonNullable<Selectors['categories']>[number];
export type DlpCoverageReason = NonNullable<Selectors['coverageReasons']>[number];
export type DlpMinSeverity = NonNullable<RuleBody['conditions']['minSeverity']>;
export type DlpSeverity = PatternBody['severity'];
export type DlpValidator = NonNullable<PatternBody['validator']>;
export type DlpMaskStyle = NonNullable<PatternBody['maskStyle']>;
export type DlpDictionaryCategory = RequestBody<'DlpDictionariesController_create_v1'>['category'];
export type DlpExceptionScope = RequestBody<'DlpExceptionsController_create_v1'>['scope'];
export type AadhaarBasis = RequestBody<'DlpComplianceController_enable_v1'>['basis'];
export type TrustedKind = RequestBody<'BecTrustedSendersController_create_v1'>['kind'];

/** The keys of an exhaustive label table, in its order. */
function keysOf<T extends string>(labels: Record<T, string>): readonly T[] {
  return Object.keys(labels) as T[];
}

export const DIRECTION_LABELS: Record<DlpDirection, string> = {
  outbound: 'Outbound',
  internal: 'Internal',
  inbound: 'Inbound',
};
export const DLP_DIRECTIONS = keysOf(DIRECTION_LABELS);

export const MODE_LABELS: Record<DlpMode, string> = {
  enforce: 'Enforce',
  monitor: 'Monitor (record matches, never change the action)',
};
export const DLP_MODES = keysOf(MODE_LABELS);

/** Weakest first: the strongest action of the matched rules of enforcing policies wins. */
export const ACTION_LABELS: Record<DlpAction, string> = {
  allow: 'Allow (record the match only)',
  alert: 'Alert',
  require_approval: 'Require approval',
  quarantine: 'Quarantine',
  block: 'Block',
};
export const DLP_ACTIONS = keysOf(ACTION_LABELS);

/** The 23 detectors of the step 4.5 detector table (id → what it finds). */
export const DETECTOR_LABELS: Record<DlpDetector, string> = {
  PC1: 'Payment card number',
  BA1: 'IBAN',
  BA2: 'Indian bank account (IFSC and account number)',
  BA3: 'SWIFT/BIC code',
  NI1: 'Indian PAN',
  NI2: 'Aadhaar number',
  PP1: 'Indian passport number',
  PP2: 'Passport machine-readable zone',
  PI1: 'Email address',
  PI2: 'Indian mobile number',
  PI3: 'Date of birth',
  PI4: 'GSTIN',
  CF1: 'Classification label',
  CF2: 'Business confidentiality keyword',
  DC1: 'Keyword dictionary match',
  SC1: 'Source code',
  CR1: 'Private key',
  CR2: 'AWS access key ID',
  CR3: 'AWS secret access key',
  CR4: 'JSON Web Token',
  CR5: 'API token',
  FI1: 'Financial document',
  CU1: 'Custom pattern',
};
export const DLP_DETECTORS = keysOf(DETECTOR_LABELS);

export const CATEGORY_LABELS: Record<DlpCategory, string> = {
  payment_card: 'Payment cards',
  bank_account: 'Bank accounts',
  national_id: 'National IDs',
  passport: 'Passports',
  personal_info: 'Personal information',
  confidential: 'Confidential',
  source_code: 'Source code',
  credential: 'Credentials',
  financial: 'Financial',
  custom: 'Custom patterns and dictionaries',
};
export const DLP_CATEGORIES = keysOf(CATEGORY_LABELS);

export const COVERAGE_LABELS: Record<DlpCoverageReason, string> = {
  'dlp.not_extracted.encrypted': 'Encrypted attachment (not extracted)',
  'dlp.not_extracted.unsupported_type': 'Unsupported file type (not extracted)',
  'dlp.not_extracted.image': 'Image without extracted text',
  'dlp.not_extracted.no_text_layer': 'Document without a text layer',
  'dlp.not_extracted.oversize': 'Attachment too large to extract',
  'dlp.not_extracted.not_stored': 'Content not stored',
  'dlp.not_extracted.parse_error': 'Attachment could not be parsed',
  'dlp.not_extracted.archive_limit': 'Archive limit reached',
  'dlp.not_extracted.resource_limit': 'Extraction resource limit reached',
  'dlp.not_extracted.attachment_cap': 'Too many attachments to scan',
  'dlp.text.truncated': 'Text truncated',
  'dlp.text.body_not_stored': 'Body not stored',
  'dlp.parse.incomplete': 'Message parsing incomplete',
  'dlp.custom.scan_truncated': 'Custom pattern scan truncated',
  'dlp.custom.pattern_invalid': 'A selected custom pattern no longer validates',
};
export const DLP_COVERAGE_REASONS = keysOf(COVERAGE_LABELS);

export const MIN_SEVERITY_LABELS: Record<DlpMinSeverity, string> = {
  info: 'Info',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};
export const DLP_MIN_SEVERITIES = keysOf(MIN_SEVERITY_LABELS);

export const SEVERITY_LABELS: Record<DlpSeverity, string> = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};
export const DLP_SEVERITIES = keysOf(SEVERITY_LABELS);

export const VALIDATOR_LABELS: Record<DlpValidator, string> = {
  none: 'None',
  luhn: 'Luhn checksum (card numbers)',
  verhoeff: 'Verhoeff checksum',
  mod97: 'Mod 97 checksum (IBAN)',
  gstin: 'GSTIN checksum',
};
export const DLP_VALIDATORS = keysOf(VALIDATOR_LABELS);

export const MASK_STYLE_LABELS: Record<DlpMaskStyle, string> = {
  last4: 'Keep the last four characters',
  full: 'Mask every character',
};
export const DLP_MASK_STYLES = keysOf(MASK_STYLE_LABELS);

export const DICTIONARY_CATEGORY_LABELS: Record<DlpDictionaryCategory, string> = {
  confidential: 'Confidential',
  financial: 'Financial',
  personal_info: 'Personal information',
  source_code: 'Source code',
  custom: 'Custom',
};
export const DLP_DICTIONARY_CATEGORIES = keysOf(DICTIONARY_CATEGORY_LABELS);

export const EXCEPTION_SCOPE_LABELS: Record<DlpExceptionScope, string> = {
  recipient_domain: 'Recipient domain',
  recipient_address: 'Recipient address',
  sender_domain: 'Sender domain',
  sender_address: 'Sender address',
};
export const DLP_EXCEPTION_SCOPES = keysOf(EXCEPTION_SCOPE_LABELS);

export const AADHAAR_BASIS_LABELS: Record<AadhaarBasis, string> = {
  regulatory_obligation: 'Regulatory obligation',
  uidai_authorised_entity: 'UIDAI-authorised entity',
  data_protection_policy: 'Data protection policy',
  other: 'Other documented basis',
};
export const AADHAAR_BASES = keysOf(AADHAAR_BASIS_LABELS);

export const TRUSTED_KIND_LABELS: Record<TrustedKind, string> = {
  address: 'Address',
  domain: 'Domain',
};
export const TRUSTED_KINDS = keysOf(TRUSTED_KIND_LABELS);

/**
 * What the step 4.5 safety validation codes of a refused custom pattern mean (the API names the
 * rule, never the pattern). Unknown codes are shown as they are.
 */
export const PATTERN_CODE_TEXT: Readonly<Record<string, string>> = {
  pattern_syntax: 'The pattern is not valid RE2 syntax.',
  pattern_unsupported: 'Backreferences, lookaround and possessive constructs are not supported.',
  pattern_too_complex:
    'The pattern is too long or too complex (counted repetition at most 100, nested repetition at most 1 000).',
  pattern_matches_empty: 'The pattern matches empty text.',
  pattern_too_broad: 'The pattern matches too much ordinary text.',
  pattern_too_slow: 'The pattern is too slow to evaluate safely.',
  pattern_invalid_options: 'The pattern options are not valid.',
};

/** Whether `code` is one of the safety validation codes of a custom pattern. */
export function isPatternCode(code: string): boolean {
  return Object.hasOwn(PATTERN_CODE_TEXT, code);
}

export function patternCodeText(code: string): string {
  return isPatternCode(code)
    ? (PATTERN_CODE_TEXT[code] as string)
    : 'The pattern was refused by the safety validation.';
}

/** One entry of a "one per line" list: the trimmed value and its 1-based line in the text. */
export interface Line {
  readonly value: string;
  readonly line: number;
}

/** The non-empty, trimmed lines of a textarea, each with its line number. */
export function linesOf(text: string): Line[] {
  const out: Line[] = [];
  text.split('\n').forEach((raw, index) => {
    const value = raw.trim();
    if (value) out.push({ value, line: index + 1 });
  });
  return out;
}

/** The values of a "one per line" list. */
export function listOf(text: string): string[] {
  return linesOf(text).map((entry) => entry.value);
}

/** The textarea line of the `index`-th entry (as sent to the API), or `null`. */
export function lineOfEntry(text: string, index: number): number | null {
  return linesOf(text)[index]?.line ?? null;
}

/** A list as a textarea value (one per line). */
export function textOf(values: readonly string[] | null | undefined): string {
  return (values ?? []).join('\n');
}

/** `YYYY-MM-DD` of an ISO instant in UTC (`''` for none). */
export function dayOf(iso: string | null | undefined): string {
  return iso ? iso.slice(0, 10) : '';
}

/** The end (23:59:59 UTC) of a `YYYY-MM-DD` day as an ISO instant. */
export function endOfDayIso(day: string): string {
  return new Date(`${day}T23:59:59.000Z`).toISOString();
}

/** `YYYY-MM-DD` of today plus `days` (UTC). */
export function dayFromNow(days: number, now = Date.now()): string {
  return new Date(now + days * 86_400_000).toISOString().slice(0, 10);
}

/** Canonical JSON with sorted object keys and sorted arrays of primitives (set semantics). */
export function canonicalSet(value: unknown): string {
  const normalize = (v: unknown): unknown => {
    if (Array.isArray(v)) {
      const items = v.map(normalize);
      return items.every((item) => typeof item !== 'object' || item === null)
        ? [...items].sort((a, b) => String(a).localeCompare(String(b)))
        : items;
    }
    if (v && typeof v === 'object') {
      return Object.fromEntries(
        Object.keys(v as Record<string, unknown>)
          .sort()
          .map((key) => [key, normalize((v as Record<string, unknown>)[key])]),
      );
    }
    return v;
  };
  return JSON.stringify(normalize(value));
}

/** Whether two lists hold the same values in the same order. */
export function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}
