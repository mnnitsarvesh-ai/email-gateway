import { z } from 'zod';
import type { RequestBody } from '@/lib/api/types';
import {
  confidence,
  enumOf,
  futureDay,
  futureDayProblem,
  lineList,
  numberOrUndefined,
  optionalConfidence,
  optionalText,
  optionalWholeNumber,
  text,
  wholeNumber,
} from './fields';
import {
  AADHAAR_BASES,
  DLP_ACTIONS,
  DLP_CATEGORIES,
  DLP_COVERAGE_REASONS,
  DLP_DETECTORS,
  DLP_DICTIONARY_CATEGORIES,
  DLP_DIRECTIONS,
  DLP_EXCEPTION_SCOPES,
  DLP_MASK_STYLES,
  DLP_MIN_SEVERITIES,
  DLP_MODES,
  DLP_SEVERITIES,
  DLP_VALIDATORS,
  canonicalSet,
  dayFromNow,
  dayOf,
  endOfDayIso,
  listOf,
  sameList,
  textOf,
  type AadhaarBasis,
  type DlpCategory,
  type DlpCoverageReason,
  type DlpDetector,
  type DlpDictionary,
  type DlpDirection,
  type DlpExceptionRow,
  type DlpMinSeverity,
  type DlpPatternRow,
  type DlpPolicyRow,
  type DlpRule,
  type DlpRuleConditions,
} from './model';

/**
 * Forms of the DLP configuration editors (step 7.3 WP5, design §2 B13): one strict zod schema per
 * form mirroring the operation's OpenAPI request body (`RequestBody<op>` of the generated client),
 * defaults from the edited entry, and body builders. Update bodies carry `version` (optimistic
 * concurrency, `409 version_conflict`) and only the fields that changed.
 */

const directions = z.array(enumOf(DLP_DIRECTIONS));

/** Lower-cased "one per line" values (the API's normal form of addresses and domains). */
const lowerList = (value: string) => listOf(value).map((item) => item.toLowerCase());

// ---------------------------------------------------------------------------------------------
// Policies (POST /dlp/policies, PATCH /dlp/policies/{id})
// ---------------------------------------------------------------------------------------------

export const dlpPolicySchema = z
  .object({
    name: text(1, 128, 'Enter a name'),
    description: optionalText(512),
    enabled: z.boolean(),
    mode: enumOf(DLP_MODES),
    priority: wholeNumber(0, 1000),
    directions: directions.min(1, 'Choose at least one direction'),
  })
  .strict();
export type DlpPolicyInput = z.infer<typeof dlpPolicySchema>;

export function dlpPolicyDefaults(policy?: DlpPolicyRow): DlpPolicyInput {
  return {
    name: policy?.name ?? '',
    description: policy?.description ?? '',
    enabled: policy?.enabled ?? true,
    mode: policy?.mode ?? 'enforce',
    priority: String(policy?.priority ?? 100),
    directions: policy ? [...policy.directions] : ['outbound', 'internal'],
  };
}

export function dlpPolicyCreateBody(
  values: DlpPolicyInput,
): RequestBody<'DlpPoliciesController_create_v1'> {
  return {
    name: values.name,
    ...(values.description ? { description: values.description } : {}),
    enabled: values.enabled,
    mode: values.mode,
    priority: Number(values.priority),
    directions: values.directions,
  };
}

export function dlpPolicyUpdateBody(
  policy: DlpPolicyRow,
  values: DlpPolicyInput,
): RequestBody<'DlpPoliciesController_update_v1'> {
  const description = values.description || null;
  const priority = Number(values.priority);
  return {
    version: policy.version,
    ...(values.name !== policy.name ? { name: values.name } : {}),
    ...(description !== policy.description ? { description } : {}),
    ...(values.enabled !== policy.enabled ? { enabled: values.enabled } : {}),
    ...(values.mode !== policy.mode ? { mode: values.mode } : {}),
    ...(priority !== policy.priority ? { priority } : {}),
    ...(canonicalSet(values.directions) !== canonicalSet(policy.directions)
      ? { directions: values.directions }
      : {}),
  };
}

// ---------------------------------------------------------------------------------------------
// Rules (POST /dlp/policies/{id}/rules, PATCH …/rules/{ruleId})
// ---------------------------------------------------------------------------------------------

const addresses = lineList({
  max: 100,
  itemMin: 3,
  itemMax: 320,
  check: 'address',
  noun: 'addresses',
});
const domains = lineList({ max: 100, itemMax: 253, check: 'domain', noun: 'domains' });

export const SELECTOR_REQUIRED =
  'Choose at least one data category, detector, custom pattern, dictionary or coverage reason';

export const dlpRuleSchema = z
  .object({
    name: text(1, 128, 'Enter a name'),
    action: enumOf(DLP_ACTIONS),
    priority: wholeNumber(0, 1000),
    enabled: z.boolean(),
    categories: z.array(enumOf(DLP_CATEGORIES)),
    detectors: z.array(enumOf(DLP_DETECTORS)),
    customPatternIds: z.array(z.string()).max(20, 'At most 20 custom patterns'),
    dictionaryIds: z.array(z.string()).max(20, 'At most 20 dictionaries'),
    coverageReasons: z.array(enumOf(DLP_COVERAGE_REASONS)),
    minCount: optionalWholeNumber(1, 10_000),
    minConfidence: optionalConfidence(),
    minSeverity: z.union([z.literal(''), enumOf(DLP_MIN_SEVERITIES)]),
    directions,
    senderAddresses: addresses,
    senderDomains: domains,
    recipientAddresses: addresses,
    recipientDomains: domains,
    externalOnly: z.boolean(),
    attachmentsOnly: z.boolean(),
  })
  .strict()
  .superRefine((values, ctx) => {
    const selected =
      values.categories.length +
      values.detectors.length +
      values.customPatternIds.length +
      values.dictionaryIds.length +
      values.coverageReasons.length;
    if (selected === 0) {
      ctx.addIssue({ code: 'custom', path: ['categories'], message: SELECTOR_REQUIRED });
    }
  });
export type DlpRuleInput = z.infer<typeof dlpRuleSchema>;

export function dlpRuleDefaults(rule?: DlpRule): DlpRuleInput {
  const c = rule?.conditions;
  return {
    name: rule?.name ?? '',
    action: rule?.action ?? 'alert',
    priority: String(rule?.priority ?? 100),
    enabled: rule?.enabled ?? true,
    categories: [...(c?.selectors.categories ?? [])],
    detectors: [...(c?.selectors.detectors ?? [])],
    customPatternIds: [...(c?.selectors.customPatternIds ?? [])],
    dictionaryIds: [...(c?.selectors.dictionaryIds ?? [])],
    coverageReasons: [...(c?.selectors.coverageReasons ?? [])],
    minCount: c?.minCount === undefined ? '' : String(c.minCount),
    minConfidence: c?.minConfidence === undefined ? '' : String(c.minConfidence),
    minSeverity: c?.minSeverity ?? '',
    directions: [...(c?.directions ?? [])],
    senderAddresses: textOf(c?.sender?.addresses),
    senderDomains: textOf(c?.sender?.domains),
    recipientAddresses: textOf(c?.recipients?.addresses),
    recipientDomains: textOf(c?.recipients?.domains),
    externalOnly: c?.recipients?.externalOnly ?? false,
    attachmentsOnly: c?.attachmentsOnly ?? false,
  };
}

type Conditions = RequestBody<'DlpPoliciesController_createRule_v1'>['conditions'];

/** The parts of a rule's conditions, typed (lists as arrays, numbers as numbers). */
interface ConditionParts {
  readonly categories: readonly DlpCategory[];
  readonly detectors: readonly DlpDetector[];
  readonly customPatternIds: readonly string[];
  readonly dictionaryIds: readonly string[];
  readonly coverageReasons: readonly DlpCoverageReason[];
  readonly minCount: number | undefined;
  readonly minConfidence: number | undefined;
  readonly minSeverity: DlpMinSeverity | undefined;
  readonly directions: readonly DlpDirection[];
  readonly senderAddresses: readonly string[];
  readonly senderDomains: readonly string[];
  readonly recipientAddresses: readonly string[];
  readonly recipientDomains: readonly string[];
  readonly externalOnly: boolean;
  readonly attachmentsOnly: boolean;
}

/** `conditions` from its parts: empty lists, empty scopes and `false` flags are omitted. */
function conditionsOf(parts: ConditionParts): Conditions {
  const sender = {
    ...(parts.senderAddresses.length ? { addresses: [...parts.senderAddresses] } : {}),
    ...(parts.senderDomains.length ? { domains: [...parts.senderDomains] } : {}),
  };
  const recipients = {
    ...(parts.recipientAddresses.length ? { addresses: [...parts.recipientAddresses] } : {}),
    ...(parts.recipientDomains.length ? { domains: [...parts.recipientDomains] } : {}),
    ...(parts.externalOnly ? { externalOnly: true } : {}),
  };
  return {
    selectors: {
      ...(parts.categories.length ? { categories: [...parts.categories] } : {}),
      ...(parts.detectors.length ? { detectors: [...parts.detectors] } : {}),
      ...(parts.customPatternIds.length ? { customPatternIds: [...parts.customPatternIds] } : {}),
      ...(parts.dictionaryIds.length ? { dictionaryIds: [...parts.dictionaryIds] } : {}),
      ...(parts.coverageReasons.length ? { coverageReasons: [...parts.coverageReasons] } : {}),
    },
    ...(parts.minCount !== undefined ? { minCount: parts.minCount } : {}),
    ...(parts.minConfidence !== undefined ? { minConfidence: parts.minConfidence } : {}),
    ...(parts.minSeverity ? { minSeverity: parts.minSeverity } : {}),
    ...(parts.directions.length ? { directions: [...parts.directions] } : {}),
    ...(Object.keys(sender).length ? { sender } : {}),
    ...(Object.keys(recipients).length ? { recipients } : {}),
    ...(parts.attachmentsOnly ? { attachmentsOnly: true } : {}),
  };
}

/** The rule `conditions` of the form values. */
export function ruleConditions(values: DlpRuleInput): Conditions {
  return conditionsOf({
    categories: values.categories,
    detectors: values.detectors,
    customPatternIds: values.customPatternIds,
    dictionaryIds: values.dictionaryIds,
    coverageReasons: values.coverageReasons,
    minCount: numberOrUndefined(values.minCount),
    minConfidence: numberOrUndefined(values.minConfidence),
    minSeverity: values.minSeverity || undefined,
    directions: values.directions,
    senderAddresses: lowerList(values.senderAddresses),
    senderDomains: lowerList(values.senderDomains),
    recipientAddresses: lowerList(values.recipientAddresses),
    recipientDomains: lowerList(values.recipientDomains),
    externalOnly: values.externalOnly,
    attachmentsOnly: values.attachmentsOnly,
  });
}

/** Stored conditions in the form's normal shape (to detect an unchanged rule). */
export function normalizedConditions(c: DlpRuleConditions): Conditions {
  return conditionsOf({
    categories: c.selectors.categories ?? [],
    detectors: c.selectors.detectors ?? [],
    customPatternIds: c.selectors.customPatternIds ?? [],
    dictionaryIds: c.selectors.dictionaryIds ?? [],
    coverageReasons: c.selectors.coverageReasons ?? [],
    minCount: c.minCount,
    minConfidence: c.minConfidence,
    minSeverity: c.minSeverity,
    directions: c.directions ?? [],
    senderAddresses: c.sender?.addresses ?? [],
    senderDomains: c.sender?.domains ?? [],
    recipientAddresses: c.recipients?.addresses ?? [],
    recipientDomains: c.recipients?.domains ?? [],
    externalOnly: c.recipients?.externalOnly ?? false,
    attachmentsOnly: c.attachmentsOnly ?? false,
  });
}

export function dlpRuleCreateBody(
  values: DlpRuleInput,
): RequestBody<'DlpPoliciesController_createRule_v1'> {
  return {
    name: values.name,
    enabled: values.enabled,
    priority: Number(values.priority),
    conditions: ruleConditions(values),
    action: values.action,
  };
}

export function dlpRuleUpdateBody(
  rule: DlpRule,
  values: DlpRuleInput,
): RequestBody<'DlpPoliciesController_updateRule_v1'> {
  const conditions = ruleConditions(values);
  const priority = Number(values.priority);
  const changed = canonicalSet(conditions) !== canonicalSet(normalizedConditions(rule.conditions));
  return {
    version: rule.version,
    ...(values.name !== rule.name ? { name: values.name } : {}),
    ...(values.enabled !== rule.enabled ? { enabled: values.enabled } : {}),
    ...(priority !== rule.priority ? { priority } : {}),
    ...(changed ? { conditions } : {}),
    ...(values.action !== rule.action ? { action: values.action } : {}),
  };
}

// ---------------------------------------------------------------------------------------------
// Exceptions (POST /dlp/exceptions, PATCH /dlp/exceptions/{id})
// ---------------------------------------------------------------------------------------------

export const EXCEPTION_TARGETS = ['all', 'policy', 'rule'] as const;
export type ExceptionTarget = (typeof EXCEPTION_TARGETS)[number];

const filterFields = {
  detectors: z.array(enumOf(DLP_DETECTORS)),
  categories: z.array(enumOf(DLP_CATEGORIES)),
};

export const dlpExceptionSchema = z
  .object({
    scope: enumOf(DLP_EXCEPTION_SCOPES),
    value: text(1, 320, 'Enter an address or a domain'),
    target: z.enum(EXCEPTION_TARGETS),
    policyId: z.string(),
    ruleId: z.string(),
    ...filterFields,
    reason: text(1, 512, 'Enter a reason'),
    expiresOn: futureDay({ required: 'Choose when the exception expires' }),
    enabled: z.boolean(),
  })
  .strict()
  .superRefine((values, ctx) => {
    const address = values.scope.endsWith('_address');
    if (address && !/^[^\s@]+@[^\s@]+$/.test(values.value)) {
      ctx.addIssue({
        code: 'custom',
        path: ['value'],
        message: 'Enter an address such as name@example.com',
      });
    }
    if (!address && (values.value.includes('@') || /\s/.test(values.value))) {
      ctx.addIssue({
        code: 'custom',
        path: ['value'],
        message: 'Enter a domain such as example.com',
      });
    }
    if (values.target !== 'all' && !values.policyId) {
      ctx.addIssue({ code: 'custom', path: ['policyId'], message: 'Choose a policy' });
    }
    if (values.target === 'rule' && !values.ruleId) {
      ctx.addIssue({ code: 'custom', path: ['ruleId'], message: 'Choose a rule' });
    }
  });
export type DlpExceptionInput = z.infer<typeof dlpExceptionSchema>;

export function dlpExceptionDefaults(now = Date.now()): DlpExceptionInput {
  return {
    scope: 'recipient_domain',
    value: '',
    target: 'all',
    policyId: '',
    ruleId: '',
    detectors: [],
    categories: [],
    reason: '',
    expiresOn: dayFromNow(30, now),
    enabled: true,
  };
}

type Filters = NonNullable<RequestBody<'DlpExceptionsController_create_v1'>['filters']>;

function filtersOf(values: {
  readonly detectors: readonly DlpDetector[];
  readonly categories: readonly DlpCategory[];
}): Filters {
  return {
    ...(values.detectors.length ? { detectors: [...values.detectors] } : {}),
    ...(values.categories.length ? { categories: [...values.categories] } : {}),
  };
}

export function dlpExceptionCreateBody(
  values: DlpExceptionInput,
): RequestBody<'DlpExceptionsController_create_v1'> {
  const filters = filtersOf(values);
  return {
    scope: values.scope,
    value: values.value,
    ...(values.target === 'policy' ? { policyId: values.policyId } : {}),
    ...(values.target === 'rule' ? { ruleId: values.ruleId } : {}),
    ...(Object.keys(filters).length ? { filters } : {}),
    reason: values.reason,
    expiresAt: endOfDayIso(values.expiresOn),
    enabled: values.enabled,
  };
}

/** The editable part of an exception (scope, value and target are fixed: delete and add instead). */
export function dlpExceptionEditSchema(exception: Pick<DlpExceptionRow, 'expiresAt'>) {
  const original = dayOf(exception.expiresAt);
  return z
    .object({
      ...filterFields,
      reason: text(1, 512, 'Enter a reason'),
      expiresOn: z.string(),
      enabled: z.boolean(),
    })
    .strict()
    .superRefine((values, ctx) => {
      // An unchanged (possibly past) expiry is not sent, so it is not checked either.
      if (values.expiresOn === original) return;
      const problem = futureDayProblem(
        values.expiresOn,
        false,
        'Choose when the exception expires',
      );
      if (problem) ctx.addIssue({ code: 'custom', path: ['expiresOn'], message: problem });
    });
}
export type DlpExceptionEditInput = z.infer<ReturnType<typeof dlpExceptionEditSchema>>;

export function dlpExceptionEditDefaults(exception: DlpExceptionRow): DlpExceptionEditInput {
  return {
    detectors: [...(exception.filters?.detectors ?? [])],
    categories: [...(exception.filters?.categories ?? [])],
    reason: exception.reason,
    expiresOn: dayOf(exception.expiresAt),
    enabled: exception.enabled,
  };
}

export function dlpExceptionUpdateBody(
  exception: DlpExceptionRow,
  values: DlpExceptionEditInput,
): RequestBody<'DlpExceptionsController_update_v1'> {
  const next = filtersOf(values);
  const before = filtersOf({
    detectors: exception.filters?.detectors ?? [],
    categories: exception.filters?.categories ?? [],
  });
  const filtersChanged = canonicalSet(next) !== canonicalSet(before);
  return {
    version: exception.version,
    ...(values.reason !== exception.reason ? { reason: values.reason } : {}),
    ...(values.expiresOn !== dayOf(exception.expiresAt)
      ? { expiresAt: endOfDayIso(values.expiresOn) }
      : {}),
    ...(values.enabled !== exception.enabled ? { enabled: values.enabled } : {}),
    ...(filtersChanged ? { filters: Object.keys(next).length ? next : null } : {}),
  };
}

// ---------------------------------------------------------------------------------------------
// Custom patterns (POST /dlp/patterns, PATCH /dlp/patterns/{id}, POST /dlp/patterns/test)
// ---------------------------------------------------------------------------------------------

export const dlpPatternSchema = z
  .object({
    name: text(1, 128, 'Enter a name'),
    // Not trimmed: spaces are part of a regular expression.
    pattern: z.string().min(1, 'Enter a pattern').max(512, 'At most 512 characters'),
    caseInsensitive: z.boolean(),
    validator: enumOf(DLP_VALIDATORS),
    contextKeywords: lineList({ max: 20, itemMax: 64, noun: 'context keywords' }),
    requireContext: z.boolean(),
    severity: enumOf(DLP_SEVERITIES),
    baseConfidence: confidence(),
    maskStyle: enumOf(DLP_MASK_STYLES),
    enabled: z.boolean(),
  })
  .strict();
export type DlpPatternInput = z.infer<typeof dlpPatternSchema>;

export function dlpPatternDefaults(pattern?: DlpPatternRow): DlpPatternInput {
  return {
    name: pattern?.name ?? '',
    pattern: pattern?.pattern ?? '',
    caseInsensitive: pattern?.caseInsensitive ?? false,
    validator: pattern?.validator ?? 'none',
    contextKeywords: textOf(pattern?.contextKeywords),
    requireContext: pattern?.requireContext ?? false,
    severity: pattern?.severity ?? 'medium',
    baseConfidence: String(pattern?.baseConfidence ?? 0.8),
    maskStyle: pattern?.maskStyle ?? 'last4',
    enabled: pattern?.enabled ?? true,
  };
}

export function dlpPatternCreateBody(
  values: DlpPatternInput,
): RequestBody<'DlpPatternsController_create_v1'> {
  return {
    name: values.name,
    pattern: values.pattern,
    caseInsensitive: values.caseInsensitive,
    validator: values.validator,
    contextKeywords: listOf(values.contextKeywords),
    requireContext: values.requireContext,
    severity: values.severity,
    baseConfidence: Number(values.baseConfidence),
    maskStyle: values.maskStyle,
    enabled: values.enabled,
  };
}

export function dlpPatternUpdateBody(
  pattern: DlpPatternRow,
  values: DlpPatternInput,
): RequestBody<'DlpPatternsController_update_v1'> {
  const contextKeywords = listOf(values.contextKeywords);
  const baseConfidence = Number(values.baseConfidence);
  return {
    version: pattern.version,
    ...(values.name !== pattern.name ? { name: values.name } : {}),
    ...(values.pattern !== pattern.pattern ? { pattern: values.pattern } : {}),
    ...(values.caseInsensitive !== pattern.caseInsensitive
      ? { caseInsensitive: values.caseInsensitive }
      : {}),
    ...(values.validator !== pattern.validator ? { validator: values.validator } : {}),
    ...(!sameList(contextKeywords, pattern.contextKeywords) ? { contextKeywords } : {}),
    ...(values.requireContext !== pattern.requireContext
      ? { requireContext: values.requireContext }
      : {}),
    ...(values.severity !== pattern.severity ? { severity: values.severity } : {}),
    ...(baseConfidence !== pattern.baseConfidence ? { baseConfidence } : {}),
    ...(values.maskStyle !== pattern.maskStyle ? { maskStyle: values.maskStyle } : {}),
    ...(values.enabled !== pattern.enabled ? { enabled: values.enabled } : {}),
  };
}

/** The sample limit of `POST /dlp/patterns/test` (characters). */
export const SAMPLE_MAX = 4096;
/** The pattern limit of `POST /dlp/patterns/test` (characters). */
export const TEST_PATTERN_MAX = 1024;

export type PatternTestOptions = Pick<
  DlpPatternInput,
  'pattern' | 'caseInsensitive' | 'validator' | 'contextKeywords' | 'requireContext' | 'maskStyle'
>;

/**
 * The body of `POST /dlp/patterns/test` from the pattern form's current (unsaved) values and a
 * typed sample. Nothing is evaluated here: the server validates and matches (design §7).
 */
export function patternTestBody(
  values: PatternTestOptions,
  sample: string,
): RequestBody<'DlpPatternsController_test_v1'> {
  return {
    pattern: values.pattern,
    caseInsensitive: values.caseInsensitive,
    validator: values.validator,
    contextKeywords: listOf(values.contextKeywords),
    requireContext: values.requireContext,
    maskStyle: values.maskStyle,
    sample,
  };
}

// ---------------------------------------------------------------------------------------------
// Keyword dictionaries (POST /dlp/dictionaries, PATCH /dlp/dictionaries/{id})
// ---------------------------------------------------------------------------------------------

export const dlpDictionarySchema = z
  .object({
    name: text(1, 128, 'Enter a name'),
    category: enumOf(DLP_DICTIONARY_CATEGORIES),
    terms: lineList({ min: 1, max: 10_000, itemMax: 64, noun: 'terms', one: 'term' }),
    severity: enumOf(DLP_SEVERITIES),
    baseConfidence: confidence(),
    minMatches: wholeNumber(1, 100),
    enabled: z.boolean(),
  })
  .strict();
export type DlpDictionaryInput = z.infer<typeof dlpDictionarySchema>;

export function dlpDictionaryDefaults(dictionary?: DlpDictionary): DlpDictionaryInput {
  return {
    name: dictionary?.name ?? '',
    category: dictionary?.category ?? 'confidential',
    terms: textOf(dictionary?.terms),
    severity: dictionary?.severity ?? 'medium',
    baseConfidence: String(dictionary?.baseConfidence ?? 0.7),
    minMatches: String(dictionary?.minMatches ?? 1),
    enabled: dictionary?.enabled ?? true,
  };
}

export function dlpDictionaryCreateBody(
  values: DlpDictionaryInput,
): RequestBody<'DlpDictionariesController_create_v1'> {
  return {
    name: values.name,
    category: values.category,
    terms: listOf(values.terms),
    severity: values.severity,
    baseConfidence: Number(values.baseConfidence),
    minMatches: Number(values.minMatches),
    enabled: values.enabled,
  };
}

export function dlpDictionaryUpdateBody(
  dictionary: DlpDictionary,
  values: DlpDictionaryInput,
): RequestBody<'DlpDictionariesController_update_v1'> {
  const terms = listOf(values.terms);
  const baseConfidence = Number(values.baseConfidence);
  const minMatches = Number(values.minMatches);
  return {
    version: dictionary.version,
    ...(values.name !== dictionary.name ? { name: values.name } : {}),
    ...(values.category !== dictionary.category ? { category: values.category } : {}),
    ...(!sameList(terms, dictionary.terms) ? { terms } : {}),
    ...(values.severity !== dictionary.severity ? { severity: values.severity } : {}),
    ...(baseConfidence !== dictionary.baseConfidence ? { baseConfidence } : {}),
    ...(minMatches !== dictionary.minMatches ? { minMatches } : {}),
    ...(values.enabled !== dictionary.enabled ? { enabled: values.enabled } : {}),
  };
}

// ---------------------------------------------------------------------------------------------
// Aadhaar compliance basis (PUT /dlp/compliance/aadhaar)
// ---------------------------------------------------------------------------------------------

export const aadhaarSchema = z
  .object({
    basis: enumOf(AADHAAR_BASES),
    reference: text(1, 256, 'Enter the document or approval reference'),
    reviewOn: futureDay({ required: 'Choose the review date' }),
    attested: z.boolean().refine((value) => value, {
      message: 'Confirm the attestation to record the basis',
    }),
  })
  .strict();
export type AadhaarInput = z.infer<typeof aadhaarSchema>;

export function aadhaarDefaults(current?: {
  basis: AadhaarBasis | null;
  reference: string | null;
  reviewDueAt: string | null;
}): AadhaarInput {
  const due = current?.reviewDueAt ?? null;
  return {
    basis: current?.basis ?? 'regulatory_obligation',
    reference: current?.reference ?? '',
    reviewOn: due && Date.parse(due) > Date.now() ? dayOf(due) : '',
    attested: false,
  };
}

export function aadhaarBody(
  expectedVersion: number,
  values: AadhaarInput,
): RequestBody<'DlpComplianceController_enable_v1'> {
  return {
    expectedVersion,
    basis: values.basis,
    reference: values.reference,
    attested: true,
    reviewDueAt: endOfDayIso(values.reviewOn),
  };
}
