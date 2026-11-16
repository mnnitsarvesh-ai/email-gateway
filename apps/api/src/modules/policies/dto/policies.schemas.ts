import {
  ACTION_STATUSES,
  DECISION_SOURCES,
  effectivePolicySettingsSchema,
  POLICY_ACTION_KINDS,
  POLICY_ACTION_PARAM_TYPES,
  POLICY_ACTION_TYPES,
  POLICY_DIRECTIONS,
  POLICY_DISPOSITIONS,
  POLICY_DSL_VERSION,
  POLICY_FIELD_GROUP_IDS,
  POLICY_FIELD_SCOPES,
  POLICY_FIELD_TYPES,
  POLICY_FIELD_UNITS,
  POLICY_FINAL_ACTIONS,
  POLICY_ITEM_KINDS,
  POLICY_MESSAGE_DIRECTIONS,
  POLICY_NON_TERMINAL_ACTIONS,
  POLICY_OPERATORS,
  POLICY_TRIGGERS,
  POLICY_VALUE_SHAPES,
  policyEvaluationResultSchema,
  recipientDecisionsSchema,
  policyEvaluationViewSchema,
  policyTenantSettingsSchema,
  syntheticFactsSchema,
  WEEKDAYS,
} from '@email-gateway/policy-dsl';
import { z } from 'zod';
import { PageQuerySchema } from '../../../http/pagination';

/**
 * Shapes of the policy routes (step 5.2 P16, P17, P22, P23, docs/plan/steps/16-policy-engine.md):
 * policies and their versions (drafts are editable, published versions are immutable), the
 * tenant settings, the catalog, policy tests with synthetic facts, the dry-run of a stored round
 * and the execution history. Every id is a public id (UUIDv7); versions are numbered per
 * policy; scans are decimal ids. Views never carry internal ids or message content.
 */

const noControl = (value: string): boolean => {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
};

const IsoDate = z.iso.datetime();
const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const RowVersion = z.number().int().min(1).max(4_294_967_295);
const VersionNo = z.number().int().min(1).max(4_294_967_295);
const Decimal = z.string().regex(/^(0|[1-9][0-9]{0,19})$/);
const RULE_ID = /^[a-z0-9][a-z0-9_-]{0,47}$/;

export const PolicyIdSchema = z.uuid();
/** `{versionNo}`: a positive version number of the policy. */
export const PolicyVersionNoSchema = z
  .string()
  .regex(/^[1-9][0-9]{0,9}$/, 'Expected a version number')
  .refine((v) => Number(v) <= 4_294_967_295, 'Expected a version number')
  .transform(Number);
/** `{scanId}`: a decimal `email_scans.id`. */
export const PolicyScanIdSchema = z
  .string()
  .refine(
    (value) => /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 18_446_744_073_709_551_615n,
    'Expected a decimal scan id',
  );

const text = (max: number) =>
  z.string().trim().min(1).max(max).refine(noControl, 'Must not contain control characters');

const ChangeNote = text(512)
  .nullable()
  .optional()
  .describe('Why the version exists (≤ 512 characters; never copied into audit metadata)');

/**
 * The definition as received: any JSON object. The DSL (`policy-dsl/1`, P2–P6) is checked by
 * `validatePolicyDefinition`, which answers `400 policy_definition_invalid` with every violation
 * by path. The catalog (`GET /policies/catalog`) and docs/architecture/policy-dsl.md describe it.
 */
const DefinitionInput = z
  .record(z.string(), z.unknown())
  .describe(
    'A `policy-dsl/1` document: `{ dslVersion, direction, priority, rules[], exceptions? }` ' +
      '(see `GET /policies/catalog` and docs/architecture/policy-dsl.md)',
  );

// --------------------------------------------------------------------------------------------
// Policies
// --------------------------------------------------------------------------------------------

export const POLICY_STATUSES = ['draft', 'active', 'disabled'] as const;
export const POLICY_VERSION_STATUSES = ['draft', 'published', 'superseded', 'rolled_back'] as const;

const DirectoryReferencesSchema = z.strictObject({
  departmentIds: z.array(z.uuid()),
  userIds: z.array(z.uuid()),
});

export const PolicyVersionSummarySchema = z.strictObject({
  policyId: z.uuid(),
  versionNo: VersionNo,
  status: z
    .enum(POLICY_VERSION_STATUSES)
    .describe('`draft` (editable), `published` (immutable), `superseded` (retired legacy row)'),
  active: z
    .boolean()
    .describe('The policy’s active version (evaluated while the policy is active)'),
  dslVersion: z.string().nullable().describe('`policy-dsl/1`; null for retired legacy rows'),
  definitionSha256: Sha256.describe('SHA-256 of the canonical JSON of the definition'),
  ruleCount: z.number().int().min(0),
  hasOverrideRules: z.boolean(),
  references: DirectoryReferencesSchema.nullable().describe(
    'Department and user public ids the definition references',
  ),
  changeNote: z.string().nullable(),
  rowVersion: RowVersion.describe('`expectedRowVersion` of PUT, DELETE and publish'),
  createdByUserId: z.uuid().nullable(),
  updatedByUserId: z.uuid().nullable(),
  publishedByUserId: z.uuid().nullable(),
  publishedAt: IsoDate.nullable(),
  createdAt: IsoDate,
  updatedAt: IsoDate,
});
export type PolicyVersionSummary = z.output<typeof PolicyVersionSummarySchema>;

const ViolationSchema = z.strictObject({ path: z.string(), code: z.string(), message: z.string() });

export const PolicyVersionDetailSchema = PolicyVersionSummarySchema.extend({
  definition: z.unknown().describe('The stored definition'),
  validation: z
    .strictObject({
      valid: z.boolean().describe('False when the current DSL no longer accepts the definition'),
      violations: z.array(ViolationSchema),
    })
    .describe('The definition validated now (a retired DSL version shows its violations)'),
});
export type PolicyVersionDetail = z.output<typeof PolicyVersionDetailSchema>;

export const PolicyVersionPageSchema = z.strictObject({
  data: z.array(PolicyVersionSummarySchema).describe('Newest first'),
  nextCursor: z.string().nullable(),
});
export type PolicyVersionPage = z.output<typeof PolicyVersionPageSchema>;

export const PolicySummarySchema = z.strictObject({
  id: z.uuid(),
  name: z.string(),
  description: z.string().nullable(),
  status: z
    .enum(POLICY_STATUSES)
    .describe(
      '`draft` (never activated), `active` (evaluated), `disabled` (has versions, not evaluated)',
    ),
  direction: z.enum(POLICY_DIRECTIONS).describe('From the active version (newest draft before)'),
  priority: z.number().int().describe('From the active version (newest draft before)'),
  activeVersionNo: VersionNo.nullable(),
  latestVersionNo: VersionNo.nullable(),
  rowVersion: RowVersion.describe('`expectedRowVersion` of PATCH, enable, disable and DELETE'),
  createdByUserId: z.uuid().nullable(),
  updatedByUserId: z.uuid().nullable(),
  createdAt: IsoDate,
  updatedAt: IsoDate,
});
export type PolicySummary = z.output<typeof PolicySummarySchema>;

export const PolicyDetailSchema = PolicySummarySchema.extend({
  activeVersion: z
    .strictObject({
      versionNo: VersionNo,
      definitionSha256: Sha256,
      ruleCount: z.number().int().min(0),
      hasOverrideRules: z.boolean(),
      publishedAt: IsoDate.nullable(),
    })
    .nullable(),
  counts: z.strictObject({
    drafts: z.number().int().min(0),
    published: z.number().int().min(0),
    superseded: z.number().int().min(0),
    limit: z.number().int().min(1).describe('POLICY_MAX_VERSIONS_PER_POLICY'),
  }),
});
export type PolicyDetail = z.output<typeof PolicyDetailSchema>;

export const PolicyPageSchema = z.strictObject({
  data: z.array(PolicySummarySchema).describe('Newest first (archived policies are not listed)'),
  nextCursor: z.string().nullable(),
  generation: Decimal.describe(
    'The organization’s policy generation (incremented by every change evaluation sees)',
  ),
});
export type PolicyPage = z.output<typeof PolicyPageSchema>;

export const PolicyListQuerySchema = PageQuerySchema.extend({
  status: z.enum(POLICY_STATUSES).optional(),
  direction: z.enum(POLICY_DIRECTIONS).optional(),
}).strict();
export type PolicyListQuery = z.output<typeof PolicyListQuerySchema>;

export const PolicyCreateSchema = z.strictObject({
  name: text(128).describe('Unique in the organization (archived policies keep their name)'),
  description: text(512).nullable().optional(),
  definition: DefinitionInput,
  changeNote: ChangeNote,
});
export type PolicyCreate = z.output<typeof PolicyCreateSchema>;

export const PolicyCreatedSchema = z.strictObject({
  policy: PolicyDetailSchema,
  version: PolicyVersionDetailSchema,
});
export type PolicyCreated = z.output<typeof PolicyCreatedSchema>;

export const PolicyUpdateSchema = z
  .strictObject({
    name: text(128).optional(),
    description: text(512).nullable().optional(),
    expectedRowVersion: RowVersion.describe('Current `rowVersion` (409 policy_conflict)'),
  })
  .refine((b) => b.name !== undefined || b.description !== undefined, {
    message: 'Nothing to change: give name and/or description',
  });
export type PolicyUpdate = z.output<typeof PolicyUpdateSchema>;
export const PolicyUpdateDocSchema = z.strictObject({
  name: z.string().min(1).max(128).optional(),
  description: z.string().min(1).max(512).nullable().optional(),
  expectedRowVersion: RowVersion,
});

/** Optional body of enable, disable and activate (an empty body is accepted). */
export const PolicyRowChangeSchema = z.preprocess(
  (value) => value ?? {},
  z.strictObject({
    expectedRowVersion: RowVersion.optional().describe(
      'When given, the change applies only at this policy `rowVersion`',
    ),
  }),
);
export type PolicyRowChange = z.output<typeof PolicyRowChangeSchema>;
export const PolicyRowChangeDocSchema = z.strictObject({
  expectedRowVersion: RowVersion.optional(),
});

export const ExpectedRowVersionQuerySchema = z.strictObject({
  expectedRowVersion: z.coerce
    .number()
    .int()
    .min(1)
    .max(4_294_967_295)
    .optional()
    .describe('When given, the delete applies only at this rowVersion'),
});
export type ExpectedRowVersionQuery = z.output<typeof ExpectedRowVersionQuerySchema>;

// --------------------------------------------------------------------------------------------
// Versions
// --------------------------------------------------------------------------------------------

export const PolicyVersionListQuerySchema = PageQuerySchema.extend({
  status: z.enum(['draft', 'published', 'superseded']).optional(),
}).strict();
export type PolicyVersionListQuery = z.output<typeof PolicyVersionListQuerySchema>;

export const PolicyVersionCreateSchema = z
  .strictObject({
    definition: DefinitionInput.optional().describe(
      'The definition; default: the definition of `basedOnVersionNo`',
    ),
    basedOnVersionNo: VersionNo.optional().describe('Copy the definition of this version'),
    changeNote: ChangeNote,
  })
  .refine((b) => b.definition !== undefined || b.basedOnVersionNo !== undefined, {
    message: 'Give definition or basedOnVersionNo',
  });
export type PolicyVersionCreate = z.output<typeof PolicyVersionCreateSchema>;
export const PolicyVersionCreateDocSchema = z.strictObject({
  definition: DefinitionInput.optional(),
  basedOnVersionNo: VersionNo.optional(),
  changeNote: z.string().max(512).nullable().optional(),
});

export const PolicyVersionUpdateSchema = z.strictObject({
  definition: DefinitionInput,
  changeNote: ChangeNote,
  expectedRowVersion: RowVersion.describe(
    'Current `rowVersion` of the draft (409 policy_conflict)',
  ),
});
export type PolicyVersionUpdate = z.output<typeof PolicyVersionUpdateSchema>;

export const PolicyVersionPublishSchema = z.strictObject({
  activate: z.boolean().default(true).describe('Also make it the active version (default true)'),
  expectedRowVersion: RowVersion.describe('Current `rowVersion` of the draft'),
});
export type PolicyVersionPublish = z.output<typeof PolicyVersionPublishSchema>;

export const PolicyChangeResultSchema = z.strictObject({
  version: PolicyVersionDetailSchema,
  policy: PolicyDetailSchema,
  generation: Decimal.describe('The organization’s policy generation after the change'),
});
export type PolicyChangeResult = z.output<typeof PolicyChangeResultSchema>;

// --------------------------------------------------------------------------------------------
// Settings
// --------------------------------------------------------------------------------------------

export const PolicySettingsViewSchema = z.strictObject({
  settings: z
    .record(z.string(), z.unknown())
    .describe('The stored settings document (`{}` before the first change)'),
  effective: effectivePolicySettingsSchema.describe('Every key resolved (P11 defaults)'),
  violations: z
    .array(ViolationSchema)
    .describe('Non-empty when the stored document is invalid (the defaults apply)'),
  generation: Decimal.describe('Incremented by every change evaluation sees (P12)'),
  rowVersion: z
    .number()
    .int()
    .min(0)
    .describe('`expectedRowVersion` of PUT; 0 before the settings row exists'),
  settingsSha256: Sha256.nullable(),
  updatedByUserId: z.uuid().nullable(),
  updatedAt: IsoDate.nullable(),
});
export type PolicySettingsView = z.output<typeof PolicySettingsViewSchema>;

export const PolicySettingsUpdateSchema = z.strictObject({
  settings: z.record(z.string(), z.unknown()).describe('The whole settings document (P11)'),
  expectedRowVersion: z
    .number()
    .int()
    .min(0)
    .max(4_294_967_295)
    .describe('Current `rowVersion` (0 before the row exists; 409 policy_conflict)'),
});
export type PolicySettingsUpdate = z.output<typeof PolicySettingsUpdateSchema>;
export const PolicySettingsUpdateDocSchema = PolicySettingsUpdateSchema.extend({
  settings: policyTenantSettingsSchema,
});

// --------------------------------------------------------------------------------------------
// Catalog
// --------------------------------------------------------------------------------------------

const QUANTIFIERS = ['any', 'all'] as const;
const Count = z.number().int().min(0);

export const PolicyCatalogFieldSchema = z.strictObject({
  name: z.string(),
  type: z.enum(POLICY_FIELD_TYPES),
  scope: z.enum(POLICY_FIELD_SCOPES),
  ops: z.array(z.enum(POLICY_OPERATORS)),
  quantified: z.boolean(),
  authenticatedIdentity: z.boolean(),
  senderIdentity: z.enum(['raw', 'authenticated']).nullable(),
  aiDerived: z.boolean(),
  directions: z.array(z.enum(POLICY_MESSAGE_DIRECTIONS)),
  values: z.array(z.string()).nullable(),
  ordered: z.boolean(),
  min: z.number().int().nullable(),
  max: z.number().int().nullable(),
  description: z.string(),
  // Step 7.3 §4.1 (presentation metadata of the DSL package).
  label: z.string().min(1).max(64).describe('Plain-English label (unique; never the code name)'),
  group: z.enum(POLICY_FIELD_GROUP_IDS).describe('Id of the field group (`fieldGroups`)'),
  unit: z
    .enum(POLICY_FIELD_UNITS)
    .nullable()
    .describe('Unit of an `int` field (`bytes`, `count`, `score`); null for other types'),
  suggestions: z
    .array(z.string())
    .nullable()
    .describe(
      'Known codes for autocomplete of an open `codes` field (one without `values`); never a ' +
        'closed list (any reason code is accepted); null otherwise',
    ),
  contexts: z
    .strictObject({
      when: z.literal(true),
      exception: z.boolean(),
      relaxingWhen: z.boolean(),
      holdRule: z.boolean(),
    })
    .describe(
      'Where the field may be used: every `when`; `exception` = rule `unless` and policy ' +
        '`exceptions` (not raw sender identity, not AI-derived); `relaxingWhen` = the `when` of ' +
        'ALLOW and override rules (not raw sender identity); `holdRule` = rules with ' +
        'REQUIRE_APPROVAL, QUARANTINE or REJECT (not AI-derived)',
    ),
});

const PolicyOperatorDefinitionSchema = z.strictObject({
  op: z.enum(POLICY_OPERATORS),
  label: z.string(),
  phrase: z.string().describe('Lower-case verb phrase of a readable summary'),
  valueShape: z
    .enum(POLICY_VALUE_SHAPES)
    .describe(
      '`scalar` one value; `list` 1..`maxItems` items of `itemKind`; `range` `[low, high]`; ' +
        '`none` no value; `boolean`; `time` (the field decides `time.window` or ' +
        '`time.date_range`)',
    ),
  itemKind: z
    .enum(POLICY_ITEM_KINDS)
    .nullable()
    .describe(
      '`field` a value of the field type and vocabulary; `domain`; `glob`; `regex` (a pattern ' +
        "string or `{ pattern, flags: '' | 'i' }`, RE2, validated by the server); `cidr`; `code`",
    ),
  maxItems: z.number().int().min(1).nullable(),
  maxItemLength: z.number().int().min(1).nullable(),
  negated: z.boolean(),
  allowedInException: z.boolean(),
  description: z.string(),
});

const PolicyActionParamSchema = z.strictObject({
  name: z.string(),
  label: z.string(),
  type: z.enum(POLICY_ACTION_PARAM_TYPES),
  required: z.boolean(),
  values: z.array(z.string()).nullable().describe('Allowed values of an `enum` parameter'),
  default: z
    .union([z.string(), z.boolean()])
    .nullable()
    .describe('The value used when the parameter is absent (null = none or a tenant setting)'),
  minLength: z.number().int().min(0).nullable(),
  maxLength: z.number().int().min(1).nullable(),
  pattern: z
    .string()
    .nullable()
    .describe('A pattern a valid string matches (documentation; the server validates)'),
  description: z.string(),
});

const PolicyActionDefinitionSchema = z.strictObject({
  type: z.enum(POLICY_ACTION_TYPES),
  label: z.string(),
  phrase: z.string().describe('Lower-case verb phrase of a readable summary'),
  kind: z.enum(POLICY_ACTION_KINDS).describe('At most one `disposition` action per rule'),
  disposition: z.enum(POLICY_DISPOSITIONS).nullable(),
  params: z.array(PolicyActionParamSchema),
  description: z.string().describe('What the platform enforces, requests or records'),
});

export const PolicyCatalogSchema = z.strictObject({
  versions: z.strictObject({ dsl: z.string(), input: z.string(), evaluator: z.string() }),
  platformDefault: z.strictObject({ id: z.string(), description: z.string() }),
  fields: z.array(PolicyCatalogFieldSchema),
  operators: z.array(z.enum(POLICY_OPERATORS)),
  actions: z.array(z.enum(POLICY_ACTION_TYPES)),
  nonTerminalActions: z.array(z.enum(POLICY_NON_TERMINAL_ACTIONS)),
  dispositions: z.array(z.enum(POLICY_DISPOSITIONS)).describe('Weakest first'),
  limits: z
    .record(z.string(), z.number().int())
    .describe(
      'The DSL limits (P4) with the organization bounds of this deployment applied, plus ' +
        '(step 7.3) `dryRunSampleMax` (POLICY_DRY_RUN_SAMPLE_MAX) and `dryRunSamplesPerMinute` ' +
        '(POLICY_SAMPLE_DRY_RUNS_PER_MINUTE)',
    ),
  settingsDefaults: effectivePolicySettingsSchema,
  enforcement: z.string(),
  // Step 7.3 §4.1: presentation metadata for visual builders (ADR-0063).
  fieldGroups: z
    .array(z.strictObject({ id: z.enum(POLICY_FIELD_GROUP_IDS), label: z.string() }))
    .describe('Field groups in display order'),
  operatorDefinitions: z.array(PolicyOperatorDefinitionSchema).describe('One per operator'),
  actionDefinitions: z.array(PolicyActionDefinitionSchema).describe('One per action'),
  quantifiers: z
    .array(z.strictObject({ id: z.enum(QUANTIFIERS), label: z.string(), phrase: z.string() }))
    .describe('`any` (at least one list element) and `all` (every element)'),
  scopeNouns: z
    .strictObject({ recipients: z.string(), attachments: z.string(), urls: z.string() })
    .describe('Noun of one element of a list-scoped field'),
  contextRules: z
    .strictObject({
      defaultQuantifier: z.enum(QUANTIFIERS),
      exceptionQuantifier: z.enum(QUANTIFIERS),
      exceptionNegation: z.boolean(),
      relaxingDispositions: z.array(z.enum(POLICY_DISPOSITIONS)),
      holdDispositions: z.array(z.enum(POLICY_DISPOSITIONS)),
    })
    .describe(
      'Placement rules (P6, P9.8): the quantifier of a list condition without one; the only ' +
        'quantifier exceptions accept; whether exceptions may negate; dispositions whose `when` ' +
        'is relaxing (plus any `override: true` rule); dispositions that hold mail',
    ),
  weekdays: z.array(z.enum(WEEKDAYS)).describe('Days of `time.window`, Monday first'),
  timeZones: z
    .array(z.string())
    .describe(
      "IANA time zones of the api runtime (`Intl.supportedValuesOf('timeZone')` plus `UTC`, " +
        'sorted); the validator also accepts aliases the runtime resolves',
    ),
  policyDirections: z.array(z.enum(POLICY_DIRECTIONS)),
  messageDirections: z.array(z.enum(POLICY_MESSAGE_DIRECTIONS)),
});
export type PolicyCatalog = z.output<typeof PolicyCatalogSchema>;

// --------------------------------------------------------------------------------------------
// Test and dry-run
// --------------------------------------------------------------------------------------------

const TargetSchema = z.union([
  z.literal('active'),
  z.literal('platform'),
  z.strictObject({ policyId: z.uuid(), versionNo: VersionNo }),
  z.strictObject({ definition: DefinitionInput }),
]);
export type PolicyTarget = z.output<typeof TargetSchema>;
const TARGET_DOC =
  '`active`: the organization’s active policies now (replica); `platform`: the platform ' +
  'default alone (the tenant settings apply); `{ policyId, versionNo }`: the active policies ' +
  'with that version (draft or published) in place of the policy’s active version (added when ' +
  'the policy is not active); `{ definition }`: an unsaved definition, validated like a draft ' +
  '(`400 policy_definition_invalid`), added to the active policies as policy ' +
  '`00000000-0000-7000-8000-000000000000` version 1';

export const PolicyTestSchema = z.strictObject({
  target: TargetSchema.default('active').describe(TARGET_DOC),
  facts: syntheticFactsSchema
    .default({})
    .describe(
      'Synthetic facts (P23); every field optional with documented defaults; ' +
        '`evaluationTime` defaults to the request time; `resolveDirectory: true` resolves ' +
        'department and user memberships of the facts’ addresses from the directory',
    ),
});
export type PolicyTest = z.output<typeof PolicyTestSchema>;

export const PolicyDryRunSchema = z.strictObject({
  target: TargetSchema.default('active').describe(TARGET_DOC),
});
export type PolicyDryRun = z.output<typeof PolicyDryRunSchema>;

const InvalidVersionSchema = z.strictObject({
  policyId: z.string(),
  versionNo: z.number().int(),
  violations: z.array(ViolationSchema),
});

export const PolicyTestResponseSchema = z.strictObject({
  result: policyEvaluationResultSchema,
  recipientSplit: z
    .boolean()
    .describe(
      'Step 5.3 (Q4): true when the recipients were evaluated one by one and their dispositions ' +
        'differ (recipient-scoped rules, `recipientSplit` setting on, ≤ 200 recipients)',
    ),
  recipientDecisions: recipientDecisionsSchema.describe(
    'Per-recipient decisions (rcptSeq, disposition, source, decisive rule, ≤ 8 reason codes); ' +
      'empty when the message was not evaluated per recipient (no recipient-scoped rule, one ' +
      'recipient, setting off, truncated or too many recipients)',
  ),
  lifecycleDisposition: z
    .enum(POLICY_DISPOSITIONS)
    .describe(
      'The disposition the message as a whole receives (Q4.4, Q5): the strictest per-recipient ' +
        'disposition when uniform; with a split, the message follows its allowed recipients',
    ),
  invalidVersions: z
    .array(InvalidVersionSchema)
    .describe('Versions of the snapshot the current DSL no longer accepts (excluded)'),
});
export type PolicyTestResponse = z.output<typeof PolicyTestResponseSchema>;

export const PolicyDryRunResponseSchema = PolicyTestResponseSchema.extend({
  stored: policyEvaluationViewSchema
    .nullable()
    .describe('The stored evaluation of the round; null when none is stored (yet)'),
  reproducible: z
    .boolean()
    .describe(
      'Target `active` and the stored `inputSha256` and `versions.snapshotSha256` equal the ' +
        'recomputed ones (false without a stored evaluation, after a policy, settings or ' +
        'directory change, or when facts were added after the evaluation)',
    ),
});
export type PolicyDryRunResponse = z.output<typeof PolicyDryRunResponseSchema>;

// --------------------------------------------------------------------------------------------
// Policy builder (step 7.3 §4.2, §4.3): validation without persisting, sample dry-run
// --------------------------------------------------------------------------------------------

export const PolicyValidateSchema = z.strictObject({
  definition: DefinitionInput,
});
export type PolicyValidate = z.output<typeof PolicyValidateSchema>;

export const PolicyValidateResponseSchema = z.strictObject({
  dslVersion: z.literal(POLICY_DSL_VERSION),
  valid: z
    .boolean()
    .describe(
      'No DSL violation (the check a draft save runs); `referenceViolations` do not make a ' +
        'definition invalid (publish, activation and enable refuse them)',
    ),
  violations: z
    .array(ViolationSchema)
    .max(100)
    .describe('Every DSL violation by JSON path (sorted by path, at most 100)'),
  referenceViolations: z
    .array(ViolationSchema)
    .max(100)
    .describe(
      'Departments and users the definition references that are not the organization’s ' +
        '(`department_unknown`, `user_unknown`; read replica; at most 100); empty when the ' +
        'definition is invalid',
    ),
  ruleCount: z.number().int().min(1).nullable().describe('Null when invalid'),
  hasOverrideRules: z.boolean().nullable().describe('Null when invalid'),
  references: DirectoryReferencesSchema.nullable().describe(
    'Department and user public ids the definition references; null when invalid',
  ),
  definitionSha256: Sha256.nullable().describe(
    'SHA-256 of the canonical JSON (what a save stores); null when invalid',
  ),
});
export type PolicyValidateResponse = z.output<typeof PolicyValidateResponseSchema>;

/** Most rounds a sample dry-run may request (`POLICY_DRY_RUN_SAMPLE_MAX` lowers it). */
export const POLICY_SAMPLE_LIMIT_MAX = 200;
export const POLICY_SAMPLE_LIMIT_DEFAULT = 25;
/** The default sample window (`from` = `to` − 7 days, at most POLICY_HISTORY_MAX_RANGE_DAYS). */
export const POLICY_SAMPLE_DEFAULT_DAYS = 7;

export const PolicySampleDryRunSchema = z.strictObject({
  target: TargetSchema.default('active').describe(TARGET_DOC),
  sample: z
    .strictObject({
      from: IsoDate.optional().describe(
        'Inclusive lower bound of `receivedAt` (default: `to` − 7 days, at most ' +
          'POLICY_HISTORY_MAX_RANGE_DAYS)',
      ),
      to: IsoDate.optional().describe('Exclusive upper bound of `receivedAt` (default: now)'),
      direction: z.enum(POLICY_MESSAGE_DIRECTIONS).optional(),
      limit: z
        .number()
        .int()
        .min(1)
        .max(POLICY_SAMPLE_LIMIT_MAX)
        .optional()
        .describe(
          'Rounds to re-evaluate, newest first (1..POLICY_DRY_RUN_SAMPLE_MAX, a larger value is ' +
            '`400`; default 25, or POLICY_DRY_RUN_SAMPLE_MAX when that is lower)',
        ),
    })
    .default({})
    .describe('The window of stored evaluations to sample (default: the last 7 days, 25 rounds)'),
});
export type PolicySampleDryRun = z.output<typeof PolicySampleDryRunSchema>;

const DispositionCountsSchema = z.strictObject({
  allow: Count,
  require_approval: Count,
  quarantine: Count,
  reject: Count,
});

export const POLICY_SAMPLE_OUTCOMES = [
  'evaluated',
  'not_complete',
  'input_invalid',
  'not_found',
] as const;
export type PolicySampleOutcome = (typeof POLICY_SAMPLE_OUTCOMES)[number];

export const PolicySampleItemSchema = z.strictObject({
  messageId: z.uuid().nullable().describe('Message public id (null if the registry row is gone)'),
  receivedAt: IsoDate,
  direction: z.enum(POLICY_MESSAGE_DIRECTIONS),
  lifecycleRound: z.number().int().min(0),
  scanId: Decimal,
  trigger: z.enum(['scanned', 'scan_failed']),
  outcome: z
    .enum(POLICY_SAMPLE_OUTCOMES)
    .describe(
      '`evaluated`; `not_complete` (the round is pending or running on the replica); ' +
        '`input_invalid` (the stored rows do not form a policy input); `not_found` (the ' +
        'message or scan is gone)',
    ),
  stored: z
    .strictObject({
      disposition: z.enum(POLICY_DISPOSITIONS),
      source: z.enum(DECISION_SOURCES),
      policyId: z.uuid().nullable(),
      versionNo: VersionNo.nullable(),
      ruleId: z.string().nullable(),
      evaluatedAt: IsoDate,
    })
    .describe('The stored evaluation of the round (message-level decision)'),
  dryRun: z
    .strictObject({
      disposition: z.enum(POLICY_DISPOSITIONS),
      lifecycleDisposition: z.enum(POLICY_DISPOSITIONS),
      source: z.enum(DECISION_SOURCES),
      policyId: z.uuid().nullable(),
      versionNo: VersionNo.nullable(),
      ruleId: z.string().nullable(),
      matchedRuleCount: Count,
      actionTypes: z.array(z.enum(POLICY_ACTION_TYPES)),
      recipientSplit: z.boolean(),
      overrideApplied: z.boolean(),
    })
    .nullable()
    .describe('The recomputed decision against the target; null unless `evaluated`'),
  dispositionChanged: z
    .boolean()
    .describe('The stored and recomputed message-level dispositions differ'),
  decisiveChanged: z
    .boolean()
    .describe('The decisive source, policy or rule differs (false unless `evaluated`)'),
});
export type PolicySampleItem = z.output<typeof PolicySampleItemSchema>;

export const PolicySampleDryRunResponseSchema = z.strictObject({
  target: z
    .strictObject({
      kind: z.enum(['active', 'platform', 'version', 'inline']),
      policyId: z.uuid().nullable(),
      versionNo: VersionNo.nullable(),
    })
    .describe(
      '`inline` reports the synthetic id `00000000-0000-7000-8000-000000000000` version 1 the ' +
        'definition is evaluated as',
    ),
  window: z.strictObject({ from: IsoDate, to: IsoDate }),
  limit: z.number().int().min(1).max(POLICY_SAMPLE_LIMIT_MAX),
  evaluated: Count.describe('Items with outcome `evaluated`'),
  skipped: Count.describe('Items with another outcome'),
  truncated: z
    .boolean()
    .describe(
      'POLICY_DRY_RUN_DEADLINE_MS stopped the run before every selected round was evaluated ' +
        '(`items` holds the evaluated prefix)',
    ),
  exhausted: z
    .boolean()
    .describe(
      'The window held fewer stored rounds than `limit` (the bounded selection read all of it)',
    ),
  summary: z.strictObject({
    changed: Count.describe('Evaluated items whose disposition changed'),
    unchanged: Count,
    stored: DispositionCountsSchema.describe('Stored dispositions of the evaluated items'),
    dryRun: DispositionCountsSchema.describe('Recomputed dispositions of the evaluated items'),
    transitions: z
      .array(
        z.strictObject({
          from: z.enum(POLICY_DISPOSITIONS),
          to: z.enum(POLICY_DISPOSITIONS),
          count: z.number().int().min(1),
        }),
      )
      .describe('Stored → recomputed disposition changes, most frequent first'),
  }),
  items: z
    .array(PolicySampleItemSchema)
    .describe('The processed rounds, newest first (one per message, at most `limit`)'),
  invalidVersions: z
    .array(InvalidVersionSchema)
    .describe('Versions of the snapshot the current DSL no longer accepts (excluded)'),
});
export type PolicySampleDryRunResponse = z.output<typeof PolicySampleDryRunResponseSchema>;

// --------------------------------------------------------------------------------------------
// Execution history and evaluations of a message
// --------------------------------------------------------------------------------------------

const booleanQuery = z
  .enum(['true', 'false'])
  .transform((v) => v === 'true')
  .optional();

export const PolicyExecutionQuerySchema = z
  .strictObject({
    from: IsoDate.describe('Inclusive lower bound of `receivedAt` (required)'),
    to: IsoDate.describe(
      'Exclusive upper bound of `receivedAt` (required; ≤ POLICY_HISTORY_MAX_RANGE_DAYS after from)',
    ),
    direction: z.enum(POLICY_MESSAGE_DIRECTIONS).optional(),
    disposition: z.enum(POLICY_DISPOSITIONS).optional(),
    source: z.enum(DECISION_SOURCES).optional().describe('Decision source'),
    policyId: z.uuid().optional().describe('Decisive policy'),
    ruleId: z.string().regex(RULE_ID).optional().describe('Decisive rule id'),
    overrideApplied: booleanQuery,
    trigger: z.enum(POLICY_TRIGGERS).optional(),
    limit: z.coerce.number().int().min(1).max(100).default(25),
    cursor: z.string().min(1).max(96).optional(),
  })
  .refine((q) => Date.parse(q.from) < Date.parse(q.to), {
    message: 'from must be before to',
    path: ['to'],
  });
export type PolicyExecutionQuery = z.output<typeof PolicyExecutionQuerySchema>;
export const PolicyExecutionQueryDocSchema = z.strictObject({
  from: IsoDate,
  to: IsoDate,
  direction: z.enum(POLICY_MESSAGE_DIRECTIONS).optional(),
  disposition: z.enum(POLICY_DISPOSITIONS).optional(),
  source: z.enum(DECISION_SOURCES).optional(),
  policyId: z.uuid().optional(),
  ruleId: z.string().optional(),
  overrideApplied: z.enum(['true', 'false']).optional(),
  trigger: z.enum(POLICY_TRIGGERS).optional(),
  limit: z.number().int().min(1).max(100).optional(),
  cursor: z.string().optional(),
});

export const PolicyExecutionSchema = z.strictObject({
  messageId: z.uuid().nullable().describe('Message public id (null if the registry row is gone)'),
  receivedAt: IsoDate,
  lifecycleRound: z.number().int().min(0),
  scanId: Decimal.nullable(),
  trigger: z.enum(POLICY_TRIGGERS),
  direction: z.enum(POLICY_MESSAGE_DIRECTIONS),
  disposition: z.enum(POLICY_DISPOSITIONS),
  finalAction: z.enum(POLICY_FINAL_ACTIONS),
  decisive: z.strictObject({
    source: z.enum(DECISION_SOURCES),
    policyId: z.uuid().nullable(),
    versionNo: VersionNo.nullable(),
    ruleId: z.string().nullable(),
  }),
  actions: z.array(
    z.strictObject({ type: z.enum(POLICY_ACTION_TYPES), status: z.enum(ACTION_STATUSES) }),
  ),
  matchedRuleCount: z.number().int().min(0),
  overrideApplied: z.boolean(),
  generation: Decimal,
  inputSha256: Sha256,
  durationUs: z.number().int().min(0),
  evaluatedAt: IsoDate,
});
export type PolicyExecution = z.output<typeof PolicyExecutionSchema>;

export const PolicyExecutionPageSchema = z.strictObject({
  data: z.array(PolicyExecutionSchema).describe('Newest `receivedAt` first'),
  nextCursor: z.string().nullable(),
});
export type PolicyExecutionPage = z.output<typeof PolicyExecutionPageSchema>;

export const MessagePolicyEvaluationsSchema = z.strictObject({
  messageId: z.uuid(),
  data: z
    .array(policyEvaluationViewSchema)
    .describe('Every stored evaluation of the message, newest round first'),
});
export type MessagePolicyEvaluations = z.output<typeof MessagePolicyEvaluationsSchema>;
