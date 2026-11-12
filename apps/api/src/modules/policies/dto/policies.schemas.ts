import {
  ACTION_STATUSES,
  DECISION_SOURCES,
  effectivePolicySettingsSchema,
  POLICY_ACTION_TYPES,
  POLICY_DIRECTIONS,
  POLICY_DISPOSITIONS,
  POLICY_FIELD_SCOPES,
  POLICY_FIELD_TYPES,
  POLICY_FINAL_ACTIONS,
  POLICY_MESSAGE_DIRECTIONS,
  POLICY_NON_TERMINAL_ACTIONS,
  POLICY_OPERATORS,
  POLICY_TRIGGERS,
  policyEvaluationResultSchema,
  recipientDecisionsSchema,
  policyEvaluationViewSchema,
  policyTenantSettingsSchema,
  syntheticFactsSchema,
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
    .describe('The DSL limits (P4) with the organization bounds of this deployment applied'),
  settingsDefaults: effectivePolicySettingsSchema,
  enforcement: z.string(),
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
