import { RISK_ACTIONS, RISK_VERDICTS } from '@email-gateway/risk-scoring';
import { REASON_CODE_PATTERN, REWRITE_SKIP_REASONS } from '@email-gateway/security-contracts';
import { z } from 'zod';
import { POLICY_FIELD_NAMES, POLICY_OPERATORS } from './fields';
import { POLICY_FLOOR_CODES } from './reason-codes';
import {
  ACTION_APPLICABILITIES,
  ACTION_ORIGINS,
  ACTION_STATUSES,
  BODY_BANNER_STATUSES,
  POLICY_ACTION_TYPES,
  POLICY_DELIVERED_OBJECTS,
  POLICY_DISPOSITIONS,
  POLICY_DSL_VERSION,
  POLICY_EVALUATOR_VERSIONS,
  POLICY_FINAL_ACTIONS,
  POLICY_INPUT_VERSION,
  POLICY_LIMITS,
  POLICY_MESSAGE_DIRECTIONS,
  POLICY_TAG_HEADER,
  POLICY_TRIGGERS,
  POLICY_WARNING_HEADER,
  type ActionStatus,
  type PolicyDeliveredObject,
  type PolicyFinalAction,
} from './vocabulary';

/**
 * `PolicyEvaluationResult` (step 5.2 P10): what `evaluatePolicy` returns and what a
 * `policy_execution_logs` row stores, with the one row ↔ result mapping
 * (`evaluationResultToRow` / `rowToEvaluationView`) the policy-engine writes and the api reads.
 * Ids, codes, enums, integers, hashes and policy data only: never message content.
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const RULE_ID = /^[a-z0-9][a-z0-9_-]{0,47}$/;
export const RULE_REF_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}#[0-9]{1,9}\/[a-z0-9][a-z0-9_-]{0,47}$/;

const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);
const decimalSchema = z.string().regex(/^[0-9]{1,20}$/);
const codeSchema = z.string().max(64).regex(REASON_CODE_PATTERN);
const refSchema = z.string().max(96).regex(RULE_REF_PATTERN);
const dispositionSchema = z.enum(POLICY_DISPOSITIONS);
const versionNoSchema = z.number().int().min(1).max(999_999_999);

export const EXPLANATION_LINE_CODES = [
  'summary',
  'decisive_rule',
  'platform_default',
  'floor',
  'override',
  'clamp',
  'exception',
  'action',
  'not_applicable',
  'snapshot',
  /** Step 5.3 Q4: per-recipient counts `{ allowed, held, review, rejected }` (never addresses). */
  'split',
] as const;
export type ExplanationLineCode = (typeof EXPLANATION_LINE_CODES)[number];

/** Parameter values: integers or bounded tokens (ids, refs, enums, codes); never content. */
export const explanationParamSchema = z.union([
  z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  z
    .string()
    .max(96)
    .regex(/^[A-Za-z0-9_/+#:,.[\]-]*$/),
]);

export const explanationLineSchema = z.strictObject({
  code: z.enum(EXPLANATION_LINE_CODES),
  params: z.record(z.string().regex(/^[a-zA-Z]{1,32}$/), explanationParamSchema),
});
export type ExplanationLine = z.infer<typeof explanationLineSchema>;

const actionParamSchema = z.union([
  z.string().max(128),
  z.number().int(),
  z.boolean(),
  z.null(),
  z.array(z.string().max(64)).max(POLICY_LIMITS.tagLabels),
]);

export const resultActionSchema = z.strictObject({
  type: z.enum(POLICY_ACTION_TYPES),
  params: z.record(z.string().regex(/^[a-zA-Z]{1,32}$/), actionParamSchema),
  origin: z.enum(ACTION_ORIGINS),
  ruleRefs: z.array(refSchema).max(POLICY_LIMITS.ruleRefsPerAction),
  applicability: z.enum(ACTION_APPLICABILITIES),
});
export type ResultAction = z.infer<typeof resultActionSchema>;

export const TRACE_RESULTS = [
  'matched',
  'not_matched',
  'unknown',
  'excepted',
  'not_evaluated',
] as const;
export type TraceResult = (typeof TRACE_RESULTS)[number];

export const CLAMP_REASONS = [
  'override_not_allowed',
  'override_disabled',
  'not_level_only',
  'ai_only',
] as const;
export type ClampReason = (typeof CLAMP_REASONS)[number];

/** The policy-engine's own URL rewrite of the copy (step 5.3 Q23; set by the engine, not the evaluator). */
export const policyUrlRewriteAttemptSchema = z.strictObject({
  status: z.enum(['rewritten', 'skipped']),
  skipReason: z.enum(REWRITE_SKIP_REASONS).nullable(),
});
export type PolicyUrlRewriteAttempt = z.infer<typeof policyUrlRewriteAttemptSchema>;

const deliverySchema = z.strictObject({
  headers: z
    .array(
      z.strictObject({
        name: z.enum([POLICY_TAG_HEADER, POLICY_WARNING_HEADER]),
        value: z
          .string()
          .min(1)
          .max(512)
          .regex(/^[\x20-\x7e]+$/),
      }),
    )
    .max(2),
  subjectPrefix: z.string().min(1).max(32).nullable(),
  /**
   * Step 5.3 Q22: `requested` (evaluator, WARN applies), the engine's outcome (`applied`,
   * `skipped_*`) or `not_supported` (5.2 rows); null without WARN.
   */
  bodyBanner: z.enum(BODY_BANNER_STATUSES).nullable(),
  urlRewrite: z.strictObject({
    required: z.boolean(),
    rewritten: z.boolean(),
    skipReason: z.enum(REWRITE_SKIP_REASONS).nullable(),
    /**
     * Step 5.3 Q23: the round was skipped only because the tenant's 4.3 setting was off
     * (`disabled`, `direction`), so the policy-engine may rewrite the copy itself.
     */
    policyRewritable: z.boolean(),
    /** Step 5.3 Q23: the engine's own rewrite of the copy (absent/null until the engine sets it). */
    policyAttempt: policyUrlRewriteAttemptSchema.nullable().optional(),
  }),
});
export type PolicyDelivery = z.infer<typeof deliverySchema>;

const policyVersionRefSchema = z.strictObject({
  policyPublicId: z.string().regex(UUID),
  versionNo: versionNoSchema,
  definitionSha256: sha256Schema,
});

export const policyEvaluationResultSchema = z.strictObject({
  status: z.literal('evaluated'),
  round: z.strictObject({
    trigger: z.enum(POLICY_TRIGGERS),
    direction: z.enum(POLICY_MESSAGE_DIRECTIONS),
    lifecycleRound: z.number().int().min(0).max(65_535),
    scanId: decimalSchema.nullable(),
  }),
  disposition: dispositionSchema,
  finalVerdict: z.enum(RISK_VERDICTS),
  riskScore: z.number().int().min(0).max(1000).nullable(),
  decisive: z.strictObject({
    source: z.enum(ACTION_ORIGINS),
    policyPublicId: z.string().regex(UUID).nullable(),
    versionNo: versionNoSchema.nullable(),
    ruleId: z.string().regex(RULE_ID).nullable(),
    reason: codeSchema,
  }),
  actions: z.array(resultActionSchema).max(POLICY_LIMITS.actions),
  delivery: deliverySchema.nullable(),
  notices: z.strictObject({ senderNonDelivery: z.boolean() }),
  matchedRules: z
    .array(
      z.strictObject({
        ref: refSchema,
        policyPublicId: z.string().regex(UUID),
        versionNo: versionNoSchema,
        ruleId: z.string().regex(RULE_ID),
        disposition: dispositionSchema.nullable(),
        actionTypes: z.array(z.enum(POLICY_ACTION_TYPES)).max(POLICY_LIMITS.actionsPerRule),
        override: z.boolean(),
      }),
    )
    .max(POLICY_LIMITS.matchedRules),
  trace: z
    .array(
      z.strictObject({
        ref: refSchema,
        result: z.enum(TRACE_RESULTS),
        at: z
          .string()
          .regex(/^(when|unless\[[0-9]\]|policy_exception\[[0-9]\])$/)
          .nullable(),
        path: z.string().max(256).nullable(),
        field: z.enum(POLICY_FIELD_NAMES).nullable(),
        op: z.enum(POLICY_OPERATORS).nullable(),
      }),
    )
    .max(POLICY_LIMITS.trace),
  traceTruncated: z.boolean(),
  floor: z.strictObject({
    disposition: dispositionSchema.nullable(),
    tag: z.boolean(),
    reasons: z.array(z.enum(POLICY_FLOOR_CODES)).max(POLICY_FLOOR_CODES.length),
  }),
  recommendation: z.strictObject({
    disposition: dispositionSchema,
    tag: z.boolean(),
    levelOnly: z.boolean(),
    riskAction: z.enum(RISK_ACTIONS).nullable(),
    revisions: z.array(z.union([z.literal(0), z.literal(1)])).max(2),
  }),
  override: z
    .strictObject({
      applied: z.literal(true),
      ref: refSchema,
      from: dispositionSchema,
      to: dispositionSchema,
    })
    .nullable(),
  clamps: z
    .array(
      z.strictObject({
        ref: refSchema,
        from: dispositionSchema,
        to: dispositionSchema,
        reason: z.enum(CLAMP_REASONS),
      }),
    )
    .max(POLICY_LIMITS.clamps),
  /** Ordered; `reasonCodes[0]` is always `decisive.reason`. */
  reasonCodes: z.array(codeSchema).min(1).max(POLICY_LIMITS.reasonCodes),
  explanation: z.strictObject({
    lines: z.array(explanationLineSchema).max(POLICY_LIMITS.explanationLines),
    text: z.string().max(POLICY_LIMITS.explanationText),
  }),
  versions: z.strictObject({
    dsl: z.literal(POLICY_DSL_VERSION),
    /** The evaluator always writes `POLICY_EVALUATOR_VERSION`; stored 5.2 rows hold `policy-eval/1`. */
    evaluator: z.enum(POLICY_EVALUATOR_VERSIONS),
    input: z.literal(POLICY_INPUT_VERSION),
    platformDefault: z.string().min(1).max(32),
    snapshotSha256: sha256Schema,
    generation: decimalSchema,
    tzdata: z.string().min(1).max(16),
    policies: z.array(policyVersionRefSchema).max(POLICY_LIMITS.activePoliciesPerOrganization),
  }),
  inputSha256: sha256Schema,
});
export type PolicyEvaluationResult = z.infer<typeof policyEvaluationResultSchema>;

// ---------------------------------------------------------------------------------------------
// Action statuses (P19)
// ---------------------------------------------------------------------------------------------

/**
 * The statuses the engine stores when every planned effect succeeds (P19): dispositions
 * `enforced`; TAG/WARN `enforced` when they write a header or the subject prefix into the
 * delivered policy copy, `recorded` when nothing is written (headers suppressed or disabled),
 * `not_applicable` when not delivered; URL_REWRITE `enforced` (rewritten copy or quarantine
 * raise) or `recorded`; ARCHIVE `requested`; ALERT `requested` (`recorded` when alerts are
 * disabled). The engine replaces TAG/WARN `enforced` by `recorded` when the copy is refused
 * (deterministic size limits), and never reports `enforced` for an effect it did not perform.
 */
export function intendedActionStatuses(result: PolicyEvaluationResult): ActionStatus[] {
  const prefix = result.delivery?.subjectPrefix ?? null;
  return result.actions.map((a): ActionStatus => {
    if (a.applicability === 'not_applicable') return 'not_applicable';
    switch (a.type) {
      case 'ALLOW':
      case 'QUARANTINE':
      case 'REQUIRE_APPROVAL':
      case 'REJECT':
        return 'enforced';
      case 'TAG': {
        const header = Array.isArray(a.params.headerLabels) && a.params.headerLabels.length > 0;
        const ownPrefix = a.params.subjectPrefix !== null && a.params.subjectPrefix === prefix;
        return header || ownPrefix ? 'enforced' : 'recorded';
      }
      case 'WARN':
        return 'enforced';
      case 'URL_REWRITE':
        return a.params.raised === true ||
          result.delivery?.urlRewrite.rewritten === true ||
          result.delivery?.urlRewrite.policyAttempt?.status === 'rewritten'
          ? 'enforced'
          : 'recorded';
      case 'ARCHIVE':
        return 'requested';
      case 'ALERT':
        return a.params.notify === true ? 'requested' : 'recorded';
      default:
        return 'recorded';
    }
  });
}

// ---------------------------------------------------------------------------------------------
// Lifecycle mapping (P18)
// ---------------------------------------------------------------------------------------------

export interface LifecycleOutcome {
  edge: 'E10' | 'E11' | 'E12' | 'E13';
  to: 'approved' | 'quarantined' | 'held_for_review' | 'rejected';
  reason:
    | 'policy_deliver'
    | 'policy_tag'
    | 'policy_quarantine'
    | 'policy_hold'
    | 'policy_reject'
    | 'policy_discard';
  finalAction: PolicyFinalAction;
}

/** P18: the disposition edge, its reason and `email_messages.final_action`. */
export function lifecycleOutcome(
  result: Pick<PolicyEvaluationResult, 'disposition' | 'actions'>,
  direction: 'inbound' | 'outbound' | 'internal',
): LifecycleOutcome {
  switch (result.disposition) {
    case 'allow': {
      const tagged = result.actions.some(
        (a) => (a.type === 'TAG' || a.type === 'WARN') && a.applicability === 'applies',
      );
      return tagged
        ? { edge: 'E10', to: 'approved', reason: 'policy_tag', finalAction: 'tag' }
        : { edge: 'E10', to: 'approved', reason: 'policy_deliver', finalAction: 'deliver' };
    }
    case 'quarantine':
      return {
        edge: 'E11',
        to: 'quarantined',
        reason: 'policy_quarantine',
        finalAction: 'quarantine',
      };
    case 'require_approval':
      return {
        edge: 'E12',
        to: 'held_for_review',
        reason: 'policy_hold',
        finalAction: 'require_approval',
      };
    case 'reject':
      return direction === 'inbound'
        ? { edge: 'E13', to: 'rejected', reason: 'policy_discard', finalAction: 'discard' }
        : { edge: 'E13', to: 'rejected', reason: 'policy_reject', finalAction: 'reject' };
  }
}

// ---------------------------------------------------------------------------------------------
// Row mapping (§3 policy_execution_logs)
// ---------------------------------------------------------------------------------------------

export type StoredAction = ResultAction & { status: ActionStatus };

/**
 * The `policy_execution_logs` columns that come from the result (§3). Plain values; decimal ids
 * as strings (the caller converts to BigInt for Prisma). `id`, `message_id`, `organization_id`,
 * `received_at`, `duration_us`, `evaluated_at`, `created_at` come from the engine.
 */
export interface PolicyEvaluationRowJson {
  evaluationSeq: number;
  scanId: string | null;
  trigger: PolicyEvaluationResult['round']['trigger'];
  direction: PolicyEvaluationResult['round']['direction'];
  disposition: PolicyEvaluationResult['disposition'];
  decisionSource: PolicyEvaluationResult['decisive']['source'];
  decisivePolicyVersionId: string | null;
  decisivePolicyPublicId: string | null;
  decisiveRuleId: string | null;
  action: PolicyFinalAction;
  finalVerdict: PolicyEvaluationResult['finalVerdict'];
  riskScore: number | null;
  overrideApplied: boolean;
  matchedPolicyVersionIds: string[];
  actions: StoredAction[];
  matchedRules: PolicyEvaluationResult['matchedRules'];
  trace: { entries: PolicyEvaluationResult['trace']; truncated: boolean };
  floor: PolicyEvaluationResult['floor'];
  recommendation: PolicyEvaluationResult['recommendation'];
  overrideDetail: PolicyEvaluationResult['override'];
  clamps: PolicyEvaluationResult['clamps'];
  reasonCodes: string[];
  delivery: PolicyEvaluationResult['delivery'];
  deliveredObject: PolicyDeliveredObject;
  objectKey: string | null;
  explanation: ExplanationLine[];
  explanationText: string;
  policyGeneration: string;
  snapshotSha256: string;
  policyVersions: PolicyEvaluationResult['versions']['policies'];
  platformDefaultId: string;
  dslVersion: string;
  evaluatorVersion: string;
  inputVersion: string;
  inputSha256: string;
  tzdataVersion: string;
}

/** What the engine actually did (P19–P21); every field optional (defaults: as intended). */
export interface AppliedEffects {
  /** One status per result action (default `intendedActionStatuses(result)`). */
  actionStatuses?: readonly ActionStatus[];
  /** Default: `original` for allow, else `none`. */
  deliveredObject?: PolicyDeliveredObject;
  /** The policy copy key (`org/<org>/policy/…`) when `deliveredObject = policy_copy`. */
  objectKey?: string | null;
  /** Internal `policy_versions.id` (decimal) by `<policyPublicId>#<versionNo>`. */
  policyVersionIds?: Readonly<Record<string, string>>;
}

const versionKey = (publicId: string, versionNo: number) => `${publicId}#${versionNo}`;

/** Result (+ what the engine applied) → the row columns it owns (§3). Validates the result. */
export function evaluationResultToRow(
  result: PolicyEvaluationResult,
  applied: AppliedEffects = {},
): PolicyEvaluationRowJson {
  const r = policyEvaluationResultSchema.parse(result);
  const statuses = applied.actionStatuses ?? intendedActionStatuses(r);
  if (statuses.length !== r.actions.length) {
    throw new RangeError('actionStatuses must have one status per action');
  }
  const ids = applied.policyVersionIds ?? {};
  const decisiveId =
    r.decisive.policyPublicId !== null && r.decisive.versionNo !== null
      ? (ids[versionKey(r.decisive.policyPublicId, r.decisive.versionNo)] ?? null)
      : null;
  const matchedIds = [
    ...new Set(
      r.matchedRules
        .map((m) => ids[versionKey(m.policyPublicId, m.versionNo)])
        .filter((x): x is string => typeof x === 'string'),
    ),
  ].sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0));
  const deliveredObject =
    applied.deliveredObject ?? (r.disposition === 'allow' ? 'original' : 'none');
  return {
    evaluationSeq: r.round.lifecycleRound,
    scanId: r.round.scanId,
    trigger: r.round.trigger,
    direction: r.round.direction,
    disposition: r.disposition,
    decisionSource: r.decisive.source,
    decisivePolicyVersionId: decisiveId,
    decisivePolicyPublicId: r.decisive.policyPublicId,
    decisiveRuleId: r.decisive.ruleId,
    action: lifecycleOutcome(r, r.round.direction).finalAction,
    finalVerdict: r.finalVerdict,
    riskScore: r.riskScore,
    overrideApplied: r.override !== null,
    matchedPolicyVersionIds: matchedIds,
    actions: r.actions.map((a, i) => ({ ...a, status: statuses[i]! })),
    matchedRules: r.matchedRules,
    trace: { entries: r.trace, truncated: r.traceTruncated },
    floor: r.floor,
    recommendation: r.recommendation,
    overrideDetail: r.override,
    clamps: r.clamps,
    reasonCodes: r.reasonCodes,
    delivery: r.delivery,
    deliveredObject,
    objectKey: deliveredObject === 'policy_copy' ? (applied.objectKey ?? null) : null,
    explanation: r.explanation.lines,
    explanationText: r.explanation.text,
    policyGeneration: r.versions.generation,
    snapshotSha256: r.versions.snapshotSha256,
    policyVersions: r.versions.policies,
    platformDefaultId: r.versions.platformDefault,
    dslVersion: r.versions.dsl,
    evaluatorVersion: r.versions.evaluator,
    inputVersion: r.versions.input,
    inputSha256: r.inputSha256,
    tzdataVersion: r.versions.tzdata,
  };
}

// ---------------------------------------------------------------------------------------------
// Per-recipient decisions (step 5.3 Q4.6; `policy_execution_logs.recipient_decisions`)
// ---------------------------------------------------------------------------------------------

/** One recipient's decision when the message was evaluated per recipient (Q4.6). */
export const recipientDecisionSchema = z.strictObject({
  rcptSeq: z.number().int().min(0).max(65_535),
  disposition: dispositionSchema,
  source: z.enum(ACTION_ORIGINS),
  decisiveRuleRef: refSchema.nullable(),
  /** The recipient result's first reason codes (decisive first), at most 8. */
  reasonCodes: z.array(codeSchema).min(1).max(POLICY_LIMITS.recipientDecisionReasonCodes),
});
export type RecipientDecision = z.infer<typeof recipientDecisionSchema>;

export const recipientDecisionsSchema = z
  .array(recipientDecisionSchema)
  .max(POLICY_LIMITS.splitRecipients)
  .refine(
    (list) => list.every((d, i) => i === 0 || list[i - 1]!.rcptSeq < d.rcptSeq),
    'Expected ascending, unique rcptSeq',
  );

/** The api view of a stored evaluation (P10, P16): the result plus round and engine facts. */
export const policyEvaluationViewSchema = policyEvaluationResultSchema.extend({
  lifecycleRound: z.number().int().min(0).max(65_535),
  trigger: z.enum(POLICY_TRIGGERS),
  direction: z.enum(POLICY_MESSAGE_DIRECTIONS),
  finalAction: z.enum(POLICY_FINAL_ACTIONS),
  actionStatuses: z.array(z.enum(ACTION_STATUSES)).max(POLICY_LIMITS.actions),
  deliveredObject: z.enum(POLICY_DELIVERED_OBJECTS),
  evaluatedAt: z.iso.datetime({ offset: false }),
  durationUs: z.number().int().min(0),
  /** Step 5.3 Q4: the recipients were decided differently (false for 5.2 rows). */
  recipientSplit: z.boolean(),
  /** Step 5.3 Q4.6: per-recipient decisions when evaluated per recipient, else null (5.2 rows). */
  recipientDecisions: recipientDecisionsSchema.nullable(),
});
export type PolicyEvaluationView = z.infer<typeof policyEvaluationViewSchema>;

/**
 * A stored row as read (JSON columns as plain values, ids as bigint or string). The 5.3 columns
 * `recipient_split` / `recipient_decisions` are optional (a caller that does not select them, or
 * a 5.2 row with NULL, reads as "not split").
 */
export type PolicyEvaluationRowRead = { [K in keyof PolicyEvaluationRowJson]: unknown } & {
  durationUs: unknown;
  evaluatedAt: Date | string;
  recipientSplit?: unknown;
  recipientDecisions?: unknown;
};

/** 5.2 rows lack `delivery.urlRewrite.policyRewritable` (no policy rewriting existed): false. */
function normalizeStoredDelivery(delivery: unknown): unknown {
  if (delivery === null || typeof delivery !== 'object') return delivery;
  const d = delivery as Record<string, unknown>;
  const rw = d.urlRewrite;
  if (rw === null || typeof rw !== 'object' || 'policyRewritable' in rw) return delivery;
  return { ...d, urlRewrite: { ...(rw as Record<string, unknown>), policyRewritable: false } };
}

const idText = (v: unknown): unknown =>
  typeof v === 'bigint' ? v.toString() : typeof v === 'number' ? String(v) : v;

/**
 * Stored row → api view (the inverse of `evaluationResultToRow`). Reads only the listed columns
 * (internal ids such as `decisive_policy_version_id` never reach the view) and validates.
 */
export function rowToEvaluationView(row: PolicyEvaluationRowRead): PolicyEvaluationView {
  const actions = Array.isArray(row.actions) ? (row.actions as Array<Record<string, unknown>>) : [];
  const trace = (row.trace ?? {}) as { entries?: unknown; truncated?: unknown };
  const policies = Array.isArray(row.policyVersions)
    ? (row.policyVersions as Array<{ policyPublicId?: unknown; versionNo?: unknown }>)
    : [];
  const decisiveVersion =
    row.decisivePolicyPublicId === null
      ? null
      : (policies.find((p) => p.policyPublicId === row.decisivePolicyPublicId)?.versionNo ?? null);
  const reasonCodes = Array.isArray(row.reasonCodes) ? (row.reasonCodes as unknown[]) : [];
  const reject = actions.find((a) => a.type === 'REJECT');
  const evaluatedAt =
    row.evaluatedAt instanceof Date ? row.evaluatedAt.toISOString() : row.evaluatedAt;
  return policyEvaluationViewSchema.parse({
    status: 'evaluated',
    round: {
      trigger: row.trigger,
      direction: row.direction,
      lifecycleRound: row.evaluationSeq,
      scanId: row.scanId === null ? null : idText(row.scanId),
    },
    disposition: row.disposition,
    finalVerdict: row.finalVerdict,
    riskScore: row.riskScore,
    decisive: {
      source: row.decisionSource,
      policyPublicId: row.decisivePolicyPublicId,
      versionNo: decisiveVersion,
      ruleId: row.decisiveRuleId,
      reason: reasonCodes[0],
    },
    actions: actions.map(({ status: _status, ...rest }) => rest),
    delivery: normalizeStoredDelivery(row.delivery),
    notices: {
      senderNonDelivery:
        reject !== undefined &&
        (reject.params as Record<string, unknown> | undefined)?.notifySender === true,
    },
    matchedRules: row.matchedRules,
    trace: trace.entries,
    traceTruncated: trace.truncated,
    floor: row.floor,
    recommendation: row.recommendation,
    override: row.overrideDetail,
    clamps: row.clamps,
    reasonCodes: row.reasonCodes,
    explanation: { lines: row.explanation, text: row.explanationText },
    versions: {
      dsl: row.dslVersion,
      evaluator: row.evaluatorVersion,
      input: row.inputVersion,
      platformDefault: row.platformDefaultId,
      snapshotSha256: row.snapshotSha256,
      generation: idText(row.policyGeneration),
      tzdata: row.tzdataVersion,
      policies: row.policyVersions,
    },
    inputSha256: row.inputSha256,
    lifecycleRound: row.evaluationSeq,
    trigger: row.trigger,
    direction: row.direction,
    finalAction: row.action,
    actionStatuses: actions.map((a) => a.status),
    deliveredObject: row.deliveredObject,
    evaluatedAt,
    durationUs: row.durationUs,
    recipientSplit:
      row.recipientSplit === undefined || row.recipientSplit === null
        ? false
        : row.recipientSplit === 1
          ? true
          : row.recipientSplit === 0
            ? false
            : row.recipientSplit,
    recipientDecisions: row.recipientDecisions ?? null,
  });
}
