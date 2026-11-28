/**
 * The policy lane of API-mode remediation (step API-4, design note 38 A4, A5, A8.1; ADR-0105).
 * Pure: the facts of a detect-mode policy evaluation the decision reads (`PolicyOutcomeFacts`),
 * the document-level `policyMapping` of `api-remediation-policy/1` (disposition → mailbox action),
 * what each policy action means after delivery (`POST_DELIVERY_ACTION_MAP`) and the detection
 * classification of a copy message. String unions mirror the `policy-dsl` vocabularies (this
 * package does not depend on it); unit tests pin every list.
 */
import { z } from 'zod';
import type { MailboxQuarantineReason } from './provider-actions';
import type { ApiCopyRecordDirection, MessageVerdict, RemediationAction } from './vocabulary';

// ---------------------------------------------------------------------------------------------
// Policy vocabularies (mirrors of `@email-gateway/policy-dsl`)
// ---------------------------------------------------------------------------------------------

/** `PolicyDisposition` (5.2), weakest first. */
export const POLICY_OUTCOME_DISPOSITIONS = [
  'allow',
  'require_approval',
  'quarantine',
  'reject',
] as const;
export type PolicyOutcomeDisposition = (typeof POLICY_OUTCOME_DISPOSITIONS)[number];

/** `PolicyDecisionSource` (5.2). */
export const POLICY_OUTCOME_DECISION_SOURCES = [
  'tenant_rule',
  'platform_default',
  'floor',
] as const;
export type PolicyOutcomeDecisionSource = (typeof POLICY_OUTCOME_DECISION_SOURCES)[number];

/** `POLICY_ACTION_TYPES` of `policy-dsl/1`. */
export const POLICY_OUTCOME_ACTION_TYPES = [
  'ALLOW',
  'REJECT',
  'QUARANTINE',
  'TAG',
  'WARN',
  'REQUIRE_APPROVAL',
  'URL_REWRITE',
  'ARCHIVE',
  'ALERT',
] as const;
export type PolicyOutcomeActionType = (typeof POLICY_OUTCOME_ACTION_TYPES)[number];

/** `DlpAction` (5.1 / security-contracts `DLP_ACTIONS`). */
export const POLICY_OUTCOME_DLP_ACTIONS = [
  'allow',
  'alert',
  'require_approval',
  'quarantine',
  'block',
] as const;
export type PolicyOutcomeDlpAction = (typeof POLICY_OUTCOME_DLP_ACTIONS)[number];

/** Stored action statuses of `policy_execution_logs.actions` (ADR-0045). */
export const POLICY_ACTION_STATUSES = [
  'enforced',
  'requested',
  'recorded',
  'not_applicable',
] as const;
export type PolicyActionStatus = (typeof POLICY_ACTION_STATUSES)[number];

/** Most floor reasons carried by `PolicyOutcomeFacts` (A4.1). */
export const POLICY_OUTCOME_MAX_FLOOR_REASONS = 8;

const unique = <T>(values: readonly T[]): boolean => new Set(values).size === values.length;
/** `<policyPublicId>#<versionNo>/<ruleId>` (the 5.2 rule reference, `RULE_REF_PATTERN`). */
export const POLICY_RULE_REF_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}#[0-9]{1,9}\/[a-z0-9][a-z0-9_-]{0,47}$/;
const FLOOR_REASON = /^policy\.floor\.[a-z0-9_]{1,48}$/;

/**
 * The facts of a detect-mode policy evaluation that the remediation decision reads (A4.1),
 * built by `policyOutcomeOf` of `@email-gateway/policy-runtime`.
 */
export const policyOutcomeFactsSchema = z.strictObject({
  disposition: z.enum(POLICY_OUTCOME_DISPOSITIONS),
  /** TAG or WARN applies with disposition `allow`. */
  tagged: z.boolean(),
  /** The P9 step 6 tenant override of the recommendation applied. */
  overrideApplied: z.boolean(),
  decisionSource: z.enum(POLICY_OUTCOME_DECISION_SOURCES),
  decisiveRuleRef: z.string().max(96).regex(POLICY_RULE_REF_PATTERN).nullable(),
  floorReasons: z
    .array(z.string().regex(FLOOR_REASON))
    .max(POLICY_OUTCOME_MAX_FLOOR_REASONS)
    .refine(unique, { message: 'duplicate_floor_reasons' }),
  dlpAction: z.enum(POLICY_OUTCOME_DLP_ACTIONS).nullable(),
  actionTypes: z
    .array(z.enum(POLICY_OUTCOME_ACTION_TYPES))
    .max(POLICY_OUTCOME_ACTION_TYPES.length)
    .refine(unique, { message: 'duplicate_action_types' }),
  /**
   * A4.3 step 3 (review fix): the disposition (or, for `allow`, the tag) only restates the
   * platform default's 5.1 risk recommendation (`recommendationOnlyOf`). The verdict lane already
   * covers that recommendation, so the policy lane ignores it. Always written from the fix on;
   * absent in decision records written before it (read as `false`).
   */
  recommendationOnly: z.boolean().optional(),
});
export type PolicyOutcomeFacts = z.infer<typeof policyOutcomeFactsSchema>;

/** `PolicyDisposition` rank (weakest first, `POLICY_OUTCOME_DISPOSITIONS` order). */
const dispositionRank = (d: PolicyOutcomeDisposition): number =>
  POLICY_OUTCOME_DISPOSITIONS.indexOf(d);

/** The 5.2 platform-default reason of a deterministic BEC hold (rule D2): not a restatement. */
export const POLICY_DEFAULT_BEC_REASON = 'policy.default.bec_deterministic';

/**
 * A4.3 step 3 (review fix): whether a policy outcome only restates the platform default's risk
 * recommendation, which the verdict lane already turns into a mailbox action through the tenant's
 * verdict rules. Such an outcome feeds no policy lane, so a verdict rule (e.g. spam → Junk) is
 * never raised to the inline default (spam → quarantine) by the same signal counted twice.
 *
 * - `allow`: true when every applying TAG/WARN comes from the platform default (the risk tag);
 *   tenant-rule and floor tags (e.g. `dlp-alert`) count. An untagged allow is false (no lane).
 * - otherwise: true when the platform default decided (`decisionSource = platform_default`), it is
 *   not a deterministic BEC hold (D2), and the mandatory floor does not bind at that disposition
 *   (a DLP, hard-block or missing-data floor reason at the same level counts as the floor's).
 *   Tenant rules (`tenant_rule`) and a raised floor (`floor`) are never a restatement.
 */
export function recommendationOnlyOf(args: {
  disposition: PolicyOutcomeDisposition;
  decisionSource: PolicyOutcomeDecisionSource;
  decisiveReason: string | null;
  floorDisposition: PolicyOutcomeDisposition | null;
  /** Origins of the applying TAG and WARN actions. */
  tagOrigins: readonly PolicyOutcomeDecisionSource[];
}): boolean {
  if (args.disposition === 'allow') {
    return args.tagOrigins.length > 0 && args.tagOrigins.every((o) => o === 'platform_default');
  }
  if (args.decisionSource !== 'platform_default') return false;
  if (args.decisiveReason === POLICY_DEFAULT_BEC_REASON) return false;
  return (
    args.floorDisposition === null ||
    dispositionRank(args.floorDisposition) < dispositionRank(args.disposition)
  );
}

// ---------------------------------------------------------------------------------------------
// policyMapping (A4.2)
// ---------------------------------------------------------------------------------------------

/** Mailbox actions a held disposition may map to (`hard_delete` never, R-I2). */
export const POLICY_MAPPING_ACTIONS = [
  'move_quarantine',
  'move_junk',
  'soft_delete',
  'tag',
  'none',
] as const;
export type PolicyMappingAction = (typeof POLICY_MAPPING_ACTIONS)[number];

/** Mailbox actions a tagged `allow` may map to. */
export const POLICY_MAPPING_TAGGED_ACTIONS = ['tag', 'none'] as const;
export type PolicyMappingTaggedAction = (typeof POLICY_MAPPING_TAGGED_ACTIONS)[number];

/** The `policyMapping` keys (the policy lane's synthetic rule ids are `policy-mapping:<key>`). */
export const POLICY_MAPPING_KEYS = [
  'quarantine',
  'require_approval',
  'reject',
  'allow_tagged',
] as const;
export type PolicyMappingKey = (typeof POLICY_MAPPING_KEYS)[number];

/** The rule id of a policy-lane decision (`policy-mapping:<key>`). */
export const policyMappingRuleId = (key: PolicyMappingKey): string => `policy-mapping:${key}`;

/**
 * `policyMapping` of `api-remediation-policy/1` (A4.2): strict, every key optional (a missing key
 * takes its default). `hard_delete` is never accepted.
 */
export const policyMappingSchema = z.strictObject({
  quarantine: z.enum(POLICY_MAPPING_ACTIONS).optional(),
  require_approval: z.enum(POLICY_MAPPING_ACTIONS).optional(),
  reject: z.enum(POLICY_MAPPING_ACTIONS).optional(),
  allow_tagged: z.enum(POLICY_MAPPING_TAGGED_ACTIONS).optional(),
});
export type PolicyMapping = z.infer<typeof policyMappingSchema>;
export type EffectivePolicyMapping = Required<PolicyMapping>;

/**
 * Product-owner default API4-3: quarantine, require approval and reject → the quarantine folder
 * (recoverable; require approval as a `review` entry), tagged allow → tag; never delete.
 */
export const DEFAULT_POLICY_MAPPING: Readonly<EffectivePolicyMapping> = Object.freeze({
  quarantine: 'move_quarantine',
  require_approval: 'move_quarantine',
  reject: 'move_quarantine',
  allow_tagged: 'tag',
});

/** The document's mapping over the defaults (documents without `policyMapping` → defaults). */
export function effectivePolicyMapping(mapping: PolicyMapping | undefined): EffectivePolicyMapping {
  return {
    quarantine: mapping?.quarantine ?? DEFAULT_POLICY_MAPPING.quarantine,
    require_approval: mapping?.require_approval ?? DEFAULT_POLICY_MAPPING.require_approval,
    reject: mapping?.reject ?? DEFAULT_POLICY_MAPPING.reject,
    allow_tagged: mapping?.allow_tagged ?? DEFAULT_POLICY_MAPPING.allow_tagged,
  };
}

/**
 * The policy lane (A4.3 step 3): `quarantine` / `require_approval` / `reject` → the mapped action;
 * `allow` + tagged → the `allow_tagged` mapping; `allow` → none. A mapping to `none` is no action.
 * An outcome that only restates the platform default's risk recommendation (`recommendationOnly`)
 * feeds no lane: the verdict lane already covers it.
 */
export function policyLaneOf(
  outcome: PolicyOutcomeFacts,
  mapping: EffectivePolicyMapping,
): { key: PolicyMappingKey; action: RemediationAction } | null {
  if (outcome.recommendationOnly === true) return null;
  let key: PolicyMappingKey | null;
  if (outcome.disposition === 'allow') key = outcome.tagged ? 'allow_tagged' : null;
  else key = outcome.disposition;
  if (key === null) return null;
  const action = mapping[key];
  return action === 'none' ? null : { key, action };
}

/**
 * A4.3 step 4: a tenant allow override of the recommendation (P9 step 6) suppresses the verdict
 * lane. The 5.2 floor lets an override through only on a level-only recommendation, so hard
 * blocks are never suppressed.
 */
export function isTenantAllowOverride(outcome: PolicyOutcomeFacts | null): boolean {
  return (
    outcome !== null &&
    outcome.disposition === 'allow' &&
    outcome.overrideApplied &&
    outcome.decisionSource === 'tenant_rule'
  );
}

// ---------------------------------------------------------------------------------------------
// Policy actions after delivery (A5)
// ---------------------------------------------------------------------------------------------

/**
 * Policy actions and effects with a post-delivery meaning (A5): the nine `policy-dsl/1` action
 * types, the derived effects `SENDER_NOTICE` (the non-delivery notice of a reject) and
 * `HEADER_EDIT` (header edits, subject prefix, WARN body banner), and the forward-compatible
 * `ENCRYPT` / `REDIRECT` rows (not in `policy-dsl/1`).
 */
export const POST_DELIVERY_EFFECTS = [
  ...POLICY_OUTCOME_ACTION_TYPES,
  'SENDER_NOTICE',
  'HEADER_EDIT',
  'ENCRYPT',
  'REDIRECT',
] as const;
export type PostDeliveryEffect = (typeof POST_DELIVERY_EFFECTS)[number];

/** Reasons of a post-delivery status (A5; `null` for a requested ALERT). */
export const POST_DELIVERY_REASONS = [
  'mapped_to_mailbox_action',
  'already_delivered',
  'post_delivery_no_bounce',
  'post_delivery_no_header_edit',
  'post_delivery_no_rewrite',
  'archive_follows_journaling',
  'post_delivery_no_encrypt',
  'post_delivery_no_redirect',
  'outbound_already_sent',
] as const;
export type PostDeliveryReason = (typeof POST_DELIVERY_REASONS)[number];

export interface PostDeliveryStatus {
  status: PolicyActionStatus;
  reason: PostDeliveryReason | null;
}

/**
 * A5 table (inbound and internal copies). `ALLOW` has no table row: the message was already
 * delivered, so the allow is recorded. Outbound copies: every effect but `ALERT` is
 * `not_applicable` (`outbound_already_sent`), see `postDeliveryStatusOf`.
 */
export const POST_DELIVERY_ACTION_MAP: Readonly<Record<PostDeliveryEffect, PostDeliveryStatus>> =
  Object.freeze({
    ALLOW: { status: 'recorded', reason: 'already_delivered' },
    QUARANTINE: { status: 'requested', reason: 'mapped_to_mailbox_action' },
    REQUIRE_APPROVAL: { status: 'requested', reason: 'mapped_to_mailbox_action' },
    REJECT: { status: 'requested', reason: 'mapped_to_mailbox_action' },
    SENDER_NOTICE: { status: 'not_applicable', reason: 'post_delivery_no_bounce' },
    TAG: { status: 'requested', reason: 'mapped_to_mailbox_action' },
    WARN: { status: 'requested', reason: 'mapped_to_mailbox_action' },
    HEADER_EDIT: { status: 'not_applicable', reason: 'post_delivery_no_header_edit' },
    URL_REWRITE: { status: 'not_applicable', reason: 'post_delivery_no_rewrite' },
    ARCHIVE: { status: 'not_applicable', reason: 'archive_follows_journaling' },
    ALERT: { status: 'requested', reason: null },
    ENCRYPT: { status: 'not_applicable', reason: 'post_delivery_no_encrypt' },
    REDIRECT: { status: 'not_applicable', reason: 'post_delivery_no_redirect' },
  });

const OUTBOUND_ALREADY_SENT: PostDeliveryStatus = Object.freeze({
  status: 'not_applicable',
  reason: 'outbound_already_sent',
});

/** A5: the post-delivery status of one effect of a copy in `direction`. */
export function postDeliveryStatusOf(
  effect: PostDeliveryEffect,
  direction: ApiCopyRecordDirection,
): PostDeliveryStatus {
  if (direction === 'outbound' && effect !== 'ALERT') return { ...OUTBOUND_ALREADY_SENT };
  return { ...POST_DELIVERY_ACTION_MAP[effect] };
}

/** Most `postDelivery` entries of a decision record (A4.4). */
export const POST_DELIVERY_MAX_ENTRIES = 9;

export interface PostDeliveryEntry extends PostDeliveryStatus {
  type: PostDeliveryEffect;
}

/**
 * The `postDelivery` list of a decision record (A4.4): one entry per applying action type of the
 * evaluation (in `POST_DELIVERY_EFFECTS` order), plus `SENDER_NOTICE` for a `REJECT` and
 * `HEADER_EDIT` for `TAG`/`WARN`; at most nine.
 */
export function postDeliveryEntries(
  actionTypes: readonly PolicyOutcomeActionType[],
  direction: ApiCopyRecordDirection,
): PostDeliveryEntry[] {
  const effects = new Set<PostDeliveryEffect>(actionTypes);
  if (effects.has('REJECT')) effects.add('SENDER_NOTICE');
  if (effects.has('TAG') || effects.has('WARN')) effects.add('HEADER_EDIT');
  return POST_DELIVERY_EFFECTS.filter((e) => effects.has(e))
    .slice(0, POST_DELIVERY_MAX_ENTRIES)
    .map((type) => ({ type, ...postDeliveryStatusOf(type, direction) }));
}

// ---------------------------------------------------------------------------------------------
// Mailbox entries of a policy-lane action (A5, R9.1 extension)
// ---------------------------------------------------------------------------------------------

/**
 * The mailbox quarantine entry kind of a policy-lane action (A5): `review` when the policy lane
 * decided a `require_approval` disposition (a restore then needs an approver, R10.1), else
 * `quarantine`.
 */
export function policyEntryKind(policyLaneKey: PolicyMappingKey | null): 'quarantine' | 'review' {
  return policyLaneKey === 'require_approval' ? 'review' : 'quarantine';
}

/**
 * The entry `reason` of a policy-lane action (A5): the verdict mapping when the verdict lane would
 * have chosen the same action; else `dlp` when a `policy.floor.dlp_*` reason decided; else
 * `policy`.
 */
export function policyEntryReason(args: {
  verdictReason: MailboxQuarantineReason;
  verdictLaneAction: RemediationAction | null;
  policyLaneAction: RemediationAction;
  outcome: PolicyOutcomeFacts;
}): MailboxQuarantineReason {
  if (args.verdictLaneAction !== null && args.verdictLaneAction === args.policyLaneAction) {
    return args.verdictReason;
  }
  if (
    args.outcome.decisionSource === 'floor' &&
    args.outcome.floorReasons.some((r) => r.startsWith('policy.floor.dlp_'))
  ) {
    return 'dlp';
  }
  return 'policy';
}

/** The fixed, content-free explanation of a policy-lane mailbox entry (A5). */
export function policyEntryExplanation(decisiveRuleRef: string | null): string {
  return `Removed from the mailbox by the tenant policy (API mode; rule ${decisiveRuleRef ?? 'platform default'})`;
}

// ---------------------------------------------------------------------------------------------
// Detection classification (A8.1)
// ---------------------------------------------------------------------------------------------

/** Verdicts that make a copy a threat detection (A8.1). */
export const COPY_THREAT_VERDICTS = [
  'spam',
  'bulk',
  'suspicious',
  'phishing',
  'malware',
  'bec',
] as const satisfies readonly MessageVerdict[];

/** The public webhook threat verdict (`threatVerdictOf`, A9.1). */
export type CopyThreatVerdict = 'spam' | 'suspicious' | 'malicious';

/** A9.1: spam/bulk → `spam`, suspicious → `suspicious`, phishing/malware/bec → `malicious`. */
export function threatVerdictOf(verdict: MessageVerdict | null): CopyThreatVerdict | null {
  switch (verdict) {
    case 'spam':
    case 'bulk':
      return 'spam';
    case 'suspicious':
      return 'suspicious';
    case 'phishing':
    case 'malware':
    case 'bec':
      return 'malicious';
    default:
      return null;
  }
}

export interface CopyDetection {
  /** A8.1: the copy message is a detection. */
  isDetection: boolean;
  /** The public threat verdict when the verdict is a threat verdict, else null. */
  threatVerdict: CopyThreatVerdict | null;
  /** The DLP action when it is not `allow`, else null. */
  dlpAction: Exclude<PolicyOutcomeDlpAction, 'allow'> | null;
}

/**
 * A8.1: a detection when the verdict is a threat verdict, or the DLP action is not `allow`, or
 * the policy disposition is not `allow`, or the policy result is tagged. `dlpAction` defaults to
 * the policy outcome's DLP action when not given.
 */
export function copyDetectionOf(args: {
  verdict: MessageVerdict | null;
  policyOutcome: PolicyOutcomeFacts | null;
  dlpAction?: PolicyOutcomeDlpAction | null;
}): CopyDetection {
  const threatVerdict = threatVerdictOf(args.verdict);
  const dlp =
    args.dlpAction !== undefined ? args.dlpAction : (args.policyOutcome?.dlpAction ?? null);
  const dlpAction = dlp !== null && dlp !== 'allow' ? dlp : null;
  const policy = args.policyOutcome;
  const policyDetection = policy !== null && (policy.disposition !== 'allow' || policy.tagged);
  return {
    isDetection: threatVerdict !== null || dlpAction !== null || policyDetection,
    threatVerdict,
    dlpAction,
  };
}
