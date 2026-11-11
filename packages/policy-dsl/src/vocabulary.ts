import { z } from 'zod';

/**
 * Versions and vocabularies of the policy DSL and evaluator (step 5.2 P1, P2, P4, P9, P10;
 * docs/plan/steps/16-policy-engine.md; ADR-0043, ADR-0045). A changed document shape, input
 * shape or algorithm is a new id, never an edit.
 */
export const POLICY_DSL_VERSION = 'policy-dsl/1';
export const POLICY_INPUT_VERSION = 'policy-input/1';
export const POLICY_EVALUATOR_VERSION = 'policy-eval/1';

/** Message directions (Prisma `MessageDirection`). */
export const POLICY_MESSAGE_DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;
export type PolicyMessageDirection = (typeof POLICY_MESSAGE_DIRECTIONS)[number];

/** Policy directions (Prisma `PolicyDirection`): a message direction or `any`. */
export const POLICY_DIRECTIONS = ['inbound', 'outbound', 'internal', 'any'] as const;
export type PolicyDirection = (typeof POLICY_DIRECTIONS)[number];

/** Final dispositions in strictness order (Prisma `PolicyDisposition`). */
export const POLICY_DISPOSITIONS = ['allow', 'require_approval', 'quarantine', 'reject'] as const;
export type PolicyDisposition = (typeof POLICY_DISPOSITIONS)[number];
export const policyDispositionSchema = z.enum(POLICY_DISPOSITIONS);

export const dispositionRank = (d: PolicyDisposition): number => POLICY_DISPOSITIONS.indexOf(d);

/** The stricter of two dispositions (`null` = none). */
export function stricterDisposition(
  a: PolicyDisposition | null,
  b: PolicyDisposition | null,
): PolicyDisposition | null {
  if (a === null) return b;
  if (b === null) return a;
  return dispositionRank(a) >= dispositionRank(b) ? a : b;
}

/** The nine actions of the brief, upper case (ADR-0045). */
export const POLICY_ACTION_TYPES = [
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
export type PolicyActionType = (typeof POLICY_ACTION_TYPES)[number];
export const policyActionTypeSchema = z.enum(POLICY_ACTION_TYPES);

/** Actions that carry a disposition (at most one per rule). */
export const POLICY_DISPOSITION_ACTIONS = [
  'ALLOW',
  'REQUIRE_APPROVAL',
  'QUARANTINE',
  'REJECT',
] as const;
export type PolicyDispositionAction = (typeof POLICY_DISPOSITION_ACTIONS)[number];

/** Actions merged across matched rules (P9.9); each at most once per rule. */
export const POLICY_NON_TERMINAL_ACTIONS = [
  'TAG',
  'WARN',
  'URL_REWRITE',
  'ARCHIVE',
  'ALERT',
] as const;
export type PolicyNonTerminalAction = (typeof POLICY_NON_TERMINAL_ACTIONS)[number];

export const DISPOSITION_OF_ACTION: Readonly<Record<PolicyDispositionAction, PolicyDisposition>> =
  Object.freeze({
    ALLOW: 'allow',
    REQUIRE_APPROVAL: 'require_approval',
    QUARANTINE: 'quarantine',
    REJECT: 'reject',
  });

export const ACTION_OF_DISPOSITION: Readonly<Record<PolicyDisposition, PolicyDispositionAction>> =
  Object.freeze({
    allow: 'ALLOW',
    require_approval: 'REQUIRE_APPROVAL',
    quarantine: 'QUARANTINE',
    reject: 'REJECT',
  });

export const isDispositionAction = (type: string): type is PolicyDispositionAction =>
  (POLICY_DISPOSITION_ACTIONS as readonly string[]).includes(type);

/** Dispositions that hold mail (AI-derived rules may not carry them, P9.8). */
export const POLICY_HOLD_DISPOSITIONS: readonly PolicyDisposition[] = Object.freeze([
  'require_approval',
  'quarantine',
  'reject',
]);

/** Stored action statuses (ADR-0045, P19): never claim enforcement that did not happen. */
export const ACTION_STATUSES = ['enforced', 'requested', 'recorded', 'not_applicable'] as const;
export type ActionStatus = (typeof ACTION_STATUSES)[number];
export const actionStatusSchema = z.enum(ACTION_STATUSES);

export const ACTION_ORIGINS = ['tenant_rule', 'platform_default', 'floor'] as const;
export type ActionOrigin = (typeof ACTION_ORIGINS)[number];
/** Who decided the final disposition (Prisma `PolicyDecisionSource`). */
export const DECISION_SOURCES = ACTION_ORIGINS;
export type DecisionSource = ActionOrigin;

export const ACTION_APPLICABILITIES = ['applies', 'not_applicable'] as const;
export type ActionApplicability = (typeof ACTION_APPLICABILITIES)[number];

/** Evaluation triggers (Prisma `PolicyEvaluationTrigger`). */
export const POLICY_TRIGGERS = ['scanned', 'scan_failed', 'parse_failed'] as const;
export type PolicyTrigger = (typeof POLICY_TRIGGERS)[number];

/** Delivered objects (Prisma `PolicyDeliveredObject`). */
export const POLICY_DELIVERED_OBJECTS = ['original', 'rewritten', 'policy_copy', 'none'] as const;
export type PolicyDeliveredObject = (typeof POLICY_DELIVERED_OBJECTS)[number];

/** Final actions written to `email_messages.final_action` (P18; Prisma `MessageAction`). */
export const POLICY_FINAL_ACTIONS = [
  'deliver',
  'tag',
  'quarantine',
  'require_approval',
  'reject',
  'discard',
] as const;
export type PolicyFinalAction = (typeof POLICY_FINAL_ACTIONS)[number];

/** WARN levels, weakest first; ALERT severities, weakest first. */
export const WARN_LEVELS = ['caution', 'warning', 'danger'] as const;
export type WarnLevel = (typeof WARN_LEVELS)[number];
export const ALERT_SEVERITIES = ['info', 'warning', 'critical'] as const;
export type AlertSeverity = (typeof ALERT_SEVERITIES)[number];
export const URL_REWRITE_FALLBACKS = ['deliver', 'quarantine'] as const;
export type UrlRewriteFallback = (typeof URL_REWRITE_FALLBACKS)[number];

/** Weekdays of `time.window` (ISO order, Monday first). */
export const WEEKDAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'] as const;
export type Weekday = (typeof WEEKDAYS)[number];

/** Delivery header names (P10); values are built only from validated policy data. */
export const POLICY_TAG_HEADER = 'X-EG-Policy-Tag';
export const POLICY_WARNING_HEADER = 'X-EG-Policy-Warning';

/**
 * Limits of `policy-dsl/1` (P4). The api may lower the organization-wide counts through its
 * environment bounds, never raise any of them.
 */
export const POLICY_LIMITS = Object.freeze({
  /** Canonical JSON of the definition, in bytes. */
  documentBytes: 262_144,
  rulesPerPolicy: 100,
  /** Nodes of `when` plus every `unless` of one rule (groups and leaves). */
  nodesPerRule: 64,
  /** Nodes of all policy-wide `exceptions` together. */
  nodesPerPolicyExceptions: 64,
  /** Tree depth, the root node being depth 1. */
  depth: 6,
  childrenPerGroup: 16,
  listValues: 500,
  stringValue: 320,
  globs: 10,
  globLength: 128,
  regexes: 5,
  regexLength: 256,
  cidrs: 100,
  codes: 64,
  exceptionsPerRule: 8,
  exceptionsPerPolicy: 8,
  actionsPerRule: 8,
  descriptionLength: 256,
  priorityMax: 10_000,
  activePoliciesPerOrganization: 100,
  activeRulesPerOrganization: 5_000,
  recipients: 1_000,
  attachments: 200,
  urls: 500,
  /** Regex subjects are cut to this many characters. */
  regexSubject: 1_024,
  /** Result bounds (P10). */
  tagLabels: 8,
  ruleRefsPerAction: 8,
  actions: 9,
  matchedRules: 64,
  trace: 200,
  clamps: 16,
  reasonCodes: 32,
  explanationLines: 24,
  explanationText: 2_048,
});
export type PolicyLimits = typeof POLICY_LIMITS;
