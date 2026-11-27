/**
 * Remediation policy of API mode (step API-2 R2, ADR-0101). Pure: the strict document schema
 * `api-remediation-policy/1`, the platform default P1 and the presets, the decision function
 * `decideRemediation` (R2.2, first matching rule, then the fixed gate order), the effective-policy
 * resolution (domain → organization → platform default, R2.6), the canonical document hash and
 * the decision record `api-remediation-decision/1` (R2.4).
 *
 * The mailbox-worker decides inside the `copies` transaction and the api validates writes and
 * shows the effective policy; both call these functions, so a rule is decided once.
 */
import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  REMEDIABLE_VERDICTS,
  REMEDIATION_MODES,
  REMEDIATION_RULE_ACTIONS,
  RULE_LEVELS,
  riskLevelRank,
  type ApiCopyStatus,
  type ApiMailboxStatus,
  type DomainEffectiveMode,
  type MessageVerdict,
  type RemediationAction,
  type RemediationMode,
  type RemediationProvider,
  type RemediationRuleAction,
  type RemediationSkipReason,
  type RiskLevel,
  type RuleLevel,
  type VerdictAuthority,
} from './vocabulary';

export const REMEDIATION_POLICY_SCHEMA_VERSION = 1;
export const REMEDIATION_DECISION_SCHEMA_VERSION = 1;

/** Document limits (R2.1). */
export const REMEDIATION_POLICY_LIMITS = Object.freeze({
  maxRules: 16,
  ruleIdMaxLength: 48,
  maxVerdictsPerRule: 9,
  maxScore: 1000,
});

/** The zod issue code (message and `params.code`) of the reserved `when.policyDispositions`. */
export const UNSUPPORTED_UNTIL_POLICY_EVALUATION = 'unsupported_until_policy_evaluation';

const RULE_ID = /^[a-z0-9_-]+$/;

const whenSchema = z
  .strictObject({
    verdicts: z
      .array(z.enum(REMEDIABLE_VERDICTS))
      .min(1)
      .max(REMEDIATION_POLICY_LIMITS.maxVerdictsPerRule)
      .refine((v) => new Set(v).size === v.length, { message: 'duplicate_verdicts' }),
    minLevel: z.enum(RULE_LEVELS).optional(),
    maxLevel: z.enum(RULE_LEVELS).optional(),
    hardBlock: z.boolean().optional(),
    minScore: z.number().int().min(0).max(REMEDIATION_POLICY_LIMITS.maxScore).optional(),
    /**
     * Reserved for the later policy-evaluation step (R2.5, product-owner item PO-D2): refused in
     * API-2 with the custom issue `unsupported_until_policy_evaluation`.
     */
    policyDispositions: z
      .custom<never>(() => false, {
        message: UNSUPPORTED_UNTIL_POLICY_EVALUATION,
        params: { code: UNSUPPORTED_UNTIL_POLICY_EVALUATION },
      })
      .optional(),
  })
  .refine(
    (w) =>
      w.minLevel === undefined ||
      w.maxLevel === undefined ||
      riskLevelRank(w.maxLevel) >= riskLevelRank(w.minLevel),
    { message: 'max_level_below_min_level', path: ['maxLevel'] },
  );

const ruleSchema = z.strictObject({
  id: z.string().min(1).max(REMEDIATION_POLICY_LIMITS.ruleIdMaxLength).regex(RULE_ID),
  when: whenSchema,
  action: z.enum(REMEDIATION_RULE_ACTIONS),
});

/** `api-remediation-policy/1` (R2.1): ordered first-match rules; strict everywhere. */
export const remediationPolicySchema = z.strictObject({
  v: z.literal(REMEDIATION_POLICY_SCHEMA_VERSION),
  rules: z
    .array(ruleSchema)
    .min(1)
    .max(REMEDIATION_POLICY_LIMITS.maxRules)
    .superRefine((rules, ctx) => {
      const seen = new Set<string>();
      rules.forEach((rule, index) => {
        if (seen.has(rule.id)) {
          ctx.addIssue({
            code: 'custom',
            message: 'duplicate_rule_id',
            path: [index, 'id'],
            params: { code: 'duplicate_rule_id' },
          });
        }
        seen.add(rule.id);
      });
    }),
  /** Reserved; must be false in API-2 (scan-failed copies are never remediated). */
  remediateScanFailures: z.literal(false).optional(),
});

export interface RemediationRuleWhen {
  verdicts: MessageVerdict[];
  minLevel?: RuleLevel;
  maxLevel?: RuleLevel;
  hardBlock?: boolean;
  minScore?: number;
}

export interface RemediationRule {
  id: string;
  when: RemediationRuleWhen;
  action: RemediationRuleAction;
}

/** `api-remediation-policy/1`. */
export interface RemediationPolicyDocument {
  v: 1;
  rules: RemediationRule[];
  remediateScanFailures?: false;
}

/** A policy as stored: the mode column plus the document. */
export interface RemediationPolicy {
  mode: RemediationMode;
  document: RemediationPolicyDocument;
}

export const remediationModeSchema = z.enum(REMEDIATION_MODES);

/** Validates an unknown value as `api-remediation-policy/1` (strict). */
export function parseRemediationPolicy(
  value: unknown,
): { ok: true; document: RemediationPolicyDocument } | { ok: false; issues: z.ZodError['issues'] } {
  const result = remediationPolicySchema.safeParse(value);
  if (!result.success) return { ok: false, issues: result.error.issues };
  return { ok: true, document: result.data };
}

/** The rule ids whose action is `hard_delete` (the api refuses them while the setting is off). */
export function hardDeleteRuleIds(document: RemediationPolicyDocument): string[] {
  return document.rules.filter((r) => r.action === 'hard_delete').map((r) => r.id);
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object') {
    for (const inner of Object.values(value)) deepFreeze(inner);
    Object.freeze(value);
  }
  return value;
}

const P1_RULES: RemediationRule[] = [
  {
    id: 'p1-high-confidence-malware-phishing-hb',
    when: { verdicts: ['malware', 'phishing'], hardBlock: true },
    action: 'move_quarantine',
  },
  {
    id: 'p1-high-confidence-malware-phishing',
    when: { verdicts: ['malware', 'phishing'], minLevel: 'critical' },
    action: 'move_quarantine',
  },
  { id: 'p1-other-malware-phishing', when: { verdicts: ['malware', 'phishing'] }, action: 'tag' },
  { id: 'p1-suspicious', when: { verdicts: ['suspicious', 'bec'] }, action: 'tag' },
];

const clone = <T>(value: T): T => structuredClone(value);

/**
 * The platform default P1 (R2.3, product-owner default API2-1): mode `enforce`; high-confidence
 * malware/phishing → quarantine folder, other malware/phishing and suspicious/BEC → tag; spam,
 * bulk and DLP → no action; never hard delete.
 */
export const DEFAULT_REMEDIATION_POLICY: Readonly<RemediationPolicy> = deepFreeze({
  mode: 'enforce',
  document: { v: 1, rules: clone(P1_RULES) },
});

/** Presets offered by the portal (R2.3). None contains `hard_delete` (R-I2). */
export const REMEDIATION_PRESETS: Readonly<{
  p1: Readonly<RemediationPolicy>;
  detectOnlyStart: Readonly<RemediationPolicy>;
  strict: Readonly<RemediationPolicy>;
}> = deepFreeze({
  p1: { mode: 'enforce', document: { v: 1, rules: clone(P1_RULES) } },
  /** P1 rules in detect-only mode: "recommended start for new tenants". */
  detectOnlyStart: { mode: 'detect_only', document: { v: 1, rules: clone(P1_RULES) } },
  /** P1 + spam → Junk. */
  strict: {
    mode: 'enforce',
    document: {
      v: 1,
      rules: [
        ...clone(P1_RULES),
        { id: 'strict-spam-junk', when: { verdicts: ['spam'] }, action: 'move_junk' },
      ],
    },
  },
});

export type RemediationPresetKey = keyof typeof REMEDIATION_PRESETS;

// ---------------------------------------------------------------------------------------------
// decideRemediation (R2.2)
// ---------------------------------------------------------------------------------------------

export interface RemediationInput {
  copy: {
    status: ApiCopyStatus;
    verdict: MessageVerdict | null;
    riskScore: number | null;
    verdictAuthority: VerdictAuthority;
  };
  /** The scan round's latest revision row (`message_risk_scores`); null when missing. */
  risk: { level: RiskLevel | null; hardBlocks: readonly string[] } | null;
  /** R2.5 hook for a later policy-evaluation step; API-2 always passes null. */
  policyOutcome: null;
  context: {
    provider: RemediationProvider;
    /** The connection's `*.mailbox_remediation` grant is `active`. */
    grantActive: boolean;
    remediationPaused: boolean;
    domainEffectiveMode: DomainEffectiveMode | null;
    mailboxStatus: ApiMailboxStatus;
  };
}

export interface RemediationDecisionOptions {
  /** `API_MODE_HARD_DELETE_ENABLED`. */
  hardDeleteEnabled: boolean;
}

/** Notes attached to an `act` decision. */
export const REMEDIATION_DECISION_NOTES = ['hard_delete_falls_back_to_trash'] as const;
export type RemediationDecisionNote = (typeof REMEDIATION_DECISION_NOTES)[number];

export type RemediationDecision =
  | { outcome: 'none' }
  | {
      outcome: 'skip';
      reason: RemediationSkipReason;
      ruleId: string | null;
      action: RemediationAction | null;
    }
  | {
      outcome: 'act';
      action: RemediationAction;
      ruleId: string;
      simulated: boolean;
      notes: RemediationDecisionNote[];
    };

/** Whether one rule matches (every present bound must hold; R2.2 last sentence). */
export function ruleMatches(rule: RemediationRule, input: RemediationInput): boolean {
  const verdict = input.copy.verdict;
  if (verdict === null || !rule.when.verdicts.includes(verdict)) return false;
  const level = input.risk?.level ?? null;
  const hardBlocks = input.risk?.hardBlocks ?? [];
  const when = rule.when;
  if (when.minLevel !== undefined) {
    if (level === null || riskLevelRank(level) < riskLevelRank(when.minLevel)) return false;
  }
  if (when.maxLevel !== undefined) {
    if (level === null || riskLevelRank(level) > riskLevelRank(when.maxLevel)) return false;
  }
  if (when.hardBlock === true && hardBlocks.length === 0) return false;
  if (when.hardBlock === false && hardBlocks.length > 0) return false;
  if (when.minScore !== undefined) {
    const score = input.copy.riskScore;
    if (score === null || score < when.minScore) return false;
  }
  return true;
}

/** The first matching rule, or null. */
export function firstMatchingRule(
  document: RemediationPolicyDocument,
  input: RemediationInput,
): RemediationRule | null {
  return document.rules.find((rule) => ruleMatches(rule, input)) ?? null;
}

/**
 * R2.2, in this order: (1) not scanned or verdict clean/unknown/null → none; (2) first matching
 * rule (none or action `none` → none); (3) inline verdict authority → skip; (4) domain not
 * api/hybrid or mailbox disabled/deleted → skip out_of_scope; (5) hard delete without the
 * platform setting → skip; (6) detect-only → act simulated; (7) paused → skip; (8) no active
 * grant → skip no_mailbox_access; (9) act.
 */
export function decideRemediation(
  input: RemediationInput,
  policy: Readonly<RemediationPolicy>,
  options: RemediationDecisionOptions,
): RemediationDecision {
  const verdict = input.copy.verdict;
  if (input.copy.status !== 'scanned' || verdict === null || verdict === 'clean') {
    return { outcome: 'none' };
  }
  if (verdict === 'unknown') return { outcome: 'none' };
  const rule = firstMatchingRule(policy.document, input);
  if (rule === null || rule.action === 'none') return { outcome: 'none' };
  const action = rule.action;
  const skip = (reason: RemediationSkipReason): RemediationDecision => ({
    outcome: 'skip',
    reason,
    ruleId: rule.id,
    action,
  });
  const ctx = input.context;
  if (input.copy.verdictAuthority === 'inline') return skip('inline_authority');
  if (
    (ctx.domainEffectiveMode !== 'api' && ctx.domainEffectiveMode !== 'hybrid') ||
    ctx.mailboxStatus === 'disabled' ||
    ctx.mailboxStatus === 'deleted'
  ) {
    return skip('out_of_scope');
  }
  if (action === 'hard_delete' && !options.hardDeleteEnabled) return skip('hard_delete_disabled');
  const notes: RemediationDecisionNote[] =
    action === 'hard_delete' && ctx.provider === 'google_workspace'
      ? ['hard_delete_falls_back_to_trash']
      : [];
  if (policy.mode === 'detect_only') {
    return { outcome: 'act', action, ruleId: rule.id, simulated: true, notes };
  }
  if (ctx.remediationPaused) return skip('remediation_paused');
  if (!ctx.grantActive) return skip('no_mailbox_access');
  return { outcome: 'act', action, ruleId: rule.id, simulated: false, notes };
}

// ---------------------------------------------------------------------------------------------
// Effective policy (R2.6) and provenance (R2.4)
// ---------------------------------------------------------------------------------------------

export type RemediationPolicyScope = 'platform_default' | 'organization' | 'domain';

/** One `api_remediation_policies` row as the caller loaded it (document already validated). */
export interface StoredRemediationPolicy {
  publicId: string;
  /** NULL for the organization row. */
  domainId: string | number | bigint | null;
  mode: RemediationMode;
  document: RemediationPolicyDocument;
  rowVersion: number;
}

export interface EffectiveRemediationPolicy {
  scope: RemediationPolicyScope;
  policy: Readonly<RemediationPolicy>;
  publicId: string | null;
  rowVersion: number | null;
}

/**
 * R2.6: the mailbox's domain row, else the organization row, else `DEFAULT_REMEDIATION_POLICY`.
 * A domain row is taken only for the mailbox's own domain (`domainId` null → no domain row).
 */
export function resolveEffectivePolicy(
  rows: {
    organization: StoredRemediationPolicy | null;
    domains: readonly StoredRemediationPolicy[];
  },
  domainId: string | number | bigint | null,
): EffectiveRemediationPolicy {
  if (domainId !== null) {
    const key = String(domainId);
    const domain = rows.domains.find(
      (row) => row.domainId !== null && String(row.domainId) === key,
    );
    if (domain) {
      return {
        scope: 'domain',
        policy: { mode: domain.mode, document: domain.document },
        publicId: domain.publicId,
        rowVersion: domain.rowVersion,
      };
    }
  }
  const org = rows.organization;
  if (org) {
    return {
      scope: 'organization',
      policy: { mode: org.mode, document: org.document },
      publicId: org.publicId,
      rowVersion: org.rowVersion,
    };
  }
  return {
    scope: 'platform_default',
    policy: DEFAULT_REMEDIATION_POLICY,
    publicId: null,
    rowVersion: null,
  };
}

/** Canonical JSON: object keys sorted, no whitespace, `undefined` members dropped. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) {
      throw new TypeError('canonical_json_non_finite_number');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

/** `document_sha256`: hex SHA-256 of the canonical JSON of the document. */
export function canonicalPolicySha256(document: RemediationPolicyDocument): string {
  return createHash('sha256').update(canonicalJson(document), 'utf8').digest('hex');
}

/** At most this many hard-block ids are recorded in a decision (R2.4). */
export const DECISION_MAX_HARD_BLOCKS = 9;

/** `api-remediation-decision/1` (R2.4), stored on the action row of a policy decision. */
export const remediationDecisionRecordSchema = z.strictObject({
  v: z.literal(REMEDIATION_DECISION_SCHEMA_VERSION),
  policy: z.strictObject({
    scope: z.enum(['platform_default', 'organization', 'domain']),
    publicId: z.string().max(36).nullable(),
    rowVersion: z.number().int().min(1).nullable(),
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
  }),
  mode: z.enum(REMEDIATION_MODES),
  ruleId: z.string().max(REMEDIATION_POLICY_LIMITS.ruleIdMaxLength).nullable(),
  inputs: z.strictObject({
    verdict: z.string().max(32).nullable(),
    riskScore: z.number().int().min(0).max(1000).nullable(),
    level: z.string().max(16).nullable(),
    hardBlocks: z.array(z.string().max(64)).max(DECISION_MAX_HARD_BLOCKS),
    verdictAuthority: z.enum(['copy', 'inline']),
  }),
  policyOutcome: z.null(),
  notes: z.array(z.string().max(64)).max(8),
});
export type RemediationDecisionRecord = z.infer<typeof remediationDecisionRecordSchema>;

/** Builds the R2.4 record of a decision taken under an effective policy. */
export function buildDecisionRecord(
  effective: EffectiveRemediationPolicy,
  input: RemediationInput,
  decision: RemediationDecision,
): RemediationDecisionRecord {
  return {
    v: REMEDIATION_DECISION_SCHEMA_VERSION,
    policy: {
      scope: effective.scope,
      publicId: effective.publicId,
      rowVersion: effective.rowVersion,
      sha256: canonicalPolicySha256(effective.policy.document),
    },
    mode: effective.policy.mode,
    ruleId: decision.outcome === 'none' ? null : decision.ruleId,
    inputs: {
      verdict: input.copy.verdict,
      riskScore: input.copy.riskScore,
      level: input.risk?.level ?? null,
      hardBlocks: [...(input.risk?.hardBlocks ?? [])].slice(0, DECISION_MAX_HARD_BLOCKS),
      verdictAuthority: input.copy.verdictAuthority,
    },
    policyOutcome: null,
    notes: decision.outcome === 'act' ? [...decision.notes] : [],
  };
}
