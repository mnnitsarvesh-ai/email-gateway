import {
  DLP_MAX_EXCEPTIONS_APPLIED,
  DLP_MAX_MATCHED_RULES,
  dlpActionRank,
  dlpRuleConditionsSchema,
  dlpSeverityRank,
  type DlpAction,
  type DlpActionSource,
  type DlpCategory,
  type DlpCoverageCode,
  type DlpDetectorId,
  type DlpDirection,
  type DlpExceptionFilters,
  type DlpExceptionScope,
  type DlpPolicyMode,
  type DlpRuleConditions,
  type DlpSeverity,
} from '@email-gateway/security-contracts';
import { registrableDomainOf } from '@email-gateway/url-security';
import { canonicalJson, sha256Hex } from '../data';

/**
 * Deterministic DLP policy evaluation (step 4.5 D11, D12; ADR-0037). A pure function of
 * (findings, coverage, direction, envelope, tenant policy snapshot, exceptions, now): rules are
 * sorted by (policy priority, policy id, rule priority, rule id), so the output never depends on
 * database or input order (asserted by a permutation-invariance property test).
 */

/** Platform default policy (no enabled tenant policy for the direction). */
export const DLP_DEFAULT_POLICY_ID = 'dlp-default/1';
export const DLP_DEFAULT_POLICY_CATEGORIES: readonly DlpCategory[] = [
  'payment_card',
  'bank_account',
  'national_id',
  'passport',
  'credential',
];
export const DLP_DEFAULT_POLICY_DIRECTIONS: readonly DlpDirection[] = ['outbound', 'internal'];

/** One reportable finding as the policy sees it (grouped per detector / pattern / dictionary). */
export interface DlpPolicyFinding {
  detector: DlpDetectorId;
  category: DlpCategory;
  severity: DlpSeverity;
  confidence: number;
  /** Distinct values. */
  count: number;
  /** Distinct values found in attachments (or their names). */
  attachmentCount: number;
  customPatternId?: string;
  dictionaryId?: string;
}

export interface DlpRuleSnapshot {
  /** Internal id (decimal string) — the stored result maps it to the public id. */
  id: string;
  version: number;
  enabled: boolean;
  priority: number;
  name?: string;
  conditions: DlpRuleConditions;
  action: DlpAction;
}

export interface DlpPolicySnapshot {
  id: string;
  version: number;
  enabled: boolean;
  mode: DlpPolicyMode;
  priority: number;
  directions: readonly DlpDirection[];
  rules: readonly DlpRuleSnapshot[];
}

export interface DlpExceptionSnapshot {
  id: string;
  version: number;
  scope: DlpExceptionScope;
  /** Normalized: lower-case address, or an A-label domain. */
  value: string;
  policyId: string | null;
  ruleId: string | null;
  filters: DlpExceptionFilters | null;
  expiresAt: Date;
  enabled: boolean;
}

export interface DlpPolicyInput {
  direction: DlpDirection;
  envelope: {
    sender: string | null;
    recipients: readonly string[];
    /** The stored recipient list was truncated (more recipients than recorded). */
    rcptTruncated: boolean;
  };
  /** The tenant's active domains (external-recipient classification). */
  tenantDomains: readonly string[];
  findings: readonly DlpPolicyFinding[];
  coverageReasons: readonly DlpCoverageCode[];
  /** Category thresholds (default `minConfidence`). */
  thresholds: Readonly<Record<DlpCategory, number>>;
  policies: readonly DlpPolicySnapshot[];
  exceptions: readonly DlpExceptionSnapshot[];
  defaultPolicy: 'alert' | 'allow';
  now: Date;
}

export interface DlpMatchedRule {
  policyId: string;
  ruleId: string;
  action: DlpAction;
  mode: DlpPolicyMode;
  exceptionIds: string[];
}

export interface DlpPolicyDecision {
  action: DlpAction;
  actionSource: DlpActionSource;
  winner: { policyId: string; ruleId: string } | null;
  matched: DlpMatchedRule[];
  /** True when more than `DLP_MAX_MATCHED_RULES` rules matched (only the first are listed). */
  matchedTruncated: boolean;
  exceptionsApplied: string[];
  policyVersion: string;
  /** Policy reason codes: action, default policy, monitor match, exception applied. */
  codes: string[];
}

/** Decimal ids compare numerically (length, then text); other ids by text. */
export const compareIds = (a: string, b: string): number =>
  a.length !== b.length && /^[0-9]+$/.test(a) && /^[0-9]+$/.test(b)
    ? a.length - b.length
    : a < b
      ? -1
      : a > b
        ? 1
        : 0;

const domainOf = (address: string): string =>
  address.slice(address.lastIndexOf('@') + 1).toLowerCase();

const safeRegistrable = (domain: string): string | null => {
  try {
    return registrableDomainOf(domain);
  } catch {
    return null;
  }
};

/** A domain scope matches a domain exactly or by its registrable domain. */
export const domainMatches = (scope: string, domain: string): boolean =>
  scope === domain || safeRegistrable(domain) === scope;

const addressScopeMatches = (
  scope: { addresses?: readonly string[] | undefined; domains?: readonly string[] | undefined },
  address: string,
): boolean =>
  (scope.addresses?.includes(address) ?? false) ||
  (scope.domains?.some((d) => domainMatches(d, domainOf(address))) ?? false);

const exceptionMatchesAddress = (exception: DlpExceptionSnapshot, address: string): boolean =>
  exception.scope.endsWith('_address')
    ? exception.value === address
    : domainMatches(exception.value, domainOf(address));

const exceptionTargets = (
  exception: DlpExceptionSnapshot,
  policyId: string | null,
  ruleId: string | null,
): boolean => {
  if (exception.ruleId !== null) return exception.ruleId === ruleId;
  if (exception.policyId !== null) return exception.policyId === policyId;
  return true;
};

const filterRemoves = (filters: DlpExceptionFilters | null, finding: DlpPolicyFinding): boolean =>
  filters === null ||
  (filters.detectors?.includes(finding.detector) ?? false) ||
  (filters.categories?.includes(finding.category) ?? false);

interface RuleView {
  policyId: string | null;
  policyPriority: number;
  mode: DlpPolicyMode;
  rule: DlpRuleSnapshot;
}

const DEFAULT_RULE: DlpRuleSnapshot = Object.freeze({
  id: 'default',
  version: 1,
  enabled: true,
  priority: 0,
  conditions: Object.freeze({
    selectors: { categories: [...DLP_DEFAULT_POLICY_CATEGORIES] },
    minSeverity: 'high',
    directions: [...DLP_DEFAULT_POLICY_DIRECTIONS],
  }),
  action: 'alert',
});

/**
 * Evaluates the tenant's DLP policies for one message (D11, D12). Pure and deterministic.
 */
export function evaluateDlpPolicy(input: DlpPolicyInput): DlpPolicyDecision {
  const now = input.now.getTime();
  const sender = input.envelope.sender?.toLowerCase() ?? null;
  const recipients = [...new Set(input.envelope.recipients.map((r) => r.toLowerCase()))].sort();
  const truncated = input.envelope.rcptTruncated;
  const tenantDomains = new Set(input.tenantDomains.map((d) => d.toLowerCase()));
  const isExternal = (address: string) => {
    const domain = domainOf(address);
    if (tenantDomains.has(domain)) return false;
    const registrable = safeRegistrable(domain);
    return !(registrable !== null && tenantDomains.has(registrable));
  };
  const exceptions = input.exceptions
    .filter((e) => e.enabled && e.expiresAt.getTime() > now)
    .sort((a, b) => compareIds(a.id, b.id));
  const coverage = new Set(input.coverageReasons);

  const candidatePolicies = input.policies
    .filter((p) => p.enabled && p.directions.includes(input.direction))
    .sort((a, b) => a.priority - b.priority || compareIds(a.id, b.id));
  const useDefault = candidatePolicies.length === 0;

  const rules: RuleView[] = [];
  if (useDefault) {
    if (input.defaultPolicy === 'alert') {
      rules.push({ policyId: null, policyPriority: 0, mode: 'enforce', rule: DEFAULT_RULE });
    }
  } else {
    for (const policy of candidatePolicies) {
      const sorted = policy.rules
        .filter((r) => r.enabled)
        .sort((a, b) => a.priority - b.priority || compareIds(a.id, b.id));
      for (const rule of sorted) {
        rules.push({
          policyId: policy.id,
          policyPriority: policy.priority,
          mode: policy.mode,
          rule,
        });
      }
    }
  }

  const matched: DlpMatchedRule[] = [];
  const applied = new Set<string>();
  let best: { action: DlpAction; view: RuleView } | null = null;
  let monitorMatch = false;

  for (const view of rules) {
    const parsed = dlpRuleConditionsSchema.safeParse(view.rule.conditions);
    // A stored rule that no longer validates is ignored (the api validates on write).
    if (!parsed.success) continue;
    const conditions = parsed.data;
    const policyDirections = useDefault
      ? DLP_DEFAULT_POLICY_DIRECTIONS
      : candidatePolicies.find((p) => p.id === view.policyId)!.directions;
    const directions = conditions.directions ?? policyDirections;
    if (!directions.includes(input.direction)) continue;

    const ruleExceptions = exceptions.filter((e) =>
      exceptionTargets(e, view.policyId, view.rule.id),
    );
    const usedHere = new Set<string>();

    // Selected findings.
    const { selectors } = conditions;
    const minSeverity = dlpSeverityRank(conditions.minSeverity ?? 'low');
    const selected = input.findings.filter((f) => {
      const selectedBy =
        (selectors.detectors?.includes(f.detector) ?? false) ||
        (selectors.categories?.includes(f.category) ?? false) ||
        (f.customPatternId !== undefined &&
          (selectors.customPatternIds?.includes(f.customPatternId) ?? false)) ||
        (f.dictionaryId !== undefined &&
          (selectors.dictionaryIds?.includes(f.dictionaryId) ?? false));
      if (!selectedBy) return false;
      if (conditions.attachmentsOnly === true && f.attachmentCount === 0) return false;
      const minConfidence = conditions.minConfidence ?? input.thresholds[f.category];
      if (f.confidence + 1e-9 < minConfidence) return false;
      return dlpSeverityRank(f.severity) >= minSeverity;
    });
    // Sender exceptions remove findings of this rule.
    const remaining = selected.filter((f) => {
      if (sender === null) return true;
      const removing = ruleExceptions.filter(
        (e) =>
          e.scope.startsWith('sender_') &&
          exceptionMatchesAddress(e, sender) &&
          filterRemoves(e.filters, f),
      );
      for (const e of removing) usedHere.add(e.id);
      return removing.length === 0;
    });
    const count = remaining.reduce(
      (sum, f) => sum + (conditions.attachmentsOnly === true ? f.attachmentCount : f.count),
      0,
    );
    const coverageHit = selectors.coverageReasons?.some((r) => coverage.has(r)) ?? false;
    const findingHit = count >= (conditions.minCount ?? 1) && count > 0;
    // Sender scope.
    const senderOk =
      conditions.sender === undefined ||
      (sender !== null && addressScopeMatches(conditions.sender, sender));
    // Recipients minus recipient exceptions (never applied to a truncated list).
    let recipientOk: boolean;
    if (truncated) {
      recipientOk = true;
    } else {
      const left = recipients.filter((r) => {
        const removing = ruleExceptions.filter(
          (e) => e.scope.startsWith('recipient_') && exceptionMatchesAddress(e, r),
        );
        for (const e of removing) usedHere.add(e.id);
        return removing.length === 0;
      });
      const scope = conditions.recipients;
      recipientOk =
        scope === undefined
          ? left.length > 0
          : left.some(
              (r) =>
                (scope.addresses === undefined && scope.domains === undefined
                  ? true
                  : addressScopeMatches(scope, r)) &&
                (scope.externalOnly !== true || isExternal(r)),
            );
    }
    for (const id of usedHere) applied.add(id);
    const isMatch = (findingHit || coverageHit) && senderOk && recipientOk;
    if (!isMatch) continue;
    const policyId = view.policyId ?? DLP_DEFAULT_POLICY_ID;
    matched.push({
      policyId,
      ruleId: view.rule.id,
      action: view.rule.action,
      mode: view.mode,
      exceptionIds: [...usedHere].sort(compareIds),
    });
    if (view.mode === 'monitor') {
      monitorMatch = true;
      continue;
    }
    if (best === null || dlpActionRank(view.rule.action) > dlpActionRank(best.action)) {
      best = { action: view.rule.action, view };
    }
  }

  const action: DlpAction = best?.action ?? 'allow';
  let actionSource: DlpActionSource = 'none';
  let winner: DlpPolicyDecision['winner'] = null;
  if (best !== null) {
    if (best.view.policyId === null) {
      actionSource = 'default_policy';
    } else {
      actionSource = 'tenant_policy';
      winner = { policyId: best.view.policyId, ruleId: best.view.rule.id };
    }
  }
  const exceptionsApplied = [...applied].sort(compareIds);
  const codes: string[] = [];
  if (action !== 'allow') codes.push(`dlp.action.${action}`);
  if (actionSource === 'default_policy') codes.push('dlp.policy.default');
  if (monitorMatch) codes.push('dlp.policy.monitor_match');
  if (exceptionsApplied.length > 0) codes.push('dlp.exception.applied');
  return {
    action,
    actionSource,
    winner,
    matched: matched.slice(0, DLP_MAX_MATCHED_RULES),
    matchedTruncated: matched.length > DLP_MAX_MATCHED_RULES,
    exceptionsApplied: exceptionsApplied.slice(0, DLP_MAX_EXCEPTIONS_APPLIED),
    policyVersion: dlpPolicyVersion(input),
    codes,
  };
}

/**
 * `pol/1;h=<12 hex>` of the canonical JSON of the policy snapshot that applied: policy ids and
 * versions with their rule ids and versions, exception ids and versions (unexpired, enabled),
 * and the default policy setting. Order-independent.
 */
export function dlpPolicyVersion(
  input: Pick<DlpPolicyInput, 'policies' | 'exceptions' | 'defaultPolicy' | 'now'>,
): string {
  const now = input.now.getTime();
  const policies = input.policies
    .filter((p) => p.enabled)
    .map((p) => ({
      id: p.id,
      version: p.version,
      rules: p.rules
        .filter((r) => r.enabled)
        .map((r) => ({ id: r.id, version: r.version }))
        .sort((a, b) => compareIds(a.id, b.id)),
    }))
    .sort((a, b) => compareIds(a.id, b.id));
  const exceptions = input.exceptions
    .filter((e) => e.enabled && e.expiresAt.getTime() > now)
    .map((e) => ({ id: e.id, version: e.version }))
    .sort((a, b) => compareIds(a.id, b.id));
  const hash = sha256Hex(
    canonicalJson({ policies, exceptions, defaultPolicy: input.defaultPolicy }),
  );
  return `pol/1;h=${hash.slice(0, 12)}`;
}
