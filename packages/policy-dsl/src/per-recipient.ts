import { leavesOf, type CompiledNode } from './conditions';
import { evaluatePolicy } from './evaluate';
import { renderExplanation } from './explanation';
import type { PolicyInput } from './input';
import type { PolicySplitCode } from './reason-codes';
import type {
  ExplanationLine,
  PolicyDelivery,
  PolicyEvaluationResult,
  RecipientDecision,
  ResultAction,
} from './result';
import type { PolicyTenantSettings } from './settings';
import type { CompiledSnapshot } from './snapshot';
import {
  ALERT_SEVERITIES,
  dispositionRank,
  POLICY_LIMITS,
  POLICY_TAG_HEADER,
  POLICY_WARNING_HEADER,
  WARN_LEVELS,
  type AlertSeverity,
  type PolicyDisposition,
  type PolicyMessageDirection,
  type UrlRewriteFallback,
  type WarnLevel,
} from './vocabulary';

/**
 * Per-recipient evaluation (step 5.3 Q4, ADR-0046 decision 2) and the delivery edits of the one
 * delivered copy (Q4.5) and of a release copy (Q13.6). Pure: the evaluator runs once for the
 * message (the decision record, unchanged semantics) and, when tenant rules are
 * recipient-scoped, once per recipient on an input restricted to that recipient. The floor and
 * the platform recommendation are message facts, so every per-recipient result is at least the
 * floor (property-tested).
 */

// ---------------------------------------------------------------------------------------------
// Recipient-scoped rules
// ---------------------------------------------------------------------------------------------

const recipientScoped = (node: CompiledNode): boolean =>
  [...leavesOf(node)].some((leaf) => leaf.def.scope === 'recipients');

/**
 * True when an enabled candidate rule of `direction` (or a policy-wide exception of its policy)
 * references `recipient.address`, `recipient.domain`, `recipient.local_part`,
 * `recipient.department` or `recipient.user` in `when` or `unless` (Q4). `recipients.count` is a
 * message fact (unchanged by the restriction) and does not count.
 */
export function snapshotHasRecipientScopedRules(
  compiled: CompiledSnapshot,
  direction: PolicyMessageDirection,
): boolean {
  for (const policy of compiled.policies) {
    if (policy.direction !== 'any' && policy.direction !== direction) continue;
    const candidates = policy.rules.filter((r) => r.enabled && r.directions.includes(direction));
    if (candidates.length === 0) continue;
    if (policy.exceptions.some(recipientScoped)) return true;
    if (candidates.some((r) => recipientScoped(r.when) || r.unless.some(recipientScoped))) {
      return true;
    }
  }
  return false;
}

type InputRecipient = PolicyInput['recipients'][number];

/**
 * The input restricted to one recipient (Q4.3): every field kept, `recipients = [that one]`,
 * `recipientsTruncated = false`, `message.recipientCount` unchanged. A recipient beyond the
 * input's 1 000-recipient window (the release of such an entry) is passed as `recipient`.
 * Throws a RangeError when the recipient is neither in the input nor given.
 */
export function restrictToRecipient(
  input: PolicyInput,
  rcptSeq: number,
  recipient?: InputRecipient,
): PolicyInput {
  const found = input.recipients.find((r) => r.rcptSeq === rcptSeq) ?? recipient;
  if (found === undefined || found.rcptSeq !== rcptSeq) {
    throw new RangeError(`rcptSeq ${rcptSeq} is not a recipient of the input`);
  }
  return { ...input, recipients: [found], recipientsTruncated: false };
}

// ---------------------------------------------------------------------------------------------
// Delivery edits (P9.9 merge rules, Q4.5, Q13.6)
// ---------------------------------------------------------------------------------------------

/** The TAG/WARN/URL_REWRITE edits of one delivered copy (headers from policy data only). */
export interface PolicyDeliveryEdits {
  headers: Array<{ name: typeof POLICY_TAG_HEADER | typeof POLICY_WARNING_HEADER; value: string }>;
  subjectPrefix: string | null;
  /** Every TAG label (sorted, ≤ 8), header or not. */
  tagLabels: string[];
  /** The WARN body banner to insert (Q22): strongest level, first text. */
  banner: { level: WarnLevel; text: string | null } | null;
  /** URL_REWRITE (Q23): the strictest fallback of the merged rules. */
  urlRewrite: { ifNotRewritten: UrlRewriteFallback } | null;
  ruleRefs: { tag: string[]; warn: string[]; urlRewrite: string[] };
}

/** Non-terminal actions of the message: the copy edits and the side effects (Q4.5). */
export interface MergedDeliveryActions {
  /** Edits of the delivered copy; null when no recipient is delivered. */
  edits: PolicyDeliveryEdits | null;
  /**
   * The `delivery` record for the delivered copy (same shape as `result.delivery`), built from
   * the merged edits and the round's URL rewrite facts; null when no recipient is delivered.
   */
  delivery: PolicyDelivery | null;
  /** ARCHIVE over all recipients (requested once). */
  archive: { ruleRefs: string[] } | null;
  /** ALERT over all recipients (highest severity). */
  alert: { severity: AlertSeverity; notify: boolean; ruleRefs: string[] } | null;
}

const sortedUnique = (values: Iterable<string>): string[] =>
  [...new Set(values)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
const uniqueOrdered = (values: Iterable<string>): string[] => [...new Set(values)];
const strArray = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
const strOrNull = (v: unknown): string | null => (typeof v === 'string' ? v : null);
const capRefs = (refs: Iterable<string>) =>
  uniqueOrdered(refs).slice(0, POLICY_LIMITS.ruleRefsPerAction);

interface ActionSource {
  actions: readonly ResultAction[];
  direction: PolicyMessageDirection;
}

/**
 * Merges the TAG/WARN/URL_REWRITE actions of several results with the P9.9 rules (labels union
 * sorted ≤ 8, first subject prefix with TAG before WARN, strongest WARN level and first text,
 * strictest URL_REWRITE fallback), ignoring applicability. With `settings`, the header labels of
 * platform tags are recomputed from `tagging.*` (P9.11).
 */
function mergeEdits(
  sources: readonly ActionSource[],
  settings: PolicyTenantSettings | null,
): PolicyDeliveryEdits {
  const labels = new Set<string>();
  const headerLabels = new Set<string>();
  let tagPrefix: string | null = null;
  let warnPrefix: string | null = null;
  let warnLevel: WarnLevel | null = null;
  let warnText: string | null = null;
  let fallback: UrlRewriteFallback | null = null;
  const tagRefs: string[] = [];
  const warnRefs: string[] = [];
  const rewriteRefs: string[] = [];
  for (const source of sources) {
    for (const a of source.actions) {
      switch (a.type) {
        case 'TAG': {
          const own = strArray(a.params.labels);
          for (const l of own) labels.add(l);
          const platform = a.origin !== 'tenant_rule';
          const headers =
            platform && settings !== null
              ? (
                  source.direction === 'outbound'
                    ? settings.tagging.platformTagOutbound
                    : settings.tagging.platformTagHeader
                )
                ? own
                : []
              : strArray(a.params.headerLabels);
          for (const l of headers) headerLabels.add(l);
          if (!platform) tagPrefix ??= strOrNull(a.params.subjectPrefix);
          tagRefs.push(...a.ruleRefs);
          break;
        }
        case 'WARN': {
          const level = a.params.level as WarnLevel;
          if (WARN_LEVELS.includes(level)) {
            warnLevel =
              warnLevel === null || WARN_LEVELS.indexOf(level) > WARN_LEVELS.indexOf(warnLevel)
                ? level
                : warnLevel;
          }
          warnText ??= strOrNull(a.params.text);
          warnPrefix ??= strOrNull(a.params.subjectPrefix);
          warnRefs.push(...a.ruleRefs);
          break;
        }
        case 'URL_REWRITE': {
          const fb = a.params.ifNotRewritten === 'quarantine' ? 'quarantine' : 'deliver';
          fallback = fallback === 'quarantine' || fb === 'quarantine' ? 'quarantine' : 'deliver';
          rewriteRefs.push(...a.ruleRefs);
          break;
        }
        default:
          break;
      }
    }
  }
  const headerList = sortedUnique(headerLabels).slice(0, POLICY_LIMITS.tagLabels);
  const headers: PolicyDeliveryEdits['headers'] = [];
  if (headerList.length > 0)
    headers.push({ name: POLICY_TAG_HEADER, value: headerList.join(', ') });
  if (warnLevel !== null) {
    headers.push({
      name: POLICY_WARNING_HEADER,
      value: warnText !== null ? `${warnLevel}; ${warnText}` : warnLevel,
    });
  }
  return {
    headers,
    subjectPrefix: tagPrefix ?? warnPrefix,
    tagLabels: sortedUnique(labels).slice(0, POLICY_LIMITS.tagLabels),
    banner: warnLevel !== null ? { level: warnLevel, text: warnText } : null,
    urlRewrite: fallback !== null ? { ifNotRewritten: fallback } : null,
    ruleRefs: { tag: capRefs(tagRefs), warn: capRefs(warnRefs), urlRewrite: capRefs(rewriteRefs) },
  };
}

/** True when the edits change the delivered copy (headers, prefix, banner or URL rewriting). */
export const hasDeliveryEdits = (edits: PolicyDeliveryEdits | null): boolean =>
  edits !== null &&
  (edits.headers.length > 0 ||
    edits.subjectPrefix !== null ||
    edits.banner !== null ||
    edits.urlRewrite !== null);

/**
 * The TAG/WARN/URL_REWRITE edits `result` would apply **if** its disposition were allow (P9.9–
 * P9.11 ignoring applicability): the edits of a release copy (Q13.6). Platform tag headers follow
 * `settings.tagging` for the result's direction.
 */
export function releaseDeliveryEdits(
  result: Pick<PolicyEvaluationResult, 'actions' | 'round'>,
  settings: PolicyTenantSettings,
): PolicyDeliveryEdits {
  return mergeEdits([{ actions: result.actions, direction: result.round.direction }], settings);
}

function sideEffects(results: readonly PolicyEvaluationResult[]): {
  archive: MergedDeliveryActions['archive'];
  alert: MergedDeliveryActions['alert'];
} {
  const archiveRefs: string[] = [];
  let archive = false;
  let severity: AlertSeverity | null = null;
  let notify = false;
  const alertRefs: string[] = [];
  for (const r of results) {
    for (const a of r.actions) {
      if (a.type === 'ARCHIVE') {
        archive = true;
        archiveRefs.push(...a.ruleRefs);
      } else if (a.type === 'ALERT') {
        const s = a.params.severity as AlertSeverity;
        if (ALERT_SEVERITIES.includes(s)) {
          severity =
            severity === null || ALERT_SEVERITIES.indexOf(s) > ALERT_SEVERITIES.indexOf(severity)
              ? s
              : severity;
        }
        notify = notify || a.params.notify === true;
        alertRefs.push(...a.ruleRefs);
      }
    }
  }
  return {
    archive: archive ? { ruleRefs: capRefs(archiveRefs) } : null,
    alert: severity !== null ? { severity, notify, ruleRefs: capRefs(alertRefs) } : null,
  };
}

function mergedActions(
  delivered: readonly PolicyEvaluationResult[],
  all: readonly PolicyEvaluationResult[],
): MergedDeliveryActions {
  const { archive, alert } = sideEffects(all);
  if (delivered.length === 0) return { edits: null, delivery: null, archive, alert };
  const edits = mergeEdits(
    delivered.map((r) => ({ actions: r.actions, direction: r.round.direction })),
    null,
  );
  const facts = delivered[0]!.delivery?.urlRewrite;
  const delivery: PolicyDelivery = {
    headers: edits.headers,
    subjectPrefix: edits.subjectPrefix,
    bodyBanner: edits.banner !== null ? 'requested' : null,
    urlRewrite: {
      required: edits.urlRewrite !== null,
      rewritten: facts?.rewritten ?? false,
      skipReason: facts?.skipReason ?? null,
      policyRewritable: facts?.policyRewritable ?? false,
      policyAttempt: null,
    },
  };
  return { edits, delivery, archive, alert };
}

// ---------------------------------------------------------------------------------------------
// Per-recipient evaluation (Q4)
// ---------------------------------------------------------------------------------------------

/**
 * Why the message was (not) evaluated per recipient. Metric `policy_recipient_split_total{result}`
 * uses `split`, `uniform`, `not_scoped` (also for `single_recipient`), `disabled`, `too_many`
 * (also for `truncated`).
 */
export const SPLIT_OUTCOMES = [
  'split',
  'uniform',
  'not_scoped',
  'disabled',
  'single_recipient',
  'truncated',
  'too_many',
] as const;
export type SplitOutcome = (typeof SPLIT_OUTCOMES)[number];

export interface SplitCounts {
  allowed: number;
  held: number;
  review: number;
  rejected: number;
}

export interface PerRecipientEvaluation {
  /** The recipients were decided differently. */
  split: boolean;
  uniform: boolean;
  outcome: SplitOutcome;
  /**
   * The message-level evaluation (the decision record stored in the row). When the message was
   * evaluated per recipient (or deliberately not), its reason codes carry the `policy.split.*`
   * code and, when evaluated per recipient, its explanation a `split` line (counts only).
   */
  message: PolicyEvaluationResult;
  /** Per-recipient results by ascending rcptSeq; null when not evaluated per recipient. */
  recipients: Array<{ rcptSeq: number; result: PolicyEvaluationResult }> | null;
  /** One entry per evaluated recipient (≤ 200); empty when not evaluated per recipient. */
  recipientDecisions: RecipientDecision[];
  /** Counts of the evaluated recipients; null when not evaluated per recipient. */
  counts: SplitCounts | null;
  /**
   * The disposition that drives the message lifecycle (Q4.4, Q5): not split → the (uniform)
   * disposition of every recipient (may differ from `message.disposition` for quantifier-`all`
   * rules); split → allow when a recipient is allowed, else quarantine when one is quarantined,
   * else require_approval.
   */
  lifecycleDisposition: PolicyDisposition;
  /** Q4.5: edits of the delivered copy (allowed recipients) and ARCHIVE/ALERT (all recipients). */
  mergedDeliveryActions: MergedDeliveryActions;
}

const SPLIT_CODE: Partial<Record<SplitOutcome, PolicySplitCode>> = {
  split: 'policy.split.applied',
  uniform: 'policy.split.uniform',
  too_many: 'policy.split.too_many_recipients',
  truncated: 'policy.split.recipients_truncated',
  disabled: 'policy.split.disabled',
};

const ruleRefOf = (r: PolicyEvaluationResult): string | null =>
  r.decisive.source === 'tenant_rule' &&
  r.decisive.policyPublicId !== null &&
  r.decisive.versionNo !== null &&
  r.decisive.ruleId !== null
    ? `${r.decisive.policyPublicId}#${r.decisive.versionNo}/${r.decisive.ruleId}`
    : null;

function decisionOf(rcptSeq: number, r: PolicyEvaluationResult): RecipientDecision {
  return {
    rcptSeq,
    disposition: r.disposition,
    source: r.decisive.source,
    decisiveRuleRef: ruleRefOf(r),
    reasonCodes: r.reasonCodes.slice(0, POLICY_LIMITS.recipientDecisionReasonCodes),
  };
}

/** Adds the split code and (when counted) the `split` explanation line to the decision record. */
function annotate(
  message: PolicyEvaluationResult,
  code: PolicySplitCode | undefined,
  counts: SplitCounts | null,
): PolicyEvaluationResult {
  if (code === undefined && counts === null) return message;
  const reasonCodes =
    code === undefined
      ? message.reasonCodes
      : uniqueOrdered([...message.reasonCodes, code]).slice(0, POLICY_LIMITS.reasonCodes);
  let explanation = message.explanation;
  if (counts !== null) {
    const lines = message.explanation.lines;
    const last = lines[lines.length - 1];
    const head = last?.code === 'snapshot' ? lines.slice(0, -1) : lines;
    const tail = last?.code === 'snapshot' ? [last] : [];
    const splitLine: ExplanationLine = { code: 'split', params: { ...counts } };
    const room = POLICY_LIMITS.explanationLines - 1 - tail.length;
    const next = [...head.slice(0, room), splitLine, ...tail];
    explanation = { lines: next, text: renderExplanation(next) };
  }
  return { ...message, reasonCodes, explanation };
}

const countsOf = (results: readonly PolicyEvaluationResult[]): SplitCounts => {
  const c: SplitCounts = { allowed: 0, held: 0, review: 0, rejected: 0 };
  for (const r of results) {
    if (r.disposition === 'allow') c.allowed += 1;
    else if (r.disposition === 'quarantine') c.held += 1;
    else if (r.disposition === 'require_approval') c.review += 1;
    else c.rejected += 1;
  }
  return c;
};

/**
 * Q4: evaluates the message and, when the tenant's recipient-scoped rules make it meaningful,
 * each recipient on an input restricted to it. No split when `recipientSplit` is off, no rule is
 * recipient-scoped, there is at most one recipient, the recipient list is truncated, or there
 * are more than `POLICY_LIMITS.splitRecipients` recipients.
 */
export function evaluatePolicyPerRecipient(
  input: PolicyInput,
  compiled: CompiledSnapshot,
): PerRecipientEvaluation {
  const raw = evaluatePolicy(input, compiled);
  const scoped = snapshotHasRecipientScopedRules(compiled, input.direction);
  let outcome: SplitOutcome | null = null;
  if (!compiled.settings.recipientSplit) outcome = 'disabled';
  else if (!scoped) outcome = 'not_scoped';
  else if (input.recipients.length <= 1) outcome = 'single_recipient';
  else if (input.recipientsTruncated) outcome = 'truncated';
  else if (input.recipients.length > POLICY_LIMITS.splitRecipients) outcome = 'too_many';

  if (outcome !== null) {
    const message = annotate(raw, scoped ? SPLIT_CODE[outcome] : undefined, null);
    return {
      split: false,
      uniform: true,
      outcome,
      message,
      recipients: null,
      recipientDecisions: [],
      counts: null,
      lifecycleDisposition: message.disposition,
      mergedDeliveryActions: mergedActions(message.disposition === 'allow' ? [message] : [], [
        message,
      ]),
    };
  }

  const ordered = [...input.recipients].sort((a, b) => a.rcptSeq - b.rcptSeq);
  const recipients = ordered.map((r) => ({
    rcptSeq: r.rcptSeq,
    result: evaluatePolicy(restrictToRecipient(input, r.rcptSeq), compiled),
  }));
  const results = recipients.map((r) => r.result);
  const distinct = new Set(results.map((r) => r.disposition));
  const split = distinct.size > 1;
  const counts = countsOf(results);
  let lifecycleDisposition: PolicyDisposition;
  if (!split) {
    lifecycleDisposition = results.reduce<PolicyDisposition>(
      (acc, r) => (dispositionRank(r.disposition) > dispositionRank(acc) ? r.disposition : acc),
      'allow',
    );
  } else if (counts.allowed > 0) lifecycleDisposition = 'allow';
  else if (counts.held > 0) lifecycleDisposition = 'quarantine';
  else lifecycleDisposition = 'require_approval';
  const message = annotate(raw, SPLIT_CODE[split ? 'split' : 'uniform'], counts);
  return {
    split,
    uniform: !split,
    outcome: split ? 'split' : 'uniform',
    message,
    recipients,
    recipientDecisions: recipients.map((r) => decisionOf(r.rcptSeq, r.result)),
    counts,
    lifecycleDisposition,
    mergedDeliveryActions: mergedActions(
      results.filter((r) => r.disposition === 'allow'),
      results,
    ),
  };
}

/**
 * The result that decides one recipient: its own result when evaluated per recipient, else the
 * message result.
 */
export function resultForRecipient(
  evaluation: PerRecipientEvaluation,
  rcptSeq: number,
): PolicyEvaluationResult {
  return evaluation.recipients?.find((r) => r.rcptSeq === rcptSeq)?.result ?? evaluation.message;
}

/** One recipient's decision (from the list, or derived from the message result). */
export function recipientDecisionFor(
  evaluation: PerRecipientEvaluation,
  rcptSeq: number,
): RecipientDecision {
  return (
    evaluation.recipientDecisions.find((d) => d.rcptSeq === rcptSeq) ??
    decisionOf(rcptSeq, evaluation.message)
  );
}

/** The 5.3 `policy_execution_logs` columns (Q4, §3.10). */
export function perRecipientToRowFields(evaluation: PerRecipientEvaluation): {
  recipientSplit: boolean;
  recipientDecisions: RecipientDecision[] | null;
} {
  return {
    recipientSplit: evaluation.split,
    recipientDecisions: evaluation.recipients === null ? null : evaluation.recipientDecisions,
  };
}
