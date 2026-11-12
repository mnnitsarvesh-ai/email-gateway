import { canonicalJson, RISK_ACTIONS, RISK_LEVELS, sha256Hex } from '@email-gateway/risk-scoring';
import type { RiskAction, RiskLevel } from '@email-gateway/risk-scoring';
import {
  buildFacts,
  decisiveRevision,
  evalNode,
  FALSE,
  presentRevisions,
  TRUE,
  type CompiledLeaf,
  type CompiledNode,
  type Facts,
} from './conditions';
import { renderExplanation } from './explanation';
import { applyFloor, computeFloor, decisiveFloorReason, type Floor } from './floor';
import type { PolicyInput } from './input';
import type { PlatformDefault } from './platform';
import type { PolicyDefaultCode } from './reason-codes';
import type { ClampReason, ExplanationLine, PolicyEvaluationResult, ResultAction } from './result';
import type { CompiledRule, CompiledSnapshot } from './snapshot';
import { tzdataVersion } from './time';
import {
  ACTION_OF_DISPOSITION,
  ALERT_SEVERITIES,
  dispositionRank,
  POLICY_DSL_VERSION,
  POLICY_EVALUATOR_VERSION,
  POLICY_HOLD_DISPOSITIONS,
  POLICY_INPUT_VERSION,
  POLICY_LIMITS,
  POLICY_REWRITABLE_SKIP_REASONS,
  POLICY_TAG_HEADER,
  POLICY_WARNING_HEADER,
  WARN_LEVELS,
  type AlertSeverity,
  type DecisionSource,
  type PolicyDisposition,
  type WarnLevel,
} from './vocabulary';

/**
 * The policy evaluator `policy-eval/2` (step 5.2 P9 steps 1–11; ADR-0043 decisions 4–6; step 5.3
 * Q22/Q23: banner request and policy-rewritable URL skips). A pure
 * function of `(PolicyInput, CompiledSnapshot)`: no I/O, no clock, no randomness. The strictness
 * floor (`./floor`) is applied after the tenant rules, the override and the URL_REWRITE raise,
 * so no rule, exception, override or setting can produce a final disposition below it.
 */

type TraceEntry = PolicyEvaluationResult['trace'][number];

interface Recommendation {
  disposition: PolicyDisposition;
  tag: boolean;
  levelOnly: boolean;
  riskAction: RiskAction | null;
  revisions: Array<0 | 1>;
  reason: PolicyDefaultCode;
  maxLevel: RiskLevel | null;
}

/** P9 step 4: the overridable platform recommendation (`pol-default/1` incl. rule D2). */
export function recommendation(input: PolicyInput, pd: PlatformDefault): Recommendation {
  const revs = presentRevisions(input);
  let riskAction: RiskAction | null = null;
  let maxLevel: RiskLevel | null = null;
  for (const { facts } of revs) {
    if (
      riskAction === null ||
      RISK_ACTIONS.indexOf(facts.recommendedAction) > RISK_ACTIONS.indexOf(riskAction)
    ) {
      riskAction = facts.recommendedAction;
    }
    if (maxLevel === null || RISK_LEVELS.indexOf(facts.level) > RISK_LEVELS.indexOf(maxLevel)) {
      maxLevel = facts.level;
    }
  }
  let disposition: PolicyDisposition = riskAction === null ? 'allow' : pd.riskActionMap[riskAction];
  let reason: PolicyDefaultCode =
    riskAction === null ? 'policy.default.risk_absent' : `policy.default.risk_${riskAction}`;
  let levelOnly = revs.length > 0 && revs.every((r) => r.facts.levelOnly);
  const bec = input.bec;
  const d2 = pd.becDeterministicHold;
  if (bec !== null && d2.verdicts.includes(bec.deterministicVerdict)) {
    if (dispositionRank(d2.disposition) > dispositionRank(disposition)) {
      disposition = d2.disposition;
      reason = 'policy.default.bec_deterministic';
    }
    if (!d2.levelOnlyVerdicts.includes(bec.deterministicVerdict)) levelOnly = false;
  }
  return {
    disposition,
    tag: riskAction !== null && pd.riskTagActions.includes(riskAction),
    levelOnly,
    riskAction,
    revisions: revs.map((r) => r.revision),
    reason,
    maxLevel,
  };
}

function firstTrue(
  nodes: readonly CompiledNode[],
  facts: Facts,
): { index: number; leaf: CompiledLeaf } | null {
  for (let i = 0; i < nodes.length; i += 1) {
    const r = evalNode(nodes[i]!, facts);
    if (r.value === TRUE) return { index: i, leaf: r.leaf };
  }
  return null;
}

const uniqueOrdered = (values: readonly string[]): string[] => [...new Set(values)];
const sorted = (values: Iterable<string>): string[] =>
  [...new Set(values)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
const strongerWarn = (a: WarnLevel, b: WarnLevel): WarnLevel =>
  WARN_LEVELS.indexOf(b) > WARN_LEVELS.indexOf(a) ? b : a;
const strongerAlert = (a: AlertSeverity, b: AlertSeverity): AlertSeverity =>
  ALERT_SEVERITIES.indexOf(b) > ALERT_SEVERITIES.indexOf(a) ? b : a;
const refs = (rules: readonly CompiledRule[]) =>
  uniqueOrdered(rules.map((r) => r.ref)).slice(0, POLICY_LIMITS.ruleRefsPerAction);

/** Evaluates one input against a compiled snapshot (P9). Never throws for a valid input. */
export function evaluatePolicy(
  input: PolicyInput,
  compiled: CompiledSnapshot,
): PolicyEvaluationResult {
  const pd = compiled.platformDefault;
  const settings = compiled.settings;
  const direction = input.direction;
  const facts = buildFacts(input);

  // 1–2. Candidate rules in order; policy-wide exceptions, when, unless, stop.
  const trace: TraceEntry[] = [];
  let traceTruncated = false;
  const pushTrace = (entry: TraceEntry) => {
    if (trace.length < POLICY_LIMITS.trace) trace.push(entry);
    else traceTruncated = true;
  };
  const matched: CompiledRule[] = [];
  const excepted: Array<{ ref: string; at: string }> = [];
  let stopped = false;
  for (const policy of compiled.policies) {
    if (policy.direction !== 'any' && policy.direction !== direction) continue;
    let policyException: { index: number; leaf: CompiledLeaf } | null | undefined;
    for (const rule of policy.rules) {
      if (!rule.enabled || !rule.directions.includes(direction)) continue;
      if (stopped) {
        pushTrace({
          ref: rule.ref,
          result: 'not_evaluated',
          at: null,
          path: null,
          field: null,
          op: null,
        });
        continue;
      }
      if (policyException === undefined) policyException = firstTrue(policy.exceptions, facts);
      if (policyException !== null) {
        const at = `policy_exception[${policyException.index}]`;
        excepted.push({ ref: rule.ref, at });
        pushTrace({
          ref: rule.ref,
          result: 'excepted',
          at,
          path: policyException.leaf.path,
          field: policyException.leaf.field,
          op: policyException.leaf.op,
        });
        continue;
      }
      const when = evalNode(rule.when, facts);
      if (when.value !== TRUE) {
        pushTrace({
          ref: rule.ref,
          result: when.value === FALSE ? 'not_matched' : 'unknown',
          at: 'when',
          path: when.leaf.path,
          field: when.leaf.field,
          op: when.leaf.op,
        });
        continue;
      }
      const unless = firstTrue(rule.unless, facts);
      if (unless !== null) {
        const at = `unless[${unless.index}]`;
        excepted.push({ ref: rule.ref, at });
        pushTrace({
          ref: rule.ref,
          result: 'excepted',
          at,
          path: unless.leaf.path,
          field: unless.leaf.field,
          op: unless.leaf.op,
        });
        continue;
      }
      pushTrace({
        ref: rule.ref,
        result: 'matched',
        at: 'when',
        path: when.leaf.path,
        field: when.leaf.field,
        op: when.leaf.op,
      });
      matched.push(rule);
      if (rule.stop) stopped = true;
    }
  }

  // 3. Tenant disposition: strictest of matched; decisive = first rule carrying it.
  const clamps: Array<{
    ref: string;
    from: PolicyDisposition;
    to: PolicyDisposition;
    reason: ClampReason;
  }> = [];
  const aiClamped = new Set<CompiledRule>();
  let tenant: PolicyDisposition | null = null;
  let tenantRule: CompiledRule | null = null;
  for (const rule of matched) {
    const d = rule.disposition;
    if (d === null) continue;
    if (rule.aiDerived && POLICY_HOLD_DISPOSITIONS.includes(d)) {
      // Refused by the schema (ai_field_in_hold_rule); ignored defensively (P9.8).
      aiClamped.add(rule);
      clamps.push({ ref: rule.ref, from: d, to: 'allow', reason: 'ai_only' });
      continue;
    }
    if (tenant === null || dispositionRank(d) > dispositionRank(tenant)) {
      tenant = d;
      tenantRule = rule;
    }
  }

  // 4–5. Recommendation and floor.
  const rec = recommendation(input, pd);
  const floor: Floor = computeFloor(input, pd);

  // 6. Base disposition (override only with flag + setting + level-only recommendation).
  let base: PolicyDisposition;
  let source: DecisionSource;
  let decisiveRule: CompiledRule | null = null;
  let override: PolicyEvaluationResult['override'] = null;
  if (tenant === null) {
    base = rec.disposition;
    source = 'platform_default';
  } else if (dispositionRank(tenant) >= dispositionRank(rec.disposition)) {
    base = tenant;
    source = 'tenant_rule';
    decisiveRule = tenantRule;
  } else {
    const overrideRule =
      matched.find((r) => r.disposition === tenant && r.override && !aiClamped.has(r)) ?? null;
    const clampReason: ClampReason | null =
      overrideRule === null
        ? 'override_not_allowed'
        : !settings.allowRecommendationOverrides
          ? 'override_disabled'
          : !rec.levelOnly
            ? 'not_level_only'
            : null;
    if (clampReason === null && overrideRule !== null) {
      base = tenant;
      source = 'tenant_rule';
      decisiveRule = overrideRule;
      override = { applied: true, ref: overrideRule.ref, from: rec.disposition, to: tenant };
    } else {
      base = rec.disposition;
      source = 'platform_default';
      clamps.push({
        ref: tenantRule!.ref,
        from: tenant,
        to: rec.disposition,
        reason: clampReason!,
      });
    }
  }

  // 7. Final = max(base, floor).
  let final = base;
  const floored = applyFloor(final, floor);
  if (floored.raised) {
    final = floored.disposition;
    source = 'floor';
    decisiveRule = null;
  }

  // 9. Merge of non-terminal actions in rule order.
  const tenantTag = {
    labels: new Set<string>(),
    header: new Set<string>(),
    prefix: null as string | null,
    rules: [] as CompiledRule[],
  };
  const warn = {
    level: null as WarnLevel | null,
    text: null as string | null,
    prefix: null as string | null,
    rules: [] as CompiledRule[],
  };
  const urlRewrite = {
    fallback: null as 'deliver' | 'quarantine' | null,
    rules: [] as CompiledRule[],
    quarantineRules: [] as CompiledRule[],
    aiRules: [] as CompiledRule[],
  };
  const archive: CompiledRule[] = [];
  const alert = { severity: null as AlertSeverity | null, rules: [] as CompiledRule[] };
  for (const rule of matched) {
    for (const a of rule.nonTerminal) {
      switch (a.type) {
        case 'TAG':
          tenantTag.labels.add(a.label);
          if (a.addHeader !== false) tenantTag.header.add(a.label);
          tenantTag.prefix ??= a.subjectPrefix ?? null;
          tenantTag.rules.push(rule);
          break;
        case 'WARN':
          warn.level = warn.level === null ? a.level : strongerWarn(warn.level, a.level);
          warn.text ??= a.text ?? null;
          warn.prefix ??= a.subjectPrefix ?? null;
          warn.rules.push(rule);
          break;
        case 'URL_REWRITE': {
          const fb = a.ifNotRewritten ?? 'deliver';
          urlRewrite.fallback =
            urlRewrite.fallback === 'quarantine' || fb === 'quarantine' ? 'quarantine' : 'deliver';
          urlRewrite.rules.push(rule);
          // An AI-only signal can tag or warn, never hold (P9.8): the quarantine fallback of a
          // rule reading AI-derived fields never raises (step 5.3 fix, clamp `ai_only`).
          if (fb === 'quarantine' && rule.aiDerived) urlRewrite.aiRules.push(rule);
          else if (fb === 'quarantine') urlRewrite.quarantineRules.push(rule);
          break;
        }
        case 'ARCHIVE':
          archive.push(rule);
          break;
        case 'ALERT':
          alert.severity =
            alert.severity === null ? a.severity : strongerAlert(alert.severity, a.severity);
          alert.rules.push(rule);
          break;
      }
    }
  }

  // URL_REWRITE `ifNotRewritten = quarantine` on a round that was not rewritten. A round skipped
  // only because the tenant's 4.3 setting was off (`disabled`, `direction`) is policy-rewritable
  // (step 5.3 Q23): the policy-engine rewrites the copy itself, so it does not raise here (if the
  // engine's own rewrite skips, it re-evaluates with that skip reason, which then raises).
  const rewritten = input.urls.rewriteStatus === 'rewritten';
  const policyRewritable =
    !rewritten &&
    input.urls.rewriteStatus === 'skipped' &&
    input.urls.rewriteSkipReason !== null &&
    (POLICY_REWRITABLE_SKIP_REASONS as readonly string[]).includes(input.urls.rewriteSkipReason);
  const urlRewriteRequired =
    urlRewrite.quarantineRules.length > 0 && !rewritten && !policyRewritable;
  if (
    urlRewrite.aiRules.length > 0 &&
    !rewritten &&
    !policyRewritable &&
    !urlRewriteRequired &&
    dispositionRank(final) < dispositionRank('quarantine')
  ) {
    clamps.push({
      ref: urlRewrite.aiRules[0]!.ref,
      from: 'quarantine',
      to: final,
      reason: 'ai_only',
    });
  }
  let urlRewriteRaised = false;
  if (urlRewriteRequired && dispositionRank(final) < dispositionRank('quarantine')) {
    final = 'quarantine';
    source = 'tenant_rule';
    decisiveRule = urlRewrite.quarantineRules[0]!;
    urlRewriteRaised = true;
  }
  // The floor again, last, on every path (never weaker than the floor).
  final = applyFloor(final, floor).disposition;

  // Decisive record.
  let decisiveReason: string;
  if (source === 'floor') decisiveReason = decisiveFloorReason(floor)!.code;
  else if (source === 'platform_default') decisiveReason = rec.reason;
  else if (urlRewriteRaised) decisiveReason = 'policy.url_rewrite.required';
  else if (override !== null) decisiveReason = 'policy.override.applied';
  else decisiveReason = 'policy.decision.tenant_rule';
  const decisive: PolicyEvaluationResult['decisive'] =
    source === 'tenant_rule' && decisiveRule !== null
      ? {
          source,
          policyPublicId: decisiveRule.policyPublicId,
          versionNo: decisiveRule.versionNo,
          ruleId: decisiveRule.ruleId,
          reason: decisiveReason,
        }
      : { source, policyPublicId: null, versionNo: null, ruleId: null, reason: decisiveReason };

  // 10–11. Actions, applicability, platform tag suppression, notices.
  const allow = final === 'allow';
  const applicability = (applies: boolean): ResultAction['applicability'] =>
    applies ? 'applies' : 'not_applicable';
  const platformHeaders =
    direction === 'outbound'
      ? settings.tagging.platformTagOutbound
      : settings.tagging.platformTagHeader;
  const codes: string[] = [];
  let senderNotice = false;
  if (final === 'reject' && direction !== 'inbound') {
    const rejectAction =
      decisive.source === 'tenant_rule' && decisiveRule !== null
        ? decisiveRule.actions.find((a) => a.type === 'REJECT')
        : undefined;
    senderNotice =
      rejectAction !== undefined &&
      rejectAction.type === 'REJECT' &&
      rejectAction.notifySender !== undefined
        ? rejectAction.notifySender
        : settings.notices.senderNonDelivery;
  }
  const actions: ResultAction[] = [
    {
      type: ACTION_OF_DISPOSITION[final],
      params: final === 'reject' ? { notifySender: senderNotice } : {},
      origin: source,
      ruleRefs:
        decisive.source === 'tenant_rule' && decisiveRule !== null ? [decisiveRule.ref] : [],
      applicability: 'applies',
    },
  ];
  let labelsTruncated = false;
  const capLabels = (labels: Iterable<string>) => {
    const all = sorted(labels);
    if (all.length > POLICY_LIMITS.tagLabels) labelsTruncated = true;
    return all.slice(0, POLICY_LIMITS.tagLabels);
  };
  if (tenantTag.rules.length > 0) {
    const labels = capLabels(tenantTag.labels);
    actions.push({
      type: 'TAG',
      params: {
        labels,
        headerLabels: labels.filter((l) => tenantTag.header.has(l)),
        subjectPrefix: tenantTag.prefix,
      },
      origin: 'tenant_rule',
      ruleRefs: refs(tenantTag.rules),
      applicability: applicability(allow),
    });
  }
  const platformTag = (labels: string[], origin: 'platform_default' | 'floor') => {
    if (labels.length === 0) return;
    if (!platformHeaders && allow) codes.push('policy.tag.platform_suppressed');
    actions.push({
      type: 'TAG',
      params: { labels, headerLabels: platformHeaders ? labels : [], subjectPrefix: null },
      origin,
      ruleRefs: [],
      applicability: applicability(allow),
    });
  };
  if (rec.tag && override === null && rec.maxLevel !== null) {
    platformTag([`${pd.riskTagPrefix}${rec.maxLevel}`], 'platform_default');
  }
  platformTag(floor.tagLabels, 'floor');
  if (warn.level !== null) {
    actions.push({
      type: 'WARN',
      params: { level: warn.level, text: warn.text, subjectPrefix: warn.prefix },
      origin: 'tenant_rule',
      ruleRefs: refs(warn.rules),
      applicability: applicability(allow),
    });
  }
  if (urlRewrite.fallback !== null) {
    actions.push({
      type: 'URL_REWRITE',
      params: { ifNotRewritten: urlRewrite.fallback, raised: urlRewriteRaised },
      origin: 'tenant_rule',
      ruleRefs: refs(urlRewrite.rules),
      applicability: applicability(allow || urlRewriteRaised),
    });
  }
  if (archive.length > 0) {
    actions.push({
      type: 'ARCHIVE',
      params: {},
      origin: 'tenant_rule',
      ruleRefs: refs(archive),
      applicability: 'applies',
    });
  }
  if (alert.severity !== null) {
    if (!settings.alerts.enabled) codes.push('policy.alert.disabled');
    actions.push({
      type: 'ALERT',
      params: { severity: alert.severity, notify: settings.alerts.enabled },
      origin: 'tenant_rule',
      ruleRefs: refs(alert.rules),
      applicability: 'applies',
    });
  }

  // Delivery edits (allow only), built from policy data only.
  let delivery: PolicyEvaluationResult['delivery'] = null;
  if (allow) {
    const headerLabels = capLabels(
      actions.flatMap((a) =>
        a.type === 'TAG' && Array.isArray(a.params.headerLabels) ? a.params.headerLabels : [],
      ),
    );
    const headers: NonNullable<PolicyEvaluationResult['delivery']>['headers'] = [];
    if (headerLabels.length > 0)
      headers.push({ name: POLICY_TAG_HEADER, value: headerLabels.join(', ') });
    if (warn.level !== null) {
      headers.push({
        name: POLICY_WARNING_HEADER,
        value: warn.text !== null ? `${warn.level}; ${warn.text}` : warn.level,
      });
    }
    delivery = {
      headers,
      subjectPrefix: tenantTag.prefix ?? warn.prefix ?? null,
      bodyBanner: warn.level !== null ? 'requested' : null,
      urlRewrite: {
        required: urlRewrite.fallback !== null,
        rewritten,
        skipReason: input.urls.rewriteSkipReason,
        policyRewritable,
        policyAttempt: null,
      },
    };
  }

  // Reason codes: decisive reason first (rowToEvaluationView relies on it).
  const reasonCodes = uniqueOrdered([
    decisive.reason,
    `policy.decision.${source}`,
    rec.reason,
    ...floor.reasons.map((r) => r.code),
    ...(override !== null ? ['policy.override.applied'] : []),
    ...clamps.map((c) => `policy.clamp.${c.reason}`),
    ...(urlRewriteRequired ? ['policy.url_rewrite.required'] : []),
    ...codes,
    ...(labelsTruncated ? ['policy.tag.labels_truncated'] : []),
    ...(senderNotice ? ['policy.notice.sender_non_delivery'] : []),
    ...(excepted.length > 0 ? ['policy.rule.excepted'] : []),
    ...compiled.reasonCodes,
    ...(traceTruncated ? ['policy.trace.truncated'] : []),
  ]).slice(0, POLICY_LIMITS.reasonCodes);

  // Explanation (fixed templates; ids, refs, enums, codes, integers).
  const lines: ExplanationLine[] = [{ code: 'summary', params: { disposition: final, source } }];
  if (decisive.source === 'tenant_rule' && decisiveRule !== null) {
    lines.push({ code: 'decisive_rule', params: { ref: decisiveRule.ref, disposition: final } });
  }
  lines.push({
    code: 'platform_default',
    params: {
      platformDefault: pd.id,
      disposition: rec.disposition,
      tag: rec.tag ? 'yes' : 'no',
      riskAction: rec.riskAction ?? 'none',
      reason: rec.reason,
    },
  });
  for (const r of floor.reasons) {
    lines.push({ code: 'floor', params: { reason: r.code, disposition: r.disposition } });
  }
  if (override !== null) {
    lines.push({
      code: 'override',
      params: { ref: override.ref, from: override.from, to: override.to },
    });
  }
  for (const c of clamps.slice(0, 4)) {
    lines.push({ code: 'clamp', params: { ref: c.ref, from: c.from, to: c.to, reason: c.reason } });
  }
  for (const e of excepted.slice(0, 3)) lines.push({ code: 'exception', params: e });
  for (const a of actions.slice(1)) {
    lines.push(
      a.applicability === 'applies'
        ? { code: 'action', params: { type: a.type, origin: a.origin } }
        : { code: 'not_applicable', params: { type: a.type, disposition: final } },
    );
  }
  const snapshotLine: ExplanationLine = {
    code: 'snapshot',
    params: {
      generation: compiled.generation,
      policies: compiled.policies.length,
      invalid: compiled.invalid.length,
    },
  };
  const bounded = [...lines.slice(0, POLICY_LIMITS.explanationLines - 1), snapshotLine];

  const revs = presentRevisions(input);
  return {
    status: 'evaluated',
    round: {
      trigger: input.trigger,
      direction,
      lifecycleRound: input.round.lifecycleRound,
      scanId: input.round.scanId,
    },
    disposition: final,
    finalVerdict: decisiveRevision(input)?.verdict ?? 'unknown',
    riskScore: revs.length > 0 ? Math.max(...revs.map((r) => r.facts.score)) : null,
    decisive,
    actions,
    delivery,
    notices: { senderNonDelivery: senderNotice },
    matchedRules: matched.slice(0, POLICY_LIMITS.matchedRules).map((r) => ({
      ref: r.ref,
      policyPublicId: r.policyPublicId,
      versionNo: r.versionNo,
      ruleId: r.ruleId,
      disposition: r.disposition,
      actionTypes: r.actions.map((a) => a.type),
      override: r.override,
    })),
    trace,
    traceTruncated,
    floor: {
      disposition: floor.disposition,
      tag: floor.tagLabels.length > 0,
      reasons: floor.reasons.map((r) => r.code),
    },
    recommendation: {
      disposition: rec.disposition,
      tag: rec.tag,
      levelOnly: rec.levelOnly,
      riskAction: rec.riskAction,
      revisions: rec.revisions,
    },
    override,
    clamps: clamps.slice(0, POLICY_LIMITS.clamps),
    reasonCodes,
    explanation: { lines: bounded, text: renderExplanation(bounded) },
    versions: {
      dsl: POLICY_DSL_VERSION,
      evaluator: POLICY_EVALUATOR_VERSION,
      input: POLICY_INPUT_VERSION,
      platformDefault: compiled.platformDefaultId,
      snapshotSha256: compiled.snapshotSha256,
      generation: compiled.generation,
      tzdata: tzdataVersion(),
      policies: compiled.versions,
    },
    inputSha256: sha256Hex(canonicalJson(input)),
  };
}
