import { normalizeDomainInput } from '@email-gateway/url-security';
import { BEC_SUPPRESSIBLE_CODES, type BecRuleId } from './codes';
import type { FiredRule, RuleEvidence, SuppressionRule } from './types';

/**
 * Feedback suppression at use (B11): only `BEC_SUPPRESSIBLE_CODES`, only unexpired rows, scope
 * `address` (the From address) or `domain` (the From registrable domain; never a free-mail
 * domain, re-checked here although the api refuses it), at most `maxWeight` (40) points
 * suppressed per message, candidates ordered by weight desc then code (greedy, a candidate that
 * would exceed the cap is skipped). Suppressed rules carry `suppressed: 'feedback'` and the
 * suppression id in their evidence; S1 lists the suppressed codes.
 */

export interface SuppressionContext {
  fromAddress: string | null;
  fromReg: string | null;
  fromFreemail: boolean;
  now: Date;
  maxWeight: number;
}

const SUPPRESSIBLE = new Set(BEC_SUPPRESSIBLE_CODES);

export function matchingSuppression(
  rule: Pick<FiredRule, 'code'>,
  suppressions: readonly SuppressionRule[],
  context: Omit<SuppressionContext, 'maxWeight'>,
): SuppressionRule | null {
  if (!SUPPRESSIBLE.has(rule.code)) return null;
  for (const s of suppressions) {
    if (s.reasonCode !== rule.code) continue;
    if (s.expiresAt.getTime() <= context.now.getTime()) continue;
    if (s.senderScope === 'address') {
      if (
        context.fromAddress !== null &&
        s.senderValue.trim().toLowerCase() === context.fromAddress
      )
        return s;
    } else {
      if (context.fromFreemail || context.fromReg === null) continue;
      const normalized = normalizeDomainInput(s.senderValue);
      if (normalized.ok && normalized.registrableDomain === context.fromReg) return s;
    }
  }
  return null;
}

export function applySuppressions(
  fired: Map<BecRuleId, FiredRule>,
  suppressions: readonly SuppressionRule[],
  context: SuppressionContext,
  fire: (id: BecRuleId, evidence: RuleEvidence) => void,
): FiredRule[] {
  const candidates = [...fired.values()]
    .filter((r) => r.suppressed === null && r.weight > 0)
    .map((rule) => ({ rule, suppression: matchingSuppression(rule, suppressions, context) }))
    .filter((c): c is { rule: FiredRule; suppression: SuppressionRule } => c.suppression !== null)
    .sort(
      (a, b) =>
        b.rule.weight - a.rule.weight ||
        (a.rule.code < b.rule.code ? -1 : a.rule.code > b.rule.code ? 1 : 0),
    );
  let total = 0;
  const applied: Array<{ rule: FiredRule; suppression: SuppressionRule }> = [];
  for (const candidate of candidates) {
    if (total + candidate.rule.weight > context.maxWeight) continue;
    total += candidate.rule.weight;
    candidate.rule.suppressed = 'feedback';
    if (candidate.rule.evidence.length >= 5) candidate.rule.evidence.pop();
    candidate.rule.evidence.push({ suppression: { id: candidate.suppression.publicId } });
    applied.push(candidate);
  }
  for (const { rule, suppression } of applied) {
    fire('S1', { suppression: { id: suppression.publicId }, suppressedCodes: [rule.code] });
  }
  return applied.map((a) => a.rule);
}
