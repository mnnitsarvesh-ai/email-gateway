import type { OperationTool } from '../registry/types';
import { valueAtPath } from './digest';
import type { ConfirmationSpec } from './specs';
import { CONFIRMATION_RISKS, type ConfirmationRisk } from './types';

/**
 * Conditional risk escalation (step AI-3 D4, ADR-0093 amendment AI-3 (k)): an otherwise low or
 * medium change becomes riskier when the final arguments touch a dangerous field (a webhook's
 * URL, an SMTP connector's networks, the organization's MFA requirement, …). The stored
 * confirmation risk is the effective risk (`requires_reauth = risk === 'high'`); the digest binds
 * it and the confirm route recomputes it from the stored arguments, refusing a difference.
 */

export type EscalationCondition =
  /** The argument path is present (not `undefined`; an explicit `null` is present). */
  | { present: string }
  /** The argument at the path strictly equals the value (`null` matches only an explicit null). */
  | { equals: { path: string; value: string | number | boolean | null } };

export interface RiskEscalation {
  when: EscalationCondition;
  risk: 'medium' | 'high';
  /** Fixed English, appended to the summary's warnings (`ImpactInput.escalationWarnings`). */
  warning: string;
}

export interface EffectiveRisk {
  risk: ConfirmationRisk;
  /** The warnings of the matching escalations, deduplicated, in the spec's order. */
  warnings: string[];
  /** The registry risk when an escalation raised it, else null. */
  escalatedFrom: ConfirmationRisk | null;
}

const RISK_ORDER: Readonly<Record<ConfirmationRisk, number>> = { low: 0, medium: 1, high: 2 };

const isConfirmationRisk = (risk: string): risk is ConfirmationRisk =>
  (CONFIRMATION_RISKS as readonly string[]).includes(risk);

/** The argument path a condition reads. */
export function escalationPath(condition: EscalationCondition): string {
  return 'present' in condition ? condition.present : condition.equals.path;
}

/** Whether the condition holds for the final arguments. */
export function escalationMatches(
  condition: EscalationCondition,
  args: Readonly<Record<string, unknown>>,
): boolean {
  if ('present' in condition) return valueAtPath(args, condition.present) !== undefined;
  return valueAtPath(args, condition.equals.path) === condition.equals.value;
}

/** `max(a, b)` in the order low < medium < high. */
export function maxRisk(a: ConfirmationRisk, b: ConfirmationRisk): ConfirmationRisk {
  return RISK_ORDER[b] > RISK_ORDER[a] ? b : a;
}

/**
 * The effective risk: the tool's registry risk raised by every matching escalation of the spec,
 * with the matching warnings. Throws for a tool whose registry risk is not confirmable (`read`,
 * `critical`): the executor refuses such a tool before it gets here (`denied_disabled`).
 */
export function effectiveRisk(
  tool: Pick<OperationTool, 'name' | 'risk'>,
  spec: Pick<ConfirmationSpec, 'escalate'> | null | undefined,
  finalArgs: Readonly<Record<string, unknown>>,
): EffectiveRisk {
  if (!isConfirmationRisk(tool.risk))
    throw new TypeError(`effectiveRisk: ${tool.name} has the non-confirmable risk ${tool.risk}`);
  const base = tool.risk;
  let risk = base;
  const warnings: string[] = [];
  for (const escalation of spec?.escalate ?? []) {
    if (!escalationMatches(escalation.when, finalArgs)) continue;
    risk = maxRisk(risk, escalation.risk);
    if (!warnings.includes(escalation.warning)) warnings.push(escalation.warning);
  }
  return { risk, warnings, escalatedFrom: risk === base ? null : base };
}

/** Short matrix note of an escalation (`↑ high when body.url`). */
export function escalationNote(escalation: RiskEscalation): string {
  const when = escalation.when;
  const condition =
    'present' in when ? when.present : `${when.equals.path} = ${String(when.equals.value)}`;
  return `↑ ${escalation.risk} when ${condition}`;
}
