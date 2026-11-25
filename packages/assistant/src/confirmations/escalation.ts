import type { OperationTool } from '../registry/types';
import { canonicalJson } from './canonical';
import { valueAtPath } from './digest';
import type { ConfirmationSnapshot, ConfirmationSpec } from './specs';
import { CONFIRMATION_RISKS, type ConfirmationRisk } from './types';

/**
 * Conditional risk escalation (step AI-3 D4, ADR-0093 amendment AI-3 (k)): an otherwise low or
 * medium change becomes riskier when the final arguments touch a dangerous field (a webhook's
 * URL, an SMTP connector's networks, the organization's MFA requirement, …). The stored
 * confirmation risk is the effective risk (`requires_reauth = risk === 'high'`); the digest binds
 * it and the confirm route recomputes it from the stored arguments, refusing a difference.
 *
 * Step AI-5 (design 33 D3, ADR-0093 amendment AI-5 (v)) adds three read-relative kinds that
 * compare an argument with the precondition read (the confirmation snapshot, keyed by field
 * path): `below` (a shortening), `becomes` (a switch to a value) and `differs` (any change). They
 * fail closed: a missing or `null` read value, a non-number for `below`, or a snapshot string
 * that no longer parses for `differs` (a list or object cut by the snapshot caps) counts as a
 * match, and so does a missing snapshot. The compared `field` must be one of the spec's state
 * fields (registry consistency), so the confirm-time state digest proves the value unchanged.
 */

export type EscalationCondition =
  /** The argument path is present (not `undefined`; an explicit `null` is present). */
  | { present: string }
  /** The argument at the path strictly equals the value (`null` matches only an explicit null). */
  | { equals: { path: string; value: string | number | boolean | null } }
  /**
   * The (numeric) argument is lower than the read's number (a shortening). `absentAs` stands in
   * for an absent argument (a `PUT` default); an absent argument without it never matches.
   */
  | { below: { path: string; field: string; absentAs?: number } }
  /** The argument equals `value` and the read's value does not (a switch to `value`). */
  | {
      becomes: {
        path: string;
        field: string;
        value: string | number | boolean | null;
        absentAs?: string | number | boolean | null;
      };
    }
  /** The argument differs from the read's value (canonical JSON; arrays keep their order). */
  | { differs: { path: string; field: string; absentAs?: unknown } };

/** The read-relative condition kinds (step AI-5 D3). */
export type ReadRelativeCondition = Extract<
  EscalationCondition,
  { below: unknown } | { becomes: unknown } | { differs: unknown }
>;

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

/** The read-relative part of a condition (`{ path, field, absentAs? }`), or null. */
export function readRelativeOf(
  condition: EscalationCondition,
): { kind: 'below' | 'becomes' | 'differs'; path: string; field: string } | null {
  if ('below' in condition) return { kind: 'below', ...condition.below };
  if ('becomes' in condition) return { kind: 'becomes', ...condition.becomes };
  if ('differs' in condition) return { kind: 'differs', ...condition.differs };
  return null;
}

/** The argument path a condition reads. */
export function escalationPath(condition: EscalationCondition): string {
  if ('present' in condition) return condition.present;
  if ('equals' in condition) return condition.equals.path;
  return readRelativeOf(condition)!.path;
}

/** The read field (snapshot key) a read-relative condition compares with, else null. */
export function escalationField(condition: EscalationCondition): string | null {
  return readRelativeOf(condition)?.field ?? null;
}

const hasOwn = (value: object, key: string): boolean =>
  Object.prototype.hasOwnProperty.call(value, key);

/**
 * The argument of a read-relative condition: the value at the path, else `absentAs` when given;
 * `{ present: false }` when the path is absent and there is no `absentAs` (never matches).
 */
function argumentOf(
  args: Readonly<Record<string, unknown>>,
  path: string,
  spec: object,
): { present: true; value: unknown } | { present: false } {
  const value = valueAtPath(args, path);
  if (value !== undefined) return { present: true, value };
  if (hasOwn(spec, 'absentAs'))
    return { present: true, value: (spec as { absentAs?: unknown }).absentAs };
  return { present: false };
}

/**
 * The snapshot value as a JSON value for `differs`: a string starting with `{` or `[` is parsed
 * (the snapshot keeps lists and objects as JSON text); `undefined` when it no longer parses (cut
 * by `SNAPSHOT_LIST_MAX_CHARS` / `SNAPSHOT_STRING_MAX_CHARS`).
 */
function snapshotJson(value: string | number | boolean): unknown {
  if (typeof value !== 'string' || !/^[[{]/.test(value)) return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return undefined;
  }
}

function canonicalOrNull(value: unknown): string | null {
  try {
    return canonicalJson(value);
  } catch {
    return null;
  }
}

/**
 * Whether the condition holds for the final arguments and the precondition snapshot (`null` or
 * omitted: no snapshot, so every read-relative condition matches; fail closed).
 */
export function escalationMatches(
  condition: EscalationCondition,
  args: Readonly<Record<string, unknown>>,
  snapshot?: Readonly<ConfirmationSnapshot> | null,
): boolean {
  if ('present' in condition) return valueAtPath(args, condition.present) !== undefined;
  if ('equals' in condition)
    return valueAtPath(args, condition.equals.path) === condition.equals.value;
  const rel = readRelativeOf(condition)!;
  const spec =
    'below' in condition
      ? condition.below
      : 'becomes' in condition
        ? condition.becomes
        : condition.differs;
  const argument = argumentOf(args, rel.path, spec);
  if (!argument.present) return false;
  if ('becomes' in condition && argument.value !== condition.becomes.value) return false;
  // Fail closed: no snapshot, or a missing / null read value.
  const read = snapshot && hasOwn(snapshot, rel.field) ? snapshot[rel.field] : null;
  if (read === null || read === undefined) return true;
  if ('below' in condition) {
    if (typeof read !== 'number' || !Number.isFinite(read)) return true;
    const value = argument.value;
    // A non-number argument is the schema check's job; treated as a match (fail closed).
    if (typeof value !== 'number' || !Number.isFinite(value)) return true;
    return value < read;
  }
  if ('becomes' in condition) return read !== condition.becomes.value;
  const parsed = snapshotJson(read);
  if (parsed === undefined) return true;
  const a = canonicalOrNull(argument.value);
  const b = canonicalOrNull(parsed);
  return a === null || b === null || a !== b;
}

/** `max(a, b)` in the order low < medium < high. */
export function maxRisk(a: ConfirmationRisk, b: ConfirmationRisk): ConfirmationRisk {
  return RISK_ORDER[b] > RISK_ORDER[a] ? b : a;
}

/**
 * The effective risk: the tool's registry risk raised by every matching escalation of the spec,
 * with the matching warnings. `snapshot` is the precondition snapshot (`buildSnapshot`, keys =
 * field paths) that read-relative conditions compare with (step AI-5 D3): the proposer passes the
 * proposal's snapshot, the confirm route the stored one. It is optional so callers of earlier
 * steps keep compiling; omitted or `null`, every read-relative condition matches (fail closed),
 * which can only raise the risk. Throws for a tool whose registry risk is not confirmable (`read`,
 * `critical`): the executor refuses such a tool before it gets here (`denied_disabled`).
 */
export function effectiveRisk(
  tool: Pick<OperationTool, 'name' | 'risk'>,
  spec: Pick<ConfirmationSpec, 'escalate'> | null | undefined,
  finalArgs: Readonly<Record<string, unknown>>,
  snapshot?: Readonly<ConfirmationSnapshot> | null,
): EffectiveRisk {
  if (!isConfirmationRisk(tool.risk))
    throw new TypeError(`effectiveRisk: ${tool.name} has the non-confirmable risk ${tool.risk}`);
  const base = tool.risk;
  let risk = base;
  const warnings: string[] = [];
  for (const escalation of spec?.escalate ?? []) {
    if (!escalationMatches(escalation.when, finalArgs, snapshot)) continue;
    risk = maxRisk(risk, escalation.risk);
    if (!warnings.includes(escalation.warning)) warnings.push(escalation.warning);
  }
  return { risk, warnings, escalatedFrom: risk === base ? null : base };
}

/**
 * Short matrix note of an escalation (`↑ high when body.url`; read-relative: `↑ high when
 * body.retentionDays < retentionDays`, `… body.onExpiry → delete`, `… body.criteria ≠ criteria`).
 */
export function escalationNote(escalation: RiskEscalation): string {
  const when = escalation.when;
  const condition =
    'present' in when
      ? when.present
      : 'equals' in when
        ? `${when.equals.path} = ${String(when.equals.value)}`
        : 'below' in when
          ? `${when.below.path} < ${when.below.field}`
          : 'becomes' in when
            ? `${when.becomes.path} → ${String(when.becomes.value)}`
            : `${when.differs.path} ≠ ${when.differs.field}`;
  return `↑ ${escalation.risk} when ${condition}`;
}
