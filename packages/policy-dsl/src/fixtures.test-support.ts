import { canonicalJson, sha256Hex } from '@email-gateway/risk-scoring';
import { evaluatePolicy } from './evaluate';
import { policyEvaluationResultSchema, type PolicyEvaluationResult } from './result';
import { compileSnapshot, type CompiledSnapshot } from './snapshot';
import { buildSyntheticInput, type SyntheticFacts } from './synthetic';
import type { PolicyInput } from './input';
import { POLICY_FIELDS } from './fields';

/**
 * Test support: policy ids, a snapshot builder over plain definitions, synthetic inputs and an
 * evaluation helper that also asserts the result against the strict schema.
 */

export const PID = {
  a: '01930000-0000-7000-8000-00000000000a',
  b: '01930000-0000-7000-8000-00000000000b',
  c: '01930000-0000-7000-8000-00000000000c',
  d: '01930000-0000-7000-8000-00000000000d',
} as const;

export const DEPT = {
  finance: '01930000-0000-7000-8000-0000000000f1',
  legal: '01930000-0000-7000-8000-0000000000f2',
  sales: '01930000-0000-7000-8000-0000000000f3',
} as const;

export const USER = {
  ceo: '01930000-0000-7000-8000-0000000000e1',
} as const;

export type Def = Record<string, unknown>;

/** A policy document with defaults (`direction: any`, `priority: 100`). */
export function policy(rules: unknown[], extra: Record<string, unknown> = {}): Def {
  return { dslVersion: 'policy-dsl/1', direction: 'any', priority: 100, rules, ...extra };
}

/** A rule with defaults (`id: r<priority>`). */
export function rule(
  priority: number,
  when: unknown,
  actions: unknown[],
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return { id: `r${priority}`, priority, when, actions, ...extra };
}

export const leaf = (field: string, op: string, value?: unknown, quantifier?: 'any' | 'all') => ({
  field,
  op,
  ...(value === undefined ? {} : { value }),
  ...(quantifier === undefined ? {} : { quantifier }),
});

export interface SnapshotOptions {
  settings?: unknown;
  generation?: string;
  platformDefaultId?: string;
}

export function snapshotOf(
  defs: ReadonlyArray<Def | { def: Def; publicId?: string; versionNo?: number }>,
  options: SnapshotOptions = {},
): CompiledSnapshot {
  const ids = Object.values(PID);
  return compileSnapshot({
    generation: options.generation ?? '1',
    settings: options.settings ?? null,
    platformDefaultId: options.platformDefaultId ?? 'pol-default/1',
    policies: defs.map((d, i) => {
      const entry =
        'def' in d ? (d as { def: Def; publicId?: string; versionNo?: number }) : { def: d };
      return {
        publicId: entry.publicId ?? ids[i]!,
        versionNo: entry.versionNo ?? 1,
        definition: entry.def,
        definitionSha256: sha256Hex(canonicalJson(entry.def)),
      };
    }),
  });
}

export const input = (facts: SyntheticFacts = {}): PolicyInput => buildSyntheticInput(facts);

/** Evaluates and validates the result against the strict schema. */
export function run(
  facts: SyntheticFacts,
  defs: ReadonlyArray<Def | { def: Def; publicId?: string; versionNo?: number }> = [],
  options: SnapshotOptions = {},
): PolicyEvaluationResult {
  const compiled = snapshotOf(defs, options);
  if (compiled.invalid.length > 0) {
    throw new Error(`invalid test policy: ${JSON.stringify(compiled.invalid[0]!.violations)}`);
  }
  const result = evaluatePolicy(input(facts), compiled);
  policyEvaluationResultSchema.parse(result);
  return result;
}

/** Risk facts for a synthetic revision. */
export const risk = (
  recommendedAction: 'deliver' | 'tag' | 'require_approval' | 'quarantine' | 'block',
  extra: Record<string, unknown> = {},
) => {
  const level = (
    {
      deliver: 'none',
      tag: 'medium',
      require_approval: 'high',
      quarantine: 'high',
      block: 'critical',
    } as const
  )[recommendedAction];
  return {
    recommendedAction,
    level,
    score: { none: 0, medium: 350, high: 600, critical: 850 }[level],
    ...extra,
  };
};

export const actionOf = (r: PolicyEvaluationResult, type: string, origin?: string) =>
  r.actions.find((a) => a.type === type && (origin === undefined || a.origin === origin));

/** A valid value for `field` × `op` (exact shapes the validator accepts). */
export function sampleValue(field: string, op: string): unknown {
  const def = POLICY_FIELDS[field as keyof typeof POLICY_FIELDS];
  const scalar = (): unknown => {
    switch (def.type) {
      case 'address':
        return 'user@example.com';
      case 'domain':
        return 'example.com';
      case 'string':
        if (field === 'attachment.sha256') return 'a'.repeat(64);
        if (field === 'attachment.extension') return 'pdf';
        return 'text';
      case 'enum':
        return def.values![0];
      case 'ip':
        return '192.0.2.1';
      case 'id':
        return DEPT.finance;
      default:
        return 'x';
    }
  };
  switch (op) {
    case 'exists':
      return undefined;
    case 'is':
      return true;
    case 'equals':
      return scalar();
    case 'in':
    case 'not_in':
      return [scalar()];
    case 'domain_in':
      return ['example.com'];
    case 'glob':
      return ['*example*'];
    case 'regex':
      return ['^a.*b$'];
    case 'in_cidr':
      return ['192.0.2.0/24'];
    case 'eq':
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte':
      return def.type === 'int' || !def.values ? 1 : (def.values[1] ?? def.values[0]);
    case 'between':
      return [1, 10];
    case 'contains_any':
    case 'contains_all':
      return def.values ? [def.values[0]] : ['spam.gtube'];
    case 'within':
      return field === 'time.window'
        ? { timeZone: 'Asia/Kolkata', days: ['mon'], from: '09:00', to: '17:00' }
        : { timeZone: 'Europe/London', from: '2026-01-01', to: '2026-12-31' };
    default:
      return 'x';
  }
}
