import {
  buildSyntheticInput,
  canonicalJson,
  compileSnapshot,
  evaluatePolicy,
  sha256Hex,
  type PolicyEvaluationResult,
  type PolicyInput,
  type SyntheticFacts,
} from '@email-gateway/policy-dsl';

/** Test support: real policy evaluations over synthetic facts. */

export const PID = '01930000-0000-7000-8000-00000000000a';

export function evaluate(
  facts: SyntheticFacts,
  rules: unknown[] = [],
  settings: unknown = null,
): { result: PolicyEvaluationResult; input: PolicyInput } {
  const definition = { dslVersion: 'policy-dsl/1', direction: 'any', priority: 1, rules };
  const compiled = compileSnapshot({
    generation: '3',
    settings,
    platformDefaultId: 'pol-default/1',
    policies:
      rules.length === 0
        ? []
        : [
            {
              publicId: PID,
              versionNo: 1,
              definition,
              definitionSha256: sha256Hex(canonicalJson(definition)),
            },
          ],
  });
  if (compiled.invalid.length > 0) throw new Error(JSON.stringify(compiled.invalid));
  const input = buildSyntheticInput(facts);
  return { result: evaluatePolicy(input, compiled), input };
}

export const always = { field: 'risk.present', op: 'is', value: true };

export const rule = (id: string, when: unknown, actions: unknown[]) => ({
  id,
  priority: 1,
  when,
  actions,
});

export const rev = (
  recommendedAction: 'deliver' | 'tag' | 'require_approval' | 'quarantine' | 'block',
  extra: Record<string, unknown> = {},
) => ({
  recommendedAction,
  level: (
    {
      deliver: 'none',
      tag: 'medium',
      require_approval: 'high',
      quarantine: 'high',
      block: 'critical',
    } as const
  )[recommendedAction],
  score: { deliver: 0, tag: 350, require_approval: 600, quarantine: 650, block: 900 }[
    recommendedAction
  ],
  ...extra,
});
