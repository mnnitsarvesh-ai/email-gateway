import {
  buildSyntheticInput,
  syntheticFactsSchema,
  validatePolicyDefinition,
} from '@email-gateway/policy-dsl';
import { describe, expect, it } from 'vitest';
import { FAKE_EXECUTABLES_DEFINITION, FAKE_EXECUTABLES_FACTS } from './fake';

/**
 * Design 29 D8 / R8: the fake provider's create-policy plan must not diverge from the real DSL.
 * `@email-gateway/policy-dsl` is a devDependency of this test only (the package itself never
 * imports another workspace package; see dependency-boundary.test.ts).
 */
describe('fake create-policy plan against @email-gateway/policy-dsl', () => {
  it('the definition D validates as policy-dsl/1 with one rule', () => {
    const result = validatePolicyDefinition(structuredClone(FAKE_EXECUTABLES_DEFINITION));
    expect(result.ok ? null : result.violations).toBeNull();
    if (result.ok) {
      expect(result.ruleCount).toBe(1);
      expect(result.hasOverrideRules).toBe(false);
    }
  });

  it('the facts F parse with the synthetic facts schema and describe one inbound executable attachment', () => {
    const facts = syntheticFactsSchema.parse(structuredClone(FAKE_EXECUTABLES_FACTS));
    const input = buildSyntheticInput(facts);
    expect(input.direction).toBe('inbound');
    expect(input.attachments.items).toHaveLength(1);
    expect(input.attachments.items[0]).toMatchObject({
      filename: 'invoice.exe',
      typeFamily: 'executable',
    });
  });
});
