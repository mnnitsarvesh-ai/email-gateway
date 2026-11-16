import { canonicalJson, sha256Hex, validatePolicyDefinition } from '@email-gateway/policy-dsl';
import { describe, expect, it } from 'vitest';
import {
  PolicySampleDryRunResponseSchema,
  PolicySampleDryRunSchema,
  PolicyValidateResponseSchema,
  PolicyValidateSchema,
} from './policies.schemas';
import { POLICY_BUILDER_EXAMPLES as X } from './policy-builder.examples';

describe('policy builder OpenAPI examples (step 7.3 §4.4)', () => {
  it('match the strict request and response schemas', () => {
    expect(PolicyValidateSchema.safeParse(X.validateBody).success).toBe(true);
    expect(PolicyValidateSchema.safeParse(X.validateInvalidBody).success).toBe(true);
    expect(PolicyValidateResponseSchema.safeParse(X.validated).success).toBe(true);
    expect(PolicySampleDryRunSchema.safeParse(X.sampleBody).success).toBe(true);
    expect(PolicySampleDryRunSchema.safeParse(X.sampleVersionBody).success).toBe(true);
    expect(PolicySampleDryRunResponseSchema.safeParse(X.sample).success).toBe(true);
  });

  it('tell the truth about the example definitions', () => {
    const valid = validatePolicyDefinition(X.validateBody.definition);
    expect(valid.ok).toBe(true);
    expect(X.validated.definitionSha256).toBe(sha256Hex(canonicalJson(X.validateBody.definition)));
    const invalid = validatePolicyDefinition(X.validateInvalidBody.definition);
    expect(invalid.ok ? [] : invalid.violations.map((v) => v.code)).toEqual(['regex_invalid']);
    // The sample summary agrees with its items.
    const evaluated = X.sample.items.filter((i) => i.outcome === 'evaluated');
    expect(X.sample.evaluated).toBe(evaluated.length);
    expect(X.sample.skipped).toBe(X.sample.items.length - evaluated.length);
    expect(X.sample.summary.changed).toBe(evaluated.filter((i) => i.dispositionChanged).length);
  });
});
