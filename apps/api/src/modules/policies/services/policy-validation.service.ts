import { Injectable } from '@nestjs/common';
import { POLICY_DSL_VERSION, type Violation } from '@email-gateway/policy-dsl';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  checkDefinition,
  referencesOf,
  unknownReferenceViolations,
} from '../domain/policy-definition';
import type { PolicyValidate, PolicyValidateResponse } from '../dto/policies.schemas';
import { PolicyFactsRepository } from '../repositories/policy-facts.repository';
import { PolicyMetrics } from './policy-writer';

/** Most violations a response lists (as `400 policy_definition_invalid`). */
const MAX_VIOLATIONS = 100;

const copy = (violations: readonly Violation[]): Violation[] =>
  violations
    .slice(0, MAX_VIOLATIONS)
    .map((v) => ({ path: v.path, code: v.code, message: v.message }));

/**
 * `POST /policies/validate` (step 7.3 §4.2, B4, ADR-0063 decision 3): checks a definition exactly
 * as a draft save does (`checkDefinition`, the `policy-dsl/1` validator) and, for a valid one, the
 * departments and users it references against the read replica (reported apart: drafts may name
 * a department created later; publish, activation and enable refuse them). **Writes nothing**: no
 * row, no audit, no outbox, no idempotency record (this service has no writer dependency). An
 * invalid definition is a result, not an error. Counted `policy_validations_total{result}`.
 */
@Injectable()
export class PolicyValidationService {
  constructor(
    private readonly facts: PolicyFactsRepository,
    private readonly metrics: PolicyMetrics,
  ) {}

  async validate(scope: TenantScope, body: PolicyValidate): Promise<PolicyValidateResponse> {
    const check = checkDefinition(body.definition);
    if (!check.ok) {
      this.metrics.validations.inc({ result: 'invalid' });
      return {
        dslVersion: POLICY_DSL_VERSION,
        valid: false,
        violations: copy(check.violations),
        referenceViolations: [],
        ruleCount: null,
        hasOverrideRules: null,
        references: null,
        definitionSha256: null,
      };
    }
    const references = referencesOf(check.content.references);
    let referenceViolations: Violation[] = [];
    if (references.departmentIds.length > 0 || references.userIds.length > 0) {
      const existing = await this.facts.existingDirectoryIds(scope, references);
      referenceViolations = copy(unknownReferenceViolations(check.definition, existing));
    }
    this.metrics.validations.inc({ result: 'valid' });
    return {
      dslVersion: POLICY_DSL_VERSION,
      valid: true,
      violations: [],
      referenceViolations,
      ruleCount: check.content.ruleCount,
      hasOverrideRules: check.content.hasOverrideRules,
      references,
      definitionSha256: check.content.definitionSha256,
    };
  }
}
