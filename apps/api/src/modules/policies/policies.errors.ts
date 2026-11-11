import { HttpStatus } from '@nestjs/common';
import type { Violation } from '@email-gateway/policy-dsl';
import { CodedHttpException } from '../../http/coded-exception';

/**
 * Stable error codes of the policy routes (step 5.2 P22, docs/plan/steps/16-policy-engine.md).
 * Bodies carry ids, version numbers, row versions, limits, paths and codes only: never a
 * definition value, a change note or message data.
 */
export const POLICY_DEFINITION_INVALID = 'policy_definition_invalid';
export const POLICY_SETTINGS_INVALID = 'policy_settings_invalid';
export const POLICY_TEST_FACTS_INVALID = 'policy_test_facts_invalid';
export const POLICY_NOT_FOUND = 'policy_not_found';
export const POLICY_VERSION_NOT_FOUND = 'policy_version_not_found';
export const POLICY_NAME_TAKEN = 'policy_name_taken';
export const POLICY_LIMIT_REACHED = 'policy_limit_reached';
export const POLICY_CONFLICT = 'policy_conflict';
export const POLICY_VERSION_LIMIT_REACHED = 'policy_version_limit_reached';
export const POLICY_VERSION_IMMUTABLE = 'policy_version_immutable';
export const POLICY_VERSION_NOT_PUBLISHED = 'policy_version_not_published';
export const POLICY_NO_ACTIVE_VERSION = 'policy_no_active_version';
export const POLICY_RULE_LIMIT_REACHED = 'policy_rule_limit_reached';
export const POLICY_INPUT_INVALID = 'policy_input_invalid';
export const POLICY_SCAN_NOT_FOUND = 'scan_not_found';
export const SCAN_ROUND_NOT_COMPLETE = 'scan_round_not_complete';
export const INCONSISTENT_READ = 'inconsistent_read';

const violationList = (violations: readonly Violation[]) =>
  violations.slice(0, 100).map((v) => ({ path: v.path, code: v.code, message: v.message }));

/** The definition breaks the DSL (P2–P6) or names an unknown department or user (P5). */
export const policyDefinitionInvalid = (violations: readonly Violation[]): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.BAD_REQUEST,
    POLICY_DEFINITION_INVALID,
    'The policy definition is invalid',
    { violations: violationList(violations) },
  );

/** The settings document breaks the strict P11 schema. */
export const policySettingsInvalid = (violations: readonly Violation[]): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.BAD_REQUEST,
    POLICY_SETTINGS_INVALID,
    'The policy settings are invalid',
    { violations: violationList(violations) },
  );

/** The synthetic facts passed the schema but do not form a policy input (P23). */
export const policyTestFactsInvalid = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.BAD_REQUEST,
    POLICY_TEST_FACTS_INVALID,
    'The synthetic facts do not form a valid policy input',
  );

/** Unknown, archived or another organization's policy: never confirms existence. */
export const policyNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, POLICY_NOT_FOUND, 'Policy not found');

export const policyVersionNotFound = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.NOT_FOUND,
    POLICY_VERSION_NOT_FOUND,
    'Policy version not found',
  );

/** Names are unique per organization, archived policies included (§3 item 1). */
export const policyNameTaken = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    POLICY_NAME_TAKEN,
    'A policy with this name exists in the organization (archived policies keep their name)',
  );

export const policyLimitReached = (limit: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    POLICY_LIMIT_REACHED,
    'The organization reached its limit of policies; delete unused policies',
    { limit },
  );

/** `expectedRowVersion` is not the current counter of the policy, version or settings row. */
export const policyConflict = (current: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    POLICY_CONFLICT,
    'The policy changed since it was read; read it and retry',
    { currentRowVersion: current },
  );

export const policyVersionLimitReached = (limit: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    POLICY_VERSION_LIMIT_REACHED,
    'The policy reached its limit of versions; delete unused drafts',
    { limit },
  );

/** A published version never changes and is never deleted (P17). */
export const policyVersionImmutable = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    POLICY_VERSION_IMMUTABLE,
    'The policy version is not a draft and is immutable; create a new draft',
  );

export const policyVersionNotPublished = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    POLICY_VERSION_NOT_PUBLISHED,
    'Only a published policy version can be activated',
  );

export const policyNoActiveVersion = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    POLICY_NO_ACTIVE_VERSION,
    'The policy has no active version; publish and activate a version first',
  );

/** Activation would exceed POLICY_MAX_ACTIVE_RULES rules of active versions (P4, §5). */
export const policyRuleLimitReached = (limit: number, requested: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    POLICY_RULE_LIMIT_REACHED,
    'Activating this version would exceed the organization’s limit of active rules',
    { limit, requested },
  );

/** The stored rows of the round do not form a policy input (a defect; the engine dead-letters). */
export const policyInputInvalid = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    POLICY_INPUT_INVALID,
    'The stored rows of the round do not form a valid policy input',
  );

export const policyScanNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, POLICY_SCAN_NOT_FOUND, 'Scan not found');

/** The round is pending or running on the read replica (or not replicated yet). */
export const scanRoundNotComplete = (status: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    SCAN_ROUND_NOT_COMPLETE,
    'The scan round is not complete yet (or not replicated yet); retry later',
    { status },
  );

/** A writer read returned another row twice in a row (step 5.2 §6); retry later. */
export const inconsistentRead = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.SERVICE_UNAVAILABLE,
    INCONSISTENT_READ,
    'The database returned an inconsistent read; retry the request',
  );

/**
 * A read on the writer returned a row other than the one asked for (4.2 §6). The writer retries
 * the transaction once, then answers `503 inconsistent_read` (step 5.2 §6, P17).
 */
export class InconsistentPolicyReadError extends Error {
  constructor(readonly read: string) {
    super(`inconsistent read (${read})`);
    this.name = 'InconsistentPolicyReadError';
  }
}
