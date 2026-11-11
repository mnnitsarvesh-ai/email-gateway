import { HttpStatus } from '@nestjs/common';
import type { Violation } from '@email-gateway/risk-scoring';
import { CodedHttpException } from '../../http/coded-exception';

/**
 * Stable error codes of the risk scoring routes (step 5.1 R15,
 * docs/plan/steps/15-risk-scoring.md). Bodies carry ids, version numbers, limits, paths and
 * codes only: never message data and never the overrides document itself.
 */
export const RISK_PROFILE_INVALID = 'risk_profile_invalid';
export const RISK_PROFILE_LIMIT_REACHED = 'risk_profile_limit_reached';
export const RISK_PROFILE_VERSION_CONFLICT = 'risk_profile_version_conflict';
export const RISK_PROFILE_VERSION_IMMUTABLE = 'risk_profile_version_immutable';
export const RISK_PROFILE_VERSION_NOT_PUBLISHED = 'risk_profile_version_not_published';
export const RISK_PROFILE_VERSION_NOT_FOUND = 'risk_profile_version_not_found';
export const RISK_SCAN_NOT_FOUND = 'scan_not_found';
export const SCAN_ROUND_NOT_COMPLETE = 'scan_round_not_complete';
export const RISK_REVISION_UNAVAILABLE = 'risk_revision_unavailable';
export const INCONSISTENT_READ = 'inconsistent_read';

/** The overrides break the schema or a bound (R10); `violations` lists every problem by path. */
export const riskProfileInvalid = (violations: readonly Violation[]): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.BAD_REQUEST,
    RISK_PROFILE_INVALID,
    'The risk profile overrides are invalid',
    { violations: violations.map((v) => ({ path: v.path, message: v.message })) },
  );

/** RISK_PROFILE_MAX_VERSIONS versions (drafts and published) exist for the organization. */
export const riskProfileLimitReached = (limit: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    RISK_PROFILE_LIMIT_REACHED,
    'The organization reached its limit of risk profile versions; delete unused drafts',
    { limit },
  );

/** `expectedRowVersion` (or `expectedProfileVersion`) is not the current counter. */
export const riskProfileVersionConflict = (
  field: 'rowVersion' | 'profileVersion',
  current: number,
): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    RISK_PROFILE_VERSION_CONFLICT,
    'The risk profile changed since it was read; read it and retry',
    field === 'rowVersion' ? { currentRowVersion: current } : { currentProfileVersion: current },
  );

/** A published version never changes and is never deleted (R10). */
export const riskProfileVersionImmutable = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    RISK_PROFILE_VERSION_IMMUTABLE,
    'The risk profile version is published and immutable; create a new draft',
  );

/** Only a published version can be activated. */
export const riskProfileVersionNotPublished = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    RISK_PROFILE_VERSION_NOT_PUBLISHED,
    'Only a published risk profile version can be activated',
  );

/** Unknown id or another organization's id: never confirms existence. */
export const riskProfileVersionNotFound = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.NOT_FOUND,
    RISK_PROFILE_VERSION_NOT_FOUND,
    'Risk profile version not found',
  );

/** The scan is not a round of the message (or of the organization). */
export const riskScanNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, RISK_SCAN_NOT_FOUND, 'Scan not found');

/** The round is pending or running on the read replica (or not replicated yet). */
export const scanRoundNotComplete = (status: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    SCAN_ROUND_NOT_COMPLETE,
    'The scan round is not complete yet (or not replicated yet); retry later',
    { status },
  );

/** Revision 1 needs a non-skipped sandbox final of the round (R12). */
export const riskRevisionUnavailable = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    RISK_REVISION_UNAVAILABLE,
    'Revision 1 needs a non-skipped sandbox result for the round',
  );

/** A writer read returned another row twice in a row (step 5.1 §6); retry later. */
export const inconsistentRead = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.SERVICE_UNAVAILABLE,
    INCONSISTENT_READ,
    'The database returned an inconsistent read; retry the request',
  );

/**
 * A read on the writer returned a row other than the one asked for (4.2 §6: Prisma may hand back
 * the reply of an abandoned statement). The writer retries the transaction once, then answers
 * `503 inconsistent_read` (step 5.1 §6).
 */
export class InconsistentRiskReadError extends Error {
  constructor(readonly read: string) {
    super(`inconsistent read (${read})`);
    this.name = 'InconsistentRiskReadError';
  }
}
