import { HttpStatus } from '@nestjs/common';
import { type IncidentError, isIncidentError } from '@email-gateway/security-incidents';
import { CodedHttpException } from '../../http/coded-exception';
import { INCONSISTENT_READ } from '../../http/listing/echo-check';

/**
 * Stable error codes of the generic security incident routes (step 8.4 §5.2, D17, D24; ADR-0075).
 * An incident of another organization **or of a category the caller may not read** answers the
 * same `404 incident_not_found` as an unknown id. Details carry ids, states and versions only.
 */
export const INCIDENT_ERROR_CODES = {
  notFound: 'incident_not_found',
  conflict: 'incident_conflict',
  transitionInvalid: 'incident_transition_invalid',
  active: 'incident_active',
  subjectNotFound: 'incident_subject_not_found',
  categoryUnsupported: 'incident_category_unsupported',
  assigneeInvalid: 'incident_assignee_invalid',
  closed: 'incident_closed',
  feedbackInvalid: 'incident_feedback_invalid',
  inconsistentRead: INCONSISTENT_READ,
} as const;

const C = INCIDENT_ERROR_CODES;
type Code = (typeof INCIDENT_ERROR_CODES)[keyof typeof INCIDENT_ERROR_CODES];

const err = (
  status: HttpStatus,
  code: Code,
  message: string,
  details: ConstructorParameters<typeof CodedHttpException>[3] = {},
): CodedHttpException => new CodedHttpException(status, code, message, details);

export const incidentNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.notFound, 'Incident not found');

export const incidentConflict = (currentRowVersion: number | null): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.conflict,
    'expectedRowVersion is not the current version of the incident',
    currentRowVersion === null ? {} : { currentRowVersion },
  );

/** Why a transition was refused (`reason`): the edge, a resolution code or the note. */
export type TransitionRefusalReason =
  | 'transition_not_allowed'
  | 'resolution_required'
  | 'resolution_invalid'
  | 'note_required'
  | 'note_invalid';

export const incidentTransitionInvalid = (
  reason: TransitionRefusalReason,
  from: string | null,
  to: string | null,
): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.transitionInvalid,
    reason === 'transition_not_allowed'
      ? 'The incident cannot move to this status from its current status'
      : reason === 'resolution_required'
        ? 'This status needs a resolution code'
        : reason === 'resolution_invalid'
          ? 'This resolution code is not allowed for this status'
          : reason === 'note_required'
            ? 'This status needs a note of 10-4000 characters'
            : 'The note must be 10-4000 characters',
    { reason, from, to },
  );

export const incidentActive = (incidentId: string | null): CodedHttpException =>
  err(
    HttpStatus.CONFLICT,
    C.active,
    'An active incident of this category already exists for the subject',
    incidentId === null ? {} : { incidentId },
  );

export const incidentSubjectNotFound = (): CodedHttpException =>
  err(HttpStatus.NOT_FOUND, C.subjectNotFound, 'The incident subject was not found');

export const incidentCategoryUnsupported = (): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.categoryUnsupported,
    'This category or subject type is not supported for manual incidents',
  );

export const incidentAssigneeInvalid = (): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.assigneeInvalid,
    'The assignee is not an active user of the organization',
  );

export const incidentClosed = (): CodedHttpException =>
  err(HttpStatus.CONFLICT, C.closed, 'The incident is closed');

export const incidentFeedbackInvalid = (): CodedHttpException =>
  err(
    HttpStatus.UNPROCESSABLE_ENTITY,
    C.feedbackInvalid,
    'categoryFeedback is not valid for this category (or not accepted with this change)',
  );

/**
 * Maps an `IncidentError` of `@email-gateway/security-incidents` to its coded HTTP answer.
 * `publicIdOf` resolves the active incident's internal id of a conflict to its public id.
 */
export async function mapIncidentError(
  error: unknown,
  publicIdOf: (id: bigint) => Promise<string | null> = () => Promise.resolve(null),
): Promise<never> {
  if (!isIncidentError(error)) throw error;
  const e: IncidentError = error;
  const from = typeof e.details.from === 'string' ? e.details.from : null;
  const to = typeof e.details.to === 'string' ? e.details.to : null;
  switch (e.code) {
    case 'incident_not_found':
      throw incidentNotFound();
    case 'incident_active_conflict': {
      const raw = e.details.activeIncidentId;
      const id =
        typeof raw === 'string' && /^\d+$/.test(raw) ? await publicIdOf(BigInt(raw)) : null;
      throw incidentActive(id);
    }
    case 'incident_version_conflict':
      throw incidentConflict(typeof e.details.actual === 'number' ? e.details.actual : null);
    case 'incident_transition_not_allowed':
      throw incidentTransitionInvalid('transition_not_allowed', from, to);
    case 'incident_resolution_required':
      throw incidentTransitionInvalid('resolution_required', from, to);
    case 'incident_resolution_invalid':
      throw incidentTransitionInvalid('resolution_invalid', from, to);
    case 'incident_note_required':
      throw incidentTransitionInvalid('note_required', from, to);
    case 'incident_note_invalid':
      throw incidentTransitionInvalid('note_invalid', from, to);
    case 'incident_closed':
      throw incidentClosed();
    case 'incident_assignee_invalid':
      throw incidentAssigneeInvalid();
    case 'incident_feedback_invalid':
      throw incidentFeedbackInvalid();
    case 'incident_category_unknown':
    case 'incident_subject_invalid':
      throw incidentCategoryUnsupported();
    case 'incident_input_invalid':
      throw err(HttpStatus.UNPROCESSABLE_ENTITY, C.transitionInvalid, 'The change is not valid', {
        reason: 'input_invalid',
        from,
        to,
      });
  }
}
