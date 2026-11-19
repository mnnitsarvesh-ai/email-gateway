/**
 * Coded errors of the shared incident model. The api maps the code to its HTTP answer
 * (`incident_*` codes of `incidents.errors.ts`, WP5); workers treat them as permanent.
 */
export const INCIDENT_ERROR_CODES = [
  'incident_not_found',
  'incident_active_conflict',
  'incident_transition_not_allowed',
  'incident_resolution_required',
  'incident_resolution_invalid',
  'incident_note_required',
  'incident_note_invalid',
  'incident_version_conflict',
  'incident_category_unknown',
  'incident_subject_invalid',
  'incident_feedback_invalid',
  'incident_closed',
  'incident_assignee_invalid',
  'incident_input_invalid',
] as const;
export type IncidentErrorCode = (typeof INCIDENT_ERROR_CODES)[number];

export class IncidentError extends Error {
  constructor(
    readonly code: IncidentErrorCode,
    message: string,
    readonly details: Record<string, string | number | boolean | null> = {},
  ) {
    super(message);
    this.name = 'IncidentError';
  }
}

/** One active incident per (organization, category, subject) exists already (D24). */
export class IncidentActiveConflictError extends IncidentError {
  constructor(readonly activeIncidentId: bigint | null) {
    super('incident_active_conflict', 'An active incident exists for this subject and category', {
      activeIncidentId: activeIncidentId?.toString() ?? null,
    });
    this.name = 'IncidentActiveConflictError';
  }
}

/** The row version moved since the caller read it (compare-and-set). */
export class IncidentVersionConflictError extends IncidentError {
  constructor(expected: number, actual: number) {
    super('incident_version_conflict', 'The incident was changed by someone else', {
      expected,
      actual,
    });
    this.name = 'IncidentVersionConflictError';
  }
}

export const isIncidentError = (error: unknown): error is IncidentError =>
  error instanceof IncidentError;
