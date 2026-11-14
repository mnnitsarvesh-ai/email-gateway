import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../http/coded-exception';

/** Stable error codes of the message lifecycle routes (step 3.3 L10.4). */
export const MESSAGE_NOT_FOUND = 'message_not_found';
export const MESSAGE_VERSION_CONFLICT = 'message_version_conflict';
export const MESSAGE_STATE_CONFLICT = 'message_state_conflict';
export const QUARANTINE_WORKFLOW_REQUIRED = 'quarantine_workflow_required';
export const NO_RELEASABLE_RECIPIENTS = 'no_releasable_recipients';
export const QUARANTINE_RESCAN_FORBIDDEN = 'quarantine_rescan_forbidden';

/** The lifecycle as a conflict body shows it: state and version only (no content). */
export interface ConflictSnapshot {
  state: string;
  version: number;
}

const current = (snapshot: ConflictSnapshot) => ({
  currentState: snapshot.state,
  currentVersion: snapshot.version,
});

/** Another organization's message or an unknown id: never confirms existence. */
export const messageNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, MESSAGE_NOT_FOUND, 'Message not found');

export const messageVersionConflict = (snapshot: ConflictSnapshot): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    MESSAGE_VERSION_CONFLICT,
    'The message changed since expectedVersion; read its lifecycle and retry',
    current(snapshot),
  );

export const messageStateConflict = (snapshot: ConflictSnapshot): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    MESSAGE_STATE_CONFLICT,
    'The current state of the message does not allow this operation',
    current(snapshot),
  );

/** The quarantine route operators use instead (step 5.3 Q30). */
export const QUARANTINE_RELEASE_ROUTE = 'POST /api/v1/quarantine/entries/{entryId}/release';

export const quarantineWorkflowRequired = (
  snapshot: ConflictSnapshot,
  entries: number,
): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    QUARANTINE_WORKFLOW_REQUIRED,
    'Quarantined and held messages are released per recipient through the quarantine workflow ' +
      '(re-validation and approvals); search the message’s entries with ' +
      'GET /api/v1/quarantine/entries?messageId=…',
    { ...current(snapshot), entries, route: QUARANTINE_RELEASE_ROUTE },
  );

/**
 * Step 5.3: a rescan of a `quarantined`/`held_for_review` message re-decides its held recipients
 * (a clean round delivers them), so it needs `quarantine:release` besides `message:rescan`.
 */
export const quarantineRescanForbidden = (
  snapshot: ConflictSnapshot,
  entries: number,
): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.FORBIDDEN,
    QUARANTINE_RESCAN_FORBIDDEN,
    'A rescan of a quarantined or held message re-decides its held recipients and may deliver ' +
      'them; it requires the quarantine:release permission',
    { ...current(snapshot), entries, permission: 'quarantine:release' },
  );

export const noReleasableRecipients = (snapshot: ConflictSnapshot): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    NO_RELEASABLE_RECIPIENTS,
    'The message has no pending or quarantined recipient to release',
    current(snapshot),
  );

/** Step 6.1: a `domainId` filter of another organization or an unknown id (D4). */
export const DOMAIN_NOT_FOUND = 'domain_not_found';

export const domainNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, DOMAIN_NOT_FOUND, 'Domain not found');

/** Step 7.2 (§2 E1, E2, §3.3): refusals of the message search. */
export const MESSAGE_FILTER_FORBIDDEN = 'message_filter_forbidden';
export const MESSAGE_SEARCH_TOO_BROAD = 'message_search_too_broad';
export const MESSAGE_SEARCH_TIMEOUT = 'message_search_timeout';

/**
 * A filter the caller's permissions do not cover (§2 E2): `recipient`/`subject`/`subjectPrefix`
 * need `message:reveal`, `deliveryStatus` needs `delivery:read`, `quarantineStatus` needs
 * `quarantine:read`. Names the filter and the permission, never the value.
 */
export const messageFilterForbidden = (filter: string, permission: string): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.FORBIDDEN,
    MESSAGE_FILTER_FORBIDDEN,
    `The ${filter} filter requires the ${permission} permission`,
    { filter, permission },
  );

/** More subject keys than the cap start with the prefix in the range (§2 E1). */
export const messageSearchTooBroad = (maxMatches: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    MESSAGE_SEARCH_TOO_BROAD,
    `More than ${maxMatches} messages in this range start with that subject; type more of it, ` +
      'use the exact subject or narrow the range',
    { maxMatches },
  );

/** A subject-prefix statement hit `MAX_EXECUTION_TIME` (MySQL 3024). */
export const messageSearchTimeout = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.SERVICE_UNAVAILABLE,
    MESSAGE_SEARCH_TIMEOUT,
    'The subject search took too long; type more of the subject, use the exact subject or ' +
      'narrow the range',
  );

/** Step 7.2 (§2 E6): the code of a reveal whose audit rows could not be written. */
export const SERVICE_UNAVAILABLE = 'service_unavailable';

/**
 * The `message.revealed` audit rows could not be committed (§2 E6, ADR-0062): the reveal answers
 * no value. Uses the generic `service_unavailable` code (§3.3: reveal adds no error code).
 */
export const revealNotRecorded = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.SERVICE_UNAVAILABLE,
    SERVICE_UNAVAILABLE,
    'The reveal could not be recorded in the audit log, so no value was returned; retry the ' +
      'request',
  );
