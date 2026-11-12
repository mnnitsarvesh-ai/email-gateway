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
