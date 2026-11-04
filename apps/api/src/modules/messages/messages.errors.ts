import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../http/coded-exception';

/** Stable error codes of the message lifecycle routes (step 3.3 L10.4). */
export const MESSAGE_NOT_FOUND = 'message_not_found';
export const MESSAGE_VERSION_CONFLICT = 'message_version_conflict';
export const MESSAGE_STATE_CONFLICT = 'message_state_conflict';
export const QUARANTINE_WORKFLOW_REQUIRED = 'quarantine_workflow_required';
export const NO_RELEASABLE_RECIPIENTS = 'no_releasable_recipients';

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

export const quarantineWorkflowRequired = (snapshot: ConflictSnapshot): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    QUARANTINE_WORKFLOW_REQUIRED,
    'The message has per-recipient quarantine entries; release it through the quarantine workflow',
    current(snapshot),
  );

export const noReleasableRecipients = (snapshot: ConflictSnapshot): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    NO_RELEASABLE_RECIPIENTS,
    'The message has no pending or quarantined recipient to release',
    current(snapshot),
  );
