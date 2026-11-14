import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../http/coded-exception';

/** Stable error codes of the saved views routes (step 7.2 §2 E4, §3.3). */
export const SAVED_VIEW_ERROR_CODES = {
  notFound: 'saved_view_not_found',
  nameTaken: 'saved_view_name_taken',
  conflict: 'saved_view_conflict',
  limitReached: 'saved_view_limit_reached',
  memberOnly: 'saved_views_member_only',
} as const;

/** Unknown id, or a view of another user or organization (never confirms existence). */
export const savedViewNotFound = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.NOT_FOUND,
    SAVED_VIEW_ERROR_CODES.notFound,
    'Saved view not found',
  );

/** Another view of the caller and kind has this name (case-insensitive). */
export const savedViewNameTaken = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    SAVED_VIEW_ERROR_CODES.nameTaken,
    'You already have a saved view with this name',
  );

/** `expectedRowVersion` is not the stored one. */
export const savedViewConflict = (currentRowVersion: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    SAVED_VIEW_ERROR_CODES.conflict,
    'The saved view changed since expectedRowVersion; read it and retry',
    { currentRowVersion },
  );

/** At most SAVED_VIEWS_MAX_PER_USER views per user and kind. */
export const savedViewLimitReached = (limit: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    SAVED_VIEW_ERROR_CODES.limitReached,
    `You have reached the limit of ${limit} saved views; delete one first`,
    { limit },
  );

/** A platform override session (not a member of the organization). */
export const savedViewsMemberOnly = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.FORBIDDEN,
    SAVED_VIEW_ERROR_CODES.memberOnly,
    'Saved views belong to members of the organization; a platform override cannot use them',
  );
