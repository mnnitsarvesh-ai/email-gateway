import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../http/coded-exception';

/** Stable error codes of the recipient suppression routes (step 6.1 §3.2, §3.3). */
export const SUPPRESSION_NOT_FOUND = 'suppression_not_found';
export const SUPPRESSION_EXISTS = 'suppression_exists';
export const SUPPRESSION_LIMIT_REACHED = 'suppression_limit_reached';

/** Unknown id, or a suppression of another organization (never confirms existence). */
export const suppressionNotFound = (): CodedHttpException =>
  new CodedHttpException(HttpStatus.NOT_FOUND, SUPPRESSION_NOT_FOUND, 'Suppression not found');

/** The address is already on the list (active or expired); `id` names the existing row. */
export const suppressionExists = (id: bigint): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    SUPPRESSION_EXISTS,
    'The address is already on the suppression list',
    { id: id.toString() },
  );

export const suppressionLimitReached = (limit: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    SUPPRESSION_LIMIT_REACHED,
    'The organization has reached the maximum number of manual suppressions',
    { limit },
  );
