import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../http/coded-exception';
import { INCONSISTENT_READ } from '../../http/listing/echo-check';

/** Stable error codes of the notification routes (step 6.2 §6.1, N3). */
export const NOTIFICATION_ERROR_CODES = {
  settingsConflict: 'notification_settings_conflict',
  settingsInvalid: 'notification_settings_invalid',
  inconsistentRead: INCONSISTENT_READ,
} as const;

/** `expectedRowVersion` is not the stored one (0 = no settings stored yet). */
export const notificationSettingsConflict = (currentRowVersion: number): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.CONFLICT,
    NOTIFICATION_ERROR_CODES.settingsConflict,
    'expectedRowVersion is not the current version of the notification settings',
    { currentRowVersion },
  );

/** The settings document breaks the strict schema of §6.3 (paths and rules, never values). */
export const notificationSettingsInvalid = (
  violations: ReadonlyArray<{ path: string; message: string }>,
): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.BAD_REQUEST,
    NOTIFICATION_ERROR_CODES.settingsInvalid,
    'The notification settings are invalid',
    { violations: violations.slice(0, 32).map((v) => ({ path: v.path, message: v.message })) },
  );
